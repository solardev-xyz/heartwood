//! Implementation of the transport protocol.
//!
//! We use the Noise XK handshake pattern to establish an encrypted stream with a remote peer.
use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;
use std::{io, net, time};

use crossbeam_channel as chan;
use cyphernet::addr::{HostName, InetHost, NetAddr};
use cyphernet::encrypt::noise::{HandshakePattern, Keyset, NoiseState};
use cyphernet::proxy::socks5;
use cyphernet::{Digest, Sha256};
use localtime::{LocalDuration, LocalTime};
use mio::net::TcpStream;
use protocol::deserializer::Deserializer;
use protocol::service;
use protocol::service::io::Io;
use protocol::service::{DisconnectReason, Metrics, Service, session};
use protocol::wire::frame;
use protocol::wire::frame::{Frame, FrameData, StreamId};
use protocol::wire::*;
use protocol::worker::{FetchRequest, FetchResult};
use radicle::collections::{RandomMap, RandomSet};
use radicle::crypto::{self, Signer as _};
use radicle::node::Address;
use radicle::node::Link;
use radicle::node::NodeId;
#[cfg(any(feature = "i2p", feature = "tor"))]
use radicle::node::config::AddressConfig;
use radicle::node::dial::Gate;
use radicle::storage::WriteStorage;

use crate::reactor;
use crate::reactor::{Listener, Transport};
use crate::reactor::{NoiseSession, ProtocolArtifact, SessionEvent, Socks5Session};
use crate::reactor::{Token, Tokens};
use crate::resolver;
use crate::worker;
use crate::worker::channels::{ChannelEvent, ChannelsConfig};
use crate::worker::{Task, TaskResult};

/// NoiseXK handshake pattern.
pub const NOISE_XK: HandshakePattern = HandshakePattern {
    initiator: cyphernet::encrypt::noise::InitiatorPattern::Xmitted,
    responder: cyphernet::encrypt::noise::OneWayPattern::Known,
};

/// Default time to wait until a network connection is considered inactive.
pub const DEFAULT_CONNECTION_TIMEOUT: time::Duration = time::Duration::from_secs(6);

/// Maximum size of a peer inbox, in bytes.
pub const MAX_INBOX_SIZE: usize = 1024 * 1024 * 2;

/// Control message used internally between workers, users, and the service.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Control {
    /// Message from the user to the service.
    User(service::Command),
    /// Message from a worker to the service.
    Worker(TaskResult),
    /// Flush data in the given stream to the remote.
    Flush { remote: NodeId, stream: StreamId },
    /// The addresses a dial's name resolved to, from its resolver thread.
    Resolved {
        id: u64,
        answers: io::Result<Vec<net::SocketAddr>>,
    },
}

/// A dial waiting for its name to resolve.
#[derive(Debug)]
struct Resolving {
    nid: NodeId,
    addr: Address,
    /// `None` for a timeout too large to add to the current time.
    deadline: Option<Instant>,
    /// Set once a worker has taken the name to resolve.
    taken: Arc<AtomicBool>,
}

/// Peer session type.
pub(crate) type WireSession = NoiseSession<crypto::SigningKey, Sha256, Socks5Session<TcpStream>>;

/// Reactor action.
type Action = reactor::Action<Listener, Transport<WireSession>>;

/// Where the wire leaves the error the service stopped the node with, for the
/// runtime to return once the reactor has ended.
pub type Stopped = Arc<Mutex<Option<service::Error>>>;

/// A worker stream.
struct Stream {
    /// Channels.
    channels: worker::channels::Channels,
    /// Data sent.
    sent_bytes: usize,
    /// Data received.
    received_bytes: usize,
}

impl Stream {
    fn new(channels: worker::channels::Channels) -> Self {
        Self {
            channels,
            sent_bytes: 0,
            received_bytes: 0,
        }
    }
}

/// Streams associated with a connected peer.
struct Streams {
    /// Active streams and their associated worker channels.
    /// Note that the gossip and control streams are not included here as they are always
    /// implied to exist.
    streams: RandomMap<StreamId, Stream>,
    /// Connection direction.
    link: Link,
    /// Sequence number used to compute the next stream id.
    seq: u64,
}

impl Streams {
    /// Create a new [`Streams`] object, passing the connection link.
    fn new(link: Link) -> Self {
        Self {
            streams: RandomMap::default(),
            link,
            seq: 0,
        }
    }

    /// Get a known stream.
    fn get(&self, stream: &StreamId) -> Option<&Stream> {
        self.streams.get(stream)
    }

    /// Get a known stream, mutably.
    fn get_mut(&mut self, stream: &StreamId) -> Option<&mut Stream> {
        self.streams.get_mut(stream)
    }

    /// Open a new stream.
    fn open(&mut self, config: ChannelsConfig) -> (StreamId, worker::channels::Channels) {
        self.seq += 1;

        let id = StreamId::git(self.link)
            .nth(self.seq)
            .expect("Streams::open: too many streams");
        let channels = self
            .register(id, config)
            .expect("Streams::open: stream was already open");

        (id, channels)
    }

    /// Register an open stream.
    fn register(
        &mut self,
        stream: StreamId,
        config: ChannelsConfig,
    ) -> Option<worker::channels::Channels> {
        let (wire, worker) = worker::channels::Channels::pair(config)
            .expect("Streams::register: fatal: unable to create channels");

        match self.streams.entry(stream) {
            Entry::Vacant(e) => {
                e.insert(Stream::new(worker));
                Some(wire)
            }
            Entry::Occupied(_) => None,
        }
    }

    /// Unregister an open stream.
    fn unregister(&mut self, stream: &StreamId) -> Option<Stream> {
        self.streams.remove(stream)
    }

    /// Close all streams.
    fn shutdown(&mut self) {
        for (sid, stream) in self.streams.drain() {
            log::debug!(target: "wire", "Closing worker stream {sid}");
            stream.channels.close().ok();
        }
    }
}

/// The initial state of an outbound peer before handshake is completed.
#[derive(Debug)]
struct Outbound {
    /// Token for I/O event notification.
    token: Token,
    /// Remote address.
    addr: NetAddr<HostName>,
    /// Remote Node ID.
    nid: NodeId,
}

/// Peer connection state machine.
enum Peer {
    /// The state after handshake is completed.
    /// Peers in this state are handled by the underlying service.
    Connected {
        #[allow(dead_code)]
        addr: NetAddr<HostName>,
        link: Link,
        nid: NodeId,
        inbox: Deserializer<MAX_INBOX_SIZE, Frame>,
        streams: Streams,
    },
    /// The peer was scheduled for disconnection. Once the transport is handed over
    /// by the reactor, we can consider it disconnected.
    Disconnecting {
        link: Link,
        nid: Option<NodeId>,
        reason: DisconnectReason,
    },
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected { link, nid, .. } => write!(f, "Connected({link:?}, {nid})"),
            Self::Disconnecting { .. } => write!(f, "Disconnecting"),
        }
    }
}

impl Peer {
    /// Return the peer's id, if any.
    fn id(&self) -> Option<&NodeId> {
        match self {
            Peer::Connected { nid, .. } | Peer::Disconnecting { nid: Some(nid), .. } => Some(nid),
            Peer::Disconnecting { nid: None, .. } => None,
        }
    }

    fn link(&self) -> Link {
        match self {
            Peer::Connected { link, .. } => *link,
            Peer::Disconnecting { link, .. } => *link,
        }
    }

    /// Connected peer.
    fn connected(nid: NodeId, addr: NetAddr<HostName>, link: Link) -> Self {
        Self::Connected {
            link,
            addr,
            nid,
            inbox: Deserializer::default(),
            streams: Streams::new(link),
        }
    }
}

/// Holds connected peers.
struct Peers(RandomMap<Token, Peer>);

impl Peers {
    fn get_mut(&mut self, token: &Token) -> Option<&mut Peer> {
        self.0.get_mut(token)
    }

    fn entry(&mut self, token: Token) -> Entry<'_, Token, Peer> {
        self.0.entry(token)
    }

    fn insert(&mut self, token: Token, peer: Peer) {
        if self.0.insert(token, peer).is_some() {
            log::debug!(target: "wire", token=token.0; "Replacing existing peer");
        }
    }

    fn remove(&mut self, id: &Token) -> Option<Peer> {
        self.0.remove(id)
    }

    fn lookup(&self, id: &NodeId) -> Option<(Token, &Peer)> {
        self.0
            .iter()
            .find(|(_, peer)| peer.id() == Some(id))
            .map(|(token, peer)| (*token, peer))
    }

    fn lookup_mut(&mut self, id: &NodeId) -> Option<(Token, &mut Peer)> {
        self.0
            .iter_mut()
            .find(|(_, peer)| peer.id() == Some(id))
            .map(|(fd, peer)| (*fd, peer))
    }

    fn active(&self) -> impl Iterator<Item = (Token, &NodeId, Link)> {
        self.0.iter().filter_map(|(id, peer)| match peer {
            Peer::Connected { nid, link, .. } => Some((*id, nid, *link)),
            Peer::Disconnecting { .. } => None,
        })
    }

    fn connected(&self) -> impl Iterator<Item = (Token, &NodeId)> {
        self.0.iter().filter_map(|(id, peer)| {
            if let Peer::Connected { nid, .. } = peer {
                Some((*id, nid))
            } else {
                None
            }
        })
    }

    fn iter(&self) -> impl Iterator<Item = &Peer> {
        self.0.values()
    }
}

/// Wire protocol implementation for a set of peers.
pub(crate) struct Wire<D, S> {
    /// Backing service instance.
    service: Service<D, S>,
    /// Worker pool interface.
    worker: chan::Sender<Task>,
    /// Used for authentication.
    secret_key: radicle::crypto::SigningKey,
    /// Node metrics.
    metrics: service::Metrics,
    /// Internal queue of actions to send to the reactor.
    actions: VecDeque<Action>,
    /// Outbound attempted peers without a session.
    outbound: RandomMap<Token, Outbound>,
    /// Inbound peers without a session.
    inbound: RandomSet<Token>,
    /// Listening addresses that are not yet registered.
    listening: RandomMap<Token, net::SocketAddr>,
    /// Peer (established) sessions.
    peers: Peers,
    /// A (practically) infinite source of tokens to identify transports and listeners.
    tokens: Tokens,
    /// Which addresses the node may dial, and how names resolve.
    gate: Arc<dyn Gate>,
    /// The resolver pool's queue.
    resolvers: resolver::Resolvers,
    /// Dials waiting for their name to resolve, by resolution.
    resolving: HashMap<u64, Resolving>,
    /// The next resolution's ID.
    next_resolution: u64,
    /// The error the service stopped the node with, once it has.
    stopped: Stopped,
}

impl<D, S> Wire<D, S>
where
    D: service::Store,
    S: WriteStorage + 'static,
{
    pub fn new(
        service: Service<D, S>,
        worker: chan::Sender<Task>,
        secret_key: crypto::SigningKey,
        gate: Arc<dyn Gate>,
        resolvers: resolver::Resolvers,
        stopped: Stopped,
    ) -> Self {
        assert!(service.started().is_some(), "Service must be initialized");

        Self {
            service,
            worker,
            secret_key,
            metrics: Metrics::default(),
            actions: VecDeque::new(),
            inbound: RandomSet::default(),
            outbound: RandomMap::default(),
            listening: RandomMap::default(),
            peers: Peers(RandomMap::default()),
            tokens: Tokens::default(),
            gate,
            resolvers,
            resolving: HashMap::new(),
            next_resolution: 0,
            stopped,
        }
    }

    pub fn listen(&mut self, socket: Listener) {
        let token = self.tokens.advance();
        self.listening.insert(token, socket.local_addr());
        self.actions
            .push_back(Action::RegisterListener(token, socket));
    }

    fn disconnect(&mut self, token: Token, reason: DisconnectReason) -> Option<(NodeId, Link)> {
        match self.peers.entry(token) {
            Entry::Vacant(_) => {
                // Connecting peer with no session.
                log::debug!(target: "wire", token=token.0; "Disconnecting pending peer: {reason}");
                self.actions.push_back(Action::UnregisterTransport(token));

                // Check for attempted outbound connections. Unestablished inbound connections don't
                // have an NID yet.
                self.outbound
                    .values()
                    .find(|o| o.token == token)
                    .map(|o| (o.nid, Link::Outbound))
            }
            Entry::Occupied(mut e) => match e.get_mut() {
                Peer::Disconnecting { nid, link, .. } => {
                    log::debug!(target: "wire", token=token.0; "Peer is already disconnecting");

                    nid.map(|n| (n, *link))
                }
                Peer::Connected {
                    nid, streams, link, ..
                } => {
                    log::debug!(target: "wire", token=token.0; "Disconnecting peer: {reason}");
                    let nid = *nid;
                    let link = *link;

                    streams.shutdown();
                    e.insert(Peer::Disconnecting {
                        nid: Some(nid),
                        link,
                        reason,
                    });
                    self.actions.push_back(Action::UnregisterTransport(token));

                    Some((nid, link))
                }
            },
        }
    }

    fn worker_result(&mut self, task: TaskResult) {
        let nid = task.remote;
        let Some((fd, peer)) = self.peers.lookup_mut(&nid) else {
            log::debug!(target: "wire", "Peer {nid} not found; ignoring fetch result");
            return;
        };

        if let Peer::Connected { link, streams, .. } = peer {
            // Nb. It's possible that the stream would already be unregistered if we received an
            // early "close" from the remote. Otherwise, we unregister it here and send the "close"
            // ourselves.
            if let Some(s) = streams.unregister(&task.stream) {
                log::debug!(
                    target: "wire", "Stream {} of {} closing with {} byte(s) sent and {} byte(s) received",
                    task.stream, task.remote, s.sent_bytes, s.received_bytes
                );
                let frame = Frame::<service::Message>::control(
                    *link,
                    frame::Control::Close {
                        stream: task.stream,
                    },
                );
                self.actions
                    .push_back(Action::Send(fd, frame.encode_to_vec()));
            }
        } else {
            // If the peer disconnected, we still let the service know about the fetch result.
            // Otherwise the fetcher's `active` entry for this repo is never cleared, which blocks
            // the repository from being fetched from any node until the node restarts.
            log::debug!(target: "wire", "Peer {nid} is not connected; reporting fetch result anyway");
        };

        // Only call into the service if we initiated this fetch.
        match task.result {
            FetchResult::Initiator { rid, result } => {
                self.service.fetched(rid, nid, result);
            }
            FetchResult::Responder { rid, result } => {
                if let Some(rid) = rid {
                    if let Some(err) = result.err() {
                        log::info!(target: "wire", "Peer {nid} failed to fetch {rid} from us: {err}");
                    } else {
                        log::info!(target: "wire", "Peer {nid} fetched {rid} from us successfully");
                    }
                }
            }
        }
    }

    /// Opens the outbound connection `route` names, for `nid` at `addr`.
    fn connect(&mut self, nid: NodeId, addr: Address, route: Route) {
        match dial(route, nid, self.secret_key.clone())
            .and_then(Transport::<WireSession>::with_session)
        {
            Ok(transport) => {
                let token = self.tokens.advance();
                self.outbound.insert(
                    token,
                    Outbound {
                        token,
                        nid,
                        addr: (*addr).clone(),
                    },
                );
                log::debug!(target: "wire", "Registering outbound transport for {nid}..");
                self.actions
                    .push_back(reactor::Action::RegisterTransport(token, transport));
            }
            Err(err) => self.dial_failed(nid, &addr, err),
        }
    }

    /// Fails the dial of `nid` at `addr` with `err`.
    fn dial_failed(&mut self, nid: NodeId, addr: &Address, err: io::Error) {
        logger::establish_connection(addr, &err);

        self.service
            .disconnected(nid, Link::Outbound, &DisconnectReason::Dial(Arc::new(err)));
    }

    /// Fails the dial of `nid` at `addr` with `err`, a reason of this node's
    /// own: the remote was never tried, and isn't held to account for it.
    fn dial_refused(&mut self, nid: NodeId, addr: &Address, err: io::Error) {
        logger::establish_connection(addr, &err);

        self.service
            .disconnected(nid, Link::Outbound, &DisconnectReason::Local(Arc::new(err)));
    }

    /// Resolves `host` on a thread of its own, through the gate, and dials
    /// `nid` at `addr` once the answer is back, or fails the dial at the
    /// deadline. The reactor never waits on a resolver.
    fn resolve(&mut self, nid: NodeId, addr: Address, host: String, port: u16) {
        let id = self.next_resolution;
        self.next_resolution += 1;
        let timeout = self.gate.resolve_timeout();
        let deadline = Instant::now().checked_add(timeout);
        let taken = Arc::new(AtomicBool::new(false));
        let job = resolver::Job {
            id,
            host,
            port,
            deadline,
            taken: taken.clone(),
        };
        if self.resolvers.submit(job).is_err() {
            // Every resolver is busy and the queue is full: fail at once, as
            // this node's own failure.
            return self.dial_refused(
                nid,
                &addr,
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many names are being resolved",
                ),
            );
        }
        self.resolving.insert(
            id,
            Resolving {
                nid,
                addr,
                deadline,
                taken,
            },
        );
        if deadline.is_some() {
            self.actions.push_back(reactor::Action::SetTimer(timeout));
        }
    }

    /// A resolution's answer: the dial goes on to a checked address, or fails.
    /// An answer that comes after its dial's deadline fails it, whenever the
    /// reactor gets to it.
    fn resolved(&mut self, id: u64, answers: io::Result<Vec<net::SocketAddr>>) {
        // Expired, and failed already.
        let Some(Resolving {
            nid,
            addr,
            deadline,
            ..
        }) = self.resolving.remove(&id)
        else {
            return;
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return self.dial_failed(
                nid,
                &addr,
                io::Error::new(io::ErrorKind::TimedOut, "name resolution timed out"),
            );
        }
        match checked(&addr, answers, self.service.config(), self.gate.as_ref()) {
            Ok(route) => self.connect(nid, addr, route),
            Err(err) => self.dial_failed(nid, &addr, err),
        }
    }

    /// Fails the dials whose names haven't resolved by `now`, and asks to be
    /// woken again at the next deadline still ahead: a timer can fire before
    /// the deadline it was set for.
    fn expire_resolutions(&mut self, now: Instant) {
        let expired = self
            .resolving
            .iter()
            .filter(|(_, r)| r.deadline.is_some_and(|deadline| deadline <= now))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            let Some(Resolving {
                nid, addr, taken, ..
            }) = self.resolving.remove(&id)
            else {
                continue;
            };
            if taken.load(Ordering::Acquire) {
                // A worker resolved the name, and it was too slow.
                self.dial_failed(
                    nid,
                    &addr,
                    io::Error::new(io::ErrorKind::TimedOut, "name resolution timed out"),
                );
            } else {
                // No worker was free before the deadline: the name was never
                // tried.
                self.dial_refused(
                    nid,
                    &addr,
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "no resolver was free before the dial's deadline",
                    ),
                );
            }
        }
        if let Some(next) = self.resolving.values().filter_map(|r| r.deadline).min() {
            self.actions.push_back(reactor::Action::SetTimer(
                next.saturating_duration_since(now) + time::Duration::from_millis(1),
            ));
        }
    }

    fn flush(&mut self, remote: NodeId, stream: StreamId) {
        let Some((fd, peer)) = self.peers.lookup_mut(&remote) else {
            log::debug!(target: "wire", "Peer {remote} is not known; ignoring flush");
            return;
        };
        let Peer::Connected { streams, link, .. } = peer else {
            log::debug!(target: "wire", "Peer {remote} is not connected; ignoring flush");
            return;
        };
        let Some(s) = streams.get_mut(&stream) else {
            log::debug!(target: "wire", "Stream {stream} cannot be found; ignoring flush");
            return;
        };
        let metrics = self.metrics.peer(remote);

        for data in s.channels.try_iter() {
            let frame = match data {
                ChannelEvent::Data(data) => {
                    metrics.sent_git_bytes += data.len();
                    metrics.sent_bytes += data.len();
                    Frame::<service::Message>::git(stream, data)
                }
                ChannelEvent::Close => Frame::control(*link, frame::Control::Close { stream }),
                ChannelEvent::Eof => Frame::control(*link, frame::Control::Eof { stream }),
            };
            self.actions
                .push_back(reactor::Action::Send(fd, frame.encode_to_vec()));
        }
    }

    fn cleanup(&mut self, token: Token) {
        if self.inbound.remove(&token) {
            log::debug!(target: "wire", token=token.0; "Cleaning up inbound peer state");
        } else if let Some(outbound) = self.outbound.remove(&token) {
            log::debug!(target: "wire", token=token.0; "Cleaning up outbound peer state");
            self.service.disconnected(
                outbound.nid,
                Link::Outbound,
                &DisconnectReason::connection(),
            );
        } else {
            log::debug!(target: "wire", token=token.0; "Tried to cleanup unknown peer");
        }
    }
}

impl<D, S> reactor::ReactionHandler for Wire<D, S>
where
    D: service::Store + Send,
    S: WriteStorage + Send + 'static,
{
    type Listener = Listener;
    type Transport = Transport<WireSession>;

    fn tick(&mut self) {
        self.metrics.open_channels = self
            .peers
            .iter()
            .filter_map(|p| {
                if let Peer::Connected { streams, .. } = p {
                    Some(streams.streams.len())
                } else {
                    None
                }
            })
            .sum();
        self.metrics.worker_queue_size = self.worker.len();

        self.service.tick(LocalTime::now(), &self.metrics);
    }

    fn stopped(&mut self) -> bool {
        if !self.service.is_stopped() {
            return false;
        }
        if let Some(error) = self.service.take_fatal() {
            log::error!(target: "wire", "Stopping the node: {error}");
            self.stopped
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_or_insert(error);
        }
        true
    }

    fn timer_reacted(&mut self) {
        self.expire_resolutions(Instant::now());
        self.service.wake();
    }

    fn listener_reacted(
        &mut self,
        _: Token, // Note that this is the token of the listener socket.
        event: io::Result<(TcpStream, std::net::SocketAddr)>,
        _: Instant,
    ) {
        match event {
            Ok((connection, peer)) => {
                let remote = NetAddr::from(peer);
                let InetHost::Ip(ip) = remote.host else {
                    log::debug!(target: "wire", "Unexpected host type for inbound connection {remote}; dropping..");
                    drop(connection);

                    return;
                };
                log::debug!(target: "wire", "Inbound connection from {remote}..");

                // If the service doesn't want to accept this connection,
                // we drop the connection here, which disconnects the socket.
                if !self.service.accepted(ip) {
                    log::debug!(target: "wire", "Rejecting inbound connection from {ip}..");
                    drop(connection);

                    return;
                }

                let session = accept(remote.clone().into(), connection, self.secret_key.clone());
                let transport = match Transport::with_session(session) {
                    Ok(transport) => transport,
                    Err(err) => {
                        log::warn!(target: "wire", "Failed to create transport for accepted connection: {err}");
                        return;
                    }
                };

                let token = self.tokens.advance();
                log::debug!(target: "wire", token=token.0; "Accepted inbound connection from {remote}..");

                self.inbound.insert(token);
                self.actions
                    .push_back(reactor::Action::RegisterTransport(token, transport))
            }
            Err(err) => {
                log::error!(target: "wire", "Error listening for inbound connections: {err}");
            }
        }
    }

    fn listener_registered(&mut self, token: Token, _listener: &Self::Listener) {
        if let Some(local_addr) = self.listening.remove(&token) {
            self.service.listening(local_addr);
        }
    }

    fn transport_registered(&mut self, token: Token, _transport: &Self::Transport) {
        if let Some(outbound) = self.outbound.get(&token) {
            log::debug!(target: "wire", token=token.0; "Outbound peer resource registered for {}", outbound.nid);
        } else if self.inbound.contains(&token) {
            log::debug!(target: "wire", token=token.0; "Inbound peer resource registered");
        } else {
            log::debug!(target: "wire", token=token.0; "Unknown peer registered");
        }
    }

    fn transport_reacted(&mut self, token: Token, event: SessionEvent<WireSession>, _: Instant) {
        match event {
            SessionEvent::Established(ProtocolArtifact { state, session }) => {
                // SAFETY: With the NoiseXK protocol, there is always a remote static key.
                let nid: NodeId = NodeId::from(*state.remote_static_key.unwrap().public_key());
                // Make sure we don't try to connect to ourselves by mistake.
                if &nid == self.secret_key.public_key() {
                    log::warn!(target: "wire", "Self-connection detected, disconnecting..");
                    self.disconnect(token, DisconnectReason::SelfConnection);

                    return;
                }

                let established_addr: NetAddr<HostName> = session.state;
                let (addr, link) = if self.inbound.remove(&token) {
                    self.metrics.peer(nid).inbound_connection_attempts += 1;
                    (established_addr, Link::Inbound)
                } else if let Some(peer) = self.outbound.remove(&token) {
                    assert_eq!(nid, peer.nid);
                    (peer.addr, Link::Outbound)
                } else {
                    log::debug!(target: "wire", token=token.0; "Session for {nid} not found");
                    return;
                };
                log::debug!(
                    target: "wire", token=token.0, direction:display=link; "Session established with {nid}"
                );

                // Connections to close.
                let mut disconnect = Vec::new();

                // Handle conflicting connections.
                // This is typical when users have mutually configured their nodes to connect to
                // each other on startup. We handle this by deterministically choosing one node
                // whose outbound connection is the one that is kept. The other connections are
                // dropped.
                {
                    // Having precedence means that our outbound connection will win over
                    // the other node's outbound connection.
                    enum Precedence {
                        Ours,
                        Theirs,
                    }

                    use Link::*;
                    use Precedence::*;

                    // Whether we have precedence in case of conflicting connections.
                    let precedence = if NodeId::from(*self.secret_key.public_key()) > nid {
                        Ours
                    } else {
                        Theirs
                    };

                    // Active sessions with the same NID but a different token are conflicting.
                    let peers = self.peers.active().filter_map(|(c_id, d, link)| {
                        (*d == nid && c_id != token).then_some((c_id, link))
                    });

                    // Outbound connection attempts with the same remote key but a different file
                    // descriptor are conflicting.
                    let outbound = self.outbound.iter().filter_map(|(c_id, other)| {
                        (other.nid == nid && *c_id != token).then_some((*c_id, Outbound))
                    });

                    for (c_token, c_link) in peers.chain(outbound) {
                        // If we have precedence, the inbound connection is closed.
                        // In the case where both connections are inbound or outbound,
                        // we close the newer connection, ie. the one with the higher
                        // token.
                        let close = match (link, c_link, &precedence) {
                            (Inbound, Outbound, Ours) => token,
                            (Inbound, Outbound, Theirs) => c_token,
                            (Outbound, Inbound, Ours) => c_token,
                            (Outbound, Inbound, Theirs) => token,
                            (Inbound, Inbound, _) => token.max(c_token),
                            (Outbound, Outbound, _) => token.max(c_token),
                        };

                        log::trace!(
                            target: "wire", "Established session with token {} conflicts with existing session with token {} for {nid}. Disconnecting session with token {}.", token.0, c_token.0, close.0
                        );
                        disconnect.push(close);
                    }
                }
                for id in &disconnect {
                    log::info!(
                        target: "wire", token=token.0; "Closing conflicting session with {nid}.."
                    );
                    // Disconnect and return the associated NID of the peer, if available.
                    if let Some((nid, link)) = self.disconnect(*id, DisconnectReason::Conflict) {
                        // We disconnect the session eagerly because otherwise we will get the new
                        // `connected` event before the `disconnect`, resulting in a duplicate
                        // connection.
                        self.service
                            .disconnected(nid, link, &DisconnectReason::Conflict);
                    }
                }
                if !disconnect.contains(&token) {
                    self.peers
                        .insert(token, Peer::connected(nid, addr.clone(), link));
                    self.service.connected(nid, addr.into(), link);
                }
            }
            SessionEvent::Data(data) => {
                if let Some(Peer::Connected {
                    nid,
                    inbox,
                    streams,
                    ..
                }) = self.peers.get_mut(&token)
                {
                    let metrics = self.metrics.peer(*nid);
                    metrics.received_bytes += data.len();

                    if inbox.input(&data).is_err() {
                        log::warn!(target: "wire", "Maximum inbox size ({MAX_INBOX_SIZE}) reached for peer {nid}");
                        log::warn!(target: "wire", "Unable to process messages fast enough for peer {nid}; disconnecting..");
                        self.disconnect(
                            token,
                            DisconnectReason::Session(session::Error::Misbehavior),
                        );

                        return;
                    }

                    loop {
                        match inbox.deserialize_next() {
                            Ok(Some(Frame {
                                data: FrameData::Control(frame::Control::Open { stream }),
                                ..
                            })) => {
                                log::debug!(target: "wire", "Received `open` command for stream {stream} from {nid}");
                                metrics.streams_opened += 1;
                                metrics.received_fetch_requests += 1;
                                let limits = &self.service.config().limits;
                                let reader_limit = limits.fetch_pack_receive;
                                let fetch_timeout: time::Duration =
                                    LocalDuration::from(limits.fetch_timeout).into();
                                let Some(channels) = streams.register(
                                    stream,
                                    ChannelsConfig::new(fetch_timeout)
                                        .with_reader_limit(reader_limit),
                                ) else {
                                    log::debug!(target: "wire", "Peer attempted to open already-open stream {stream}");
                                    continue;
                                };

                                let task = Task {
                                    fetch: FetchRequest::Responder {
                                        remote: *nid,
                                        emitter: self.service.emitter(),
                                    },
                                    stream,
                                    channels,
                                };
                                if let Err(e) = self.worker.try_send(task) {
                                    log::warn!(
                                        target: "wire",
                                        "Worker pool failed to accept incoming fetch request: {e}"
                                    );
                                }
                            }
                            Ok(Some(Frame {
                                data: FrameData::Control(frame::Control::Eof { stream }),
                                ..
                            })) => {
                                if let Some(s) = streams.get(&stream) {
                                    log::debug!(target: "wire", "Received `end-of-file` on stream {stream} from {nid}");

                                    if s.channels.send(ChannelEvent::Eof).is_err() {
                                        log::debug!(target: "wire", "Worker is disconnected; cannot send `EOF`");
                                    }
                                } else {
                                    log::debug!(target: "wire", "Ignoring frame on closed or unknown stream {stream}");
                                }
                            }
                            Ok(Some(Frame {
                                data: FrameData::Control(frame::Control::Close { stream }),
                                ..
                            })) => {
                                log::debug!(target: "wire", "Received `close` command for stream {stream} from {nid}");

                                if let Some(s) = streams.unregister(&stream) {
                                    log::debug!(
                                        target: "wire",
                                        "Stream {stream} of {nid} closed with {} byte(s) sent and {} byte(s) received",
                                        s.sent_bytes, s.received_bytes
                                    );
                                    s.channels.close().ok();
                                }
                            }
                            Ok(Some(Frame {
                                data: FrameData::Gossip(msg),
                                ..
                            })) => {
                                metrics.received_gossip_messages += 1;
                                self.service.received_message(*nid, msg);
                            }
                            Ok(Some(Frame {
                                stream,
                                data: FrameData::Git(data),
                                ..
                            })) => {
                                if let Some(s) = streams.get_mut(&stream) {
                                    metrics.received_git_bytes += data.len();
                                    // Send via channel to the worker thread
                                    if s.channels.send(ChannelEvent::Data(data)).is_err() {
                                        log::warn!(target: "wire", "Worker is disconnected; cannot send data");
                                    }
                                } else {
                                    log::debug!(target: "wire", "Ignoring frame on closed or unknown stream {stream}");
                                }
                            }
                            Ok(None) => {
                                // Buffer is empty, or message isn't complete.
                                break;
                            }
                            Err(e) => {
                                log::warn!(target: "wire", "Invalid gossip message from {nid}: {e}");

                                if !inbox.is_empty() {
                                    log::debug!(target: "wire", "Dropping read buffer for {nid} with {} bytes", inbox.len());
                                }
                                self.disconnect(
                                    token,
                                    DisconnectReason::Session(session::Error::Misbehavior),
                                );
                                break;
                            }
                        }
                    }
                } else {
                    log::debug!(target: "wire", token=token.0; "Dropping message from unconnected peer");
                }
            }
            SessionEvent::Terminated(err) => {
                self.disconnect(token, DisconnectReason::Connection(Arc::new(err)));
            }
        }
    }

    fn handle_command(&mut self, cmd: Control) {
        match cmd {
            Control::User(cmd) => self.service.command(cmd),
            Control::Worker(result) => self.worker_result(result),
            Control::Flush { remote, stream } => self.flush(remote, stream),
            Control::Resolved { id, answers } => self.resolved(id, answers),
        }
    }

    fn handle_error(&mut self, err: reactor::Error<Listener, Transport<WireSession>>) {
        match err {
            reactor::Error::Poll(err) | reactor::Error::Registration(err) => {
                // TODO: This should be a fatal error, there's nothing we can do here.
                log::error!(target: "wire", "Can't poll connections: {err}");
            }
            reactor::Error::ListenerDisconnect(token, _) => {
                // TODO: This should be a fatal error, there's nothing we can do here.
                log::error!(target: "wire", token=token.0; "Listener disconnected");
            }
            reactor::Error::TransportDisconnect(token, transport) => {
                log::trace!(target: "wire", token=token.0; "Peer disconnected");

                // We're dropping the TCP connection here.
                drop(transport);

                // The peer transport is already disconnected and removed from the reactor;
                // therefore there is no need to initiate a disconnection. We simply remove
                // the peer from the map.
                match self.peers.remove(&token) {
                    Some(mut peer) => {
                        if let Peer::Connected { streams, .. } = &mut peer {
                            streams.shutdown();
                        }

                        if let Some(id) = peer.id() {
                            self.service.disconnected(
                                *id,
                                peer.link(),
                                &DisconnectReason::connection(),
                            );
                        } else {
                            log::debug!(target: "wire", "Inbound disconnection before handshake; ignoring..")
                        }
                    }
                    None => self.cleanup(token),
                }
            }
        }
    }

    fn handover_listener(&mut self, token: Token, _listener: Self::Listener) {
        log::warn!(target: "wire", token=token.0; "Listener handover is not supported");
    }

    fn handover_transport(&mut self, token: Token, transport: Self::Transport) {
        match self.peers.entry(token) {
            Entry::Occupied(e) => {
                match e.get() {
                    Peer::Disconnecting {
                        nid, reason, link, ..
                    } => {
                        log::debug!(target: "wire", token=token.0; "Transport handover for disconnecting peer");

                        // Disconnect TCP stream.
                        drop(transport);

                        // If there is no NID, the service is not aware of the peer.
                        if let Some(nid) = nid {
                            // In the case of a conflicting connection, there will be two resources
                            // for the peer. However, at the service level, there is only one, and
                            // it is identified by NID.
                            //
                            // Therefore, we specify which of the connections we're closing by
                            // passing the `link`.
                            self.service.disconnected(*nid, *link, reason);
                        }
                        e.remove();
                    }
                    Peer::Connected { nid, .. } => {
                        panic!(
                            "Wire::handover_transport: Unexpected handover of connected peer {nid} with token {}",
                            token.0
                        );
                    }
                }
            }
            Entry::Vacant(_) => self.cleanup(token),
        }
    }
}

impl<D, S> Iterator for Wire<D, S>
where
    D: service::Store,
    S: WriteStorage + 'static,
{
    type Item = Action;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(ev) = self.service.next() {
            match ev {
                Io::Write(node_id, msgs) => {
                    let (fd, link) = match self.peers.lookup(&node_id) {
                        Some((fd, Peer::Connected { link, .. })) => (fd, *link),
                        Some((_, peer)) => {
                            // If the peer is disconnected by the wire protocol, the service may
                            // not be aware of this yet, and may continue to write messages to it.
                            log::debug!(target: "wire", "Dropping {} message(s) to {node_id} ({peer:?})", msgs.len());
                            continue;
                        }
                        None => {
                            log::debug!(target: "wire", "Dropping {} message(s) to {node_id}: unknown peer", msgs.len());
                            continue;
                        }
                    };
                    log::trace!(
                        target: "wire", "Writing {} message(s) to {}", msgs.len(), node_id
                    );
                    let mut data = Vec::new();
                    let metrics = self.metrics.peer(node_id);
                    metrics.sent_gossip_messages += msgs.len();

                    for msg in msgs {
                        Frame::gossip(link, msg).encode(&mut data);
                    }
                    metrics.sent_bytes += data.len();

                    self.actions.push_back(reactor::Action::Send(fd, data));
                }
                Io::Connect(node_id, addr) => {
                    if self.peers.connected().any(|(_, id)| id == &node_id) {
                        log::debug!(
                            target: "wire",
                            "Attempt to connect to already connected peer {node_id}"
                        );
                        // FIXME: The problem here is the session will stay in "initial" state,
                        // because it can't transition to attempted.
                        continue;
                    }
                    self.service.attempted(node_id, addr.clone());
                    self.metrics.peer(node_id).outbound_connection_attempts += 1;

                    match route(&addr, self.service.config(), self.gate.as_ref()) {
                        Ok(Route::Resolve { host, port }) => {
                            self.resolve(node_id, addr, host, port)
                        }
                        Ok(route) => self.connect(node_id, addr, route),
                        Err(err) => self.dial_failed(node_id, &addr, err),
                    }
                }
                Io::Disconnect(nid, reason) => {
                    if let Some((id, Peer::Connected { .. })) = self.peers.lookup(&nid) {
                        if let Some((nid, _)) = self.disconnect(id, reason) {
                            self.metrics.peer(nid).disconnects += 1;
                        }
                    } else {
                        log::debug!(target: "wire", "Peer {nid} is not connected: ignoring disconnect");
                    }
                }
                Io::Wakeup(d) => {
                    self.actions.push_back(reactor::Action::SetTimer(d.into()));
                }
                Io::Fetch {
                    rid,
                    remote,
                    reader_limit,
                    refs_at,
                    config,
                } => {
                    log::trace!(target: "wire", "Processing fetch for {rid} from {remote}..");

                    let Some((fd, Peer::Connected { link, streams, .. })) =
                        self.peers.lookup_mut(&remote)
                    else {
                        // Nb. It's possible that a peer is disconnected while an `Io::Fetch`
                        // is in the service's i/o buffer. Since the service may not purge the
                        // buffer on disconnect, we drop fetches that don't have a connected peer.
                        // We must still report the failure so the fetcher clears its `active`
                        // entry; otherwise the repository can no longer be fetched from any node.
                        log::debug!(target: "wire", "Peer {remote} is not connected: dropping fetch");
                        self.service.fetched(
                            rid,
                            remote,
                            Err(protocol::worker::FetchError::Io(io::Error::new(
                                io::ErrorKind::NotConnected,
                                "peer disconnected before fetch could start",
                            ))),
                        );
                        continue;
                    };
                    let (stream, channels) = streams.open(
                        ChannelsConfig::new(config.timeout()).with_reader_limit(reader_limit),
                    );

                    log::debug!(target: "wire", "Opened new stream with id {stream} for {rid} and remote {remote}");

                    let link = *link;
                    let task = Task {
                        fetch: FetchRequest::Initiator {
                            rid,
                            remote,
                            refs_at,
                            config: config.fetch_config(),
                        },
                        stream,
                        channels,
                    };

                    if !self.worker.is_empty() {
                        log::warn!(
                            target: "wire",
                            "Worker pool is busy: {} tasks pending, fetch requests may be delayed", self.worker.len()
                        );
                    }
                    if let Err(e) = self.worker.try_send(task) {
                        log::warn!(
                            target: "wire",
                            "Worker pool failed to accept outgoing fetch request: {e}"
                        );
                    }
                    let metrics = self.metrics.peer(remote);
                    metrics.streams_opened += 1;
                    metrics.sent_fetch_requests += 1;

                    self.actions.push_back(Action::Send(
                        fd,
                        Frame::<service::Message>::control(link, frame::Control::Open { stream })
                            .encode_to_vec(),
                    ));
                }
            }
        }
        self.actions.pop_front()
    }
}

/// How to reach a peer address.
#[derive(Debug, PartialEq, Eq)]
enum Route {
    /// Open a connection to `connect`. Through a proxy, ask it for `socks`.
    Connect {
        connect: net::SocketAddr,
        socks: Option<NetAddr<HostName>>,
    },
    /// Resolve `host` first, off the reactor ([`checked`] then routes the answer).
    Resolve { host: String, port: u16 },
}

/// The refusal of an address the gate doesn't allow.
fn refused(addr: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{addr} is refused by the address policy"),
    )
}

/// How to reach `target`, given the node's configuration and its gate:
/// - an IP address is checked, then dialled, directly or through the proxy as
///   that IP address;
/// - a DNS name is resolved first, whether or not there is a proxy, so that
///   every address it resolves to is checked ([`checked`]). Only a gate that
///   lets the proxy resolve names ([`Gate::proxy_resolves_names`], as
///   [`radicle::node::dial::Open`] does) hands it the name instead;
/// - an onion or I2P name goes to the proxy its address family is configured
///   with, as the name, on a path of its own.
fn route(target: &Address, config: &radicle::node::Config, gate: &dyn Gate) -> io::Result<Route> {
    #[cfg(any(feature = "i2p", feature = "tor"))]
    fn proxy_or_forward<H: std::fmt::Display>(
        config: &AddressConfig,
        global_proxy: Option<net::SocketAddr>,
        host: HostName,
        name: H,
        port: u16,
    ) -> io::Result<Route> {
        match config {
            // In proxy mode, simply use the configured proxy address.
            // This takes precedence over any global proxy.
            AddressConfig::Proxy { address } => Ok(Route::Connect {
                connect: *address,
                socks: Some(NetAddr::new(host, port)),
            }),
            // In "forward" mode, if a global proxy is set, we use that; otherwise,
            // we treat the address as a regular DNS name.
            AddressConfig::Forward => Ok(match global_proxy {
                Some(proxy) => Route::Connect {
                    connect: proxy,
                    socks: Some(NetAddr::new(host, port)),
                },
                None => Route::Resolve {
                    host: name.to_string(),
                    port,
                },
            }),
            // If address type support isn't configured, refuse to connect.
            AddressConfig::Drop => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "no configuration found for address type",
            )),
        }
    }

    let port = target.port;
    match &target.host {
        HostName::Ip(ip) => {
            let addr = net::SocketAddr::new(*ip, port);
            if !gate.allows(target, &addr) {
                return Err(refused(addr));
            }
            Ok(through(addr, config.proxy))
        }
        HostName::Dns(name) => match config.proxy {
            Some(proxy) if gate.proxy_resolves_names() => Ok(Route::Connect {
                connect: proxy,
                socks: Some(NetAddr::new(HostName::Dns(name.clone()), port)),
            }),
            _ => Ok(Route::Resolve {
                host: name.clone(),
                port,
            }),
        },
        // For onion addresses, handle with care.
        #[cfg(feature = "tor")]
        host @ HostName::Tor(onion) => {
            proxy_or_forward(&config.onion, config.proxy, host.clone(), onion, port)
        }
        #[cfg(feature = "i2p")]
        host @ HostName::I2p(i2p) => {
            proxy_or_forward(&config.i2p, config.proxy, host.clone(), i2p, port)
        }
        #[allow(unreachable_patterns)]
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported remote address type",
        )),
    }
}

/// The route to a checked IP address: directly, or through `proxy` as that
/// IP address, never as a name.
fn through(addr: net::SocketAddr, proxy: Option<net::SocketAddr>) -> Route {
    match proxy {
        Some(proxy) => Route::Connect {
            connect: proxy,
            socks: Some(NetAddr::new(HostName::Ip(addr.ip()), addr.port())),
        },
        None => Route::Connect {
            connect: addr,
            socks: None,
        },
    }
}

/// The route for `target` once its name has resolved to `answers`: the first
/// address the gate allows. A failed lookup, an empty answer or one whose
/// every address is refused fails the dial; the name is never handed to a
/// proxy instead.
fn checked(
    target: &Address,
    answers: io::Result<Vec<net::SocketAddr>>,
    config: &radicle::node::Config,
    gate: &dyn Gate,
) -> io::Result<Route> {
    let answers = answers?;
    if answers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("{target} resolved to no address"),
        ));
    }
    let addr = answers
        .into_iter()
        .find(|addr| gate.allows(target, addr))
        .ok_or_else(|| refused(format!("every address {target} resolved to")))?;

    Ok(match &target.host {
        HostName::Dns(_) => through(addr, config.proxy),
        // An onion or I2P name forwarded without a proxy, as the node always
        // has: to the address its name resolves to, which a forwarder there
        // is asked for the name.
        host => Route::Connect {
            connect: addr,
            socks: Some(NetAddr::new(host.clone(), target.port)),
        },
    })
}

/// Establish a new outgoing connection, along `route`, which must be a
/// [`Route::Connect`].
fn dial(
    route: Route,
    remote_id: crypto::PublicKey,
    signer: crypto::SigningKey,
) -> io::Result<WireSession> {
    let Route::Connect { connect, socks } = route else {
        return Err(io::Error::other("a dial needs a resolved route"));
    };
    // TODO: Nicer error.
    let remote_id = crypto::VerifyingKey::try_from(&remote_id)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidInput, source.to_string()))?;

    // NOTE: Previously, here was a note about setting the timeout for connecting
    // to DEFAULT_DIAL_TIMEOUT, for which we have not figured out a way yet.
    // Generally, we should understand what happens if the following call to
    // `connect` fails. How do we learn about it? Where's the leak?

    let connection = TcpStream::connect(connect)?;

    // Through a proxy, the session asks it for `socks`; otherwise it talks to
    // the peer directly.
    let (remote_addr, force_proxy) = match socks {
        Some(socks) => (socks, true),
        None => (
            NetAddr::new(HostName::Ip(connect.ip()), connect.port()),
            false,
        ),
    };

    Ok(session(
        remote_addr,
        Some(remote_id),
        connection,
        force_proxy,
        signer,
    ))
}

/// Accept a new connection.
pub fn accept(
    remote_addr: NetAddr<HostName>,
    connection: TcpStream,
    secret_key: crypto::SigningKey,
) -> WireSession {
    session(remote_addr, None, connection, false, secret_key)
}

/// Create a new [`WireSession`].
fn session(
    remote_addr: NetAddr<HostName>,
    remote_id: Option<crypto::VerifyingKey>,
    connection: TcpStream,
    force_proxy: bool,
    secret_key: crypto::SigningKey,
) -> WireSession {
    if let Err(e) = connection.set_nodelay(true) {
        log::warn!(target: "wire", "Unable to set TCP_NODELAY on socket {connection:?}: {e}");
    }

    let connection = std::net::TcpStream::from(connection);

    if let Err(e) = connection.set_read_timeout(Some(DEFAULT_CONNECTION_TIMEOUT)) {
        log::warn!(target: "wire", "Unable to set TCP read timeout on socket {connection:?}: {e}");
    }

    if let Err(e) = connection.set_write_timeout(Some(DEFAULT_CONNECTION_TIMEOUT)) {
        log::warn!(target: "wire", "Unable to set TCP write timeout on socket {connection:?}: {e}");
    }

    #[cfg(feature = "socket2")]
    {
        let connection = socket2::SockRef::from(&connection);

        let ka = socket2::TcpKeepalive::new().with_time(time::Duration::from_secs(30));

        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "windows",
            target_os = "cygwin",
        ))]
        let ka = ka.with_interval(time::Duration::from_secs(10));

        #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "ios",
            target_os = "visionos",
            target_os = "linux",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "cygwin",
        ))]
        let ka = ka.with_retries(3);

        if let Err(e) = connection.set_tcp_keepalive(&ka) {
            log::warn!(target: "wire", "Failed to set TCP_KEEPALIVE on socket {connection:?}: {e}");
        }
    }

    #[cfg(not(feature = "socket2"))]
    log::debug!(target: "wire", "Not attempting to set TCP_KEEPALIVE on socket {connection:?}");

    let connection = TcpStream::from_std(connection);

    let proxy = {
        let socks5 = socks5::Socks5::with(remote_addr, force_proxy);
        Socks5Session::new(connection, socks5)
    };

    let mut random = [0; 32];
    getrandom::fill(&mut random).expect("failed get random bytes from the operating system");

    let noise = {
        let keyset = Keyset {
            e: crypto::SigningKey::from_seed(crypto::Seed::new(random)),
            s: Some(secret_key),
            re: None,
            rs: remote_id,
        };

        NoiseState::initialize::<{ Sha256::OUTPUT_LEN }>(NOISE_XK, remote_id.is_some(), &[], keyset)
    };

    WireSession::new(proxy, noise)
}

mod logger {
    use radicle::node::Address;

    pub fn establish_connection(addr: &Address, err: &std::io::Error) {
        use std::io::ErrorKind::*;
        match err.kind() {
            ConnectionRefused | ConnectionReset | HostUnreachable | ConnectionAborted
            | NotConnected => {
                log::info!(target: "wire", "Could not establish connection to {addr}: {err}")
            }
            _ => log::warn!(target: "wire", "Failed to establish connection to {addr}: {err}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use protocol::service::ServiceState as _;
    use protocol::service::{Message, ZeroBytes};
    use radicle::identity::RepoId;
    use radicle::node;
    use radicle::test::arbitrary;
    use radicle::test::storage::MockStorage;

    use crate::wire;
    use crate::wire::varint;

    /// A gate that allows only `allowed`, and answers every name with
    /// `answers`.
    #[derive(Debug, Default)]
    struct Fixed {
        allowed: Vec<net::IpAddr>,
        answers: Vec<net::SocketAddr>,
        proxy_resolves_names: bool,
    }

    impl Gate for Fixed {
        fn allows(&self, _target: &Address, addr: &net::SocketAddr) -> bool {
            self.allowed.contains(&addr.ip())
        }

        fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<net::SocketAddr>> {
            Ok(self.answers.clone())
        }

        fn proxy_resolves_names(&self) -> bool {
            self.proxy_resolves_names
        }
    }

    const ALLOWED: [u8; 4] = [203, 0, 113, 7];
    const REFUSED: [u8; 4] = [10, 0, 0, 7];
    const PROXY: ([u8; 4], u16) = ([127, 0, 0, 1], 9150);

    fn gate() -> Fixed {
        Fixed {
            allowed: vec![ALLOWED.into()],
            ..Fixed::default()
        }
    }

    fn config(proxy: bool) -> radicle::node::Config {
        let mut config = radicle::node::Config::test(node::Alias::new("dial"));
        if proxy {
            config.proxy = Some(PROXY.into());
            config.onion = AddressConfig::Proxy {
                address: PROXY.into(),
            };
        }
        config
    }

    fn address(s: &str) -> Address {
        s.parse().unwrap()
    }

    fn ip(addr: [u8; 4], port: u16) -> NetAddr<HostName> {
        NetAddr::new(HostName::Ip(addr.into()), port)
    }

    #[test]
    fn an_ip_address_is_checked_then_dialled() {
        let target = address("203.0.113.7:8776");
        assert_eq!(
            route(&target, &config(false), &gate()).unwrap(),
            Route::Connect {
                connect: (ALLOWED, 8776).into(),
                socks: None
            }
        );
        // Through the proxy, as that address.
        assert_eq!(
            route(&target, &config(true), &gate()).unwrap(),
            Route::Connect {
                connect: PROXY.into(),
                socks: Some(ip(ALLOWED, 8776)),
            }
        );
        let refused = route(&address("10.0.0.7:8776"), &config(true), &gate()).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_name_is_resolved_first_with_or_without_a_proxy() {
        let target = address("seed.example:8776");
        for proxy in [false, true] {
            assert_eq!(
                route(&target, &config(proxy), &gate()).unwrap(),
                Route::Resolve {
                    host: "seed.example".to_owned(),
                    port: 8776
                }
            );
        }
        // Only a gate that lets the proxy resolve names hands it the name, as
        // the node always did.
        let open = Fixed {
            proxy_resolves_names: true,
            ..gate()
        };
        assert_eq!(
            route(&target, &config(true), &open).unwrap(),
            Route::Connect {
                connect: PROXY.into(),
                socks: Some(NetAddr::new(HostName::Dns("seed.example".to_owned()), 8776)),
            }
        );
        assert_eq!(
            route(&target, &config(false), &open).unwrap(),
            Route::Resolve {
                host: "seed.example".to_owned(),
                port: 8776
            }
        );
    }

    #[test]
    fn a_resolved_name_goes_to_the_first_allowed_address_never_as_the_name() {
        let target = address("seed.example:8776");
        let answers = || Ok(vec![(REFUSED, 8776).into(), (ALLOWED, 8776).into()]);
        assert_eq!(
            checked(&target, answers(), &config(false), &gate()).unwrap(),
            Route::Connect {
                connect: (ALLOWED, 8776).into(),
                socks: None
            }
        );
        assert_eq!(
            checked(&target, answers(), &config(true), &gate()).unwrap(),
            Route::Connect {
                connect: PROXY.into(),
                socks: Some(ip(ALLOWED, 8776)),
            }
        );
    }

    #[test]
    fn a_failed_empty_or_refused_answer_fails_the_dial() {
        let target = address("seed.example:8776");
        for proxy in [false, true] {
            let config = config(proxy);
            let failed = checked(
                &target,
                Err(io::ErrorKind::NotFound.into()),
                &config,
                &gate(),
            );
            assert_eq!(failed.unwrap_err().kind(), io::ErrorKind::NotFound);
            let empty = checked(&target, Ok(vec![]), &config, &gate());
            assert_eq!(empty.unwrap_err().kind(), io::ErrorKind::AddrNotAvailable);
            let refused = checked(&target, Ok(vec![(REFUSED, 8776).into()]), &config, &gate());
            assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }

    // Review of heartwood #4, round 1: with `Open`, an onion or I2P name
    // forwarded without a proxy takes exactly the route it always has: its
    // name is resolved, and the address it resolves to is asked for the name
    // over SOCKS, byte for byte as before.
    #[test]
    fn a_forwarded_name_keeps_its_socks_handshake_under_open() {
        let open = radicle::node::dial::Open;
        let resolved: net::SocketAddr = (ALLOWED, 9050).into();
        let mut config = config(false);
        config.onion = AddressConfig::Forward;
        config.i2p = AddressConfig::Forward;
        for name in [
            "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion:8776",
            "f2atcc7udeub5kh4nkljtjwyk7ikjviorufzgwnfwhkphljl3vhq.b32.i2p:8776",
        ] {
            let target = address(name);
            let host = match route(&target, &config, &open).unwrap() {
                Route::Resolve { host, port } => {
                    assert_eq!(port, 8776);
                    host
                }
                other => panic!("{name}: unexpected route {other:?}"),
            };
            assert_eq!(format!("{host}:8776"), name);
            let Route::Connect { connect, socks } =
                checked(&target, Ok(vec![resolved]), &config, &open).unwrap()
            else {
                panic!("{name}: not a connection");
            };
            assert_eq!(connect, resolved);
            // What the node always sent: SOCKS to the resolved address, for
            // the name.
            let before = socks5::Socks5::with((*target).clone(), false)
                .advance(&[])
                .unwrap();
            let after = socks5::Socks5::with(socks.expect("SOCKS"), true)
                .advance(&[])
                .unwrap();
            assert_eq!(before, vec![5, 1, 0]);
            assert_eq!(after, before, "{name}");
        }
    }

    #[test]
    fn an_onion_name_goes_to_its_proxy_as_the_name() {
        let onion = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion:8776";
        let target = address(onion);
        match route(&target, &config(true), &gate()).unwrap() {
            Route::Connect {
                connect,
                socks: Some(socks),
            } => {
                assert_eq!(connect, net::SocketAddr::from(PROXY));
                assert!(matches!(socks.host, HostName::Tor(_)));
            }
            other => panic!("unexpected route {other:?}"),
        }
        // Without an onion route, it is refused before any socket.
        let dropped = route(&target, &config(false), &gate()).unwrap_err();
        assert_eq!(dropped.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_pong_message_with_extension() {
        use protocol::deserializer;

        let mut stream = Vec::new();
        let pong = Message::Pong {
            zeroes: ZeroBytes::new(42),
        };
        frame::PROTOCOL_VERSION_STRING.encode(&mut stream);
        frame::StreamId::gossip(Link::Outbound).encode(&mut stream);

        // Serialize gossip message with some extension fields.
        let mut gossip = pong.encode_to_vec();
        String::from("extra").encode(&mut gossip);
        48u8.encode(&mut gossip);

        // Encode gossip message using the varint-prefix format into the stream.
        varint::payload::encode(&gossip, &mut stream);

        let mut de = deserializer::Deserializer::<1024, Frame>::new(1024);
        de.input(&stream).unwrap();

        // The "pong" message decodes successfully, even though there is trailing data.
        assert_eq!(
            de.deserialize_next().unwrap().unwrap(),
            Frame::gossip(Link::Outbound, pong)
        );
        assert!(de.deserialize_next().unwrap().is_none());
        assert!(de.is_empty());
    }

    #[test]
    fn test_inventory_ann_with_extension() {
        use protocol::deserializer;

        #[derive(Debug)]
        struct MessageWithExt {
            msg: Message,
            ext: String,
        }

        impl wire::Encode for MessageWithExt {
            fn encode(&self, writer: &mut impl bytes::BufMut) {
                self.msg.encode(writer);
                self.ext.encode(writer);
            }
        }

        impl wire::Decode for MessageWithExt {
            fn decode(reader: &mut impl bytes::Buf) -> Result<Self, wire::Error> {
                let msg = Message::decode(reader)?;
                let ext = String::decode(reader).unwrap_or_default();

                Ok(MessageWithExt { msg, ext })
            }
        }

        let rid = arbitrary::r#gen(1);
        let pk = arbitrary::r#gen(1);
        let sig: [u8; 64] = arbitrary::r#gen(1);

        // Message with extension.
        let mut stream = Vec::new();
        let ann = Message::announcement(
            pk,
            service::gossip::inventory(radicle::node::Timestamp::MAX, [rid]),
            radicle::crypto::Signature::from(sig),
        );
        let pong = Message::Pong {
            zeroes: ZeroBytes::new(42),
        };
        // Framed message with extension.
        frame::Frame::gossip(
            Link::Outbound,
            MessageWithExt {
                msg: ann.clone(),
                ext: String::from("extra"),
            },
        )
        .encode(&mut stream);
        // Pong message that comes after, without extension.
        frame::Frame::gossip(Link::Outbound, pong.clone()).encode(&mut stream);

        // First test deserializing using the message with extension type.
        {
            let mut de = deserializer::Deserializer::<1024, Frame<MessageWithExt>>::new(1024);
            de.input(&stream).unwrap();

            radicle::assert_matches!(
                de.deserialize_next().unwrap().unwrap().data,
                FrameData::Gossip(MessageWithExt {
                    msg,
                    ext,
                }) if msg == ann && ext == *"extra"
            );
            radicle::assert_matches!(
                de.deserialize_next().unwrap().unwrap().data,
                FrameData::Gossip(MessageWithExt {
                    msg,
                    ext,
                }) if msg == pong && ext.is_empty()
            );
            assert!(de.deserialize_next().unwrap().is_none());
            assert!(de.is_empty());
        }

        // Then test deserializing using the current message type without the extension.
        {
            let mut de = deserializer::Deserializer::<1024, Frame<Message>>::new(1024);
            de.input(&stream).unwrap();

            radicle::assert_matches!(
                de.deserialize_next().unwrap().unwrap().data,
                FrameData::Gossip(msg)
                if msg == ann
            );
            radicle::assert_matches!(
                de.deserialize_next().unwrap().unwrap().data,
                FrameData::Gossip(msg)
                if msg == pong
            );
            assert!(de.deserialize_next().unwrap().is_none());
            assert!(de.is_empty());
        }
    }

    // Builds a service holding an active fetch from `bob`, wrapped in a `Wire`.
    // Returns the wire, the repo id, and bob's id/address.
    #[allow(clippy::type_complexity)]
    fn wire_with_active_fetch() -> (
        Wire<radicle::node::Database, MockStorage>,
        RepoId,
        NodeId,
        NetAddr<HostName>,
    ) {
        use crate::test::peer::Peer as TestPeer;

        let storage = arbitrary::nonempty_storage(1);
        let rid = *storage.repos.keys().next().unwrap();
        let mut alice = TestPeer::with_storage("alice", 7, storage);
        let bob = TestPeer::bob();
        let bob_id = *bob.nid();
        let bob_addr = NetAddr {
            host: HostName::Ip(net::IpAddr::from([8, 8, 8, 8])),
            port: node::DEFAULT_PORT,
        };

        // Start a fetch from Bob so the service holds `active[rid] = { from: bob }`.
        alice.connect_to(&bob);
        let (cmd, _recv) =
            protocol::service::Command::fetch(rid, bob_id, radicle::node::DEFAULT_TIMEOUT, None);
        alice.command(cmd);
        assert!(
            alice.fetches().any(|(r, _)| r == rid),
            "fetch should be initiated"
        );
        assert!(alice.fetcher().active_fetches().contains_key(&rid));

        let (worker_tx, _worker_rx) = chan::unbounded::<Task>();
        let wire = Wire::new(
            alice.into_service(),
            worker_tx,
            crypto::SigningKey::mock(100),
            Arc::new(radicle::node::dial::Open),
            resolver::Resolvers::closed(),
            Stopped::default(),
        );

        (wire, rid, bob_id, bob_addr)
    }

    fn timed_out_fetch_result(rid: RepoId, remote: NodeId) -> TaskResult {
        TaskResult {
            remote,
            stream: StreamId::git(Link::Outbound).nth(1).unwrap(),
            result: FetchResult::Initiator {
                rid,
                result: Err(protocol::worker::FetchError::Io(std::io::Error::from(
                    std::io::ErrorKind::TimedOut,
                ))),
            },
        }
    }

    // Regression test: a fetch result for a non-`Connected` peer must still reach
    // `service.fetched` so `active[rid]` is cleared; otherwise the repo can no
    // longer be fetched from any node until the process restarts.
    #[test]
    fn worker_result_clears_active_when_peer_disconnecting() {
        let (mut wire, rid, bob_id, _addr) = wire_with_active_fetch();

        // Bob is mid-disconnect at the wire layer: present, but not `Connected`.
        wire.peers.insert(
            Token(1),
            Peer::Disconnecting {
                link: Link::Outbound,
                nid: Some(bob_id),
                reason: DisconnectReason::connection(),
            },
        );

        wire.worker_result(timed_out_fetch_result(rid, bob_id));

        assert!(
            !wire.service.fetcher().active_fetches().contains_key(&rid),
            "fetch result must be reported even when the peer disconnected"
        );
    }

    // Contrast: with the peer still `Connected`, the active entry clears too,
    // confirming the test above exercises the disconnect path, not a vacuous
    // assertion.
    #[test]
    fn worker_result_clears_active_when_peer_connected() {
        let (mut wire, rid, bob_id, addr) = wire_with_active_fetch();

        wire.peers
            .insert(Token(1), Peer::connected(bob_id, addr, Link::Outbound));

        wire.worker_result(timed_out_fetch_result(rid, bob_id));

        assert!(
            !wire.service.fetcher().active_fetches().contains_key(&rid),
            "fetch result should have cleared active[rid]"
        );
    }
}
