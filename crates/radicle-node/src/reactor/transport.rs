use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::{fmt, io};

use mio::event::{Event, Source};
use mio::{Interest, Registry, Token};

use crate::reactor::EventHandler;
use crate::reactor::session::Session;

const READ_BUFFER_SIZE: usize = u16::MAX as usize;

/// The most reads one readiness event takes: the reactor re-registers every
/// transport each turn, so data left in the socket is read on the next one.
/// So what a turn hands the handler is bounded, whatever the socket holds.
const READS_PER_TURN: usize = 4;

/// An event happening for a [`Transport`] network transport and delivered to
/// a [`ReactionHandler`].
///
/// [`ReactionHandler`]: crate::reactor::ReactionHandler
pub enum SessionEvent<S: Session> {
    Established(S::Artifact),
    Data(Vec<u8>),
    Terminated(io::Error),
}

impl<S: Session> SessionEvent<S> {
    fn is_connection_reset(&self) -> bool {
        matches!(self, SessionEvent::Terminated(err) if err.kind() == io::ErrorKind::ConnectionReset)
    }
}

/// A state of [`Transport`] network transport.
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum TransportState {
    /// The transport is initiated, but the connection has not been established yet.
    /// This happens only for outgoing connections due to the use of
    /// non-blocking calls to `connect`. The state changes once
    /// we receive the first notification on a `write` event on this resource
    /// from the reactor.
    Init,

    /// The connection is established, but the session handshake is still in
    /// progress. This happens while encryption handshake, authentication and
    /// other protocols injected into the session haven't completed yet.
    Handshake,

    /// The session is active. All handshakes have completed.
    Active,

    /// Session was terminated (for an unspecified reason, e.g. local shutdown,
    /// remote orderly shutdown, connectivity issue, dropped connections,
    /// encryption, or authentication problem etc.
    /// Reading and writing from the resource in
    /// this state will result in an error ([`io::Error`]).
    Terminated,
}

/// Transport is an adaptor around a specific [`Session`] (implementing
/// session management, including optional handshake, encoding, etc.) to be used
/// as a transport resource in a [`crate::reactor::Reactor`].
pub struct Transport<S: Session> {
    state: TransportState,
    session: S,
    write_intent: bool,
    read_buffer: Box<[u8; READ_BUFFER_SIZE]>,
    write_buffer: VecDeque<u8>,
    /// How many bytes `write_buffer` holds, shared with the handler, so that
    /// it can hold back what it would add to a buffer already full.
    buffered: Arc<AtomicUsize>,
    /// Whether it reads from its session, set by the handler: cleared while
    /// the handler can't take more from it, so that the peer waits.
    reading: Arc<AtomicBool>,
}

impl<S: Session> std::fmt::Debug for Transport<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("state", &self.state)
            .field("write_intent", &self.write_intent)
            .finish()
    }
}

impl<S: Session + Source> Source for Transport<S> {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.session.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.session.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.session.deregister(registry)
    }
}

impl<S: Session> Display for Transport<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.session.artifact() {
            None => f
                .debug_struct("Transport")
                .field("state", &self.state)
                .field("write_intent", &self.write_intent)
                .finish(),
            Some(id) => Display::fmt(&id, f),
        }
    }
}

impl<S: Session> Transport<S> {
    /// Constructs reactor-managed resource around an existing [`Session`].
    ///
    /// Must not be called for connections created in a non-blocking mode!
    ///
    /// # Errors
    ///
    /// If a session can be put into a non-blocking mode.
    pub fn with_session(session: S) -> io::Result<Self> {
        let state = if session.is_established() {
            // If we are disconnected, we will get instantly updated from the
            // reactor and the state will change automatically
            TransportState::Active
        } else {
            TransportState::Handshake
        };
        Ok(Self {
            state,
            session,
            write_intent: true,
            read_buffer: Box::new([0u8; READ_BUFFER_SIZE]),
            write_buffer: VecDeque::new(),
            buffered: Arc::default(),
            reading: Arc::new(AtomicBool::new(true)),
        })
    }

    /// What it is to be registered for.
    fn wanted(&self) -> Option<Interest> {
        use TransportState::*;
        use mio::Interest;

        // While the handler has paused reading, only writes are of interest
        // (a registration needs one interest: writable is the one that costs
        // nothing on an idle socket).
        let reading = self.reading.load(Ordering::Relaxed);
        match self.state {
            Init => Some(Interest::WRITABLE),
            Active if !reading => Some(Interest::WRITABLE),
            Active | Handshake if self.write_intent => {
                Some(Interest::READABLE | Interest::WRITABLE)
            }
            Active | Handshake => Some(Interest::READABLE),
            Terminated => None,
        }
    }

    /// Whether it reads from its session: the handler clears it to stop
    /// reading, and sets it again to resume.
    pub fn reading(&self) -> Arc<AtomicBool> {
        self.reading.clone()
    }

    /// How many bytes its write buffer holds, as it changes: what is buffered
    /// and not yet written to the session.
    pub fn buffered(&self) -> Arc<AtomicUsize> {
        self.buffered.clone()
    }

    pub fn display(&self) -> impl Display {
        self.session
            .artifact()
            .map(|artifact| artifact.to_string())
            .unwrap_or_else(|| "<no-artifact>".to_string())
    }

    fn terminate(&mut self, reason: io::Error) -> SessionEvent<S> {
        log::trace!(target: "transport", "Terminating session {self} due to {reason:?}");

        self.state = TransportState::Terminated;
        SessionEvent::Terminated(reason)
    }

    /// This function is responsible for draining readiness.
    /// According to the `mio` documentation, this means that I/O operations
    /// should be performed until they would block.
    ///
    /// Therefore [`Self::handle_readable`] and [`Self::handle_writable`]
    /// implement corresponding loops.
    ///
    /// See <https://github.com/tokio-rs/mio/blob/v1.1.1/src/poll.rs#L108-L115>.
    fn handle_io(&mut self, interest: Interest, events: &mut Vec<SessionEvent<S>>) {
        let mut force_write_intent = false;
        if self.state == TransportState::Init {
            log::debug!(target: "transport", "Transport {self} is connected, initializing handshake");

            force_write_intent = true;
            self.state = TransportState::Handshake;
        } else if self.state == TransportState::Handshake {
            debug_assert!(!self.session.is_established());

            log::trace!(target: "transport", "Transport {self} got I/O while in handshake mode");
        }

        match interest {
            Interest::READABLE => self.handle_readable(events),
            Interest::WRITABLE => self.handle_writable(events),
            _ => unreachable!(),
        };

        if force_write_intent {
            self.write_intent = true;
        } else if self.state == TransportState::Handshake {
            // During handshake, after each read we need to write and then wait
            self.write_intent = interest == Interest::READABLE;
        }

        if events.iter().any(|event| event.is_connection_reset())
            && self.state != TransportState::Handshake
        {
            log::debug!(target: "transport", "Peer {self} has reset the connection");

            self.state = TransportState::Terminated;
        } else if self.session.is_established() && self.state == TransportState::Handshake {
            log::debug!(target: "transport", "Handshake with {self} is complete");

            // We just got connected; may need to send output
            self.write_intent = true;
            self.state = TransportState::Active;
            events.push(SessionEvent::Established(
                self.session.artifact().expect("session is established"),
            ));
        }
    }

    fn handle_writable(&mut self, events: &mut Vec<SessionEvent<S>>) {
        use io::ErrorKind::*;

        if !self.session.is_established() {
            let _ = self.session.write(&[]);
            self.write_intent = true;
            return;
        }

        self.write_buffer.make_contiguous();
        let n = self.write_buffer.len();

        log::trace!(target: "transport", "Resource {} is flushing its buffer of {n} bytes", self.display());

        /// Accumulates multiple writes.
        struct Written {
            /// The cumulative number of bytes successfully written to
            /// `self.session` and drained from `self.write_buffer`.
            n: usize,
            /// The first error encountered while writing to `self.session`,
            /// if any. Note that this error might be of kind
            /// [`WouldBlock`] which only indicates that
            /// `self.session` is not ready to accept more data.
            err: Option<io::Error>,
        }

        let written = {
            let mut n = 0;

            // This loop is a bit like [`std::io::copy`], but by breaking on
            // `Written`, we keep track of how many bytes were successfully
            // written, even if an error (in particular [`WouldBlock`])
            // occurs.
            loop {
                // Since `self.write_buffer` is contiguous, we can get a single slice of it.
                let slice = {
                    let slices = self.write_buffer.as_slices();

                    // Assert guarantees of earlier call to `self.write_buffer.make_contiguous()`.
                    debug_assert_eq!(
                        slices.0.len(),
                        self.write_buffer.len(),
                        "write buffer is not contiguous"
                    );
                    debug_assert_eq!(slices.1.len(), 0, "write buffer is not contiguous");

                    // Since `self.write_buffer` is contiguous, disregard the second
                    // (empty!) slice.
                    slices.0
                };

                if slice.is_empty() {
                    // There are no more bytes in `self.write_buffer` to write.
                    break Written { n, err: None };
                }

                n += match self.session.write(slice) {
                    Ok(n) => {
                        self.write_buffer.drain(..n);
                        n
                    }
                    Err(err) if err.kind() == Interrupted => 0,
                    Err(err) => break Written { n, err: Some(err) },
                };
            }
        };

        debug_assert!(
            written.n <= n,
            "written more bytes than were in the write buffer (wrote {} out of {} bytes)",
            written.n,
            n
        );

        self.write_intent = n > written.n;
        self.buffered
            .store(self.write_buffer.len(), Ordering::Relaxed);

        if self.write_intent {
            log::debug!(target: "transport", "Resource {} was able to consume only a part of the buffered data ({} of {n} bytes)", written.n, self.display());
        } else {
            log::trace!(target: "transport", "Resource {} was able to consume all of the buffered data ({} of {n} bytes)", written.n, self.display());
        }

        if let Some(err) = written.err
            && err.kind() != WouldBlock
            && err.kind() != WriteZero
        {
            events.push(self.terminate(err))
        }
    }

    fn handle_readable(&mut self, events: &mut Vec<SessionEvent<S>>) {
        use io::ErrorKind::*;

        let mut reads = 0;
        loop {
            // Paused, or done for this turn: what is left waits in the socket.
            if !self.reading.load(Ordering::Relaxed) || reads >= READS_PER_TURN {
                return;
            }
            match self.session.read(self.read_buffer.as_mut()) {
                Ok(0) => {}
                Ok(len) => {
                    events.push(SessionEvent::Data(self.read_buffer[..len].to_vec()));
                    reads += 1;
                    continue;
                }
                Err(err) if err.kind() == Interrupted => continue,
                Err(err) if err.kind() == WouldBlock => {}
                Err(err) => {
                    events.push(self.terminate(err));
                }
            }
            return;
        }
    }
}

impl<S: Session + Source> EventHandler for Transport<S> {
    type Reaction = SessionEvent<S>;

    fn interests(&self) -> Option<Interest> {
        self.wanted()
    }

    fn handle(&mut self, event: &Event) -> Vec<Self::Reaction> {
        let mut events = Vec::new();

        if self.state == TransportState::Terminated {
            log::debug!(target: "transport", "Transport {self} is terminated, ignoring I/O event");
            return events;
        }

        if event.is_writable() {
            self.handle_io(Interest::WRITABLE, &mut events);
        }

        if event.is_readable() {
            self.handle_io(Interest::READABLE, &mut events);
        }

        events
    }
}

impl<S: Session> super::BufferWrite for Transport<S> {
    fn buffer_write(&mut self, buf: &[u8]) {
        assert_eq!(
            self.state,
            TransportState::Active,
            "buffer_write called when transport is not active"
        );

        if buf.is_empty() {
            return;
        }

        self.write_buffer.extend(buf);
        self.buffered
            .store(self.write_buffer.len(), Ordering::Relaxed);
        self.write_intent = true;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::io::{Read, Write};

    use super::super::BufferWrite as _;
    use super::*;

    /// A session that takes at most `accept` bytes a write, then blocks.
    struct Slow {
        accept: usize,
        written: Vec<u8>,
    }

    impl Read for Slow {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl Write for Slow {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.accept == 0 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let n = buf.len().min(self.accept);
            self.accept -= n;
            self.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Session for Slow {
        type Artifact = String;

        fn artifact(&self) -> Option<String> {
            Some("slow".to_owned())
        }
    }

    /// A session that always has bytes to read, and counts the reads.
    struct Endless {
        reads: usize,
    }

    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            buf.fill(7);
            Ok(buf.len())
        }
    }

    impl Write for Endless {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Session for Endless {
        type Artifact = String;

        fn artifact(&self) -> Option<String> {
            Some("endless".to_owned())
        }
    }

    // Security R-10: a turn reads a bounded amount, whatever the socket holds,
    // and none while the handler has paused reading; then only writes are of
    // interest.
    #[test]
    fn its_reads_are_bounded_a_turn_and_pause_at_the_handler_s_word() {
        let mut transport = Transport::with_session(Endless { reads: 0 }).unwrap();
        let mut events = Vec::new();
        transport.handle_readable(&mut events);
        assert_eq!(transport.session.reads, READS_PER_TURN);
        assert_eq!(events.len(), READS_PER_TURN);

        let reading = transport.reading();
        reading.store(false, Ordering::Relaxed);
        transport.handle_readable(&mut events);
        assert_eq!(transport.session.reads, READS_PER_TURN);
        assert_eq!(transport.wanted(), Some(Interest::WRITABLE));

        reading.store(true, Ordering::Relaxed);
        assert!(transport.wanted().unwrap().is_readable());
        transport.handle_readable(&mut events);
        assert_eq!(transport.session.reads, 2 * READS_PER_TURN);
    }

    // Security R-10: the handler sees how much a transport has buffered, as
    // it is buffered and as it is written.
    #[test]
    fn its_buffered_bytes_follow_its_write_buffer() {
        let mut transport = Transport::with_session(Slow {
            accept: 300,
            written: Vec::new(),
        })
        .unwrap();
        let buffered = transport.buffered();
        assert_eq!(buffered.load(Ordering::Relaxed), 0);
        transport.buffer_write(&[1; 1_000]);
        assert_eq!(buffered.load(Ordering::Relaxed), 1_000);

        let mut events = Vec::new();
        transport.handle_writable(&mut events);
        assert!(events.is_empty());
        assert_eq!(transport.session.written.len(), 300);
        assert_eq!(buffered.load(Ordering::Relaxed), 700);

        transport.session.accept = usize::MAX;
        transport.handle_writable(&mut events);
        assert_eq!(buffered.load(Ordering::Relaxed), 0);
    }
}
