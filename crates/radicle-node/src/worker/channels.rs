use std::io::{Read, Write};
use std::ops::Deref;
use std::{fmt, io, time};

use crossbeam_channel as chan;
use radicle::node::NodeId;
use radicle::node::config::FetchPackSizeLimit;

use crate::runtime::handle::Handle;
use protocol::wire::StreamId;

/// Maximum size of channel used to communicate with a worker.
/// Note that as long as we're using [`std::io::copy`] to copy data from the
/// upload-pack's stdout, the data chunks are of a maximum size of 8192 bytes.
pub const MAX_WORKER_CHANNEL_SIZE: usize = 64;

/// The most data one channel event carries: a worker's larger write is split.
/// So that a channel holds at most `MAX_WORKER_CHANNEL_SIZE` events of this
/// size, and each becomes a wire frame a receiver's inbox can take.
pub const MAX_CHANNEL_EVENT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct ChannelsConfig {
    timeout: time::Duration,
    reader_limit: FetchPackSizeLimit,
}

impl ChannelsConfig {
    pub fn new(timeout: time::Duration) -> Self {
        Self {
            timeout,
            reader_limit: FetchPackSizeLimit::default(),
        }
    }

    pub fn with_timeout(self, timeout: time::Duration) -> Self {
        Self { timeout, ..self }
    }

    pub fn with_reader_limit(self, reader_limit: FetchPackSizeLimit) -> Self {
        Self {
            reader_limit,
            ..self
        }
    }
}

/// A reader and writer pair that can be used in the fetch protocol.
///
/// It implements [`radicle::fetch::transport::ConnectionStream`] to
/// provide its underlying channels for reading and writing.
pub struct ChannelsFlush {
    receiver: ChannelReader,
    sender: ChannelFlushWriter,
}

impl ChannelsFlush {
    pub fn new(handle: Handle, channels: Channels, remote: NodeId, stream: StreamId) -> Self {
        Self {
            receiver: channels.receiver,
            sender: ChannelFlushWriter {
                writer: channels.sender,
                stream,
                handle,
                remote,
            },
        }
    }

    pub fn split(&mut self) -> (&mut ChannelReader, &mut ChannelFlushWriter) {
        (&mut self.receiver, &mut self.sender)
    }

    pub fn timeout(&self) -> time::Duration {
        self.sender.writer.timeout.max(self.receiver.timeout)
    }

    /// The pack size limit of the stream: what a fetch reads at most, and
    /// what an upload sends at most.
    #[cfg(feature = "serve-in-process")]
    pub fn limit(&self) -> FetchPackSizeLimit {
        self.receiver.limiter.limit
    }
}

impl fetch::transport::ConnectionStream for ChannelsFlush {
    type Read = ChannelReader;
    type Write = ChannelFlushWriter;

    fn open(&mut self) -> (&mut Self::Read, &mut Self::Write) {
        (&mut self.receiver, &mut self.sender)
    }
}

/// Why an event wasn't sent without waiting.
pub enum TrySend<T> {
    /// The channel is full: the event, to send later.
    Full(ChannelEvent<T>),
    /// The other end is gone.
    Disconnected,
}

/// Data that can be sent and received on worker channels.
pub enum ChannelEvent<T = Vec<u8>> {
    /// Git protocol data.
    Data(T),
    /// A request to close the channel.
    Close,
    /// A signal that the git protocol has ended, eg. when the remote fetch closes the
    /// connection.
    Eof,
}

impl<T> From<T> for ChannelEvent<T> {
    fn from(value: T) -> Self {
        Self::Data(value)
    }
}

impl<T> fmt::Debug for ChannelEvent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(_) => write!(f, "ChannelEvent::Data(..)"),
            Self::Close => write!(f, "ChannelEvent::Close"),
            Self::Eof => write!(f, "ChannelEvent::Eof"),
        }
    }
}

/// Worker channels for communicating through the git stream with the remote.
pub struct Channels<T = Vec<u8>> {
    sender: ChannelWriter<T>,
    receiver: ChannelReader<T>,
}

impl<T: AsRef<[u8]>> Channels<T> {
    pub fn new(
        sender: chan::Sender<ChannelEvent<T>>,
        receiver: chan::Receiver<ChannelEvent<T>>,
        config: ChannelsConfig,
    ) -> Self {
        let sender = ChannelWriter {
            sender,
            timeout: config.timeout,
        };
        let receiver = ChannelReader::new(receiver, config.timeout, config.reader_limit);

        Self { sender, receiver }
    }

    pub fn pair(config: ChannelsConfig) -> io::Result<(Channels<T>, Channels<T>)> {
        let (l_send, r_recv) = chan::bounded::<ChannelEvent<T>>(MAX_WORKER_CHANNEL_SIZE);
        let (r_send, l_recv) = chan::bounded::<ChannelEvent<T>>(MAX_WORKER_CHANNEL_SIZE);

        let l = Channels::new(l_send, l_recv, config);
        let r = Channels::new(r_send, r_recv, config);

        Ok((l, r))
    }

    pub fn try_iter(&self) -> impl Iterator<Item = ChannelEvent<T>> + '_ {
        self.receiver.try_iter()
    }

    /// Whether no event waits to be taken.
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    pub fn send(&self, event: ChannelEvent<T>) -> io::Result<()> {
        self.sender.send(event)
    }

    /// Sends `event` if the channel has room, without waiting: the event back
    /// if it hasn't.
    pub fn try_send(&self, event: ChannelEvent<T>) -> Result<(), TrySend<T>> {
        match self.sender.sender.try_send(event) {
            Ok(()) => Ok(()),
            Err(chan::TrySendError::Full(event)) => Err(TrySend::Full(event)),
            Err(chan::TrySendError::Disconnected(_)) => Err(TrySend::Disconnected),
        }
    }

    /// Closes the stream, without waiting ([`ChannelWriter::close`]).
    pub fn close(self) {
        self.sender.close()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ReadLimiter {
    limit: FetchPackSizeLimit,
    total_read: usize,
}

impl ReadLimiter {
    pub fn new(limit: FetchPackSizeLimit) -> Self {
        Self {
            limit,
            total_read: 0,
        }
    }

    pub fn read(&mut self, bytes: usize) -> io::Result<()> {
        self.total_read = self.total_read.saturating_add(bytes);
        log::trace!(target: "worker", "limit {}, total bytes read: {}", self.limit, self.total_read);
        if self.limit.exceeded_by(self.total_read) {
            Err(io::Error::other(
                "sender has exceeded number of allowed bytes, aborting read",
            ))
        } else {
            Ok(())
        }
    }
}

/// Wraps a [`chan::Receiver`] and provides it with [`io::Read`].
#[derive(Clone)]
pub struct ChannelReader<T = Vec<u8>> {
    buffer: io::Cursor<Vec<u8>>,
    receiver: chan::Receiver<ChannelEvent<T>>,
    timeout: time::Duration,
    limiter: ReadLimiter,
}

impl<T> Deref for ChannelReader<T> {
    type Target = chan::Receiver<ChannelEvent<T>>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl<T: AsRef<[u8]>> ChannelReader<T> {
    pub fn new(
        receiver: chan::Receiver<ChannelEvent<T>>,
        timeout: time::Duration,
        limit: FetchPackSizeLimit,
    ) -> Self {
        Self {
            buffer: io::Cursor::new(Vec::new()),
            receiver,
            timeout,
            limiter: ReadLimiter::new(limit),
        }
    }
}

impl Read for ChannelReader<Vec<u8>> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.buffer.read(buf)?;
        self.limiter.read(read)?;
        if read > 0 {
            return Ok(read);
        }

        match self.receiver.recv_timeout(self.timeout) {
            Ok(ChannelEvent::Data(data)) => {
                self.buffer = io::Cursor::new(data);
                self.buffer.read(buf)
            }
            Ok(ChannelEvent::Eof) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(ChannelEvent::Close) => Err(io::ErrorKind::ConnectionReset.into()),

            Err(chan::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "error reading from stream: channel timed out",
            )),
            Err(chan::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "error reading from stream: channel is disconnected",
            )),
        }
    }
}

/// Wraps a [`chan::Sender`] and provides it with [`io::Write`].
#[derive(Clone)]
struct ChannelWriter<T = Vec<u8>> {
    sender: chan::Sender<ChannelEvent<T>>,
    timeout: time::Duration,
}

/// Wraps a [`ChannelWriter`] alongside the associated [`Handle`] and [`NodeId`].
///
/// This allows the channel to [`Write::flush`] when calling
/// [`Write::write`], which is necessary to signal to the
/// controller to send the wire data.
pub struct ChannelFlushWriter<T = Vec<u8>> {
    writer: ChannelWriter<T>,
    handle: Handle,
    stream: StreamId,
    remote: NodeId,
}

impl fetch::transport::SignalEof for ChannelFlushWriter<Vec<u8>> {
    fn eof(&mut self) -> io::Result<()> {
        self.writer.send(ChannelEvent::Eof)?;
        self.flush()
    }
}

impl Write for ChannelFlushWriter<Vec<u8>> {
    /// Sends `buf` as events of at most [`MAX_CHANNEL_EVENT`] bytes each.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for chunk in buf.chunks(MAX_CHANNEL_EVENT) {
            self.writer.send(chunk.to_vec())?;
        }
        self.flush()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush(self.remote, self.stream)
    }
}

impl<T: AsRef<[u8]>> ChannelWriter<T> {
    pub fn send(&self, event: impl Into<ChannelEvent<T>>) -> io::Result<()> {
        match self.sender.send_timeout(event.into(), self.timeout) {
            Ok(()) => Ok(()),
            Err(chan::SendTimeoutError::Timeout(_)) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "error writing to stream: channel timed out",
            )),
            Err(chan::SendTimeoutError::Disconnected(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "error writing to stream: channel is disconnected",
            )),
        }
    }

    /// Permanently close this stream, without waiting: if its channel is
    /// full, dropping the sender closes it all the same, and the other end
    /// sees it disconnected.
    pub fn close(self) {
        self.sender.try_send(ChannelEvent::Close).ok();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use std::io::Write as _;
    use std::sync::Arc;

    use super::*;
    use crate::reactor::Controller;
    use radicle::profile::Home;

    // Review of heartwood #11, round 1: a worker's write is split into
    // events of at most `MAX_CHANNEL_EVENT`, so that no event, and no frame
    // made of one, is larger whatever the worker writes.
    #[test]
    fn a_write_is_split_into_bounded_events() {
        let tmp = tempfile::tempdir().unwrap();
        let poll = mio::Poll::new().unwrap();
        let waker = Arc::new(mio::Waker::new(poll.registry(), mio::Token(0)).unwrap());
        let (sender, _commands) = chan::unbounded();
        let handle = Handle::new(
            Home::new(tmp.path().join("home")).unwrap(),
            None,
            Controller::new(sender, waker),
            Default::default(),
        );
        let (wire, worker) =
            Channels::<Vec<u8>>::pair(ChannelsConfig::new(time::Duration::from_secs(1))).unwrap();
        let remote = radicle::test::arbitrary::r#gen(1);
        let stream = StreamId::git(radicle::node::Link::Outbound).nth(1).unwrap();
        let mut flush = ChannelsFlush::new(handle, worker, remote, stream);
        let (_, writer) = flush.split();
        let data = vec![5u8; 3 * MAX_CHANNEL_EVENT + 7];
        assert_eq!(writer.write(&data).unwrap(), data.len());
        let events = wire
            .try_iter()
            .map(|event| match event {
                ChannelEvent::Data(data) => data.len(),
                _ => panic!("not data"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            [MAX_CHANNEL_EVENT, MAX_CHANNEL_EVENT, MAX_CHANNEL_EVENT, 7]
        );
    }
}
