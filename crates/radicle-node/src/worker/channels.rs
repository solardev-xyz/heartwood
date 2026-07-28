use std::io::{Read, Write};
use std::ops::Deref;
use std::{io, time};

use crossbeam_channel as chan;
use radicle::node::config::FetchPackSizeLimit;
use std::sync::Arc;
use tokio::sync::Notify;

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

    pub fn with_reader_limit(self, reader_limit: FetchPackSizeLimit) -> Self {
        Self {
            reader_limit,
            ..self
        }
    }

    pub fn timeout(self) -> time::Duration {
        self.timeout
    }

    pub fn reader_limit(self) -> FetchPackSizeLimit {
        self.reader_limit
    }
}

/// Async side of a worker byte-stream bridge.
pub struct NetworkChannels<T = Vec<u8>> {
    sender: chan::Sender<T>,
    receiver: chan::Receiver<T>,
    worker_data: Arc<Notify>,
    worker_space: Arc<Notify>,
}

impl<T: Send + 'static> NetworkChannels<T> {
    pub fn new(
        sender: chan::Sender<T>,
        receiver: chan::Receiver<T>,
        worker_data: Arc<Notify>,
        worker_space: Arc<Notify>,
    ) -> Self {
        Self {
            sender,
            receiver,
            worker_data,
            worker_space,
        }
    }

    /// Receive an event written by a blocking worker without blocking Tokio.
    pub async fn recv(&self) -> Result<T, chan::RecvError> {
        loop {
            let notified = self.worker_data.notified();
            match self.receiver.try_recv() {
                Ok(event) => return Ok(event),
                Err(chan::TryRecvError::Disconnected) => return Err(chan::RecvError),
                Err(chan::TryRecvError::Empty) => notified.await,
            }
        }
    }

    /// Send an event to a blocking worker while applying bounded backpressure.
    pub async fn send(&self, mut event: T) -> Result<(), chan::SendError<T>> {
        loop {
            let notified = self.worker_space.notified();
            match self.sender.try_send(event) {
                Ok(()) => return Ok(()),
                Err(chan::TrySendError::Disconnected(event)) => return Err(chan::SendError(event)),
                Err(chan::TrySendError::Full(next)) => {
                    event = next;
                    notified.await;
                }
            }
        }
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
    receiver: chan::Receiver<T>,
    space: Arc<Notify>,
    timeout: time::Duration,
    limiter: ReadLimiter,
}

impl<T> Deref for ChannelReader<T> {
    type Target = chan::Receiver<T>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl<T> ChannelReader<T> {
    pub fn new(
        receiver: chan::Receiver<T>,
        space: Arc<Notify>,
        timeout: time::Duration,
        limit: FetchPackSizeLimit,
    ) -> Self {
        Self {
            buffer: io::Cursor::new(Vec::new()),
            receiver,
            space,
            timeout,
            limiter: ReadLimiter::new(limit),
        }
    }

    pub(crate) fn timeout(&self) -> time::Duration {
        self.timeout
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
            Ok(data) => {
                self.space.notify_one();
                self.buffer = io::Cursor::new(data);
                self.buffer.read(buf)
            }
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
pub struct ChannelWriter<T = Vec<u8>> {
    sender: chan::Sender<T>,
    timeout: time::Duration,
    data: Arc<Notify>,
}

impl Write for ChannelWriter<Vec<u8>> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        self.send(buf.to_vec())?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<T> ChannelWriter<T> {
    pub fn new(sender: chan::Sender<T>, timeout: time::Duration, data: Arc<Notify>) -> Self {
        Self {
            sender,
            timeout,
            data,
        }
    }

    pub fn send(&self, event: impl Into<T>) -> io::Result<()> {
        match self.sender.send_timeout(event.into(), self.timeout) {
            Ok(()) => {
                self.data.notify_one();
                Ok(())
            }
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
}
