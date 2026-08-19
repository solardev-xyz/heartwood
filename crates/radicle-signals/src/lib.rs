#[cfg(any(all(unix, not(target_os = "ios")), windows))]
use std::io;

// iOS: no signal handling — an embedded in-app node never installs
// process signal handlers, and the sem_safe transitive dependency does
// not compile for iOS (libc lacks `sem_getvalue` there). Only the
// `Signal` type is available, which is all the node runtime's channel
// plumbing needs.
#[cfg(all(unix, not(target_os = "ios")))]
mod unix;

#[cfg(all(unix, not(target_os = "ios")))]
pub use unix::*;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::*;

/// Operating system signal.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Signal {
    /// `SIGINT`.
    Interrupt,
    /// `SIGTERM`.
    Terminate,
    /// `SIGHUP`.
    Hangup,
    /// `SIGWINCH`.
    WindowChanged,
}

/// Return an error indicating that signal handling is already installed.
#[cfg(any(all(unix, not(target_os = "ios")), windows))]
#[inline(always)]
fn already_installed() -> io::Error {
    io::Error::new(
        io::ErrorKind::AlreadyExists,
        "signal handling is already installed",
    )
}
