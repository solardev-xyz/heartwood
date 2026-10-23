//! What a node may dial: which peer addresses it may connect to, and how it
//! resolves the names among them.
//!
//! A host that embeds the node decides, by handing its runtime a [`Gate`].
//! [`Open`] keeps the node's own behaviour: every address is allowed, and
//! names are resolved by the system resolver.

use std::fmt;
use std::io;
use std::net;
use std::time::Duration;

use super::Address;

/// Decides which addresses a node may connect to, and resolves names.
pub trait Gate: Send + Sync + fmt::Debug {
    /// Whether the node may connect to `addr`, an IP address and port, for
    /// the peer address `target`: the same address, for an IP target, or
    /// the name `addr` was resolved from, for a DNS target.
    ///
    /// Also asked of the IP addresses a peer announces, before they enter
    /// the address book.
    fn allows(&self, target: &Address, addr: &net::SocketAddr) -> bool;

    /// The addresses `host` resolves to, for `port`.
    ///
    /// Called on a thread of its own, never on the node's reactor. The node
    /// waits for the answer for [`Gate::resolve_timeout`] at most, then fails
    /// the dial; a resolver should bound its own work too.
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<net::SocketAddr>>;

    /// How long a dial waits for [`Gate::resolve`] before it fails.
    fn resolve_timeout(&self) -> Duration {
        RESOLVE_TIMEOUT
    }

    /// Whether a node that dials through a proxy hands it a DNS name to
    /// resolve, rather than resolving the name with [`Gate::resolve`] and
    /// asking the proxy for a checked address. `false` unless a gate says
    /// otherwise: only then is every address the node connects to checked.
    fn proxy_resolves_names(&self) -> bool {
        false
    }
}

/// How long a dial waits for its name to resolve, unless a gate says otherwise.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// The node's own behaviour: every address is allowed, names are resolved
/// by the system resolver, and a proxy is handed names to resolve itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct Open;

impl Gate for Open {
    fn allows(&self, _target: &Address, _addr: &net::SocketAddr) -> bool {
        true
    }

    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<net::SocketAddr>> {
        use std::net::ToSocketAddrs as _;

        Ok((host, port).to_socket_addrs()?.collect())
    }

    fn proxy_resolves_names(&self) -> bool {
        true
    }
}
