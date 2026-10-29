//! The node's SOCKS5 client handshake ([RFC 1928]), with username and
//! password authentication ([RFC 1929]), as a state machine its session
//! drives.
//!
//! With credentials, it offers username and password authentication only, so
//! that a proxy that won't take them fails the dial rather than letting it
//! share another's circuits. Without them, it offers no authentication, as
//! the node always has. Every reply is parsed strictly, at exactly the length
//! its fields give.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929

use std::net::IpAddr;

use cyphernet::addr::{HostName, NetAddr};
use thiserror::Error;

/// SOCKS version 5.
const VERSION: u8 = 0x05;
/// The username/password subnegotiation's version.
const AUTH_VERSION: u8 = 0x01;
/// No authentication.
const NO_AUTH: u8 = 0x00;
/// Username and password.
const USERNAME_PASSWORD: u8 = 0x02;
/// The server's refusal of every method offered.
const NO_ACCEPTABLE_METHOD: u8 = 0xff;
/// `CONNECT`.
const CONNECT: u8 = 0x01;
/// An IPv4 address.
const IPV4: u8 = 0x01;
/// A domain name.
const DOMAIN: u8 = 0x03;
/// An IPv6 address.
const IPV6: u8 = 0x04;

/// A handshake's failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The input isn't the length the handshake asked for.
    #[error("a SOCKS5 reply of {got} bytes, where {expected} were expected")]
    Length { expected: usize, got: usize },
    /// A reply of another protocol version.
    #[error("a SOCKS5 reply of version {0}")]
    Version(u8),
    /// The proxy accepts none of the methods offered.
    #[error("the SOCKS5 proxy accepts none of the authentication methods offered")]
    NoAcceptableMethod,
    /// The proxy chose a method that wasn't offered.
    #[error("the SOCKS5 proxy chose authentication method {0}, which wasn't offered")]
    MethodNotOffered(u8),
    /// The proxy refused the credentials.
    #[error("the SOCKS5 proxy refused the credentials (status {0})")]
    AuthFailed(u8),
    /// The proxy refused the connection.
    #[error("the SOCKS5 proxy refused the connection (reply {0})")]
    Refused(u8),
    /// A reply whose reserved byte isn't zero.
    #[error("a SOCKS5 reply whose reserved byte is {0}")]
    Reserved(u8),
    /// A reply with an address of an unknown type.
    #[error("a SOCKS5 reply with an address of unknown type {0}")]
    AddressType(u8),
    /// A reply with an empty domain name.
    #[error("a SOCKS5 reply with an empty domain name")]
    EmptyDomain,
    /// A target the request can't carry.
    #[error("the SOCKS5 request can't carry the target {0}")]
    Target(String),
    /// Credentials outside RFC 1929's bounds: 1 to 255 bytes each.
    #[error("SOCKS5 credentials must be 1 to 255 bytes each")]
    Credentials,
    /// The handshake is over.
    #[error("the SOCKS5 handshake is over")]
    Completed,
    /// The handshake failed already.
    #[error("the SOCKS5 handshake failed")]
    Closed,
}

/// Credentials for username and password authentication ([RFC 1929]).
///
/// [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl Credentials {
    /// Credentials of 1 to 255 bytes each.
    pub fn new(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Result<Self, Error> {
        let (username, password) = (username.into(), password.into());
        for field in [&username, &password] {
            if field.is_empty() || field.len() > usize::from(u8::MAX) {
                return Err(Error::Credentials);
            }
        }
        Ok(Self { username, password })
    }

    #[cfg(test)]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    #[cfg(test)]
    pub fn password(&self) -> &[u8] {
        &self.password
    }
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Where a handshake is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum State {
    /// The greeting is to be sent.
    Initial,
    /// The greeting is sent: the method chosen is awaited.
    Greeted,
    /// The credentials are sent: their status is awaited.
    Authenticating,
    /// The request is sent: the reply's first five bytes are awaited.
    Requested,
    /// The reply's address and port are awaited, of this many bytes.
    Bound(usize),
    /// The handshake is over: the session is the target's.
    Active,
    /// The handshake failed.
    Failed,
}

/// A SOCKS5 client handshake for `target`, or none, for a session that talks
/// to its peer directly.
#[derive(Debug)]
pub struct Socks5 {
    target: NetAddr<HostName>,
    credentials: Option<Credentials>,
    state: State,
}

impl Socks5 {
    /// No handshake: the session talks to `peer` directly.
    pub fn direct(peer: NetAddr<HostName>) -> Self {
        Self {
            target: peer,
            credentials: None,
            state: State::Active,
        }
    }

    /// A handshake asking the proxy for `target`, authenticated with
    /// `credentials` if there are any.
    pub fn through(target: NetAddr<HostName>, credentials: Option<Credentials>) -> Self {
        Self {
            target,
            credentials,
            state: State::Initial,
        }
    }

    /// The session's peer, once the handshake is over.
    pub fn target(&self) -> Option<&NetAddr<HostName>> {
        (self.state == State::Active).then_some(&self.target)
    }

    /// How many bytes of the proxy's reply the handshake reads next: none
    /// before its greeting, and once it is over or has failed.
    pub fn next_read_len(&self) -> usize {
        match self.state {
            State::Initial | State::Active | State::Failed => 0,
            State::Greeted | State::Authenticating => 2,
            // VER, REP, RSV, ATYP, and the first byte of BND.ADDR: a
            // domain's length, if it is one.
            State::Requested => 5,
            State::Bound(len) => len,
        }
    }

    /// Takes the proxy's next reply, exactly [`Socks5::next_read_len`] bytes
    /// of it, and returns what to send it next. The greeting is made from no
    /// input.
    pub fn advance(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let expected = self.next_read_len();
        let result = if matches!(self.state, State::Active) {
            Err(Error::Completed)
        } else if matches!(self.state, State::Failed) {
            Err(Error::Closed)
        } else if input.len() != expected {
            Err(Error::Length {
                expected,
                got: input.len(),
            })
        } else {
            self.step(input)
        };
        if result.is_err() && !matches!(self.state, State::Active) {
            self.state = State::Failed;
        }
        result
    }

    fn step(&mut self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self.state {
            State::Initial => {
                let method = if self.credentials.is_some() {
                    USERNAME_PASSWORD
                } else {
                    NO_AUTH
                };
                self.state = State::Greeted;
                Ok(vec![VERSION, 1, method])
            }
            State::Greeted => {
                let [version, method] = [input[0], input[1]];
                if version != VERSION {
                    return Err(Error::Version(version));
                }
                match (method, &self.credentials) {
                    (NO_ACCEPTABLE_METHOD, _) => Err(Error::NoAcceptableMethod),
                    (USERNAME_PASSWORD, Some(credentials)) => {
                        let mut out = Vec::with_capacity(
                            3 + credentials.username.len() + credentials.password.len(),
                        );
                        out.push(AUTH_VERSION);
                        // Their lengths are checked as they are made.
                        out.push(credentials.username.len() as u8);
                        out.extend_from_slice(&credentials.username);
                        out.push(credentials.password.len() as u8);
                        out.extend_from_slice(&credentials.password);
                        self.state = State::Authenticating;
                        Ok(out)
                    }
                    (NO_AUTH, None) => self.request(),
                    (method, _) => Err(Error::MethodNotOffered(method)),
                }
            }
            State::Authenticating => {
                let [version, status] = [input[0], input[1]];
                if version != AUTH_VERSION {
                    return Err(Error::Version(version));
                }
                if status != 0 {
                    return Err(Error::AuthFailed(status));
                }
                self.request()
            }
            State::Requested => {
                let [version, reply, reserved, kind, first] =
                    [input[0], input[1], input[2], input[3], input[4]];
                if version != VERSION {
                    return Err(Error::Version(version));
                }
                if reply != 0 {
                    return Err(Error::Refused(reply));
                }
                if reserved != 0 {
                    return Err(Error::Reserved(reserved));
                }
                // What is left of BND.ADDR, and BND.PORT's two bytes.
                let left = match kind {
                    IPV4 => 4 - 1 + 2,
                    IPV6 => 16 - 1 + 2,
                    DOMAIN if first == 0 => return Err(Error::EmptyDomain),
                    DOMAIN => usize::from(first) + 2,
                    kind => return Err(Error::AddressType(kind)),
                };
                self.state = State::Bound(left);
                Ok(vec![])
            }
            // The address the proxy bound isn't needed: its length is all
            // that is checked.
            State::Bound(_) => {
                self.state = State::Active;
                Ok(vec![])
            }
            State::Active | State::Failed => unreachable!("checked by `advance`"),
        }
    }

    /// The `CONNECT` request for the target.
    fn request(&mut self) -> Result<Vec<u8>, Error> {
        let mut out = vec![VERSION, CONNECT, 0];
        match &self.target.host {
            HostName::Ip(IpAddr::V4(ip)) => {
                out.push(IPV4);
                out.extend_from_slice(&ip.octets());
            }
            HostName::Ip(IpAddr::V6(ip)) => {
                out.push(IPV6);
                out.extend_from_slice(&ip.octets());
            }
            host => {
                let name = host.to_string();
                let len = u8::try_from(name.len())
                    .ok()
                    .filter(|len| *len > 0)
                    .ok_or_else(|| Error::Target(name.clone()))?;
                out.push(DOMAIN);
                out.push(len);
                out.extend_from_slice(name.as_bytes());
            }
        }
        out.extend_from_slice(&self.target.port.to_be_bytes());
        self.state = State::Requested;
        Ok(out)
    }
}

#[cfg(test)]
mod test {
    use std::io::{Read as _, Write as _};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
    use std::str::FromStr as _;
    use std::thread;

    use super::*;

    fn target(host: &str, port: u16) -> NetAddr<HostName> {
        NetAddr::new(HostName::from_str(host).unwrap(), port)
    }

    fn credentials() -> Credentials {
        Credentials::new("radicle", "secret").unwrap()
    }

    /// The `CONNECT` request for `127.0.0.1:8776`.
    const REQUEST: [u8; 10] = [5, 1, 0, 1, 127, 0, 0, 1, 0x22, 0x48];
    /// A reply that the proxy bound `0.0.0.0:0`.
    const BOUND: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    /// Feeds `reply` to `socks` as its proxy would, a read at a time, and
    /// returns everything it sent.
    fn run(socks: &mut Socks5, mut reply: &[u8]) -> Result<Vec<u8>, Error> {
        let mut sent = socks.advance(&[])?;
        while socks.target().is_none() {
            let len = socks.next_read_len().min(reply.len());
            let (input, rest) = reply.split_at(len);
            reply = rest;
            sent.extend(socks.advance(input)?);
        }
        Ok(sent)
    }

    #[test]
    fn it_authenticates_then_connects() {
        let mut socks = Socks5::through(target("127.0.0.1", 8776), Some(credentials()));
        assert_eq!(socks.next_read_len(), 0);
        assert_eq!(
            socks.advance(&[]).unwrap(),
            [5, 1, 2],
            "only username/password"
        );
        assert_eq!(
            socks.advance(&[5, 2]).unwrap(),
            [&[1, 7][..], b"radicle", &[6], b"secret"].concat()
        );
        assert_eq!(socks.advance(&[1, 0]).unwrap(), REQUEST);
        assert!(socks.target().is_none());
        assert_eq!(socks.next_read_len(), 5);
        assert_eq!(socks.advance(&BOUND[..5]).unwrap(), Vec::<u8>::new());
        assert_eq!(socks.next_read_len(), 5);
        assert_eq!(socks.advance(&BOUND[5..]).unwrap(), Vec::<u8>::new());
        assert_eq!(socks.target(), Some(&target("127.0.0.1", 8776)));
        assert_eq!(socks.advance(&[]), Err(Error::Completed));
    }

    #[test]
    fn without_credentials_it_offers_no_authentication() {
        let mut socks = Socks5::through(target("127.0.0.1", 8776), None);
        let sent = run(&mut socks, &[&[5, 0][..], &BOUND].concat()).unwrap();
        assert_eq!(sent, [&[5, 1, 0][..], &REQUEST].concat());
    }

    #[test]
    fn a_direct_session_has_no_handshake() {
        let socks = Socks5::direct(target("127.0.0.1", 8776));
        assert_eq!(socks.target(), Some(&target("127.0.0.1", 8776)));
        assert_eq!(socks.next_read_len(), 0);
    }

    #[test]
    fn its_request_carries_each_kind_of_target() {
        let request = |host: &str| {
            let mut socks = Socks5::through(target(host, 8776), None);
            socks.advance(&[]).unwrap();
            socks.advance(&[5, 0]).unwrap()
        };
        assert_eq!(request("10.0.0.1"), [5, 1, 0, 1, 10, 0, 0, 1, 0x22, 0x48]);
        assert_eq!(
            request("::1"),
            [
                &[5, 1, 0, 4][..],
                &Ipv6Addr::LOCALHOST.octets(),
                &[0x22, 0x48]
            ]
            .concat()
        );
        assert_eq!(
            request("seed.radicle.xyz"),
            [&[5, 1, 0, 3, 16][..], b"seed.radicle.xyz", &[0x22, 0x48]].concat()
        );
        let onion = "xmrhfasfg5suueegrnc4gsgyi2tyclcy5oz7f5drnrodmdtob6t2ioyd.onion";
        assert_eq!(
            request(onion),
            [&[5, 1, 0, 3, 62][..], onion.as_bytes(), &[0x22, 0x48]].concat()
        );
    }

    #[test]
    fn a_name_too_long_for_a_request_is_refused() {
        let name = format!("{}.example", "a".repeat(250));
        let mut socks = Socks5::through(NetAddr::new(HostName::Dns(name.clone()), 8776), None);
        socks.advance(&[]).unwrap();
        assert_eq!(socks.advance(&[5, 0]), Err(Error::Target(name)));
        assert_eq!(socks.advance(&[]), Err(Error::Closed));
    }

    #[test]
    fn credentials_are_bounded() {
        assert_eq!(Credentials::new("", "x"), Err(Error::Credentials));
        assert_eq!(Credentials::new("x", ""), Err(Error::Credentials));
        assert_eq!(
            Credentials::new("x", vec![b'p'; 256]),
            Err(Error::Credentials)
        );
        assert!(Credentials::new(vec![b'u'; 255], vec![b'p'; 255]).is_ok());
        assert!(!format!("{:?}", credentials()).contains("secret"));
    }

    #[test]
    fn its_replies_are_parsed_strictly() {
        let authenticated = || {
            let mut socks = Socks5::through(target("127.0.0.1", 8776), Some(credentials()));
            socks.advance(&[]).unwrap();
            socks
        };
        let requested = || {
            let mut socks = authenticated();
            socks.advance(&[5, 2]).unwrap();
            socks.advance(&[1, 0]).unwrap();
            socks
        };
        let cases: [(Socks5, &[u8], Error); 12] = [
            // The method.
            (authenticated(), &[5, 0xff], Error::NoAcceptableMethod),
            (authenticated(), &[5, 0], Error::MethodNotOffered(0)),
            (authenticated(), &[5, 1], Error::MethodNotOffered(1)),
            (authenticated(), &[4, 2], Error::Version(4)),
            // A short and an overlong reply.
            (
                authenticated(),
                &[5],
                Error::Length {
                    expected: 2,
                    got: 1,
                },
            ),
            (
                authenticated(),
                &[5, 2, 0],
                Error::Length {
                    expected: 2,
                    got: 3,
                },
            ),
            // The credentials' status.
            (
                {
                    let mut socks = authenticated();
                    socks.advance(&[5, 2]).unwrap();
                    socks
                },
                &[1, 1],
                Error::AuthFailed(1),
            ),
            (
                {
                    let mut socks = authenticated();
                    socks.advance(&[5, 2]).unwrap();
                    socks
                },
                &[5, 0],
                Error::Version(5),
            ),
            // The reply to the request.
            (requested(), &[5, 5, 0, 1, 0], Error::Refused(5)),
            (requested(), &[5, 0, 1, 1, 0], Error::Reserved(1)),
            (requested(), &[5, 0, 0, 2, 0], Error::AddressType(2)),
            (requested(), &[5, 0, 0, 3, 0], Error::EmptyDomain),
        ];
        for (mut socks, reply, error) in cases {
            assert_eq!(socks.advance(reply), Err(error.clone()), "{reply:?}");
            // A failed handshake stays failed.
            assert_eq!(socks.next_read_len(), 0);
            assert!(socks.target().is_none());
            assert_eq!(socks.advance(&[]), Err(Error::Closed), "{error}");
        }
    }

    #[test]
    fn its_reply_s_address_is_read_at_its_length() {
        for (kind, rest) in [
            (IPV4, vec![0; 4 - 1 + 2]),
            (IPV6, vec![0; 16 - 1 + 2]),
            (DOMAIN, [b"seed".as_slice(), &[0, 0]].concat()),
        ] {
            let mut socks = Socks5::through(target("127.0.0.1", 8776), None);
            socks.advance(&[]).unwrap();
            socks.advance(&[5, 0]).unwrap();
            let first = if kind == DOMAIN { 4 } else { 0 };
            socks.advance(&[5, 0, 0, kind, first]).unwrap();
            assert_eq!(socks.next_read_len(), rest.len(), "{kind}");
            socks.advance(&rest).unwrap();
            assert!(socks.target().is_some());
        }
    }

    /// A proxy's script: what it expects to be sent, and its reply, in turn.
    type Script = Vec<(Vec<u8>, Vec<u8>)>;

    /// A proxy that reads what it is sent, checks it against what the script
    /// expects, and sends the script's replies, then closes.
    fn proxy(script: Script) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for (expected, reply) in script {
                let mut got = vec![0; expected.len()];
                stream.read_exact(&mut got).unwrap();
                assert_eq!(got, expected, "the proxy was sent something else");
                stream.write_all(&reply).unwrap();
            }
        });
        (addr, server)
    }

    /// Drives `socks` over `stream`, as the node's session does.
    fn handshake(socks: &mut Socks5, stream: &mut TcpStream) -> std::io::Result<()> {
        let greeting = socks.advance(&[]).map_err(std::io::Error::other)?;
        stream.write_all(&greeting)?;
        while socks.target().is_none() {
            let mut input = vec![0; socks.next_read_len()];
            stream.read_exact(&mut input)?;
            let out = socks.advance(&input).map_err(std::io::Error::other)?;
            stream.write_all(&out)?;
        }
        Ok(())
    }

    fn auth() -> Vec<u8> {
        [&[1, 7][..], b"radicle", &[6], b"secret"].concat()
    }

    #[test]
    fn it_completes_with_a_scripted_proxy() {
        let (addr, server) = proxy(vec![
            (vec![5, 1, 2], vec![5, 2]),
            (auth(), vec![1, 0]),
            // An overlong reply: the peer's first bytes come after it.
            (REQUEST.to_vec(), [&BOUND[..], b"peer"].concat()),
        ]);
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut socks = Socks5::through(target("127.0.0.1", 8776), Some(credentials()));
        handshake(&mut socks, &mut stream).unwrap();
        assert_eq!(socks.target(), Some(&target("127.0.0.1", 8776)));
        // The handshake took the reply and nothing more.
        let mut peer = Vec::new();
        stream.read_to_end(&mut peer).unwrap();
        assert_eq!(peer, b"peer");
        server.join().unwrap();
    }

    #[test]
    fn a_scripted_proxy_s_refusals_fail_the_handshake() {
        let refusals: [(Script, &str); 5] = [
            // It doesn't take username and password.
            (vec![(vec![5, 1, 2], vec![5, 0xff])], "accepts none"),
            // It picks no authentication, which wasn't offered.
            (vec![(vec![5, 1, 2], vec![5, 0])], "wasn't offered"),
            // It refuses the credentials.
            (
                vec![(vec![5, 1, 2], vec![5, 2]), (auth(), vec![1, 1])],
                "refused the credentials",
            ),
            // A wrong address type.
            (
                vec![
                    (vec![5, 1, 2], vec![5, 2]),
                    (auth(), vec![1, 0]),
                    (REQUEST.to_vec(), vec![5, 0, 0, 9, 0]),
                ],
                "unknown type 9",
            ),
            // A short reply, then the proxy closes.
            (
                vec![
                    (vec![5, 1, 2], vec![5, 2]),
                    (auth(), vec![1, 0]),
                    (REQUEST.to_vec(), vec![5, 0, 0, 1, 0, 0]),
                ],
                "failed to fill whole buffer",
            ),
        ];
        for (script, failure) in refusals {
            let (addr, server) = proxy(script);
            let mut stream = TcpStream::connect(addr).unwrap();
            let mut socks = Socks5::through(target("127.0.0.1", 8776), Some(credentials()));
            let err = handshake(&mut socks, &mut stream).unwrap_err();
            assert!(err.to_string().contains(failure), "{err}");
            assert!(socks.target().is_none());
            server.join().unwrap();
        }
    }
}
