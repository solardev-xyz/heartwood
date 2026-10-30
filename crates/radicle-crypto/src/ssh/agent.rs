extern crate std;

use std::borrow::ToOwned as _;
use std::cell::RefCell;
use std::env::VarError;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::path::PathBuf;
use std::string::{String, ToString as _};
use std::vec::Vec;

use proto::{PrivateCredential, ProtoError, PublicCredential};
use ssh_agent_lib::blocking::Client;
pub use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto;
use ssh_agent_lib::ssh_encoding::{Decode as _, Encode as _};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{PublicKey, Signature, SigningKey, VerifyingKey};

#[cfg(unix)]
use std::os::unix::net::UnixStream as Stream;

#[cfg(windows)]
use winpipe::WinStream as Stream;

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error("Unable to read environment variable '{var}': {source}")]
    EnvVar { var: String, source: VarError },
}

impl ConnectError {
    pub fn is_not_running(&self) -> bool {
        use std::io::ErrorKind::*;
        match self {
            Self::EnvVar {
                source: VarError::NotPresent,
                ..
            } => true,
            Self::Agent(AgentError::IO(source)) if source.kind() == NotFound => true,
            #[cfg(windows)]
            Self::Agent(AgentError::IO(source)) if source.kind() == ConnectionRefused => {
                // On Windows, a named pipe might be used, and if no
                // agent is running, we might get a "connection refused"
                // error, even though the `SSH_AUTH_SOCK` environment variable
                // is set and a named pipe exists.
                true
            }
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum IntoSignerError {
    #[error(transparent)]
    Agent(#[from] AgentError),
    #[error("Identity {identity} not found in agent.")]
    IdentityNotFound { identity: PublicKey },
}

pub struct Agent {
    path: PathBuf,
    stream: Stream,
}

impl Agent {
    /// Connect to a running SSH agent.
    pub fn connect() -> Result<Self, ConnectError> {
        const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

        let path = match std::env::var(SSH_AUTH_SOCK) {
            Ok(path) => Ok(PathBuf::from(path)),
            #[cfg(windows)]
            Err(VarError::NotPresent) => {
                // Windows exposes the SSH Agent on a default named pipe.
                const DEFAULT_SSH_AGENT_PIPE: &str = "\\\\.\\pipe\\openssh-ssh-agent";
                Ok(PathBuf::from(DEFAULT_SSH_AGENT_PIPE))
            }
            Err(err) => Err(ConnectError::EnvVar {
                var: SSH_AUTH_SOCK.to_string(),
                source: err,
            }),
        }?;

        let stream =
            Stream::connect(&path).map_err(|err| ConnectError::Agent(AgentError::IO(err)))?;

        Ok(Self { path, stream })
    }

    /// An agent reached through `stream`.
    #[cfg(all(test, unix))]
    fn with(stream: Stream) -> Self {
        Self {
            path: PathBuf::new(),
            stream,
        }
    }

    /// The agent's client, for a request that carries no secret.
    fn client(&mut self) -> Client<&mut Stream> {
        Client::new(&mut self.stream)
    }

    /// Register a key with the agent.
    ///
    /// The request carries the private key, so it is encoded here rather
    /// than by `ssh-agent-lib`'s client, which encodes a request into a
    /// buffer it never wipes. This one is wiped once the request is sent, and
    /// is sized beforehand, so that it never grows and leaves a copy behind.
    pub fn register(&mut self, key: &SigningKey) -> Result<(), AgentError> {
        use ssh_key::private::{Ed25519Keypair, KeypairData};

        let bytes = Zeroizing::new(key.to_keypair_bytes());
        let request = proto::Request::AddIdentity(proto::AddIdentity {
            credential: PrivateCredential::Key {
                privkey: KeypairData::Ed25519(Ed25519Keypair::from_bytes(&bytes).unwrap()),
                comment: "".into(),
            },
        });
        match Self::secret_request(&mut self.stream, &request)? {
            proto::Response::Success => Ok(()),
            _ => Err(ProtoError::UnexpectedResponse.into()),
        }
    }

    /// Sends `request`, which carries a secret, and returns the agent's
    /// response.
    fn secret_request(
        stream: &mut Stream,
        request: &proto::Request,
    ) -> Result<proto::Response, ProtoError> {
        let len = request.encoded_len()?;
        let framed = len
            .checked_add(4)
            .ok_or(ssh_agent_lib::ssh_encoding::Error::Overflow)?;
        let mut message = Zeroizing::new(Vec::with_capacity(framed));
        u32::try_from(len)
            .map_err(|_| ssh_agent_lib::ssh_encoding::Error::Overflow)?
            .encode(&mut *message)?;
        request.encode(&mut *message)?;
        debug_assert_eq!(
            message.len(),
            framed,
            "a request's encoding isn't the length it gives"
        );
        stream.write_all(&message)?;
        drop(message);

        // The response, as `ssh-agent-lib`'s client reads it.
        let mut len = [0; 4];
        stream.read_exact(&mut len)?;
        let mut response = std::vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut response)?;
        proto::Response::decode(&mut &response[..])
    }

    pub fn unregister(&mut self, key: &VerifyingKey) -> Result<(), AgentError> {
        self.client().remove_identity(proto::RemoveIdentity {
            credential: PublicCredential::Key(Self::key_data(key)),
        })
    }

    pub fn unregister_all(&mut self) -> Result<(), AgentError> {
        self.client().remove_all_identities()
    }

    pub fn sign(&mut self, key: &VerifyingKey, data: &[u8]) -> Result<[u8; 64], AgentError> {
        let sig = self.client().sign(proto::SignRequest {
            credential: PublicCredential::Key(Self::key_data(key)),
            data: data.to_vec(),
            flags: 0,
        })?;

        Ok(sig.as_bytes().to_owned().try_into().unwrap())
    }

    /// Transform this [`Agent`] into an [`AgentSigner`] scoped to the given
    /// `identity`.
    pub fn into_signer(mut self, identity: VerifyingKey) -> Result<AgentSigner, IntoSignerError> {
        if self.request_identities()?.contains(identity.public_key()) {
            Ok(AgentSigner::new(self, identity))
        } else {
            Err(IntoSignerError::IdentityNotFound {
                identity: *identity.public_key(),
            })
        }
    }

    pub fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub fn request_identities(&mut self) -> Result<Vec<PublicKey>, AgentError> {
        Ok(self
            .client()
            .request_identities()?
            .into_iter()
            .filter_map(|identity| {
                identity
                    .credential
                    .key_data()
                    .ed25519()
                    .map(|key| PublicKey::from(key.0))
            })
            .collect())
    }

    fn key_data(key: &VerifyingKey) -> KeyData {
        KeyData::Ed25519(Ed25519PublicKey(key.to_bytes()))
    }
}

/// A [`crate::signature::Signer`] that uses `ssh-agent`.
pub struct AgentSigner {
    agent: RefCell<Agent>,
    public: VerifyingKey,
}

impl crate::signature::Signer<Signature> for AgentSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, crate::signature::Error> {
        let sig = self
            .agent
            .borrow_mut()
            .sign(&self.public, msg)
            .map_err(crate::signature::Error::from_source)?;
        Ok(Signature::from(sig))
    }
}

impl AsRef<VerifyingKey> for AgentSigner {
    fn as_ref(&self) -> &VerifyingKey {
        &self.public
    }
}

impl AsRef<crate::PublicKey> for AgentSigner {
    fn as_ref(&self) -> &crate::PublicKey {
        self.public.public_key()
    }
}

impl crate::signature::KeypairRef for AgentSigner {
    type VerifyingKey = VerifyingKey;
}

impl AgentSigner {
    pub fn new(agent: Agent, public: VerifyingKey) -> Self {
        let agent = RefCell::new(agent);

        Self { agent, public }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// A global allocator for this crate's tests. On a thread that watches
    /// for a secret, it looks at every block freed for that secret.
    #[cfg(unix)]
    mod freed {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        struct Watch;

        std::thread_local! {
            static SECRET: Cell<Option<[u8; 32]>> = const { Cell::new(None) };
            static FOUND: Cell<usize> = const { Cell::new(0) };
        }

        // SAFETY: it allocates and frees as `System` does. Every block is
        // zeroed as it is allocated, so that a block read as it is freed has
        // no byte uninitialised.
        unsafe impl GlobalAlloc for Watch {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                unsafe { System.alloc_zeroed(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if let Ok(Some(secret)) = SECRET.try_with(Cell::get) {
                    // SAFETY: `ptr` is a live block of `layout.size()`
                    // initialised bytes until it is freed below.
                    let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                    if block.windows(secret.len()).any(|bytes| bytes == secret) {
                        FOUND.with(|found| found.set(found.get() + 1));
                    }
                }
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        #[global_allocator]
        static WATCH: Watch = Watch;

        /// Runs `f`, and counts the blocks freed on this thread meanwhile
        /// that held `secret`.
        pub fn watching<T>(secret: [u8; 32], f: impl FnOnce() -> T) -> (T, usize) {
            FOUND.with(|found| found.set(0));
            SECRET.with(|watched| watched.set(Some(secret)));
            let out = f();
            SECRET.with(|watched| watched.set(None));
            (out, FOUND.with(Cell::get))
        }
    }

    #[cfg(unix)]
    #[test]
    // Review of heartwood #15, round 1: registering a key with the agent
    // frees no memory that holds the private key: the request that carries
    // it is wiped once sent.
    fn a_registered_key_leaves_no_copy_in_freed_memory() {
        use std::os::unix::net::UnixStream;

        let secret: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ 0x5a);
        // The watch itself sees a copy that isn't wiped.
        let ((), found) = freed::watching(secret, || drop(secret.to_vec()));
        assert_eq!(found, 1);

        let (ours, mut theirs) = UnixStream::pair().unwrap();
        let agent = std::thread::spawn(move || {
            let mut len = [0; 4];
            theirs.read_exact(&mut len).unwrap();
            let mut request = std::vec![0; u32::from_be_bytes(len) as usize];
            theirs.read_exact(&mut request).unwrap();
            // `SSH_AGENT_SUCCESS`.
            theirs.write_all(&[0, 0, 0, 1, 6]).unwrap();
            request
        });
        let key = SigningKey::from_seed(crate::Seed::new(secret));
        let mut client = Agent::with(ours);
        let (registered, found) = freed::watching(secret, || client.register(&key));

        registered.unwrap();
        let request = agent.join().unwrap();
        assert!(
            request.windows(secret.len()).any(|bytes| bytes == secret),
            "the agent wasn't sent the key"
        );
        assert_eq!(
            found, 0,
            "memory that held the private key was freed unwiped"
        );
    }

    use ssh_agent_lib::blocking::Client;
    use ssh_agent_lib::proto::{PublicCredential, SignRequest};
    use ssh_agent_lib::ssh_key::public::{Ed25519PublicKey, KeyData};

    use crate::VerifyingKey;

    #[test]
    fn test_agent_encoding_remove() {
        use std::str::FromStr;

        let pk =
            VerifyingKey::from_str("z6MktWkM9vcfysWFq1c2aaLjJ6j4PYYg93TLPswR4qtuoAeT").unwrap();
        let expected = [
            0, 0, 0, 56, // Message length
            18, // Message type (remove identity)
            0, 0, 0, 51, // Key blob length
            0, 0, 0, 11, // Key type length
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, // Key type
            0, 0, 0, 32, // Key length
            208, 232, 92, 138, 225, 114, 116, 99, 156, 177, 148, 93, 65, 93, 198, 25, 46, 203, 79,
            37, 145, 51, 176, 174, 61, 136, 160, 107, 4, 95, 175, 144, // Key
        ];

        let mut client = Client::new(std::io::Cursor::new(Vec::new()));

        // We expect this to fail with an unexpected EOF, since the client will
        // attempt to read a response from the stream, but the stream is empty,
        // since we are not actually connected to SSH agent.
        assert!(
            matches!(client.remove_identity(ssh_agent_lib::proto::RemoveIdentity {
                credential: PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey(pk.to_bytes()))),
            }),
                Err(
                    super::AgentError::Proto(ssh_agent_lib::proto::ProtoError::IO(err)),
                ) if err.kind() == std::io::ErrorKind::UnexpectedEof
            )
        );

        assert_eq!(client.into_inner().into_inner(), expected.as_slice());
    }

    #[test]
    fn test_agent_encoding_sign() {
        use std::str::FromStr;

        let pk =
            VerifyingKey::from_str("z6MktWkM9vcfysWFq1c2aaLjJ6j4PYYg93TLPswR4qtuoAeT").unwrap();
        let expected = [
            0, 0, 0, 73, // Message length
            13, // Message type (sign request)
            0, 0, 0, 51, // Key blob length
            0, 0, 0, 11, // Key type length
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, // Key type
            0, 0, 0, 32, // Public key
            208, 232, 92, 138, 225, 114, 116, 99, 156, 177, 148, 93, 65, 93, 198, 25, 46, 203, 79,
            37, 145, 51, 176, 174, 61, 136, 160, 107, 4, 95, 175, 144, // Key
            0, 0, 0, 9, // Length of data to sign
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Data to sign
            0, 0, 0, 0, // Signature flags
        ];

        let mut client = Client::new(std::io::Cursor::new(Vec::new()));
        let data: Vec<u8> = [1, 2, 3, 4, 5, 6, 7, 8, 9].into_iter().collect();

        client
            .sign(SignRequest {
                credential: PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey(
                    pk.to_bytes(),
                ))),
                data,
                flags: 0,
            })
            .ok();

        assert_eq!(client.into_inner().into_inner(), expected);
    }
}
