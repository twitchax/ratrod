//! Protocol message types and serialization.
//!
//! This module contains the types and serialization methods for the protocol messages.

use std::fmt::{Display, Formatter};

use anyhow::anyhow;
use bincode::{BorrowDecode, Encode};
use bytes::Bytes;
use ouroboros::self_referencing;
use serde::{Deserialize, Serialize};

use crate::base::{Constant, Res, Void};

// Wire types.

/// A helper type for a challenge.
pub type Challenge = [u8; Constant::CHALLENGE_SIZE];

/// A helper type for a signature.
pub type Signature = [u8; Constant::SIGNATURE_SIZE];

/// A helper type for an ephemeral public key.
pub type ExchangePublicKey = [u8; Constant::EXCHANGE_PUBLIC_KEY_SIZE];

/// Serves as the preamble for the connection.
#[derive(Clone, Debug, PartialEq, Eq, Encode, BorrowDecode)]
pub struct ClientPreamble<'a> {
    pub exchange_public_key: &'a [u8],
    pub remote: &'a str,
    pub challenge: &'a [u8],
    pub should_encrypt: bool,
    pub is_udp: bool,
}

/// Serves as the server's response to the preamble, containing its
/// public key, its signature of the client's challenge and a challenge.
/// The server signs the client's challenge to prove its identity.
#[derive(Clone, Debug, PartialEq, Eq, Encode, BorrowDecode)]
pub struct ServerPreamble<'a> {
    /// The server's identity public key (base64 encoded Ed25519 key)
    pub identity_public_key: &'a str,
    /// The server's ephemeral public key for the key exchange
    pub exchange_public_key: &'a [u8],
    /// The server's signature of the client's challenge
    pub signature: &'a [u8],
    /// A random challenge for the client to sign
    pub challenge: &'a [u8],
}

/// Serves as the client's response to the server's challenge.
#[derive(Clone, Debug, PartialEq, Eq, Encode, BorrowDecode)]
pub struct ClientAuthentication<'a> {
    pub identity_public_key: &'a str,
    pub signature: &'a [u8],
}

// Message types.

/// A helper type for protocol messages.
///
/// This is the main message type for the protocol. It is used to send and receive messages over the network.
/// It is also used to serialize and deserialize messages.
#[derive(Debug, PartialEq, Eq, Encode, BorrowDecode)]
pub enum ProtocolMessage<'a> {
    ClientPreamble(ClientPreamble<'a>),
    ServerPreamble(ServerPreamble<'a>),
    ClientAuthentication(ClientAuthentication<'a>),
    HandshakeCompletion,
    Data(&'a [u8]),
    UdpData(&'a [u8]),
    Error(ProtocolError<'a>),
    Shutdown,
}

impl ProtocolMessage<'_> {
    /// Checks if the message is an error.
    ///
    /// If it is, returns the message wrapped in an error.
    pub fn fail_if_error(&self) -> Res<&Self> {
        if let ProtocolMessage::Error(error) = self {
            return Err(anyhow!(error.to_string()));
        }

        Ok(self)
    }
}

// Message error types.

/// A helper type for protocol errors.
///
/// This is used to send and receive errors over the network.
/// It is also used to serialize and deserialize errors.
///
/// It should not be sent / received over the network, as it
/// should be sent as a [`ProtocolMessage::Error`] message.
/// The type system should prevent this from happening.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Encode, BorrowDecode)]
pub enum ProtocolError<'a> {
    InvalidHost(&'a str),
    InvalidKey(&'a str),
    RemoteFailed(&'a str),
    Unknown(&'a str),
}

impl Display for ProtocolError<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::InvalidHost(host) => write!(f, "Invalid host: {}", host),
            ProtocolError::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            ProtocolError::RemoteFailed(message) => write!(f, "Remote failed: {}", message),
            ProtocolError::Unknown(message) => write!(f, "Unknown: {}", message),
        }
    }
}

impl ProtocolError<'_> {
    /// Sends the error message and shuts down the stream.
    ///
    /// The generic parameter R represents the return type expected by the calling function.
    /// This method always returns an error, but needs to have the expected return type for the context.
    pub async fn send_and_bail<T, R>(self, stream: &mut T) -> Res<R>
    where
        T: BincodeSend,
    {
        let error_message = self.to_string();

        let _ = stream.push(ProtocolMessage::Error(self)).await;
        let _ = stream.close().await;

        Err(anyhow!(error_message))
    }
}

/// A helper type for protocol message guards.
///
/// Essentially, this is a wrapper around [`ProtocolMessage`] that allows
/// for tying, self-referentially, the underlying buffer to the message.
/// As a result, while the message is essentially "borrowed" from the buffer,
/// the buffer is "owned" by the guard.
///
/// After a guard goes out of scope, the buffer is dropped, and, due to
/// the way `BytesMut` works, it _may_ (read: "will when able") reclaim
/// the memory used by this buffer, thereby reducing buffer allocations
/// and data clones.
#[self_referencing(pub_extras)]
pub struct ProtocolMessageGuard {
    pub buffer: Bytes,
    #[borrows(buffer)]
    #[covariant]
    pub inner: ProtocolMessage<'this>,
}

impl ProtocolMessageGuard {
    /// The inner message of this guard.
    pub fn message(&self) -> &ProtocolMessage<'_> {
        self.borrow_inner()
    }
}

// Bincode stream impls.

/// A trait for sending protocol messages over a stream.
///
/// This impl is designed to ensure that the push method can only be used to send
/// [`ProtocolMessage`] messages. This restriction is important for type safety
/// and to ensure that all messages sent through the stream follow the protocol
/// format and are properly encrypted if necessary.
pub trait BincodeSend: Unpin + Sized {
    /// Pushes a message to the stream.
    ///
    /// Right now, this only requires `T: Encode`, but in the future, it may
    /// require a concrete type, such as `ProtocolMessage`.
    fn push<T>(&mut self, message: T) -> impl Future<Output = Void>
    where
        T: Encode;

    /// Closes the stream via `shutdown`.
    fn close(&mut self) -> impl Future<Output = Void>;
}

/// A trait for receiving protocol messages over a stream.
///
/// This impl is designed to ensure that the pull method can only be used to receive
/// [`ProtocolMessage`] messages. This restriction provides type safety and ensures
/// proper message decryption and protocol handling for incoming data.
pub trait BincodeReceive: Unpin + Sized {
    /// Pulls a message from the stream.
    ///
    /// Since are reading here, we just return the concrete type, though
    /// it stands to reason that we could just constrain this with a Guard
    /// of a `type Result: BorrowDecode`.
    fn pull(&mut self) -> impl Future<Output = Res<ProtocolMessageGuard>>;
}

// Tests.

#[cfg(test)]
mod tests {
    use crate::utils::tests::{generate_test_duplex, generate_test_fake_exchange_public_key};

    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_bincode() {
        let (mut client, mut server) = generate_test_duplex();

        let data = ClientPreamble {
            exchange_public_key: &generate_test_fake_exchange_public_key(),
            remote: "remote",
            challenge: &Challenge::default(),
            should_encrypt: true,
            is_udp: false,
        };

        client.push(ProtocolMessage::ClientPreamble(data.clone())).await.unwrap();

        let guard = server.pull().await.unwrap();
        let ProtocolMessage::ClientPreamble(message) = guard.message() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, *message);
    }
}
