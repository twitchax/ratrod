//! Protocol message types and serialization.
//!
//! This module contains the types and serialization methods for the protocol messages.

use std::fmt::{Display, Formatter};

use anyhow::Context;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::base::{Constant, Err, Res, Void};

// Wire types.

/// A helper type for a challenge.
pub type Challenge = [u8; Constant::CHALLENGE_SIZE];

/// A helper type for a signature.
pub type Signature = [u8; Constant::SIGNATURE_SIZE];

/// A helper type for an ephemeral public key.
pub type ExchangePublicKey = [u8; Constant::PEER_PUBLIC_KEY_SIZE];

/// Serves as the preamble for the connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientPreamble {
    pub exchange_public_key: ExchangePublicKey,
    pub remote: String,
    pub challenge: Challenge,
    pub should_encrypt: bool,
    pub is_udp: bool,
}

/// Serves as the server's response to the preamble, containing its
/// public key, its signature of the client's challenge and a challenge.
/// The server signs the client's challenge to prove its identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerPreamble {
    /// The server's identity public key (base64 encoded Ed25519 key)
    pub identity_public_key: String,
    /// The server's ephemeral public key for the key exchange
    pub exchange_public_key: ExchangePublicKey,
    /// The server's signature of the client's challenge
    pub signature: SerializeableSignature,
    /// A random challenge for the client to sign
    pub challenge: Challenge,
}

/// Serves as the client's response to the server's challenge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuthentication {
    pub identity_public_key: String,
    pub signature: SerializeableSignature,
}

// Message types.

/// A helper trait for protocol messages.
pub trait BincodeMessage: Serialize + DeserializeOwned {}

/// A helper type for protocol messages.
///
/// This is the main message type for the protocol. It is used to send and receive messages over the network.
/// It is also used to serialize and deserialize messages.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolMessage {
    ClientPreamble(ClientPreamble),
    ServerPreamble(ServerPreamble),
    ClientAuthentication(ClientAuthentication),
    HandshakeCompletion,
    Data(Vec<u8>),
    UdpData(Vec<u8>),
    Error(ProtocolError),
    Shutdown,
}

impl ProtocolMessage {
    /// Checks if the message is an error.
    ///
    /// If it is, returns the message wrapped in an error.
    pub fn fail_if_error(self) -> Res<Self> {
        if let ProtocolMessage::Error(error) = self {
            return Err(Err::msg(error));
        }

        Ok(self)
    }
}

impl BincodeMessage for ProtocolMessage {}

/// A wrapper type for protocol messages.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolMessageWrapper {
    Plain(ProtocolMessage),
    Encrypted { nonce: [u8; Constant::SHARED_SECRET_NONCE_SIZE], data: Vec<u8> },
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidHost(String),
    InvalidKey(String),
    RemoteFailed(String),
    Unknown(String),
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::InvalidHost(host) => write!(f, "Invalid host: {}", host),
            ProtocolError::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            ProtocolError::RemoteFailed(message) => write!(f, "Remote failed: {}", message),
            ProtocolError::Unknown(message) => write!(f, "Unknown: {}", message),
        }
    }
}

impl ProtocolError {
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

        Err(Err::msg(error_message))
    }
}

// Bincode stream impls.

/// A trait for sending protocol messages over a stream.
///
/// This impl is designed to ensure that the push method can only be used to send
/// [`ProtocolMessage`] messages. This restriction is important for type safety
/// and to ensure that all messages sent through the stream follow the protocol
/// format and are properly encrypted if necessary.
pub trait BincodeSend: Sink<ProtocolMessage> + Unpin + Sized {
    fn push(&mut self, message: ProtocolMessage) -> impl Future<Output = Void> {
        async move { self.send(message).await.map_err(|_| Err::msg("Failed to send message")) }
    }

    fn push_all(&mut self, messages: impl IntoIterator<Item = ProtocolMessage>) -> impl Future<Output = Void> {
        async move {
            for message in messages.into_iter() {
                self.feed(message).await.map_err(|_| Err::msg("Failed to feed message"))?;
            }
            
            self.flush().await.map_err(|_| Err::msg("Failed to flush"))?;

            Ok(())
        }
    }
}

/// A trait for receiving protocol messages over a stream.
///
/// This impl is designed to ensure that the pull method can only be used to receive
/// [`ProtocolMessage`] messages. This restriction provides type safety and ensures
/// proper message decryption and protocol handling for incoming data.
pub trait BincodeReceive: Stream<Item = std::io::Result<ProtocolMessage>> + Unpin + Sized {
    fn pull(&mut self) -> impl Future<Output = Res<ProtocolMessage>> {
        async move {
            let message = match self.next().await {
                Some(Ok(message)) => message,
                Some(Err(e)) => return Err(Err::msg(format!("Failed to receive message: {}", e))),
                None => ProtocolMessage::Shutdown,
            };
            Ok(message)
        }
    }
}

// Blanket impl for BincodeSend and BincodeReceive where T implements `Sink` and `Stream`.

impl<T> BincodeSend for T where Self: Sink<ProtocolMessage> + Unpin + Sized {}
impl<T> BincodeReceive for T where Self: Stream<Item = std::io::Result<ProtocolMessage>> + Unpin + Sized {}

// Signature serialization.

/// A helper type for serializing signatures (bincode cannot serialize a `[u8; 64]` out of the box).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerializeableSignature(pub Signature);

impl From<Signature> for SerializeableSignature {
    fn from(signature: Signature) -> Self {
        Self(signature)
    }
}

impl From<&Signature> for SerializeableSignature {
    fn from(signature: &Signature) -> Self {
        Self(*signature)
    }
}

impl From<SerializeableSignature> for Signature {
    fn from(signature: SerializeableSignature) -> Self {
        signature.0
    }
}

impl Serialize for SerializeableSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SerializeableSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <&[u8]>::deserialize(deserializer)?;

        if bytes.len() != Constant::SIGNATURE_SIZE {
            return Err(serde::de::Error::custom(format!("Invalid signature length: {}", bytes.len())));
        }

        let mut signature = [0; Constant::SIGNATURE_SIZE];
        signature.copy_from_slice(bytes);

        Ok(SerializeableSignature(signature))
    }
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
            exchange_public_key: generate_test_fake_exchange_public_key(),
            remote: "remote".to_string(),
            challenge: Challenge::default(),
            should_encrypt: true,
            is_udp: false,
        };

        client.push(ProtocolMessage::ClientPreamble(data.clone())).await.unwrap();

        let ProtocolMessage::ClientPreamble(message) = server.pull().await.unwrap() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, message);
    }
}
