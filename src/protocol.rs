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
pub type PeerPublicKey = [u8; Constant::PEER_PUBLIC_KEY_SIZE];

/// Serves as the preamble for the connection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Preamble {
    pub remote: String,
    pub peer_public_key: Option<PeerPublicKey>,
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
    HandshakeStart(Preamble),
    HandshakeChallenge(Challenge),
    HandshakeChallengeResponse(SerializeableSignature),
    HandshakeCompletion(PeerPublicKey),
    PlaintextPacket(Vec<u8>),
    EncryptedPacket { nonce: [u8; Constant::SHARED_SECRET_NONCE_SIZE], data: Vec<u8> },
    Error(ProtocolError),
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
    Unknown(String),
}

impl Display for ProtocolError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::InvalidHost(host) => write!(f, "Invalid host: {}", host),
            ProtocolError::InvalidKey(key) => write!(f, "Invalid key: {}", key),
            ProtocolError::Unknown(message) => write!(f, "Unknown: {}", message),
        }
    }
}

impl ProtocolError {
    /// Sends the error message and shuts down the stream.
    pub async fn send_and_bail<T, R>(self, stream: &mut T) -> Res<R>
    where
        T: BincodeSend,
    {
        let error_message = self.to_string();

        let _ = stream.push(ProtocolMessage::Error(self)).await;
        let _ = stream.shutdown().await;

        Err(Err::msg(error_message))
    }
}

// Bincode stream impls.

/// A trait for sending protocol messages over a stream.
///
/// This impl is designed to ensure that the push method can only be used to send
/// [`ProtocolMessage`] messages.
pub trait BincodeSend: Sink<ProtocolMessage> + AsyncWrite + AsyncWriteExt + Unpin + Sized {
    fn push(&mut self, message: ProtocolMessage) -> impl Future<Output = Void> {
        async move { self.send(message).await.map_err(|_| Err::msg("Failed to send message")) }
    }
}

/// A trait for receiving protocol messages over a stream.
///
/// This impl is designed to ensure that the pull method can only be used to receive
/// [`ProtocolMessage`] messages.
pub trait BincodeReceive: Stream<Item = std::io::Result<ProtocolMessage>> + AsyncRead + AsyncReadExt + Unpin + Sized {
    fn pull(&mut self) -> impl Future<Output = Res<ProtocolMessage>> {
        async move {
            let message = self.next().await.context("Failed to read message")?.context("Failed to parse message")?;
            Ok(message)
        }
    }
}

// Blanket impl for BincodeSend and BincodeReceive where T implements `Sink` and `Stream`.

impl<T> BincodeSend for T where Self: Sink<ProtocolMessage> + AsyncWrite + Unpin + Sized {}
impl<T> BincodeReceive for T where Self: Stream<Item = std::io::Result<ProtocolMessage>> + AsyncRead + Unpin + Sized {}

// Signature serialization.

/// A helper type for serializing signatures (bincode cannot serialize a `[u8; 64]` our of the box).
#[derive(Debug, PartialEq, Eq)]
pub struct SerializeableSignature(pub Signature);

impl From<Signature> for SerializeableSignature {
    fn from(signature: Signature) -> Self {
        Self(signature)
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
    use crate::utils::tests::{generate_test_duplex, generate_test_fake_peer_public_key};

    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_bincode() {
        let (mut client, mut server) = generate_test_duplex();

        let data = Preamble {
            remote: "remote".to_string(),
            peer_public_key: Some(generate_test_fake_peer_public_key()),
        };

        client.push(ProtocolMessage::HandshakeStart(data.clone())).await.unwrap();

        let ProtocolMessage::HandshakeStart(message) = server.pull().await.unwrap() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, message);
    }
}
