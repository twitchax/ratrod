// Wire types.

use std::fmt::{Display, Formatter};

use anyhow::Context;
use futures::{Sink, SinkExt, Stream, StreamExt};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::base::{Constant, Err, Res, Void};

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
    pub peer_public_key: PeerPublicKey,
}

// Message types.

/// A helper trait for protocol messages.
pub trait BincodeMessage: Serialize + DeserializeOwned {}

/// A helper type for protocol messages.
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

pub trait BincodeSend: Sink<ProtocolMessage> + AsyncWrite + AsyncWriteExt + Unpin + Sized {
    fn push(&mut self, message: ProtocolMessage) -> impl Future<Output = Void> {
        async move { self.send(message).await.map_err(|_| Err::msg("Failed to send message")) }
    }
}

pub trait BincodeReceive: Stream<Item = std::io::Result<ProtocolMessage>> + AsyncRead + AsyncReadExt + Unpin + Sized {
    fn pull(&mut self) -> impl Future<Output = Res<ProtocolMessage>> {
        async move {
            let message = self.next().await.context("Failed to read message")?.context("Failed to parse message")?;
            Ok(message)
        }
    }
}

impl<T> BincodeSend for T where Self: Sink<ProtocolMessage> + AsyncWrite + Unpin + Sized {}
impl<T> BincodeReceive for T where Self: Stream<Item = std::io::Result<ProtocolMessage>> + AsyncRead + Unpin + Sized {}

// Signature serialization.

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
    use crate::{buffed_stream::BuffedStream, utils::tests::generate_test_fake_peer_public_key};

    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_bincode() {
        let (client, server) = tokio::io::duplex(Constant::BUFFER_SIZE);

        let data = Preamble {
            remote: "remote".to_string(),
            peer_public_key: generate_test_fake_peer_public_key(),
        };

        let mut client = BuffedStream::new(client);
        let mut server = BuffedStream::new(server);

        client.push(ProtocolMessage::HandshakeStart(data.clone())).await.unwrap();

        let ProtocolMessage::HandshakeStart(message) = server.pull().await.unwrap() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, message);
    }
}
