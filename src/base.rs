//! This module contains constants and types used throughout the code.
//!
//! It includes constants for cryptographic algorithms, buffer sizes, and other parameters.

use std::time::Duration;

use base64::{engine::GeneralPurpose, prelude::BASE64_URL_SAFE_NO_PAD};
use bincode::config::BigEndian;
use ring::{
    aead::{self, CHACHA20_POLY1305},
    agreement::{EphemeralPrivateKey, PublicKey},
    hkdf::{self, HKDF_SHA256},
};
use secrecy::SecretBox;

use crate::protocol::{Challenge, ExchangePublicKey};

/// A helper type for errors.
pub type Err = anyhow::Error;
/// A helper type for results.
pub type Res<T> = anyhow::Result<T, Err>;
/// A helper type for void results.
pub type Void = Res<()>;
/// A struct for constants.
pub struct Constant;

impl Constant {
    /// The AEAD algorithm used for encryption.
    pub const AEAD: &'static aead::Algorithm = &CHACHA20_POLY1305;
    /// The alrgorithm used for key agreement.
    pub const AGREEMENT: &'static ring::agreement::Algorithm = &ring::agreement::X25519;
    /// Thedefault base4 engine used for encoding and decoding keys.
    pub const BASE64_ENGINE: GeneralPurpose = BASE64_URL_SAFE_NO_PAD;
    /// The default bincode engine used for encoding and decoding data across data streams.
    pub const BINCODE_CONFIG: bincode::config::Configuration<BigEndian> = bincode::config::standard().with_big_endian();
    /// The default buffer size (defaulting to extra large for now).
    pub const BUFFER_SIZE: usize = 128 * 1024 - Constant::ENCRYPTION_OVERHEAD;
    /// The size of a signature challenge.
    pub const CHALLENGE_SIZE: usize = 32;
    /// The size of the encryption overhead.
    pub const ENCRYPTION_OVERHEAD: usize = 256;
    /// The size of a key exchange public key.
    pub const EXCHANGE_PUBLIC_KEY_SIZE: usize = 32;
    /// The base64 encoded size of a key exchange private key.
    pub const IDENTITY_PRIVATE_KEY_LENGTH: usize = 111;
    /// The base64 encoded size of a key exchange public key.
    pub const IDENTITY_PUBLIC_KEY_LENGTH: usize = 43;
    /// The algorithm used to produce the shared secret of the key exchange.
    pub const KDF: hkdf::Algorithm = HKDF_SHA256;
    /// The size of the shared secret nonce.
    pub const SHARED_SECRET_NONCE_SIZE: usize = 12;
    /// The size of the shared secret.
    pub const SHARED_SECRET_SIZE: usize = 32;
    /// The size of the shared secret encryption tag.
    pub const SHARED_SECRET_TAG_SIZE: usize = 16;
    /// The type of signature used for the handshake.
    pub const SIGNATURE: &'static ring::signature::EdDSAParameters = &ring::signature::ED25519;
    /// The size of the signature used for the handshake.
    pub const SIGNATURE_SIZE: usize = 64;
    /// The default timeout for the stale connections.
    pub const TIMEOUT: Duration = Duration::from_secs(120);
}

/// A helper for the Shape of the shared secret.
pub type SharedSecretShape = [u8; Constant::SHARED_SECRET_SIZE];

/// A helper type for a shared secret.
///
/// These are the secrets that each end of the connection will use to encrypt and decrypt data.
/// They are derived from the ephemeral keys, and DH key exchange.
pub type SharedSecret = SecretBox<SharedSecretShape>;

/// A helper type for a shared secret nonce.
///
/// These are the nonces that each end of the connection will use to encrypt and decrypt data.
/// They are generated randomly, and are used to ensure that the same data encrypted multiple times will
/// produce different ciphertexts.
pub type SharedSecretNonce = [u8; Constant::SHARED_SECRET_NONCE_SIZE];

/// The bind address and host address for the client.
///
/// This is used to determine where to bind the socket, and where to connect to on the server side.
/// Essentially, this is the tunnel.
#[derive(Clone, Debug)]
pub struct TunnelDefinition {
    pub bind_address: String,
    pub remote_address: String,
}

/// A public-private key pair.
///
/// This is used to sign and verify data, primarily during the handshake phase.
#[derive(Clone, Debug)]
pub struct Base64KeyPair {
    pub public_key: String,
    pub private_key: String,
}

/// A public-private key pair for ephemeral key exchange.
///
/// This is used to derive a shared secret, which is used to encrypt and decrypt data.
/// This is used during the handshake phase.
pub struct ExchangeKeyPair {
    pub public_key: PublicKey,
    pub private_key: EphemeralPrivateKey,
}

/// A wrapper for a local ephemeral key pair, and a peer public key.
///
/// This is used to derive a shared secret, which is used to encrypt and decrypt data.
/// Essentially, it holds the instances _local_ public/private key pair, and the _remote_ peer public key.
/// The _local_ private key, couples with the _peer_ public key and challenge is used to derive the shared secret.
#[derive(Debug)]
pub struct ClientKeyExchangeData {
    pub server_exchange_public_key: ExchangePublicKey,
    pub server_challenge: Challenge,
    pub local_exchange_private_key: EphemeralPrivateKey,
    pub local_challenge: Challenge,
}

/// A wrapper for the Preamble, and the EphemeralKeyPair.
///
/// This is mostly used as a convenience type, to hold the preamble and the ephemeral key pair together.
pub struct ServerKeyExchangeData {
    pub client_exchange_public_key: ExchangePublicKey,
    pub client_challenge: Challenge,
    pub local_exchange_private_key: EphemeralPrivateKey,
    pub local_challenge: Challenge,
    pub requested_remote_address: String,
    pub requested_should_encrypt: bool,
    pub requested_is_udp: bool,
}

/// A wrapper for the Challenge, and the PeerPublicKey.
///
/// This is mostly used as a convenience type, to hold the challenge and the peer public key together.
#[derive(Clone, Debug)]
pub struct ClientHandshakeData {
    pub server_challenge: Challenge,
    pub server_exchange_public_key: ExchangePublicKey,
}

/// A wrapper for encrypted data, and its nonce.
///
/// This is used to encrypt and decrypt data, using the shared secret.
/// The nonce is used to ensure that the same data encrypted multiple times will produce different ciphertexts.
/// The data and nonce, together, are required to decrypt the data.
pub struct EncryptedData {
    pub nonce: SharedSecretNonce,
    pub data: Vec<u8>,
}
