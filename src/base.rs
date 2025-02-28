//! This module contains constants and types used throughout the code.
//!
//! It includes constants for cryptographic algorithms, buffer sizes, and other parameters.

use base64::{engine::GeneralPurpose, prelude::BASE64_URL_SAFE_NO_PAD};
use ring::{
    aead::{self, CHACHA20_POLY1305},
    agreement::{EphemeralPrivateKey, PublicKey},
    hkdf::{self, HKDF_SHA256},
};

use crate::protocol::{Challenge, PeerPublicKey, Preamble};

/// A helper type for errors.
pub type Err = anyhow::Error;
/// A helper type for results.
pub type Res<T> = anyhow::Result<T, Err>;
/// A helper type for void results.
pub type Void = Res<()>;

/// A struct for constants.
pub struct Constant;

impl Constant {
    pub const AEAD: &'static aead::Algorithm = &CHACHA20_POLY1305;
    pub const AGREEMENT: &'static ring::agreement::Algorithm = &ring::agreement::X25519;
    pub const BASE64_ENGINE: GeneralPurpose = BASE64_URL_SAFE_NO_PAD;
    pub const BUFFER_SIZE: usize = 8192;
    pub const CHALLENGE_SIZE: usize = 32;
    pub const DELIMITER: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBB";
    pub const DELIMITER_SIZE: usize = 8;
    pub const ENCRYPTION_OVERHEAD: usize = Self::SHARED_SECRET_NONCE_SIZE + Self::SHARED_SECRET_TAG_SIZE + Self::DELIMITER_SIZE;
    pub const KDF: hkdf::Algorithm = HKDF_SHA256;
    pub const NULL_PEER_PUBLIC_KEY: PeerPublicKey = [0; Self::PEER_PUBLIC_KEY_SIZE];
    pub const PEER_PUBLIC_KEY_SIZE: usize = 32;
    pub const PRIVATE_KEY_SIZE: usize = 83;
    pub const SHARED_SECRET_NONCE_SIZE: usize = 12;
    pub const SHARED_SECRET_SIZE: usize = 32;
    pub const SHARED_SECRET_TAG_SIZE: usize = 16;
    pub const SIGNATURE: &'static ring::signature::EdDSAParameters = &ring::signature::ED25519;
    pub const SIGNATURE_SIZE: usize = 64;
}

/// A helper type for a shared secret.
///
/// These are the secrets that each end of the connection will use to encrypt and decrypt data.
/// They are derived from the ephemeral keys, and DH key exchange.
pub type SharedSecret = [u8; Constant::SHARED_SECRET_SIZE];

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
pub struct EphemeralKeyPair {
    pub public_key: PublicKey,
    pub private_key: EphemeralPrivateKey,
}

/// A wrapper for a local ephemeral key pair, and a peer public key.
///
/// This is used to derive a shared secret, which is used to encrypt and decrypt data.
/// Essentially, it holds the instances _local_ public/private key pair, and the _remote_ peer public key.
/// The _local_ private key, couples with the _peer_ public key and challenge is used to derive the shared secret.
pub struct ClientKeyExchangeData {
    pub local_private_key: EphemeralPrivateKey,
    pub peer_public_key: PeerPublicKey,
    pub challenge: Challenge,
}

/// A wrapper for the Preamble, and the EphemeralKeyPair.
///
/// This is mostly used as a convenience type, to hold the preamble and the ephemeral key pair together.
pub struct ServerHandshakeData {
    pub preamble: Preamble,
    pub local_ephemeral_key_pair: EphemeralKeyPair,
}

/// A wrapper for the Challenge, and the PeerPublicKey.
///
/// This is mostly used as a convenience type, to hold the challenge and the peer public key together.
pub struct ClientHandshakeData {
    pub challenge: Challenge,
    pub peer_public_key: PeerPublicKey,
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
