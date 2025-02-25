use base64::{engine::GeneralPurpose, prelude::BASE64_URL_SAFE_NO_PAD};
use ring::{aead::{self, CHACHA20_POLY1305}, agreement::{EphemeralPrivateKey, PublicKey}, hkdf::{self, HKDF_SHA256}};


pub type Err = anyhow::Error;
pub type Res<T> = anyhow::Result<T, Err>;
pub type Void = Res<()>;

pub struct Constant;

impl Constant {
    pub const BASE64_ENGINE: GeneralPurpose = BASE64_URL_SAFE_NO_PAD;

    pub const KDF: hkdf::Algorithm = HKDF_SHA256;
    pub const AGREEMENT: &'static ring::agreement::Algorithm = &ring::agreement::X25519;
    pub const SIGNATURE: &'static ring::signature::EdDSAParameters = &ring::signature::ED25519;
    pub const AEAD: &'static aead::Algorithm = &CHACHA20_POLY1305;

    pub const DELIMITER_SIZE: usize = 8;
    pub const BUFFER_SIZE: usize = 8192;

    pub const CHALLENGE_SIZE: usize = 32;
    pub const SIGNATURE_SIZE: usize = 64;
    pub const PRIVATE_KEY_SIZE: usize = 83;

    pub const PEER_PUBLIC_KEY_SIZE: usize = 32;
    pub const SHARED_SECRET_SIZE: usize = 32;
    pub const SHARED_SECRET_NONCE_SIZE: usize = 12;
    pub const SHARED_SECRET_TAG_SIZE: usize = 16;
    pub const ENCRYPTION_OVERHEAD: usize = Self::SHARED_SECRET_NONCE_SIZE + Self::SHARED_SECRET_TAG_SIZE + Self::DELIMITER_SIZE;

    pub const DELIMITER: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBB";

    pub const PREAMBLE_INIT: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBC";

    pub const HANDSHAKE_CHALLENGE: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBD";
    pub const HANDSHAKE_CHALLENGE_RESPONSE: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBE";
    pub const HANDSHAKE_COMPLETION: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBF";

    pub const ERROR_INVALID_KEY: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xCA";
    pub const ERROR_INVALID_HOST: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xCB";
}

/// A helper type for a shared secret.
pub type SharedSecret = [u8; Constant::SHARED_SECRET_SIZE];

/// A helper type for a shared secret nonce.
pub type SharedSecretNonce = [u8; Constant::SHARED_SECRET_NONCE_SIZE];

/// A helper type for a challenge.
pub type Challenge = [u8; Constant::CHALLENGE_SIZE];

/// A helper type for a signature.
pub type Signature = [u8; Constant::SIGNATURE_SIZE];

/// A helper type for an ephemeral public key.
pub type PeerPublicKey = [u8; Constant::PEER_PUBLIC_KEY_SIZE];

/// Serves as the preamble for the connection.
pub struct Preamble {
    pub remote: String,
    pub peer_public_key: PeerPublicKey,
}

/// The bind address and host address for the client.
pub struct TunnelDefinition {
    pub bind_address: String,
    pub remote_address: String,
}

/// A public-private key pair.
pub struct Base64KeyPair {
    pub public_key: String,
    pub private_key: String,
}

/// A public-private key pair for ephemeral key exchange.
pub struct EphemeralKeyPair {
    pub public_key: PublicKey,
    pub private_key: EphemeralPrivateKey,
}

/// A wrapper for a local ephemeral key pair, and a peer public key.
pub struct EphemeralData {
    pub ephemeral_key_pair: EphemeralKeyPair,
    pub peer_public_key: PeerPublicKey,
    pub challenge: Challenge,
}

/// A wrapper for the Preamble, and the EphemeralKeyPair.
pub struct HandshakeData {
    pub preamble: Preamble,
    pub ephemeral_key_pair: EphemeralKeyPair,
}

/// A wrapper for encrypted data, and its nonce.
pub struct EncryptedData {
    pub nonce: SharedSecretNonce,
    pub data: Vec<u8>,
}