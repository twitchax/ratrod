
pub type Err = anyhow::Error;
pub type Res<T> = anyhow::Result<T, Err>;
pub type Void = Res<()>;

pub struct Sentinel;

impl Sentinel {
    pub const SIZE: usize = 8;
    pub const BUFFER_SIZE: usize = 4096;
    pub const CHALLENGE_SIZE: usize = 32;
    pub const SIGNATURE_SIZE: usize = 64;
    pub const PRIVATE_KEY_SIZE: usize = 83;

    pub const DELIMITER: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBB";

    pub const PREAMBLE_INIT: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBC";

    pub const HANDSHAKE_CHALLENGE: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBD";
    pub const HANDSHAKE_CHALLENGE_RESPONSE: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBE";
    pub const HANDSHAKE_COMPLETION: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xBF";

    pub const ERROR_INVALID_KEY: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xCA";
    pub const ERROR_INVALID_HOST: &[u8] = b"\xAA\xAB\xAC\xAD\xAE\xAF\xBA\xCB";
}

/// Serves as the preamble for the connection.
pub struct Preamble {
    pub remote: String,
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