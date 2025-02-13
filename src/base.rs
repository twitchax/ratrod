
pub type Err = anyhow::Error;
pub type Res<T> = anyhow::Result<T, Err>;
pub type Void = Res<()>;

pub struct Sentinel;

impl Sentinel {
    pub const PREAMBLE_SIZE: usize = 4096;
    pub const SENTINEL_SIZE: usize = 8;

    pub const PREAMBLE_DELIMITER: &[u8] = b"\xAA\xBB\xCC\xDD\xEE\xFF\x99\x88";
    pub const PREAMBLE_COMPLETION: &[u8] = b"\xAA\xBB\xCC\xDD\xEE\xFF\x99\x77";

    pub const ERROR_INVALID_KEY: &[u8] = b"\xAA\xBB\xCC\xDD\xEE\xFF\x99\x66";
    pub const ERROR_INVALID_HOST: &[u8] = b"\xAA\xBB\xCC\xDD\xEE\xFF\x99\x55";
}

/// Serves as the preamble for the connection.
pub struct Preamble {
    pub key: String,
    pub host: String,
}