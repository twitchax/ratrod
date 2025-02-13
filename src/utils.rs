use std::time::Duration;

use rand::{distr::Alphanumeric, Rng};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::base::{Preamble, Res, Err, Sentinel};

pub fn random_string(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn hash_key(key: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();

    hasher.update(key);
    hasher.update(salt);

    format!("{:x}", hasher.finalize())
}

pub fn verify_key(key: &str, salt: &str, hash: &str) -> bool {
    hash_key(key, salt) == hash
}

pub async fn prepare_preamble(key: &str, host: &str) -> Res<Vec<u8>> {
    let key_bytes = key.as_bytes();
    let host_bytes = host.as_bytes();

    let mut preamble = Vec::with_capacity(key_bytes.len() + host_bytes.len() + 3 * Sentinel::SENTINEL_SIZE);

    preamble.extend_from_slice(Sentinel::PREAMBLE_DELIMITER);
    preamble.extend_from_slice(key_bytes);
    preamble.extend_from_slice(Sentinel::PREAMBLE_DELIMITER);
    preamble.extend_from_slice(host_bytes);
    preamble.extend_from_slice(Sentinel::PREAMBLE_DELIMITER);

    Ok(preamble)
}

pub async fn process_preamble<T>(stream: &mut T) -> Res<Preamble>
where 
    T: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(Sentinel::PREAMBLE_SIZE);
    let mut delim_indices = [0usize; 3];
    let mut num_delims = 0;

    let mut reader = BufReader::new(stream);

    for _ in 0..100 {
        let inner_buffer = reader.fill_buf().await?;

        // Find all delimiter indices.
        
        for (k, window) in inner_buffer.windows(Sentinel::SENTINEL_SIZE).enumerate() {
            if window == Sentinel::PREAMBLE_DELIMITER {
                delim_indices[num_delims] = k;
                num_delims += 1;

                if num_delims == 3 {
                    break;
                }
            }
        }

        if num_delims == 3 {
            buffer.extend_from_slice(&inner_buffer[..delim_indices[2] + Sentinel::SENTINEL_SIZE]);
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if num_delims != 3 {
        return Err(Err::msg("Unable to read preamble from stream after 100 100-millisecond reads (about 10 seconds)."));
    }

    // Since we found three delimiters, we can read the preamble.

    let delim1 = delim_indices[0];
    let delim2 = delim_indices[1];
    let delim3 = delim_indices[2];

    let key = String::from_utf8_lossy(&buffer[delim1 + Sentinel::SENTINEL_SIZE..delim2]);
    let host = String::from_utf8_lossy(&buffer[delim2 + Sentinel::SENTINEL_SIZE..delim3]);

    // Consume the preamble.
    reader.consume(delim3 + Sentinel::SENTINEL_SIZE);

    Ok(Preamble {
        key: key.to_string(),
        host: host.to_string(),
    })
}