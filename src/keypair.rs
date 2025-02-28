//! Keypair generation and resolution.
//!
//! This module provides functions to generate a keypair, resolve private and public keys from files or strings, and handle errors related to key resolution.

use anyhow::Context;
use base64::Engine;
use tracing::info;

use crate::{
    base::{Constant, Err, Res, Void},
    utils,
};

/// Gets the user's home directory.
pub fn get_home() -> Res<String> {
    let home = homedir::my_home()
        .context("Failed to get home directory.")?
        .ok_or_else(|| Err::msg("Failed to get home directory."))?
        .to_string_lossy()
        .to_string();

    Ok(home)
}

/// Generates a keypair and writes them to the specified location.
pub fn generate(print: bool, location: Option<String>, filename: Option<String>) -> Void {
    let home = get_home()?;
    let pair = utils::generate_key_pair()?;

    if print {
        info!("📢 Public key: `{}`", pair.public_key);
        info!("🔑 Private key: `{}`", pair.private_key);
    }

    let location = location.unwrap_or_else(|| format!("{}/.ratrod", home));

    let filename = filename.unwrap_or_else(|| "key".to_string());

    let path = format!("{}/{}", location, filename);

    std::fs::create_dir_all(&location).context("Failed to create directory")?;
    std::fs::write(&path, pair.private_key).context("Failed to write private key")?;
    std::fs::write(format!("{}.pub", path), pair.public_key).context("Failed to write public key")?;

    info!("📦 Keypair written to `{}`", path);

    Ok(())
}

/// Resolves the private key from a file or string.
pub fn resolve_private_key(key: Option<String>) -> Res<String> {
    let path = match key {
        Some(key) => {
            // First, see if the user provided as a command line argument.
            if Constant::BASE64_ENGINE.decode(&key).is_ok() {
                return Ok(key);
            }

            // The key is likely a file path.
            key
        }
        None => {
            // If no key was provided, fall back to the default location.
            let home = get_home()?;
            format!("{}/.ratrod/key", home)
        }
    };

    std::fs::read_to_string(&path).context("Failed to read private key")
}

/// Resolves the public key from a file or string.
pub fn resolve_public_key(key: Option<String>) -> Res<String> {
    let path = match key {
        Some(key) => {
            // First, see if the user provided as a command line argument.
            if Constant::BASE64_ENGINE.decode(&key).is_ok() {
                return Ok(key);
            }

            // The key is likely a file path.
            key
        }
        None => {
            // If no key was provided, fall back to the default location.
            let home = get_home()?;
            format!("{}/.ratrod/key.pub", home)
        }
    };

    std::fs::read_to_string(&path).context("Failed to read public key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{generate_challenge, generate_key_pair, sign_challenge, validate_signed_challenge};

    #[test]
    fn test_generate() {
        generate(true, Some("./target/test".to_string()), Some("fake_key".to_string())).unwrap();

        let private_key = resolve_private_key(Some("./target/test/fake_key".to_string())).unwrap();
        let public_key = resolve_public_key(Some("./target/test/fake_key.pub".to_string())).unwrap();

        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &private_key).unwrap();

        validate_signed_challenge(&challenge, &signature, &public_key).unwrap();
    }

    #[test]
    fn test_from_text() {
        let keypair = generate_key_pair().unwrap();
        let private_key = keypair.private_key;
        let public_key = keypair.public_key;

        let private_key = resolve_private_key(Some(private_key)).unwrap();
        let public_key = resolve_public_key(Some(public_key)).unwrap();

        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &private_key).unwrap();
        validate_signed_challenge(&challenge, &signature, &public_key).unwrap();
    }
}
