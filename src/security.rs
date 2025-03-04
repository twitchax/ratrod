//! Keypair generation and resolution.
//!
//! This module provides functions to generate a keypair, resolve private and public keys from files or strings, and handle errors related to key resolution.

use anyhow::Context;
use secrecy::SecretString;
use tracing::info;

use crate::{
    base::{Err, Res, Void},
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

/// Computes the concrete keypath.
pub fn resolve_keypath<P>(path: P) -> Res<String>
where
    P: Into<Option<String>>,
{
    let home = get_home()?;
    let path = match path.into() {
        Some(path) => path,
        None => format!("{}/.ratrod", home),
    };

    Ok(path)
}

/// Generates a keypair and writes them to the specified location.
pub fn generate<P>(print: bool, path: P) -> Void
where
    P: AsRef<str>,
{
    let pair = utils::generate_key_pair()?;

    if print {
        info!("📢 Public key: `{}`", pair.public_key);
        info!("🔑 Private key: `{}`", pair.private_key);
    }

    std::fs::create_dir_all(path.as_ref()).context("Failed to create directory")?;

    let file = format!("{}/key", path.as_ref());

    std::fs::write(&file, pair.private_key).context("Failed to write private key")?;
    std::fs::write(format!("{}.pub", file), pair.public_key).context("Failed to write public key")?;

    info!("📦 Keypair written to `{}`", file);

    Ok(())
}

/// Resolves the private key of this instance.
pub fn resolve_private_key<P>(path: P) -> Res<SecretString>
where
    P: AsRef<str>,
{
    let file = format!("{}/key", path.as_ref());

    Ok(std::fs::read_to_string(&file)
        .context("Failed to read private key (you may need to run `generate-keypair`)")
        .map(|s| s.trim().to_string())?
        .into())
}

/// Resolves the public key of this instance.
pub fn resolve_public_key<P>(path: P) -> Res<String>
where
    P: AsRef<str>,
{
    let file = format!("{}/key.pub", path.as_ref());

    std::fs::read_to_string(&file)
        .context("Failed to read public key (you may need to run `generate-keypair`)")
        .map(|s| s.trim().to_string())
}

/// Resolves to the list of known hosts.
pub fn resolve_known_hosts<P>(path: P) -> Vec<String>
where
    P: AsRef<str>,
{
    let file = format!("{}/known_hosts", path.as_ref());

    std::fs::read_to_string(&file).unwrap_or_default().lines().map(|s| s.trim().to_string()).collect()
}

/// Resolves to the list of authorized keys.
pub fn resolve_authorized_keys<P>(path: P) -> Vec<String>
where
    P: AsRef<str>,
{
    let file = format!("{}/authorized_keys", path.as_ref());

    std::fs::read_to_string(&file).unwrap_or_default().lines().map(|s| s.trim().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{generate_challenge, sign_challenge, validate_signed_challenge};

    #[test]
    fn test_generate() {
        generate(true, "./target/test").unwrap();

        let private_key = resolve_private_key("./target/test").unwrap();
        let public_key = resolve_public_key("./target/test").unwrap();

        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &private_key).unwrap();

        validate_signed_challenge(&challenge, &signature, &public_key).unwrap();
    }

    #[test]
    fn test_get_authorized_keys() {
        let keys = resolve_authorized_keys("./test/server");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "iFOM_F9if7PwXmaCMttge8lhJHYjjS_hYUOZwZkHsi0");
    }

    #[test]
    fn test_get_known_hosts() {
        let keys = resolve_known_hosts("./test/client");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "HQYY0BNIhdawY2Jw62DudkUsK2GKj3hGO3qSVBlCinI");
    }
}
