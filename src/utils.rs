//! Utility functions for the application.
//!
//! This module provides various utility functions for generating keys, encrypting/decrypting data, and handling tunnels.
//! It also includes functions for parsing tunnel definitions and handling bidirectional data transfer.

use anyhow::Context;
use base64::Engine;
use futures::future::Either;
use rand::{Rng, distr::Alphanumeric};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    agreement::{EphemeralPrivateKey, agree_ephemeral},
    hkdf::Salt,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use secrecy::{ExposeSecret, SecretString};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};
use tracing::{debug, info};

use crate::{
    base::{Base64KeyPair, Constant, EncryptedData, Err, ExchangeKeyPair, Res, SharedSecret, SharedSecretNonce, SharedSecretShape, TunnelDefinition, Void},
    buffed_stream::BuffedTcpStream,
    protocol::{BincodeReceive, BincodeSend, Challenge, ExchangePublicKey, ProtocolMessage, Signature},
};

/// Generates a random alphanumeric string of the specified length.
///
/// This is used for creating unique identifiers, such as connection IDs.
pub fn random_string(len: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

pub fn generate_key_pair() -> Res<Base64KeyPair> {
    let rng = SystemRandom::new();
    // Generate Ed25519 key pair in PKCS#8 format
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).context("Unable to generate key pair")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).context("Failed to create key pair")?;

    let public = Constant::BASE64_ENGINE.encode(key_pair.public_key().as_ref());
    let private = Constant::BASE64_ENGINE.encode(pkcs8.as_ref());

    Ok(Base64KeyPair { public_key: public, private_key: private })
}

pub fn generate_key_pair_from_key(private_key: &str) -> Res<Base64KeyPair> {
    let key_bytes = Constant::BASE64_ENGINE.decode(private_key).context("Could not decode seed")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes).context("Failed to create key pair")?;

    let public = Constant::BASE64_ENGINE.encode(key_pair.public_key().as_ref());

    Ok(Base64KeyPair {
        public_key: public,
        private_key: private_key.to_string(),
    })
}

pub fn generate_challenge() -> Challenge {
    let rng = SystemRandom::new();
    let mut challenge = Challenge::default();
    rng.fill(&mut challenge).expect("Failed to generate challenge");
    challenge
}

pub fn sign_challenge(challenge: &Challenge, private_key: &SecretString) -> Res<Signature> {
    debug!("Challenge: `{:?}`", challenge);

    let private_key = Constant::BASE64_ENGINE.decode(private_key.expose_secret()).context("Could not decode private key")?;
    debug!("Signing challenge with private key: {:?}", &private_key);

    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key).map_err(|_| Err::msg("Invalid private key"))?;
    debug!("Key pair: {:?}", key_pair);

    let signature = key_pair.sign(challenge).as_ref()[..Constant::SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| Err::msg("Invalid signature length"))?;
    debug!("Signature: {:?}", &signature);

    Ok(signature)
}

pub fn validate_signed_challenge(challenge: &Challenge, signature: &Signature, public_key: &str) -> Void {
    let public_key = Constant::BASE64_ENGINE.decode(public_key).context("Could not decode public key")?;

    let unparsed_public_key = ring::signature::UnparsedPublicKey::new(Constant::SIGNATURE, public_key);

    unparsed_public_key.verify(challenge, signature).context("Invalid signature")?;

    Ok(())
}

pub fn generate_ephemeral_key_pair() -> Res<ExchangeKeyPair> {
    let rng = SystemRandom::new();

    let my_private_key = EphemeralPrivateKey::generate(Constant::AGREEMENT, &rng)?;

    let public_key = my_private_key.compute_public_key()?;

    Ok(ExchangeKeyPair { public_key, private_key: my_private_key })
}

pub fn generate_shared_secret(private_key: EphemeralPrivateKey, peer_public_key: &ExchangePublicKey, salt_bytes: &[u8]) -> Res<SharedSecret> {
    let unparsed_peer_public_key = ring::agreement::UnparsedPublicKey::new(Constant::AGREEMENT, peer_public_key);

    let shared_secret = agree_ephemeral(private_key, &unparsed_peer_public_key, |shared_secret| generate_chacha_key(shared_secret, salt_bytes))??;
    Ok(shared_secret)
}

fn generate_chacha_key(private_key: &[u8], salt_bytes: &[u8]) -> Res<SharedSecret> {
    let salt = Salt::new(Constant::KDF, salt_bytes);
    let info = &[salt_bytes];

    let prk = salt.extract(private_key);
    let okm = prk.expand(info, Constant::KDF)?;

    let mut key = SharedSecretShape::default();
    okm.fill(&mut key)?;

    Ok(SharedSecret::init_with(|| key))
}

pub fn encrypt(shared_secret: &SharedSecret, plaintext: &[u8]) -> Res<EncryptedData> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; Constant::SHARED_SECRET_NONCE_SIZE];
    rng.fill(&mut nonce_bytes).context("Could not fill nonce for encryption")?;

    let unbound_key = UnboundKey::new(Constant::AEAD, shared_secret.expose_secret()).context("Could not generate unbound key for encryption")?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    in_out.reserve_exact(Constant::AEAD.tag_len());

    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .context("Could not seal in place during encryption")?;

    Ok(EncryptedData { nonce: nonce_bytes, data: in_out })
}

pub fn decrypt(shared_secret: &SharedSecret, ciphertext: &[u8], nonce_bytes: &SharedSecretNonce) -> Res<Vec<u8>> {
    let unbound_key = UnboundKey::new(Constant::AEAD, shared_secret.expose_secret()).context("Could not generate unbound key for decryption")?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key.open_in_place(nonce, Aad::empty(), &mut in_out).context("Could not open in place for decryption")?;

    Ok(plaintext.to_vec())
}

/// Parses the tunnel definition from the given input string.
///
/// Input is of the form:
/// - `local_port:destination_host:destination_port`
/// - `local_port:destination_port`
/// - `local_port`
pub fn parse_tunnel_definition(tunnel: &str) -> Res<TunnelDefinition> {
    let parts: Vec<&str> = tunnel.split(':').collect();

    match parts.len() {
        4 => {
            let bind_address = format!("{}:{}", parts[0], parts[1]);
            let host_address = format!("{}:{}", parts[2], parts[3]);

            Ok(TunnelDefinition {
                bind_address,
                remote_address: host_address,
            })
        }
        3 => {
            let bind_address = format!("127.0.0.1:{}", parts[0]);
            let host_address = format!("{}:{}", parts[1], parts[2]);

            Ok(TunnelDefinition {
                bind_address,
                remote_address: host_address,
            })
        }
        2 => {
            let bind_address = format!("127.0.0.1:{}", parts[0]);
            let host_address = format!("127.0.0.1:{}", parts[1]);

            Ok(TunnelDefinition {
                bind_address,
                remote_address: host_address,
            })
        }
        1 => {
            let bind_address = format!("127.0.0.1:{}", parts[0]);
            let host_address = format!("127.0.0.1:{}", parts[0]);

            Ok(TunnelDefinition {
                bind_address,
                remote_address: host_address,
            })
        }
        _ => Err(Err::msg("Invalid tunnel definition format")),
    }
}

pub fn parse_tunnel_definitions<T>(tunnels: &[T]) -> Res<Vec<TunnelDefinition>>
where
    T: AsRef<str>,
{
    tunnels.iter().map(|tunnel| parse_tunnel_definition(tunnel.as_ref())).collect()
}

pub async fn handle_pump(a: TcpStream, b: BuffedTcpStream) -> Res<(u64, u64)> {
    let (mut read_a, mut write_a) = a.into_split();
    let (mut read_b, mut write_b) = b.into_split();

    let a_to_b: JoinHandle<Res<u64>> = tokio::spawn(async move {
        let buf = &mut [0u8; Constant::BUFFER_SIZE];
        let mut count = 0;
        loop {
            let n = read_a.read(buf).await?;

            if n == 0 {
                break;
            }

            write_b.push(ProtocolMessage::Data(buf[..n].to_vec())).await?;

            count += n as u64;
        }

        Ok(count)
    });

    let b_to_a: JoinHandle<Res<u64>> = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let data = match read_b.pull().await? {
                ProtocolMessage::Data(data) => data,
                ProtocolMessage::Shutdown => break,
                _ => return Err(Err::msg("Failed to read data in pump (wrong type)")),
            };

            if data.is_empty() {
                break;
            }

            write_a.write_all(&data).await?;
            write_a.flush().await?;

            count += data.len() as u64;
        }

        Ok(count)
    });

    let result = futures::future::select(a_to_b, b_to_a).await;

    match result {
        Either::Left((a_to_b, other)) => {
            let right = a_to_b??;
            let left = other.await??;

            info!("📊 {} ⮀ {}", left, right);

            Ok((left, right))
        }
        Either::Right((b_to_a, other)) => {
            let right = b_to_a??;
            let left = other.await??;

            info!("📊 {} ⮀ {}", left, right);

            Ok((left, right))
        }
    }
}

#[cfg(test)]
pub mod tests {

    use crate::buffed_stream::{BuffedDuplexStream, BuffedStream};

    use super::*;
    use pretty_assertions::assert_eq;

    pub fn generate_test_duplex() -> (BuffedDuplexStream, BuffedDuplexStream) {
        let (a, b) = tokio::io::duplex(Constant::BUFFER_SIZE);
        (BuffedStream::from(a), BuffedStream::from(b))
    }

    pub fn generate_test_duplex_with_encryption() -> (BuffedDuplexStream, BuffedDuplexStream) {
        let (a, b) = tokio::io::duplex(Constant::BUFFER_SIZE);
        let secret_box = generate_test_shared_secret();
        let shared_secret = secret_box.expose_secret();

        (
            BuffedStream::from(a).with_encryption(SharedSecret::init_with(|| *shared_secret)),
            BuffedStream::from(b).with_encryption(SharedSecret::init_with(|| *shared_secret)),
        )
    }

    pub fn generate_test_ephemeral_key_pair() -> ExchangeKeyPair {
        generate_ephemeral_key_pair().unwrap()
    }

    pub fn generate_test_shared_secret() -> SharedSecret {
        let ephemeral_key_pair = generate_test_ephemeral_key_pair();
        let challenge = generate_challenge();

        generate_shared_secret(ephemeral_key_pair.private_key, ephemeral_key_pair.public_key.as_ref().try_into().unwrap(), &challenge).unwrap()
    }

    pub fn generate_test_fake_exchange_public_key() -> ExchangePublicKey {
        b"this needs to be exactly 32 byte".as_ref().try_into().unwrap()
    }

    #[test]
    fn test_generate_key_pair() {
        let key_pair = generate_key_pair().unwrap();
        assert_eq!(key_pair.public_key.len(), 43);
        assert_eq!(key_pair.private_key.len(), 111);
    }

    #[test]
    fn test_generate_key_pair_from_key() {
        let key_pair = generate_key_pair().unwrap();
        let new_key_pair = generate_key_pair_from_key(&key_pair.private_key).unwrap();
        assert_eq!(new_key_pair.public_key, key_pair.public_key);
        assert_eq!(new_key_pair.private_key, key_pair.private_key);
    }

    #[test]
    fn test_ed25519() {
        let key_pair = generate_key_pair().unwrap();

        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &key_pair.private_key.into()).unwrap();

        validate_signed_challenge(&challenge, &signature, &key_pair.public_key).unwrap();
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let ephemeral_key_pair_1 = generate_ephemeral_key_pair().unwrap();
        let ephemeral_key_pair_2 = generate_ephemeral_key_pair().unwrap();
        let challenge = generate_challenge();

        let shared_secret_1 = generate_shared_secret(ephemeral_key_pair_1.private_key, ephemeral_key_pair_2.public_key.as_ref().try_into().unwrap(), &challenge).unwrap();
        let shared_secret_2 = generate_shared_secret(ephemeral_key_pair_2.private_key, ephemeral_key_pair_1.public_key.as_ref().try_into().unwrap(), &challenge).unwrap();

        assert_eq!(shared_secret_1.expose_secret().len(), Constant::SHARED_SECRET_SIZE);
        assert_eq!(shared_secret_1.expose_secret(), shared_secret_2.expose_secret());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let shared_secret = generate_test_shared_secret();

        let plaintext = b"Hello, world!";
        let encrypted_data = encrypt(&shared_secret, plaintext).unwrap();
        let decrypted_data = decrypt(&shared_secret, &encrypted_data.data, &encrypted_data.nonce).unwrap();

        assert_eq!(decrypted_data, plaintext);
    }

    #[test]
    fn test_parse_tunnel_definition() {
        let input = "a:b:c:d";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "a:b");
        assert_eq!(result.remote_address, "c:d");

        let input = "a:b:c";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "127.0.0.1:a");
        assert_eq!(result.remote_address, "b:c");

        let input = "a:b";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "127.0.0.1:a");
        assert_eq!(result.remote_address, "127.0.0.1:b");

        let input = "a";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "127.0.0.1:a");
        assert_eq!(result.remote_address, "127.0.0.1:a");
    }

    #[test]
    fn test_bad_tunnel_definition() {
        let input = "a:b:c:d:e";
        assert!(parse_tunnel_definition(input).is_err());

        let input = "a:b:c:d:e:f";
        assert!(parse_tunnel_definition(input).is_err());
    }
}
