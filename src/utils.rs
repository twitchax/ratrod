//! Utility functions for the application.
//!
//! This module provides various utility functions for generating keys, encrypting/decrypting data, and handling tunnels.
//! It also includes functions for parsing tunnel definitions and handling bidirectional data transfer.

use std::sync::Arc;

use anyhow::{Context, anyhow};
use base64::Engine;
use bytes::BytesMut;
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
    net::{TcpStream, UdpSocket},
    select,
    sync::Mutex,
    task::JoinHandle,
    time::Instant,
};
use tracing::{debug, info};

use crate::{
    base::{Base64KeyPair, Constant, EncryptedData, ExchangeKeyPair, Res, SharedSecret, SharedSecretNonce, SharedSecretShape, TunnelDefinition, Void},
    buffed_stream::{BincodeSplit, BuffedTcpStream},
    protocol::{BincodeReceive, BincodeSend, Challenge, ProtocolMessage, Signature},
};

/// Generates a random alphanumeric string of the specified length.
///
/// This is used for creating unique identifiers, such as connection IDs.
pub fn random_string(len: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

/// Generates a random alphanumeric string of the specified length.
pub fn generate_key_pair() -> Res<Base64KeyPair> {
    let rng = SystemRandom::new();
    // Generate Ed25519 key pair in PKCS#8 format
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).context("Unable to generate key pair")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).context("Failed to create key pair")?;

    let public = Constant::BASE64_ENGINE.encode(key_pair.public_key().as_ref());
    let private = Constant::BASE64_ENGINE.encode(pkcs8.as_ref());

    Ok(Base64KeyPair { public_key: public, private_key: private })
}

/// Generates a key pair from a given private key.
pub fn generate_key_pair_from_key(private_key: &str) -> Res<Base64KeyPair> {
    let key_bytes = Constant::BASE64_ENGINE.decode(private_key).context("Could not decode seed")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes).context("Failed to create key pair")?;

    let public = Constant::BASE64_ENGINE.encode(key_pair.public_key().as_ref());

    Ok(Base64KeyPair {
        public_key: public,
        private_key: private_key.to_string(),
    })
}

/// Generates a random challenge for a peer to sign.
pub fn generate_challenge() -> Challenge {
    let rng = SystemRandom::new();
    let mut challenge = Challenge::default();
    rng.fill(&mut challenge).expect("Failed to generate challenge");
    challenge
}

/// Signs a challenge using the provided private key.
pub fn sign_challenge(challenge: &[u8], private_key: &SecretString) -> Res<Signature> {
    if challenge.len() != Constant::CHALLENGE_SIZE {
        return Err(anyhow!("Invalid challenge length"));
    }

    debug!("Challenge: `{:?}`", challenge);

    let private_key = Constant::BASE64_ENGINE.decode(private_key.expose_secret()).context("Could not decode private key")?;
    debug!("Signing challenge with private key: {:?}", &private_key);

    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key).map_err(|_| anyhow!("Invalid private key"))?;
    debug!("Key pair: {:?}", key_pair);

    let signature = key_pair.sign(challenge).as_ref()[..Constant::SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| anyhow!("Invalid signature length"))?;
    debug!("Signature: {:?}", &signature);

    Ok(signature)
}

/// Validates a signed challenge using the provided public key.
pub fn validate_signed_challenge(challenge: &[u8], signature: &[u8], public_key: &str) -> Void {
    if challenge.len() != Constant::CHALLENGE_SIZE {
        return Err(anyhow!("Invalid challenge length"));
    }

    if signature.len() != Constant::SIGNATURE_SIZE {
        return Err(anyhow!("Invalid signature length"));
    }

    let public_key = Constant::BASE64_ENGINE.decode(public_key).context("Could not decode public key")?;

    let unparsed_public_key = ring::signature::UnparsedPublicKey::new(Constant::SIGNATURE, public_key);

    unparsed_public_key.verify(challenge, signature).context("Invalid signature")?;

    Ok(())
}

/// Generates an ephemeral key pair for key exchange.
pub fn generate_ephemeral_key_pair() -> Res<ExchangeKeyPair> {
    let rng = SystemRandom::new();

    let my_private_key = EphemeralPrivateKey::generate(Constant::AGREEMENT, &rng)?;

    let public_key = my_private_key.compute_public_key()?;

    Ok(ExchangeKeyPair { public_key, private_key: my_private_key })
}

/// Derives a shared secret for encrypting and decrypting data.
pub fn generate_shared_secret(private_key: EphemeralPrivateKey, peer_public_key: &[u8], salt_bytes: &[u8]) -> Res<SharedSecret> {
    if peer_public_key.len() != Constant::EXCHANGE_PUBLIC_KEY_SIZE {
        return Err(anyhow!("Invalid public key length"));
    }

    let unparsed_peer_public_key = ring::agreement::UnparsedPublicKey::new(Constant::AGREEMENT, peer_public_key);

    let shared_secret = agree_ephemeral(private_key, &unparsed_peer_public_key, |shared_secret| generate_chacha_key(shared_secret, salt_bytes))??;
    Ok(shared_secret)
}

/// Generates a ChaCha20 key from the shared secret and salt bytes.
fn generate_chacha_key(private_key: &[u8], salt_bytes: &[u8]) -> Res<SharedSecret> {
    let salt = Salt::new(Constant::KDF, salt_bytes);
    let info = &[salt_bytes];

    let prk = salt.extract(private_key);
    let okm = prk.expand(info, Constant::KDF)?;

    let mut key = SharedSecretShape::default();
    okm.fill(&mut key)?;

    Ok(SharedSecret::init_with(|| key))
}

/// Encrypts the given plaintext using the shared secret.
pub fn encrypt(shared_secret: &SharedSecret, plaintext: &[u8]) -> Res<EncryptedData> {
    let mut in_out = BytesMut::from(plaintext);

    let nonce = encrypt_into(shared_secret, &mut in_out)?;

    Ok(EncryptedData { nonce, data: in_out.to_vec() })
}

/// Encrypts the data in place and appends the tag to the end of the buffer.
/// The nonce is generated randomly.
///
/// This method updates the `in_out` length.
pub fn encrypt_into(shared_secret: &SharedSecret, in_out: &mut BytesMut) -> Res<SharedSecretNonce> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; Constant::SHARED_SECRET_NONCE_SIZE];
    rng.fill(&mut nonce_bytes).context("Could not fill nonce for encryption")?;

    let unbound_key = UnboundKey::new(Constant::AEAD, shared_secret.expose_secret()).context("Could not generate unbound key for encryption")?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    sealing_key.seal_in_place_append_tag(nonce, Aad::empty(), in_out).context("Could not seal in place during encryption")?;

    Ok(nonce_bytes)
}

/// Decrypts the given ciphertext using the shared secret.
pub fn decrypt(shared_secret: &SharedSecret, nonce_bytes: &SharedSecretNonce, ciphertext: &[u8]) -> Res<Vec<u8>> {
    let mut in_out = BytesMut::from(ciphertext);

    decrypt_in_place(shared_secret, nonce_bytes, &mut in_out)?;

    Ok(in_out.to_vec())
}

/// Decrypts the data in place.
///
/// This method updates the `in_out` length.
pub fn decrypt_in_place(shared_secret: &SharedSecret, nonce_bytes: &SharedSecretNonce, in_out: &mut BytesMut) -> Void {
    let unbound_key = UnboundKey::new(Constant::AEAD, shared_secret.expose_secret()).context("Could not generate unbound key for decryption")?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let length = opening_key.open_in_place(nonce, Aad::empty(), in_out).context("Could not open in place for decryption")?.len();

    // SAFETY: Decryption in place reduces the length, so we can safely set the length
    // to the length of the decrypted data.
    unsafe {
        in_out.set_len(length);
    }

    Ok(())
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
        _ => Err(anyhow!("Invalid tunnel definition format")),
    }
}

/// Parses a list of tunnel definitions from the given input strings.
pub fn parse_tunnel_definitions<T>(tunnels: &[T]) -> Res<Vec<TunnelDefinition>>
where
    T: AsRef<str>,
{
    tunnels.iter().map(|tunnel| parse_tunnel_definition(tunnel.as_ref())).collect()
}

/// Handles bidirectional data transfer between two streams.
pub async fn handle_tcp_pump(a: TcpStream, b: BuffedTcpStream) -> Res<(u64, u64)> {
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

            write_b.push(ProtocolMessage::Data(&buf[..n])).await?;

            count += n as u64;
        }

        Ok(count)
    });

    let b_to_a: JoinHandle<Res<u64>> = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let guard = read_b.pull().await?;
            let data = match guard.message() {
                ProtocolMessage::Data(data) => data,
                ProtocolMessage::Shutdown => break,
                _ => return Err(anyhow!("Failed to read data in pump (wrong type)")),
            };

            if data.is_empty() {
                break;
            }

            write_a.write_all(data).await?;
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

/// Handles bidirectional data transfer between a UDP socket and a TCP stream.
pub async fn handle_udp_pump(a: UdpSocket, b: BuffedTcpStream) -> Void {
    // Split the client connection into a read and write half.
    let (mut b_read, mut b_write) = b.into_split();

    // Split the remote connection into a read and write half (just requires `Arc`ing, since the UDP send / receive does not require `&mut`).
    let a_up = Arc::new(a);
    let a_down = a_up.clone();

    // Run the pumps.

    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let last_activity_up = last_activity.clone();
    let last_activity_down = last_activity.clone();

    let pump_up: JoinHandle<Void> = tokio::spawn(async move {
        loop {
            let guard = b_read.pull().await?;
            let ProtocolMessage::UdpData(data) = guard.message() else {
                break;
            };

            a_up.send(data).await?;
            *last_activity_up.lock().await = Instant::now();
        }

        Ok(())
    });

    let pump_down: JoinHandle<Void> = tokio::spawn(async move {
        let mut buf = [0; Constant::BUFFER_SIZE];

        loop {
            let size = a_down.recv(&mut buf).await?;
            b_write.push(ProtocolMessage::UdpData(&buf[..size])).await?;
            *last_activity_down.lock().await = Instant::now();
        }
    });

    let timeout: JoinHandle<Void> = tokio::spawn(async move {
        loop {
            let last_activity = *last_activity.lock().await;

            if last_activity.elapsed() > Constant::TIMEOUT {
                info!("✅ UDP connection timed out (assumed graceful close).");
                return Ok(());
            }

            tokio::time::sleep(Constant::TIMEOUT).await;
        }
    });

    // Wait for the pumps to finish.  This employs a "last activity" type timeout, and uses `select!` to break
    // out of the loop if any of the pumps finish.  In general, the UDP side to the remote will not close,
    // but the client may break the pipe, so we need to handle that.
    // The `select!` macro will return the first result that completes,
    // and the `timeout` will return if the last activity is too long ago.

    let result = select! {
        r = pump_up => r?,
        r = pump_down => r?,
        r = timeout => r?,
    };

    // Check for errors.

    result?;

    Ok(())
}

#[cfg(test)]
pub mod tests {

    use crate::{
        buffed_stream::{BuffedDuplexStream, BuffedStream},
        protocol::ExchangePublicKey,
    };

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

        generate_shared_secret(ephemeral_key_pair.private_key, ephemeral_key_pair.public_key.as_ref(), &challenge).unwrap()
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

        let shared_secret_1 = generate_shared_secret(ephemeral_key_pair_1.private_key, ephemeral_key_pair_2.public_key.as_ref(), &challenge).unwrap();
        let shared_secret_2 = generate_shared_secret(ephemeral_key_pair_2.private_key, ephemeral_key_pair_1.public_key.as_ref(), &challenge).unwrap();

        assert_eq!(shared_secret_1.expose_secret().len(), Constant::SHARED_SECRET_SIZE);
        assert_eq!(shared_secret_1.expose_secret(), shared_secret_2.expose_secret());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let shared_secret = generate_test_shared_secret();

        let plaintext = b"Hello, world!";
        let encrypted_data = encrypt(&shared_secret, plaintext).unwrap();
        let decrypted_data = decrypt(&shared_secret, &encrypted_data.nonce, &encrypted_data.data).unwrap();

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
