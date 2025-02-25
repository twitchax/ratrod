use std::time::Duration;

use anyhow::Context;
use base64::Engine;
use rand::{Rng, distr::Alphanumeric};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    agreement::{EphemeralPrivateKey, agree_ephemeral},
    hkdf::Salt,
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite};
use tracing::{debug, info};

use crate::base::{Base64KeyPair, Challenge, Constant, EncryptedData, EphemeralKeyPair, Err, PeerPublicKey, Preamble, Res, SharedSecret, SharedSecretNonce, Signature, TunnelDefinition, Void};

pub fn random_string(len: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(len).map(char::from).collect()
}

pub fn generate_key_pair() -> Res<Base64KeyPair> {
    let rng = SystemRandom::new();
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

pub fn sign_challenge(challenge: &[u8], private_key: &str) -> Res<Signature> {
    debug!("Challenge: `{:?}`", challenge);

    let private_key = Constant::BASE64_ENGINE.decode(private_key).context("Could not decode private key")?;
    debug!("Signing challenge with private key: {:?}", &private_key);

    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key).map_err(|_| Err::msg("Invalid private key"))?;
    debug!("Key pair: {:?}", key_pair);

    let signature = key_pair.sign(challenge).as_ref()[..Constant::SIGNATURE_SIZE]
        .try_into()
        .map_err(|_| Err::msg("Invalid signature length"))?;
    debug!("Signature: {:?}", &signature);

    Ok(signature)
}

pub fn generate_ephemeral_key_pair() -> Res<EphemeralKeyPair> {
    let rng = SystemRandom::new();

    let my_private_key = EphemeralPrivateKey::generate(Constant::AGREEMENT, &rng)?;

    let public_key = my_private_key.compute_public_key()?;

    Ok(EphemeralKeyPair { public_key, private_key: my_private_key })
}

pub fn generate_shared_secret(private_key: EphemeralPrivateKey, peer_public_key: &PeerPublicKey, challenge: &Challenge) -> Res<SharedSecret> {
    let unparsed_peer_public_key = ring::agreement::UnparsedPublicKey::new(Constant::AGREEMENT, peer_public_key);
    let shared_secret = agree_ephemeral(private_key, &unparsed_peer_public_key, |shared_secret| generate_chacha_key(shared_secret, challenge))??;

    Ok(shared_secret)
}

fn generate_chacha_key(private_key: &[u8], challenge: &[u8]) -> Res<SharedSecret> {
    let salt = Salt::new(Constant::KDF, challenge);
    let info = &[challenge];

    let prk = salt.extract(private_key);
    let okm = prk.expand(info, Constant::KDF)?;

    let mut key = SharedSecret::default();
    okm.fill(&mut key)?;

    Ok(key)
}

pub fn encrypt(chacha_key: &[u8], plaintext: &[u8]) -> Res<EncryptedData> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; Constant::SHARED_SECRET_NONCE_SIZE];
    rng.fill(&mut nonce_bytes).context("Could not fill nonce for encryption")?;

    let unbound_key = UnboundKey::new(Constant::AEAD, chacha_key).context("Could not generate unbound key for encryption")?;
    let sealing_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    in_out.reserve_exact(Constant::AEAD.tag_len());

    sealing_key
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
        .context("Could not seal in place during encryption")?;

    Ok(EncryptedData { nonce: nonce_bytes, data: in_out })
}

pub fn decrypt(chacha_key: &[u8], ciphertext: &[u8], nonce_bytes: &SharedSecretNonce) -> Res<Vec<u8>> {
    let unbound_key = UnboundKey::new(Constant::AEAD, chacha_key).context("Could not generate unbound key for decryption")?;
    let opening_key = LessSafeKey::new(unbound_key);
    let nonce = Nonce::assume_unique_for_key(*nonce_bytes);

    let mut in_out = ciphertext.to_vec();
    let plaintext = opening_key.open_in_place(nonce, Aad::empty(), &mut in_out).context("Could not open in place for decryption")?;

    Ok(plaintext.to_vec())
}

pub fn validate_signed_challenge(challenge: &[u8], signature: &[u8], public_key: &str) -> Void {
    let public_key = Constant::BASE64_ENGINE.decode(public_key).context("Could not decode public key")?;

    let unparsed_public_key = ring::signature::UnparsedPublicKey::new(Constant::SIGNATURE, public_key);

    unparsed_public_key.verify(challenge, signature).context("Invalid signature")?;

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
        _ => Err(Err::msg("Invalid tunnel definition format")),
    }
}

pub fn parse_tunnel_definitions<T>(tunnels: &[T]) -> Res<Vec<TunnelDefinition>>
where 
    T: AsRef<str>,
{
    tunnels.iter().map(|tunnel| parse_tunnel_definition(tunnel.as_ref())).collect()
}

pub fn prepare_preamble(remote: &str, peer_public_key: &PeerPublicKey) -> Res<Vec<u8>> {
    let remote_bytes = remote.as_bytes();

    let preamble = [Constant::PREAMBLE_INIT, remote_bytes, Constant::DELIMITER, peer_public_key, Constant::DELIMITER].concat();

    Ok(preamble)
}

pub async fn process_preamble<T>(stream: &mut T) -> Res<Preamble>
where
    T: AsyncBufRead + Unpin,
{
    let data = read_to_next_delimiter(stream).await?;

    let (init, remote_bytes) = data.split_at(Constant::DELIMITER_SIZE);

    if init != Constant::PREAMBLE_INIT {
        return Err(Err::msg("Invalid preamble"));
    }

    let remote = String::from_utf8(remote_bytes.to_vec()).context("Invalid UTF-8 in preamble")?;

    let peer_public_key = read_to_next_delimiter(stream).await?.try_into().map_err(|_| Err::msg("Invalid ephemeral public key length"))?;

    Ok(Preamble { remote, peer_public_key })
}

pub fn find_next_delimiter(data: &[u8]) -> Option<usize> {
    data.windows(Constant::DELIMITER_SIZE).position(|window| window == Constant::DELIMITER)
}

pub async fn read_to_next_delimiter<T>(stream: &mut T) -> Res<Vec<u8>>
where
    T: AsyncBufRead + Unpin,
{
    let mut buffer = Vec::with_capacity(Constant::BUFFER_SIZE);
    let mut delimiter_index = usize::MAX;

    for _ in 0..100 {
        let inner_buffer = stream.fill_buf().await?;

        // Find next delimiter.

        for (k, window) in inner_buffer.windows(Constant::DELIMITER_SIZE).enumerate() {
            if window == Constant::DELIMITER {
                delimiter_index = k;
                break;
            }
        }

        if delimiter_index != usize::MAX {
            buffer.extend_from_slice(&inner_buffer[..delimiter_index]);
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    if delimiter_index == usize::MAX {
        return Err(Err::msg("Unable to read to next delimiter from stream after 100 100-millisecond reads (about 10 seconds)."));
    }

    // Consume the data.
    stream.consume(delimiter_index + Constant::DELIMITER_SIZE);

    Ok(buffer)
}

pub async fn handle_pump<A, B>(a: &mut A, b: &mut B) -> Res<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let result = tokio::io::copy_bidirectional_with_sizes(a, b, Constant::BUFFER_SIZE, Constant::BUFFER_SIZE).await?;

    info!("➡️ {} bytes ⬅️ {} bytes", result.0, result.1);

    Ok(result)
}

#[cfg(test)]
pub mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
        vec,
    };
    use tokio::io::AsyncWriteExt;

    use crate::buffed_stream::BuffedStream;

    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::{
        io::{AsyncWrite, ReadBuf},
        net::TcpListener,
    };

    pub struct MockStream {
        pub read: Vec<u8>,
        pub write: Vec<u8>,
    }

    impl MockStream {
        pub fn new(read: Vec<u8>, write: Vec<u8>) -> Self {
            Self { read, write }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().read.as_slice()).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().write).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().write).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
        }
    }

    pub struct EchoServer;

    impl EchoServer {
        pub async fn start(bind_address: String) -> Void {
            let listener = TcpListener::bind(bind_address).await?;

            loop {
                let (client, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let (mut read, mut write) = client.into_split();

                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        }
    }

    pub fn generate_test_ephemeral_key_pair() -> EphemeralKeyPair {
        generate_ephemeral_key_pair().unwrap()
    }

    pub fn generate_test_shared_secret() -> SharedSecret {
        let ephemeral_key_pair = generate_test_ephemeral_key_pair();
        let challenge = generate_challenge();

        generate_shared_secret(ephemeral_key_pair.private_key, ephemeral_key_pair.public_key.as_ref().try_into().unwrap(), &challenge).unwrap()
    }

    pub fn generate_test_fake_peer_public_key() -> PeerPublicKey {
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
        let signature = sign_challenge(&challenge, &key_pair.private_key).unwrap();

        validate_signed_challenge(&challenge, &signature, &key_pair.public_key).unwrap();
    }

    #[test]
    fn test_ephemeral_key_exchange() {
        let ephemeral_key_pair_1 = generate_ephemeral_key_pair().unwrap();
        let ephemeral_key_pair_2 = generate_ephemeral_key_pair().unwrap();
        let challenge = generate_challenge();

        let shared_secret_1 = generate_shared_secret(ephemeral_key_pair_1.private_key, ephemeral_key_pair_2.public_key.as_ref().try_into().unwrap(), &challenge).unwrap();
        let shared_secret_2 = generate_shared_secret(ephemeral_key_pair_2.private_key, ephemeral_key_pair_1.public_key.as_ref().try_into().unwrap(), &challenge).unwrap();

        assert_eq!(shared_secret_1.len(), Constant::SHARED_SECRET_SIZE);
        assert_eq!(shared_secret_1, shared_secret_2);
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

    #[test]
    fn test_prepare_preamble() {
        let remote = "test_remote";
        let peer_public_key = &generate_test_fake_peer_public_key();

        let preamble = prepare_preamble(remote, peer_public_key).unwrap();

        assert_eq!(preamble.len(), remote.len() + peer_public_key.len() + 3 * Constant::DELIMITER_SIZE);
    }

    #[tokio::test]
    async fn test_process_preamble() {
        let remote = "test_remote";
        let peer_public_key = &generate_test_fake_peer_public_key();

        let client_to_server = prepare_preamble(remote, peer_public_key).unwrap();

        let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

        let preamble = process_preamble(&mut stream).await.unwrap();

        assert_eq!(preamble.remote, remote);
    }

    #[tokio::test]
    async fn test_handle_pump() {
        let (mut client, mut server1) = tokio::io::duplex(1024);
        let (mut server2, mut remote) = tokio::io::duplex(1024);

        client.write_all(b"Hello, remote!").await.unwrap();
        client.shutdown().await.unwrap();
        remote.write_all(b"Hello, client!!").await.unwrap();
        remote.shutdown().await.unwrap();

        let (up, down) = handle_pump(&mut server1, &mut server2).await.unwrap();

        assert_eq!(up, 14);
        assert_eq!(down, 15);
    }

    #[tokio::test]
    async fn test_read_to_next_delimiter() {
        let message = b"Hello, world!";
        let data = [message, Constant::DELIMITER].concat();
        let mut stream = BuffedStream::new(MockStream::new(data, vec![]));

        let result = read_to_next_delimiter(&mut stream).await.unwrap();

        assert_eq!(result, message);
    }
}
