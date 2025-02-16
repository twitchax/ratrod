use std::time::Duration;

use anyhow::Context;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use rand::{distr::Alphanumeric, Rng};
use ring::{rand::{SecureRandom, SystemRandom}, signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey}};
use sha2::{Digest, Sha256};
use tokio::{io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite}, net::TcpStream};

use crate::base::{Base64KeyPair, Err, Preamble, Res, Sentinel, TunnelDefinition, Void};

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

pub fn generate_key_pair() -> Res<Base64KeyPair> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).context("Unable to generate key pair")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).context("Failed to create key pair")?;

    let public = BASE64_URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    let private = BASE64_URL_SAFE_NO_PAD.encode(pkcs8.as_ref());

    Ok(Base64KeyPair { public_key: public, private_key: private })
}

pub fn generate_key_pair_from_key(private_key: &str) -> Res<Base64KeyPair> {
    let key_bytes = BASE64_URL_SAFE_NO_PAD.decode(private_key).context("Could not decode seed")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(&key_bytes).context("Failed to create key pair")?;

    let public = BASE64_URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());

    Ok(Base64KeyPair { public_key: public, private_key: private_key.to_string() })
}

pub fn generate_challenge() -> [u8; Sentinel::CHALLENGE_SIZE] {
    let rng = SystemRandom::new();
    let mut challenge = [0u8; Sentinel::CHALLENGE_SIZE];
    rng.fill(&mut challenge).expect("Failed to generate challenge");
    challenge
}

pub fn sign_challenge(challenge: &[u8], private_key: &str) -> Res<[u8; Sentinel::SIGNATURE_SIZE]> {
    let private_key = BASE64_URL_SAFE_NO_PAD.decode(private_key).context("Could not decode private key")?;

    let key_pair = Ed25519KeyPair::from_pkcs8(&private_key).map_err(|_| Err::msg("Invalid private key"))?;

    let signature = key_pair.sign(challenge).as_ref()[..Sentinel::SIGNATURE_SIZE].try_into().map_err(|_| Err::msg("Invalid signature length"))?;

    Ok(signature)
}

pub fn validate_signed_challenge(challenge: &[u8], signature: &[u8], public_key: &str) -> Void {
    let public_key = BASE64_URL_SAFE_NO_PAD.decode(public_key).context("Could not decode public key")?;

    let unparsed_public_key = UnparsedPublicKey::new(&ring::signature::ED25519, public_key);

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
            Ok(TunnelDefinition { bind_address, remote_address: host_address })
        }
        3 => {
            let bind_address = format!("localhost:{}", parts[0]);
            let host_address = format!("{}:{}", parts[1], parts[2]);
            Ok(TunnelDefinition { bind_address, remote_address: host_address })
        }
        2 => {
            let bind_address = format!("localhost:{}", parts[0]);
            let host_address = format!("localhost:{}", parts[1]);
            Ok(TunnelDefinition { bind_address, remote_address: host_address })
        }
        1 => {
            let bind_address = format!("localhost:{}", parts[0]);
            let host_address = format!("localhost:{}", parts[0]);
            Ok(TunnelDefinition { bind_address, remote_address: host_address })
        }
        _ => Err(Err::msg("Invalid tunnel definition format")),
    }
}

pub fn prepare_preamble(remote: &str) -> Res<Vec<u8>> {
    let remote_bytes = remote.as_bytes();

    let preamble = [Sentinel::PREAMBLE_INIT, remote_bytes, Sentinel::DELIMITER].concat();

    Ok(preamble)
}


pub async fn process_preamble<T>(stream: &mut T) -> Res<Preamble>
where 
    T: AsyncBufRead + Unpin,
{
    let data = read_to_next_delimiter(stream).await?;

    let (init, remote_bytes) = data.split_at(Sentinel::SIZE);

    if init != Sentinel::PREAMBLE_INIT {
        return Err(Err::msg("Invalid preamble"));
    }

    let remote = String::from_utf8(remote_bytes.to_vec()).context("Invalid UTF-8 in preamble")?;

    Ok(Preamble { remote })
}

pub async fn read_to_next_delimiter<T>(stream: &mut T) -> Res<Vec<u8>>
where 
    T: AsyncBufRead + Unpin,
{
    let mut buffer = Vec::with_capacity(Sentinel::BUFFER_SIZE);
    let mut delimiter_index = usize::MAX;

    for _ in 0..100 {
        let inner_buffer = stream.fill_buf().await?;

        // Find next delimiter.

        for (k, window) in inner_buffer.windows(Sentinel::SIZE).enumerate() {
            if window == Sentinel::DELIMITER {
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
    stream.consume(delimiter_index + Sentinel::SIZE);

    Ok(buffer)
}

pub async fn handle_tcp_pump(client: &mut TcpStream, remote: &mut TcpStream) -> Void {
    let (mut remote_reader, mut remote_writer) = remote.split();
    let (mut client_reader, mut client_writer) = client.split();
    
    handle_pump(&mut client_reader, &mut client_writer, &mut remote_reader, &mut remote_writer).await?;

    Ok(())
}

async fn handle_pump<'a, 'b, R, W>(
    reader_left: &'a mut R,
    writer_left: &'b mut W,
    reader_right: &'b mut R,
    writer_right: &'a mut W,
) -> Res<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (up_result, down_result) = tokio::join!(
        tokio::io::copy(reader_left, writer_right),
        tokio::io::copy(reader_right, writer_left)
    );

    if let Err(err) = up_result {
        let message = format!("Error forwarding data from client to remote: `{}`", err);
        return Err(Err::msg(message));
    }

    if let Err(err) = down_result {
        let message = format!("Error forwarding data from client to socket: `{}`", err);
        return Err(Err::msg(message));
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::{io, pin::Pin, task::{Context, Poll}, vec};
    use tokio::io::BufReader;

    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::{io::{AsyncWrite, ReadBuf}, net::TcpListener};

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
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().read.as_slice()).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
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
                    let (mut read, mut write) =  client.into_split();

                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        }
    }

    #[test]
    fn test_parse_tunnel_definition() {
        let input = "a:b:c:d";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "a:b");
        assert_eq!(result.remote_address, "c:d");

        let input = "a:b:c";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "localhost:a");
        assert_eq!(result.remote_address, "b:c");

        let input = "a:b";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "localhost:a");
        assert_eq!(result.remote_address, "localhost:b");

        let input = "a";
        let result = parse_tunnel_definition(input).unwrap();
        assert_eq!(result.bind_address, "localhost:a");
        assert_eq!(result.remote_address, "localhost:a");
    }

    #[test]
    fn test_prepare_preamble() {
        let remote = "test_remote";

        let preamble = prepare_preamble(remote).unwrap();

        assert_eq!(preamble.len(), remote.len() + 2 * Sentinel::SIZE);
    }

    #[tokio::test]
    async fn test_process_preamble() {
        let remote = "test_remote";

        let client_to_server = prepare_preamble(remote).unwrap();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        let preamble = process_preamble(&mut stream).await.unwrap();

        assert_eq!(preamble.remote, remote);
    }

    #[tokio::test]
    async fn test_handle_pump() {
        let mut client = MockStream::new(vec![1, 2, 3], vec![]);

        let mut remote = MockStream::new(vec![4, 5, 6], vec![]);

        handle_pump(&mut client.read.as_slice(), &mut client.write, &mut remote.read.as_slice(), &mut remote.write).await.unwrap();

        assert_eq!(client.write, vec![4, 5, 6]);
        assert_eq!(remote.write, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_read_to_next_delimiter() {
        let message = b"Hello, world!";
        let data = [message, Sentinel::DELIMITER].concat();
        let mut stream = BufReader::new(MockStream::new(data, vec![]));

        let result = read_to_next_delimiter(&mut stream).await.unwrap();

        assert_eq!(result, message);
    }

    #[test]
    fn test_ed25519() {
        let key_pair = generate_key_pair().unwrap();

        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &key_pair.private_key).unwrap();

        validate_signed_challenge(&challenge, &signature, &key_pair.public_key).unwrap();
    }
}