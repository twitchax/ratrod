use std::{borrow::Cow, sync::OnceLock};

use anyhow::Context;
use regex::Regex;
use tokio::{io::{AsyncBufRead, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{error, info, info_span, Instrument};

use crate::{base::{Err, Preamble, Res, Sentinel, Void}, utils::{generate_challenge, handle_tcp_pump, process_preamble, random_string, read_to_next_delimiter, validate_signed_challenge}};

static PUBLIC_KEY: OnceLock<String> = OnceLock::new();

static REMOTE_REGEX: OnceLock<Regex> = OnceLock::new();

static BIND_ADDRESS: OnceLock<String> = OnceLock::new();

pub async fn start(bind_address: String, public_key: String, remote_regex: String) -> Void {
    // Prepare the globals.

    prepare_globals(public_key, remote_regex, bind_address)?;

    // Finally, start the server.

    run_tcp_server().await?;

    Ok(())
}

fn prepare_globals<'a, 'b, 'c>(public_key: impl Into<Cow<'a, str>>, remote_regex: impl Into<Cow<'b, str>>, bind_address: impl Into<Cow<'c, str>>) -> Void {
    PUBLIC_KEY.get_or_init(|| public_key.into().to_string() );

    let remote_regex = Regex::new(remote_regex.into().as_ref()).context("Unable to parse the supplied `host_regex`")?;
    REMOTE_REGEX.get_or_init(|| remote_regex );

    BIND_ADDRESS.get_or_init(|| bind_address.into().to_string() );

    Ok(())
}

async fn handle_handshake<T>(stream: &mut T, challenge: &[u8]) -> Res<Preamble>
where 
    T: AsyncBufRead + AsyncWriteExt + Unpin,
{
    let preamble = process_preamble(stream).await?;
    
    verify_preamble_host(stream, &preamble).await?;
    handle_and_validate_key_challenge(stream, challenge).await?;
    complete_handshake(stream).await?;

    Ok(preamble)
}

async fn verify_preamble_host<T>(stream: &mut T, preamble: &Preamble) -> Void
where
    T: AsyncWriteExt + Unpin,
{
    if !REMOTE_REGEX.get().unwrap().is_match(&preamble.remote) {
        // Attempt to let the client know that the host is invalid.
        let message = format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.remote, REMOTE_REGEX.get().unwrap());
        let _ = stream.write_all(&[Sentinel::ERROR_INVALID_HOST, message.as_bytes(), Sentinel::DELIMITER].concat()).await;
        let _ = stream.shutdown().await;

        return Err(Err::msg(message));
    }

    Ok(())
}

async fn handle_and_validate_key_challenge<T>(stream: &mut T, challenge: &[u8]) -> Void
where
    T: AsyncBufRead + AsyncWriteExt + Unpin,
{
    info!("🚧 Sending handshake challenge to client ...");

    stream.write_all(&[Sentinel::HANDSHAKE_CHALLENGE, challenge, Sentinel::DELIMITER].concat()).await?;

    // Wait for the client to respond.

    let signature_response = read_to_next_delimiter(stream).await?;
    let (signature_sentinel, signature) = signature_response.split_at(Sentinel::SIZE);

    if !signature_sentinel.eq(Sentinel::HANDSHAKE_CHALLENGE_RESPONSE) {
        let message = "Invalid handshake response";
        let _ = stream.write_all(&[Sentinel::ERROR_INVALID_KEY, message.as_bytes(), Sentinel::DELIMITER].concat()).await;
        let _ = stream.shutdown().await;

        return Err(Err::msg(message));
    }

    if signature.len() != Sentinel::SIGNATURE_SIZE {
        let message = "Invalid signature length";
        let _ = stream.write_all(&[Sentinel::ERROR_INVALID_KEY, message.as_bytes(), Sentinel::DELIMITER].concat()).await;
        let _ = stream.shutdown().await;

        return Err(Err::msg(message));
    }

    // Verify the signature.

    match validate_signed_challenge(challenge, signature, PUBLIC_KEY.get().unwrap()) {
        Ok(_) => info!("✅ Handshake challenge completed!"),
        Err(_) => {
            let message = format!("Invalid challenge signature from client (supplied `{}`)", PUBLIC_KEY.get().unwrap());
            let _ = stream.write_all(&[Sentinel::ERROR_INVALID_KEY, message.as_bytes(), Sentinel::DELIMITER].concat()).await;
            let _ = stream.shutdown().await;

            return Err(Err::msg(message));
        }
    }

    Ok(())
}

async fn complete_handshake<T>(stream: &mut T) -> Void
where
    T: AsyncWriteExt + Unpin,
{
    stream.write_all(&[Sentinel::HANDSHAKE_COMPLETION, Sentinel::DELIMITER].concat()).await?;
    info!("✅ Handshake completed.");

    Ok(())
}

async fn run_tcp_server() -> Void {
    let listener = TcpListener::bind(BIND_ADDRESS.get().unwrap()).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket));
    }
}

async fn handle_tcp(client: TcpStream) {
    let mut client = BufReader::new(client);

    let id = random_string(6);
    let span = info_span!("conn", id = id);

    async move {
        let Ok(peer_addr) = client.get_ref().peer_addr() else {
            error!("❌ Unable to get peer address.");
            return;
        };
    
        info!("✅ Accepted connection from `{}`.", peer_addr);
    
        // Create a challenge.
    
        let challenge = generate_challenge();
    
        // Handle the preamble.
        
        let preamble = match handle_handshake(&mut client, &challenge).await {
            Ok(preamble) => preamble,
            Err(err) => {
                let chain = err.chain().collect::<Vec<_>>();
                let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");
    
                error!("❌ Error handling connection: {}.", full_chain);
    
                return;
            }
        };
    
        // Connect to remote.
        
        // This does not need to be a `BufReader` because it is immediately
        // handed off to the pump, which will do as it may with `copy`.
        let mut remote = match TcpStream::connect(&preamble.remote).await {
            Ok(remote) => remote,
            Err(err) => {
                let message = format!("Error connecting to remote server `{}`: `{}`.", preamble.remote, err);
                error!("❌ {}", message);
                return;
            }
        };
    
        info!("✅ Connected to remote server `{}`.", preamble.remote);

        info!("⛽ Pumping data between client and remote ...");
    
        // Handle the TCP pump.
    
        match handle_tcp_pump(&mut client.into_inner(), &mut remote).await {
            Ok(_) => info!("✅ Connection closed."),
            Err(err) => {
                let chain = err.chain().collect::<Vec<_>>();
                let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");
    
                error!("❌ Error handling the pump: `{}`.", full_chain);
            }
        };
    }.instrument(span).await;
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::utils::{generate_key_pair, prepare_preamble, sign_challenge, tests::MockStream};

    use super::*;

    #[test]
    fn test_prepare_globals() {
        prepare_globals("test_key", ".*", "foo").unwrap();

        assert_eq!(PUBLIC_KEY.get().unwrap().len(), 8);
        assert_eq!(REMOTE_REGEX.get().unwrap().as_str(), ".*");
        assert_eq!(BIND_ADDRESS.get().unwrap(), "foo");
    }

    #[test]
    fn test_can_set_host_regex() {
        prepare_globals("", ".*", "").unwrap();
    }

    #[test]
    fn test_can_hash_key() {
        prepare_globals("test_key", ".*", "").unwrap();
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {
        assert!(prepare_globals("test_key", "[a-z", "").is_err());
    }

    #[tokio::test]
    async fn test_can_handle_handshake() {
        let keypair = generate_key_pair().unwrap();
        let remote = "test_remote";

        // We need to compute the total stream from the client back to the server.
        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &keypair.private_key).unwrap();

        let client_to_server = [&prepare_preamble(remote).unwrap(), Sentinel::HANDSHAKE_CHALLENGE_RESPONSE, &signature, Sentinel::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        prepare_globals(keypair.public_key, ".*", "").unwrap();
        let preamble = handle_handshake(&mut stream, &challenge).await.unwrap();

        assert_eq!(preamble.remote, remote);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_challenge_response() {
        let remote = "test_remote";
        let error_message = "Invalid handshake response";

        let client_to_server = [&prepare_preamble(remote).unwrap(), Sentinel::HANDSHAKE_COMPLETION, random_string(64).as_bytes(), Sentinel::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        prepare_globals("another", ".*", "").unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Sentinel::ERROR_INVALID_KEY, error_message.as_bytes(), Sentinel::DELIMITER].concat();

        let skip = Sentinel::SIZE + Sentinel::CHALLENGE_SIZE + Sentinel::SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_key_length() {
        let remote = "test_remote";
        let error_message = "Invalid signature length";

        let client_to_server = [&prepare_preamble(remote).unwrap(), Sentinel::HANDSHAKE_CHALLENGE_RESPONSE, random_string(32).as_bytes(), Sentinel::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        prepare_globals("another", ".*", "").unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Sentinel::ERROR_INVALID_KEY, error_message.as_bytes(), Sentinel::DELIMITER].concat();

        let skip = Sentinel::SIZE + Sentinel::CHALLENGE_SIZE + Sentinel::SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_bad_host() {
        let key = "test_key";
        let remote = "test_remote";
        let error_message = "Invalid host from client (supplied `test_remote`, but need to satisfy `hots`)";

        let client_to_server = prepare_preamble(remote).unwrap();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        prepare_globals(key, "hots", "").unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Sentinel::ERROR_INVALID_HOST, error_message.as_bytes(), Sentinel::DELIMITER].concat();

        assert_eq!(stream.get_ref().write, expected_write_stream);
    }
}