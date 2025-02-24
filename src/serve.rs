use std::{marker::PhantomData, sync::OnceLock};

use anyhow::Context;
use regex::Regex;
use tokio::{io::{AsyncBufRead, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{error, info, info_span, Instrument};

use crate::{base::{Err, Preamble, Res, Constant, Void}, utils::{generate_challenge, handle_tcp_pump, process_preamble, random_string, read_to_next_delimiter, validate_signed_challenge}};

// State machine.

pub struct ConfigState;
pub struct ReadyState;

pub struct Instance<S = ConfigState> {
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    pub fn prepare<A, B, C, D>(private_key: A, public_key: B, remote_regex: C, bind_address: D, should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: Into<String>,
        C: AsRef<str>,
        D: Into<String>,
    {
        let remote_regex = Regex::new(remote_regex.as_ref()).context("Invalid regex for remote host.")?;

        Config::create(private_key.into(), public_key.into(), bind_address.into(), remote_regex, should_encrypt)?;

        Ok(Instance { _phantom: PhantomData })
    }
    
}

impl Instance<ReadyState> {
    pub async fn start(self) -> Void {
        run_tcp_server().await?;

        Ok(())
    }
}

// Operations.

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
    if !Config::remote_regex().is_match(&preamble.remote) {
        // Attempt to let the client know that the host is invalid.
        let message = format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.remote, Config::remote_regex());
        let _ = stream.write_all(&[Constant::ERROR_INVALID_HOST, message.as_bytes(), Constant::DELIMITER].concat()).await;
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

    stream.write_all(&[Constant::HANDSHAKE_CHALLENGE, challenge, Constant::DELIMITER].concat()).await?;

    // Wait for the client to respond.

    let signature_response = read_to_next_delimiter(stream).await?;
    let (signature_sentinel, signature) = signature_response.split_at(Constant::SIZE);

    if !signature_sentinel.eq(Constant::HANDSHAKE_CHALLENGE_RESPONSE) {
        let message = "Invalid handshake response";
        let _ = stream.write_all(&[Constant::ERROR_INVALID_KEY, message.as_bytes(), Constant::DELIMITER].concat()).await;
        let _ = stream.shutdown().await;

        return Err(Err::msg(message));
    }

    if signature.len() != Constant::SIGNATURE_SIZE {
        let message = "Invalid signature length";
        let _ = stream.write_all(&[Constant::ERROR_INVALID_KEY, message.as_bytes(), Constant::DELIMITER].concat()).await;
        let _ = stream.shutdown().await;

        return Err(Err::msg(message));
    }

    // Verify the signature.

    match validate_signed_challenge(challenge, signature, Config::public_key()) {
        Ok(_) => info!("✅ Handshake challenge completed!"),
        Err(_) => {
            let message = format!("Invalid challenge signature from client (supplied `{}`)", Config::public_key());
            let _ = stream.write_all(&[Constant::ERROR_INVALID_KEY, message.as_bytes(), Constant::DELIMITER].concat()).await;
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
    stream.write_all(&[Constant::HANDSHAKE_COMPLETION, Constant::DELIMITER].concat()).await?;
    info!("✅ Handshake completed.");

    Ok(())
}

async fn run_tcp_server() -> Void {
    let listener = TcpListener::bind(Config::bind_address()).await?;

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

// Statics.

static CONFIG: OnceLock<Config> = OnceLock::new();

struct Config {
    private_key: String,
    public_key: String,
    bind_address: String,
    remote_regex: Regex,
    should_encrypt: bool,
}

impl Config {
    fn create(private_key: String, public_key: String, bind_address: String, remote_regex: Regex, should_encrypt: bool) -> Res<&'static Self> {
        if Self::ready() {
            return Err(Err::msg("Configuration has already been set: only one config per process"));
        }

        let this = Self {
            private_key,
            public_key,
            bind_address,
            remote_regex,
            should_encrypt,
        };

        Ok(CONFIG.get_or_init(move || this))
    }

    fn ready() -> bool {
        CONFIG.get().is_some()
    }

    fn get() -> &'static Self {
        CONFIG.get().unwrap()
    }
    
    fn private_key() -> &'static str {
        Self::get().private_key.as_str()
    }

    fn public_key() -> &'static str {
        Self::get().public_key.as_str()
    }

    fn bind_address() -> &'static str {
        Self::get().bind_address.as_str()
    }

    fn remote_regex() -> &'static Regex {
        &Self::get().remote_regex
    }

    fn should_encrypt() -> bool {
        Self::get().should_encrypt
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::utils::{generate_key_pair, prepare_preamble, sign_challenge, tests::MockStream};

    use super::*;

    #[test]
    fn test_prepare_config() {
        Instance::prepare("private_key", "test_key", ".*", "foo", true).unwrap();

        assert_eq!(Config::private_key(), "private_key");
        assert_eq!(Config::public_key(), "test_key");
        assert_eq!(Config::remote_regex().as_str(), ".*");
        assert_eq!(Config::bind_address(), "foo");
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {
        
    }

    #[tokio::test]
    async fn test_can_handle_handshake() {
        let keypair = generate_key_pair().unwrap();
        let remote = "test_remote";

        // We need to compute the total stream from the client back to the server.
        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &keypair.private_key).unwrap();

        let client_to_server = [&prepare_preamble(remote).unwrap(), Constant::HANDSHAKE_CHALLENGE_RESPONSE, &signature, Constant::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("doesnt_matter_for_handshake", keypair.public_key, ".*", "", false).unwrap();
        let preamble = handle_handshake(&mut stream, &challenge).await.unwrap();

        assert_eq!(preamble.remote, remote);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_challenge_response() {
        let remote = "test_remote";
        let error_message = "Invalid handshake response";

        let client_to_server = [&prepare_preamble(remote).unwrap(), Constant::HANDSHAKE_COMPLETION, random_string(64).as_bytes(), Constant::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("key", "another", ".*", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

        let skip = Constant::SIZE + Constant::CHALLENGE_SIZE + Constant::SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_key_length() {
        let remote = "test_remote";
        let error_message = "Invalid signature length";

        let client_to_server = [&prepare_preamble(remote).unwrap(), Constant::HANDSHAKE_CHALLENGE_RESPONSE, random_string(32).as_bytes(), Constant::DELIMITER].concat();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("key", "another", ".*", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

        let skip = Constant::SIZE + Constant::CHALLENGE_SIZE + Constant::SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_bad_host() {
        let key = "test_key";
        let remote = "test_remote";
        let error_message = "Invalid host from client (supplied `test_remote`, but need to satisfy `hots`)";

        let client_to_server = prepare_preamble(remote).unwrap();

        let mut stream = BufReader::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("doesnt_matter", key, "hots", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_HOST, error_message.as_bytes(), Constant::DELIMITER].concat();

        assert_eq!(stream.get_ref().write, expected_write_stream);
    }
}