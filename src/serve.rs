use std::{marker::PhantomData, sync::OnceLock};

use anyhow::Context;
use regex::Regex;
use tokio::{
    io::{AsyncBufRead, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{Constant, EphemeralData, EphemeralKeyPair, Err, HandshakeData, Preamble, Res, Void},
    buffed_stream::BuffedStream,
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret, handle_pump, process_preamble, random_string, read_to_next_delimiter, validate_signed_challenge},
};

// State machine.

pub struct ConfigState;
pub struct ReadyState;

pub struct Instance<S = ConfigState> {
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    pub fn prepare<A, B, C>(public_key: A, remote_regex: B, bind_address: C, should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: AsRef<str>,
        C: Into<String>,
    {
        let remote_regex = Regex::new(remote_regex.as_ref()).context("Invalid regex for remote host.")?;

        Config::create(public_key.into(), bind_address.into(), remote_regex, should_encrypt)?;

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

async fn handle_handshake<T>(stream: &mut T, challenge: &[u8]) -> Res<HandshakeData>
where
    T: AsyncBufRead + AsyncWriteExt + Unpin,
{
    let preamble = process_preamble(stream).await?;

    verify_preamble(stream, &preamble).await?;
    handle_and_validate_key_challenge(stream, challenge).await?;
    let ephemeral_key_pair = complete_handshake(stream).await?;

    Ok(HandshakeData { preamble, ephemeral_key_pair })
}

async fn verify_preamble<T>(stream: &mut T, preamble: &Preamble) -> Void
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
    stream.flush().await?;

    // Wait for the client to respond.

    let signature_response = read_to_next_delimiter(stream).await?;
    let (signature_sentinel, signature) = signature_response.split_at(Constant::DELIMITER_SIZE);

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

async fn complete_handshake<T>(stream: &mut T) -> Res<EphemeralKeyPair>
where
    T: AsyncWriteExt + Unpin,
{
    let ephemeral_key_pair = generate_ephemeral_key_pair()?;

    stream
        .write_all(&[Constant::HANDSHAKE_COMPLETION, ephemeral_key_pair.public_key.as_ref(), Constant::DELIMITER].concat())
        .await?;
    stream.flush().await?;

    info!("✅ Handshake completed.");

    Ok(ephemeral_key_pair)
}

async fn run_tcp_server() -> Void {
    let listener = TcpListener::bind(Config::bind_address()).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket));
    }
}

async fn handle_tcp(client: TcpStream) {
    let mut client = BuffedStream::new(client);

    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        let peer_addr = client.get_ref().peer_addr().context("Error getting peer address")?;

        info!("✅ Accepted connection from `{}`.", peer_addr);

        // Create a challenge.

        let challenge = generate_challenge();

        // Handle the preamble.

        let handshake_data = handle_handshake(&mut client, &challenge).await.context("Error handling handshake")?;

        // Compute the ephemeral data.
        let ephemeral_data = EphemeralData {
            ephemeral_key_pair: handshake_data.ephemeral_key_pair,
            peer_public_key: handshake_data.preamble.peer_public_key,
            challenge,
        };

        // Extract the remote.
        let remote_address = handshake_data.preamble.remote;

        // Connect to remote.

        let mut remote = TcpStream::connect(&remote_address).await.context("Error connecting to remote")?;

        info!("✅ Connected to remote server `{}`.", remote_address);

        // Generate and apply the shared secret, if needed.
        if Config::should_encrypt() {
            let private_key = ephemeral_data.ephemeral_key_pair.private_key;
            let peer_public_key = ephemeral_data.peer_public_key;
            let challenge = ephemeral_data.challenge;

            let shared_secret = generate_shared_secret(private_key, &peer_public_key, &challenge)?;

            client = client.with_encryption(shared_secret);
            info!("🔒 Encryption applied ...");
        }

        // Handle the TCP pump.

        info!("⛽ Pumping data between client and remote ...");

        handle_pump(&mut client, &mut remote).await.context("Error handling TCP pump.")?;

        info!("✅ Connection closed.");

        Ok(())
    }
    .instrument(span.clone())
    .await;

    // Enter the span, so that the error is logged with the span's metadata, if needed.
    let _guard = span.enter();

    if let Err(err) = result {
        let chain = err.chain().collect::<Vec<_>>();
        let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");

        error!("❌ Error handling connection: {}.", full_chain);
    }
}

// Statics.

static CONFIG: OnceLock<Config> = OnceLock::new();

struct Config {
    public_key: String,
    bind_address: String,
    remote_regex: Regex,
    should_encrypt: bool,
}

impl Config {
    fn create(public_key: String, bind_address: String, remote_regex: Regex, should_encrypt: bool) -> Res<&'static Self> {
        if Self::ready() {
            return Err(Err::msg("Configuration has already been set: only one config per process"));
        }

        let this = Self {
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

    use crate::utils::{
        generate_key_pair, prepare_preamble, sign_challenge,
        tests::{MockStream, generate_test_fake_peer_public_key},
    };

    use super::*;

    #[test]
    fn test_prepare_config() {
        Instance::prepare("test_key", ".*", "foo", true).unwrap();

        assert_eq!(Config::public_key(), "test_key");
        assert_eq!(Config::remote_regex().as_str(), ".*");
        assert_eq!(Config::bind_address(), "foo");
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {}

    #[tokio::test]
    async fn test_can_handle_handshake() {
        let keypair = generate_key_pair().unwrap();
        let peer_public_key = &generate_test_fake_peer_public_key();
        let remote = "test_remote";

        // We need to compute the total stream from the client back to the server.
        let challenge = generate_challenge();
        let signature = sign_challenge(&challenge, &keypair.private_key).unwrap();

        let client_to_server = [
            &prepare_preamble(remote, peer_public_key).unwrap(),
            Constant::HANDSHAKE_CHALLENGE_RESPONSE,
            &signature,
            Constant::DELIMITER,
        ]
        .concat();

        let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare(keypair.public_key, ".*", "", false).unwrap();
        let handshake_data = handle_handshake(&mut stream, &challenge).await.unwrap();

        assert_eq!(handshake_data.preamble.remote, remote);
        assert_eq!(&handshake_data.preamble.peer_public_key, peer_public_key);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_challenge_response() {
        let remote = "test_remote";
        let peer_public_key = &generate_test_fake_peer_public_key();
        let error_message = "Invalid handshake response";

        let client_to_server = [
            &prepare_preamble(remote, peer_public_key).unwrap(),
            Constant::HANDSHAKE_COMPLETION,
            random_string(64).as_bytes(),
            Constant::DELIMITER,
        ]
        .concat();

        let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("public_key", ".*", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

        let skip = Constant::DELIMITER_SIZE + Constant::CHALLENGE_SIZE + Constant::DELIMITER_SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_key_length() {
        let remote = "test_remote";
        let peer_public_key = &generate_test_fake_peer_public_key();
        let error_message = "Invalid signature length";

        let client_to_server = [
            &prepare_preamble(remote, peer_public_key).unwrap(),
            Constant::HANDSHAKE_CHALLENGE_RESPONSE,
            random_string(32).as_bytes(),
            Constant::DELIMITER,
        ]
        .concat();

        let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare("public_key", ".*", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

        let skip = Constant::DELIMITER_SIZE + Constant::CHALLENGE_SIZE + Constant::DELIMITER_SIZE;
        assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    }

    #[tokio::test]
    async fn test_can_disallow_bad_host() {
        let key = "test_key";
        let remote = "test_remote";
        let peer_public_key = &generate_test_fake_peer_public_key();
        let error_message = "Invalid host from client (supplied `test_remote`, but need to satisfy `hots`)";

        let client_to_server = prepare_preamble(remote, peer_public_key).unwrap();

        let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

        Instance::prepare(key, "hots", "", false).unwrap();
        let preamble_result = handle_handshake(&mut stream, &generate_challenge()).await;

        assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

        let expected_write_stream = [Constant::ERROR_INVALID_HOST, error_message.as_bytes(), Constant::DELIMITER].concat();

        assert_eq!(stream.get_ref().write, expected_write_stream);
    }
}
