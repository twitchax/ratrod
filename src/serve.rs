//! This module implements the server-side of the protocol.

use std::marker::PhantomData;

use anyhow::Context;
use regex::Regex;
use secrecy::SecretString;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{ExchangeKeyPair, Res, ServerKeyExchangeData, Void},
    buffed_stream::{BincodeSplit, BuffedTcpStream},
    protocol::{BincodeReceive, BincodeSend, Challenge, ClientPreamble, ProtocolError, ProtocolMessage, ServerPreamble, Signature},
    security::{resolve_authorized_keys, resolve_keypath, resolve_private_key, resolve_public_key},
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret, handle_tcp_pump, handle_udp_pump, random_string, sign_challenge, validate_signed_challenge},
};

// State machine.

/// The server is in the configuration state.
pub struct ConfigState;
/// The server is in the ready state.
pub struct ReadyState;

/// The server instance.
///
/// This is the main entry point for the server. It is used to prepare the server, and start it.
pub struct Instance<S = ConfigState> {
    config: Config,
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    /// Prepares the server instance.
    pub fn prepare<A, B, C>(key_path: A, remote_regex: B, bind_address: C) -> Res<Instance<ReadyState>>
    where
        A: Into<Option<String>>,
        B: AsRef<str>,
        C: Into<String>,
    {
        let remote_regex = Regex::new(remote_regex.as_ref()).context("Invalid regex for remote host.")?;

        let key_path = resolve_keypath(key_path)?;
        let private_key = resolve_private_key(&key_path)?;
        let public_key = resolve_public_key(&key_path)?;
        let authorized_keys = resolve_authorized_keys(&key_path);

        let config = Config::new(public_key, private_key, authorized_keys, bind_address.into(), remote_regex);

        Ok(Instance { config, _phantom: PhantomData })
    }
}

impl Instance<ReadyState> {
    /// Starts the server instance.
    pub async fn start(self) -> Void {
        info!("🚀 Starting server on `{}` ...", self.config.bind_address);

        run_tcp_server(self.config.clone()).await?;

        Ok(())
    }
}

// Operations.

/// Verifies the preamble from the client.
///
/// This is used to ensure that the client is allowed to connect to the specified remote.
async fn verify_client_preamble<T>(stream: &mut T, config: &Config, preamble: &ClientPreamble<'_>) -> Res<Signature>
where
    T: BincodeSend,
{
    // Validate the remote is OK.

    if !config.remote_regex.is_match(preamble.remote) {
        return ProtocolError::InvalidHost(&format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.remote, config.remote_regex))
            .send_and_bail(stream)
            .await;
    }

    // Sign the challenge.

    let signature = sign_challenge(preamble.challenge, &config.private_key)?;

    Ok(signature)
}

/// Sends the server preamble to the client.
async fn send_server_preamble<T>(stream: &mut T, config: &Config, server_signature: &Signature, server_challenge: &Challenge) -> Res<ExchangeKeyPair>
where
    T: BincodeSend,
{
    info!("🚧 Sending handshake challenge to client ...");

    let exchange_key_pair = generate_ephemeral_key_pair()?;
    let exchange_public_key = exchange_key_pair.public_key.as_ref();

    let preamble = ServerPreamble {
        challenge: server_challenge,
        exchange_public_key,
        identity_public_key: &config.public_key,
        signature: server_signature,
    };

    stream.push(ProtocolMessage::ServerPreamble(preamble)).await?;

    Ok(exchange_key_pair)
}

/// Handles the key challenge from the client.
///
/// This is used to ensure that the client is allowed to connect to the server.
/// It also verifies the signature of the challenge from the client, authenticating the client.
async fn handle_and_validate_key_challenge<T>(stream: &mut T, config: &Config, server_challenge: &Challenge) -> Void
where
    T: BincodeSend + BincodeReceive,
{
    // Wait for the client to respond.

    let guard = stream.pull().await?;
    let ProtocolMessage::ClientAuthentication(client_authentication) = guard.message().fail_if_error()? else {
        return ProtocolError::InvalidKey("Invalid handshake response").send_and_bail(stream).await;
    };

    // Verify the signature.

    if validate_signed_challenge(server_challenge, client_authentication.signature, client_authentication.identity_public_key).is_err() {
        return ProtocolError::InvalidKey("Invalid challenge signature from client").send_and_bail(stream).await;
    }

    // Validate that the key is authorized.
    if !config.authorized_keys.iter().any(|k| k == client_authentication.identity_public_key) {
        return ProtocolError::InvalidKey("Unauthorized key from client").send_and_bail(stream).await;
    }

    info!("✅ Handshake challenge completed!");

    Ok(())
}

/// Completes the handshake.
///
/// This is used to send the server's ephemeral public key to the client
/// for the key exchange.
async fn complete_handshake<T>(stream: &mut T) -> Void
where
    T: BincodeSend,
{
    let completion = ProtocolMessage::HandshakeCompletion;

    stream.push(completion).await?;

    info!("✅ Handshake completed.");

    Ok(())
}

/// Handles the e2e handshake.
///
/// This is used to handle the handshake between the client and server.
/// It verifies the preamble, handles the key challenge, and completes the handshake.
async fn handle_handshake<T>(stream: &mut T, config: &Config) -> Res<ServerKeyExchangeData>
where
    T: BincodeSplit + BincodeReceive + BincodeSend,
{
    let (read, write) = stream.split();

    // Ingest the preamble from the client.

    let guard = read.pull().await?;
    let ProtocolMessage::ClientPreamble(preamble) = guard.message() else {
        return ProtocolError::Unknown("Invalid handshake start").send_and_bail(stream).await;
    };

    // Extract the preamble ta so the borrows into the stream can be dropped.

    let client_exchange_public_key = preamble.exchange_public_key.try_into()?;
    let client_challenge = preamble.challenge.try_into()?;
    let requested_remote_address = preamble.remote.into();
    let requested_should_encrypt = preamble.should_encrypt;
    let requested_is_udp = preamble.is_udp;

    // Verify the preamble.

    let server_signature = verify_client_preamble(write, config, preamble).await?;

    // Create a challenge.

    let server_challenge = generate_challenge();

    // Send the server preamble.

    let local_exchange_key_pair = send_server_preamble(write, config, &server_signature, &server_challenge).await?;

    // Validate the client's auth response.

    handle_and_validate_key_challenge(stream, config, &server_challenge).await?;

    // Complete the handshake.

    complete_handshake(stream).await?;

    Ok(ServerKeyExchangeData {
        client_exchange_public_key,
        client_challenge,
        local_exchange_private_key: local_exchange_key_pair.private_key,
        local_challenge: server_challenge,
        requested_remote_address,
        requested_should_encrypt,
        requested_is_udp,
    })
}

/// Runs the pump with a TCP-connected remote.
async fn run_tcp_pump(mut client: BuffedTcpStream, remote_address: &str) -> Void {
    let Ok(remote) = TcpStream::connect(remote_address).await.context("Error connecting to remote") else {
        return ProtocolError::RemoteFailed(&format!("Failed to connect to remote `{}`", remote_address))
            .send_and_bail(&mut client)
            .await;
    };

    remote.set_nodelay(true)?;

    info!("✅ Connected to remote server `{}`.", remote_address);

    handle_tcp_pump(remote, client).await.context("Error handling TCP pump.")?;

    Ok(())
}

/// Runs the pump with a UDP-connected remote.
async fn run_udp_pump(mut client: BuffedTcpStream, remote_address: &str) -> Void {
    let remote = UdpSocket::bind("127.0.0.1:0").await.context("Error binding UDP socket")?;
    if remote.connect(remote_address).await.is_err() {
        return ProtocolError::RemoteFailed(&format!("Failed to connect to remote `{}`", remote_address))
            .send_and_bail(&mut client)
            .await;
    }

    info!("✅ Connected to remote server `{}`.", remote_address);

    handle_udp_pump(remote, client).await.context("Error handling UDP pump.")?;

    Ok(())
}

/// Runs the TCP server.
///
/// This is the main entry point for the server. It binds to the specified address, and handles incoming connections.
async fn run_tcp_server(config: Config) -> Void {
    let listener = TcpListener::bind(&config.bind_address).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_connection(socket, config.clone()));
    }
}

/// Handles the TCP connection.
///
/// This is used to handle the TCP connection between the client and server.
/// It handles the handshake, and pumps data between the client and server.
async fn handle_connection(client: TcpStream, config: Config) {
    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        client.set_nodelay(true)?;
        let peer_addr = client.peer_addr().context("Error getting peer address")?;

        let mut client = BuffedTcpStream::from(client);

        info!("✅ Accepted connection from `{}`.", peer_addr);

        // Handle the handshake.

        let handshake_data = handle_handshake(&mut client, &config).await.context("Error handling handshake")?;

        // Generate and apply the shared secret, if needed.
        if handshake_data.requested_should_encrypt {
            let private_key = handshake_data.local_exchange_private_key;
            let salt_bytes = [handshake_data.local_challenge, handshake_data.client_challenge].concat();
            let shared_secret = generate_shared_secret(private_key, &handshake_data.client_exchange_public_key, &salt_bytes)?;

            client = client.with_encryption(shared_secret);
            info!("🔒 Encryption applied ...");
        }

        // Handle the pump.

        info!("⛽ Pumping data between client and remote ...");

        if handshake_data.requested_is_udp {
            run_udp_pump(client, &handshake_data.requested_remote_address).await?;
        } else {
            run_tcp_pump(client, &handshake_data.requested_remote_address).await?;
        }

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

// Config.

/// The server configuration.
///
/// This is used to store the server's configuration.
#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) public_key: String,
    pub(crate) private_key: SecretString,
    pub(crate) authorized_keys: Vec<String>,
    pub(crate) bind_address: String,
    pub(crate) remote_regex: Regex,
}

impl Config {
    /// Creates a new server configuration.
    fn new(public_key: String, private_key: SecretString, authorized_keys: Vec<String>, bind_address: String, remote_regex: Regex) -> Self {
        Self {
            public_key,
            private_key,
            authorized_keys,
            bind_address,
            remote_regex,
        }
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::{
        connect::tests::generate_test_client_config,
        protocol::ClientAuthentication,
        utils::{
            generate_key_pair, sign_challenge,
            tests::{generate_test_duplex, generate_test_fake_exchange_public_key},
        },
    };

    use super::*;

    pub(crate) fn generate_test_server_config() -> Config {
        let key_path = "test/server";

        let public_key = resolve_public_key(key_path).unwrap();
        let private_key = resolve_private_key(key_path).unwrap();
        let authorized_keys = resolve_authorized_keys(key_path);
        let remote_regex = Regex::new(".*").unwrap();

        Config {
            public_key,
            private_key,
            authorized_keys,
            bind_address: "bind_address".to_string(),
            remote_regex,
        }
    }

    #[test]
    fn test_prepare_config() {
        let instance = Instance::prepare("test/server".to_string(), ".*", "foo").unwrap();

        assert_eq!(instance.config.public_key, "HQYY0BNIhdawY2Jw62DudkUsK2GKj3hGO3qSVBlCinI");
        assert_eq!(instance.config.remote_regex.as_str(), ".*");
        assert_eq!(instance.config.bind_address, "foo");
    }

    #[tokio::test]
    async fn test_handle_handshake_success() {
        // Setup test environment
        let mut config = generate_test_server_config();
        let (mut client, mut server) = generate_test_duplex();
        let client_config = generate_test_client_config();

        // Add client's public key to authorized keys
        config.authorized_keys.push(client_config.public_key.clone());

        // Client sends preamble
        let client_challenge: Challenge = [8u8; 32];
        let client_preamble = ClientPreamble {
            remote: "localhost",
            challenge: &client_challenge,
            exchange_public_key: &generate_test_fake_exchange_public_key(),
            should_encrypt: true,
            is_udp: false,
        };

        client.push(ProtocolMessage::ClientPreamble(client_preamble.clone())).await.unwrap();

        // Client prepares to respond to server's challenge
        let client_handle = tokio::spawn(async move {
            // Get server preamble
            let guard = client.pull().await.unwrap();
            let server_challenge = match guard.message() {
                ProtocolMessage::ServerPreamble(preamble) => preamble.challenge,
                _ => panic!("Expected ServerPreamble message, got: {:?}", guard.message()),
            };

            // Send client authentication
            let signature = sign_challenge(server_challenge, &client_config.private_key).unwrap();
            let client_auth = ClientAuthentication {
                identity_public_key: &client_config.public_key,
                signature: &signature,
            };

            client.push(ProtocolMessage::ClientAuthentication(client_auth)).await.unwrap();

            // Verify handshake completion
            let guard = client.pull().await.unwrap();
            assert!(matches!(guard.message(), ProtocolMessage::HandshakeCompletion));
        });

        // Execute handshake on server side
        let result = handle_handshake(&mut server, &config).await;

        // Wait for client to complete
        client_handle.await.unwrap();

        // Verify success
        assert!(result.is_ok());
        let key_data = result.unwrap();

        // Verify returned data
        assert_eq!(key_data.client_exchange_public_key, client_preamble.exchange_public_key);
        assert_eq!(key_data.client_challenge, client_challenge);
        assert_eq!(key_data.requested_remote_address, "localhost");
        assert_eq!(key_data.requested_should_encrypt, true);
    }

    #[tokio::test]
    async fn test_handle_handshake_invalid_start() {
        // Setup
        let config = generate_test_server_config();
        let (mut client, mut server) = generate_test_duplex();

        // Send invalid initial message
        client.push(ProtocolMessage::HandshakeCompletion).await.unwrap();

        // Execute handshake
        let result = handle_handshake(&mut server, &config).await;

        // Verify error
        assert!(result.is_err());

        // Verify client received error
        let guard = client.pull().await.unwrap();
        if let ProtocolMessage::Error(error) = guard.message() {
            assert_eq!(error, &ProtocolError::Unknown("Invalid handshake start"));
        } else {
            panic!("Expected error message, got: {:?}", guard.message());
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_invalid_host() {
        // Setup
        let mut config = generate_test_server_config();
        config.remote_regex = Regex::new("^only-this-host$").unwrap();
        let (mut client, mut server) = generate_test_duplex();

        // Send preamble with non-matching host
        let client_preamble = ClientPreamble {
            remote: "different-host",
            challenge: &[9u8; 32],
            exchange_public_key: &generate_test_fake_exchange_public_key(),
            should_encrypt: false,
            is_udp: false,
        };

        client.push(ProtocolMessage::ClientPreamble(client_preamble)).await.unwrap();

        // Execute handshake
        let result = handle_handshake(&mut server, &config).await;

        // Verify error
        assert!(result.is_err());

        // Verify client received error
        let guard = client.pull().await.unwrap();
        if let ProtocolMessage::Error(error) = guard.message() {
            assert!(matches!(error, ProtocolError::InvalidHost(_)));
        } else {
            panic!("Expected error message, got: {:?}", guard.message());
        }
    }

    #[tokio::test]
    async fn test_handle_handshake_unauthorized_key() {
        // Setup
        let config = generate_test_server_config();
        let (mut client, mut server) = generate_test_duplex();

        // Client sends preamble
        let client_preamble = ClientPreamble {
            remote: "localhost",
            challenge: &[10u8; 32],
            exchange_public_key: &generate_test_fake_exchange_public_key(),
            should_encrypt: false,
            is_udp: false,
        };

        client.push(ProtocolMessage::ClientPreamble(client_preamble)).await.unwrap();

        // Generate unauthorized key pair
        let unauthorized_key_pair = generate_key_pair().unwrap();
        let unauthorized_private_key = unauthorized_key_pair.private_key.into();

        // Client responds with unauthorized key
        let client_handle = tokio::spawn(async move {
            // Get server preamble
            let guard = client.pull().await.unwrap();
            let server_challenge = match guard.message() {
                ProtocolMessage::ServerPreamble(preamble) => preamble.challenge,
                _ => panic!("Expected ServerPreamble message, got: {:?}", guard.message()),
            };

            // Send client authentication with unauthorized key
            let signature = sign_challenge(server_challenge, &unauthorized_private_key).unwrap();
            let client_auth = ClientAuthentication {
                identity_public_key: &unauthorized_key_pair.public_key,
                signature: &signature,
            };

            client.push(ProtocolMessage::ClientAuthentication(client_auth)).await.unwrap();

            // Check for error response
            let guard = client.pull().await.unwrap();
            assert!(matches!(guard.message(), &ProtocolMessage::Error(_)));
        });

        // Execute handshake on server side
        let result = handle_handshake(&mut server, &config).await;

        // Wait for client to complete
        client_handle.await.unwrap();

        // Verify failure
        assert!(result.is_err());
    }
}
