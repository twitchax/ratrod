//! This module implements the server-side of the protocol.

use std::marker::PhantomData;

use anyhow::Context;
use regex::Regex;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{EphemeralKeyPair, Res, ServerHandshakeData, Void},
    buffed_stream::BuffedStream,
    protocol::{BincodeReceive, BincodeSend, Challenge, Preamble, ProtocolError, ProtocolMessage},
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret, handle_pump, random_string, validate_signed_challenge},
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
    pub fn prepare<A, B, C>(public_key: A, remote_regex: B, bind_address: C) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: AsRef<str>,
        C: Into<String>,
    {
        let remote_regex = Regex::new(remote_regex.as_ref()).context("Invalid regex for remote host.")?;

        let config = Config::new(public_key.into(), bind_address.into(), remote_regex);

        Ok(Instance { config, _phantom: PhantomData })
    }
}

impl Instance<ReadyState> {
    /// Starts the server instance.
    pub async fn start(self) -> Void {
        info!("🚀 Starting server on `{}` ...", self.config.bind_address);

        run_tcp_server(self.config).await?;

        Ok(())
    }
}

// Operations.

/// Verifies the preamble from the client.
///
/// This is used to ensure that the client is allowed to connect to the specified remote.
async fn verify_preamble<T>(stream: &mut T, preamble: &Preamble, remote_regex: &Regex) -> Void
where
    T: BincodeSend,
{
    if !remote_regex.is_match(&preamble.remote) {
        return ProtocolError::InvalidHost(format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.remote, remote_regex))
            .send_and_bail::<_, ()>(stream)
            .await;
    }

    Ok(())
}

/// Handles the key challenge from the client.
///
/// This is used to ensure that the client is allowed to connect to the server.
/// It also verifies the signature of the challenge from the client, authenticating the client.
async fn handle_and_validate_key_challenge<T>(stream: &mut T, public_key: &str, challenge: &Challenge) -> Void
where
    T: BincodeSend + BincodeReceive,
{
    info!("🚧 Sending handshake challenge to client ...");

    stream.push(ProtocolMessage::HandshakeChallenge(*challenge)).await?;

    // Wait for the client to respond.

    let ProtocolMessage::HandshakeChallengeResponse(signature) = stream.pull().await?.fail_if_error()? else {
        return ProtocolError::InvalidKey("Invalid handshake response".into()).send_and_bail(stream).await;
    };

    // Verify the signature.

    if validate_signed_challenge(challenge, &signature.into(), public_key).is_err() {
        return ProtocolError::InvalidKey("Invalid challenge signature from client".into()).send_and_bail(stream).await;
    }

    info!("✅ Handshake challenge completed!");

    Ok(())
}

/// Completes the handshake.
///
/// This is used to send the server's ephemeral public key to the client
/// for the key exchange.
async fn complete_handshake<T>(stream: &mut T) -> Res<EphemeralKeyPair>
where
    T: BincodeSend,
{
    let ephemeral_key_pair = generate_ephemeral_key_pair()?;

    let peer_public_key = ephemeral_key_pair.public_key.as_ref().try_into()?;
    let completion = ProtocolMessage::HandshakeCompletion(peer_public_key);

    stream.push(completion).await?;

    info!("✅ Handshake completed.");

    Ok(ephemeral_key_pair)
}

/// Handles the e2e handshake.
///
/// This is used to handle the handshake between the client and server.
/// It verifies the preamble, handles the key challenge, and completes the handshake.
async fn handle_handshake<T>(stream: &mut T, public_key: &str, remote_regex: &Regex, challenge: &Challenge) -> Res<ServerHandshakeData>
where
    T: BincodeReceive + BincodeSend,
{
    let ProtocolMessage::HandshakeStart(preamble) = stream.pull().await? else {
        return ProtocolError::Unknown("Invalid handshake start".into()).send_and_bail(stream).await;
    };

    verify_preamble(stream, &preamble, remote_regex).await?;
    handle_and_validate_key_challenge(stream, public_key, challenge).await?;
    let ephemeral_key_pair = complete_handshake(stream).await?;

    Ok(ServerHandshakeData {
        preamble,
        local_ephemeral_key_pair: ephemeral_key_pair,
    })
}

/// Runs the TCP server.
///
/// This is the main entry point for the server. It binds to the specified address, and handles incoming connections.
async fn run_tcp_server(config: Config) -> Void {
    let listener = TcpListener::bind(&config.bind_address).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket, config.clone()));
    }
}

/// Handles the TCP connection.
///
/// This is used to handle the TCP connection between the client and server.
/// It handles the handshake, and pumps data between the client and server.
async fn handle_tcp(client: TcpStream, config: Config) {
    let mut client = BuffedStream::new(client);

    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        let peer_addr = client.peer_addr().context("Error getting peer address")?;

        info!("✅ Accepted connection from `{}`.", peer_addr);

        // Create a challenge.

        let challenge = generate_challenge();

        // Handle the handshake.

        let handshake_data = handle_handshake(&mut client, &config.public_key, &config.remote_regex, &challenge)
            .await
            .context("Error handling handshake")?;

        // Extract the remote.
        let remote_address = handshake_data.preamble.remote;

        // Connect to remote.

        let mut remote = TcpStream::connect(&remote_address).await.context("Error connecting to remote")?;

        info!("✅ Connected to remote server `{}`.", remote_address);

        // Generate and apply the shared secret, if needed.
        if let Some(peer_public_key) = handshake_data.preamble.peer_public_key {
            let private_key = handshake_data.local_ephemeral_key_pair.private_key;

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

// Config.

/// The server configuration.
///
/// This is used to store the server's configuration.
#[derive(Clone)]
struct Config {
    public_key: String,
    bind_address: String,
    remote_regex: Regex,
}

impl Config {
    /// Creates a new server configuration.
    fn new(public_key: String, bind_address: String, remote_regex: Regex) -> Self {
        Self { public_key, bind_address, remote_regex }
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::utils::{
        generate_key_pair, sign_challenge,
        tests::{generate_test_duplex, generate_test_fake_peer_public_key},
    };

    use super::*;

    #[test]
    fn test_prepare_config() {
        let instance = Instance::prepare("test_key", ".*", "foo").unwrap();

        assert_eq!(instance.config.public_key, "test_key");
        assert_eq!(instance.config.remote_regex.as_str(), ".*");
        assert_eq!(instance.config.bind_address, "foo");
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {}

    #[tokio::test]
    async fn test_can_handle_handshake() {
        let (mut client, mut server) = generate_test_duplex();
        let keypair = generate_key_pair().unwrap();
        let peer_public_key = Some(generate_test_fake_peer_public_key());
        let remote = "test_remote";
        let challenge = generate_challenge();

        let preamble = Preamble { remote: remote.into(), peer_public_key };

        // First, send everything from the client to the server.
        let preamble_message = ProtocolMessage::HandshakeStart(preamble.clone());
        let handshake_message = ProtocolMessage::HandshakeChallengeResponse(sign_challenge(&challenge, &keypair.private_key).unwrap().into());

        client.push(preamble_message).await.unwrap();
        client.push(handshake_message).await.unwrap();

        // Then, handle the handshake on the server.

        let handshake_data = handle_handshake(&mut server, &keypair.public_key, &Regex::new(".*").unwrap(), &challenge).await.unwrap();

        assert_eq!(handshake_data.preamble, preamble);
    }

    #[tokio::test]
    async fn test_can_disallow_wrong_challenge_response() {
        let (mut client, mut server) = generate_test_duplex();
        let keypair = generate_key_pair().unwrap();
        let peer_public_key = Some(generate_test_fake_peer_public_key());
        let remote = "test_remote";
        let challenge = generate_challenge();
        let bad_key = generate_key_pair().unwrap().private_key;

        let preamble = Preamble { remote: remote.into(), peer_public_key };

        let bad_signature = sign_challenge(&challenge, &bad_key).unwrap();

        // First, send everything from the client to the server.
        let preamble_message = ProtocolMessage::HandshakeStart(preamble);
        let handshake_message = ProtocolMessage::HandshakeChallengeResponse(bad_signature.into());

        client.push(preamble_message).await.unwrap();
        client.push(handshake_message).await.unwrap();

        // Then, handle the handshake on the server.

        let result = handle_handshake(&mut server, &keypair.public_key, &Regex::new(".*").unwrap(), &challenge).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Invalid key: Invalid challenge signature from client");
    }

    #[tokio::test]
    async fn test_can_disallow_bad_host() {
        let (mut client, mut server) = generate_test_duplex();
        let keypair = generate_key_pair().unwrap();
        let peer_public_key = Some(generate_test_fake_peer_public_key());
        let remote = "doesn't match";
        let challenge = generate_challenge();

        let preamble = Preamble { remote: remote.into(), peer_public_key };

        // First, send everything from the client to the server.
        let preamble_message = ProtocolMessage::HandshakeStart(preamble.clone());
        let handshake_message = ProtocolMessage::HandshakeChallengeResponse(sign_challenge(&challenge, &keypair.private_key).unwrap().into());

        client.push(preamble_message).await.unwrap();
        client.push(handshake_message).await.unwrap();

        // Then, handle the handshake on the server.

        let result = handle_handshake(&mut server, &keypair.public_key, &Regex::new("strict").unwrap(), &challenge).await;

        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "Invalid host: Invalid host from client (supplied `doesn't match`, but need to satisfy `strict`)"
        );
    }
}
