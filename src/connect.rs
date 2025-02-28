//! This module contains the code for the client-side of the tunnel.
//!
//! It includes the state machine, operations, and configuration.

use std::marker::PhantomData;

use anyhow::Context;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{ClientHandshakeData, ClientKeyExchangeData, Err, Res, TunnelDefinition, Void},
    buffed_stream::BuffedStream,
    protocol::{BincodeReceive, BincodeSend, PeerPublicKey, Preamble, ProtocolMessage, SerializeableSignature},
    utils::{generate_ephemeral_key_pair, generate_shared_secret, handle_pump, parse_tunnel_definitions, random_string, sign_challenge},
};

// State machine.

/// The client is in the configuration state.
pub struct ConfigState;
/// The client is in the ready state.
pub struct ReadyState;

/// The client instance.
///
/// This is the main entry point for the client. It is used to connect, configure, and start the client.
pub struct Instance<S = ConfigState> {
    tunnel_definitions: Vec<TunnelDefinition>,
    config: Config,
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    /// Prepares the client instance.
    pub fn prepare<A, B, C>(private_key: A, connect_address: B, tunnel_definitions: &[C], should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: Into<String>,
        C: AsRef<str>,
    {
        let tunnel_definitions = parse_tunnel_definitions(tunnel_definitions)?;

        let config = Config::new(private_key.into(), connect_address.into(), should_encrypt);

        Ok(Instance {
            tunnel_definitions,
            config,
            _phantom: PhantomData,
        })
    }
}

impl Instance<ReadyState> {
    /// Starts the client instance.
    ///
    /// This is the main entry point for the client. It is used to connect, configure, and start the client
    pub async fn start(self) -> Void {
        // Finally, start the server(s) (one per tunnel definition).

        let tasks = self
            .tunnel_definitions
            .into_iter()
            .map(|tunnel_definition| {
                // Schedule a test connection.
                tokio::spawn(test_server_connection(tunnel_definition.clone(), self.config.clone()));

                // Start the server.
                tokio::spawn(run_tcp_server(tunnel_definition, self.config.clone()))
            })
            .collect::<Vec<_>>();

        // Basically, only crash if _all_ of the servers fail to start.  Otherwise, the user can use the error logs to see that some of the
        // servers failed to start.  As a result, we _do not_ log an error, since the user can see the errors in the logs.
        futures::future::join_all(tasks).await;

        Ok(())
    }
}

// Operations.

/// Sends the preamble to the server.
///
/// This is the first message sent to the server. It contains the remote address and the peer public key
/// for the future key exchange.
async fn send_preamble<T>(stream: &mut T, remote_address: &str, peer_public_key: Option<PeerPublicKey>) -> Void
where
    T: BincodeSend,
{
    let preamble = Preamble {
        remote: remote_address.to_string(),
        peer_public_key,
    };

    stream.push(ProtocolMessage::HandshakeStart(preamble)).await?;

    info!("✅ Sent preamble to server ...");

    Ok(())
}

/// Handles the challenge from the server.
///
/// This is the second message sent to the server. It receives the challenge,
/// signs it, and sends the signature back to the server.
async fn handle_challenge<T>(stream: &mut T, private_key: &str) -> Res<ClientHandshakeData>
where
    T: BincodeSend + BincodeReceive,
{
    let ProtocolMessage::HandshakeChallenge(challenge) = stream.pull().await? else {
        return Err(Err::msg("Handshake failed: improper message type (expected handshake challenge)"));
    };

    info!("🚧 Handshake challenge received ...");

    let signature = sign_challenge(&challenge, private_key)?;
    stream.push(ProtocolMessage::HandshakeChallengeResponse(SerializeableSignature::from(signature))).await?;

    info!("⏳ Awaiting challenge validation ...");

    let ProtocolMessage::HandshakeCompletion(peer_public_key) = stream.pull().await?.fail_if_error()? else {
        return Err(Err::msg("Handshake failed: improper message type (expected handshake completion)"));
    };

    Ok(ClientHandshakeData { challenge, peer_public_key })
}

/// Handles the handshake with the server.
async fn handle_handshake<T>(stream: &mut T, private_key: &str, remote_address: &str, should_encrypt: bool) -> Res<ClientKeyExchangeData>
where
    T: BincodeSend + BincodeReceive,
{
    // If we want to request encryption, we need to generate an ephemeral key pair, and send the public key to the server.
    let local_ephemeral_key_pair = generate_ephemeral_key_pair()?;
    let local_peer_public_key = if should_encrypt {
        let pair = local_ephemeral_key_pair
            .public_key
            .as_ref()
            .try_into()
            .map_err(|_| Err::msg("Could not convert peer public key to array"))?;

        Some(pair)
    } else {
        None
    };

    send_preamble(stream, remote_address, local_peer_public_key).await?;
    let handshake_data = handle_challenge(stream, private_key).await?;

    // Compute the ephemeral data.

    let ephemeral_data = ClientKeyExchangeData {
        local_private_key: local_ephemeral_key_pair.private_key,
        peer_public_key: handshake_data.peer_public_key,
        challenge: handshake_data.challenge,
    };

    info!("✅ Challenge accepted!");

    Ok(ephemeral_data)
}

/// Runs the TCP server.
///
/// This is the main entry point for the server. It is used to accept connections and handle them.
async fn run_tcp_server(tunnel_definition: TunnelDefinition, config: Config) {
    let result: Void = async move {
        let listener = TcpListener::bind(&tunnel_definition.bind_address).await?;

        info!(
            "📻 Listening on `{}`, and routing through `{}` to `{}` ...",
            tunnel_definition.bind_address, config.connect_address, tunnel_definition.remote_address
        );

        loop {
            // TODO: Don't "accept" until the handshake is complete with the server?
            let (socket, _) = listener.accept().await?;

            tokio::spawn(handle_tcp(socket, tunnel_definition.remote_address.clone(), config.clone()));
        }
    }
    .await;

    if let Err(err) = result {
        error!("❌ Error starting TCP server, or accepting a connection (shutting down listener for this bind address): {}", err);
    }
}

/// Handles the TCP connection.
///
/// This is the main entry point for the connection. It is used to handle the handshake and pump data between the client and server.
async fn handle_tcp(mut local: TcpStream, remote_address: String, config: Config) {
    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        // Connect to the server.
        let mut remote = BuffedStream::new(remote_connect_tcp(&config.connect_address).await?);

        // Handle the handshake.
        let client_exchange_data = handle_handshake(&mut remote, &config.private_key, &remote_address, config.should_encrypt)
            .await
            .context("Error handling handshake")?;

        info!("✅ Handshake successful: connection established!");

        // Generate and apply the shared secret, if needed.
        if config.should_encrypt {
            let private_key = client_exchange_data.local_private_key;
            let peer_public_key = client_exchange_data.peer_public_key;
            let challenge = client_exchange_data.challenge;

            let shared_secret = generate_shared_secret(private_key, &peer_public_key, &challenge)?;

            remote = remote.with_encryption(shared_secret);
            info!("🔒 Encryption applied ...");
        }

        // Handle the TCP pump.

        info!("⛽ Pumping data between client and remote ...");

        handle_pump(&mut local, &mut remote).await.context("Error handling pump")?;

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

        error!("❌ Error handling the connection: {}.", full_chain);
    }
}

/// Connects to the requested remote.
async fn remote_connect_tcp(connext_address: &str) -> Res<TcpStream> {
    let stream = TcpStream::connect(connext_address).await?;
    info!("✅ Connected to server `{}` ...", connext_address);

    Ok(stream)
}

/// Tests the server connection by performing a handshake.
async fn test_server_connection(tunnel_definition: TunnelDefinition, config: Config) -> Void {
    info!("⏳ Testing server connection ...");

    // Connect to the server.
    let mut remote = BuffedStream::new(remote_connect_tcp(&config.connect_address).await?);

    // Handle the handshake.
    if let Err(e) = handle_handshake(&mut remote, &config.private_key, &tunnel_definition.remote_address, config.should_encrypt).await {
        error!("❌ Test connection failed: {}", e);
        return Err(e);
    }

    info!("✅ Test connection successful!");

    Ok(())
}

// Config.

/// The configuration for the client.
///
/// This is used to store the private key, the connect address, and whether or not to encrypt the connection.
#[derive(Clone)]
struct Config {
    private_key: String,
    connect_address: String,
    should_encrypt: bool,
}

impl Config {
    /// Creates a new configuration.
    fn new(private_key: String, connect_address: String, should_encrypt: bool) -> Self {
        Self {
            private_key,
            connect_address,
            should_encrypt,
        }
    }
}

// Tests.

#[cfg(test)]
pub mod tests {
    use crate::{
        protocol::ProtocolError,
        utils::{
            generate_key_pair,
            tests::{generate_test_duplex, generate_test_fake_peer_public_key},
        },
    };

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_prepare_globals() {
        let key = "key";
        let connect_address = "connect_address";
        let tunnel_definitions = ["a:b:c:d"];

        let instance = Instance::prepare(key, connect_address, &tunnel_definitions, false).unwrap();

        assert_eq!(instance.config.private_key, key);
        assert_eq!(instance.config.connect_address, "connect_address");
        assert_eq!(instance.config.should_encrypt, false);

        assert_eq!(instance.tunnel_definitions[0].bind_address, "a:b");
        assert_eq!(instance.tunnel_definitions[0].remote_address, "c:d");
    }

    #[tokio::test]
    async fn test_send_preamble() {
        let (mut client, mut server) = generate_test_duplex();
        let local_peer_public_key = Some(generate_test_fake_peer_public_key());

        let remote_address = "remote_address:3000";

        send_preamble(&mut client, remote_address, local_peer_public_key).await.unwrap();
        let received = server.pull().await.unwrap();

        assert_eq!(
            received,
            ProtocolMessage::HandshakeStart(Preamble {
                remote: remote_address.to_string(),
                peer_public_key: local_peer_public_key,
            })
        );
    }

    #[tokio::test]
    async fn test_handle_handshake_response() {
        let (mut client, mut server) = generate_test_duplex();
        let key = generate_key_pair().unwrap().private_key;
        let peer_public_key = b"this is a peer public key with s";

        // Have the server send a challenge.
        let challenge_message = ProtocolMessage::HandshakeChallenge(b"this is a challenge and it needs".to_owned());
        let handshake_response_message = ProtocolMessage::HandshakeCompletion(peer_public_key.to_owned());
        server.push(challenge_message).await.unwrap();
        server.push(handshake_response_message).await.unwrap();

        let result = handle_handshake(&mut client, &key, "remote_address", false).await.unwrap();

        assert_eq!(result.peer_public_key, *peer_public_key);
    }

    #[tokio::test]
    async fn test_handle_failed_key_handshake_response() {
        let (mut client, mut server) = generate_test_duplex();
        let key = generate_key_pair().unwrap().private_key;
        let error_message = "error_message";

        // Have the server send a challenge.
        let challenge_message = ProtocolMessage::HandshakeChallenge(b"this is a challenge and it needs".to_owned());
        let handshake_response_message = ProtocolMessage::Error(ProtocolError::InvalidKey(error_message.to_string()));
        server.push(challenge_message).await.unwrap();
        server.push(handshake_response_message).await.unwrap();

        let result = handle_handshake(&mut client, &key, "remote_address", false).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Invalid key: {}", error_message));
    }

    #[tokio::test]
    async fn test_handle_failed_host_handshake_response() {
        let (mut client, mut server) = generate_test_duplex();
        let key = generate_key_pair().unwrap().private_key;
        let error_message = "error_message";

        // Have the server send a challenge.
        let challenge_message = ProtocolMessage::HandshakeChallenge(b"this is a challenge and it needs".to_owned());
        let handshake_response_message = ProtocolMessage::Error(ProtocolError::InvalidHost(error_message.to_string()));
        server.push(challenge_message).await.unwrap();
        server.push(handshake_response_message).await.unwrap();

        let result = handle_handshake(&mut client, &key, "remote_address", false).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Invalid host: {}", error_message));
    }

    #[tokio::test]
    async fn test_handle_failed_unknown_handshake_response() {
        let (mut client, mut server) = generate_test_duplex();
        let key = generate_key_pair().unwrap().private_key;
        let error_message = "error_message";

        // Have the server send a challenge.
        let challenge_message = ProtocolMessage::HandshakeChallenge(b"this is a challenge and it needs".to_owned());
        let handshake_response_message = ProtocolMessage::Error(ProtocolError::Unknown(error_message.to_string()));
        server.push(challenge_message).await.unwrap();
        server.push(handshake_response_message).await.unwrap();

        let result = handle_handshake(&mut client, &key, "remote_address", false).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Unknown: {}", error_message));
    }
}
