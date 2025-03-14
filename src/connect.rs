//! This module contains the code for the client-side of the tunnel.
//!
//! It includes the state machine, operations, and configuration.

use std::{collections::HashMap, marker::PhantomData, net::SocketAddr, sync::Arc};

use anyhow::Context;
use futures::join;
use secrecy::SecretString;
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket}, select, sync::{
        mpsc::{UnboundedReceiver, UnboundedSender}, Mutex
    }, task::JoinHandle
};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{ClientHandshakeData, ClientKeyExchangeData, Constant, Err, Res, TunnelDefinition, Void},
    buffed_stream::BuffedTcpStream,
    protocol::{BincodeReceive, BincodeSend, Challenge, ClientAuthentication, ClientPreamble, ExchangePublicKey, ProtocolMessage},
    security::{resolve_keypath, resolve_known_hosts, resolve_private_key, resolve_public_key},
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret, handle_pump, parse_tunnel_definitions, random_string, sign_challenge, validate_signed_challenge},
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
    pub fn prepare<A, B, C>(key_path: A, connect_address: B, tunnel_definitions: &[C], accept_all_hosts: bool, should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<Option<String>>,
        B: Into<String>,
        C: AsRef<str>,
    {
        let tunnel_definitions = parse_tunnel_definitions(tunnel_definitions)?;

        let key_path = resolve_keypath(key_path)?;
        let private_key = resolve_private_key(&key_path)?;
        let public_key = resolve_public_key(&key_path)?;
        let known_hosts = resolve_known_hosts(&key_path);

        let config = Config::new(public_key, private_key, known_hosts, connect_address.into(), accept_all_hosts, should_encrypt)?;

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
            .map(|tunnel_definition| async {
                // Schedule a test connection.
                tokio::spawn(test_server_connection(tunnel_definition.clone(), self.config.clone()));

                // Start the servers.
                let tcp = tokio::spawn(run_tcp_server(tunnel_definition.clone(), self.config.clone()));
                let udp = tokio::spawn(run_udp_server(tunnel_definition, self.config.clone()));

                let (tcp_result, udp_result) = join!(tcp, udp);

                tcp_result?;
                udp_result?;

                Void::Ok(())
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
async fn send_preamble<T, R>(stream: &mut T, config: &Config, remote_address: R, exchange_public_key: ExchangePublicKey, is_udp: bool) -> Res<Challenge>
where
    T: BincodeSend,
    R: Into<String>,
{
    let challenge = generate_challenge();

    let preamble = ClientPreamble {
        exchange_public_key,
        remote: remote_address.into(),
        challenge,
        should_encrypt: config.should_encrypt,
        is_udp,
    };

    stream.push(ProtocolMessage::ClientPreamble(preamble)).await?;

    info!("✅ Sent preamble to server ...");

    Ok(challenge)
}

/// Handles the challenge from the server.
///
/// This is the second message sent to the server. It receives the challenge,
/// signs it, and sends the signature back to the server.
async fn handle_challenge<T>(stream: &mut T, config: &Config, client_challenge: &Challenge) -> Res<ClientHandshakeData>
where
    T: BincodeSend + BincodeReceive,
{
    // Wait for the server's preamble.

    let ProtocolMessage::ServerPreamble(server_preamble) = stream.pull().await? else {
        return Err(Err::msg("Handshake failed: improper message type (expected handshake challenge)"));
    };

    // Validate the server's signature.

    validate_signed_challenge(client_challenge, &server_preamble.signature.into(), &server_preamble.identity_public_key)?;

    info!("✅ Server's signature validated with public key `{}` ...", server_preamble.identity_public_key);

    // Ensure that the server is in the `known_hosts` file.

    if !config.accept_all_hosts && !config.known_hosts.contains(&server_preamble.identity_public_key) {
        // Client doesn't really need to tell the server about failures, so will error and break the pipe.
        return Err(Err::msg(format!("Server's public key `{}` is not in the known hosts file", server_preamble.identity_public_key)));
    }

    info!("🚧 Signing server challenge ...");

    let client_signature = sign_challenge(&server_preamble.challenge, &config.private_key)?;
    let client_authentication = ClientAuthentication {
        identity_public_key: config.public_key.clone(),
        signature: client_signature.into(),
    };
    stream.push(ProtocolMessage::ClientAuthentication(client_authentication)).await?;

    info!("⏳ Awaiting challenge validation ...");

    let ProtocolMessage::HandshakeCompletion = stream.pull().await?.fail_if_error()? else {
        return Err(Err::msg("Handshake failed: improper message type (expected handshake completion)"));
    };

    Ok(ClientHandshakeData {
        server_challenge: server_preamble.challenge,
        server_exchange_public_key: server_preamble.exchange_public_key,
    })
}

/// Handles the handshake with the server.
async fn handle_handshake<T, R>(stream: &mut T, config: &Config, remote_address: R, is_udp: bool) -> Res<ClientKeyExchangeData>
where
    T: BincodeSend + BincodeReceive,
    R: Into<String>,
{
    // If we want to request encryption, we need to generate an ephemeral key pair, and send the public key to the server.
    let exchange_key_pair = generate_ephemeral_key_pair()?;
    let exchange_public_key = exchange_key_pair.public_key.as_ref().try_into().map_err(|_| Err::msg("Could not convert peer public key to array"))?;

    let client_challenge = send_preamble(stream, config, remote_address, exchange_public_key, is_udp).await?;
    let handshake_data = handle_challenge(stream, config, &client_challenge).await?;

    // Compute the ephemeral data.

    let ephemeral_data = ClientKeyExchangeData {
        server_exchange_public_key: handshake_data.server_exchange_public_key,
        server_challenge: handshake_data.server_challenge,
        local_exchange_private_key: exchange_key_pair.private_key,
        local_challenge: client_challenge,
    };

    info!("✅ Challenge accepted!");

    Ok(ephemeral_data)
}

/// Connects to the requested remote.
async fn server_connect(connect_address: &str) -> Res<TcpStream> {
    let stream = TcpStream::connect(connect_address).await?;
    info!("✅ Connected to server `{}` ...", connect_address);

    Ok(stream)
}

/// Establishes the e2e connection with server.
async fn connect(config: &Config, remote_address: &str, is_udp: bool) -> Res<BuffedTcpStream> {
    // Connect to the server.
    let server = server_connect(&config.connect_address).await?;
    server.set_nodelay(true)?;

    let mut server = BuffedTcpStream::from(server);

    // Handle the handshake.
    let handshake_data = handle_handshake(&mut server, config, remote_address, is_udp).await.context("Error handling handshake")?;

    info!("✅ Handshake successful: connection established!");

    // Generate and apply the shared secret, if needed.
    if config.should_encrypt {
        let salt_bytes = [handshake_data.server_challenge, handshake_data.local_challenge].concat();

        let shared_secret = generate_shared_secret(handshake_data.local_exchange_private_key, &handshake_data.server_exchange_public_key, &salt_bytes)?;

        server = server.with_encryption(shared_secret);
        info!("🔒 Encryption applied ...");
    }

    Ok(server)
}

// TCP connection.

/// Runs the TCP server.
///
/// This is the main entry point for the server. It is used to accept connections and handle them.
async fn run_tcp_server(tunnel_definition: TunnelDefinition, config: Config) {
    let result: Void = async move {
        let listener = TcpListener::bind(&tunnel_definition.bind_address).await?;

        info!(
            "📻 [TCP] Listening on `{}`, and routing through `{}` to `{}` ...",
            tunnel_definition.bind_address, config.connect_address, tunnel_definition.remote_address
        );

        loop {
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
    let span = info_span!("tcp", id = id);

    let result: Void = async move {
        // Connect.

        let mut server = connect(&config, &remote_address, false).await?;

        // Handle the TCP pump.

        info!("⛽ Pumping data between client and remote ...");

        local.set_nodelay(true)?;

        handle_pump(&mut local, &mut server.take()?).await.context("Error handling pump")?;

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

// UDP connection.

/// Runs the UDP server.
///
/// This is the main entry point for the server. It is used to accept connections and handle them.
async fn run_udp_server(tunnel_definition: TunnelDefinition, config: Config) {
    let result: Void = async move {
        let socket = Arc::new(UdpSocket::bind(&tunnel_definition.bind_address).await?);

        info!(
            "📻 [UDP] Listening on `{}`, and routing through `{}` to `{}` ...",
            tunnel_definition.bind_address, config.connect_address, tunnel_definition.remote_address
        );

        let clients = Arc::new(Mutex::new(HashMap::<SocketAddr, UnboundedSender<Vec<u8>>>::new()));

        loop {
            // Receive a datagram.

            // TODO: _technically_, this could be up to 65,507 bytes, but that would be a bit silly, so 8 KB should be fine (since most systems use the MTU of 1500).
            let mut buf = vec![0; Constant::BUFFER_SIZE];
            let (read, addr) = socket.recv_from(&mut buf).await?;
            buf.truncate(read);

            // Handle the packet.

            if let Some(data_sender) = clients.lock().await.get_mut(&addr) {
                // In the case where we already have a connection, we should push the message into the channel.
                data_sender.send(buf)?;
            } else {
                // In this case, we need to create a new connection.
                let socket_clone = socket.clone();
                let config_clone = config.clone();

                // Create a new channel for the client.
                let (data_sender, data_receiver) = tokio::sync::mpsc::unbounded_channel();
                data_sender.send(buf)?;
                clients.lock().await.insert(addr, data_sender);

                // Spawn a new task to handle the connection.
                let clients_clone = clients.clone();
                let remote_address = tunnel_definition.remote_address.clone();
                tokio::spawn(async move {
                    // Handle the connection.
                    handle_udp(addr, socket_clone, data_receiver, remote_address, config_clone).await;

                    // Remove the client from the list of clients.
                    clients_clone.lock().await.remove(&addr);
                });
            }
        }
    }
    .await;

    if let Err(err) = result {
        error!("❌ Error starting UDP server, or accepting a connection (shutting down listener for this bind address): {}", err);
    }
}

/// Handles a new UDP connection.
async fn handle_udp(address: SocketAddr, client_socket: Arc<UdpSocket>, mut data_receiver: UnboundedReceiver<Vec<u8>>, remote_address: String, config: Config) {
    let id = random_string(6);
    let span = info_span!("udp", id = id);

    let result: Void = async move {
        // Connect.

        let server = connect(&config, &remote_address, true).await?;

        // Handle the UDP pump.

        info!("⛽ Pumping data between client and remote ...");

        let client_socket_clone = client_socket.clone();
        let (mut remote_read, mut remote_write) = server.into_split();

        // Connection will be closed automatically when either client side disconnects or 
        // when the server detects inactivity timeout. No explicit disconnect logic needed here.

        let pump_up: JoinHandle<Void> = tokio::spawn(async move {
            while let Some(data) = data_receiver.recv().await {
                remote_write.push(ProtocolMessage::UdpData(data.to_vec())).await?;
            }

            Ok(())
        });

        let pump_down: JoinHandle<Void> = tokio::spawn(async move {
            while let ProtocolMessage::UdpData(data) = remote_read.pull().await? {
                client_socket_clone.send_to(&data, &address).await?;
            }

            Ok(())
        });

        // Wait for either side to finish (server handles the connection closing when it has not detected activity on the pump).
        // Essentially, we are waiting for either side to finish, or to time out.  The server will handle the timeout, which will close the
        // TCP side, which will then close the UDP side (and then the client is removed from the client list).

        let result = select! {
            r = pump_up => r?,
            r = pump_down => r?,
        };

        // Check for errors.

        result?;

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

// Client connection tests.

/// Tests the server connection by performing a handshake.
async fn test_server_connection(tunnel_definition: TunnelDefinition, config: Config) -> Void {
    info!("⏳ Testing server connection ...");

    // Connect to the server.
    let mut remote = BuffedTcpStream::from(server_connect(&config.connect_address).await?);

    // Handle the handshake.
    if let Err(e) = handle_handshake(&mut remote, &config, &tunnel_definition.remote_address, false).await {
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
pub(crate) struct Config {
    pub(crate) public_key: String,
    pub(crate) private_key: SecretString,
    pub(crate) known_hosts: Vec<String>,
    pub(crate) connect_address: String,
    pub(crate) accept_all_hosts: bool,
    pub(crate) should_encrypt: bool,
}

impl Config {
    /// Creates a new configuration.
    fn new(public_key: String, private_key: SecretString, known_hosts: Vec<String>, connect_address: String, accept_all_hosts: bool, should_encrypt: bool) -> Res<Self> {
        Ok(Self {
            public_key,
            private_key,
            connect_address,
            known_hosts,
            accept_all_hosts,
            should_encrypt,
        })
    }
}

// Tests.

#[cfg(test)]
pub mod tests {
    use crate::utils::{
        generate_key_pair,
        tests::{generate_test_duplex, generate_test_fake_exchange_public_key},
    };

    use super::*;
    use pretty_assertions::assert_eq;

    pub(crate) fn generate_test_client_config() -> Config {
        let key_path = "test/client";

        let public_key = resolve_public_key(key_path).unwrap();
        let private_key = resolve_private_key(key_path).unwrap();
        let known_hosts = resolve_known_hosts(key_path);

        Config {
            public_key,
            private_key,
            known_hosts,
            connect_address: "connect_address".to_string(),
            accept_all_hosts: false,
            should_encrypt: false,
        }
    }

    #[test]
    fn test_prepare() {
        let key_path = "test/client";
        let connect_address = "connect_address";
        let tunnel_definitions = ["localhost:5000:example.com:80", "127.0.0.1:6000:api.example.com:443"];
        let accept_all_hosts = false;
        let should_encrypt = false;

        let instance = Instance::prepare(key_path.to_owned(), connect_address, &tunnel_definitions, accept_all_hosts, should_encrypt).unwrap();

        // Verify config
        assert_eq!(instance.config.connect_address, connect_address);
        assert_eq!(instance.config.should_encrypt, should_encrypt);

        // Verify the public key was loaded correctly
        let expected_public_key = resolve_public_key(key_path).unwrap();
        assert_eq!(instance.config.public_key, expected_public_key);

        // Verify known hosts were loaded correctly
        let expected_known_hosts = resolve_known_hosts(key_path);
        assert_eq!(instance.config.known_hosts, expected_known_hosts);

        // Verify tunnel definitions
        assert_eq!(instance.tunnel_definitions.len(), 2);
        assert_eq!(instance.tunnel_definitions[0].bind_address, "localhost:5000");
        assert_eq!(instance.tunnel_definitions[0].remote_address, "example.com:80");
        assert_eq!(instance.tunnel_definitions[1].bind_address, "127.0.0.1:6000");
        assert_eq!(instance.tunnel_definitions[1].remote_address, "api.example.com:443");
    }

    #[tokio::test]
    async fn test_send_preamble() {
        let (mut client, mut server) = generate_test_duplex();
        let config = generate_test_client_config();
        let remote_address = "remote_address:3000";
        let exchange_public_key = generate_test_fake_exchange_public_key();

        let client_challenge = send_preamble(&mut client, &config, remote_address, exchange_public_key, false).await.unwrap();

        let received = server.pull().await.unwrap();

        match received {
            ProtocolMessage::ClientPreamble(preamble) => {
                assert_eq!(preamble.remote, remote_address);
                assert_eq!(preamble.exchange_public_key, exchange_public_key);
                assert_eq!(preamble.challenge, client_challenge);
                assert_eq!(preamble.should_encrypt, config.should_encrypt);
            }
            _ => panic!("Expected ClientPreamble, got different message type"),
        }
    }

    #[tokio::test]
    async fn test_handle_challenge_bad_key() {
        let (mut client, mut server) = generate_test_duplex();
        let config = generate_test_client_config();
        let client_challenge = generate_challenge();
        let bad_key = generate_key_pair().unwrap().private_key;

        tokio::spawn(async move {
            // Create and send ServerPreamble with unknown key
            let preamble = crate::protocol::ServerPreamble {
                identity_public_key: bad_key,
                signature: [0u8; 64].into(), // Mock signature
                challenge: generate_challenge(),
                exchange_public_key: generate_test_fake_exchange_public_key(),
            };

            server.push(ProtocolMessage::ServerPreamble(preamble)).await.unwrap();
        });

        let result = handle_challenge(&mut client, &config, &client_challenge).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid signature");
    }

    #[tokio::test]
    async fn test_handle_challenge_wrong_message_type() {
        let (mut client, mut server) = generate_test_duplex();
        let config = generate_test_client_config();
        let client_challenge = generate_challenge();

        tokio::spawn(async move {
            // Send wrong message type
            server.push(ProtocolMessage::HandshakeCompletion).await.unwrap();
        });

        let result = handle_challenge(&mut client, &config, &client_challenge).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("improper message type"));
    }
}
