use std::{io::ErrorKind, marker::PhantomData, sync::OnceLock, time::Duration};

use anyhow::Context;
use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{Challenge, Constant, EphemeralData, Err, PeerPublicKey, Res, TunnelDefinition, Void},
    buffed_stream::BuffedStream,
    utils::{generate_ephemeral_key_pair, generate_shared_secret, handle_pump, parse_tunnel_definitions, prepare_preamble, random_string, read_to_next_delimiter, sign_challenge},
};

// State machine.

pub struct ConfigState;
pub struct ReadyState;

pub struct Instance<S = ConfigState> {
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    pub fn prepare<A, B, C>(private_key: A, connect_address: B, tunnel_definitions: &[C], should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: Into<String>,
        C: AsRef<str>,
    {
        let tunnel_definitions = parse_tunnel_definitions(tunnel_definitions)?;

        Config::create(private_key.into(), connect_address.into(), tunnel_definitions, should_encrypt)?;

        Ok(Instance { _phantom: PhantomData })
    }
}

impl Instance<ReadyState> {
    pub async fn start(self) -> Void {
        if !Config::ready() {
            return Err(Err::msg("Configuration has not been set: only one config per process"));
        }

        // Finally, start the server(s) (one per tunnel definition).

        let tasks = Config::tunnel_definitions()
            .iter()
            .map(|tunnel_definition| {
                // Schedule a test connection.
                tokio::spawn(test_tcp_connection(&tunnel_definition.bind_address));

                // Start the server.
                tokio::spawn(run_tcp_server(tunnel_definition))
            })
            .collect::<Vec<_>>();

        // Basically, only crash if _all_ of the servers fail to start.  Otherwise, the user can use the error logs to see that some of the
        // servers failed to start.
        futures::future::join_all(tasks).await;

        Ok(())
    }
}

// Operations.

async fn handle_handshake<T>(stream: &mut T, remote_address: &str) -> Res<EphemeralData>
where
    T: AsyncBufRead + AsyncWrite + Unpin,
{
    let ephemeral_key_pair = generate_ephemeral_key_pair()?;
    let peer_public_key = ephemeral_key_pair.public_key.as_ref().try_into().map_err(|_| Err::msg("Could not convert peer public key to array"))?;

    send_preamble(stream, remote_address, peer_public_key).await?;
    let challenge = handle_challenge(stream).await?;

    // Await the handshake response.

    let data = handle_handshake_response(stream).await?;

    // Compute the ephemeral data.
    let peer_public_key = data.try_into().map_err(|_| Err::msg("Could not convert peer public key to array"))?;
    let ephemeral_data = EphemeralData {
        ephemeral_key_pair,
        peer_public_key,
        challenge,
    };

    info!("✅ Challenge accepted ...");

    Ok(ephemeral_data)
}

async fn handle_challenge<T>(stream: &mut T) -> Res<Challenge>
where
    T: AsyncBufRead + AsyncWrite + Unpin,
{
    let challenge: Challenge = handle_handshake_response(stream).await?.try_into().map_err(|_| Err::msg("Could not convert challenge to array"))?;
    info!("🚧 Handshake challenge received ...");

    let signature = sign_challenge(&challenge, Config::private_key())?;
    stream.write_all(&[Constant::HANDSHAKE_CHALLENGE_RESPONSE, &signature, Constant::DELIMITER].concat()).await?;
    stream.flush().await?;

    info!("⏳ Awaiting challenge validation ...");

    Ok(challenge)
}

async fn send_preamble<T>(stream: &mut T, remote_address: &str, peer_public_key: &PeerPublicKey) -> Void
where
    T: AsyncWrite + Unpin,
{
    let preamble = prepare_preamble(remote_address, peer_public_key)?;
    stream.write_all(&preamble).await?;
    stream.flush().await?;

    info!("✅ Sent preamble to server ...");

    Ok(())
}

async fn handle_handshake_response<T>(stream: &mut T) -> Res<Vec<u8>>
where
    T: AsyncBufRead + Unpin,
{
    let buf = read_to_next_delimiter(stream).await?;

    if buf.starts_with(Constant::HANDSHAKE_COMPLETION) {
        let server_ephemeral_public_key = buf[Constant::DELIMITER_SIZE..].to_vec();
        Ok(server_ephemeral_public_key)
    } else if buf.starts_with(Constant::HANDSHAKE_CHALLENGE) {
        if !buf.starts_with(Constant::HANDSHAKE_CHALLENGE) {
            return Err(Err::msg("Handshake failed (challenge message did not start with the expected sentinel)"));
        }

        let challenge = buf[Constant::DELIMITER_SIZE..].to_vec();
        Ok(challenge)
    } else if buf.starts_with(Constant::ERROR_INVALID_KEY) {
        let message = String::from_utf8(buf[Constant::DELIMITER_SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid key): {}", message)))
    } else if buf.starts_with(Constant::ERROR_INVALID_HOST) {
        let message = String::from_utf8(buf[Constant::DELIMITER_SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid host): {}", message)))
    } else {
        Err(Err::msg("Handshake failed (unknown error)"))
    }
}

async fn run_tcp_server(tunnel_definition: &'static TunnelDefinition) {
    let result: Void = async move {
        let listener = TcpListener::bind(&tunnel_definition.bind_address).await?;

        info!(
            "📻 Listening on `{}`, and routing through `{}` to `{}` ...",
            tunnel_definition.bind_address,
            Config::connect_address(),
            tunnel_definition.remote_address
        );

        loop {
            let (socket, _) = listener.accept().await?;

            tokio::spawn(handle_tcp(socket, &tunnel_definition.remote_address));
        }
    }
    .await;

    if let Err(err) = result {
        error!("❌ Error starting TCP server, or accepting a connection (shutting down listener for this bind address): {}", err);
    }
}

async fn handle_tcp(mut local: TcpStream, remote_address: &str) {
    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        // Connect to the server.
        let mut remote = BuffedStream::new(remote_connect_tcp().await?);

        // Handle the handshake.
        let ephemeral_data = handle_handshake(&mut remote, remote_address).await.context("Error handling handshake")?;

        info!("✅ Handshake successful: connection established!");

        // Generate and apply the shared secret, if needed.
        if Config::should_encrypt() {
            let private_key = ephemeral_data.ephemeral_key_pair.private_key;
            let peer_public_key = ephemeral_data.peer_public_key;
            let challenge = ephemeral_data.challenge;

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

async fn remote_connect_tcp() -> Res<TcpStream> {
    let stream = TcpStream::connect(Config::connect_address()).await?;
    info!("✅ Connected to server `{}` ...", Config::connect_address());

    Ok(stream)
}

async fn test_tcp_connection(bind_address: &'static str) {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    info!("⏳ Testing TCP connection ...");

    let result = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(bind_address)).await;

    let mut stream = match result {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            error!("❌ Error connecting to TCP server: {}", err);
            return;
        }
        Err(_) => {
            error!("❌ Timeout connecting to TCP server");
            return;
        }
    };

    // For our test connect, we attempt to read a `u8`.  If it times out, that's "good", since it means that this instance was likely able to
    // complete the handshake with the server.  If it fails with EOF, then the handshake was likely not completed, so this test socket was closed
    // by this instance.
    // Therefore:
    // - Timeout: good.
    // - EOF: bad.

    let result = tokio::time::timeout(Duration::from_secs(1), stream.read_u8()).await;

    match result {
        Ok(Ok(_)) => panic!("This should never happen.  The read test should not have bytes to read."),
        Ok(Err(err)) => {
            if err.kind() == ErrorKind::UnexpectedEof {
                error!("❌ The test socket was closed, which indicates the handshake may have failed.");
            } else {
                error!("❌ Another error occurred reading from TCP connection test (this may be OK): {}", err);
            }
        }
        Err(_) => {}
    }
}

// Statics.

static CONFIG: OnceLock<Config> = OnceLock::new();

struct Config {
    private_key: String,
    connect_address: String,
    tunnel_definitions: Vec<TunnelDefinition>,
    should_encrypt: bool,
}

impl Config {
    fn create(private_key: String, connect_address: String, tunnel_definitions: Vec<TunnelDefinition>, should_encrypt: bool) -> Res<&'static Self> {
        if Self::ready() {
            return Err(Err::msg("Configuration has already been set."));
        }

        let this = Self {
            private_key,
            connect_address,
            tunnel_definitions,
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

    fn connect_address() -> &'static str {
        Self::get().connect_address.as_str()
    }

    fn tunnel_definitions() -> &'static [TunnelDefinition] {
        Self::get().tunnel_definitions.as_slice()
    }

    fn should_encrypt() -> bool {
        Self::get().should_encrypt
    }
}

// Tests.

#[cfg(test)]
pub mod tests {
    use crate::utils::tests::{MockStream, generate_test_fake_peer_public_key};

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_prepare_globals() {
        let key = "key";
        let connect_address = "connect_address";
        let tunnel_definitions = ["a:b:c:d"];

        Instance::prepare(key, connect_address, &tunnel_definitions, false).unwrap();

        assert_eq!(Config::private_key(), key);
        assert_eq!(Config::connect_address(), "connect_address");
        assert_eq!(Config::tunnel_definitions()[0].bind_address, "a:b");
        assert_eq!(Config::tunnel_definitions()[0].remote_address, "c:d");
        assert_eq!(Config::should_encrypt(), false);
    }

    #[tokio::test]
    async fn test_send_preamble() {
        let key = "key";
        let peer_public_key = &generate_test_fake_peer_public_key();

        let remote_address = "remote_address:3000";
        let tunnel_definitions = [format!("a:b:{}", remote_address)];

        let expected = prepare_preamble(remote_address, peer_public_key).unwrap();

        Instance::prepare(key, "connect_address", &tunnel_definitions, false).unwrap();

        let mut stream = MockStream::new(vec![], vec![]);

        send_preamble(&mut stream, remote_address, peer_public_key).await.unwrap();

        assert_eq!(stream.write, expected);
    }

    #[tokio::test]
    async fn test_handle_handshake_response() {
        let mut stream = BuffedStream::new(MockStream::new([Constant::HANDSHAKE_COMPLETION, Constant::DELIMITER].concat(), vec![]));

        handle_handshake_response(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn handle_failed_key_handshake_response() {
        let message = "foo";
        let mut stream = BuffedStream::new(MockStream::new([Constant::ERROR_INVALID_KEY, message.as_bytes(), Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid key): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_host_handshake_response() {
        let message = "foo";
        let mut stream = BuffedStream::new(MockStream::new([Constant::ERROR_INVALID_HOST, message.as_bytes(), Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid host): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_unknown_handshake_response() {
        let mut stream = BuffedStream::new(MockStream::new([&[0x00], Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Handshake failed (unknown error)");
    }
}
