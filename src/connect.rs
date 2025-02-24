use std::{io::ErrorKind, marker::PhantomData, sync::OnceLock, time::Duration};

use tokio::{io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{error, info, info_span, Instrument};

use crate::{base::{Err, Res, Constant, Void}, utils::{handle_tcp_pump, parse_tunnel_definition, prepare_preamble, random_string, read_to_next_delimiter, sign_challenge}};

// State machine.

pub struct ConfigState;
pub struct ReadyState;

pub struct Instance<S = ConfigState> {
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    pub fn prepare<A, B, C>(private_key: A, connect_address: B, tunnel_definition: C, should_encrypt: bool) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: Into<String>,
        C: AsRef<str>,
    {
        let tunnel = parse_tunnel_definition(tunnel_definition.as_ref())?;
    
        Config::create(private_key.into(), tunnel.bind_address, connect_address.into(), tunnel.remote_address, should_encrypt)?;
    
        Ok(Instance { _phantom: PhantomData })
    }
}

impl Instance<ReadyState> {
    pub async fn start(self) -> Void {
        if !Config::ready() {
            return Err(Err::msg("Configuration has not been set: only one config per process"));
        }

        // Schedule a test connection.

        tokio::spawn(test_tcp_connection());

        // Finally, start the server.

        info!("📻 Listening on `{}`, and routing through `{}` to `{}` ...", Config::bind_address(), Config::connect_address(), Config::remote_address());
        run_tcp_server().await?;

        Ok(())
    }
}

// Operations.

async fn handle_handshake<T>(stream: &mut T) -> Void
where 
    T: AsyncBufRead + AsyncWrite + Unpin,
{
    send_preamble(stream).await?;
    handle_challenge(stream).await?;
    
    // Await the handshake response.

    let data = handle_handshake_response(stream).await?;
    if !data.is_empty() {
        return Err(Err::msg("Handshake failed (completion message had data)"));
    }

    info!("✅ Challenge accepted ...");

    Ok(())
}

async fn handle_challenge<T>(stream: &mut T) -> Void
where 
    T: AsyncBufRead + AsyncWrite + Unpin,
{
    let challenge = handle_handshake_response(stream).await?;
    info!("🚧 Handshake challenge received ...");

    let signature = sign_challenge(&challenge, Config::private_key())?;
    stream.write_all(&[Constant::HANDSHAKE_CHALLENGE_RESPONSE, &signature, Constant::DELIMITER].concat()).await?;

    info!("⏳ Awaiting challenge validation ...");

    Ok(())
}

async fn send_preamble<T>(stream: &mut T) -> Void
where 
    T: AsyncWrite + Unpin,
{
    let preamble = prepare_preamble(Config::remote_address())?;
    stream.write_all(&preamble).await?;
    info!("✅ Sent preamble to server ...");

    Ok(())
}

async fn handle_handshake_response<T>(stream: &mut T) -> Res<Vec<u8>>
where 
    T: AsyncBufRead + Unpin,
{
    let buf = read_to_next_delimiter(stream).await?;

    if buf.starts_with(Constant::HANDSHAKE_COMPLETION) {
        Ok(vec![])
    } else if buf.starts_with(Constant::HANDSHAKE_CHALLENGE) {
        if !buf.starts_with(Constant::HANDSHAKE_CHALLENGE) {
            return Err(Err::msg("Handshake failed (challenge message did not start with the expected sentinel)"));
        }

        let challenge = buf[Constant::SIZE..].to_vec();
        Ok(challenge)
    } else if buf.starts_with(Constant::ERROR_INVALID_KEY) {
        let message = String::from_utf8(buf[Constant::SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid key): {}", message)))
    } else if buf.starts_with(Constant::ERROR_INVALID_HOST) {
        let message = String::from_utf8(buf[Constant::SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid host): {}", message)))
    } else {
        Err(Err::msg("Handshake failed (unknown error)"))
    }
}

async fn run_tcp_server() -> Void {
    let listener = TcpListener::bind(Config::bind_address()).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket));
    }
}

async fn handle_tcp(mut local: TcpStream) -> Void {
    let id = random_string(6);
    let span = info_span!("conn", id = id);

    async move {
        // Connect to the server.
        let mut remote = BufReader::new(remote_connect_tcp().await?);

        // Handle the handshake.
        match handle_handshake(&mut remote).await {
            Ok(_) => info!("✅ Handshake successful: connection established!"),
            Err(err) => {
                let chain = err.chain().collect::<Vec<_>>();
                let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");

                error!("❌ Error handling the handshake: {}.", full_chain);
                return Err(err);
            }
        };

        info!("⛽ Pumping data between client and remote ...");

        // Handle the TCP pump.
        match handle_tcp_pump(&mut local, &mut remote.into_inner()).await {
            Ok(_) => info!("✅ Connection closed."),
            Err(err) => {
                let chain = err.chain().collect::<Vec<_>>();
                let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");

                error!("❌ Error handling the pump: {}.", full_chain);
                return Err(err);
            }
        };

        Ok(())
    }.instrument(span).await
}

async fn remote_connect_tcp() -> Res<TcpStream> {
    let stream = TcpStream::connect(Config::connect_address()).await?;
    info!("✅ Connected to server `{}` ...", Config::connect_address());

    Ok(stream)
}

async fn test_tcp_connection() {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    info!("⏳ Testing TCP connection ...");
    
    let result = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(Config::bind_address())).await;

    let mut stream = match result {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            error!("❌ Error connecting to TCP server: {}", err);
            return;
        },
        Err(_) => {
            error!("❌ Timeout connecting to TCP server");
            return;
        },
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
        },
        Err(_) => info!("✅ TCP connection test passed: connection is good."),
    }
}

// Statics.

static CONFIG: OnceLock<Config> = OnceLock::new();

struct Config {
    private_key: String,
    bind_address: String,
    connect_address: String,
    remote_address: String,
    should_encrypt: bool,
}

impl Config {
    fn create(private_key: String, bind_address: String, connect_address: String, remote_address: String, should_encrypt: bool) -> Res<&'static Self> {
        if Self::ready() {
            return Err(Err::msg("Configuration has already been set."));
        }

        let this = Self {
            private_key,
            bind_address,
            connect_address,
            remote_address,
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
    
    fn bind_address() -> &'static str {
        Self::get().bind_address.as_str()
    }

    fn connect_address() -> &'static str {
        Self::get().connect_address.as_str()
    }

    fn remote_address() -> &'static str {
        Self::get().remote_address.as_str()
    }

    fn should_encrypt() -> bool {
        Self::get().should_encrypt
    }
}

// Tests.

#[cfg(test)]
pub mod tests {
    use crate::utils::tests::MockStream;

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_prepare_globals() {
        let key = "key";
        let connect_address = "connect_address";
        let tunnel_definition = "a:b:c:d";

        Instance::prepare(key, connect_address, tunnel_definition, false).unwrap();

        assert_eq!(Config::private_key(), key);
        assert_eq!(Config::bind_address(), "a:b");
        assert_eq!(Config::connect_address(), "connect_address");
        assert_eq!(Config::remote_address(), "c:d");
        assert_eq!(Config::should_encrypt(), false);
    }

    #[tokio::test]
    async fn test_send_preamble() {
        let key = "key";
        let remote_address = "remote_address:3000";
        let tunnel_definition = format!("a:b:{}", remote_address);
        let expected = prepare_preamble(remote_address).unwrap();

        Instance::prepare(key, "connect_address", tunnel_definition, false).unwrap();

        let mut stream = MockStream::new(vec![], vec![]);
        
        send_preamble(&mut stream).await.unwrap();
        
        assert_eq!(stream.write, expected);
    }

    #[tokio::test]
    async fn test_handle_handshake_response() {
        let mut stream = BufReader::new(MockStream::new([Constant::HANDSHAKE_COMPLETION, Constant::DELIMITER].concat(), vec![]));

        handle_handshake_response(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn handle_failed_key_handshake_response() {
        let message = "foo";
        let mut stream = BufReader::new(MockStream::new([Constant::ERROR_INVALID_KEY, message.as_bytes(), Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid key): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_host_handshake_response() {
        let message = "foo";
        let mut stream = BufReader::new(MockStream::new([Constant::ERROR_INVALID_HOST, message.as_bytes(), Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid host): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_unknown_handshake_response() {
        let mut stream = BufReader::new(MockStream::new([&[0x00], Constant::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Handshake failed (unknown error)");
    }
}