use std::{borrow::Cow, io::ErrorKind, sync::OnceLock, time::Duration};

use tokio::{io::{AsyncBufRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader}, net::{TcpListener, TcpStream}};
use tracing::{error, info, info_span, Instrument};

use crate::{base::{Err, Res, Sentinel, Void}, utils::{handle_tcp_pump, parse_tunnel_definition, prepare_preamble, random_string, read_to_next_delimiter, sign_challenge}};

static PRIVATE_KEY: OnceLock<String> = OnceLock::new();

static BIND_ADDRESS: OnceLock<String> = OnceLock::new();
static CONNECT_ADDRESS: OnceLock<String> = OnceLock::new();
static REMOTE_ADDRESS: OnceLock<String> = OnceLock::new();

pub async fn start(server: String, tunnel: String, private_key: String) -> Void {
    // Compute the tunnel definition.

    let tunnel_definition = parse_tunnel_definition(&tunnel)?;

    // Prepare the globals.

    prepare_globals(private_key, tunnel_definition.bind_address, server, tunnel_definition.remote_address)?;

    // Schedule a test connection.

    tokio::spawn(test_tcp_connection());

    // Finally, start the server.

    info!("📻 Listening on `{}`, and routing through `{}` to `{}` ...", BIND_ADDRESS.get().unwrap(), CONNECT_ADDRESS.get().unwrap(), REMOTE_ADDRESS.get().unwrap());
    run_tcp_server().await?;

    Ok(())   
}

fn prepare_globals<'a, 'b, 'c>(key: impl Into<Cow<'a, str>>, bind_address: impl Into<Cow<'b, str>>, connect_address: impl Into<Cow<'c, str>>, remote_address: impl Into<Cow<'c, str>>) -> Void {
    PRIVATE_KEY.get_or_init(|| key.into().to_string());
    BIND_ADDRESS.get_or_init(|| bind_address.into().to_string());
    CONNECT_ADDRESS.get_or_init(|| connect_address.into().to_string());
    REMOTE_ADDRESS.get_or_init(|| remote_address.into().to_string());

    Ok(())
}

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

    let signature = sign_challenge(&challenge, PRIVATE_KEY.get().unwrap())?;
    stream.write_all(&[Sentinel::HANDSHAKE_CHALLENGE_RESPONSE, &signature, Sentinel::DELIMITER].concat()).await?;

    info!("⏳ Awaiting challenge validation ...");

    Ok(())
}

async fn send_preamble<T>(stream: &mut T) -> Void
where 
    T: AsyncWrite + Unpin,
{
    let preamble = prepare_preamble(REMOTE_ADDRESS.get().unwrap())?;
    stream.write_all(&preamble).await?;
    info!("✅ Sent preamble to server ...");

    Ok(())
}

async fn handle_handshake_response<T>(stream: &mut T) -> Res<Vec<u8>>
where 
    T: AsyncBufRead + Unpin,
{
    let buf = read_to_next_delimiter(stream).await?;

    if buf.starts_with(Sentinel::HANDSHAKE_COMPLETION) {
        Ok(vec![])
    } else if buf.starts_with(Sentinel::HANDSHAKE_CHALLENGE) {
        if !buf.starts_with(Sentinel::HANDSHAKE_CHALLENGE) {
            return Err(Err::msg("Handshake failed (challenge message did not start with the expected sentinel)"));
        }

        let challenge = buf[Sentinel::SIZE..].to_vec();
        Ok(challenge)
    } else if buf.starts_with(Sentinel::ERROR_INVALID_KEY) {
        let message = String::from_utf8(buf[Sentinel::SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid key): {}", message)))
    } else if buf.starts_with(Sentinel::ERROR_INVALID_HOST) {
        let message = String::from_utf8(buf[Sentinel::SIZE..].to_vec())?;

        Err(Err::msg(format!("Handshake failed (invalid host): {}", message)))
    } else {
        Err(Err::msg("Handshake failed (unknown error)"))
    }
}

async fn run_tcp_server() -> Void {
    let listener = TcpListener::bind(BIND_ADDRESS.get().unwrap()).await?;

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
    let stream = TcpStream::connect(CONNECT_ADDRESS.get().unwrap()).await?;
    info!("✅ Connected to server `{}` ...", CONNECT_ADDRESS.get().unwrap());

    Ok(stream)
}

async fn test_tcp_connection() {
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    info!("⏳ Testing TCP connection ...");
    
    let result = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(BIND_ADDRESS.get().unwrap())).await;

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

#[cfg(test)]
pub mod tests {
    use crate::utils::tests::MockStream;

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_prepare_globals() {
        let key = "key";
        let bind_address = "bind_address";
        let connect_address = "connect_address";
        let remote_address = "remote_address";

        prepare_globals(key, bind_address, connect_address, remote_address).unwrap();

        assert_eq!(PRIVATE_KEY.get().unwrap(), key);
        assert_eq!(BIND_ADDRESS.get().unwrap(), bind_address);
        assert_eq!(CONNECT_ADDRESS.get().unwrap(), connect_address);
        assert_eq!(REMOTE_ADDRESS.get().unwrap(), remote_address);
    }

    #[tokio::test]
    async fn test_send_preamble() {
        let key = "key";
        let remote_address = "remote_address";
        let expected = prepare_preamble(remote_address).unwrap();

        prepare_globals(key, "bind_address", "connect_address", remote_address).unwrap();

        let mut stream = MockStream::new(vec![], vec![]);
        
        send_preamble(&mut stream).await.unwrap();
        
        assert_eq!(stream.write, expected);
    }

    #[tokio::test]
    async fn test_handle_handshake_response() {
        let mut stream = BufReader::new(MockStream::new([Sentinel::HANDSHAKE_COMPLETION, Sentinel::DELIMITER].concat(), vec![]));

        handle_handshake_response(&mut stream).await.unwrap();
    }

    #[tokio::test]
    async fn handle_failed_key_handshake_response() {
        let message = "foo";
        let mut stream = BufReader::new(MockStream::new([Sentinel::ERROR_INVALID_KEY, message.as_bytes(), Sentinel::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid key): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_host_handshake_response() {
        let message = "foo";
        let mut stream = BufReader::new(MockStream::new([Sentinel::ERROR_INVALID_HOST, message.as_bytes(), Sentinel::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), format!("Handshake failed (invalid host): {}", message));
    }

    #[tokio::test]
    async fn handle_failed_unknown_handshake_response() {
        let mut stream = BufReader::new(MockStream::new([&[0x00], Sentinel::DELIMITER].concat(), vec![]));

        let result = handle_handshake_response(&mut stream).await;

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Handshake failed (unknown error)");
    }
}