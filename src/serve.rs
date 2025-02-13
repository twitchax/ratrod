use std::{borrow::Cow, sync::OnceLock};

use anyhow::Context;
use regex::Regex;
use tokio::{io::{AsyncRead, AsyncWriteExt}, net::{TcpListener, TcpStream}};
use tracing::{error, info, info_span};

use crate::{base::{Err, Preamble, Res, Sentinel}, utils::{hash_key, process_preamble, random_string, verify_key}};

static KEY_SALT: OnceLock<String> = OnceLock::new();
static KEY_HASH: OnceLock<String> = OnceLock::new();
static HOST_REGEX: OnceLock<Regex> = OnceLock::new();

pub async fn start(bind: String, key: String, host_regex: String) -> Res<()> {
    // Prepare the globals.

    prepare_globals(key, host_regex)?;

    // Finally, start the server.

    run_tcp_server(bind).await?;

    Ok(())
}

fn prepare_globals<'a, 'b>(key: impl Into<Cow<'a, str>>, host_regex: impl Into<Cow<'b, str>>) -> Res<()> {
    // First, make sure the key salt and hash are set.

    let salt = random_string(30);
    KEY_SALT.get_or_init(|| salt );

    // Next make sure the key hash is set.

    let hash = hash_key(key.into().as_ref(), KEY_SALT.get().unwrap());
    KEY_HASH.get_or_init(|| hash );

    // Next, make sure the host regex is set.

    let host_regex = Regex::new(host_regex.into().as_ref()).context("Unable to parse the supplied `host_regex`")?;
    HOST_REGEX.get_or_init(|| host_regex );

    Ok(())
}

async fn run_tcp_server(bind: String) -> Res<()> {
    let listener = TcpListener::bind(bind).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket));
    }
}

async fn handle_tcp(mut client: TcpStream) {
    let id = random_string(6);
    let span = info_span!("handle", id = id);
    let _span_guard = span.enter();

    let Ok(peer_addr) = client.peer_addr() else {
        error!("Unable to get peer address.");
        return;
    };

    info!("✔️ Accepted connection from `{}`.", peer_addr);

    // Handle the preamble.
    
    let preamble = match handle_preamble(&mut client).await {
        Ok(preamble) => preamble,
        Err(err) => {
            let chain = err.chain().collect::<Vec<_>>();
            let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");

            error!("Error handling connection: {}.", full_chain);

            return;
        }
    };

    // Connect to remote.
    
    let remote = match TcpStream::connect(&preamble.host).await {
        Ok(remote) => remote,
        Err(err) => {
            let message = format!("Error connecting to remote server `{}`: `{}`.", preamble.host, err);
            error!("{}", message);
            return;
        }
    };

    info!("✔️ Connected to remote server `{}`.", preamble.host);

    // Handle the TCP pump.

    match handle_tcp_pump(client, remote).await {
        Ok(_) => info!("✔️ Connection closed."),
        Err(err) => {
            let chain = err.chain().collect::<Vec<_>>();
            let full_chain = chain.iter().map(|e| format!("`{}`", e)).collect::<Vec<_>>().join(" => ");

            error!("Error handling the pump: `{}`.", full_chain);
        }
    };
}

async fn handle_tcp_pump(client: TcpStream, remote: TcpStream) -> Res<()> {
    let (mut remote_reader, mut remote_writer) = remote.into_split();
    let (mut socket_reader, mut socket_writer) = client.into_split();
    let (up_result, down_result) = tokio::join!(
        tokio::io::copy(&mut socket_reader, &mut remote_writer),
        tokio::io::copy(&mut remote_reader, &mut socket_writer)
    );

    if let Err(err) = up_result {
        let message = format!("Error forwarding data from socket to remote: `{}`", err);
        return Err(Err::msg(message));
    }

    if let Err(err) = down_result {
        let message = format!("Error forwarding data from remote to socket: `{}`", err);
        return Err(Err::msg(message));
    }

    Ok(())
}

async fn handle_preamble<T>(socket: &mut T) -> Res<Preamble>
where 
    T: AsyncRead + AsyncWriteExt + Unpin,
{
    // Get the preamble.

    let preamble = process_preamble(socket).await?;

    // Check the key.

    if !verify_key(&preamble.key, KEY_SALT.get().unwrap(), KEY_HASH.get().unwrap()) {
        // Attempt to let the client know that the key is invalid.
        let message = format!("Invalid key from client (supplied `{}`)", preamble.key);
        let _ = socket.write_all(Sentinel::ERROR_INVALID_KEY).await;
        let _ = socket.write_all(message.as_bytes()).await;
        let _ = socket.shutdown().await;

        return Err(Err::msg(message));
    }

    // Check the host.

    if !HOST_REGEX.get().unwrap().is_match(&preamble.host) {
        // Attempt to let the client know that the host is invalid.
        let message = format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.host, HOST_REGEX.get().unwrap());
        let _ = socket.write_all(Sentinel::ERROR_INVALID_HOST).await;
        let _ = socket.write_all(message.as_bytes()).await;
        let _ = socket.shutdown().await;

        return Err(Err::msg(message));
    }

    // Let the client know that the connection is established.

    socket.write_all(Sentinel::PREAMBLE_COMPLETION).await?;
    info!("✔️ Preamble completion sent to client.");

    Ok(preamble)
}

#[cfg(test)]
mod tests {
    use std::{io, pin::Pin, task::Poll};
    use core::task::Context;

    use tokio::io::{AsyncWrite, ReadBuf};

    use crate::utils::prepare_preamble;

    use super::*;
    
    struct MockStream {
        pub read: Vec<u8>,
        pub write: Vec<u8>,
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let slice = std::pin::pin!(self.get_mut().read.as_slice());
            
            slice.poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_write(cx, buf) }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_flush(cx) }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            unsafe { self.map_unchecked_mut(|s| &mut s.write).poll_shutdown(cx) }
        }
    }

    #[test]
    fn test_can_set_host_regex() {
        prepare_globals("", ".*").unwrap();
    }

    #[test]
    fn test_can_hash_key() {
        prepare_globals("test_key", ".*").unwrap();
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {
        assert!(prepare_globals("test_key", "[a-z").is_err());
    }

    #[tokio::test]
    async fn test_can_handle_generic_preamble() {
        let key = "test_key";
        let host = "test_host";

        let client_to_server = prepare_preamble(key, host).await.unwrap();

        let mut stream = MockStream {
            read: client_to_server,
            write: Vec::new(),
        };

        prepare_globals(key.to_string(), ".*").unwrap();
        let preamble = handle_preamble(&mut stream).await.unwrap();

        assert_eq!(preamble.key, key);
        assert_eq!(preamble.host, host);

        assert_eq!(stream.write, Sentinel::PREAMBLE_COMPLETION);
    }
}