//! Ratrod
//!
//! A TCP tunneler that uses public / private key authentication with encryption.
//! Basically, it's `ssh -L`.  This is useful for tunneling through a machine that doesn't support SSH.

#![feature(coverage_attribute)]
#![feature(const_type_name)]

use clap::{Parser, Subcommand};
use ratrodlib::security::generate;
use ratrodlib::{
    base::{Err, Void},
    security::resolve_keypath,
};
use tracing::error;

#[coverage(off)]
#[tokio::main]
async fn main() {
    let args = Args::parse();

    let level = if args.verbose { tracing::Level::DEBUG } else { tracing::Level::INFO };

    tracing_subscriber::fmt()
        .with_ansi(true)
        .with_level(true)
        .with_file(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_max_level(level)
        .init();

    let result = execute_command(args.command).await;

    if let Err(err) = result {
        error!("❌ {}", err);
        std::process::exit(1);
    }
}

async fn execute_command(command: Option<Command>) -> Void {
    match command {
        Some(Command::Serve { bind, key_path, remote_regex }) => {
            ratrodlib::serve::Instance::prepare(key_path, remote_regex, bind)?.start().await?;
        }
        Some(Command::Connect { server, tunnel, key_path, encrypt }) => {
            ratrodlib::connect::Instance::prepare(key_path, server, &tunnel, encrypt)?.start().await?;
        }
        Some(Command::GenerateKeypair { output, path }) => {
            let key_path = resolve_keypath(path)?;
            generate(output, key_path)?;
        }
        None => {
            return Err(Err::msg("No command specified."));
        }
    };

    Ok(())
}

/// Tunnels a local port to a remote server, which then redirects
/// traffic to a specified remote host.
///
/// A TCP tunneler that uses public / private key authentication with encryption.
/// Basically, it's `ssh -L`.  This is useful for tunneling through a machine that doesn't support SSH.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Flag that specifies verbose logging.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand, PartialEq, Debug)]
enum Command {
    /// Start a server on this machine that listens for incoming
    /// connections and forwards them to a remote server (as
    /// specified by the client).
    Serve {
        /// Specifies the local `host:port` to bind to.
        ///
        /// E.g., you may want to bind to `0.0.0.0:3000` to
        /// listen for connections from other machines on any interface,
        /// or `192.168.1.100:3000` to listen for connections from other
        /// machines on a specific interface.
        bind: String,

        /// Specifies the path to the key store (`key`, `key.pub`, `authorized_keys`).
        ///
        /// The default value is read from `$HOME/.ratrod`.
        #[arg(short, long)]
        key_path: Option<String>,

        /// Specifies an optional regex restriction on the remote hostnames that can be connected to.
        /// This is used to prevent clients from connecting to arbitrary through the server.
        ///
        /// The regex is matched against the entire hostname, so `^` and `$` are not needed.
        #[arg(short, long, default_value = ".*")]
        remote_regex: String,
    },

    /// Connects to a server and forwards traffic from a local port to a remote `host:port`
    /// "through" the server.
    Connect {
        /// Specifies the server's `host:port` to connect to.
        ///
        /// This is the destination of the server, and is not
        /// the "routing destination" of the traffic.
        ///
        /// This would usually take the form of the server's address, e.g., `192.168.1.100:3000`
        server: String,

        /// Specifies the remote(s) (e.g., `client_port:host:remote_port`) that the client wishes the server to route
        /// the traffic to.
        ///
        /// This is the destination of the traffic, and is not
        /// necessarily the same as the server's `host:port`.
        ///
        /// This can also be reduced to `client_port:remote_port` if the client wishes to connect to the server's
        /// own port.  Or, if the client wishes to connect to the server's same port,
        /// it can be reduced to `remote_port`.
        ///
        /// Some examples:
        /// - `3000:127.0.0.1:3000`: Requests to the client port 3000 route to `127.0.0.1:3000` on the server (
        ///   same as `3000:3000` or `3000`).
        /// - `3000:127.0.0.1:80`: - Requests to the client port 3000 route to `127.0.0.1:80` on the server (
        ///   same as `3000:80`).
        /// - `3000:example.com:80`: - Requests to the client port 3000 route to `example.com:80` on the server.
        ///   This is for use cases where the client can contact the server, but not the remote host, so the server
        ///   must act as a TCP proxy.
        tunnel: Vec<String>,

        /// Specifies a private key to use for authentication from connecting clients.  This can be either
        /// a base64-encoded keyfile, or a base64-encoded key.
        ///
        /// The key is checked at connection time.
        /// The key is not used for encryption.  The default value is read from `$HOME/.ratrod/key`.
        #[arg(short, long)]
        key_path: Option<String>,

        /// Specifies whether to encrypt the traffic between the client and server.
        ///
        /// Both the client and server must specify this flag for it to take effect properly.
        #[arg(short, long, default_value_t = false)]
        encrypt: bool,
    },

    /// Generates a keypair and prints it to the console.
    ///
    /// This allows the user to easily get a keypair for use
    /// with the `serve` command, if they are looking for a
    /// stable keypair.
    GenerateKeypair {
        /// Specifies that the keypair should be printed to stdout.
        #[arg(short, long)]
        output: bool,

        /// Specifies the location to write the keypair to (the default is `$HOME/.ratrod`).
        #[arg(short, long)]
        path: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    pub struct EchoServer;

    impl EchoServer {
        pub async fn start(bind_address: String) -> Void {
            let listener = TcpListener::bind(bind_address).await?;

            loop {
                let (client, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let (mut read, mut write) = client.into_split();

                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        }
    }

    async fn bootstrap_e2e(server_key_path: String, client_key_path: String, remote_regex: String, port: u16, should_encrypt: bool) -> [String; 2] {
        let remote_address = format!("127.0.0.1:{}", port);
        let server_address = format!("127.0.0.1:{}", port + 1);
        let client_tunnels = [format!("{}:{}", port + 2, port), format!("{}:{}", port + 3, port)];
        let client_addresses = [format!("127.0.0.1:{}", port + 2), format!("127.0.0.1:{}", port + 3)];

        // Start a "remote" echo server.
        tokio::spawn(EchoServer::start(remote_address));

        // Start a "server".
        tokio::spawn(ratrodlib::serve::Instance::prepare(server_key_path, remote_regex, server_address.clone()).unwrap().start());

        // Start a "client".
        tokio::spawn(ratrodlib::connect::Instance::prepare(client_key_path, server_address, &client_tunnels, should_encrypt).unwrap().start());

        // Do a "healthcheck" to ensure that the server is up and running.

        while TcpStream::connect(&client_addresses[0]).await.is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        client_addresses
    }

    #[test]
    fn test_args() {
        let args = Args::parse_from(["", "serve", "127.0.0.1:3000", "--key-path", "key", "--remote-regex", ".*"]);

        assert_eq!(
            args.command,
            Some(Command::Serve {
                bind: "127.0.0.1:3000".to_string(),
                key_path: Some("key".to_string()),
                remote_regex: ".*".to_string(),
            })
        );

        let args = Args::parse_from(["", "connect", "127.0.0.1:3000", "3000:127.0.0.1:3000", "4000", "--key-path", "key", "-e"]);

        assert_eq!(
            args.command,
            Some(Command::Connect {
                server: "127.0.0.1:3000".to_string(),
                tunnel: vec!["3000:127.0.0.1:3000".to_string(), "4000".to_string()],
                key_path: Some("key".to_string()),
                encrypt: true
            })
        );
    }

    #[tokio::test]
    async fn test_e2e() {
        let remote_regex = ".*".to_string();
        let port = 3000;

        let client_addresses = bootstrap_e2e("./test/server".to_owned(), "./test/client".to_owned(), remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_addresses[0]).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        client.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, message);

        // Close the client connection.
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_e2e_encrypt() {
        let remote_regex = ".*".to_string();
        let port = 3100;

        let client_addresses = bootstrap_e2e("./test/server".to_owned(), "./test/client".to_owned(), remote_regex, port, true).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_addresses[1]).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        client.read_exact(&mut buffer).await.unwrap();

        assert_eq!(buffer, message);

        // Close the client connection.
        client.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_e2e_bad_client_key() {
        let remote_regex = ".*".to_string();
        let port = 3200;

        let client_addresses = bootstrap_e2e("./test/server".to_owned(), "./test/bad".to_owned(), remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_addresses[0]).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        let result = client.read_exact(&mut buffer).await;

        // intermediary disconnected because the key is bad.
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Connection reset by peer (os error 104)");
    }

    #[tokio::test]
    async fn test_e2e_bad_server_key() {
        let remote_regex = ".*".to_string();
        let port = 3300;

        let client_addresses = bootstrap_e2e("./test/bad".to_owned(), "./test/client".to_owned(), remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_addresses[0]).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        let result = client.read_exact(&mut buffer).await;

        // intermediary disconnected because the key is bad.
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Connection reset by peer (os error 104)");
    }

    #[tokio::test]
    async fn test_e2e_bad_host() {
        let remote_regex = "not_127.0.0.1".to_string();
        let port = 3300;

        let client_addresses = bootstrap_e2e("./test/server".to_owned(), "./test/client".to_owned(), remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_addresses[0]).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        let result = client.read_exact(&mut buffer).await;

        // intermediary disconnected because the host is bad.
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Connection reset by peer (os error 104)");
    }
}
