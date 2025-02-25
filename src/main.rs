#![feature(coverage_attribute)]

use anyhow::Context;
use base::{Err, Void};
use clap::{Parser, Subcommand};
use tracing::{error, info};

pub mod base;
pub mod buffed_stream;
pub mod connect;
pub mod serve;
pub mod utils;

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
        Some(Command::Serve { bind, key, remote_regex, encrypt }) => {
            let pair = match key {
                Some(key) => utils::generate_key_pair_from_key(&key),
                None => utils::generate_key_pair(),
            }
            .context("Failed to generate keypair")?;

            info!("🔑 Private key (for clients): `{}`.", pair.private_key);

            info!("🚀 Starting server on `{}` ...", bind);

            serve::Instance::prepare(pair.public_key, remote_regex, bind, encrypt)?.start().await?;
        }
        Some(Command::Connect { server, tunnel, key, encrypt }) => {
            connect::Instance::prepare(key, server, &tunnel, encrypt)?.start().await?;
        }
        Some(Command::GenerateKeypair) => {
            let pair = utils::generate_key_pair().unwrap();
            info!("📢 Public key: `{}`", pair.public_key);
            info!("🔑 Private key: `{}`", pair.private_key);
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
/// A (likely semi-inefficient) TCP tunneler that uses public/private key authentication without subsequent encryption.
/// Basically, it's `ssh -L`, but without the encryption.  This is useful for tunneling through a machine that doesn't support SSH.
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

        /// Specifies an optional private key to use for generating the keypair.
        ///
        /// Otherwise, a random keypair is generated.
        #[arg(short, long)]
        key: Option<String>,

        /// Specifies an optional regex restriction on the remote hostnames that can be connected to.
        /// This is used to prevent clients from connecting to arbitrary through the server.
        ///
        /// The regex is matched against the entire hostname, so `^` and `$` are not needed.
        #[arg(short, long, default_value = ".*")]
        remote_regex: String,

        /// Specifies whether to encrypt the traffic between the client and server.
        ///
        /// Both the client and server must specify this flag for it to take effect properly.
        #[arg(short, long, default_value_t = false)]
        encrypt: bool,
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

        /// Specifies an optional key to use for authentication from connecting clients.
        ///
        /// The key is hashed with a salt, and thrown away, but otherwise is merely checked at connection time.
        /// The key is not used for encryption.
        #[arg(short, long, default_value = "")]
        key: String,

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
    GenerateKeypair,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        base::Base64KeyPair,
        utils::{generate_key_pair, tests::EchoServer},
    };

    use super::*;
    use pretty_assertions::assert_eq;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    async fn bootstrap_e2e(public_key: String, private_key: String, remote_regex: String, port: u16, should_encrypt: bool) -> String {
        let remote_address = format!("127.0.0.1:{}", port);
        let server_address = format!("127.0.0.1:{}", port + 1);
        let client_tunnels = [format!("{}:{}", port + 2, port)];
        let client_address = format!("127.0.0.1:{}", port + 2);

        // Start a "remote" echo server.
        tokio::spawn(EchoServer::start(remote_address));

        // Start a "server".
        tokio::spawn(serve::Instance::prepare(public_key, remote_regex, server_address.clone(), should_encrypt).unwrap().start());

        // Start a "client".
        tokio::spawn(connect::Instance::prepare(private_key, server_address, &client_tunnels, should_encrypt).unwrap().start());

        // Give a moment for the server to start.

        tokio::time::sleep(Duration::from_millis(100)).await;

        client_address
    }

    #[test]
    fn test_args() {
        let args = Args::parse_from(["", "serve", "127.0.0.1:3000", "--key", "key", "--remote-regex", ".*", "-e"]);

        assert_eq!(
            args.command,
            Some(Command::Serve {
                bind: "127.0.0.1:3000".to_string(),
                key: Some("key".to_string()),
                remote_regex: ".*".to_string(),
                encrypt: true
            })
        );

        let args = Args::parse_from(["", "connect", "127.0.0.1:3000", "3000:127.0.0.1:3000", "4000", "--key", "key"]);

        assert_eq!(
            args.command,
            Some(Command::Connect {
                server: "127.0.0.1:3000".to_string(),
                tunnel: vec!["3000:127.0.0.1:3000".to_string(), "4000".to_string()],
                key: "key".to_string(),
                encrypt: false
            })
        );
    }

    #[tokio::test]
    async fn test_e2e() {
        let remote_regex = ".*".to_string();
        let port = 3000;

        let Base64KeyPair { public_key, private_key } = generate_key_pair().unwrap();
        let client_address = bootstrap_e2e(public_key, private_key, remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_address).await.unwrap();

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

        let Base64KeyPair { public_key, private_key } = generate_key_pair().unwrap();
        let client_address = bootstrap_e2e(public_key, private_key, remote_regex, port, true).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_address).await.unwrap();

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
    async fn test_e2e_bad_key() {
        let remote_regex = ".*".to_string();
        let port = 3200;

        let Base64KeyPair { public_key, .. } = generate_key_pair().unwrap();
        let Base64KeyPair { private_key, .. } = generate_key_pair().unwrap();
        let client_address = bootstrap_e2e(public_key, private_key, remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_address).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        let result = client.read_exact(&mut buffer).await;

        // intermediary disconnected because the key is bad.
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_e2e_bad_host() {
        let remote_regex = "not_127.0.0.1".to_string();
        let port = 3300;

        let Base64KeyPair { public_key, private_key } = generate_key_pair().unwrap();
        let client_address = bootstrap_e2e(public_key, private_key, remote_regex, port, false).await;

        // Open a client connection.

        let mut client = TcpStream::connect(&client_address).await.unwrap();

        // Send a message to the server.
        let message = b"Hello, world!";
        client.write_all(message).await.unwrap();
        client.flush().await.unwrap();

        // Read the message back from the server.
        let mut buffer = vec![0; message.len()];
        let result = client.read_exact(&mut buffer).await;

        // intermediary disconnected because the host is bad.
        assert!(result.is_err());
    }
}
