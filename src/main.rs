use clap::{Parser, Subcommand};
use tracing::{error, info};
use base::Err;

pub mod base;
pub mod utils;
pub mod serve;
pub mod connect;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::fmt()
        //.pretty()
        .with_ansi(true)
        .with_level(true)
        .with_file(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_thread_names(false)
        .init();

    let result = match args.command {
        Some(Command::Serve { bind, key, host_regex }) => {
            info!("Starting server on `{}` ...", bind);

            serve::start(bind, key, host_regex).await
        }
        Some(Command::Connect { server, remote, key }) => {
            info!("Connecting to server `{}` ...", server);

            connect::start(server, remote, key).await
        }
        None => {
            Err(Err::msg("No command specified."))
        }
    };

    if let Err(err) = result {
        error!("{}", err);
        std::process::exit(1);
    }
}

/// Tunnels a local port to a remote server, which then redirects the
/// traffic to the same port on the server.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
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

        /// Specifies an optional key to use for authentication from connecting clients.
        /// 
        /// The key is hashed with a salt, and thrown away, but otherwise is merely checked at connection time.
        /// The key is not used for encryption.
        #[arg(short, long, default_value = "")]
        key: String,

        /// Specifies an optional regex restriction on the remote hostnames that can be connected to.
        /// This is used to prevent clients from connecting to arbitrary through the server.
        /// 
        /// The regex is matched against the entire hostname, so `^` and `$` are not needed.
        #[arg(short = 'r', long, default_value = ".*")]
        host_regex: String,
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

        /// Specifies the remote `client_port:host:remote_port` that the client wishes the server to route
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
        /// - `3000:localhost:3000`: Requests to the client port 3000 route to `localhost:3000` on the server (
        ///   same as `3000:3000` or `3000`).
        /// - `3000:localhost:80`: - Requests to the client port 3000 route to `localhost:80` on the server (
        ///   same as `3000:80`).
        /// - `3000:example.com:80`: - Requests to the client port 3000 route to `example.com:80` on the server.
        ///   This is for use cases where the client can contact the server, but not the remote host, so the server
        ///   must act as a TCP proxy.
        remote: String,

        /// Specifies an optional key to use for authentication from connecting clients.
        /// 
        /// The key is hashed with a salt, and thrown away, but otherwise is merely checked at connection time.
        /// The key is not used for encryption.
        #[arg(short, long, default_value = "")]
        key: String,
    },
}