[![Build and Test](https://github.com/twitchax/ratrod/actions/workflows/build.yml/badge.svg)](https://github.com/twitchax/ratrod/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/twitchax/ratrod/branch/main/graph/badge.svg?token=35MZN0YFZF)](https://codecov.io/gh/twitchax/ratrod)
[![Version](https://img.shields.io/crates/v/ratrod.svg)](https://crates.io/crates/ratrod)
[![Crates.io](https://img.shields.io/crates/d/ratrod?label=crate)](https://crates.io/crates/ratrod)
[![GitHub all releases](https://img.shields.io/github/downloads/twitchax/ratrod/total?label=binary)](https://github.com/twitchax/ratrod/releases)
[![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# ratrod

A TCP tunneler that uses public / private key authentication with encryption.  Basically, it's `ssh -L`.  This is useful for tunneling through a machine that doesn't support SSH.

## Usage

```bash
$ ratrod -h
Tunnels a local port to a remote server, which then redirects traffic to a specified remote host.

Usage: ratrod [OPTIONS] [COMMAND]

Commands:
  serve             Start a server on this machine that listens for incoming connections and forwards them to a remote server (as specified by the client)
  connect           Connects to a server and forwards traffic from a local port to a remote `host:port` "through" the server
  generate-keypair  Generates a keypair and prints it to the console
  help              Print this message or the help of the given subcommand(s)

Options:
  -v, --verbose  Flag that specifies verbose logging
  -h, --help     Print help
  -V, --version  Print version
```

Below illustrates a common flow.

### Generate Keypair

On the client, generate a keypair.  Really, this can be done from anywhere, but the "safest" method would be to generate the keypair on the client.

```bash
$ ratrod generate-keypair -h
Generates a keypair and prints it to the console

Usage: ratrod generate-keypair [OPTIONS]

Options:
  -p, --print                Specifies that the keypair should be printed to stdout
  -l, --location <LOCATION>  Specifies the location to write the keypair to (the default is `$HOME/.ratrod`)
  -f, --filename <FILENAME>  Indicates the filename to write the keypair to (the default is `key`) [default: key]
  -h, --help                 Print help (see more with '--help')
```

Then, the easiest option is to just use the default location and filename.

```bash
$ ratrod generate-keypair
2025-02-28T07:36:09.213051Z  INFO 📦 Keypair written to `/home/user/.ratrod/key`
```

This will also write `key.pub` to the same location.

```bash
$ cat ~/.ratrod/key.pub
HQYY0BNIhdawY2Jw62DudkUsK2GKj3hGO3qSVBlCinI
```

Then, via whatever means you prefer, copy the public key to the server at the most convenient location (`$HOME/.ratrod/key.pub` is the default).

### Start a Server

```bash
$ ratrod serve -h
Start a server on this machine that listens for incoming connections and forwards them to a remote server (as specified by the client)

Usage: ratrod serve [OPTIONS] <BIND>

Arguments:
  <BIND>  Specifies the local `host:port` to bind to

Options:
  -k, --key <KEY>                    Specifies a public key to use for authentication from connecting clients.  This can be either a base64-encoded keyfile, or a base64-encoded key
  -r, --remote-regex <REMOTE_REGEX>  Specifies an optional regex restriction on the remote hostnames that can be connected to. This is used to prevent clients from connecting to arbitrary through the server [default: .*]
  -h, --help                         Print help (see more with '--help')
```

Basic usage pulls the key from the default location (`$HOME/.ratrod/key.pub`).

```bash
$ ratrod serve 0.0.0.0:19000
2025-02-28T07:39:04.925015Z  INFO 🚀 Starting server on `0.0.0.0:19000` ...
```

Otherwise, you can specify the public key with the `--key` (`-k`) flag.

```bash
$ ratrod serve -k HQYY0BNIhdawY2Jw62DudkUsK2GKj3hGO3qSVBlCinI 0.0.0.0:19000
```

Or, pass the keyfile.

```bash
$ ratrod serve -k ~/.ratrod/key.pub 0.0.0.0:19000
```

### Connect to a Server

```bash
$ ratrod connect -h
Connects to a server and forwards traffic from a local port to a remote `host:port` "through" the server

Usage: ratrod connect [OPTIONS] <SERVER> [TUNNEL]...

Arguments:
  <SERVER>     Specifies the server's `host:port` to connect to
  [TUNNEL]...  Specifies the remote(s) (e.g., `client_port:host:remote_port`) that the client wishes the server to route the traffic to

Options:
  -k, --key <KEY>  Specifies a private key to use for authentication from connecting clients.  This can be either a base64-encoded keyfile, or a base64-encoded key
  -e, --encrypt    Specifies whether to encrypt the traffic between the client and server
  -h, --help       Print help (see more with '--help')
```

Usage is as simple as (assuming you're using the default keyfile location):

```bash
$ ratrod connect 192.168.1.100:19000 2000:google.com:80
2025-02-28T07:44:01.795619Z  INFO ⏳ Testing server connection ...
2025-02-28T07:44:01.795650Z  INFO 📻 Listening on `127.0.0.1:2000`, and routing through `192.168.229.100:19000` to `google.com:80` ...
2025-02-28T07:44:01.795799Z  INFO ✅ Connected to server `192.168.229.100:19000` ...
2025-02-28T07:44:01.795938Z  INFO ✅ Sent preamble to server ...
2025-02-28T07:44:01.796165Z  INFO 🚧 Handshake challenge received ...
2025-02-28T07:44:01.796294Z  INFO ⏳ Awaiting challenge validation ...
2025-02-28T07:44:01.796596Z  INFO ✅ Challenge accepted!
2025-02-28T07:44:01.796609Z  INFO ✅ Test connection successful!
```

If you want to use encryption, you can specify the `--encrypt` (`-e`) flag.

```bash
$ ratrod connect -e 192.168.1.100:19000 2000:google.com:80
```

The client and server will each generate an ephemeral keypair for each connection, and they will generate a shared secret using the
[Diffie-Hellman key exchange algorithm](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/).
The shared secret is used to encrypt the traffic between the client and server after the handshake (handshake is plaintext).

### Tunnel Format

The `host` argument accepts the form `[local_host:[local_port:[remote_host:]]]remote_port`.  This means you could have various scenarios like this:
- `0.0.0.0:2000:google.com:80`: connects to `google.com:80` and listens on `0.0.0.0:2000`.
- `2000:google.com:80`: connects to `google.com:80` and listens on `127.0.0.1:2000`.
- `2000:80`: connects to `server:80` and listens on `127.0.0.1:2000`.
- `80`: connects to `server:80` and listens on `127.0.0.1:80`.

## Install

Windows:

```powershell
$ iwr https://github.com/twitchax/ratrod/releases/latest/download/ratrod_x86_64-pc-windows-gnu.zip
$ Expand-Archive ratrod_x86_64-pc-windows-gnu.zip -DestinationPath C:\Users\%USERNAME%\AppData\Local\Programs\ratrod
```

Mac OS (Apple Silicon):

```bash
$ curl -LO https://github.com/twitchax/ratrod/releases/latest/download/ratrod_aarch64-apple-darwin.zip
$ unzip ratrod_aarch64-apple-darwin.zip -d /usr/local/bin
$ chmod a+x /usr/local/bin/ratrod
```

Linux:

```bash
$ curl -LO https://github.com/twitchax/ratrod/releases/latest/downloadratrod_x86_64-unknown-linux-gnu.zip
$ unzip ratrod_x86_64-unknown-linux-gnu.zip -d /usr/local/bin
$ chmod a+x /usr/local/bin/ratrod
```

Cargo:

```bash
$ cargo install ratrod
```

## Testing

```bash
$ cargo nextest run
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.