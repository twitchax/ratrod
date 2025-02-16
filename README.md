[![Build and Test](https://github.com/twitchax/ratrod/actions/workflows/build.yml/badge.svg)](https://github.com/twitchax/ratrod/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/twitchax/ratrod/branch/main/graph/badge.svg?token=35MZN0YFZF)](https://codecov.io/gh/twitchax/ratrod)
[![Version](https://img.shields.io/crates/v/ratrod.svg)](https://crates.io/crates/ratrod)
[![Crates.io](https://img.shields.io/crates/d/ratrod?label=crate)](https://crates.io/crates/ratrod)
[![GitHub all releases](https://img.shields.io/github/downloads/twitchax/ratrod/total?label=binary)](https://github.com/twitchax/ratrod/releases)
[![Documentation](https://docs.rs/ratrod/badge.svg)](https://docs.rs/ratrod)
[![Rust](https://img.shields.io/crates/msrv/ratrod)](https://github.com/twitchax/ratrod)
[![License:MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# ratrod

A (likely semi-inefficient) TCP tunneler that uses public/private key authentication without subsequent encryption.  Basically, it's `ssh -L`, but without the encryption.  This is useful for tunneling through a machine that doesn't support SSH.

## Basic Usage

### Usage

```bash
$ ratrod -h
Tunnels a local port to a remote server, which then redirects the traffic to a specified remote host

Usage: ratrod [COMMAND]

Commands:
  serve             Start a server on this machine that listens for incoming connections and forwards them to a remote server (as specified by the client)
  connect           Connects to a server and forwards traffic from a local port to a remote `host:port` "through" the server
  generate-keypair  Generates a keypair and prints it to the console
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

#### Generate Keypair

```bash
$ ratrod generate-keypair -h
Generates a keypair and prints it to the console

Usage: ratrod generate-keypair

Options:
  -h, --help  Print help (see more with '--help')
```

```bash
$ ratrod generate-keypair
2025-02-16T21:46:14.114260Z  INFO 📢 Public key: `kRIPwCb48iyW6F_48GA2GX_7iIXaDSzN1xrZpxJVrR4`
2025-02-16T21:46:14.114288Z  INFO 🔑 Private key: `MFECAQEwBQYDK2VwBCIEIC0eDq_DR7flRXszmG_4USM6f4hM12TjAxLbJotjP-OzgSEAkRIPwCb48iyW6F_48GA2GX_7iIXaDSzN1xrZpxJVrR4`
```

#### Start a Server

```bash
$ ratrod serve -h
Start a server on this machine that listens for incoming connections and forwards them to a remote server (as specified by the client)

Usage: ratrod serve [OPTIONS] <BIND>

Arguments:
  <BIND>  Specifies the local `host:port` to bind to

Options:
  -k, --key <KEY>                    Specifies an optional private key to use for generating the keypair
  -r, --remote-regex <REMOTE_REGEX>  Specifies an optional regex restriction on the remote hostnames that can be connected to. This is used to prevent clients from connecting to arbitrary through the server [default: .*]
  -h, --help                         Print help (see more with '--help')
```

Basic usage generates a random private key, which printed to the console for the user to give to clients.

```bash
$ ratrod serve 0.0.0.0:19000
2025-02-16T21:46:54.989623Z  INFO 🔑 Private key (for clients): `MFECAQEwBQYDK2VwBCIEILrnsOXw6V5tYH7Svvxxtrhjn8DojNSomOtCDARkokDGgSEAwIB407MrQdO3iGRFn7pGjJDnJKPFXCnGFelX1OJa0oc`.
2025-02-16T21:46:54.989651Z  INFO 🚀 Starting server on `[::]:19000` ...
```

If you have a generated keypair, you can specify the private key with the `--key` (`-k`) flag.

```bash
$ ratrod serve -k MFECAQEwBQYDK2VwBCIEIC0eDq_DR7flRXszmG_4USM6f4hM12TjAxLbJotjP-OzgSEAkRIPwCb48iyW6F_48GA2GX_7iIXaDSzN1xrZpxJVrR4 [::]:19000
2025-02-16T23:06:23.204880Z  INFO 🔑 Private key (for clients): `MFECAQEwBQYDK2VwBCIEIC0eDq_DR7flRXszmG_4USM6f4hM12TjAxLbJotjP-OzgSEAkRIPwCb48iyW6F_48GA2GX_7iIXaDSzN1xrZpxJVrR4`.
2025-02-16T23:06:23.204911Z  INFO 🚀 Starting server on `[::]:19000` ...
2025-02-16T23:06:28.764912Z  INFO conn{id="BPxETR"}: ✅ Accepted connection from `[::ffff:127.0.0.1]:48720`.
2025-02-16T23:06:28.765303Z  INFO conn{id="BPxETR"}: 🚧 Sending handshake challenge to client ...
2025-02-16T23:06:28.766762Z  INFO conn{id="BPxETR"}: ✅ Handshake challenge completed!
2025-02-16T23:06:28.766838Z  INFO conn{id="BPxETR"}: ✅ Handshake completed.
2025-02-16T23:06:28.801000Z  INFO conn{id="BPxETR"}: ✅ Connected to remote server `google.com:80`.
2025-02-16T23:06:28.801077Z  INFO conn{id="BPxETR"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:06:28.916065Z  INFO conn{id="BPxETR"}: ✅ Connection closed.
2025-02-16T23:06:42.180789Z  INFO conn{id="nyulYr"}: ✅ Accepted connection from `[::ffff:127.0.0.1]:53786`.
2025-02-16T23:06:42.181316Z  INFO conn{id="nyulYr"}: 🚧 Sending handshake challenge to client ...
2025-02-16T23:06:42.183300Z  INFO conn{id="nyulYr"}: ✅ Handshake challenge completed!
2025-02-16T23:06:42.183360Z  INFO conn{id="nyulYr"}: ✅ Handshake completed.
2025-02-16T23:06:42.200463Z  INFO conn{id="nyulYr"}: ✅ Connected to remote server `google.com:80`.
2025-02-16T23:06:42.200516Z  INFO conn{id="nyulYr"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:06:42.367411Z  INFO conn{id="nyulYr"}: ✅ Connection closed.
2025-02-16T23:06:42.792522Z  INFO conn{id="Zht5ma"}: ✅ Accepted connection from `[::ffff:127.0.0.1]:53790`.
2025-02-16T23:06:42.792788Z  INFO conn{id="Zht5ma"}: 🚧 Sending handshake challenge to client ...
2025-02-16T23:06:42.794003Z  INFO conn{id="Zht5ma"}: ✅ Handshake challenge completed!
2025-02-16T23:06:42.794052Z  INFO conn{id="Zht5ma"}: ✅ Handshake completed.
2025-02-16T23:06:42.806509Z  INFO conn{id="Zht5ma"}: ✅ Connected to remote server `google.com:80`.
2025-02-16T23:06:42.806561Z  INFO conn{id="Zht5ma"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:06:42.973926Z  INFO conn{id="Zht5ma"}: ✅ Connection closed.
```

#### Connect to a Server

```bash
$ ratrod connect -k MFECAQEwBQYDK2VwBCIEIC0eDq_DR7flRXszmG_4USM6f4hM12TjAxLbJotjP-OzgSEAkRIPwCb48iyW6F_48GA2GX_7iIXaDSzN1xrZpxJVrR4 192.168.1.100:19000 2000:google.com:80
2025-02-16T23:08:37.303408Z  INFO 📻 Listening on `localhost:2000`, and routing through `localhost:19000` to `google.com:80` ...
2025-02-16T23:08:39.812532Z  INFO conn{id="Be8spx"}: ✅ Connected to server `localhost:19000` ...
2025-02-16T23:08:39.812662Z  INFO conn{id="Be8spx"}: ✅ Sent preamble to server ...
2025-02-16T23:08:39.813250Z  INFO conn{id="Be8spx"}: 🚧 Handshake challenge received ...
2025-02-16T23:08:39.813810Z  INFO conn{id="Be8spx"}: ⏳ Awaiting challenge validation ...
2025-02-16T23:08:39.815189Z  INFO conn{id="Be8spx"}: ✅ Challenge accepted ...
2025-02-16T23:08:39.815217Z  INFO conn{id="Be8spx"}: ✅ Handshake successful: connection established!
2025-02-16T23:08:39.815230Z  INFO conn{id="Be8spx"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:08:40.000492Z  INFO conn{id="Be8spx"}: ✅ Connection closed.
2025-02-16T23:08:40.948126Z  INFO conn{id="jWLwHH"}: ✅ Connected to server `localhost:19000` ...
2025-02-16T23:08:40.948305Z  INFO conn{id="jWLwHH"}: ✅ Sent preamble to server ...
2025-02-16T23:08:40.949282Z  INFO conn{id="jWLwHH"}: 🚧 Handshake challenge received ...
2025-02-16T23:08:40.950223Z  INFO conn{id="jWLwHH"}: ⏳ Awaiting challenge validation ...
2025-02-16T23:08:40.951574Z  INFO conn{id="jWLwHH"}: ✅ Challenge accepted ...
2025-02-16T23:08:40.951625Z  INFO conn{id="jWLwHH"}: ✅ Handshake successful: connection established!
2025-02-16T23:08:40.951650Z  INFO conn{id="jWLwHH"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:08:41.126602Z  INFO conn{id="jWLwHH"}: ✅ Connection closed.
2025-02-16T23:08:41.813399Z  INFO conn{id="fPku4k"}: ✅ Connected to server `localhost:19000` ...
2025-02-16T23:08:41.813513Z  INFO conn{id="fPku4k"}: ✅ Sent preamble to server ...
2025-02-16T23:08:41.814171Z  INFO conn{id="fPku4k"}: 🚧 Handshake challenge received ...
2025-02-16T23:08:41.815062Z  INFO conn{id="fPku4k"}: ⏳ Awaiting challenge validation ...
2025-02-16T23:08:41.816399Z  INFO conn{id="fPku4k"}: ✅ Challenge accepted ...
2025-02-16T23:08:41.816450Z  INFO conn{id="fPku4k"}: ✅ Handshake successful: connection established!
2025-02-16T23:08:41.816474Z  INFO conn{id="fPku4k"}: ⛽ Pumping data between client and remote ...
2025-02-16T23:08:41.955483Z  INFO conn{id="fPku4k"}: ✅ Connection closed.
```

The `host` argument accepts the form `[local_host:[local_port:[remote_host:]]]remote_port`.  This means you could have various scenarios like this:
- `0.0.0.0:2000:google.com:80`: connects to `google.com:80` and listens on `0.0.0.0:2000`.
- `2000:google.com:80`: connects to `google.com:80` and listens on `localhost:2000`.
- `2000:80`: connects to `server:80` and listens on `localhost:2000`.
- `80`: connects to `server:80` and listens on `localhost:80`.

### Install

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