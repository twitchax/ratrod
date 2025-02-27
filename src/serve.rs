use std::marker::PhantomData;

use anyhow::Context;
use regex::Regex;
use tokio::net::{TcpListener, TcpStream};
use tracing::{Instrument, error, info, info_span};

use crate::{
    base::{Constant, EphemeralData, EphemeralKeyPair, HandshakeData, Res, Void},
    buffed_stream::BuffedStream,
    protocol::{BincodeReceive, BincodeSend, Challenge, Preamble, ProtocolError, ProtocolMessage},
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret, handle_pump, random_string, validate_signed_challenge},
};

// State machine.

pub struct ConfigState;
pub struct ReadyState;

pub struct Instance<S = ConfigState> {
    config: Config,
    _phantom: PhantomData<S>,
}

impl Instance<ConfigState> {
    pub fn prepare<A, B, C>(public_key: A, remote_regex: B, bind_address: C) -> Res<Instance<ReadyState>>
    where
        A: Into<String>,
        B: AsRef<str>,
        C: Into<String>,
    {
        let remote_regex = Regex::new(remote_regex.as_ref()).context("Invalid regex for remote host.")?;

        let config = Config::new(public_key.into(), bind_address.into(), remote_regex);

        Ok(Instance { config, _phantom: PhantomData })
    }
}

impl Instance<ReadyState> {
    pub async fn start(self) -> Void {
        run_tcp_server(self.config).await?;

        Ok(())
    }
}

// Operations.

async fn handle_handshake<T>(stream: &mut T, public_key: &str, remote_regex: &Regex, challenge: &Challenge) -> Res<HandshakeData>
where
    T: BincodeReceive + BincodeSend,
{
    let ProtocolMessage::HandshakeStart(preamble) = stream.pull().await? else {
        return ProtocolError::Unknown("Invalid handshake start".into()).send_and_bail(stream).await;
    };

    verify_preamble(stream, &preamble, remote_regex).await?;
    handle_and_validate_key_challenge(stream, public_key, challenge).await?;
    let ephemeral_key_pair = complete_handshake(stream).await?;

    Ok(HandshakeData { preamble, ephemeral_key_pair })
}

async fn verify_preamble<T>(stream: &mut T, preamble: &Preamble, remote_regex: &Regex) -> Void
where
    T: BincodeSend,
{
    if !remote_regex.is_match(&preamble.remote) {
        return ProtocolError::InvalidHost(format!("Invalid host from client (supplied `{}`, but need to satisfy `{}`)", preamble.remote, remote_regex))
            .send_and_bail::<_, ()>(stream)
            .await;
    }

    Ok(())
}

async fn handle_and_validate_key_challenge<T>(stream: &mut T, public_key: &str, challenge: &Challenge) -> Void
where
    T: BincodeSend + BincodeReceive,
{
    info!("🚧 Sending handshake challenge to client ...");

    stream.push(ProtocolMessage::HandshakeChallenge(*challenge)).await?;

    // Wait for the client to respond.

    let ProtocolMessage::HandshakeChallengeResponse(signature) = stream.pull().await?.fail_if_error()? else {
        return ProtocolError::InvalidKey("Invalid handshake response".into()).send_and_bail(stream).await;
    };

    // Verify the signature.

    if validate_signed_challenge(challenge, &signature.into(), public_key).is_err() {
        return ProtocolError::InvalidKey(format!("Invalid challenge signature from client (supplied `{}`)", public_key))
            .send_and_bail(stream)
            .await;
    }

    info!("✅ Handshake challenge completed!");

    Ok(())
}

async fn complete_handshake<T>(stream: &mut T) -> Res<EphemeralKeyPair>
where
    T: BincodeSend,
{
    let ephemeral_key_pair = generate_ephemeral_key_pair()?;

    let peer_public_key = ephemeral_key_pair.public_key.as_ref().try_into()?;
    let completion = ProtocolMessage::HandshakeCompletion(peer_public_key);

    stream.push(completion).await?;

    info!("✅ Handshake completed.");

    Ok(ephemeral_key_pair)
}

async fn run_tcp_server(config: Config) -> Void {
    let listener = TcpListener::bind(&config.bind_address).await?;

    loop {
        let (socket, _) = listener.accept().await?;

        tokio::spawn(handle_tcp(socket, config.clone()));
    }
}

async fn handle_tcp(client: TcpStream, config: Config) {
    let mut client = BuffedStream::new(client);

    let id = random_string(6);
    let span = info_span!("conn", id = id);

    let result: Void = async move {
        let peer_addr = client.peer_addr().context("Error getting peer address")?;

        info!("✅ Accepted connection from `{}`.", peer_addr);

        // Create a challenge.

        let challenge = generate_challenge();

        // Handle the preamble.

        let handshake_data = handle_handshake(&mut client, &config.public_key, &config.remote_regex, &challenge)
            .await
            .context("Error handling handshake")?;

        // Compute the ephemeral data.
        let ephemeral_data = EphemeralData {
            ephemeral_key_pair: handshake_data.ephemeral_key_pair,
            peer_public_key: handshake_data.preamble.peer_public_key,
            challenge,
        };

        // Extract the remote.
        let remote_address = handshake_data.preamble.remote;

        // Connect to remote.

        let mut remote = TcpStream::connect(&remote_address).await.context("Error connecting to remote")?;

        info!("✅ Connected to remote server `{}`.", remote_address);

        // Generate and apply the shared secret, if needed.
        if handshake_data.preamble.peer_public_key != Constant::NULL_PEER_PUBLIC_KEY {
            let private_key = ephemeral_data.ephemeral_key_pair.private_key;
            let peer_public_key = ephemeral_data.peer_public_key;
            let challenge = ephemeral_data.challenge;

            let shared_secret = generate_shared_secret(private_key, &peer_public_key, &challenge)?;

            client = client.with_encryption(shared_secret);
            info!("🔒 Encryption applied ...");
        }

        // Handle the TCP pump.

        info!("⛽ Pumping data between client and remote ...");

        handle_pump(&mut client, &mut remote).await.context("Error handling TCP pump.")?;

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

        error!("❌ Error handling connection: {}.", full_chain);
    }
}

// Statics.

#[derive(Clone)]
struct Config {
    public_key: String,
    bind_address: String,
    remote_regex: Regex,
}

impl Config {
    fn new(public_key: String, bind_address: String, remote_regex: Regex) -> Self {
        Self { public_key, bind_address, remote_regex }
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::utils::{generate_key_pair, sign_challenge, tests::generate_test_fake_peer_public_key};

    use super::*;

    #[test]
    fn test_prepare_config() {
        let instance = Instance::prepare("test_key", ".*", "foo").unwrap();

        assert_eq!(instance.config.public_key, "test_key");
        assert_eq!(instance.config.remote_regex.as_str(), ".*");
        assert_eq!(instance.config.bind_address, "foo");
    }

    #[test]
    fn test_cannot_set_unparsable_host_regex() {}

    // #[tokio::test]
    // async fn test_can_handle_handshake() {
    //     let (mut client, mut server) = tokio::io::duplex(Constant::BUFFER_SIZE);
    //     let keypair = generate_key_pair().unwrap();
    //     let peer_public_key = &generate_test_fake_peer_public_key();
    //     let remote = "test_remote";

    //     // We need to compute the total stream from the client back to the server.
    //     let challenge = generate_challenge();
    //     let signature = sign_challenge(&challenge, &keypair.private_key).unwrap();

    //     let preamble = Preamble {
    //         remote: remote.into(),
    //         peer_public_key: peer_public_key.clone(),
    //     };
    //     // Send the preamble and signature.
    //     client.send(&preamble).await.unwrap();
    //     client.send(&SerializeableSignature::from(signature)).await.unwrap();

    //     // Receive.
    //     let received_preamble: Preamble = server.receive().await.unwrap();
    //     let received_signature: Signature = server.receive::<SerializeableSignature>().await.unwrap().into();

    //     assert_eq!(received_preamble, preamble);
    //     assert_eq!(received_signature, signature);
    // }

    // #[tokio::test]
    // async fn test_can_disallow_wrong_challenge_response() {
    //     let remote = "test_remote";
    //     let peer_public_key = &generate_test_fake_peer_public_key();
    //     let error_message = "Invalid handshake response";

    //     let client_to_server = [
    //         &prepare_preamble(remote, peer_public_key).unwrap(),
    //         Constant::HANDSHAKE_COMPLETION,
    //         random_string(64).as_bytes(),
    //         Constant::DELIMITER,
    //     ]
    //     .concat();

    //     let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

    //     let preamble_result = handle_handshake(&mut stream, "public_key", &Regex::new(".*").unwrap(), &generate_challenge()).await;

    //     assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

    //     let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

    //     let skip = Constant::DELIMITER_SIZE + Constant::CHALLENGE_SIZE + Constant::DELIMITER_SIZE;
    //     assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    // }

    // #[tokio::test]
    // async fn test_can_disallow_wrong_key_length() {
    //     let remote = "test_remote";
    //     let peer_public_key = &generate_test_fake_peer_public_key();
    //     let error_message = "Invalid signature length";

    //     let client_to_server = [
    //         &prepare_preamble(remote, peer_public_key).unwrap(),
    //         Constant::HANDSHAKE_CHALLENGE_RESPONSE,
    //         random_string(32).as_bytes(),
    //         Constant::DELIMITER,
    //     ]
    //     .concat();

    //     let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

    //     let preamble_result = handle_handshake(&mut stream, "public_key", &Regex::new(".*").unwrap(), &generate_challenge()).await;

    //     assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

    //     let expected_write_stream = [Constant::ERROR_INVALID_KEY, error_message.as_bytes(), Constant::DELIMITER].concat();

    //     let skip = Constant::DELIMITER_SIZE + Constant::CHALLENGE_SIZE + Constant::DELIMITER_SIZE;
    //     assert_eq!(stream.get_ref().write[skip..], expected_write_stream);
    // }

    // #[tokio::test]
    // async fn test_can_disallow_bad_host() {
    //     let key = "test_key";
    //     let remote = "test_remote";
    //     let peer_public_key = &generate_test_fake_peer_public_key();
    //     let error_message = "Invalid host from client (supplied `test_remote`, but need to satisfy `hots`)";

    //     let client_to_server = prepare_preamble(remote, peer_public_key).unwrap();

    //     let mut stream = BuffedStream::new(MockStream::new(client_to_server, vec![]));

    //     let preamble_result = handle_handshake(&mut stream, key, &Regex::new("hots").unwrap(), &generate_challenge()).await;

    //     assert_eq!(preamble_result.err().unwrap().to_string(), error_message);

    //     let expected_write_stream = [Constant::ERROR_INVALID_HOST, error_message.as_bytes(), Constant::DELIMITER].concat();

    //     assert_eq!(stream.get_ref().write, expected_write_stream);
    // }
}
