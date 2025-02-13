use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream};
use tracing::info;

use crate::{base::{Err, Res, Sentinel}, utils::prepare_preamble};

pub async fn start(server: String, remote: String, key: String) -> Res<()> {
    let tab = " ";

    // Check that key and remote, together, are no more than PREAMBLE_SIZE - 3 * DELIMITER_SIZE.

    if key.len() + remote.len() > Sentinel::PREAMBLE_SIZE - 3 * Sentinel::PREAMBLE_SIZE {
        let message = format!("Key and remote together are too long (must be less than PREAMBLE_SIZE [{}] - 3 * DELIMITER_SIZE [{}] bytes)", Sentinel::PREAMBLE_SIZE, Sentinel::PREAMBLE_SIZE);
        return Err(Err::msg(message));
    }

    // Connect to the server.

    let mut stream = TcpStream::connect(&server).await?;
    info!("{}✔️ Connected to server `{}` ...", tab, server);

    // Send the preamble.

    let preamble = prepare_preamble(&key, &remote).await?;
    stream.write_all(&preamble).await?;
    info!("{}✔️ Sent preamble to server ...", tab);

    // Await the handshake response.

    let mut buf = [0; 8];
    stream.read_exact(&mut buf).await?;

    if buf == Sentinel::PREAMBLE_COMPLETION {
        info!("{}✔️ Handshake successful: connection established!", tab);
    } else if buf == Sentinel::ERROR_INVALID_KEY {
        let mut message = String::new();
        let _ = stream.read_to_string(&mut message).await;

        return Err(Err::msg(format!("Handshake failed (invalid key): {}", message)));
    } else if buf == Sentinel::ERROR_INVALID_HOST {
        let mut message = String::new();
        let _ = stream.read_to_string(&mut message).await;

        return Err(Err::msg(format!("Handshake failed (invalid host): {}", message)));
    } else {
        return Err(Err::msg("Handshake failed (unknown error)"));
    }
    


    Ok(())
}