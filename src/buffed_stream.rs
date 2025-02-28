use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_bincode::{AsyncDestination, tokio::AsyncBincodeStream};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, SimplexStream};

use crate::{
    base::{Constant, SharedSecret},
    protocol::{BincodeReceive, BincodeSend, ProtocolMessage},
    utils::{decrypt, encrypt},
};

// Macros.

/// Macro to get a ref to `Pin<&mut BuffedStream<T>>` and return the inner `Pin<&mut BufReader<T>>`.
macro_rules! pinned_inner {
    ($self:ident) => {
        Pin::new(&mut $self.inner)
    };
}

/// Macro to take a `Pin<&mut BuffedStream<T>>` and return the inner `Pin<&mut BufReader<T>>`.
macro_rules! take_pinned_inner {
    ($self:ident) => {
        Pin::new(&mut $self.get_mut().inner)
    };
}

/// Macro to get a ref to `Pin<&mut BuffedStream<T>>` and return the decryption stream `Pin<&mut BufReader<SimplexStream>>`.
macro_rules! pinned_read_stream {
    ($self:ident) => {
        Pin::new($self.read_stream.as_mut().unwrap())
    };
}

/// Macro to take a `Pin<&mut BuffedStream<T>>` and return the decryption stream `Pin<&mut BufReader<SimplexStream>>`.
macro_rules! take_pinned_read_stream {
    ($self:ident) => {
        Pin::new($self.get_mut().read_stream.as_mut().unwrap())
    };
}

// Type.

pub struct BuffedStream<T> {
    inner: AsyncBincodeStream<T, ProtocolMessage, ProtocolMessage, AsyncDestination>,
    shared_secret: Option<SharedSecret>,
    read_stream: Option<SimplexStream>,
}

// Impl.

impl<T> BuffedStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    pub fn new(stream: T) -> Self {
        Self {
            inner: AsyncBincodeStream::from(stream).for_async(),
            shared_secret: None,
            read_stream: None,
        }
    }

    pub fn with_encryption(mut self, shared_secret: SharedSecret) -> Self {
        self.shared_secret = Some(shared_secret);
        self.read_stream = Some(SimplexStream::new_unsplit(Constant::BUFFER_SIZE));

        self
    }
}

// Trait impls.

impl<T> Unpin for BuffedStream<T> where T: Unpin {}

impl<T> Deref for BuffedStream<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.inner.get_ref()
    }
}

impl<T> From<T> for BuffedStream<T>
where
    T: BincodeSend + BincodeReceive,
{
    fn from(buf: T) -> Self {
        Self::new(buf)
    }
}

impl<T> Stream for BuffedStream<T>
where
    T: AsyncRead + Unpin,
{
    type Item = std::io::Result<ProtocolMessage>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match take_pinned_inner!(self).poll_next(cx) {
            Poll::Ready(Some(Ok(message))) => Poll::Ready(Some(Ok(message))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Error on bincode reading during stream next: {}", e),
            )))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> Sink<ProtocolMessage> for BuffedStream<T>
where
    T: AsyncWrite + Unpin,
{
    type Error = std::io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        take_pinned_inner!(self)
            .poll_ready(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to flush inner stream: {}", e)))
    }

    fn start_send(self: Pin<&mut Self>, item: ProtocolMessage) -> Result<(), Self::Error> {
        take_pinned_inner!(self)
            .start_send(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to write encrypted packet: {}", e)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        futures::Sink::<ProtocolMessage>::poll_flush(take_pinned_inner!(self), cx).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to flush inner stream: {}", e)))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        take_pinned_inner!(self)
            .poll_close(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to shutdown inner stream: {}", e)))
    }
}

impl<T> AsyncRead for BuffedStream<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        // Read directly from the inner stream if there is no shared secret.
        // This is the case where we are not encrypting the stream.
        if self.shared_secret.is_none() {
            return Pin::new(self.inner.get_mut()).poll_read(cx, buf);
        }

        // Perform the decryption logic.

        let key = &self.shared_secret.unwrap();

        // Use the bincode reader to get the next packet.
        // TODO: We could actually loop on poll next here until we either get a pending, or we no longer have space in the
        // read stream.
        let result = pinned_inner!(self).poll_next(cx);

        match result {
            Poll::Ready(Some(Ok(message))) => {
                let ProtocolMessage::EncryptedPacket { nonce, data } = message else {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid message type when decrypting")));
                };

                let Ok(decrypted_data) = decrypt(key, &data, &nonce) else {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")));
                };

                // We have the decrypted data, so we can write it to the `read_stream`.
                let written = ready!(pinned_read_stream!(self).poll_write(cx, &decrypted_data)?);

                // Fail if the interim buffer is too small.
                if written < decrypted_data.len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Decryption stream buffer overflow (shouldn't happen unless there is a mismatched buffer size between client and server)",
                    )));
                }

                ready!(pinned_read_stream!(self).poll_flush(cx)?);
            }
            Poll::Ready(Some(Err(e))) => {
                // This is the case where we have a bincode error, so we should
                // return the error.

                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Error on bincode reading during pump: {}", e))));
            }
            Poll::Ready(None) => {
                // If we read no data from the inner buffer, then we are "shutdown",
                // so we should shutdown the write side of the `decryption_stream`, and
                // return the final poll result (bottom of function).

                ready!(pinned_read_stream!(self).poll_shutdown(cx)?);
            }
            Poll::Pending => {
                // If we are pending, then we should pass through to the underlying decryption stream (so do nothing here).
                // The underlying decryption stream will be properly shutdown in the case of a shutdown on the inner stream.
            }
        }

        // At this point, if there was data to decrypt, we have decrypted it; if not, we may have some data in the
        // decrypted stream, so we just offload onto its `poll_fill_buf` method.;
        take_pinned_read_stream!(self).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for BuffedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.shared_secret.is_none() {
            return Pin::new(self.inner.get_mut()).poll_write(cx, buf);
        }

        let key = self.shared_secret.as_ref().unwrap();

        // First, we need to pare down the data to the maximum size of the encrypted data, if needed.
        let max_size = Constant::BUFFER_SIZE - Constant::ENCRYPTION_OVERHEAD;
        let amt = std::cmp::min(buf.len(), max_size);
        let buf = &buf[..amt];

        // Get the actual encrypted data.
        let encrypted_data = encrypt(key, buf).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed"))?;

        let message = ProtocolMessage::EncryptedPacket {
            nonce: encrypted_data.nonce,
            data: encrypted_data.data,
        };

        // Write the encrypted data.
        pinned_inner!(self)
            .start_send(message)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to write encrypted packet"))?;

        // Need to report the amount of data that was written _from the input_, not the _actual_ amount written to the inner stream.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        pinned_inner!(self)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to flush inner stream: {}", e)))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        pinned_inner!(self)
            .poll_close(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to shutdown inner stream: {}", e)))
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::utils::tests::{generate_test_duplex, generate_test_duplex_with_encryption};

    #[tokio::test]
    async fn test_unencrypted_buffed_stream() {
        let (mut client, mut server) = generate_test_duplex();

        let data = b"Hello, world!";

        client.write_all(data).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();

        assert_eq!(data, &received[..]);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream() {
        let (mut client, mut server) = generate_test_duplex_with_encryption();

        let data = b"Hello, world!";

        client.write_all(data).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();

        assert_eq!(data, &received[..]);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream_with_multiple_packets() {
        let (mut client, mut server) = generate_test_duplex_with_encryption();

        let data1 = b"Hello, world!";
        let data2 = b"Hello, world!";

        client.write_all(data1).await.unwrap();
        client.write_all(data2).await.unwrap();
        client.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();

        assert_eq!(data1.len() + data2.len(), received.len());
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream_with_large_data() {
        let (mut client, mut server) = generate_test_duplex_with_encryption();

        let data = b"Hello, world!";
        let data = data.repeat(10000);

        let data_clone = data.clone();

        let write_task = tokio::spawn(async move {
            client.write_all(&data_clone).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let read_task = tokio::spawn(async move {
            let mut received = Vec::new();
            server.read_to_end(&mut received).await.unwrap();
            assert_eq!(data.len(), received.len());
        });

        tokio::select! {
            write_result = write_task => write_result.unwrap(),
            read_result = read_task => read_result.unwrap(),
        };
    }
}
