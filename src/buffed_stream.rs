//! Buffed stream module.
//!
//! This module contains the `BuffedStream` type, which is a wrapper around a stream that provides
//! buffering and encryption/decryption functionality.
//!
//! It is used to provide a bincode-centric stream that can be used to send and receive data
//! in a more efficient manner.  In addition, the `AsyncRead` and `AsyncWrite` implementations
//! are designed to "transparently" handle encryption and decryption of the data being sent
//! and received (for the "pump" phase of the lifecycle).

use std::{
    ops::Deref,
    pin::Pin,
    task::{Context, Poll, ready},
};

use async_bincode::{AsyncDestination, tokio::AsyncBincodeStream};
use futures::{Sink, Stream};
use secrecy::ExposeSecret;
use tokio::io::{AsyncRead, AsyncWrite, SimplexStream};

use crate::{
    base::{Constant, SharedSecret},
    protocol::{BincodeReceive, BincodeSend, ProtocolMessage, ProtocolMessageWrapper},
    utils::{decrypt, encrypt},
};

// Macros.

/// Macro to get a ref to `Pin<&mut BuffedStream<T>>` and return the inner `Pin<&mut AsyncBincodeStream<T>>`.
macro_rules! pinned_inner {
    ($self:ident) => {
        Pin::new(&mut $self.inner)
    };
}

/// Macro to take a `Pin<&mut BuffedStream<T>>` and return the inner `Pin<&mut AsyncBincodeStream<T>>`.
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

// Types.

/// BuffedStream type.
///
/// This type is a wrapper around a stream that provides buffering and encryption/decryption functionality.
/// It is used to provide a bincode-centric stream that can be used to send and receive data
/// in a more efficient manner.
/// 
/// > This type is used to provide a bincode-centric stream that can be used to send and receive data
/// > so it is inadvisable to use any other methods than the `push` and `pull` methods from the protocol
/// > module.  Using `read` and `write` directly will bypass the normal logic, and should only be used when
/// > you know what you are doing (most common use case is pumping data).
///
/// The `shared_secret` field is used to encrypt and decrypt data.
/// The `read_stream` field is used to buffer data that has been decrypted.
pub struct BuffedStream<T> {
    inner: AsyncBincodeStream<T, ProtocolMessageWrapper, ProtocolMessageWrapper, AsyncDestination>,
    shared_secret: Option<SharedSecret>,
    read_stream: Option<SimplexStream>,
}

// Impl.

impl<T> BuffedStream<T>
where
    T: AsyncRead + AsyncWrite,
{
    /// Creates a new `BuffedStream` from the given stream.
    pub fn new(stream: T) -> Self {
        Self {
            inner: AsyncBincodeStream::from(stream).for_async(),
            shared_secret: None,
            read_stream: None,
        }
    }

    /// Sets the shared secret for the stream, and enables encryption / decryption.
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
        // Get an option to the shared secret.
        let key = self.shared_secret.as_ref().map(|s| SharedSecret::init_with(|| *s.expose_secret()));

        match take_pinned_inner!(self).poll_next(cx) {
            Poll::Ready(Some(Ok(wrapper))) => match wrapper {
                ProtocolMessageWrapper::Plain(message) => Poll::Ready(Some(Ok(message))),
                ProtocolMessageWrapper::Encrypted { nonce, data } => {
                    let Some(key) = key else {
                        return Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Received encrypted message without shared secret on this end",
                        ))));
                    };

                    let Ok(decrypted_data) = decrypt(&key, &data, &nonce) else {
                        return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed"))));
                    };

                    let Ok(message) = bincode::deserialize::<ProtocolMessage>(&decrypted_data) else {
                        return Poll::Ready(Some(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to deserialize decrypted data"))));
                    };

                    Poll::Ready(Some(Ok(message)))
                }
            },
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
        if let Some(key) = self.shared_secret.as_ref() {
            let encrypted_data = encrypt(
                key,
                &bincode::serialize(&item).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to serialize message"))?,
            )
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed"))?;

            let message = ProtocolMessageWrapper::Encrypted {
                nonce: encrypted_data.nonce,
                data: encrypted_data.data,
            };

            take_pinned_inner!(self)
                .start_send(message)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to write encrypted packet: {}", e)))?;

            return Ok(());
        }

        take_pinned_inner!(self)
            .start_send(ProtocolMessageWrapper::Plain(item))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to write plain packet: {}", e)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        futures::Sink::<ProtocolMessageWrapper>::poll_flush(take_pinned_inner!(self), cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to flush inner stream: {}", e)))
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
        //
        // Basically, this is an optimization that both `poll_read` and `poll_write` can use for 
        // the case where we are not encrypting the stream.
        if self.shared_secret.is_none() {
            return Pin::new(self.inner.get_mut()).poll_read(cx, buf);
        }

        // Use the "self" reader to get the next packet (and perform any needed decryption).
        // TODO: We could actually loop on poll next here until we either get a pending, or we no longer have space in the
        // read stream.
        let result = self.as_mut().poll_next(cx);

        match result {
            Poll::Ready(Some(Ok(message))) => {
                let ProtocolMessage::Data(data) = message else {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Received non-data message during `poll_read`, which shouldn't happen")));
                };

                // We have the data, so we can write it to the `read_stream`.
                let written = ready!(pinned_read_stream!(self).poll_write(cx, &data)?);

                // Fail if the interim buffer is too small.
                if written < data.len() {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Decryption stream buffer overflow (shouldn't happen unless there is a mismatched buffer size between client and server)",
                    )));
                }

                // Flush the `read_stream` to ensure that the data is available for reading (see below).
                ready!(pinned_read_stream!(self).poll_flush(cx)?);
            }
            Poll::Ready(Some(Err(e))) => {
                // This is the case where we have a bincode error, so we should return the error.

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
        // decrypted stream, so we just offload onto its `poll_read` method.
        take_pinned_read_stream!(self).poll_read(cx, buf)
    }
}

impl<T> AsyncWrite for BuffedStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        // If there is no shared secret, then we are not encrypting the stream,
        // so we can just write directly to the inner stream.
        //
        // Basically, this is an optimization that both `poll_read` and `poll_write` can use for 
        // the case where we are not encrypting the stream.
        if self.shared_secret.is_none() {
            return Pin::new(self.inner.get_mut()).poll_write(cx, buf);
        }

        // First, we need to pare down the data to the maximum size of the encrypted data, if needed.
        let max_size = Constant::BUFFER_SIZE - Constant::ENCRYPTION_OVERHEAD;
        let amt = std::cmp::min(buf.len(), max_size);
        let buf = &buf[..amt];

        let message = ProtocolMessage::Data(buf.to_vec());
        
        // Write the encrypted data to the "self" `start_send`, which performs any needed encryption logic.
        self
            .as_mut()
            .start_send(message)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Failed to write encrypted packet"))?;

        // Need to report the amount of data that was written _from the input_, not the _actual_ amount written to the inner stream.
        // This allows the caller to know how much of _their_ data was written, which is all that matters.
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
    use futures::future::join_all;
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

        join_all([write_task, read_task]).await.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
    }
}
