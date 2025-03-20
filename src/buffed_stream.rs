//! Buffed stream module.
//!
//! This module contains the `BuffedStream` type, which is a wrapper around a stream that provides
//! buffering and encryption/decryption functionality.
//!
//! It is used to provide a bincode-centric stream that can be used to send and receive data
//! in a more efficient manner.  In addition, the `AsyncRead` and `AsyncWrite` implementations
//! are designed to "transparently" handle encryption and decryption of the data being sent
//! and received (for the "pump" phase of the lifecycle).

use anyhow::{Context as _, anyhow};
use bincode::Encode;
use bytes::{BufMut, Bytes, BytesMut};
use secrecy::ExposeSecret;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
};
use tracing::{error, warn};

use crate::{
    base::{Constant, Res, SharedSecret, Void},
    protocol::{BincodeReceive, BincodeSend, ProtocolMessage, ProtocolMessageGuard, ProtocolMessageGuardBuilder},
    utils::{decrypt_in_place, encrypt_into},
};

// Traits.

/// A trait for splitting a [`BuffedStream`] into its read and write halves.
pub trait BincodeSplit {
    type ReadHalf: BincodeReceive;
    type WriteHalf: BincodeSend;

    /// Takes and splits the buffered stream into its read and write halves.
    ///
    /// This allows the read and write halves to be used independently, potentially
    /// from different tasks or threads.
    fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf);

    /// Splits the buffered stream into mutably borrowed read and write halves.
    ///
    /// This allows the read and write halves to be used independently, potentially
    /// from different tasks or threads.
    fn split(&mut self) -> (&mut Self::ReadHalf, &mut Self::WriteHalf);
}

// Types.

/// A type alias for a buffed [`TcpStream`].
pub type BuffedTcpStream = BuffedStream<OwnedReadHalf, OwnedWriteHalf>;
/// A type alias for a buffed [`DuplexStream`].
pub type BuffedDuplexStream = BuffedStream<ReadHalf<DuplexStream>, WriteHalf<DuplexStream>>;

/// BuffedStream type.
///
/// This type is a wrapper around a stream that provides buffering and encryption/decryption functionality.
/// It is used to provide a bincode-centric stream that can be used to send and receive data
/// in a more efficient manner.  In order to make _usual_ future splitting more ergonomic, this type
/// is designed to be a wrapper around the split halves.
///
/// > This type is used to provide a bincode-centric stream that can be used to send and receive data
/// > so it is inadvisable to use any other methods than the `push` and `pull` methods from the protocol
/// > module.
pub struct BuffedStream<R, W> {
    /// The read half of the buffered stream
    inner_read: BuffedStreamReadHalf<R>,
    /// The write half of the buffered stream
    inner_write: BuffedStreamWriteHalf<W>,
}

// Impl.

impl<R, W> BuffedStream<R, W> {
    /// Sets the shared secret for the stream, and enables encryption / decryption.
    pub fn with_encryption(mut self, shared_secret: SharedSecret) -> Self {
        let secret_clone = SharedSecret::init_with(|| *shared_secret.expose_secret());

        self.inner_read.shared_secret = Some(secret_clone);
        self.inner_write.shared_secret = Some(shared_secret);

        self
    }
}

impl<R, W> BincodeSplit for BuffedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    type ReadHalf = BuffedStreamReadHalf<R>;
    type WriteHalf = BuffedStreamWriteHalf<W>;

    fn into_split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (self.inner_read, self.inner_write)
    }

    fn split(&mut self) -> (&mut Self::ReadHalf, &mut Self::WriteHalf) {
        (&mut self.inner_read, &mut self.inner_write)
    }
}

impl From<TcpStream> for BuffedStream<OwnedReadHalf, OwnedWriteHalf> {
    fn from(stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();

        Self {
            inner_read: BuffedStreamReadHalf::new(read),
            inner_write: BuffedStreamWriteHalf::new(write),
        }
    }
}

impl<T> From<T> for BuffedStream<ReadHalf<T>, WriteHalf<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn from(stream: T) -> Self {
        let (read, write) = tokio::io::split(stream);

        Self {
            inner_read: BuffedStreamReadHalf::new(read),
            inner_write: BuffedStreamWriteHalf::new(write),
        }
    }
}

impl<R, W> BuffedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn from_splits(inner_read: R, inner_write: W) -> Self {
        Self {
            inner_read: BuffedStreamReadHalf::new(inner_read),
            inner_write: BuffedStreamWriteHalf::new(inner_write),
        }
    }
}

impl<R> BuffedStream<R, OwnedWriteHalf> {
    pub fn as_inner_tcp_write_ref(&self) -> &OwnedWriteHalf {
        &self.inner_write.inner
    }

    pub fn as_inner_tcp_write_mut(&mut self) -> &mut OwnedWriteHalf {
        &mut self.inner_write.inner
    }
}

impl<W> BuffedStream<OwnedReadHalf, W> {
    pub fn as_inner_tcp_read_ref(&self) -> &OwnedReadHalf {
        &self.inner_read.inner
    }

    pub fn as_inner_tcp_read_mut(&mut self) -> &mut OwnedReadHalf {
        &mut self.inner_read.inner
    }
}

impl BuffedStream<OwnedReadHalf, OwnedWriteHalf> {
    pub fn take(self) -> Res<TcpStream> {
        let read = self.inner_read.take();
        let write = self.inner_write.take();

        read.reunite(write).context("Failed to reunite read and write halves")
    }
}

// Trait impls.

impl<R, W> BincodeSend for BuffedStream<R, W>
where
    R: Unpin,
    W: AsyncWrite + Unpin,
{
    async fn push<E>(&mut self, message: E) -> Void
    where
        E: Encode,
    {
        self.inner_write.push(message).await?;

        Ok(())
    }

    async fn close(&mut self) -> Void {
        self.inner_write.close().await?;

        Ok(())
    }
}

impl<R, W> BincodeReceive for BuffedStream<R, W>
where
    R: AsyncRead + Unpin,
    W: Unpin,
{
    async fn pull(&mut self) -> Res<ProtocolMessageGuard> {
        self.inner_read.pull().await
    }
}

// Split streams.

/// A type for the read half of a buffed stream.
pub struct BuffedStreamReadHalf<T> {
    inner: T,
    shared_secret: Option<SharedSecret>,
    buffer: BytesMut,
    decryption_buffer: BytesMut,
}

impl<T> BuffedStreamReadHalf<T>
where
    T: AsyncRead + Unpin,
{
    /// Creates a new `BuffedStreamReadHalf` from the given [`AsyncRead`].
    fn new(async_read: T) -> Self {
        Self {
            inner: async_read,
            shared_secret: None,
            buffer: BytesMut::with_capacity(2 * Constant::BUFFER_SIZE),
            decryption_buffer: BytesMut::with_capacity(2 * Constant::BUFFER_SIZE),
        }
    }

    /// Takes the inner stream and returns it.
    fn take(self) -> T {
        if !self.buffer.is_empty() {
            warn!("Buffer was not empty when taking the stream");
        }

        self.inner
    }
}

impl<T> BincodeReceive for BuffedStreamReadHalf<T>
where
    T: AsyncRead + Unpin,
{
    async fn pull(&mut self) -> Res<ProtocolMessageGuard> {
        // Use reserve here to make sure we have at least the space for the next read.
        // The `Bytes` go _with_ the returned guard, so we need to make sure we have enough space
        // for the next read.
        //
        // In many cases, the guards may have been dropped, and reserve will not allocate,
        // but we need to make sure we have enough space for the next read in case they haven't.
        //
        // In practice, this is used in the pump, so guards are usually dropped within a
        // few reads, but not after _every_ read (which is why we don't use `try_reclaim` here).

        self.buffer.clear();
        self.decryption_buffer.clear();
        self.buffer.reserve(Constant::BUFFER_SIZE);
        self.decryption_buffer.reserve(Constant::BUFFER_SIZE);

        // First, read the encryption flag.

        let is_encrypted = match self.inner.read_u8().await {
            Ok(1) => true,
            Ok(_) => false,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Ok(ProtocolMessageGuardBuilder {
                        buffer: Bytes::new(),
                        inner_builder: |_| ProtocolMessage::Shutdown,
                    }
                    .build());
                } else {
                    return Err(anyhow!("Failed to read encryption flag: {}", e));
                }
            }
        };

        // Next, read the nonce, if the message is encrypted.

        let maybe_encryption_data = if is_encrypted {
            let mut nonce = [0; Constant::SHARED_SECRET_NONCE_SIZE];
            self.inner.read_exact(&mut nonce).await.context("Failed to read nonce")?;

            Some(nonce)
        } else {
            None
        };

        // Read the size of the message from the stream.

        let message_size = self.inner.read_u64().await.context("Failed to read size")? as usize;

        // Bail if we got a FIN (?) or a message that is too large.

        if message_size == 0 {
            let guard = ProtocolMessageGuardBuilder {
                buffer: Bytes::new(),
                inner_builder: |_| ProtocolMessage::Shutdown,
            }
            .build();

            return Ok(guard);
        }

        if message_size > Constant::BUFFER_SIZE {
            return Err(anyhow!("Message size is too large for the buffer during pull"));
        }

        // Read the stream into the buffer.

        // SAFTY: We know _exactly_ how many bytes we are going to read, so we can safely
        // set the length of the buffer to the size of the message.  However, we check
        // afterward just to make sure.
        unsafe { self.buffer.set_len(message_size) };
        let n = self.inner.read_exact(&mut self.buffer).await?;

        if message_size != n {
            return Err(anyhow!("Failed to read message: expected {} bytes, got {}", message_size, n));
        }

        // Split off the needed bytes for the borrowed message.

        let data_buffer = self.buffer.split().freeze();

        // Perform any needed encryption.

        let data_buffer = if let Some(nonce) = maybe_encryption_data {
            let Some(key) = self.shared_secret.as_ref() else {
                return Err(anyhow!("Shared secret is not set when receiving encrypted message"));
            };

            self.decryption_buffer.put(data_buffer);

            // The length is of the buffer is adjusted by this call.
            decrypt_in_place(key, &nonce, &mut self.decryption_buffer).context("Failed to decrypt message")?;

            self.decryption_buffer.split().freeze()
        } else {
            data_buffer
        };

        // Prepare the result into the guard.

        Ok(ProtocolMessageGuardBuilder {
            buffer: data_buffer,
            inner_builder: |data| match bincode::borrow_decode_from_slice::<ProtocolMessage<'_>, _>(data, Constant::BINCODE_CONFIG) {
                Ok((message, n)) => {
                    if n != data.len() {
                        error!("Failed to decrypt message: expected {} bytes, got {}", data.len(), n);
                        return ProtocolMessage::Shutdown;
                    }

                    message
                }
                Err(e) => {
                    error!("Failed to decode message: {}", e);
                    ProtocolMessage::Shutdown
                }
            },
        }
        .build())
    }
}

/// A type for the write half of a buffed stream.
pub struct BuffedStreamWriteHalf<T> {
    inner: T,
    shared_secret: Option<SharedSecret>,
    buffer: BytesMut,
}

impl<T> BuffedStreamWriteHalf<T>
where
    T: AsyncWrite + Unpin,
{
    /// Creates a new `BuffedStreamWriteHalf` from the given [`AsyncWrite`].
    fn new(async_write: T) -> Self {
        Self {
            inner: async_write,
            shared_secret: None,
            buffer: BytesMut::with_capacity(2 * Constant::BUFFER_SIZE),
        }
    }

    /// Takes the inner stream and returns it.
    fn take(self) -> T {
        self.inner
    }
}

impl<T> BincodeSend for BuffedStreamWriteHalf<T>
where
    T: AsyncWrite + Unpin,
{
    async fn push<E>(&mut self, message: E) -> Void
    where
        E: Encode,
    {
        // Restore the buffer to its original state.
        // We use `try_reclaim` here to avoid allocating a new buffer, and there
        // _should_ never be a case where we cannot.  The produced interim `Bytes` are all dropped
        // at the end of the function, and we currently have a unique mutable borrow, so there cannot
        // be any other references to the buffer.

        self.buffer.clear();
        assert!(self.buffer.try_reclaim(2 * Constant::BUFFER_SIZE));

        // Encode the message into the buffer.

        // SAFETY: We know the size of the buffer, and we are going to fill it with
        // the encoded message.  We also know that the buffer is empty, so we can safely
        // set the length of the buffer to the size of the message.
        unsafe { self.buffer.set_len(Constant::BUFFER_SIZE) };
        let n = bincode::encode_into_slice(message, &mut self.buffer, Constant::BINCODE_CONFIG)?;
        unsafe { self.buffer.set_len(n) };

        // Encrypt the message if, needed.

        let maybe_nonce = if let Some(key) = self.shared_secret.as_ref() {
            // This call extends the buffer through `Extend`, so no need to update the length.
            let nonce = encrypt_into(key, &mut self.buffer).context("Encryption failed")?;

            Some(nonce)
        } else {
            None
        };

        // Ensure the buffer is not empty and is not too large.

        let data_length = self.buffer.len();

        if data_length == 0 {
            return Err(anyhow!("Buffer is empty"));
        }

        if data_length > Constant::BUFFER_SIZE {
            return Err(anyhow!("Buffer is too large"));
        }

        // Write enryption / nonce.

        if let Some(nonce) = maybe_nonce {
            self.inner.write_u8(1).await.context("Failed to write encryption flag")?;
            self.inner.write_all(&nonce).await.context("Failed to write nonce")?;
        } else {
            self.inner.write_u8(0).await.context("Failed to write encryption flag")?;
        }

        // Write the message size.

        self.inner.write_u64(data_length as u64).await.context("Failed to write size")?;

        // Write the data.

        self.inner.write_all(&self.buffer).await?;

        // Flush the stream.

        self.inner.flush().await.context("Failed to flush stream")?;

        Ok(())
    }

    async fn close(&mut self) -> Void {
        self.inner.shutdown().await.context("Failed to close stream")?;

        Ok(())
    }
}

// Tests.

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{BincodeReceive, BincodeSend, ProtocolMessage},
        utils::tests::{generate_test_duplex, generate_test_duplex_with_encryption},
    };

    #[tokio::test]
    async fn test_unencrypted_buffed_stream() {
        let (mut client, mut server) = generate_test_duplex();

        let data = b"Hello, world!";

        client.push(ProtocolMessage::Data(data)).await.unwrap();
        client.close().await.unwrap();

        let guard = server.pull().await.unwrap();
        let ProtocolMessage::Data(received) = *guard.message() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, received);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream() {
        let (mut client, mut server) = generate_test_duplex_with_encryption();

        let data = b"Hello, world!";

        client.push(ProtocolMessage::Data(data)).await.unwrap();
        client.close().await.unwrap();

        let guard = server.pull().await.unwrap();
        let ProtocolMessage::Data(received) = *guard.message() else {
            panic!("Failed to receive message");
        };

        assert_eq!(data, received);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream_with_multiple_packets() {
        let (mut client, mut server) = generate_test_duplex_with_encryption();

        let data1 = b"Hello, world!";
        let data2 = b"Hello, wold!";

        client.push(ProtocolMessage::Data(data1)).await.unwrap();
        client.push(ProtocolMessage::Data(data2)).await.unwrap();
        client.close().await.unwrap();

        let guard = server.pull().await.unwrap();
        let ProtocolMessage::Data(received) = *guard.message() else {
            panic!("Failed to receive message");
        };
        assert_eq!(data1, received);

        let guard = server.pull().await.unwrap();
        let ProtocolMessage::Data(received) = *guard.message() else {
            panic!("Failed to receive message");
        };
        assert_eq!(data2, received);
    }
}
