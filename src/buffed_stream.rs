use std::{ops::{Deref, DerefMut}, pin::Pin, task::{Context, Poll}};

use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufReader, SimplexStream};

use crate::{base::{Constant, SharedSecret}, utils::{decrypt, encrypt, find_next_delimiter}};

pub struct BuffedStream<T>
{
    inner: BufReader<T>,
    shared_secret: Option<SharedSecret>,
    decryption_stream: Option<BufReader<SimplexStream>>,
}

impl<T> BuffedStream<T>
where 
    T: AsyncRead,
{
    pub fn new(stream: T) -> Self {
        Self {
            inner: BufReader::with_capacity(Constant::BUFFER_SIZE, stream),
            shared_secret: None,
            decryption_stream: None,
        }
    }

    pub fn with_encryption(mut self, shared_secret: SharedSecret) -> Self {
        self.shared_secret = Some(shared_secret);
        self.decryption_stream = Some(BufReader::new(SimplexStream::new_unsplit(Constant::BUFFER_SIZE)));
        self
    }
}

impl<T> Unpin for BuffedStream<T>
where 
    T: Unpin,
{}

impl<T> Deref for BuffedStream<T> {
    type Target = BufReader<T>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for BuffedStream<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T> AsRef<BufReader<T>> for BuffedStream<T> {
    fn as_ref(&self) -> &BufReader<T> {
        &self.inner
    }
}

impl<T> AsMut<BufReader<T>> for BuffedStream<T> {
    fn as_mut(&mut self) -> &mut BufReader<T> {
        &mut self.inner
    }
}

impl<T> From<BufReader<T>> for BuffedStream<T> {
    fn from(buf: BufReader<T>) -> Self {
        Self {
            inner: buf,
            shared_secret: None,
            decryption_stream: None,
        }
    }
}

impl<T> AsyncRead for BuffedStream<T>
where 
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // In the unencrypted case, we can just read the data from the `BufReader`, 
        // and let it handle its internal structure.
        if self.shared_secret.is_none() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        // In the encrypted case, attempt to read the data from self as a `BufReader`, and advance the
        // `decryption_stream` if data was read.

        let rem = match Pin::new(&mut self).poll_fill_buf(cx) {
            Poll::Ready(Ok(rem)) => rem,
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };

        let amt = std::cmp::min(rem.len(), buf.remaining());
        buf.put_slice(&rem[..amt]);
        self.consume(amt);

        Poll::Ready(Ok(()))
    }
}

impl<T> AsyncBufRead for BuffedStream<T>
where 
    T: AsyncRead + Unpin,
{
    fn poll_fill_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        // In the unencrypted case, we can just read the data from the `BufReader`, 
        // and let it handle its internal structure.
        if self.shared_secret.is_none() {
            return Pin::new(&mut self.get_mut().inner).poll_fill_buf(cx);
        }

        // In the encrypted case, we need to decrypt the data, so use the
        // `poll_fill_buf` method to get the data through the `BufReader`'s
        // internal logic, and then decrypt it.

        let key = &self.shared_secret.unwrap();
        let result = Pin::new(&mut self.inner).poll_fill_buf(cx);

        // In the case where we got more data, we need to decrypt it.
        if let Poll::Ready(Ok(data)) = result {
            // If we read no data from the inner buffer, then we are "shutdown", 
            // so we should shutdown the write side of the `decryption_stream`, and
            // return the final poll result.
            if data.is_empty() {
                match Pin::new(self.as_mut().decryption_stream.as_mut().unwrap()).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                }
                
                return Pin::new(self.get_mut().decryption_stream.as_mut().unwrap()).poll_fill_buf(cx);
            }

            // If there is no delimiter, we don't have enough data to decrypt, so fallback to
            // polling the decryption stream, but do not advance the inner `BufReader` stream.

            let delimiter_index = find_next_delimiter(data);
            let Some(delimiter_index) = delimiter_index else {
                return Pin::new(self.get_mut().decryption_stream.as_mut().unwrap()).poll_fill_buf(cx);
            };

            // We have the encrypted data, so we can decrypt it.

            let encrypted_packet = &data[..delimiter_index];
            let Ok(nonce) = encrypted_packet[..Constant::SHARED_SECRET_NONCE_SIZE].try_into() else {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid nonce size when decrypting")));
            };
            let encrypted_data = &encrypted_packet[Constant::SHARED_SECRET_NONCE_SIZE..];

            let Ok(decrypted_data) = decrypt(key, encrypted_data, &nonce) else {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption failed")));
            };

            // We have the decrypted data, so we can write it to the `decryption_stream`.
            let pinned_decryption_stream = Pin::new(self.decryption_stream.as_mut().unwrap());
            let written = match pinned_decryption_stream.poll_write(cx, &decrypted_data) {
                Poll::Ready(Ok(written)) => written,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            };

            // Fail if the interim buffer is too small.
            if written < decrypted_data.len() {
                return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Decryption stream buffer overflow")));
            }

            let pinned_decryption_stream = Pin::new(self.decryption_stream.as_mut().unwrap());
            match pinned_decryption_stream.poll_flush(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            }

            // Since the data has successfully been written to the `decryption_stream`, we can consume it from the `inner` stream.
            let pinned_inner = Pin::new(&mut self.inner);
            pinned_inner.consume(delimiter_index + Constant::DELIMITER_SIZE);
        }

        // At this point, if there was data to decrypt, we have decrypted it; if not, we may have some data in the 
        // decrypted stream, so we just offload onto its `poll_fill_buf` method.;
        Pin::new(self.get_mut().decryption_stream.as_mut().unwrap()).poll_fill_buf(cx)
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        // In the unencrypted case, we can just consume the data from the `BufReader`,
        // and let it handle its internal structure.
        if self.shared_secret.is_none() {
            Pin::new(&mut self.inner).consume(amt);
            return;
        }

        // In the encrypted case, we only consume from the `decryption_stream`, since the 
        // `inner` stream is consumed in the `poll_fill_buf` method.

        Pin::new(self.decryption_stream.as_mut().unwrap()).consume(amt)
    }
}

impl<T> AsyncWrite for BuffedStream<T>
where 
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // In the unencrypted case, we can just write the data to the `BufReader`,
        // and let it handle its internal structure.
        if self.shared_secret.is_none() {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }
        
        // In the encrypted case, we need to encrypt the data, so use the
        // `poll_write` method to write to the underlying stream.

        // First, we need to pare down the data to the maximum size of the encrypted data, if needed.
        let max_size = Constant::BUFFER_SIZE - Constant::ENCRYPTION_OVERHEAD;
        let amt = std::cmp::min(buf.len(), max_size);
        let buf = &buf[..amt];

        // Get the actual encrypted data.
        let key = &self.shared_secret.unwrap();
        let encrypted_data = match encrypt(key, buf) {
            Ok(encrypted_data) => encrypted_data,
            Err(_) => return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Encryption failed"))),
        };

        // Create the encrypted packet.
        let encrypted_packet = [encrypted_data.nonce.as_ref(), &encrypted_data.data, Constant::DELIMITER].concat();

        // Write the encrypted data to the inner `BufReader`.
        let written = match Pin::new(&mut self.inner).poll_write(cx, &encrypted_packet) {
            Poll::Ready(Ok(written)) => written,
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        };

        // Check to make sure that the full write succeeded.
        if written < encrypted_packet.len() {
            return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Encrypted packet buffer overflow (on the inner stream): the author of this utility should add a flag to allow you to increase it")));
        }

        // Need to report the amount of data that was written _from the input_, not the _actual_ amount written to the inner stream.
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{base::Constant, utils::tests::generate_test_shared_secret};

    use super::BuffedStream;

    #[tokio::test]
    async fn test_unencrypted_buffed_stream() {
        let (client, mut server) = tokio::io::duplex(1024);
        
        let mut client_stream = BuffedStream::new(client);
        
        let data = b"Hello, world!";

        client_stream.write_all(data).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();

        assert_eq!(data, &received[..]);
    }

    #[tokio::test]
    async fn test_encrypted_buffed_stream() {
        let shared_secret = generate_test_shared_secret();

        let (client, mut server) = tokio::io::duplex(1024);
        let mut client_stream = BuffedStream::new(client).with_encryption(shared_secret);
        
        let data = b"Hello, world!";

        client_stream.write_all(data).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        server.read_to_end(&mut received).await.unwrap();

        assert_eq!(received.len(), 49);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream() {
        let shared_secret = generate_test_shared_secret();

        let (client, server) = tokio::io::duplex(1024);
        let mut client_stream = BuffedStream::new(client).with_encryption(shared_secret);
        let mut server_stream = BuffedStream::new(server).with_encryption(shared_secret);
        
        let data = b"Hello, world!";

        client_stream.write_all(data).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        server_stream.read_to_end(&mut received).await.unwrap();

        assert_eq!(data, &received[..]);
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream_with_multiple_packets() {
        let shared_secret = generate_test_shared_secret();

        let (client, server) = tokio::io::duplex(1024);
        let mut client_stream = BuffedStream::new(client).with_encryption(shared_secret);
        let mut server_stream = BuffedStream::new(server).with_encryption(shared_secret);
        
        let data1 = b"Hello, world!";
        let data2 = b"Hello, world!";

        client_stream.write_all(data1).await.unwrap();
        client_stream.write_all(data2).await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut received = Vec::new();
        server_stream.read_to_end(&mut received).await.unwrap();

        assert_eq!(data1.len() + data2.len(), received.len());
    }

    #[tokio::test]
    async fn test_e2e_encrypted_buffed_stream_with_large_data() {
        let shared_secret = generate_test_shared_secret();

        let (client, server) = tokio::io::duplex(Constant::BUFFER_SIZE);
        let mut client_stream = BuffedStream::new(client).with_encryption(shared_secret);
        let mut server_stream = BuffedStream::new(server).with_encryption(shared_secret);

        let data = b"Hello, world!";
        let data = data.repeat(10000);

        let data_clone = data.clone();

        let write_task = tokio::spawn(async move {
            client_stream.write_all(&data_clone).await.unwrap();
            client_stream.shutdown().await.unwrap();
        });

        let read_task = tokio::spawn(async move {
            let mut received = Vec::new();
            server_stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(data.len(), received.len());
        });

        tokio::select! {
            write_result = write_task => write_result.unwrap(),
            read_result = read_task => read_result.unwrap(),
        };
    }
}