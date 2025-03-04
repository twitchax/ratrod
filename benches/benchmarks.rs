use criterion::{Criterion, criterion_group, criterion_main};
use futures::future::join_all;
use ratrodlib::{
    base::{Constant, ExchangeKeyPair, SharedSecret},
    buffed_stream::BuffedStream,
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret},
};
use secrecy::ExposeSecret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub fn generate_test_ephemeral_key_pair() -> ExchangeKeyPair {
    generate_ephemeral_key_pair().unwrap()
}

pub fn generate_test_shared_secret() -> SharedSecret {
    let ephemeral_key_pair = generate_test_ephemeral_key_pair();
    let challenge = generate_challenge();

    generate_shared_secret(ephemeral_key_pair.private_key, ephemeral_key_pair.public_key.as_ref().try_into().unwrap(), &challenge).unwrap()
}

async fn large_data_bench(encrypted: bool) {
    let (client, server) = tokio::io::duplex(Constant::BUFFER_SIZE);

    let (mut client, mut server) = if encrypted {
        let secret_box = generate_test_shared_secret();
        let shared_secret = secret_box.expose_secret();

        (
            BuffedStream::new(client).with_encryption(SharedSecret::init_with(|| *shared_secret)),
            BuffedStream::new(server).with_encryption(SharedSecret::init_with(|| *shared_secret)),
        )
    } else {
        (BuffedStream::new(client), BuffedStream::new(server))
    };

    let data = b"Hello, world!";
    let data = data.repeat(1000000);

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

fn bench(c: &mut Criterion) {
    c.bench_function("bench large data", |b| {
        b.iter(async || {
            large_data_bench(false).await;
        })
    });
    c.bench_function("bench encrypted large data", |b| {
        b.iter(async || {
            large_data_bench(true).await;
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
