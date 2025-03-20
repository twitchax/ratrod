use criterion::{Criterion, criterion_group, criterion_main};
use ratrodlib::{
    base::{Constant, ExchangeKeyPair, SharedSecret},
    buffed_stream::BuffedDuplexStream,
    protocol::{BincodeReceive, BincodeSend, ProtocolMessage},
    utils::{generate_challenge, generate_ephemeral_key_pair, generate_shared_secret},
};
use secrecy::ExposeSecret;

pub fn generate_test_ephemeral_key_pair() -> ExchangeKeyPair {
    generate_ephemeral_key_pair().unwrap()
}

pub fn generate_test_shared_secret() -> SharedSecret {
    let ephemeral_key_pair = generate_test_ephemeral_key_pair();
    let challenge = generate_challenge();

    generate_shared_secret(ephemeral_key_pair.private_key, ephemeral_key_pair.public_key.as_ref(), &challenge).unwrap()
}

async fn large_data_bench(encrypted: bool) {
    let (client, server) = tokio::io::duplex(Constant::BUFFER_SIZE);

    let (mut client, mut server) = if encrypted {
        let secret_box = generate_test_shared_secret();
        let shared_secret = secret_box.expose_secret();

        (
            BuffedDuplexStream::from(client).with_encryption(SharedSecret::init_with(|| *shared_secret)),
            BuffedDuplexStream::from(server).with_encryption(SharedSecret::init_with(|| *shared_secret)),
        )
    } else {
        (BuffedDuplexStream::from(client), BuffedDuplexStream::from(server))
    };

    let data = b"Hello, world!";
    let data = data.repeat(1000000);

    client.push(ProtocolMessage::Data(&data)).await.unwrap();
    client.close().await.unwrap();

    let guard = server.pull().await.unwrap();
    let ProtocolMessage::Data(received) = *guard.message() else {
        panic!("Failed to receive message");
    };

    assert_eq!(received, data);
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
