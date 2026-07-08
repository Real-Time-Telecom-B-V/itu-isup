//! Codec micro-benchmarks: ISUP message encode/decode.
//!
//! Run with `cargo bench`. Numbers feed the README "Performance" table.
//!
//! All fixtures are built from the public API, so the benches measure exactly the
//! work this crate does, the mandatory fixed part, the variable-part pointer
//! arithmetic, address-signal BCD packing, and the optional-part TLV walk, with
//! no I/O in the path. Digits are synthetic (fictional +1-555 range).

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use itu_isup::{calling_party_category, CauseIndicators, Message, MessageType, Number, Parameter};

/// An Initial Address Message carrying a called party number and an optional
/// calling party number, the fullest common set-up message.
fn iam() -> Message {
    let called = Number::called(4, 1, false, "15551234567");
    let calling = Number::calling(4, 1, false, 0, 3, "15559876543");
    Message::iam(
        1,
        0x00,
        0x2000,
        calling_party_category::ORDINARY,
        0x00,
        &called,
    )
    .expect("valid iam")
    .with_optional(Parameter::calling_party_number(&calling).expect("valid calling"))
}

/// A Release message with a cause, the smallest mandatory-variable case.
fn release() -> Message {
    Message::release(1, &CauseIndicators::new(1, 16))
}

/// A Blocking message, CIC + type only, the smallest message.
fn blocking() -> Message {
    Message::blocking(1)
}

fn bench_codec(c: &mut Criterion) {
    let iam = iam();
    let release = release();
    let blocking = blocking();

    let iam_bytes = iam.encode().expect("valid iam");
    let release_bytes = release.encode().expect("valid release");
    let blocking_bytes = blocking.encode().expect("valid blocking");

    // Sanity: message-type octets are what we expect.
    assert_eq!(iam_bytes[2], MessageType::Iam.value());
    assert_eq!(release_bytes[2], MessageType::Rel.value());

    let mut g = c.benchmark_group("codec");
    g.throughput(Throughput::Elements(1));

    g.bench_function("iam/decode", |b| {
        b.iter(|| Message::decode(&iam_bytes).unwrap())
    });
    g.bench_function("iam/encode", |b| {
        b.iter_batched(
            || iam.clone(),
            |m| m.encode().unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("release/decode", |b| {
        b.iter(|| Message::decode(&release_bytes).unwrap())
    });
    g.bench_function("release/encode", |b| {
        b.iter_batched(
            || release.clone(),
            |m| m.encode().unwrap(),
            BatchSize::SmallInput,
        )
    });
    g.bench_function("blocking/decode", |b| {
        b.iter(|| Message::decode(&blocking_bytes).unwrap())
    });
    g.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
