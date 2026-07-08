# itu-isup

[![crates.io](https://img.shields.io/crates/v/itu-isup.svg)](https://crates.io/crates/itu-isup)
[![docs.rs](https://docs.rs/itu-isup/badge.svg)](https://docs.rs/itu-isup)
[![CI](https://github.com/Real-Time-Telecom-B-V/itu-isup/actions/workflows/ci.yaml/badge.svg)](https://github.com/Real-Time-Telecom-B-V/itu-isup/actions/workflows/ci.yaml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

An **ISUP (ISDN User Part) codec** per **ITU-T Q.763**, the SS7 call-control
protocol that sets up, supervises and releases circuit-switched trunks. ISUP is a
**direct MTP3-user** (Service Indicator 5): it rides MTP3 (or M3UA) straight, not
over SCCP/TCAP, and each message names a circuit by a point code plus a **Circuit
Identification Code (CIC)**. Pure Rust: encoders and decoders for the message body
(CIC, message type, and the mandatory-fixed / mandatory-variable / optional parts
with their pointer arithmetic and the end-of-optional-parameters marker) and the
Q.763 parameter values, **no async, no I/O**, so every consumer can unit-test
against it. It ships as **both** a Rust crate (`cargo add itu-isup`) and a Rust-backed
Python wheel (`pip install itu-isup`), built from one source tree and one version.

This is a **codec only**. It builds no Q.764 call state machine, does no CIC
management, and performs no ISUP↔SIP interworking, those belong to a separate
MGCF.

```rust
use itu_isup::{Message, Number, calling_party_category};

// Build an Initial Address Message on CIC 1 to a national number. Digits are
// synthetic (fictional +1-555 range).
let called = Number::called(3, 1, false, "5551234");
let iam = Message::iam(
    1,      // CIC
    0x00,   // nature of connection indicators
    0x2000, // forward call indicators
    calling_party_category::ORDINARY,
    0x00,   // transmission medium requirement (speech)
    &called,
)
.unwrap();

let wire = iam.encode().unwrap();
let decoded = Message::decode(&wire).unwrap();
assert_eq!(decoded.message_type, itu_isup::MessageType::Iam);
assert_eq!(decoded.mandatory_variable[0].as_number().unwrap().digits, "5551234");
```

```python
import itu_isup

called = itu_isup.Number.called("5551234", nature_of_address=3)
iam = itu_isup.Message.iam(1, called, forward_call_indicators=0x2000)

wire = iam.encode()                 # bytes
msg = itu_isup.decode(wire)             # -> Message
assert msg.message_type == itu_isup.MESSAGE_TYPE_IAM
```

## Where it fits

An encoded ISUP message is the payload (SIF) of an MTP3 Message Signal Unit. The
[`mtp3`](https://crates.io/crates/mtp3) crate frames it: `Message::to_msu(...)`
wraps the bytes as an `Mtp3Msu` with Service Indicator 5 (ISUP), and an MGCF
drives it over the `mtp3::Mtp3UserPart` SAP, native MTP3 over M2PA, or M3UA over
SCTP, exactly as SCCP does.

## Coverage

### Messages (Q.763 Table 4)

| Message | Code | Message | Code |
|---|---|---|---|
| IAM, Initial address | `0x01` | RSC, Reset circuit | `0x12` |
| ACM, Address complete | `0x06` | BLO, Blocking | `0x13` |
| CON, Connect | `0x07` | BLA, Blocking ack | `0x15` |
| ANM, Answer | `0x09` | UBL, Unblocking | `0x14` |
| CPG, Call progress | `0x2C` | UBA, Unblocking ack | `0x16` |
| REL, Release | `0x0C` | GRS, Circuit group reset | `0x17` |
| RLC, Release complete | `0x10` | GRA, Circuit group reset ack | `0x29` |
| SUS, Suspend | `0x0D` | CGB, Circuit group blocking | `0x18` |
| RES, Resume | `0x0E` | CGU, Circuit group unblocking | `0x19` |
| FOT, Forward transfer | `0x08` | CGBA, Circuit group blocking ack | `0x1A` |
| INR, Information request | `0x03` | CGUA, Circuit group unblocking ack | `0x1B` |
| INF, Information | `0x04` | | |

The `MessageType` table names the full Q.763 set (with an `Other(u8)`
fall-through); the message types above encode + decode with their mandatory and
optional parts.

### Parameters (Q.763 Table 5)

Structured types with typed encode/decode: **Called party number** (`0x04`),
**Calling party number** (`0x0A`), **Redirecting number** (`0x0B`), **Redirection
number** (`0x0C`), **Cause indicators** (`0x12`), **Range and status** (`0x16`).
Indicator parameters as typed builders: **Nature of connection indicators**
(`0x06`), **Forward call indicators** (`0x07`), **Backward call indicators**
(`0x11`), **Calling party's category** (`0x09`), **Transmission medium
requirement** (`0x02`), **Event information** (`0x24`), **Suspend/resume
indicators** (`0x22`), **Information request indicators** (`0x0E`), **Information
indicators** (`0x0F`), **Circuit group supervision message type** (`0x15`).
Carried verbatim: **User service information** (`0x1D`), **Redirection
information** (`0x13`). Any other parameter decodes as an opaque `(code, value)`
TLV, so unknown optional parameters round-trip losslessly. The `ParameterType`
table names the full Q.763 set.

The Q.764 procedures (call state machine, CIC management, timers) and ISUP↔SIP
interworking are **out of scope**, this crate is the wire codec. See
[`docs/OVERVIEW.md`](docs/OVERVIEW.md) for the module map and full public API.

## Validation

Encode vectors are **known-answer tested against the Wireshark (tshark) ITU-T
Q.763 ISUP dissector**, not against round-trips (a shared encode/decode bug passes
a round-trip). Each message is wrapped as the SIF of an MTP3 MSU with SI=5, written
into a LINKTYPE_MTP3 pcap and dissected with `tshark -V`; the test asserts the
decoded message type and parameter fields (called/calling digits, cause value,
nature of connection, …) and that the dissection is free of `Malformed` / expert
`Error` ([`tests/tshark_kat.rs`](tests/tshark_kat.rs), skipped when tshark is
absent). Round-trips and field checks that need no external tools live in
[`tests/integration.rs`](tests/integration.rs) and the module unit tests.

## Performance

Single-core, `cargo bench` ([`benches/codec.rs`](benches/codec.rs)); the codec is
allocation-light (a `Vec` per encoded message; parameter values on decode). Encode
+ decode of an IAM with a called and calling party, a Release with a cause, and a
Blocking message are all in the tens-of-nanoseconds range.

A counting-allocator [leak check](examples/leak_check.rs)
(`./scripts/mem_leak_test.sh`) hammers encode/decode of the IAM, Release and
circuit-supervision paths and asserts **live bytes stay flat** (Δ 0 over millions
of cycles). Both run in CI.

The Python wheel is the same Rust code behind PyO3; per-call overhead is the
Python↔Rust boundary, not the codec. The module is declared `gil_used = false`, so
it loads on free-threaded ("no-GIL") CPython 3.13t / 3.14t.

## Install

```bash
cargo add itu-isup     # Rust crate (zero pyo3 in the default build)
pip install itu-isup   # Rust-backed Python wheel
```

## Development

```bash
cargo test                              # unit + integration + doctests
cargo test --features python            # + the PyO3 binding face
cargo clippy --all-targets -- -D warnings
cargo bench --no-run
./scripts/mem_leak_test.sh              # live-bytes leak check (PASS/FAIL)
cargo deny check                        # advisories, licenses, sources

# Python wheel
maturin develop && pytest python/tests -q
```

## License

MIT, see [LICENSE](LICENSE).
