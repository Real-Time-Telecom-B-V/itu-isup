# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). See
[VERSIONING.md](VERSIONING.md) for the policy.

## [1.0.0]

First release, the ISUP (ITU-T Q.763) message + parameter codec for the SS7
stack, a direct MTP3-user (Service Indicator 5).

### Added
- **`Message`**, encode/decode of the whole ISUP message body: the CIC (12-bit +
  4 spare, little-endian), the message type, and the mandatory-fixed /
  mandatory-variable / optional parts, with the pointer arithmetic and the
  end-of-optional-parameters marker. A per-message-type `Layout` table (sourced
  from Q.763, cross-checked against the Wireshark ISUP dissector) drives the
  framing. Typed constructors for **IAM, ACM, CON, ANM, CPG, REL, RLC, SUS, RES,
  FOT, INR, INF, BLO, BLA, UBL, UBA, RSC, GRS, GRA, CGB, CGU, CGBA, CGUA**.
- **`MessageType`** and **`ParameterType`**, the full Q.763 message-type and
  parameter-name tables as open enums with an `Other(u8)` fall-through.
- **`Number`**, called / calling / redirecting / redirection number values
  (nature of address, numbering plan, the parameter-specific indicators, and
  address-signal BCD digits).
- **`Parameter`**, the generic `(code, value)` TLV with typed builders and
  accessors, **`CauseIndicators`** (Q.850) and **`RangeAndStatus`**.
- **`bcd`**, ISUP address-signal digit packing (two per octet, low nibble first,
  odd/even filler).
- **`SERVICE_INDICATOR`**, `encode_cic` / `decode_cic`, and `Message::to_msu`,
  the MTP3-user glue that frames a message as an `mtp3::Mtp3Msu` with SI=5.
- **`IsupError`**, a `thiserror` enum covering the decode/encode failure modes.
- Encode vectors known-answer-tested against the Wireshark (tshark) Q.763 ISUP
  dissector; integration + unit tests covering round-trips, field checks and error
  paths; a runnable doctest on the crate root; a Rust-backed Python wheel exposing
  the same codec.

[1.0.0]: https://github.com/Real-Time-Telecom-B-V/itu-isup/releases/tag/v1.0.0
