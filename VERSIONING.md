# Versioning

`itu-isup` follows [Semantic Versioning 2.0.0](https://semver.org/). The public API,
the `Message` type and its constructors, `MessageType` / `ParameterType`,
`Number`, `Parameter` / `CauseIndicators` / `RangeAndStatus`, the `bcd` functions,
`SERVICE_INDICATOR` / `encode_cic` / `decode_cic` / `Message::to_msu`, and
`IsupError`, is the contract.

## The git tag is the source of truth

`Cargo.toml`'s `version` matches the release tag; the release workflow's
`verify-version` job refuses to publish if they disagree. Bump `version`, commit,
tag `vX.Y.Z`, push the tag.

## Post-1.0 rule

- **MAJOR**, remove/rename/re-signature a `pub` item, or change documented
  wire-encoding or decode semantics.
- **MINOR**, backward-compatible additions (new message constructors, new
  `MessageType` / `ParameterType` constants, new parameter types or helper
  methods).
- **PATCH**, bug fixes, docs, behaviour-neutral dependency bumps.
