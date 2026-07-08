# itu-isup, overview

An **ISUP (ISDN User Part) codec** per **ITU-T Q.763**. ISUP is the SS7
call-control protocol that sets up, supervises and releases circuit-switched
trunks. It is a **direct MTP3-user** (Service Indicator 5), it rides MTP3 (or
M3UA) straight, not over SCCP/TCAP, and names each circuit by a point code plus a
Circuit Identification Code (CIC). This crate is a pure codec: no transport, no
async, no call state machine, it encodes/decodes bytes and nothing else.

## Module map

| Module | Public surface |
|---|---|
| `message` | `Message`, CIC + message type + the three parts; encode/decode and the typed constructors |
| `parameter` | `Parameter` (the `(code, value)` TLV), `CauseIndicators`, `RangeAndStatus`, and the typed value builders |
| `number` | `Number`, called / calling / redirecting / redirection number values |
| `types` | `MessageType` (Q.763 Table 4), `ParameterType` (Q.763 Table 5) |
| `bcd` | `encode_address_signals` / `decode_address_signals`, address-signal digit packing |
| `error` | `IsupError` (`thiserror`) |

The crate root re-exports the headline types and the MTP3-user glue
(`SERVICE_INDICATOR`, `encode_cic` / `decode_cic`, `Message::to_msu`), so
`use itu_isup::{Message, Number, MessageType};` is enough for typical use.

## The message body

An ISUP message on an MTP3-user payload is:

```text
0..1: Circuit Identification Code (CIC): 12-bit CIC + 4 spare, little-endian
2:    Message type code
Mandatory fixed part:    fixed-length parameter values, in order, no framing
Mandatory variable part: one 1-octet pointer per variable parameter (+ one for the
                         optional part, if any), then each variable value
                         length-prefixed
Optional part:           code + length + value TLVs, ending with the
                         end-of-optional-parameters octet (0x00)
```

Each pointer counts the octets from its own position to the length octet of the
parameter it addresses (or to the first optional parameter); the optional pointer
is `0` when no optional part is present. Every message type shares this
meta-structure, so `Message` holds three parameter lists and a per-type `Layout`
table (which mandatory fixed parameters and their lengths, which mandatory
variable parameters, and whether an optional part is allowed) drives the framing.
The table is sourced from ITU-T Q.763 and cross-checked against the Wireshark ISUP
dissector.

### Messages (`message`)

`Message` models the whole body. The typed constructors (`Message::iam`,
`Message::acm`, `Message::release`, `Message::circuit_group_blocking`, …) populate
the mandatory parts in Q.763 order; `with_optional` appends optional-part TLVs.
`encode` lays out the CIC, the message type, the mandatory fixed values, the
pointer block, the length-prefixed variable values and the optional TLVs;
`decode` walks the pointers back, validating every offset against the buffer
length and returning `IsupError` rather than panicking on a truncated frame.
`decode` returns `InvalidMessageType` for a type outside this codec's scope.

### Parameters (`parameter`, `number`)

Every ISUP parameter is a `Parameter { code, value }`. Typed builders produce the
value with the right code (`Parameter::called_party_number`,
`Parameter::cause_indicators`, `Parameter::forward_call_indicators`, …) and the
accessors parse it back (`as_number`, `as_cause_indicators`, `as_range_and_status`,
`as_u8`, `as_u16`). `Number` models the four number parameters (nature of address,
numbering plan, the parameter-specific second indicator octet, and the digits);
`CauseIndicators` models the Q.850 cause; `RangeAndStatus` the circuit-group range
and status bitmap.

### Address signals (`bcd`)

`encode_address_signals` / `decode_address_signals` pack address digits two per
octet, first digit in the low nibble, with the odd/even indicator selecting
whether the final high nibble is a digit or a filler.

## Scope

Codec only. The Q.764 procedures (call state machine, CIC management, timers) and
ISUP↔SIP interworking are out of scope; those belong to a separate MGCF.

## Where it fits

An encoded message is the SIF of an MTP3 Message Signal Unit. `Message::to_msu`
frames it as an `mtp3::Mtp3Msu` with Service Indicator 5 (ISUP); the MSU rides the
`mtp3::Mtp3UserPart` SAP, native MTP3 over M2PA links, or M3UA over SCTP, so the
codec stays pure and portable.
