//! ISUP messages (ITU-T Q.763): the [`Message`] type, the per-message-type
//! format table, and the encode / decode of the whole message body.
//!
//! An ISUP message on an MTP3-user payload is:
//!
//! ```ignore
//! 0..1: Circuit Identification Code (CIC): 12-bit CIC + 4 spare, little-endian
//! 2:    Message type code
//! Mandatory fixed part:    fixed-length parameter values, in order, no framing
//! Mandatory variable part: one 1-octet pointer per variable parameter (+ one for
//!                          the optional part, if any), then each variable value
//!                          length-prefixed
//! Optional part:           code + length + value TLVs, ending with the
//!                          end-of-optional-parameters octet (0x00)
//! ```
//!
//! Each pointer counts the octets from its own position to the length octet of
//! the parameter it addresses (or to the first optional parameter); the optional
//! pointer is 0 when there is no optional part. All message types share this
//! meta-structure, so [`Message`] holds the three parameter lists and a small
//! per-type [`Layout`] table (sourced from ITU-T Q.763 and cross-checked against
//! the Wireshark ISUP dissector) drives the framing.

use std::fmt;

use crate::error::IsupError;
use crate::number::Number;
use crate::parameter::{CauseIndicators, Parameter, RangeAndStatus};
use crate::types::{MessageType, ParameterType};

/// A fixed-length parameter slot in the mandatory fixed part.
struct FixedField {
    code: ParameterType,
    len: usize,
}

/// The Q.763 format of one message type: its mandatory fixed parameters (with
/// lengths), its mandatory variable parameters (in order), and whether it may
/// carry an optional part.
struct Layout {
    fixed: &'static [FixedField],
    variable: &'static [ParameterType],
    optional: bool,
}

use ParameterType as P;

// Mandatory fixed parts.
const IAM_FIXED: &[FixedField] = &[
    FixedField {
        code: P::NatureOfConnectionIndicators,
        len: 1,
    },
    FixedField {
        code: P::ForwardCallIndicators,
        len: 2,
    },
    FixedField {
        code: P::CallingPartysCategory,
        len: 1,
    },
    FixedField {
        code: P::TransmissionMediumRequirement,
        len: 1,
    },
];
const BACKWARD_ONLY: &[FixedField] = &[FixedField {
    code: P::BackwardCallIndicators,
    len: 2,
}];
const EVENT_ONLY: &[FixedField] = &[FixedField {
    code: P::EventInformation,
    len: 1,
}];
const SUSPEND_RESUME_ONLY: &[FixedField] = &[FixedField {
    code: P::SuspendResumeIndicators,
    len: 1,
}];
const INFO_REQ_ONLY: &[FixedField] = &[FixedField {
    code: P::InformationRequestIndicators,
    len: 2,
}];
const INFO_ONLY: &[FixedField] = &[FixedField {
    code: P::InformationIndicators,
    len: 2,
}];
const CGS_ONLY: &[FixedField] = &[FixedField {
    code: P::CircuitGroupSupervisionMessageType,
    len: 1,
}];

// Mandatory variable parts.
const CALLED_VAR: &[ParameterType] = &[P::CalledPartyNumber];
const CAUSE_VAR: &[ParameterType] = &[P::CauseIndicators];
const RANGE_VAR: &[ParameterType] = &[P::RangeAndStatus];

/// The Q.763 layout for a message type, or `None` for a type this codec does
/// not model.
fn message_layout(mt: MessageType) -> Option<Layout> {
    let l = |fixed, variable, optional| Layout {
        fixed,
        variable,
        optional,
    };
    Some(match mt {
        // Basic call control.
        MessageType::Iam => l(IAM_FIXED, CALLED_VAR, true),
        MessageType::Acm => l(BACKWARD_ONLY, &[], true),
        MessageType::Con => l(BACKWARD_ONLY, &[], true),
        MessageType::Anm => l(&[], &[], true),
        MessageType::Cpg => l(EVENT_ONLY, &[], true),
        MessageType::Rel => l(&[], CAUSE_VAR, true),
        MessageType::Rlc => l(&[], &[], true),
        MessageType::Sus => l(SUSPEND_RESUME_ONLY, &[], true),
        MessageType::Res => l(SUSPEND_RESUME_ONLY, &[], true),
        MessageType::Fot => l(&[], &[], true),
        MessageType::Inr => l(INFO_REQ_ONLY, &[], true),
        MessageType::Inf => l(INFO_ONLY, &[], true),
        // Circuit maintenance / supervision, no optional part.
        MessageType::Blo
        | MessageType::Bla
        | MessageType::Ubl
        | MessageType::Uba
        | MessageType::Rsc => l(&[], &[], false),
        MessageType::Grs => l(&[], RANGE_VAR, false),
        MessageType::Gra => l(&[], RANGE_VAR, false),
        MessageType::Cgb | MessageType::Cgu | MessageType::Cgba | MessageType::Cgua => {
            l(CGS_ONLY, RANGE_VAR, false)
        }
        _ => return None,
    })
}

/// An ISUP message: a Circuit Identification Code, a message type, and the three
/// parameter parts (mandatory fixed, mandatory variable, optional).
///
/// The mandatory parts are populated in Q.763 order by the constructors
/// ([`Message::iam`], [`Message::release`], …); the optional part is a TLV list
/// built with [`Message::with_optional`]. `encode` / `decode` handle the CIC,
/// the message type, the pointer arithmetic and the end-of-optional marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Circuit Identification Code (12 bits; the naming circuit for this call).
    pub cic: u16,
    /// Message type code.
    pub message_type: MessageType,
    /// Mandatory fixed-part parameters, in Q.763 order.
    pub mandatory_fixed: Vec<Parameter>,
    /// Mandatory variable-part parameters, in Q.763 order.
    pub mandatory_variable: Vec<Parameter>,
    /// Optional-part parameters (TLV), in send order.
    pub optional: Vec<Parameter>,
}

impl Message {
    /// Build an empty message of `message_type` on `cic` (no parameters). Use the
    /// typed constructors below for the mandatory parts.
    fn bare(message_type: MessageType, cic: u16) -> Self {
        Self {
            cic,
            message_type,
            mandatory_fixed: Vec::new(),
            mandatory_variable: Vec::new(),
            optional: Vec::new(),
        }
    }

    /// Append an optional parameter (builder style). Only meaningful for message
    /// types that carry an optional part.
    pub fn with_optional(mut self, parameter: Parameter) -> Self {
        self.optional.push(parameter);
        self
    }

    // ── Constructors: basic call control ────────────────────────────────────

    /// Initial Address Message (IAM): nature of connection, forward call
    /// indicators, calling party's category, transmission medium requirement,
    /// and the called party number.
    pub fn iam(
        cic: u16,
        nature_of_connection: u8,
        forward_call_indicators: u16,
        calling_partys_category: u8,
        transmission_medium_requirement: u8,
        called_party: &Number,
    ) -> Result<Self, IsupError> {
        let mut m = Self::bare(MessageType::Iam, cic);
        m.mandatory_fixed = vec![
            Parameter::nature_of_connection(nature_of_connection),
            Parameter::forward_call_indicators(forward_call_indicators),
            Parameter::calling_partys_category(calling_partys_category),
            Parameter::transmission_medium_requirement(transmission_medium_requirement),
        ];
        m.mandatory_variable = vec![Parameter::called_party_number(called_party)?];
        Ok(m)
    }

    /// Address Complete Message (ACM): backward call indicators.
    pub fn acm(cic: u16, backward_call_indicators: u16) -> Self {
        let mut m = Self::bare(MessageType::Acm, cic);
        m.mandatory_fixed = vec![Parameter::backward_call_indicators(
            backward_call_indicators,
        )];
        m
    }

    /// Connect (CON): backward call indicators.
    pub fn con(cic: u16, backward_call_indicators: u16) -> Self {
        let mut m = Self::bare(MessageType::Con, cic);
        m.mandatory_fixed = vec![Parameter::backward_call_indicators(
            backward_call_indicators,
        )];
        m
    }

    /// Answer (ANM): no mandatory parameters.
    pub fn anm(cic: u16) -> Self {
        Self::bare(MessageType::Anm, cic)
    }

    /// Call Progress (CPG): an event information indicator.
    pub fn cpg(cic: u16, event: u8) -> Self {
        let mut m = Self::bare(MessageType::Cpg, cic);
        m.mandatory_fixed = vec![Parameter::event_information(event)];
        m
    }

    /// Release (REL): the cause indicators.
    pub fn release(cic: u16, cause: &CauseIndicators) -> Self {
        let mut m = Self::bare(MessageType::Rel, cic);
        m.mandatory_variable = vec![Parameter::cause_indicators(cause)];
        m
    }

    /// Release Complete (RLC): no mandatory parameters.
    pub fn release_complete(cic: u16) -> Self {
        Self::bare(MessageType::Rlc, cic)
    }

    /// Suspend (SUS): a suspend/resume indicator.
    pub fn suspend(cic: u16, indicators: u8) -> Self {
        let mut m = Self::bare(MessageType::Sus, cic);
        m.mandatory_fixed = vec![Parameter::suspend_resume_indicators(indicators)];
        m
    }

    /// Resume (RES): a suspend/resume indicator.
    pub fn resume(cic: u16, indicators: u8) -> Self {
        let mut m = Self::bare(MessageType::Res, cic);
        m.mandatory_fixed = vec![Parameter::suspend_resume_indicators(indicators)];
        m
    }

    /// Forward Transfer (FOT): no mandatory parameters.
    pub fn forward_transfer(cic: u16) -> Self {
        Self::bare(MessageType::Fot, cic)
    }

    /// Information Request (INR): the information request indicators.
    pub fn information_request(cic: u16, indicators: u16) -> Self {
        let mut m = Self::bare(MessageType::Inr, cic);
        m.mandatory_fixed = vec![Parameter::information_request_indicators(indicators)];
        m
    }

    /// Information (INF): the information indicators.
    pub fn information(cic: u16, indicators: u16) -> Self {
        let mut m = Self::bare(MessageType::Inf, cic);
        m.mandatory_fixed = vec![Parameter::information_indicators(indicators)];
        m
    }

    // ── Constructors: circuit maintenance / supervision ─────────────────────

    /// Blocking (BLO): no parameters.
    pub fn blocking(cic: u16) -> Self {
        Self::bare(MessageType::Blo, cic)
    }

    /// Blocking Acknowledgement (BLA): no parameters.
    pub fn blocking_ack(cic: u16) -> Self {
        Self::bare(MessageType::Bla, cic)
    }

    /// Unblocking (UBL): no parameters.
    pub fn unblocking(cic: u16) -> Self {
        Self::bare(MessageType::Ubl, cic)
    }

    /// Unblocking Acknowledgement (UBA): no parameters.
    pub fn unblocking_ack(cic: u16) -> Self {
        Self::bare(MessageType::Uba, cic)
    }

    /// Reset Circuit (RSC): no parameters.
    pub fn reset_circuit(cic: u16) -> Self {
        Self::bare(MessageType::Rsc, cic)
    }

    /// Circuit Group Reset (GRS): a range (no status subfield).
    pub fn circuit_group_reset(cic: u16, range_and_status: &RangeAndStatus) -> Self {
        let mut m = Self::bare(MessageType::Grs, cic);
        m.mandatory_variable = vec![Parameter::range_and_status(range_and_status)];
        m
    }

    /// Circuit Group Reset Acknowledgement (GRA): a range and status.
    pub fn circuit_group_reset_ack(cic: u16, range_and_status: &RangeAndStatus) -> Self {
        let mut m = Self::bare(MessageType::Gra, cic);
        m.mandatory_variable = vec![Parameter::range_and_status(range_and_status)];
        m
    }

    /// One of the four circuit-group blocking/unblocking messages (CGB, CGU,
    /// CGBA, CGUA): the supervision-message-type indicator and a range + status.
    fn circuit_group_supervision(
        message_type: MessageType,
        cic: u16,
        supervision: u8,
        range_and_status: &RangeAndStatus,
    ) -> Self {
        let mut m = Self::bare(message_type, cic);
        m.mandatory_fixed = vec![Parameter::circuit_group_supervision(supervision)];
        m.mandatory_variable = vec![Parameter::range_and_status(range_and_status)];
        m
    }

    /// Circuit Group Blocking (CGB).
    pub fn circuit_group_blocking(cic: u16, supervision: u8, rns: &RangeAndStatus) -> Self {
        Self::circuit_group_supervision(MessageType::Cgb, cic, supervision, rns)
    }

    /// Circuit Group Unblocking (CGU).
    pub fn circuit_group_unblocking(cic: u16, supervision: u8, rns: &RangeAndStatus) -> Self {
        Self::circuit_group_supervision(MessageType::Cgu, cic, supervision, rns)
    }

    /// Circuit Group Blocking Acknowledgement (CGBA).
    pub fn circuit_group_blocking_ack(cic: u16, supervision: u8, rns: &RangeAndStatus) -> Self {
        Self::circuit_group_supervision(MessageType::Cgba, cic, supervision, rns)
    }

    /// Circuit Group Unblocking Acknowledgement (CGUA).
    pub fn circuit_group_unblocking_ack(cic: u16, supervision: u8, rns: &RangeAndStatus) -> Self {
        Self::circuit_group_supervision(MessageType::Cgua, cic, supervision, rns)
    }

    // ── Accessors ───────────────────────────────────────────────────────────

    /// The first parameter with `code` from any part (fixed, variable, then
    /// optional).
    pub fn find(&self, code: ParameterType) -> Option<&Parameter> {
        self.mandatory_fixed
            .iter()
            .chain(&self.mandatory_variable)
            .chain(&self.optional)
            .find(|p| p.code == code)
    }

    /// The first optional parameter with `code`.
    pub fn optional(&self, code: ParameterType) -> Option<&Parameter> {
        self.optional.iter().find(|p| p.code == code)
    }

    // ── Codec ───────────────────────────────────────────────────────────────

    /// Encode the whole message body (CIC, message type, all three parts) as it
    /// rides an MTP3-user payload.
    pub fn encode(&self) -> Result<Vec<u8>, IsupError> {
        let layout = message_layout(self.message_type)
            .ok_or_else(|| IsupError::InvalidMessageType(self.message_type.value()))?;

        if self.mandatory_fixed.len() != layout.fixed.len() {
            return Err(IsupError::InvalidParameter(format!(
                "{} needs {} mandatory fixed parameter(s), got {}",
                self.message_type,
                layout.fixed.len(),
                self.mandatory_fixed.len()
            )));
        }
        if self.mandatory_variable.len() != layout.variable.len() {
            return Err(IsupError::InvalidParameter(format!(
                "{} needs {} mandatory variable parameter(s), got {}",
                self.message_type,
                layout.variable.len(),
                self.mandatory_variable.len()
            )));
        }
        if !layout.optional && !self.optional.is_empty() {
            return Err(IsupError::InvalidParameter(format!(
                "{} carries no optional part",
                self.message_type
            )));
        }

        let mut buf = Vec::new();
        // CIC: 12-bit value + 4 spare bits, little-endian.
        buf.push((self.cic & 0xFF) as u8);
        buf.push(((self.cic >> 8) & 0x0F) as u8);
        buf.push(self.message_type.value());

        // Mandatory fixed part.
        for (field, param) in layout.fixed.iter().zip(&self.mandatory_fixed) {
            if param.value.len() != field.len {
                return Err(IsupError::BadParameterLength {
                    code: field.code.value(),
                    expected: field.len,
                    actual: param.value.len(),
                });
            }
            buf.extend_from_slice(&param.value);
        }

        // Pointer block: one pointer per variable parameter, plus one for the
        // optional part if the type carries one.
        let n_pointers = self.mandatory_variable.len() + usize::from(layout.optional);
        let pointer_block_start = buf.len();
        buf.resize(pointer_block_start + n_pointers, 0);

        // Mandatory variable part: each pointer counts octets from its own
        // position to the length octet it addresses.
        for (i, param) in self.mandatory_variable.iter().enumerate() {
            let value_pos = buf.len();
            let ptr_pos = pointer_block_start + i;
            buf[ptr_pos] = (value_pos - ptr_pos) as u8;
            buf.push(param.value.len() as u8);
            buf.extend_from_slice(&param.value);
        }

        // Optional part.
        if layout.optional {
            let opt_ptr_pos = pointer_block_start + self.mandatory_variable.len();
            if self.optional.is_empty() {
                buf[opt_ptr_pos] = 0;
            } else {
                let opt_pos = buf.len();
                buf[opt_ptr_pos] = (opt_pos - opt_ptr_pos) as u8;
                for param in &self.optional {
                    buf.push(param.code.value());
                    buf.push(param.value.len() as u8);
                    buf.extend_from_slice(&param.value);
                }
                buf.push(ParameterType::EndOfOptionalParameters.value());
            }
        }

        Ok(buf)
    }

    /// Decode a whole ISUP message body from an MTP3-user payload (CIC, message
    /// type, and the three parts). Returns [`IsupError::InvalidMessageType`] for
    /// a message type this codec does not model.
    pub fn decode(bytes: &[u8]) -> Result<Self, IsupError> {
        if bytes.len() < 3 {
            return Err(IsupError::TooShort {
                expected: 3,
                actual: bytes.len(),
            });
        }
        let cic = (bytes[0] as u16) | (((bytes[1] & 0x0F) as u16) << 8);
        let message_type = MessageType::from_u8(bytes[2]);
        let layout = message_layout(message_type).ok_or(IsupError::InvalidMessageType(bytes[2]))?;

        // Pointers are relative to their own octet within `rest` (the bytes after
        // the message type), which is also the coordinate system Q.763 uses.
        let rest = &bytes[3..];
        let mut i = 0usize;

        let mut mandatory_fixed = Vec::with_capacity(layout.fixed.len());
        for field in layout.fixed {
            let end = i + field.len;
            if end > rest.len() {
                return Err(IsupError::TooShort {
                    expected: 3 + end,
                    actual: bytes.len(),
                });
            }
            mandatory_fixed.push(Parameter::new(field.code, rest[i..end].to_vec()));
            i = end;
        }

        let pointer_block_start = i;
        let n_pointers = layout.variable.len() + usize::from(layout.optional);
        if pointer_block_start + n_pointers > rest.len() {
            return Err(IsupError::TooShort {
                expected: 3 + pointer_block_start + n_pointers,
                actual: bytes.len(),
            });
        }

        let mut mandatory_variable = Vec::with_capacity(layout.variable.len());
        for (k, code) in layout.variable.iter().enumerate() {
            let ptr_pos = pointer_block_start + k;
            let ptr = rest[ptr_pos] as usize;
            if ptr == 0 {
                return Err(IsupError::InvalidParameter(format!(
                    "mandatory variable parameter {} has a zero pointer",
                    code
                )));
            }
            let len_pos = ptr_pos + ptr;
            if len_pos >= rest.len() {
                return Err(IsupError::PointerOutOfRange {
                    offset: 3 + len_pos,
                    len: bytes.len(),
                });
            }
            let plen = rest[len_pos] as usize;
            let vstart = len_pos + 1;
            let vend = vstart + plen;
            if vend > rest.len() {
                return Err(IsupError::PointerOutOfRange {
                    offset: 3 + vend,
                    len: bytes.len(),
                });
            }
            mandatory_variable.push(Parameter::new(*code, rest[vstart..vend].to_vec()));
        }

        let mut optional = Vec::new();
        if layout.optional {
            let opt_ptr_pos = pointer_block_start + layout.variable.len();
            let ptr = rest[opt_ptr_pos] as usize;
            if ptr != 0 {
                let mut o = opt_ptr_pos + ptr;
                loop {
                    if o >= rest.len() {
                        // Ran out before the end-of-optional marker: tolerate it
                        // as the end of the optional part.
                        break;
                    }
                    let code = rest[o];
                    if code == ParameterType::EndOfOptionalParameters.value() {
                        break;
                    }
                    if o + 1 >= rest.len() {
                        return Err(IsupError::TooShort {
                            expected: 3 + o + 2,
                            actual: bytes.len(),
                        });
                    }
                    let plen = rest[o + 1] as usize;
                    let vstart = o + 2;
                    let vend = vstart + plen;
                    if vend > rest.len() {
                        return Err(IsupError::PointerOutOfRange {
                            offset: 3 + vend,
                            len: bytes.len(),
                        });
                    }
                    optional.push(Parameter::new(
                        ParameterType::from_u8(code),
                        rest[vstart..vend].to_vec(),
                    ));
                    o = vend;
                }
            }
        }

        Ok(Self {
            cic,
            message_type,
            mandatory_fixed,
            mandatory_variable,
            optional,
        })
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} [cic={}, fixed={}, variable={}, optional={}]",
            self.message_type,
            self.cic,
            self.mandatory_fixed.len(),
            self.mandatory_variable.len(),
            self.optional.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parameter::{calling_party_category, event_information};

    // ── Known-answer encode vectors ─────────────────────────────────────────
    // Each byte string below was dissected clean by the Wireshark (tshark)
    // ITU-T Q.763 ISUP dissector (see tests/tshark_kat.rs), so asserting
    // `encode() == vector` checks the wire layout against an independent oracle,
    // not a round-trip.

    #[test]
    fn iam_matches_q763_vector() {
        // CIC 1, nature of connection 0x00, forward call indicators 0x2000,
        // ordinary calling category, speech, called party 5551234 (national).
        let called = Number::called(3, 1, false, "5551234");
        let iam = Message::iam(
            1,
            0x00,
            0x2000,
            calling_party_category::ORDINARY,
            0x00,
            &called,
        )
        .unwrap();
        let expected = hex::decode("0100010020000a00020006831055153204").unwrap();
        assert_eq!(iam.encode().unwrap(), expected);
        let decoded = Message::decode(&expected).unwrap();
        assert_eq!(decoded, iam);
        assert_eq!(decoded.cic, 1);
        assert_eq!(decoded.message_type, MessageType::Iam);
        assert_eq!(
            decoded.mandatory_variable[0].as_number().unwrap().digits,
            "5551234"
        );
    }

    #[test]
    fn release_matches_q763_vector() {
        // CIC 1, cause: location 1, cause value 16 (normal call clearing).
        let cause = CauseIndicators::new(1, 16);
        let rel = Message::release(1, &cause);
        let expected = hex::decode("01000c0200028190").unwrap();
        assert_eq!(rel.encode().unwrap(), expected);
        let decoded = Message::decode(&expected).unwrap();
        assert_eq!(decoded, rel);
        assert_eq!(
            decoded.mandatory_variable[0]
                .as_cause_indicators()
                .unwrap()
                .cause_value,
            16
        );
    }

    #[test]
    fn blocking_is_cic_and_type_only() {
        let blo = Message::blocking(5);
        let expected = hex::decode("050013").unwrap();
        assert_eq!(blo.encode().unwrap(), expected);
        assert_eq!(Message::decode(&expected).unwrap(), blo);
    }

    #[test]
    fn circuit_group_reset_range_only() {
        let grs = Message::circuit_group_reset(1, &RangeAndStatus::range_only(4));
        let expected = hex::decode("010017010104").unwrap();
        assert_eq!(grs.encode().unwrap(), expected);
        let decoded = Message::decode(&expected).unwrap();
        assert_eq!(decoded, grs);
        assert_eq!(
            decoded.mandatory_variable[0]
                .as_range_and_status()
                .unwrap()
                .circuits(),
            5
        );
    }

    #[test]
    fn circuit_group_blocking_fixed_plus_variable() {
        let cgb =
            Message::circuit_group_blocking(1, 0x00, &RangeAndStatus::with_status(3, vec![0x0F]));
        let expected = hex::decode("010018000102030f").unwrap();
        assert_eq!(cgb.encode().unwrap(), expected);
        assert_eq!(Message::decode(&expected).unwrap(), cgb);
    }

    #[test]
    fn answer_is_optional_pointer_only() {
        // ANM has no mandatory parts, only the optional-part pointer (0 here).
        let anm = Message::anm(7);
        let expected = hex::decode("07000900").unwrap();
        assert_eq!(anm.encode().unwrap(), expected);
        assert_eq!(Message::decode(&expected).unwrap(), anm);
    }

    #[test]
    fn iam_with_calling_party_optional_round_trips() {
        let called = Number::called(4, 1, false, "15551234567");
        let calling = Number::calling(4, 1, false, 0, 3, "15559876543");
        let iam = Message::iam(
            42,
            0x00,
            0x2000,
            calling_party_category::ORDINARY,
            0x00,
            &called,
        )
        .unwrap()
        .with_optional(Parameter::calling_party_number(&calling).unwrap());
        let wire = iam.encode().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded, iam);
        let got = decoded
            .optional(ParameterType::CallingPartyNumber)
            .unwrap()
            .as_number()
            .unwrap();
        assert_eq!(got.digits, "15559876543");
    }

    #[test]
    fn cpg_carries_event_information() {
        let cpg = Message::cpg(3, event_information::ALERTING);
        let decoded = Message::decode(&cpg.encode().unwrap()).unwrap();
        assert_eq!(decoded.mandatory_fixed[0].as_u8().unwrap(), 0x01);
        assert_eq!(decoded.optional.len(), 0);
    }

    #[test]
    fn decode_rejects_unmodelled_type() {
        // COT (0x05) is a valid Q.763 type but out of this codec's scope.
        assert!(matches!(
            Message::decode(&[0x01, 0x00, 0x05]),
            Err(IsupError::InvalidMessageType(0x05))
        ));
    }

    #[test]
    fn decode_rejects_truncated() {
        assert!(matches!(
            Message::decode(&[0x01, 0x00]),
            Err(IsupError::TooShort { .. })
        ));
        // IAM claiming a called-party pointer past the buffer end.
        assert!(matches!(
            Message::decode(&[0x01, 0x00, 0x01, 0x00, 0x20, 0x00, 0x0A, 0x00, 0x7F, 0x00]),
            Err(IsupError::PointerOutOfRange { .. })
        ));
    }

    #[test]
    fn every_supported_type_round_trips() {
        let rns = RangeAndStatus::with_status(3, vec![0x0F]);
        let cause = CauseIndicators::new(1, 16);
        let called = Number::called(3, 1, false, "5551234");
        let messages = vec![
            Message::iam(1, 0, 0x2000, 0x0A, 0, &called).unwrap(),
            Message::acm(1, 0x1010),
            Message::con(1, 0x1010),
            Message::anm(1),
            Message::cpg(1, 1),
            Message::release(1, &cause),
            Message::release_complete(1),
            Message::suspend(1, 0x01),
            Message::resume(1, 0x01),
            Message::forward_transfer(1),
            Message::information_request(1, 0x0001),
            Message::information(1, 0x0001),
            Message::blocking(1),
            Message::blocking_ack(1),
            Message::unblocking(1),
            Message::unblocking_ack(1),
            Message::reset_circuit(1),
            Message::circuit_group_reset(1, &RangeAndStatus::range_only(4)),
            Message::circuit_group_reset_ack(1, &rns),
            Message::circuit_group_blocking(1, 0, &rns),
            Message::circuit_group_unblocking(1, 0, &rns),
            Message::circuit_group_blocking_ack(1, 0, &rns),
            Message::circuit_group_unblocking_ack(1, 0, &rns),
        ];
        for m in messages {
            let wire = m.encode().unwrap();
            assert_eq!(Message::decode(&wire).unwrap(), m, "round-trip {m}");
        }
    }
}
