//! ISUP parameters: the generic [`Parameter`] TLV plus typed builders and
//! parsers for the parameter values this codec understands (ITU-T Q.763 §3).
//!
//! Every ISUP parameter is a `(code, value)` pair. On the wire the value appears
//! bare in the mandatory fixed part, length-prefixed in the mandatory variable
//! part, and code + length prefixed in the optional part; [`Parameter`] carries
//! only the code and the raw value octets, and [`crate::message`] lays out the
//! framing. The typed constructors ([`Parameter::called_party_number`],
//! [`Parameter::cause_indicators`], …) build a value with the correct code, and
//! the accessors ([`Parameter::as_number`], [`Parameter::as_cause_indicators`],
//! …) parse it back.

use crate::error::IsupError;
use crate::number::Number;
use crate::types::ParameterType;

/// Well-known [`ParameterType::CallingPartysCategory`] values (Q.763 §3.11).
pub mod calling_party_category {
    /// Ordinary calling subscriber.
    pub const ORDINARY: u8 = 0x0A;
    /// Calling subscriber with priority.
    pub const PRIORITY: u8 = 0x0B;
    /// Data call (voice-band data).
    pub const DATA_CALL: u8 = 0x0C;
    /// Test call.
    pub const TEST_CALL: u8 = 0x0D;
    /// Payphone.
    pub const PAYPHONE: u8 = 0x0F;
}

/// Well-known [`ParameterType::TransmissionMediumRequirement`] values (Q.763 §3.54).
pub mod transmission_medium_requirement {
    /// Speech.
    pub const SPEECH: u8 = 0x00;
    /// 64 kbit/s unrestricted.
    pub const UNRESTRICTED_64K: u8 = 0x02;
    /// 3.1 kHz audio.
    pub const AUDIO_3_1_KHZ: u8 = 0x03;
}

/// Well-known [`ParameterType::EventInformation`] event indicators (Q.763 §3.21).
pub mod event_information {
    /// ALERTING.
    pub const ALERTING: u8 = 0x01;
    /// PROGRESS.
    pub const PROGRESS: u8 = 0x02;
    /// In-band information or an appropriate pattern is now available.
    pub const IN_BAND_INFO: u8 = 0x03;
    /// Call forwarded on busy.
    pub const CALL_FORWARDED_BUSY: u8 = 0x04;
    /// Call forwarded on no reply.
    pub const CALL_FORWARDED_NO_REPLY: u8 = 0x05;
    /// Call forwarded unconditional.
    pub const CALL_FORWARDED_UNCONDITIONAL: u8 = 0x06;
}

/// A decoded ISUP **Cause indicators** value (Q.763 §3.12 / Q.850), the payload
/// of a Release or Release-complete message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CauseIndicators {
    /// Location (4 bits): 0 = user, 1 = private network serving the local user,
    /// 2 = public network serving the local user, etc.
    pub location: u8,
    /// Coding standard (2 bits): 0 = ITU-T.
    pub coding_standard: u8,
    /// Cause value (7 bits), per ITU-T Q.850 (e.g. 16 = normal call clearing,
    /// 17 = user busy, 1 = unallocated number).
    pub cause_value: u8,
    /// Optional diagnostic octets.
    pub diagnostics: Vec<u8>,
}

impl CauseIndicators {
    /// Build a cause with coding standard 0 (ITU-T) and no diagnostics.
    pub fn new(location: u8, cause_value: u8) -> Self {
        Self {
            location,
            coding_standard: 0,
            cause_value,
            diagnostics: Vec::new(),
        }
    }

    /// Encode to the parameter value octets.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(2 + self.diagnostics.len());
        // Octet 1: ext(1) | coding standard(2) | spare(1)=0 | location(4).
        buf.push(0x80 | ((self.coding_standard & 0x03) << 5) | (self.location & 0x0F));
        // Octet 2: ext(1) | cause value(7).
        buf.push(0x80 | (self.cause_value & 0x7F));
        buf.extend_from_slice(&self.diagnostics);
        buf
    }

    /// Decode from the parameter value octets.
    pub fn decode(bytes: &[u8]) -> Result<Self, IsupError> {
        if bytes.len() < 2 {
            return Err(IsupError::TooShort {
                expected: 2,
                actual: bytes.len(),
            });
        }
        let location = bytes[0] & 0x0F;
        let coding_standard = (bytes[0] >> 5) & 0x03;
        let cause_value = bytes[1] & 0x7F;
        Ok(Self {
            location,
            coding_standard,
            cause_value,
            diagnostics: bytes[2..].to_vec(),
        })
    }
}

/// A decoded ISUP **Range and status** value (Q.763 §3.43), carried by the
/// circuit-group supervision messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeAndStatus {
    /// The range indicator octet as it appears on the wire: the number of
    /// affected circuits is `range + 1` (see [`RangeAndStatus::circuits`]).
    pub range: u8,
    /// The per-circuit status bitmap (one bit per circuit in the range, LSB
    /// first). Empty for Circuit Group Reset (GRS), which carries only a range.
    pub status: Vec<u8>,
}

impl RangeAndStatus {
    /// Build a range-only value (no status subfield), as used by GRS. `range` is
    /// the wire value: `circuits - 1`.
    pub fn range_only(range: u8) -> Self {
        Self {
            range,
            status: Vec::new(),
        }
    }

    /// Build a value with a range and an explicit status bitmap, as used by the
    /// circuit-group blocking / unblocking / reset-acknowledgement messages.
    pub fn with_status(range: u8, status: Vec<u8>) -> Self {
        Self { range, status }
    }

    /// The number of circuits the range covers (`range + 1`).
    pub fn circuits(&self) -> u16 {
        self.range as u16 + 1
    }

    /// Encode to the parameter value octets (range octet then status bitmap).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.status.len());
        buf.push(self.range);
        buf.extend_from_slice(&self.status);
        buf
    }

    /// Decode from the parameter value octets.
    pub fn decode(bytes: &[u8]) -> Result<Self, IsupError> {
        if bytes.is_empty() {
            return Err(IsupError::TooShort {
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            range: bytes[0],
            status: bytes[1..].to_vec(),
        })
    }
}

/// An ISUP parameter: a name code plus its raw value octets (no length prefix,
/// no end-of-optional marker, [`crate::message`] adds the framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parameter {
    /// The parameter name code.
    pub code: ParameterType,
    /// The raw value octets.
    pub value: Vec<u8>,
}

impl Parameter {
    /// Build a parameter from a code and raw value octets.
    pub fn new(code: ParameterType, value: Vec<u8>) -> Self {
        Self { code, value }
    }

    // ── Fixed indicator parameters ──────────────────────────────────────────

    /// Nature of connection indicators (Q.763 §3.35), one octet.
    pub fn nature_of_connection(indicators: u8) -> Self {
        Self::new(
            ParameterType::NatureOfConnectionIndicators,
            vec![indicators],
        )
    }

    /// Forward call indicators (Q.763 §3.23), two octets (big-endian).
    pub fn forward_call_indicators(indicators: u16) -> Self {
        Self::new(
            ParameterType::ForwardCallIndicators,
            indicators.to_be_bytes().to_vec(),
        )
    }

    /// Backward call indicators (Q.763 §3.5), two octets (big-endian).
    pub fn backward_call_indicators(indicators: u16) -> Self {
        Self::new(
            ParameterType::BackwardCallIndicators,
            indicators.to_be_bytes().to_vec(),
        )
    }

    /// Calling party's category (Q.763 §3.11), one octet. See
    /// [`calling_party_category`] for named values.
    pub fn calling_partys_category(category: u8) -> Self {
        Self::new(ParameterType::CallingPartysCategory, vec![category])
    }

    /// Transmission medium requirement (Q.763 §3.54), one octet. See
    /// [`transmission_medium_requirement`] for named values.
    pub fn transmission_medium_requirement(tmr: u8) -> Self {
        Self::new(ParameterType::TransmissionMediumRequirement, vec![tmr])
    }

    /// Event information (Q.763 §3.21), one octet. See [`event_information`] for
    /// named values.
    pub fn event_information(event: u8) -> Self {
        Self::new(ParameterType::EventInformation, vec![event])
    }

    /// Suspend/resume indicators (Q.763 §3.52), one octet.
    pub fn suspend_resume_indicators(indicators: u8) -> Self {
        Self::new(ParameterType::SuspendResumeIndicators, vec![indicators])
    }

    /// Information request indicators (Q.763 §3.29), two octets (big-endian).
    pub fn information_request_indicators(indicators: u16) -> Self {
        Self::new(
            ParameterType::InformationRequestIndicators,
            indicators.to_be_bytes().to_vec(),
        )
    }

    /// Information indicators (Q.763 §3.28), two octets (big-endian).
    pub fn information_indicators(indicators: u16) -> Self {
        Self::new(
            ParameterType::InformationIndicators,
            indicators.to_be_bytes().to_vec(),
        )
    }

    /// Circuit group supervision message type indicator (Q.763 §3.13), one
    /// octet: 0 = maintenance-oriented, 1 = hardware-failure-oriented.
    pub fn circuit_group_supervision(indicator: u8) -> Self {
        Self::new(
            ParameterType::CircuitGroupSupervisionMessageType,
            vec![indicator & 0x03],
        )
    }

    /// User service information (Q.763 §3.57), a Q.931 bearer-capability value
    /// carried verbatim.
    pub fn user_service_information(value: &[u8]) -> Self {
        Self::new(ParameterType::UserServiceInformation, value.to_vec())
    }

    /// Redirection information (Q.763 §3.45), carried verbatim.
    pub fn redirection_information(value: &[u8]) -> Self {
        Self::new(ParameterType::RedirectionInformation, value.to_vec())
    }

    // ── Structured parameters ───────────────────────────────────────────────

    /// Called party number (Q.763 §3.9).
    pub fn called_party_number(number: &Number) -> Result<Self, IsupError> {
        Ok(Self::new(
            ParameterType::CalledPartyNumber,
            number.encode()?,
        ))
    }

    /// Calling party number (Q.763 §3.10).
    pub fn calling_party_number(number: &Number) -> Result<Self, IsupError> {
        Ok(Self::new(
            ParameterType::CallingPartyNumber,
            number.encode()?,
        ))
    }

    /// Redirecting number (Q.763 §3.44).
    pub fn redirecting_number(number: &Number) -> Result<Self, IsupError> {
        Ok(Self::new(
            ParameterType::RedirectingNumber,
            number.encode()?,
        ))
    }

    /// Redirection number (Q.763 §3.46).
    pub fn redirection_number(number: &Number) -> Result<Self, IsupError> {
        Ok(Self::new(
            ParameterType::RedirectionNumber,
            number.encode()?,
        ))
    }

    /// Cause indicators (Q.763 §3.12).
    pub fn cause_indicators(cause: &CauseIndicators) -> Self {
        Self::new(ParameterType::CauseIndicators, cause.encode())
    }

    /// Range and status (Q.763 §3.43).
    pub fn range_and_status(rns: &RangeAndStatus) -> Self {
        Self::new(ParameterType::RangeAndStatus, rns.encode())
    }

    // ── Accessors ───────────────────────────────────────────────────────────

    /// Parse the value as a [`Number`] (called / calling / redirecting /
    /// redirection number).
    pub fn as_number(&self) -> Result<Number, IsupError> {
        Number::decode(&self.value)
    }

    /// Parse the value as [`CauseIndicators`].
    pub fn as_cause_indicators(&self) -> Result<CauseIndicators, IsupError> {
        CauseIndicators::decode(&self.value)
    }

    /// Parse the value as [`RangeAndStatus`].
    pub fn as_range_and_status(&self) -> Result<RangeAndStatus, IsupError> {
        RangeAndStatus::decode(&self.value)
    }

    /// The value as a single octet (for the one-octet indicator parameters).
    pub fn as_u8(&self) -> Result<u8, IsupError> {
        match self.value.as_slice() {
            [b] => Ok(*b),
            _ => Err(IsupError::BadParameterLength {
                code: self.code.value(),
                expected: 1,
                actual: self.value.len(),
            }),
        }
    }

    /// The value as a big-endian `u16` (for the two-octet indicator parameters).
    pub fn as_u16(&self) -> Result<u16, IsupError> {
        match self.value.as_slice() {
            [hi, lo] => Ok(u16::from_be_bytes([*hi, *lo])),
            _ => Err(IsupError::BadParameterLength {
                code: self.code.value(),
                expected: 2,
                actual: self.value.len(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cause_indicators_round_trip() {
        // Location 1 (private network serving local user), cause 16 (normal
        // call clearing).
        let cause = CauseIndicators::new(1, 16);
        let bytes = cause.encode();
        assert_eq!(bytes, vec![0x81, 0x90]);
        let back = CauseIndicators::decode(&bytes).unwrap();
        assert_eq!(back, cause);
        assert_eq!(back.cause_value, 16);
    }

    #[test]
    fn range_and_status_range_only() {
        let rns = RangeAndStatus::range_only(4);
        assert_eq!(rns.encode(), vec![0x04]);
        assert_eq!(rns.circuits(), 5);
        assert_eq!(RangeAndStatus::decode(&[0x04]).unwrap(), rns);
    }

    #[test]
    fn range_and_status_with_status() {
        let rns = RangeAndStatus::with_status(7, vec![0b1010_1010]);
        assert_eq!(rns.encode(), vec![0x07, 0xAA]);
        let back = RangeAndStatus::decode(&[0x07, 0xAA]).unwrap();
        assert_eq!(back, rns);
        assert_eq!(back.circuits(), 8);
    }

    #[test]
    fn indicator_parameter_accessors() {
        let p = Parameter::forward_call_indicators(0x2001);
        assert_eq!(p.value, vec![0x20, 0x01]);
        assert_eq!(p.as_u16().unwrap(), 0x2001);

        let p = Parameter::calling_partys_category(calling_party_category::ORDINARY);
        assert_eq!(p.as_u8().unwrap(), 0x0A);
    }

    #[test]
    fn number_parameter_round_trip() {
        let n = Number::called(4, 1, false, "15551234567");
        let p = Parameter::called_party_number(&n).unwrap();
        assert_eq!(p.code, ParameterType::CalledPartyNumber);
        assert_eq!(p.as_number().unwrap(), n);
    }

    #[test]
    fn as_u8_rejects_wrong_length() {
        let p = Parameter::forward_call_indicators(0x1234);
        assert!(matches!(
            p.as_u8(),
            Err(IsupError::BadParameterLength { .. })
        ));
    }
}
