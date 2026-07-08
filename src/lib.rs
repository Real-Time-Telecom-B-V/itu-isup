//! ISUP (ISDN User Part) message + parameter codec per ITU-T Q.763.
//!
//! ISUP is the SS7 call-control protocol that sets up, supervises and tears down
//! circuit-switched trunks. It is a **direct MTP3-user** (Service Indicator 5),
//! it rides MTP3 (or M3UA) straight, not over SCCP/TCAP, and each message names
//! a circuit by a point code plus a **Circuit Identification Code (CIC)**.
//!
//! This crate is a pure codec: it encodes and decodes ISUP message bodies
//! (CIC, message type, and the mandatory-fixed / mandatory-variable / optional
//! parts with their pointer arithmetic and the end-of-optional-parameters
//! marker) and the Q.763 parameter values. It builds **no** call state machine,
//! does **no** CIC management, and performs **no** ISUP↔SIP interworking, those
//! belong to a separate MGCF. The Q.764 procedures are out of scope.
//!
//! # Where it sits
//!
//! An encoded message is the payload of an MTP3 Message Signal Unit. The
//! [`mtp3`] crate frames it: [`Message::to_msu`] wraps the bytes as the SIF of an
//! [`mtp3::Mtp3Msu`] with [`SERVICE_INDICATOR`] (ISUP), and an MGCF drives it
//! over the [`mtp3::Mtp3UserPart`] SAP exactly as SCCP does.
//!
//! # Example
//!
//! ```
//! use itu_isup::{Message, Number, calling_party_category};
//!
//! // Build an Initial Address Message on CIC 1 to a national number. Digits are
//! // synthetic (fictional +1-555 range).
//! let called = Number::called(3, 1, false, "5551234");
//! let iam = Message::iam(
//!     1,      // CIC
//!     0x00,   // nature of connection indicators
//!     0x2000, // forward call indicators
//!     calling_party_category::ORDINARY,
//!     0x00,   // transmission medium requirement (speech)
//!     &called,
//! )
//! .unwrap();
//!
//! let wire = iam.encode().unwrap();
//! let decoded = Message::decode(&wire).unwrap();
//! assert_eq!(decoded.message_type, itu_isup::MessageType::Iam);
//! assert_eq!(
//!     decoded.mandatory_variable[0].as_number().unwrap().digits,
//!     "5551234"
//! );
//! ```
#![warn(missing_docs)]

pub mod bcd;
pub mod error;
pub mod message;
pub mod number;
pub mod parameter;
pub mod types;

#[cfg(feature = "python")]
pub mod python;

pub use error::IsupError;
pub use message::Message;
pub use number::Number;
pub use parameter::{
    calling_party_category, event_information, transmission_medium_requirement, CauseIndicators,
    Parameter, RangeAndStatus,
};
pub use types::{MessageType, ParameterType};

use mtp3::{Mtp3Msu, NetworkIndicator, PointCode, ServiceIndicator};

/// The MTP3 Service Indicator for ISUP (Q.704 / Q.763): `5`. An ISUP message
/// rides an MSU whose SIO low nibble is this value.
pub const SERVICE_INDICATOR: ServiceIndicator = ServiceIndicator::ISUP;

/// Encode a 12-bit Circuit Identification Code to its two on-wire octets: the
/// low 8 bits, then the high 4 bits with the top 4 spare bits zero
/// (little-endian, Q.763 §1.2).
pub fn encode_cic(cic: u16) -> [u8; 2] {
    [(cic & 0xFF) as u8, ((cic >> 8) & 0x0F) as u8]
}

/// Decode a Circuit Identification Code from its two on-wire octets, masking off
/// the four spare bits.
pub fn decode_cic(octets: [u8; 2]) -> u16 {
    (octets[0] as u16) | (((octets[1] & 0x0F) as u16) << 8)
}

impl Message {
    /// Wrap this message as the SIF of an [`mtp3::Mtp3Msu`] ready for the wire:
    /// Service Indicator ISUP, message priority 0, the given routing label
    /// (`opc` / `dpc` / `sls`) and network indicator. The MSU is encoded for the
    /// wire with [`mtp3::Mtp3Msu::encode`].
    ///
    /// For ISUP the SLS is conventionally derived from the CIC (load-sharing per
    /// circuit); the caller supplies it so the policy stays theirs.
    pub fn to_msu(
        &self,
        opc: PointCode,
        dpc: PointCode,
        ni: NetworkIndicator,
        sls: u8,
    ) -> Result<Mtp3Msu, IsupError> {
        Ok(Mtp3Msu {
            si: SERVICE_INDICATOR,
            ni,
            mp: 0,
            opc,
            dpc,
            sls,
            data: self.encode()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtp3::Variant;

    #[test]
    fn cic_round_trips_and_masks_spare_bits() {
        for cic in [0u16, 1, 42, 0x0FFF] {
            assert_eq!(decode_cic(encode_cic(cic)), cic);
        }
        // The four spare bits (top of the second octet) are ignored on decode.
        assert_eq!(decode_cic([0x01, 0xF0]), 1);
    }

    #[test]
    fn service_indicator_is_isup() {
        assert_eq!(SERVICE_INDICATOR, ServiceIndicator::ISUP);
        assert_eq!(SERVICE_INDICATOR.0, 5);
    }

    #[test]
    fn to_msu_carries_the_encoded_message() {
        let blo = Message::blocking(1);
        let opc = PointCode::from_value(4107, Variant::Itu).unwrap();
        let dpc = PointCode::from_value(8209, Variant::Itu).unwrap();
        let msu = blo.to_msu(opc, dpc, NetworkIndicator::National, 5).unwrap();
        assert_eq!(msu.si, ServiceIndicator::ISUP);
        assert_eq!(msu.data, blo.encode().unwrap());
        // The MSU frames cleanly for the wire.
        let wire = msu.encode(Variant::Itu);
        assert_eq!(wire[0] & 0x0F, 5); // SIO low nibble = ISUP
    }
}
