//! ISUP number parameters (ITU-T Q.763 §3.9, §3.10, §3.16, §3.66).
//!
//! Called party number, calling party number, redirecting number and
//! redirection number all share the same shape: a first indicator octet
//! carrying the odd/even indicator (bit 7) and a 7-bit nature-of-address
//! indicator (NAI), a second parameter-specific indicator octet, then the packed
//! address signals. They differ only in what the second octet means, so this
//! module models one [`Number`] holding the NAI, the raw second octet
//! (`qualifier`) and the digit string, with typed constructors and accessors for
//! each parameter's second-octet layout.

use crate::bcd::{decode_address_signals, encode_address_signals};
use crate::error::IsupError;

/// An ISUP number parameter value (called / calling / redirecting / redirection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    /// Nature of address indicator (7 bits): 3 = national (significant) number,
    /// 4 = international number, etc.
    pub nature_of_address: u8,
    /// The second indicator octet verbatim, its meaning is parameter-specific
    /// (numbering plan / INN / NI / presentation / screening). Build it with one
    /// of the constructors and read the sub-fields with the accessors.
    pub qualifier: u8,
    /// The address digits.
    pub digits: String,
}

impl Number {
    /// Build a **called party number** / **redirection number** value: NAI, a
    /// 3-bit numbering-plan indicator (NPI), the internal-network-number (INN)
    /// indicator, and digits. Second octet = `INN(bit7) | NPI(bits4-6)`.
    pub fn called(nature_of_address: u8, numbering_plan: u8, inn: bool, digits: &str) -> Self {
        let qualifier = ((inn as u8) << 7) | ((numbering_plan & 0x07) << 4);
        Self {
            nature_of_address,
            qualifier,
            digits: digits.to_string(),
        }
    }

    /// Build a **calling party number** value: NAI, NPI, the number-incomplete
    /// (NI) indicator, a 2-bit address-presentation-restricted indicator and a
    /// 2-bit screening indicator. Second octet =
    /// `NI(bit7) | NPI(bits4-6) | presentation(bits2-3) | screening(bits0-1)`.
    pub fn calling(
        nature_of_address: u8,
        numbering_plan: u8,
        ni: bool,
        presentation: u8,
        screening: u8,
        digits: &str,
    ) -> Self {
        let qualifier = ((ni as u8) << 7)
            | ((numbering_plan & 0x07) << 4)
            | ((presentation & 0x03) << 2)
            | (screening & 0x03);
        Self {
            nature_of_address,
            qualifier,
            digits: digits.to_string(),
        }
    }

    /// Build a **redirecting number** value: NAI, NPI and a 2-bit
    /// address-presentation-restricted indicator. Second octet =
    /// `NPI(bits4-6) | presentation(bits2-3)`.
    pub fn redirecting(
        nature_of_address: u8,
        numbering_plan: u8,
        presentation: u8,
        digits: &str,
    ) -> Self {
        let qualifier = ((numbering_plan & 0x07) << 4) | ((presentation & 0x03) << 2);
        Self {
            nature_of_address,
            qualifier,
            digits: digits.to_string(),
        }
    }

    /// The numbering-plan indicator (bits 4-6 of the second octet): 1 = ISDN
    /// (E.164), 3 = data (X.121), 4 = telex (F.69).
    pub fn numbering_plan(&self) -> u8 {
        (self.qualifier >> 4) & 0x07
    }

    /// The internal-network-number indicator (bit 7), for called / redirection
    /// numbers.
    pub fn inn(&self) -> bool {
        (self.qualifier & 0x80) != 0
    }

    /// The number-incomplete indicator (bit 7), for a calling party number.
    pub fn ni(&self) -> bool {
        (self.qualifier & 0x80) != 0
    }

    /// The address-presentation-restricted indicator (bits 2-3).
    pub fn presentation(&self) -> u8 {
        (self.qualifier >> 2) & 0x03
    }

    /// The screening indicator (bits 0-1), for a calling party number.
    pub fn screening(&self) -> u8 {
        self.qualifier & 0x03
    }

    /// Encode this number to its parameter value octets (two indicator octets
    /// then the packed address signals).
    pub fn encode(&self) -> Result<Vec<u8>, IsupError> {
        let (signals, odd) = encode_address_signals(&self.digits)?;
        let mut buf = Vec::with_capacity(2 + signals.len());
        buf.push(((odd as u8) << 7) | (self.nature_of_address & 0x7F));
        buf.push(self.qualifier);
        buf.extend_from_slice(&signals);
        Ok(buf)
    }

    /// Decode a number from its parameter value octets.
    pub fn decode(bytes: &[u8]) -> Result<Self, IsupError> {
        if bytes.len() < 2 {
            return Err(IsupError::TooShort {
                expected: 2,
                actual: bytes.len(),
            });
        }
        let odd = (bytes[0] & 0x80) != 0;
        let nature_of_address = bytes[0] & 0x7F;
        let qualifier = bytes[1];
        let digits = decode_address_signals(&bytes[2..], odd);
        Ok(Self {
            nature_of_address,
            qualifier,
            digits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn called_number_round_trip() {
        // International (NAI 4), ISDN plan (NPI 1), no INN, 11 digits (odd).
        let n = Number::called(4, 1, false, "15551234567");
        let bytes = n.encode().unwrap();
        // octet1 = odd(1)<<7 | NAI 4 = 0x84; octet2 = NPI 1 << 4 = 0x10.
        assert_eq!(bytes[0], 0x84);
        assert_eq!(bytes[1], 0x10);
        assert_eq!(&bytes[2..], &[0x51, 0x55, 0x21, 0x43, 0x65, 0x07]);
        let back = Number::decode(&bytes).unwrap();
        assert_eq!(back, n);
        assert_eq!(back.numbering_plan(), 1);
        assert_eq!(back.digits, "15551234567");
    }

    #[test]
    fn calling_number_round_trip() {
        let n = Number::calling(4, 1, false, 0, 3, "15559876543");
        let bytes = n.encode().unwrap();
        assert_eq!(bytes[0], 0x84);
        // NPI 1<<4 | presentation 0<<2 | screening 3 = 0x13.
        assert_eq!(bytes[1], 0x13);
        let back = Number::decode(&bytes).unwrap();
        assert_eq!(back, n);
        assert_eq!(back.screening(), 3);
        assert_eq!(back.digits, "15559876543");
    }

    #[test]
    fn redirecting_number_round_trip() {
        let n = Number::redirecting(3, 1, 1, "5550100");
        let back = Number::decode(&n.encode().unwrap()).unwrap();
        assert_eq!(back, n);
        assert_eq!(back.presentation(), 1);
        assert_eq!(back.numbering_plan(), 1);
    }

    #[test]
    fn decode_too_short() {
        assert!(matches!(
            Number::decode(&[0x84]),
            Err(IsupError::TooShort { .. })
        ));
    }
}
