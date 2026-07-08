//! ISUP address-signal digit packing (ITU-T Q.763 §3.9 / §3.10).
//!
//! Address digits are packed two per octet, the first (odd) digit in the low
//! nibble and the second (even) digit in the high nibble. An odd number of
//! digits leaves the final high nibble as a `0000` filler; the odd/even
//! indicator carried in the number parameter tells the decoder to drop it.
//!
//! Each nibble is one address signal: 0-9 map to `'0'`-`'9'`, and the extension
//! codes 10-15 map to the hex letters `'a'`-`'f'` (15 being ST). The alphabet is
//! a clean bijection, so encode and decode are exact inverses.

use crate::error::IsupError;

/// Map an address-signal digit character to its 4-bit code.
fn digit_to_nibble(c: char) -> Result<u8, IsupError> {
    Ok(match c {
        '0'..='9' => c as u8 - b'0',
        'a'..='f' => c as u8 - b'a' + 0x0A,
        'A'..='F' => c as u8 - b'A' + 0x0A,
        _ => return Err(IsupError::InvalidDigit(c)),
    })
}

/// Map a 4-bit code back to its address-signal digit character.
fn nibble_to_char(nibble: u8) -> char {
    match nibble & 0x0F {
        0..=9 => (b'0' + nibble) as char,
        0x0A => 'a',
        0x0B => 'b',
        0x0C => 'c',
        0x0D => 'd',
        0x0E => 'e',
        _ => 'f',
    }
}

/// Encode a digit string into packed ISUP address signals.
///
/// Two digits per octet, first digit in the low nibble. An odd digit count pads
/// the final high nibble with the `0000` filler. Returns the packed octets and
/// the odd/even flag (`true` when the digit count is odd), which the caller
/// writes into the number parameter's indicator octet.
///
/// ```
/// use itu_isup::bcd::encode_address_signals;
/// // "15551234567" (odd length): low nibble first, 0x0 filler in the last high nibble.
/// let (octets, odd) = encode_address_signals("15551234567").unwrap();
/// assert!(odd);
/// assert_eq!(octets, [0x51, 0x55, 0x21, 0x43, 0x65, 0x07]);
/// ```
pub fn encode_address_signals(digits: &str) -> Result<(Vec<u8>, bool), IsupError> {
    let nibbles: Vec<u8> = digits
        .chars()
        .map(digit_to_nibble)
        .collect::<Result<_, _>>()?;
    let odd = nibbles.len() % 2 == 1;

    let mut octets = Vec::with_capacity(nibbles.len().div_ceil(2));
    let mut i = 0;
    while i < nibbles.len() {
        let low = nibbles[i];
        let high = if i + 1 < nibbles.len() {
            nibbles[i + 1]
        } else {
            0x00 // filler for the odd trailing nibble
        };
        octets.push((high << 4) | low);
        i += 2;
    }
    Ok((octets, odd))
}

/// Decode packed ISUP address signals back to a digit string.
///
/// `odd` is the odd/even indicator from the number parameter: when set, the
/// final high nibble is a filler and is dropped.
pub fn decode_address_signals(octets: &[u8], odd: bool) -> String {
    let mut digits = String::with_capacity(octets.len() * 2);
    for (idx, &octet) in octets.iter().enumerate() {
        digits.push(nibble_to_char(octet & 0x0F));
        let is_last = idx + 1 == octets.len();
        if !(is_last && odd) {
            digits.push(nibble_to_char((octet >> 4) & 0x0F));
        }
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_even() {
        let (octets, odd) = encode_address_signals("1234").unwrap();
        assert!(!odd);
        assert_eq!(octets, vec![0x21, 0x43]);
    }

    #[test]
    fn encode_odd_uses_zero_filler() {
        let (octets, odd) = encode_address_signals("12345").unwrap();
        assert!(odd);
        assert_eq!(octets, vec![0x21, 0x43, 0x05]);
    }

    #[test]
    fn round_trip_odd() {
        let (octets, odd) = encode_address_signals("15551234567").unwrap();
        assert_eq!(decode_address_signals(&octets, odd), "15551234567");
    }

    #[test]
    fn round_trip_even() {
        let (octets, odd) = encode_address_signals("5550100").unwrap();
        let with_pad = decode_address_signals(&octets, odd);
        assert_eq!(with_pad, "5550100");
    }

    #[test]
    fn empty() {
        let (octets, odd) = encode_address_signals("").unwrap();
        assert!(octets.is_empty());
        assert!(!odd);
        assert_eq!(decode_address_signals(&[], false), "");
    }

    #[test]
    fn invalid_digit() {
        match encode_address_signals("12x34") {
            Err(IsupError::InvalidDigit('x')) => {}
            other => panic!("expected InvalidDigit, got {other:?}"),
        }
    }
}
