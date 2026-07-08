//! Error type for ISUP encoding and decoding.

/// Errors that can occur during ISUP message processing.
#[derive(Debug, thiserror::Error)]
pub enum IsupError {
    /// The input buffer ended before a required field could be read.
    #[error("message too short: expected at least {expected} bytes, got {actual}")]
    TooShort {
        /// Number of bytes the decoder needed to be present.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },

    /// The message-type octet did not match a type this codec can decode.
    #[error("invalid message type: 0x{0:02x}")]
    InvalidMessageType(u8),

    /// A mandatory-variable or optional parameter pointer led past the end of
    /// the message.
    #[error("parameter pointer out of range: points to offset {offset}, message is {len} bytes")]
    PointerOutOfRange {
        /// The offset the pointer resolved to.
        offset: usize,
        /// The message length.
        len: usize,
    },

    /// A fixed-length parameter value was not the length its layout requires.
    #[error("parameter 0x{code:02x}: expected {expected} value octets, got {actual}")]
    BadParameterLength {
        /// The parameter code.
        code: u8,
        /// The length the layout mandates.
        expected: usize,
        /// The length supplied.
        actual: usize,
    },

    /// A digit could not be encoded to ISUP address-signal BCD (not `0`-`9`,
    /// `*`, `#`, `a`-`c`, `e`, or `f`).
    #[error("invalid address-signal digit: {0:?}")]
    InvalidDigit(char),

    /// A structured parameter value was malformed; the string describes why.
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}
