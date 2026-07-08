//! ISUP enumerations: message-type codes and parameter-name codes (ITU-T Q.763).
//!
//! Both are modelled as open enums (a named set plus an `Other(u8)` fall-through)
//! so an unknown code decodes losslessly and round-trips. The numeric codes are
//! the ITU-T Q.763 values, cross-checked against the Wireshark ISUP dissector.

use std::fmt;

/// ISUP message-type codes (ITU-T Q.763 Table 4).
///
/// The maintenance / circuit-supervision and basic call-control types this codec
/// handles are named; any other code decodes to [`MessageType::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Initial Address Message.
    Iam,
    /// Subsequent Address Message.
    Sam,
    /// Information Request (national use).
    Inr,
    /// Information (national use).
    Inf,
    /// Continuity.
    Cot,
    /// Address Complete.
    Acm,
    /// Connect.
    Con,
    /// Forward Transfer.
    Fot,
    /// Answer.
    Anm,
    /// Release.
    Rel,
    /// Suspend.
    Sus,
    /// Resume.
    Res,
    /// Release Complete.
    Rlc,
    /// Continuity Check Request.
    Ccr,
    /// Reset Circuit.
    Rsc,
    /// Blocking.
    Blo,
    /// Unblocking.
    Ubl,
    /// Blocking Acknowledgement.
    Bla,
    /// Unblocking Acknowledgement.
    Uba,
    /// Circuit Group Reset.
    Grs,
    /// Circuit Group Blocking.
    Cgb,
    /// Circuit Group Unblocking.
    Cgu,
    /// Circuit Group Blocking Acknowledgement.
    Cgba,
    /// Circuit Group Unblocking Acknowledgement.
    Cgua,
    /// Facility Request.
    Far,
    /// Facility Accepted.
    Faa,
    /// Facility Reject.
    Frj,
    /// Loop Back Acknowledgement (national use).
    Lpa,
    /// Pass-Along (national use).
    Pam,
    /// Circuit Group Reset Acknowledgement.
    Gra,
    /// Circuit Group Query (national use).
    Cqm,
    /// Circuit Group Query Response (national use).
    Cqr,
    /// Call Progress.
    Cpg,
    /// User-to-User Information.
    Usr,
    /// Unequipped Circuit Identification Code (national use).
    Ucic,
    /// Confusion.
    Cfn,
    /// Overload (national use).
    Olm,
    /// Charge Information (national use).
    Crg,
    /// Network Resource Management.
    Nrm,
    /// Facility.
    Fac,
    /// User Part Test.
    Upt,
    /// User Part Available.
    Upa,
    /// Identification Request.
    Idr,
    /// Identification Response.
    Irs,
    /// Segmentation.
    Sgm,
    /// Loop Prevention.
    Lop,
    /// Application Transport.
    Apm,
    /// Pre-Release Information.
    Pri,
    /// Subsequent Directory Number (national use).
    Sdn,
    /// Any other message-type code not named above.
    Other(u8),
}

impl MessageType {
    /// Map a message-type octet to its [`MessageType`].
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::Iam,
            0x02 => Self::Sam,
            0x03 => Self::Inr,
            0x04 => Self::Inf,
            0x05 => Self::Cot,
            0x06 => Self::Acm,
            0x07 => Self::Con,
            0x08 => Self::Fot,
            0x09 => Self::Anm,
            0x0C => Self::Rel,
            0x0D => Self::Sus,
            0x0E => Self::Res,
            0x10 => Self::Rlc,
            0x11 => Self::Ccr,
            0x12 => Self::Rsc,
            0x13 => Self::Blo,
            0x14 => Self::Ubl,
            0x15 => Self::Bla,
            0x16 => Self::Uba,
            0x17 => Self::Grs,
            0x18 => Self::Cgb,
            0x19 => Self::Cgu,
            0x1A => Self::Cgba,
            0x1B => Self::Cgua,
            0x1F => Self::Far,
            0x20 => Self::Faa,
            0x21 => Self::Frj,
            0x24 => Self::Lpa,
            0x28 => Self::Pam,
            0x29 => Self::Gra,
            0x2A => Self::Cqm,
            0x2B => Self::Cqr,
            0x2C => Self::Cpg,
            0x2D => Self::Usr,
            0x2E => Self::Ucic,
            0x2F => Self::Cfn,
            0x30 => Self::Olm,
            0x31 => Self::Crg,
            0x32 => Self::Nrm,
            0x33 => Self::Fac,
            0x34 => Self::Upt,
            0x35 => Self::Upa,
            0x36 => Self::Idr,
            0x37 => Self::Irs,
            0x38 => Self::Sgm,
            0x40 => Self::Lop,
            0x41 => Self::Apm,
            0x42 => Self::Pri,
            0x43 => Self::Sdn,
            other => Self::Other(other),
        }
    }

    /// The raw message-type octet.
    pub fn value(self) -> u8 {
        match self {
            Self::Iam => 0x01,
            Self::Sam => 0x02,
            Self::Inr => 0x03,
            Self::Inf => 0x04,
            Self::Cot => 0x05,
            Self::Acm => 0x06,
            Self::Con => 0x07,
            Self::Fot => 0x08,
            Self::Anm => 0x09,
            Self::Rel => 0x0C,
            Self::Sus => 0x0D,
            Self::Res => 0x0E,
            Self::Rlc => 0x10,
            Self::Ccr => 0x11,
            Self::Rsc => 0x12,
            Self::Blo => 0x13,
            Self::Ubl => 0x14,
            Self::Bla => 0x15,
            Self::Uba => 0x16,
            Self::Grs => 0x17,
            Self::Cgb => 0x18,
            Self::Cgu => 0x19,
            Self::Cgba => 0x1A,
            Self::Cgua => 0x1B,
            Self::Far => 0x1F,
            Self::Faa => 0x20,
            Self::Frj => 0x21,
            Self::Lpa => 0x24,
            Self::Pam => 0x28,
            Self::Gra => 0x29,
            Self::Cqm => 0x2A,
            Self::Cqr => 0x2B,
            Self::Cpg => 0x2C,
            Self::Usr => 0x2D,
            Self::Ucic => 0x2E,
            Self::Cfn => 0x2F,
            Self::Olm => 0x30,
            Self::Crg => 0x31,
            Self::Nrm => 0x32,
            Self::Fac => 0x33,
            Self::Upt => 0x34,
            Self::Upa => 0x35,
            Self::Idr => 0x36,
            Self::Irs => 0x37,
            Self::Sgm => 0x38,
            Self::Lop => 0x40,
            Self::Apm => 0x41,
            Self::Pri => 0x42,
            Self::Sdn => 0x43,
            Self::Other(v) => v,
        }
    }

    /// The short acronym for this message type (e.g. `"IAM"`).
    pub fn acronym(self) -> &'static str {
        match self {
            Self::Iam => "IAM",
            Self::Sam => "SAM",
            Self::Inr => "INR",
            Self::Inf => "INF",
            Self::Cot => "COT",
            Self::Acm => "ACM",
            Self::Con => "CON",
            Self::Fot => "FOT",
            Self::Anm => "ANM",
            Self::Rel => "REL",
            Self::Sus => "SUS",
            Self::Res => "RES",
            Self::Rlc => "RLC",
            Self::Ccr => "CCR",
            Self::Rsc => "RSC",
            Self::Blo => "BLO",
            Self::Ubl => "UBL",
            Self::Bla => "BLA",
            Self::Uba => "UBA",
            Self::Grs => "GRS",
            Self::Cgb => "CGB",
            Self::Cgu => "CGU",
            Self::Cgba => "CGBA",
            Self::Cgua => "CGUA",
            Self::Far => "FAR",
            Self::Faa => "FAA",
            Self::Frj => "FRJ",
            Self::Lpa => "LPA",
            Self::Pam => "PAM",
            Self::Gra => "GRA",
            Self::Cqm => "CQM",
            Self::Cqr => "CQR",
            Self::Cpg => "CPG",
            Self::Usr => "USR",
            Self::Ucic => "UCIC",
            Self::Cfn => "CFN",
            Self::Olm => "OLM",
            Self::Crg => "CRG",
            Self::Nrm => "NRM",
            Self::Fac => "FAC",
            Self::Upt => "UPT",
            Self::Upa => "UPA",
            Self::Idr => "IDR",
            Self::Irs => "IRS",
            Self::Sgm => "SGM",
            Self::Lop => "LOP",
            Self::Apm => "APM",
            Self::Pri => "PRI",
            Self::Sdn => "SDN",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(v) => write!(f, "MSG(0x{v:02x})"),
            other => write!(f, "{}", other.acronym()),
        }
    }
}

/// ISUP parameter-name codes (ITU-T Q.763 Table 5).
///
/// A named set covering the parameters this codec understands, plus an
/// `Other(u8)` fall-through so unknown parameters decode as opaque TLVs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterType {
    /// End of optional parameters (`0x00`), the optional-part terminator.
    EndOfOptionalParameters,
    /// Call reference (national use).
    CallReference,
    /// Transmission medium requirement.
    TransmissionMediumRequirement,
    /// Access transport.
    AccessTransport,
    /// Called party number.
    CalledPartyNumber,
    /// Subsequent number.
    SubsequentNumber,
    /// Nature of connection indicators.
    NatureOfConnectionIndicators,
    /// Forward call indicators.
    ForwardCallIndicators,
    /// Optional forward call indicators.
    OptionalForwardCallIndicators,
    /// Calling party's category.
    CallingPartysCategory,
    /// Calling party number.
    CallingPartyNumber,
    /// Redirecting number.
    RedirectingNumber,
    /// Redirection number.
    RedirectionNumber,
    /// Connection request.
    ConnectionRequest,
    /// Information request indicators (national use).
    InformationRequestIndicators,
    /// Information indicators (national use).
    InformationIndicators,
    /// Continuity indicators.
    ContinuityIndicators,
    /// Backward call indicators.
    BackwardCallIndicators,
    /// Cause indicators.
    CauseIndicators,
    /// Redirection information.
    RedirectionInformation,
    /// Circuit group supervision message type indicator.
    CircuitGroupSupervisionMessageType,
    /// Range and status.
    RangeAndStatus,
    /// Facility indicator.
    FacilityIndicator,
    /// Closed user group interlock code.
    ClosedUserGroupInterlockCode,
    /// User service information.
    UserServiceInformation,
    /// Signalling point code (national use).
    SignallingPointCode,
    /// User-to-user information.
    UserToUserInformation,
    /// Connected number.
    ConnectedNumber,
    /// Suspend/resume indicators.
    SuspendResumeIndicators,
    /// Transit network selection (national use).
    TransitNetworkSelection,
    /// Event information.
    EventInformation,
    /// Circuit assignment map.
    CircuitAssignmentMap,
    /// Circuit state indicator (national use).
    CircuitStateIndicator,
    /// Automatic congestion level.
    AutomaticCongestionLevel,
    /// Original called number.
    OriginalCalledNumber,
    /// Optional backward call indicators.
    OptionalBackwardCallIndicators,
    /// User-to-user indicators.
    UserToUserIndicators,
    /// Origination ISC point code.
    OriginationIscPointCode,
    /// Generic notification indicator.
    GenericNotificationIndicator,
    /// Call history information.
    CallHistoryInformation,
    /// Access delivery information.
    AccessDeliveryInformation,
    /// Network specific facility (national use).
    NetworkSpecificFacility,
    /// User service information prime.
    UserServiceInformationPrime,
    /// Propagation delay counter.
    PropagationDelayCounter,
    /// Remote operations (national use).
    RemoteOperations,
    /// Service activation.
    ServiceActivation,
    /// User teleservice information.
    UserTeleserviceInformation,
    /// Transmission medium used.
    TransmissionMediumUsed,
    /// Call diversion information.
    CallDiversionInformation,
    /// Echo control information.
    EchoControlInformation,
    /// Message compatibility information.
    MessageCompatibilityInformation,
    /// Parameter compatibility information.
    ParameterCompatibilityInformation,
    /// MLPP precedence.
    MlppPrecedence,
    /// MCID request indicators.
    McidRequestIndicators,
    /// MCID response indicators.
    McidResponseIndicators,
    /// Hop counter.
    HopCounter,
    /// Transmission medium requirement prime.
    TransmissionMediumRequirementPrime,
    /// Location number.
    LocationNumber,
    /// Redirection number restriction.
    RedirectionNumberRestriction,
    /// Generic number.
    GenericNumber,
    /// Generic digits (national use).
    GenericDigits,
    /// Any other parameter code not named above.
    Other(u8),
}

impl ParameterType {
    /// Map a parameter-code octet to its [`ParameterType`].
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::EndOfOptionalParameters,
            0x01 => Self::CallReference,
            0x02 => Self::TransmissionMediumRequirement,
            0x03 => Self::AccessTransport,
            0x04 => Self::CalledPartyNumber,
            0x05 => Self::SubsequentNumber,
            0x06 => Self::NatureOfConnectionIndicators,
            0x07 => Self::ForwardCallIndicators,
            0x08 => Self::OptionalForwardCallIndicators,
            0x09 => Self::CallingPartysCategory,
            0x0A => Self::CallingPartyNumber,
            0x0B => Self::RedirectingNumber,
            0x0C => Self::RedirectionNumber,
            0x0D => Self::ConnectionRequest,
            0x0E => Self::InformationRequestIndicators,
            0x0F => Self::InformationIndicators,
            0x10 => Self::ContinuityIndicators,
            0x11 => Self::BackwardCallIndicators,
            0x12 => Self::CauseIndicators,
            0x13 => Self::RedirectionInformation,
            0x15 => Self::CircuitGroupSupervisionMessageType,
            0x16 => Self::RangeAndStatus,
            0x18 => Self::FacilityIndicator,
            0x1A => Self::ClosedUserGroupInterlockCode,
            0x1D => Self::UserServiceInformation,
            0x1E => Self::SignallingPointCode,
            0x20 => Self::UserToUserInformation,
            0x21 => Self::ConnectedNumber,
            0x22 => Self::SuspendResumeIndicators,
            0x23 => Self::TransitNetworkSelection,
            0x24 => Self::EventInformation,
            0x25 => Self::CircuitAssignmentMap,
            0x26 => Self::CircuitStateIndicator,
            0x27 => Self::AutomaticCongestionLevel,
            0x28 => Self::OriginalCalledNumber,
            0x29 => Self::OptionalBackwardCallIndicators,
            0x2A => Self::UserToUserIndicators,
            0x2B => Self::OriginationIscPointCode,
            0x2C => Self::GenericNotificationIndicator,
            0x2D => Self::CallHistoryInformation,
            0x2E => Self::AccessDeliveryInformation,
            0x2F => Self::NetworkSpecificFacility,
            0x30 => Self::UserServiceInformationPrime,
            0x31 => Self::PropagationDelayCounter,
            0x32 => Self::RemoteOperations,
            0x33 => Self::ServiceActivation,
            0x34 => Self::UserTeleserviceInformation,
            0x35 => Self::TransmissionMediumUsed,
            0x36 => Self::CallDiversionInformation,
            0x37 => Self::EchoControlInformation,
            0x38 => Self::MessageCompatibilityInformation,
            0x39 => Self::ParameterCompatibilityInformation,
            0x3A => Self::MlppPrecedence,
            0x3B => Self::McidRequestIndicators,
            0x3C => Self::McidResponseIndicators,
            0x3D => Self::HopCounter,
            0x3E => Self::TransmissionMediumRequirementPrime,
            0x3F => Self::LocationNumber,
            0x40 => Self::RedirectionNumberRestriction,
            0xC0 => Self::GenericNumber,
            0xC1 => Self::GenericDigits,
            other => Self::Other(other),
        }
    }

    /// The raw parameter-code octet.
    pub fn value(self) -> u8 {
        match self {
            Self::EndOfOptionalParameters => 0x00,
            Self::CallReference => 0x01,
            Self::TransmissionMediumRequirement => 0x02,
            Self::AccessTransport => 0x03,
            Self::CalledPartyNumber => 0x04,
            Self::SubsequentNumber => 0x05,
            Self::NatureOfConnectionIndicators => 0x06,
            Self::ForwardCallIndicators => 0x07,
            Self::OptionalForwardCallIndicators => 0x08,
            Self::CallingPartysCategory => 0x09,
            Self::CallingPartyNumber => 0x0A,
            Self::RedirectingNumber => 0x0B,
            Self::RedirectionNumber => 0x0C,
            Self::ConnectionRequest => 0x0D,
            Self::InformationRequestIndicators => 0x0E,
            Self::InformationIndicators => 0x0F,
            Self::ContinuityIndicators => 0x10,
            Self::BackwardCallIndicators => 0x11,
            Self::CauseIndicators => 0x12,
            Self::RedirectionInformation => 0x13,
            Self::CircuitGroupSupervisionMessageType => 0x15,
            Self::RangeAndStatus => 0x16,
            Self::FacilityIndicator => 0x18,
            Self::ClosedUserGroupInterlockCode => 0x1A,
            Self::UserServiceInformation => 0x1D,
            Self::SignallingPointCode => 0x1E,
            Self::UserToUserInformation => 0x20,
            Self::ConnectedNumber => 0x21,
            Self::SuspendResumeIndicators => 0x22,
            Self::TransitNetworkSelection => 0x23,
            Self::EventInformation => 0x24,
            Self::CircuitAssignmentMap => 0x25,
            Self::CircuitStateIndicator => 0x26,
            Self::AutomaticCongestionLevel => 0x27,
            Self::OriginalCalledNumber => 0x28,
            Self::OptionalBackwardCallIndicators => 0x29,
            Self::UserToUserIndicators => 0x2A,
            Self::OriginationIscPointCode => 0x2B,
            Self::GenericNotificationIndicator => 0x2C,
            Self::CallHistoryInformation => 0x2D,
            Self::AccessDeliveryInformation => 0x2E,
            Self::NetworkSpecificFacility => 0x2F,
            Self::UserServiceInformationPrime => 0x30,
            Self::PropagationDelayCounter => 0x31,
            Self::RemoteOperations => 0x32,
            Self::ServiceActivation => 0x33,
            Self::UserTeleserviceInformation => 0x34,
            Self::TransmissionMediumUsed => 0x35,
            Self::CallDiversionInformation => 0x36,
            Self::EchoControlInformation => 0x37,
            Self::MessageCompatibilityInformation => 0x38,
            Self::ParameterCompatibilityInformation => 0x39,
            Self::MlppPrecedence => 0x3A,
            Self::McidRequestIndicators => 0x3B,
            Self::McidResponseIndicators => 0x3C,
            Self::HopCounter => 0x3D,
            Self::TransmissionMediumRequirementPrime => 0x3E,
            Self::LocationNumber => 0x3F,
            Self::RedirectionNumberRestriction => 0x40,
            Self::GenericNumber => 0xC0,
            Self::GenericDigits => 0xC1,
            Self::Other(v) => v,
        }
    }
}

impl fmt::Display for ParameterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PARAM(0x{:02x})", self.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_round_trips() {
        for raw in 0u8..=0xFF {
            assert_eq!(MessageType::from_u8(raw).value(), raw);
        }
    }

    #[test]
    fn parameter_type_round_trips() {
        for raw in 0u8..=0xFF {
            assert_eq!(ParameterType::from_u8(raw).value(), raw);
        }
    }

    #[test]
    fn named_message_codes_match_q763() {
        assert_eq!(MessageType::Iam.value(), 0x01);
        assert_eq!(MessageType::Acm.value(), 0x06);
        assert_eq!(MessageType::Anm.value(), 0x09);
        assert_eq!(MessageType::Rel.value(), 0x0C);
        assert_eq!(MessageType::Rlc.value(), 0x10);
        assert_eq!(MessageType::Cpg.value(), 0x2C);
        assert_eq!(MessageType::Grs.value(), 0x17);
        assert_eq!(MessageType::Gra.value(), 0x29);
        assert_eq!(MessageType::Cgb.value(), 0x18);
    }

    #[test]
    fn named_parameter_codes_match_q763() {
        assert_eq!(ParameterType::NatureOfConnectionIndicators.value(), 0x06);
        assert_eq!(ParameterType::ForwardCallIndicators.value(), 0x07);
        assert_eq!(ParameterType::CalledPartyNumber.value(), 0x04);
        assert_eq!(ParameterType::CallingPartyNumber.value(), 0x0A);
        assert_eq!(ParameterType::CauseIndicators.value(), 0x12);
        assert_eq!(ParameterType::BackwardCallIndicators.value(), 0x11);
        assert_eq!(ParameterType::RangeAndStatus.value(), 0x16);
        assert_eq!(ParameterType::EventInformation.value(), 0x24);
    }

    #[test]
    fn unknown_codes_fall_through() {
        assert_eq!(MessageType::from_u8(0xF5), MessageType::Other(0xF5));
        assert_eq!(ParameterType::from_u8(0x77), ParameterType::Other(0x77));
    }
}
