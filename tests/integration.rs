//! Integration tests, end-to-end ISUP message encode/decode over the public API.
//!
//! Digits are synthetic (fictional +1-555 range); point codes are decimal. These
//! complement the tshark known-answer vectors (`tests/tshark_kat.rs`) with
//! round-trips and field-level checks that need no external tools.

use itu_isup::{
    calling_party_category, event_information, transmission_medium_requirement, CauseIndicators,
    IsupError, Message, MessageType, Number, Parameter, ParameterType, RangeAndStatus,
};

/// A full IAM with a called party number, an optional calling party number and
/// an optional user service information, round-trips with every field intact.
#[test]
fn iam_full_round_trip() {
    let called = Number::called(4, 1, false, "15551234567");
    let calling = Number::calling(4, 1, false, 0, 3, "15559876543");
    let iam = Message::iam(
        100,
        0x00,
        0x2000,
        calling_party_category::ORDINARY,
        transmission_medium_requirement::SPEECH,
        &called,
    )
    .unwrap()
    .with_optional(Parameter::calling_party_number(&calling).unwrap())
    .with_optional(Parameter::user_service_information(&[0x80, 0x90, 0xA3]));

    let wire = iam.encode().unwrap();
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded, iam);
    assert_eq!(decoded.cic, 100);
    assert_eq!(decoded.message_type, MessageType::Iam);

    // Mandatory fixed part, in Q.763 order.
    assert_eq!(decoded.mandatory_fixed[0].as_u8().unwrap(), 0x00); // nature of conn
    assert_eq!(decoded.mandatory_fixed[1].as_u16().unwrap(), 0x2000); // forward call
    assert_eq!(
        decoded.mandatory_fixed[2].as_u8().unwrap(),
        calling_party_category::ORDINARY
    );

    // Mandatory variable part: the called party number.
    let got_called = decoded.mandatory_variable[0].as_number().unwrap();
    assert_eq!(got_called.digits, "15551234567");
    assert_eq!(got_called.numbering_plan(), 1);

    // Optional part.
    let got_calling = decoded
        .optional(ParameterType::CallingPartyNumber)
        .unwrap()
        .as_number()
        .unwrap();
    assert_eq!(got_calling.digits, "15559876543");
    assert_eq!(got_calling.screening(), 3);
    assert_eq!(
        decoded
            .optional(ParameterType::UserServiceInformation)
            .unwrap()
            .value,
        vec![0x80, 0x90, 0xA3]
    );
}

/// Release with a Q.850 cause, decoded field by field.
#[test]
fn release_cause_fields() {
    let rel = Message::release(7, &CauseIndicators::new(1, 17)); // user busy
    let decoded = Message::decode(&rel.encode().unwrap()).unwrap();
    let cause = decoded.mandatory_variable[0].as_cause_indicators().unwrap();
    assert_eq!(cause.location, 1);
    assert_eq!(cause.cause_value, 17);
    assert_eq!(cause.coding_standard, 0);
}

/// The call-progress path: ACM then ANM then CPG then REL then RLC on one CIC.
#[test]
fn call_control_sequence() {
    let cic = 42;
    let messages = [
        Message::acm(cic, 0x1010),
        Message::anm(cic),
        Message::cpg(cic, event_information::PROGRESS),
        Message::release(cic, &CauseIndicators::new(1, 16)),
        Message::release_complete(cic),
    ];
    for m in messages {
        let decoded = Message::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(decoded, m);
        assert_eq!(decoded.cic, cic);
    }
}

/// Circuit-group supervision: GRS carries a range only, CGB carries a supervision
/// indicator and a range + status bitmap.
#[test]
fn circuit_group_supervision() {
    let grs = Message::circuit_group_reset(1, &RangeAndStatus::range_only(23));
    let decoded = Message::decode(&grs.encode().unwrap()).unwrap();
    let rns = decoded.mandatory_variable[0].as_range_and_status().unwrap();
    assert_eq!(rns.circuits(), 24);
    assert!(rns.status.is_empty());

    let cgb = Message::circuit_group_blocking(1, 0x01, &RangeAndStatus::with_status(7, vec![0xFF]));
    let decoded = Message::decode(&cgb.encode().unwrap()).unwrap();
    assert_eq!(decoded.mandatory_fixed[0].as_u8().unwrap(), 0x01);
    let rns = decoded.mandatory_variable[0].as_range_and_status().unwrap();
    assert_eq!(rns.circuits(), 8);
    assert_eq!(rns.status, vec![0xFF]);
}

/// Every circuit-maintenance message with no parameters is exactly CIC + type.
#[test]
fn maintenance_messages_are_three_octets() {
    for (m, code) in [
        (Message::blocking(1), MessageType::Blo),
        (Message::blocking_ack(1), MessageType::Bla),
        (Message::unblocking(1), MessageType::Ubl),
        (Message::unblocking_ack(1), MessageType::Uba),
        (Message::reset_circuit(1), MessageType::Rsc),
    ] {
        let wire = m.encode().unwrap();
        assert_eq!(wire.len(), 3);
        assert_eq!(wire[2], code.value());
        assert_eq!(Message::decode(&wire).unwrap(), m);
    }
}

/// A decoder rejects a message type outside this codec's scope.
#[test]
fn decode_rejects_out_of_scope_type() {
    // Continuity (COT, 0x05) is a valid Q.763 type but out of scope.
    assert!(matches!(
        Message::decode(&[0x01, 0x00, 0x05]),
        Err(IsupError::InvalidMessageType(0x05))
    ));
}

/// Redirecting / redirection numbers round-trip through the optional part.
#[test]
fn redirection_numbers_round_trip() {
    let redirecting = Number::redirecting(3, 1, 1, "5550142");
    let redirection = Number::called(3, 1, false, "5550199");
    let acm = Message::acm(9, 0x1010)
        .with_optional(Parameter::redirecting_number(&redirecting).unwrap())
        .with_optional(Parameter::redirection_number(&redirection).unwrap());
    let decoded = Message::decode(&acm.encode().unwrap()).unwrap();
    assert_eq!(
        decoded
            .optional(ParameterType::RedirectingNumber)
            .unwrap()
            .as_number()
            .unwrap()
            .digits,
        "5550142"
    );
    assert_eq!(
        decoded
            .optional(ParameterType::RedirectionNumber)
            .unwrap()
            .as_number()
            .unwrap()
            .digits,
        "5550199"
    );
}

/// A large optional part (several parameters) walks correctly.
#[test]
fn many_optional_parameters() {
    let mut anm = Message::anm(1);
    for i in 0..8u8 {
        anm = anm.with_optional(Parameter::new(ParameterType::Other(0x80 + i), vec![i; 4]));
    }
    let decoded = Message::decode(&anm.encode().unwrap()).unwrap();
    assert_eq!(decoded.optional.len(), 8);
    for (i, p) in decoded.optional.iter().enumerate() {
        assert_eq!(p.code, ParameterType::Other(0x80 + i as u8));
        assert_eq!(p.value, vec![i as u8; 4]);
    }
}
