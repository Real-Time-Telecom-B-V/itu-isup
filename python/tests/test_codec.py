"""Codec parity / round-trip tests for the itu-isup wheel.

These exercise the same Rust codec the crate ships, through the Python surface:
``encode`` must match the ITU-T Q.763 wire form, ``decode`` must recover the
fields, and message construction must round-trip. The golden vectors are the ones
dissected clean by the Wireshark ISUP dissector in the Rust suite. Digits are
synthetic (fictional +1-555 range).
"""

from __future__ import annotations

import pytest

import itu_isup

# IAM on CIC 1: nature of connection 0x00, forward call indicators 0x2000,
# ordinary calling category, speech, called party 5551234 (national). No optional
# part. Dissects clean as "Initial address" in Wireshark (Q.763).
GOLDEN_IAM = bytes.fromhex("0100010020000a00020006831055153204")

# REL on CIC 1: cause location 1, cause value 16 (normal call clearing).
GOLDEN_REL = bytes.fromhex("01000c0200028190")

# BLO on CIC 5: CIC + message type only.
GOLDEN_BLO = bytes.fromhex("050013")

# GRS on CIC 1: range only (range octet 4 -> 5 circuits), no status subfield.
GOLDEN_GRS = bytes.fromhex("010017010104")

# CGB on CIC 1: supervision 0, range 3 (-> 4 circuits) + status bitmap 0x0F.
GOLDEN_CGB = bytes.fromhex("010018000102030f")

# ANM on CIC 7: no mandatory parts, optional-part pointer 0.
GOLDEN_ANM = bytes.fromhex("07000900")


def test_message_type_constants() -> None:
    assert itu_isup.MESSAGE_TYPE_IAM == 0x01
    assert itu_isup.MESSAGE_TYPE_ACM == 0x06
    assert itu_isup.MESSAGE_TYPE_ANM == 0x09
    assert itu_isup.MESSAGE_TYPE_REL == 0x0C
    assert itu_isup.MESSAGE_TYPE_RLC == 0x10
    assert itu_isup.MESSAGE_TYPE_CPG == 0x2C
    assert itu_isup.MESSAGE_TYPE_GRS == 0x17
    assert itu_isup.MESSAGE_TYPE_GRA == 0x29
    assert itu_isup.MESSAGE_TYPE_CGB == 0x18


def test_parameter_type_constants() -> None:
    assert itu_isup.PARAM_NATURE_OF_CONNECTION == 0x06
    assert itu_isup.PARAM_FORWARD_CALL_INDICATORS == 0x07
    assert itu_isup.PARAM_CALLED_PARTY_NUMBER == 0x04
    assert itu_isup.PARAM_CALLING_PARTY_NUMBER == 0x0A
    assert itu_isup.PARAM_CAUSE_INDICATORS == 0x12
    assert itu_isup.PARAM_BACKWARD_CALL_INDICATORS == 0x11
    assert itu_isup.PARAM_RANGE_AND_STATUS == 0x16
    assert itu_isup.PARAM_EVENT_INFORMATION == 0x24


def test_iam_matches_golden_vector() -> None:
    called = itu_isup.Number.called("5551234", nature_of_address=3, numbering_plan=1)
    iam = itu_isup.Message.iam(
        1,
        called,
        nature_of_connection=0x00,
        forward_call_indicators=0x2000,
        calling_partys_category=itu_isup.CALLING_PARTY_CATEGORY_ORDINARY,
        transmission_medium_requirement=itu_isup.TMR_SPEECH,
    )
    assert iam.encode() == GOLDEN_IAM


def test_decode_golden_iam() -> None:
    msg = itu_isup.decode(GOLDEN_IAM)
    assert isinstance(msg, itu_isup.Message)
    assert msg.cic == 1
    assert msg.message_type == itu_isup.MESSAGE_TYPE_IAM
    assert msg.mandatory_fixed[0].as_u8() == 0x00  # nature of connection
    assert msg.mandatory_fixed[1].as_u16() == 0x2000  # forward call indicators
    assert msg.mandatory_fixed[2].as_u8() == itu_isup.CALLING_PARTY_CATEGORY_ORDINARY
    called = msg.mandatory_variable[0].as_number()
    assert called.digits == "5551234"
    assert called.numbering_plan == 1
    assert msg.optional == []
    assert msg.encode() == GOLDEN_IAM


def test_iam_with_optional_calling_party_round_trip() -> None:
    called = itu_isup.Number.called("15551234567", nature_of_address=4)
    calling = itu_isup.Number.calling("15559876543", nature_of_address=4, screening=3)
    iam = itu_isup.Message.iam(42, called, forward_call_indicators=0x2000).with_optional(
        itu_isup.Parameter.calling_party_number(calling)
    )
    decoded = itu_isup.decode(iam.encode())
    assert decoded == iam
    got = decoded.optional_parameter(itu_isup.PARAM_CALLING_PARTY_NUMBER)
    assert got is not None
    assert got.as_number().digits == "15559876543"
    assert got.as_number().screening == 3


def test_release_matches_golden_and_fields() -> None:
    rel = itu_isup.Message.release(1, itu_isup.CauseIndicators(1, 16))
    assert rel.encode() == GOLDEN_REL
    decoded = itu_isup.decode(GOLDEN_REL)
    assert decoded.message_type == itu_isup.MESSAGE_TYPE_REL
    cause = decoded.mandatory_variable[0].as_cause_indicators()
    assert cause.location == 1
    assert cause.cause_value == 16
    assert decoded.encode() == GOLDEN_REL


def test_blocking_golden() -> None:
    blo = itu_isup.Message.blocking(5)
    assert blo.encode() == GOLDEN_BLO
    decoded = itu_isup.decode(GOLDEN_BLO)
    assert decoded.cic == 5
    assert decoded.message_type == itu_isup.MESSAGE_TYPE_BLO


def test_circuit_group_reset_golden() -> None:
    grs = itu_isup.Message.circuit_group_reset(1, itu_isup.RangeAndStatus.range_only(4))
    assert grs.encode() == GOLDEN_GRS
    decoded = itu_isup.decode(GOLDEN_GRS)
    rns = decoded.mandatory_variable[0].as_range_and_status()
    assert rns.circuits == 5
    assert rns.status == b""


def test_circuit_group_blocking_golden() -> None:
    cgb = itu_isup.Message.circuit_group_blocking(
        1, 0x00, itu_isup.RangeAndStatus.with_status(3, bytes([0x0F]))
    )
    assert cgb.encode() == GOLDEN_CGB
    decoded = itu_isup.decode(GOLDEN_CGB)
    assert decoded.mandatory_fixed[0].as_u8() == 0x00
    rns = decoded.mandatory_variable[0].as_range_and_status()
    assert rns.circuits == 4
    assert rns.status == bytes([0x0F])


def test_answer_golden() -> None:
    anm = itu_isup.Message.anm(7)
    assert anm.encode() == GOLDEN_ANM
    assert itu_isup.decode(GOLDEN_ANM) == anm


@pytest.mark.parametrize(
    "message",
    [
        itu_isup.Message.acm(1, 0x1010),
        itu_isup.Message.con(1, 0x1010),
        itu_isup.Message.cpg(1, itu_isup.EVENT_ALERTING),
        itu_isup.Message.release_complete(1),
        itu_isup.Message.suspend(1, 0x01),
        itu_isup.Message.resume(1, 0x01),
        itu_isup.Message.forward_transfer(1),
        itu_isup.Message.information_request(1, 0x0001),
        itu_isup.Message.information(1, 0x0001),
        itu_isup.Message.unblocking(1),
        itu_isup.Message.reset_circuit(1),
        itu_isup.Message.circuit_group_reset_ack(1, itu_isup.RangeAndStatus.with_status(3, b"\x0f")),
        itu_isup.Message.circuit_group_unblocking(1, 0, itu_isup.RangeAndStatus.with_status(3, b"\x0f")),
    ],
)
def test_supported_messages_round_trip(message) -> None:
    assert itu_isup.decode(message.encode()) == message


def test_number_encode_decode() -> None:
    n = itu_isup.Number.calling("15559876543", nature_of_address=4, numbering_plan=1, screening=3)
    assert itu_isup.Number.decode(n.encode()) == n
    assert n.digits == "15559876543"


def test_decode_rejects_out_of_scope_type() -> None:
    # Continuity (COT, 0x05) is a valid Q.763 type but out of this codec's scope.
    with pytest.raises(itu_isup.IsupError):
        itu_isup.decode(bytes([0x01, 0x00, 0x05]))


def test_decode_rejects_truncated() -> None:
    with pytest.raises(itu_isup.IsupError):
        itu_isup.decode(b"\x01\x00")


def test_bad_digit_raises() -> None:
    with pytest.raises(itu_isup.IsupError):
        itu_isup.Number.called("55x123", nature_of_address=3).encode()
