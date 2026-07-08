"""itu_isup, Rust-backed ISUP (ITU-T Q.763) message + parameter codec for Python.

ISUP (ISDN User Part) is the SS7 call-control protocol that sets up, supervises
and releases circuit-switched trunks. It is a direct MTP3-user (Service Indicator
5): each message names a circuit by a point code plus a Circuit Identification
Code (CIC). This package exposes the same codec the Rust crate (``cargo add
itu-isup``) ships, the message body (CIC, message type, and the mandatory-fixed /
mandatory-variable / optional parts) and the Q.763 parameter values, from one
source tree / one version.

The wire work (the variable-part pointer arithmetic, address-signal BCD packing,
the optional-part TLV walk) runs in Rust; Python just builds and inspects
messages. This is a codec only: no Q.764 call state machine, no CIC management, no
ISUP<->SIP interworking.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._itu_isup import (
    CALLING_PARTY_CATEGORY_ORDINARY,
    EVENT_ALERTING,
    EVENT_PROGRESS,
    MESSAGE_TYPE_ACM,
    MESSAGE_TYPE_ANM,
    MESSAGE_TYPE_BLA,
    MESSAGE_TYPE_BLO,
    MESSAGE_TYPE_CGB,
    MESSAGE_TYPE_CGBA,
    MESSAGE_TYPE_CGU,
    MESSAGE_TYPE_CGUA,
    MESSAGE_TYPE_CON,
    MESSAGE_TYPE_COT,
    MESSAGE_TYPE_CPG,
    MESSAGE_TYPE_FOT,
    MESSAGE_TYPE_GRA,
    MESSAGE_TYPE_GRS,
    MESSAGE_TYPE_IAM,
    MESSAGE_TYPE_INF,
    MESSAGE_TYPE_INR,
    MESSAGE_TYPE_REL,
    MESSAGE_TYPE_RES,
    MESSAGE_TYPE_RLC,
    MESSAGE_TYPE_RSC,
    MESSAGE_TYPE_SAM,
    MESSAGE_TYPE_SUS,
    MESSAGE_TYPE_UBA,
    MESSAGE_TYPE_UBL,
    PARAM_BACKWARD_CALL_INDICATORS,
    PARAM_CALLED_PARTY_NUMBER,
    PARAM_CALLING_PARTY_NUMBER,
    PARAM_CALLING_PARTYS_CATEGORY,
    PARAM_CAUSE_INDICATORS,
    PARAM_CIRCUIT_GROUP_SUPERVISION,
    PARAM_EVENT_INFORMATION,
    PARAM_FORWARD_CALL_INDICATORS,
    PARAM_INFORMATION_INDICATORS,
    PARAM_INFORMATION_REQUEST_INDICATORS,
    PARAM_NATURE_OF_CONNECTION,
    PARAM_RANGE_AND_STATUS,
    PARAM_REDIRECTING_NUMBER,
    PARAM_REDIRECTION_INFORMATION,
    PARAM_REDIRECTION_NUMBER,
    PARAM_SUSPEND_RESUME_INDICATORS,
    PARAM_TRANSMISSION_MEDIUM_REQUIREMENT,
    PARAM_USER_SERVICE_INFORMATION,
    TMR_3_1_KHZ_AUDIO,
    TMR_SPEECH,
    CauseIndicators,
    IsupError,
    Message,
    Number,
    Parameter,
    RangeAndStatus,
    decode,
)

try:
    __version__ = version("itu-isup")
except PackageNotFoundError:  # running from a source checkout without an installed dist
    __version__ = "0.0.0+unknown"

__all__ = [
    # structured values + messages + codec
    "Number",
    "CauseIndicators",
    "RangeAndStatus",
    "Parameter",
    "Message",
    "decode",
    "IsupError",
    # message-type codes
    "MESSAGE_TYPE_IAM",
    "MESSAGE_TYPE_SAM",
    "MESSAGE_TYPE_INR",
    "MESSAGE_TYPE_INF",
    "MESSAGE_TYPE_COT",
    "MESSAGE_TYPE_ACM",
    "MESSAGE_TYPE_CON",
    "MESSAGE_TYPE_FOT",
    "MESSAGE_TYPE_ANM",
    "MESSAGE_TYPE_REL",
    "MESSAGE_TYPE_SUS",
    "MESSAGE_TYPE_RES",
    "MESSAGE_TYPE_RLC",
    "MESSAGE_TYPE_RSC",
    "MESSAGE_TYPE_BLO",
    "MESSAGE_TYPE_UBL",
    "MESSAGE_TYPE_BLA",
    "MESSAGE_TYPE_UBA",
    "MESSAGE_TYPE_GRS",
    "MESSAGE_TYPE_GRA",
    "MESSAGE_TYPE_CGB",
    "MESSAGE_TYPE_CGU",
    "MESSAGE_TYPE_CGBA",
    "MESSAGE_TYPE_CGUA",
    "MESSAGE_TYPE_CPG",
    # parameter-name codes
    "PARAM_NATURE_OF_CONNECTION",
    "PARAM_FORWARD_CALL_INDICATORS",
    "PARAM_BACKWARD_CALL_INDICATORS",
    "PARAM_CALLING_PARTYS_CATEGORY",
    "PARAM_TRANSMISSION_MEDIUM_REQUIREMENT",
    "PARAM_CALLED_PARTY_NUMBER",
    "PARAM_CALLING_PARTY_NUMBER",
    "PARAM_REDIRECTING_NUMBER",
    "PARAM_REDIRECTION_NUMBER",
    "PARAM_CAUSE_INDICATORS",
    "PARAM_EVENT_INFORMATION",
    "PARAM_REDIRECTION_INFORMATION",
    "PARAM_RANGE_AND_STATUS",
    "PARAM_CIRCUIT_GROUP_SUPERVISION",
    "PARAM_SUSPEND_RESUME_INDICATORS",
    "PARAM_INFORMATION_REQUEST_INDICATORS",
    "PARAM_INFORMATION_INDICATORS",
    "PARAM_USER_SERVICE_INFORMATION",
    # well-known field values
    "CALLING_PARTY_CATEGORY_ORDINARY",
    "TMR_SPEECH",
    "TMR_3_1_KHZ_AUDIO",
    "EVENT_ALERTING",
    "EVENT_PROGRESS",
    "__version__",
]
