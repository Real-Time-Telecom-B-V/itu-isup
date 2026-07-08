"""Type stubs for the Rust-backed ``itu_isup._itu_isup`` extension module."""

from __future__ import annotations

# ── Message-type codes (Q.763 Table 4) ───────────────────────────────────────
MESSAGE_TYPE_IAM: int
MESSAGE_TYPE_SAM: int
MESSAGE_TYPE_INR: int
MESSAGE_TYPE_INF: int
MESSAGE_TYPE_COT: int
MESSAGE_TYPE_ACM: int
MESSAGE_TYPE_CON: int
MESSAGE_TYPE_FOT: int
MESSAGE_TYPE_ANM: int
MESSAGE_TYPE_REL: int
MESSAGE_TYPE_SUS: int
MESSAGE_TYPE_RES: int
MESSAGE_TYPE_RLC: int
MESSAGE_TYPE_RSC: int
MESSAGE_TYPE_BLO: int
MESSAGE_TYPE_UBL: int
MESSAGE_TYPE_BLA: int
MESSAGE_TYPE_UBA: int
MESSAGE_TYPE_GRS: int
MESSAGE_TYPE_GRA: int
MESSAGE_TYPE_CGB: int
MESSAGE_TYPE_CGU: int
MESSAGE_TYPE_CGBA: int
MESSAGE_TYPE_CGUA: int
MESSAGE_TYPE_CPG: int

# ── Parameter-name codes (Q.763 Table 5) ─────────────────────────────────────
PARAM_NATURE_OF_CONNECTION: int
PARAM_FORWARD_CALL_INDICATORS: int
PARAM_BACKWARD_CALL_INDICATORS: int
PARAM_CALLING_PARTYS_CATEGORY: int
PARAM_TRANSMISSION_MEDIUM_REQUIREMENT: int
PARAM_CALLED_PARTY_NUMBER: int
PARAM_CALLING_PARTY_NUMBER: int
PARAM_REDIRECTING_NUMBER: int
PARAM_REDIRECTION_NUMBER: int
PARAM_CAUSE_INDICATORS: int
PARAM_EVENT_INFORMATION: int
PARAM_REDIRECTION_INFORMATION: int
PARAM_RANGE_AND_STATUS: int
PARAM_CIRCUIT_GROUP_SUPERVISION: int
PARAM_SUSPEND_RESUME_INDICATORS: int
PARAM_INFORMATION_REQUEST_INDICATORS: int
PARAM_INFORMATION_INDICATORS: int
PARAM_USER_SERVICE_INFORMATION: int

# ── Well-known field values ──────────────────────────────────────────────────
CALLING_PARTY_CATEGORY_ORDINARY: int
TMR_SPEECH: int
TMR_3_1_KHZ_AUDIO: int
EVENT_ALERTING: int
EVENT_PROGRESS: int

class IsupError(Exception):
    """ISUP protocol / codec error (ITU-T Q.763)."""

class Number:
    """An ISUP number parameter value (called / calling / redirecting / redirection)."""

    digits: str
    nature_of_address: int
    numbering_plan: int
    presentation: int
    screening: int
    @staticmethod
    def called(
        digits: str, *, nature_of_address: int, numbering_plan: int = 1, inn: bool = False
    ) -> Number:
        """Build a called party / redirection number."""
    @staticmethod
    def calling(
        digits: str,
        *,
        nature_of_address: int,
        numbering_plan: int = 1,
        ni: bool = False,
        presentation: int = 0,
        screening: int = 0,
    ) -> Number:
        """Build a calling party number."""
    @staticmethod
    def redirecting(
        digits: str, *, nature_of_address: int, numbering_plan: int = 1, presentation: int = 0
    ) -> Number:
        """Build a redirecting number."""
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> Number: ...
    def __eq__(self, other: object) -> bool: ...

class CauseIndicators:
    """A decoded Cause indicators value (Q.850)."""

    location: int
    coding_standard: int
    cause_value: int
    diagnostics: bytes
    def __init__(
        self,
        location: int,
        cause_value: int,
        *,
        coding_standard: int = 0,
        diagnostics: bytes = ...,
    ) -> None: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> CauseIndicators: ...
    def __eq__(self, other: object) -> bool: ...

class RangeAndStatus:
    """A decoded Range and status value."""

    range: int
    circuits: int
    status: bytes
    @staticmethod
    def range_only(range: int) -> RangeAndStatus: ...
    @staticmethod
    def with_status(range: int, status: bytes) -> RangeAndStatus: ...
    def encode(self) -> bytes: ...
    @staticmethod
    def decode(data: bytes) -> RangeAndStatus: ...
    def __eq__(self, other: object) -> bool: ...

class Parameter:
    """An ISUP parameter: a name code plus its raw value octets."""

    code: int
    value: bytes
    def __init__(self, code: int, value: bytes) -> None: ...
    @staticmethod
    def nature_of_connection(indicators: int) -> Parameter: ...
    @staticmethod
    def forward_call_indicators(indicators: int) -> Parameter: ...
    @staticmethod
    def backward_call_indicators(indicators: int) -> Parameter: ...
    @staticmethod
    def calling_partys_category(category: int) -> Parameter: ...
    @staticmethod
    def transmission_medium_requirement(tmr: int) -> Parameter: ...
    @staticmethod
    def event_information(event: int) -> Parameter: ...
    @staticmethod
    def suspend_resume_indicators(indicators: int) -> Parameter: ...
    @staticmethod
    def information_request_indicators(indicators: int) -> Parameter: ...
    @staticmethod
    def information_indicators(indicators: int) -> Parameter: ...
    @staticmethod
    def circuit_group_supervision(indicator: int) -> Parameter: ...
    @staticmethod
    def called_party_number(number: Number) -> Parameter: ...
    @staticmethod
    def calling_party_number(number: Number) -> Parameter: ...
    @staticmethod
    def redirecting_number(number: Number) -> Parameter: ...
    @staticmethod
    def redirection_number(number: Number) -> Parameter: ...
    @staticmethod
    def cause_indicators(cause: CauseIndicators) -> Parameter: ...
    @staticmethod
    def range_and_status(rns: RangeAndStatus) -> Parameter: ...
    @staticmethod
    def user_service_information(value: bytes) -> Parameter: ...
    @staticmethod
    def redirection_information(value: bytes) -> Parameter: ...
    def as_number(self) -> Number: ...
    def as_cause_indicators(self) -> CauseIndicators: ...
    def as_range_and_status(self) -> RangeAndStatus: ...
    def as_u8(self) -> int: ...
    def as_u16(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...

class Message:
    """An ISUP message: a CIC, a message type and the three parameter parts."""

    cic: int
    message_type: int
    mandatory_fixed: list[Parameter]
    mandatory_variable: list[Parameter]
    optional: list[Parameter]
    def __init__(
        self,
        cic: int,
        message_type: int,
        *,
        mandatory_fixed: list[Parameter] = ...,
        mandatory_variable: list[Parameter] = ...,
        optional: list[Parameter] = ...,
    ) -> None: ...
    @staticmethod
    def iam(
        cic: int,
        called_party: Number,
        *,
        nature_of_connection: int = 0,
        forward_call_indicators: int = 0,
        calling_partys_category: int = 0x0A,
        transmission_medium_requirement: int = 0,
    ) -> Message: ...
    @staticmethod
    def acm(cic: int, backward_call_indicators: int) -> Message: ...
    @staticmethod
    def con(cic: int, backward_call_indicators: int) -> Message: ...
    @staticmethod
    def anm(cic: int) -> Message: ...
    @staticmethod
    def cpg(cic: int, event: int) -> Message: ...
    @staticmethod
    def release(cic: int, cause: CauseIndicators) -> Message: ...
    @staticmethod
    def release_complete(cic: int) -> Message: ...
    @staticmethod
    def suspend(cic: int, indicators: int) -> Message: ...
    @staticmethod
    def resume(cic: int, indicators: int) -> Message: ...
    @staticmethod
    def forward_transfer(cic: int) -> Message: ...
    @staticmethod
    def information_request(cic: int, indicators: int) -> Message: ...
    @staticmethod
    def information(cic: int, indicators: int) -> Message: ...
    @staticmethod
    def blocking(cic: int) -> Message: ...
    @staticmethod
    def blocking_ack(cic: int) -> Message: ...
    @staticmethod
    def unblocking(cic: int) -> Message: ...
    @staticmethod
    def unblocking_ack(cic: int) -> Message: ...
    @staticmethod
    def reset_circuit(cic: int) -> Message: ...
    @staticmethod
    def circuit_group_reset(cic: int, range_and_status: RangeAndStatus) -> Message: ...
    @staticmethod
    def circuit_group_reset_ack(cic: int, range_and_status: RangeAndStatus) -> Message: ...
    @staticmethod
    def circuit_group_blocking(cic: int, supervision: int, rns: RangeAndStatus) -> Message: ...
    @staticmethod
    def circuit_group_unblocking(cic: int, supervision: int, rns: RangeAndStatus) -> Message: ...
    @staticmethod
    def circuit_group_blocking_ack(cic: int, supervision: int, rns: RangeAndStatus) -> Message: ...
    @staticmethod
    def circuit_group_unblocking_ack(
        cic: int, supervision: int, rns: RangeAndStatus
    ) -> Message: ...
    def with_optional(self, parameter: Parameter) -> Message: ...
    def optional_parameter(self, code: int) -> Parameter | None: ...
    def encode(self) -> bytes: ...
    def __eq__(self, other: object) -> bool: ...

def decode(data: bytes) -> Message:
    """Decode a whole ISUP message body into a :class:`Message`."""
