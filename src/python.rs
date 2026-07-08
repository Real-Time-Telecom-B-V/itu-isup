//! PyO3 bindings, `pip install itu-isup` gives a Rust-backed wheel exposing the
//! **same** ISUP (ITU-T Q.763) message + parameter codec the crate ships.
//!
//! Compiled only with `--features python`; the default crate build is pyo3-free, so
//! `cargo add itu-isup` / crates.io consumers pull zero pyo3. Two entry points share one
//! `add_contents()`:
//! * `#[pymodule] fn _itu_isup`, the standalone wheel (maturin `module-name`).
//! * `pub fn register(py, parent)`, mount `itu_isup` as a submodule of another
//!   extension, so a host can expose itu_isup without a second shared object.
//!
//! The Python surface mirrors the Rust one: [`PyNumber`] builds the number
//! parameters, [`PyCauseIndicators`] / [`PyRangeAndStatus`] the structured values,
//! [`PyParameter`] the generic TLV with typed builders and accessors, and
//! [`PyMessage`] builds and parses whole messages (`itu_isup.decode(...)` dispatches on
//! the message-type octet). The module is declared `gil_used = false`, so it loads
//! on free-threaded ("no-GIL") CPython.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

use crate::{
    CauseIndicators, IsupError as CoreIsupError, Message, MessageType, Number, Parameter,
    ParameterType, RangeAndStatus,
};

// ── Error mapping ───────────────────────────────────────────────────────────
create_exception!(
    itu_isup,
    IsupError,
    PyException,
    "ISUP protocol / codec error (ITU-T Q.763)."
);

fn isup_err(e: CoreIsupError) -> PyErr {
    IsupError::new_err(e.to_string())
}

// ── Number (Q.763 §3.9, §3.10, §3.44, §3.46) ────────────────────────────────
/// An ISUP number parameter value (called / calling / redirecting / redirection).
#[pyclass(name = "Number", module = "itu_isup._itu_isup", from_py_object)]
#[derive(Clone)]
pub struct PyNumber {
    inner: Number,
}

#[pymethods]
impl PyNumber {
    /// Build a called party / redirection number: NAI, numbering plan, the INN
    /// indicator, and digits.
    #[staticmethod]
    #[pyo3(signature = (digits, *, nature_of_address, numbering_plan = 1, inn = false))]
    fn called(digits: &str, nature_of_address: u8, numbering_plan: u8, inn: bool) -> Self {
        Self {
            inner: Number::called(nature_of_address, numbering_plan, inn, digits),
        }
    }

    /// Build a calling party number: NAI, numbering plan, the NI indicator, the
    /// presentation and screening indicators, and digits.
    #[staticmethod]
    #[pyo3(signature = (digits, *, nature_of_address, numbering_plan = 1, ni = false, presentation = 0, screening = 0))]
    fn calling(
        digits: &str,
        nature_of_address: u8,
        numbering_plan: u8,
        ni: bool,
        presentation: u8,
        screening: u8,
    ) -> Self {
        Self {
            inner: Number::calling(
                nature_of_address,
                numbering_plan,
                ni,
                presentation,
                screening,
                digits,
            ),
        }
    }

    /// Build a redirecting number: NAI, numbering plan, presentation, and digits.
    #[staticmethod]
    #[pyo3(signature = (digits, *, nature_of_address, numbering_plan = 1, presentation = 0))]
    fn redirecting(
        digits: &str,
        nature_of_address: u8,
        numbering_plan: u8,
        presentation: u8,
    ) -> Self {
        Self {
            inner: Number::redirecting(nature_of_address, numbering_plan, presentation, digits),
        }
    }

    /// The address digits.
    #[getter]
    fn digits(&self) -> String {
        self.inner.digits.clone()
    }

    /// The nature-of-address indicator (7 bits).
    #[getter]
    fn nature_of_address(&self) -> u8 {
        self.inner.nature_of_address
    }

    /// The numbering-plan indicator (3 bits).
    #[getter]
    fn numbering_plan(&self) -> u8 {
        self.inner.numbering_plan()
    }

    /// The presentation-restricted indicator (2 bits).
    #[getter]
    fn presentation(&self) -> u8 {
        self.inner.presentation()
    }

    /// The screening indicator (2 bits, calling party number).
    #[getter]
    fn screening(&self) -> u8 {
        self.inner.screening()
    }

    /// Encode to the parameter value octets.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode().map_err(isup_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    /// Decode a number from its parameter value octets.
    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Number::decode(data).map_err(isup_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!("Number(digits={:?})", self.inner.digits)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// ── CauseIndicators (Q.763 §3.12 / Q.850) ───────────────────────────────────
/// A decoded Cause indicators value.
#[pyclass(
    name = "CauseIndicators",
    module = "itu_isup._itu_isup",
    from_py_object
)]
#[derive(Clone)]
pub struct PyCauseIndicators {
    inner: CauseIndicators,
}

#[pymethods]
impl PyCauseIndicators {
    #[new]
    #[pyo3(signature = (location, cause_value, *, coding_standard = 0, diagnostics = Vec::new()))]
    fn new(location: u8, cause_value: u8, coding_standard: u8, diagnostics: Vec<u8>) -> Self {
        Self {
            inner: CauseIndicators {
                location,
                coding_standard,
                cause_value,
                diagnostics,
            },
        }
    }

    /// The cause location (4 bits).
    #[getter]
    fn location(&self) -> u8 {
        self.inner.location
    }

    /// The coding standard (2 bits; 0 = ITU-T).
    #[getter]
    fn coding_standard(&self) -> u8 {
        self.inner.coding_standard
    }

    /// The Q.850 cause value (7 bits).
    #[getter]
    fn cause_value(&self) -> u8 {
        self.inner.cause_value
    }

    /// The diagnostic octets.
    #[getter]
    fn diagnostics<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.diagnostics)
    }

    /// Encode to the parameter value octets.
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    /// Decode from the parameter value octets.
    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: CauseIndicators::decode(data).map_err(isup_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "CauseIndicators(location={}, cause_value={})",
            self.inner.location, self.inner.cause_value
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// ── RangeAndStatus (Q.763 §3.43) ────────────────────────────────────────────
/// A decoded Range and status value.
#[pyclass(name = "RangeAndStatus", module = "itu_isup._itu_isup", from_py_object)]
#[derive(Clone)]
pub struct PyRangeAndStatus {
    inner: RangeAndStatus,
}

#[pymethods]
impl PyRangeAndStatus {
    /// Build a range-only value (no status subfield), as used by GRS.
    #[staticmethod]
    fn range_only(range: u8) -> Self {
        Self {
            inner: RangeAndStatus::range_only(range),
        }
    }

    /// Build a range + status value, as used by the circuit-group blocking /
    /// unblocking / reset-acknowledgement messages.
    #[staticmethod]
    fn with_status(range: u8, status: Vec<u8>) -> Self {
        Self {
            inner: RangeAndStatus::with_status(range, status),
        }
    }

    /// The wire range octet (`circuits - 1`).
    #[getter]
    fn range(&self) -> u8 {
        self.inner.range
    }

    /// The number of circuits the range covers (`range + 1`).
    #[getter]
    fn circuits(&self) -> u16 {
        self.inner.circuits()
    }

    /// The status bitmap.
    #[getter]
    fn status<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.status)
    }

    /// Encode to the parameter value octets.
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    /// Decode from the parameter value octets.
    #[staticmethod]
    fn decode(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: RangeAndStatus::decode(data).map_err(isup_err)?,
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "RangeAndStatus(range={}, status_len={})",
            self.inner.range,
            self.inner.status.len()
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// ── Parameter (the generic TLV) ─────────────────────────────────────────────
/// An ISUP parameter: a name code plus its raw value octets.
#[pyclass(name = "Parameter", module = "itu_isup._itu_isup", from_py_object)]
#[derive(Clone)]
pub struct PyParameter {
    inner: Parameter,
}

#[pymethods]
impl PyParameter {
    #[new]
    fn new(code: u8, value: Vec<u8>) -> Self {
        Self {
            inner: Parameter::new(ParameterType::from_u8(code), value),
        }
    }

    /// The parameter name code.
    #[getter]
    fn code(&self) -> u8 {
        self.inner.code.value()
    }

    /// The raw value octets.
    #[getter]
    fn value<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.value)
    }

    // Typed builders.

    /// Nature of connection indicators.
    #[staticmethod]
    fn nature_of_connection(indicators: u8) -> Self {
        Self {
            inner: Parameter::nature_of_connection(indicators),
        }
    }

    /// Forward call indicators.
    #[staticmethod]
    fn forward_call_indicators(indicators: u16) -> Self {
        Self {
            inner: Parameter::forward_call_indicators(indicators),
        }
    }

    /// Backward call indicators.
    #[staticmethod]
    fn backward_call_indicators(indicators: u16) -> Self {
        Self {
            inner: Parameter::backward_call_indicators(indicators),
        }
    }

    /// Calling party's category.
    #[staticmethod]
    fn calling_partys_category(category: u8) -> Self {
        Self {
            inner: Parameter::calling_partys_category(category),
        }
    }

    /// Transmission medium requirement.
    #[staticmethod]
    fn transmission_medium_requirement(tmr: u8) -> Self {
        Self {
            inner: Parameter::transmission_medium_requirement(tmr),
        }
    }

    /// Event information.
    #[staticmethod]
    fn event_information(event: u8) -> Self {
        Self {
            inner: Parameter::event_information(event),
        }
    }

    /// Suspend/resume indicators.
    #[staticmethod]
    fn suspend_resume_indicators(indicators: u8) -> Self {
        Self {
            inner: Parameter::suspend_resume_indicators(indicators),
        }
    }

    /// Information request indicators.
    #[staticmethod]
    fn information_request_indicators(indicators: u16) -> Self {
        Self {
            inner: Parameter::information_request_indicators(indicators),
        }
    }

    /// Information indicators.
    #[staticmethod]
    fn information_indicators(indicators: u16) -> Self {
        Self {
            inner: Parameter::information_indicators(indicators),
        }
    }

    /// Circuit group supervision message type indicator.
    #[staticmethod]
    fn circuit_group_supervision(indicator: u8) -> Self {
        Self {
            inner: Parameter::circuit_group_supervision(indicator),
        }
    }

    /// Called party number.
    #[staticmethod]
    fn called_party_number(number: &PyNumber) -> PyResult<Self> {
        Ok(Self {
            inner: Parameter::called_party_number(&number.inner).map_err(isup_err)?,
        })
    }

    /// Calling party number.
    #[staticmethod]
    fn calling_party_number(number: &PyNumber) -> PyResult<Self> {
        Ok(Self {
            inner: Parameter::calling_party_number(&number.inner).map_err(isup_err)?,
        })
    }

    /// Redirecting number.
    #[staticmethod]
    fn redirecting_number(number: &PyNumber) -> PyResult<Self> {
        Ok(Self {
            inner: Parameter::redirecting_number(&number.inner).map_err(isup_err)?,
        })
    }

    /// Redirection number.
    #[staticmethod]
    fn redirection_number(number: &PyNumber) -> PyResult<Self> {
        Ok(Self {
            inner: Parameter::redirection_number(&number.inner).map_err(isup_err)?,
        })
    }

    /// Cause indicators.
    #[staticmethod]
    fn cause_indicators(cause: &PyCauseIndicators) -> Self {
        Self {
            inner: Parameter::cause_indicators(&cause.inner),
        }
    }

    /// Range and status.
    #[staticmethod]
    fn range_and_status(rns: &PyRangeAndStatus) -> Self {
        Self {
            inner: Parameter::range_and_status(&rns.inner),
        }
    }

    /// User service information (Q.931 bearer capability, verbatim).
    #[staticmethod]
    fn user_service_information(value: &[u8]) -> Self {
        Self {
            inner: Parameter::user_service_information(value),
        }
    }

    /// Redirection information (verbatim).
    #[staticmethod]
    fn redirection_information(value: &[u8]) -> Self {
        Self {
            inner: Parameter::redirection_information(value),
        }
    }

    // Accessors.

    /// Parse the value as a [`PyNumber`].
    fn as_number(&self) -> PyResult<PyNumber> {
        Ok(PyNumber {
            inner: self.inner.as_number().map_err(isup_err)?,
        })
    }

    /// Parse the value as [`PyCauseIndicators`].
    fn as_cause_indicators(&self) -> PyResult<PyCauseIndicators> {
        Ok(PyCauseIndicators {
            inner: self.inner.as_cause_indicators().map_err(isup_err)?,
        })
    }

    /// Parse the value as [`PyRangeAndStatus`].
    fn as_range_and_status(&self) -> PyResult<PyRangeAndStatus> {
        Ok(PyRangeAndStatus {
            inner: self.inner.as_range_and_status().map_err(isup_err)?,
        })
    }

    /// The value as a single octet.
    fn as_u8(&self) -> PyResult<u8> {
        self.inner.as_u8().map_err(isup_err)
    }

    /// The value as a big-endian `u16`.
    fn as_u16(&self) -> PyResult<u16> {
        self.inner.as_u16().map_err(isup_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "Parameter(code=0x{:02x}, len={})",
            self.inner.code.value(),
            self.inner.value.len()
        )
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

fn params(list: Vec<PyParameter>) -> Vec<Parameter> {
    list.into_iter().map(|p| p.inner).collect()
}

fn py_params(list: &[Parameter]) -> Vec<PyParameter> {
    list.iter()
        .map(|p| PyParameter { inner: p.clone() })
        .collect()
}

// ── Message ─────────────────────────────────────────────────────────────────
/// An ISUP message: a CIC, a message type and the three parameter parts.
#[pyclass(name = "Message", module = "itu_isup._itu_isup", skip_from_py_object)]
#[derive(Clone)]
pub struct PyMessage {
    inner: Message,
}

impl PyMessage {
    fn wrap(inner: Message) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyMessage {
    #[new]
    #[pyo3(signature = (cic, message_type, *, mandatory_fixed = Vec::new(), mandatory_variable = Vec::new(), optional = Vec::new()))]
    fn new(
        cic: u16,
        message_type: u8,
        mandatory_fixed: Vec<PyParameter>,
        mandatory_variable: Vec<PyParameter>,
        optional: Vec<PyParameter>,
    ) -> Self {
        Self {
            inner: Message {
                cic,
                message_type: MessageType::from_u8(message_type),
                mandatory_fixed: params(mandatory_fixed),
                mandatory_variable: params(mandatory_variable),
                optional: params(optional),
            },
        }
    }

    /// Initial Address Message (IAM).
    #[staticmethod]
    #[pyo3(signature = (cic, called_party, *, nature_of_connection = 0, forward_call_indicators = 0, calling_partys_category = 0x0A, transmission_medium_requirement = 0))]
    fn iam(
        cic: u16,
        called_party: &PyNumber,
        nature_of_connection: u8,
        forward_call_indicators: u16,
        calling_partys_category: u8,
        transmission_medium_requirement: u8,
    ) -> PyResult<Self> {
        Ok(Self::wrap(
            Message::iam(
                cic,
                nature_of_connection,
                forward_call_indicators,
                calling_partys_category,
                transmission_medium_requirement,
                &called_party.inner,
            )
            .map_err(isup_err)?,
        ))
    }

    /// Address Complete Message (ACM).
    #[staticmethod]
    fn acm(cic: u16, backward_call_indicators: u16) -> Self {
        Self::wrap(Message::acm(cic, backward_call_indicators))
    }

    /// Connect (CON).
    #[staticmethod]
    fn con(cic: u16, backward_call_indicators: u16) -> Self {
        Self::wrap(Message::con(cic, backward_call_indicators))
    }

    /// Answer (ANM).
    #[staticmethod]
    fn anm(cic: u16) -> Self {
        Self::wrap(Message::anm(cic))
    }

    /// Call Progress (CPG).
    #[staticmethod]
    fn cpg(cic: u16, event: u8) -> Self {
        Self::wrap(Message::cpg(cic, event))
    }

    /// Release (REL).
    #[staticmethod]
    fn release(cic: u16, cause: &PyCauseIndicators) -> Self {
        Self::wrap(Message::release(cic, &cause.inner))
    }

    /// Release Complete (RLC).
    #[staticmethod]
    fn release_complete(cic: u16) -> Self {
        Self::wrap(Message::release_complete(cic))
    }

    /// Suspend (SUS).
    #[staticmethod]
    fn suspend(cic: u16, indicators: u8) -> Self {
        Self::wrap(Message::suspend(cic, indicators))
    }

    /// Resume (RES).
    #[staticmethod]
    fn resume(cic: u16, indicators: u8) -> Self {
        Self::wrap(Message::resume(cic, indicators))
    }

    /// Forward Transfer (FOT).
    #[staticmethod]
    fn forward_transfer(cic: u16) -> Self {
        Self::wrap(Message::forward_transfer(cic))
    }

    /// Information Request (INR).
    #[staticmethod]
    fn information_request(cic: u16, indicators: u16) -> Self {
        Self::wrap(Message::information_request(cic, indicators))
    }

    /// Information (INF).
    #[staticmethod]
    fn information(cic: u16, indicators: u16) -> Self {
        Self::wrap(Message::information(cic, indicators))
    }

    /// Blocking (BLO).
    #[staticmethod]
    fn blocking(cic: u16) -> Self {
        Self::wrap(Message::blocking(cic))
    }

    /// Blocking Acknowledgement (BLA).
    #[staticmethod]
    fn blocking_ack(cic: u16) -> Self {
        Self::wrap(Message::blocking_ack(cic))
    }

    /// Unblocking (UBL).
    #[staticmethod]
    fn unblocking(cic: u16) -> Self {
        Self::wrap(Message::unblocking(cic))
    }

    /// Unblocking Acknowledgement (UBA).
    #[staticmethod]
    fn unblocking_ack(cic: u16) -> Self {
        Self::wrap(Message::unblocking_ack(cic))
    }

    /// Reset Circuit (RSC).
    #[staticmethod]
    fn reset_circuit(cic: u16) -> Self {
        Self::wrap(Message::reset_circuit(cic))
    }

    /// Circuit Group Reset (GRS).
    #[staticmethod]
    fn circuit_group_reset(cic: u16, range_and_status: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_reset(cic, &range_and_status.inner))
    }

    /// Circuit Group Reset Acknowledgement (GRA).
    #[staticmethod]
    fn circuit_group_reset_ack(cic: u16, range_and_status: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_reset_ack(
            cic,
            &range_and_status.inner,
        ))
    }

    /// Circuit Group Blocking (CGB).
    #[staticmethod]
    fn circuit_group_blocking(cic: u16, supervision: u8, rns: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_blocking(
            cic,
            supervision,
            &rns.inner,
        ))
    }

    /// Circuit Group Unblocking (CGU).
    #[staticmethod]
    fn circuit_group_unblocking(cic: u16, supervision: u8, rns: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_unblocking(
            cic,
            supervision,
            &rns.inner,
        ))
    }

    /// Circuit Group Blocking Acknowledgement (CGBA).
    #[staticmethod]
    fn circuit_group_blocking_ack(cic: u16, supervision: u8, rns: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_blocking_ack(
            cic,
            supervision,
            &rns.inner,
        ))
    }

    /// Circuit Group Unblocking Acknowledgement (CGUA).
    #[staticmethod]
    fn circuit_group_unblocking_ack(cic: u16, supervision: u8, rns: &PyRangeAndStatus) -> Self {
        Self::wrap(Message::circuit_group_unblocking_ack(
            cic,
            supervision,
            &rns.inner,
        ))
    }

    /// The Circuit Identification Code.
    #[getter]
    fn cic(&self) -> u16 {
        self.inner.cic
    }

    /// The message type code.
    #[getter]
    fn message_type(&self) -> u8 {
        self.inner.message_type.value()
    }

    /// The mandatory fixed-part parameters.
    #[getter]
    fn mandatory_fixed(&self) -> Vec<PyParameter> {
        py_params(&self.inner.mandatory_fixed)
    }

    /// The mandatory variable-part parameters.
    #[getter]
    fn mandatory_variable(&self) -> Vec<PyParameter> {
        py_params(&self.inner.mandatory_variable)
    }

    /// The optional-part parameters.
    #[getter]
    fn optional(&self) -> Vec<PyParameter> {
        py_params(&self.inner.optional)
    }

    /// Return a copy with `parameter` appended to the optional part.
    fn with_optional(&self, parameter: &PyParameter) -> Self {
        Self::wrap(self.inner.clone().with_optional(parameter.inner.clone()))
    }

    /// The first optional parameter with `code`, or `None`.
    fn optional_parameter(&self, code: u8) -> Option<PyParameter> {
        self.inner
            .optional(ParameterType::from_u8(code))
            .map(|p| PyParameter { inner: p.clone() })
    }

    /// Encode the whole message (CIC, type, and all three parts).
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode().map_err(isup_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn __repr__(&self) -> String {
        format!("Message({})", self.inner)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

// ── decode() ────────────────────────────────────────────────────────────────
/// Decode a whole ISUP message body (CIC, message type, and the three parts)
/// into a [`Message`]. Raises `IsupError` for a message type this codec does not
/// model, or on a malformed body.
#[pyfunction]
fn decode(data: &[u8]) -> PyResult<PyMessage> {
    Ok(PyMessage {
        inner: Message::decode(data).map_err(isup_err)?,
    })
}

// ── Module wiring ───────────────────────────────────────────────────────────
fn add_contents(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("IsupError", m.py().get_type::<IsupError>())?;
    m.add_class::<PyNumber>()?;
    m.add_class::<PyCauseIndicators>()?;
    m.add_class::<PyRangeAndStatus>()?;
    m.add_class::<PyParameter>()?;
    m.add_class::<PyMessage>()?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;

    // Message-type codes (Q.763 Table 4).
    for (name, mt) in [
        ("MESSAGE_TYPE_IAM", MessageType::Iam),
        ("MESSAGE_TYPE_SAM", MessageType::Sam),
        ("MESSAGE_TYPE_INR", MessageType::Inr),
        ("MESSAGE_TYPE_INF", MessageType::Inf),
        ("MESSAGE_TYPE_COT", MessageType::Cot),
        ("MESSAGE_TYPE_ACM", MessageType::Acm),
        ("MESSAGE_TYPE_CON", MessageType::Con),
        ("MESSAGE_TYPE_FOT", MessageType::Fot),
        ("MESSAGE_TYPE_ANM", MessageType::Anm),
        ("MESSAGE_TYPE_REL", MessageType::Rel),
        ("MESSAGE_TYPE_SUS", MessageType::Sus),
        ("MESSAGE_TYPE_RES", MessageType::Res),
        ("MESSAGE_TYPE_RLC", MessageType::Rlc),
        ("MESSAGE_TYPE_RSC", MessageType::Rsc),
        ("MESSAGE_TYPE_BLO", MessageType::Blo),
        ("MESSAGE_TYPE_UBL", MessageType::Ubl),
        ("MESSAGE_TYPE_BLA", MessageType::Bla),
        ("MESSAGE_TYPE_UBA", MessageType::Uba),
        ("MESSAGE_TYPE_GRS", MessageType::Grs),
        ("MESSAGE_TYPE_CGB", MessageType::Cgb),
        ("MESSAGE_TYPE_CGU", MessageType::Cgu),
        ("MESSAGE_TYPE_CGBA", MessageType::Cgba),
        ("MESSAGE_TYPE_CGUA", MessageType::Cgua),
        ("MESSAGE_TYPE_GRA", MessageType::Gra),
        ("MESSAGE_TYPE_CPG", MessageType::Cpg),
    ] {
        m.add(name, mt.value())?;
    }

    // Parameter-name codes (Q.763 Table 5).
    for (name, pt) in [
        (
            "PARAM_NATURE_OF_CONNECTION",
            ParameterType::NatureOfConnectionIndicators,
        ),
        (
            "PARAM_FORWARD_CALL_INDICATORS",
            ParameterType::ForwardCallIndicators,
        ),
        (
            "PARAM_BACKWARD_CALL_INDICATORS",
            ParameterType::BackwardCallIndicators,
        ),
        (
            "PARAM_CALLING_PARTYS_CATEGORY",
            ParameterType::CallingPartysCategory,
        ),
        (
            "PARAM_TRANSMISSION_MEDIUM_REQUIREMENT",
            ParameterType::TransmissionMediumRequirement,
        ),
        (
            "PARAM_CALLED_PARTY_NUMBER",
            ParameterType::CalledPartyNumber,
        ),
        (
            "PARAM_CALLING_PARTY_NUMBER",
            ParameterType::CallingPartyNumber,
        ),
        ("PARAM_REDIRECTING_NUMBER", ParameterType::RedirectingNumber),
        ("PARAM_REDIRECTION_NUMBER", ParameterType::RedirectionNumber),
        ("PARAM_CAUSE_INDICATORS", ParameterType::CauseIndicators),
        ("PARAM_EVENT_INFORMATION", ParameterType::EventInformation),
        (
            "PARAM_REDIRECTION_INFORMATION",
            ParameterType::RedirectionInformation,
        ),
        ("PARAM_RANGE_AND_STATUS", ParameterType::RangeAndStatus),
        (
            "PARAM_CIRCUIT_GROUP_SUPERVISION",
            ParameterType::CircuitGroupSupervisionMessageType,
        ),
        (
            "PARAM_SUSPEND_RESUME_INDICATORS",
            ParameterType::SuspendResumeIndicators,
        ),
        (
            "PARAM_INFORMATION_REQUEST_INDICATORS",
            ParameterType::InformationRequestIndicators,
        ),
        (
            "PARAM_INFORMATION_INDICATORS",
            ParameterType::InformationIndicators,
        ),
        (
            "PARAM_USER_SERVICE_INFORMATION",
            ParameterType::UserServiceInformation,
        ),
    ] {
        m.add(name, pt.value())?;
    }

    // Well-known field values.
    m.add(
        "CALLING_PARTY_CATEGORY_ORDINARY",
        crate::calling_party_category::ORDINARY,
    )?;
    m.add("TMR_SPEECH", crate::transmission_medium_requirement::SPEECH)?;
    m.add(
        "TMR_3_1_KHZ_AUDIO",
        crate::transmission_medium_requirement::AUDIO_3_1_KHZ,
    )?;
    m.add("EVENT_ALERTING", crate::event_information::ALERTING)?;
    m.add("EVENT_PROGRESS", crate::event_information::PROGRESS)?;

    Ok(())
}

/// Standalone wheel entry point (maturin `module-name = "itu_isup._itu_isup"`).
#[pymodule]
fn _itu_isup(m: &Bound<'_, PyModule>) -> PyResult<()> {
    add_contents(m)
}

/// Embedding entry point: build an `itu_isup` submodule and attach it to `parent`,
/// so a host extension can expose itu_isup without a second shared object.
pub fn register(py: Python<'_>, parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let m = PyModule::new(py, "itu_isup")?;
    add_contents(&m)?;
    parent.setattr("itu_isup", &m)?;
    Ok(())
}
