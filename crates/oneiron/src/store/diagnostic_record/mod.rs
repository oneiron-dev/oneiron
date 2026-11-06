//! Diagnostic record vocabulary, canonical body codecs and content addresses.

mod address;
pub(crate) mod admission;
pub(crate) mod diagnostic_codec;
pub(crate) mod event;
pub(crate) mod invariant_canonical;
pub(crate) mod normal_baseline;
pub(crate) mod untrusted_text;

pub use address::diagnostic_event_id;
pub(crate) use admission::validate_diagnostic_event_admission;
pub use diagnostic_codec::{decode_diagnostic_event_body, encode_diagnostic_event_body};
pub(crate) use diagnostic_codec::{
    validate_diagnostic_event_body_bytes, validate_stored_diagnostic_event_body_bytes,
    validate_token,
};
pub(crate) use event::invalid_diagnostic;
pub use event::{
    AgentHealthSignal, DIAGNOSTIC_BODY_KEYS, DIAGNOSTIC_SCHEMA_VERSION, DeterministicDetector,
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation,
    DiagnosticReplayCoordinate, DiagnosticSourceKind, DiagnosticWorkingSet,
};
