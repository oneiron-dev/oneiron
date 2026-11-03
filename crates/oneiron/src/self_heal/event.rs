//! Closed diagnostic event vocabulary: classes, sources, criticality, event and working-set types, bounds.
pub use crate::store::diagnostic_record::event::{
    DIAGNOSTIC_SCHEMA_VERSION, DIAGNOSTIC_BODY_KEYS, DiagnosticEventClass, AgentHealthSignal, DiagnosticSourceKind, DiagnosticCriticality, DiagnosticReplayCoordinate, DiagnosticEvent, DiagnosticObservation, DiagnosticWorkingSet, DeterministicDetector,
};
pub(super) use crate::store::diagnostic_record::event::{
    DIAGNOSTIC_ACTOR_CLASSES, DIAGNOSTIC_EVENT_ID_DOMAIN, MAX_REF_LEN, MAX_TOKEN_LEN, MAX_INVARIANT_DEPTH, MAX_INVARIANT_NODES, MAX_INVARIANT_WIDTH, invalid_diagnostic,
};
