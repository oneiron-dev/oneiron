//! Closed diagnostic event vocabulary: classes, sources, criticality, event and working-set types, bounds.
pub use crate::store::diagnostic_record::event::{
    AgentHealthSignal, DIAGNOSTIC_BODY_KEYS, DIAGNOSTIC_SCHEMA_VERSION, DeterministicDetector,
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticObservation,
    DiagnosticReplayCoordinate, DiagnosticSourceKind, DiagnosticWorkingSet,
};
pub(super) use crate::store::diagnostic_record::event::{
    DIAGNOSTIC_ACTOR_CLASSES, DIAGNOSTIC_EVENT_ID_DOMAIN, MAX_INVARIANT_DEPTH, MAX_INVARIANT_NODES,
    MAX_INVARIANT_WIDTH, MAX_REF_LEN, MAX_TOKEN_LEN, invalid_diagnostic,
};
