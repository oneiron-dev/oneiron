//! The retrieval signals a run scores entities by: which channel ranked a
//! result. The pipeline (`pipeline`) runs them; the store's retrieval
//! telemetry and the token budget record them.

/// Retrieval signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
    Hyde,
}
