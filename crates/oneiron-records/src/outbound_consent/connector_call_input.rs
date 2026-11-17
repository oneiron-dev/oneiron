//! Moved from `crates/oneiron/src/outbound_consent/connector_call_input.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// The round of questions a call waits on, as its status read shows it
/// (FIX 3837): its handle, generation, how many questions it asks, the end
/// of its live lease, and whether its live exchange ended unanswered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallInput {
    pub handle: String,
    pub generation: u64,
    pub asked: usize,
    pub live_until_ms: u64,
    pub uncertain: bool,
}
