//! Moved from `crates/oneiron/src/compaction/self_writer.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;

/// One paid call of a self-written pass, held until its host files it in
/// the model-step family (FIX 4465 B): the admitted request and the
/// provider's whole answer, each as its JSON. The step's model, purpose and
/// params identity and its canonical hash are read from the request; the
/// answer is the step's response. It never reaches a receipt or a store of
/// its own: the filed step is the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionCall {
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    /// Every record the call's words were read from: its request's sources
    /// and each home part it wore, the summary's own lineage. Its filed step
    /// and any response artifact derive from each (FIX 5977), so withdrawing
    /// one withdraws them as it withdraws the summary. `None` means the whole
    /// input was not witnessed: the call stays unfiled (FIX 11937).
    pub sources: Option<Vec<EntityId>>,
}
