//! Moved from `crates/oneiron/src/compaction/self_writer.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::revision_ref::RevisionRef;
use serde::Deserialize;
use serde::Serialize;

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

/// Provider-reported usage of one self-written call. `None` is unknown, never
/// a measured zero: an adapter that reports no cache counter leaves it unset.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionUsage {
    pub input_tokens: Option<u64>,
    pub cached_read_tokens: Option<u64>,
    pub cache_write_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

/// The state of a home part the call wore whole: the only state that shaped
/// what it wrote. A cut part never reached the call; an absent one is named
/// by why.
pub const HOME_PART_WORN: &str = "present";

/// One part of the home a self-written call wore, by ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionHomeRef {
    /// `voice`, `self_model`, `diary` or `lessons`.
    pub part: String,
    /// The row it was read from; `None` for an absent part.
    pub row: Option<EntityId>,
    /// `present`, `truncated` (it did not fit the call's room), or
    /// `absent:<why>`.
    pub state: String,
    /// The row's live revision in the snapshot its words were read in (FIX
    /// 4817). A worn part's summary stands only while the row still reads
    /// at it: an edit that publishes another revision withdraws the summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<RevisionRef>,
}

/// Every home row a call wore whole. A cut or absent part is not an input.
pub fn compaction_home_worn_rows(
    home: &[CompactionHomeRef],
) -> impl Iterator<Item = EntityId> + '_ {
    compaction_home_worn_parts(home).filter_map(|part| part.row)
}

/// Every home part a call wore whole, each with the revision its words were
/// read at (FIX 4817). A cut or absent part pins nothing.
pub fn compaction_home_worn_parts(
    home: &[CompactionHomeRef],
) -> impl Iterator<Item = &CompactionHomeRef> + '_ {
    home.iter().filter(|part| part.state == HOME_PART_WORN)
}

/// One filed call of a self-written pass: its terminal `dreamer.step`
/// claim, whose job is the run the pass compacted (FIX 4465 B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactionStepRef {
    /// The step's claim.
    pub claim: EntityId,
    /// The hex BLAKE3 of the admitted request's canonical bytes.
    pub step_hash: String,
}

/// The retained evidence a self-written summary was cut from, by revision.
/// An executor run's (FIX 4465 B) is its committed steps `first..=last`,
/// pinned by the chained state hash the span's last checkpoint committed; a
/// conversation's (FIX 4465 D) is its SESSION, conversation and branch and
/// the ordered retained turns of the span, each pinned by its projection's
/// fingerprint. A later read that finds another pin reads other evidence.
/// Each source keeps its own fields, so an executor receipt reads as it was
/// written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CompactionEvidence {
    Executor {
        run: EntityId,
        first: u64,
        last: u64,
        /// Hex of the last step's committed state hash.
        revision: String,
    },
    Conversation(super::ConversationEvidence),
}

/// Where a self-written summary landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CompactionLanding {
    /// One epoch of its run: its SUMMARY row and its number.
    Epoch { summary: EntityId, epoch: u64 },
    /// One fold of its run's ledger.
    Fold { fold: u64 },
}
