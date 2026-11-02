//! The per-item cleanup review and decision vocabulary (FIX 1758): what the
//! owner reads about each slot of one open proposal, and the complete verdict
//! he sends back.

use serde::{Deserialize, Serialize};

use super::CleanupKind;
use crate::claim::ScopedReadResult;
use crate::entity_id::EntityId;
use crate::memory::EntityView;
use crate::note::NoteReadView;

/// Which open proposal to review.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupReviewRequest {
    /// The proposal's id, from a cleanup run or the owner cleanup review.
    pub proposal: EntityId,
}

/// One open proposal, every slot disclosed in proposal order.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewView {
    /// The proposal's id.
    pub proposal: EntityId,
    /// The 32-hex attempt id of the run that opened it.
    pub attempt: String,
    /// When the run opened it, in recorded seconds.
    pub created_at: u64,
    /// When this review was read, in recorded seconds; ages are measured
    /// against it.
    pub read_at: u64,
    /// 64-hex BLAKE3 over the proposal's slots and each slot's stored bytes
    /// as this review read them. Send it back as `expected_revision` to
    /// decide only on what was reviewed.
    pub revision: String,
    /// The task retention period in days the TASK and attempt arms measure
    /// against now; `0` turns those arms off.
    pub task_retention_days: u64,
    /// How many slots the proposal holds, by kind.
    pub counts: CleanupReviewCounts,
    /// Every slot, in proposal order, an erased one too.
    pub items: Vec<CleanupReviewItem>,
}

/// A proposal's slots counted by kind: all five arms, and the slots an
/// erase reached.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewCounts {
    /// Every slot, erased ones included.
    pub total: usize,
    /// Extraction-minted PERSON rows with no live claim.
    pub claimless_extraction_persons: usize,
    /// SUMMARY rows with no live claim, member or reference.
    pub empty_summaries: usize,
    /// Completed TASK rows past the retention period.
    pub completed_tasks: usize,
    /// Completed private attempts past the retention period.
    pub completed_attempts: usize,
    /// NOTE rows past the days their kind keeps them.
    pub retained_notes: usize,
    /// Slots an erase reached since the proposal opened.
    pub erased: usize,
}

/// One slot of the proposal, as it stands now.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewItem {
    /// The slot's place in the proposal; a decision names it.
    pub slot: usize,
    /// How the slot stands now.
    pub state: CleanupItemState,
    /// The record, or the completed attempt's id; none for an erased slot.
    pub entity: Option<EntityId>,
    /// The arm that proposed it; none for an erased slot.
    pub kind: Option<CleanupKind>,
    /// 64-hex BLAKE3 of its stored bytes now: the encoded record, with a
    /// NOTE's live document version after it, or the attempt's queue row.
    /// None when erased or gone, or when a record does not read.
    pub revision: Option<String>,
    /// Why its arm proposes it, read now; none when erased, gone or
    /// unreadable.
    pub evidence: Option<CleanupReviewEvidence>,
    /// Its full current content; none when erased or gone.
    pub content: Option<CleanupReviewContent>,
    /// What accepting this slot does.
    pub accept: CleanupAcceptEffect,
    /// `Some(true)` when its stored bytes changed while the review read its
    /// content, on every read the review took: that content may be newer
    /// than the facts and `revision` beside it (FIX 10502). `None` otherwise.
    pub changed_during_review: Option<bool>,
}

/// How one slot stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupItemState {
    /// An erase reached what it named: no id, kind or content stays.
    Erased,
    /// Its arm's rule holds now.
    Eligible,
    /// It is there, but its arm's rule no longer holds: it gained a claim or
    /// an edge, changed, was kept by the owner or archived since.
    Changed,
    /// Nothing is stored under it any more.
    Gone,
    /// Its stored row does not read.
    Unreadable,
}

/// What accepting one slot does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupAcceptEffect {
    /// Archives it: a local mark hides it from the working set and keeps its
    /// body and indexes. Reversible: the owner restores it, or reverts the
    /// run, and keeps it.
    Archive,
    /// Leaves it as it is: the accept re-runs its arm's rule and skips it.
    Skip,
    /// Nothing: an erased slot names no one.
    Nothing,
    /// The decision fails as a whole: its arm's rule cannot read the row.
    /// Reject this slot to decide the rest.
    Fails,
}

/// The facts behind a slot's arm, read now. Each field is filled for the
/// arms it applies to and empty for the others.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewEvidence {
    /// The arm's rule, in words.
    pub rule: String,
    /// Whether the rule holds now; an accept runs it again.
    pub holds_now: bool,
    /// PERSON and SUMMARY: the live claims about it.
    pub live_claims: Option<u64>,
    /// SUMMARY: the member or reference edge kinds it has, in or out; empty
    /// when it has none.
    pub linked_edges: Vec<String>,
    /// PERSON: whether its mint-time evidence binds this revision to a
    /// machine source.
    pub extraction_minted: Option<bool>,
    /// TASK: when it finished; attempt: its last update; NOTE: when it was
    /// learned. Recorded seconds.
    pub since: Option<u64>,
    /// TASK and attempt: the retention period in days; NOTE: the days its
    /// kind keeps it.
    pub keep_days: Option<u64>,
}

/// A slot's full current content, through the reads the owner already has.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupReviewContent {
    /// A record as `vault.get` reads it for the owner, with that read's
    /// narrowing receipt; its value is none when that read withholds it.
    pub record: Option<ScopedReadResult<Option<EntityView>>>,
    /// A NOTE's document as `vault.notes.read` reads it for the owner.
    pub note: Option<ScopedReadResult<Option<NoteReadView>>>,
    /// A completed attempt: every field of its stored queue row, read under
    /// the owner's proof.
    pub attempt: Option<serde_json::Value>,
    /// Each read that refused, as `code: message`; the slot stays.
    pub refused: Vec<String>,
}

/// The owner's complete verdict on one open proposal: one choice per slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupDecideRequest {
    /// The proposal's id.
    pub proposal: EntityId,
    /// Exactly one choice for every slot of the proposal, an erased one too,
    /// in any order.
    pub choices: Vec<CleanupItemChoice>,
    /// The review's `revision`. When sent, the decision applies only while
    /// the slots and their stored bytes still read as reviewed; when absent,
    /// nothing is bound.
    #[serde(default)]
    pub expected_revision: Option<String>,
}

/// One slot's choice.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CleanupItemChoice {
    /// The slot, as the review numbers it.
    pub slot: usize,
    /// Accept or reject it.
    pub decision: CleanupItemDecision,
}

/// Accept or reject one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupItemDecision {
    /// Archive it, if its arm's rule still holds.
    Accept,
    /// Leave it as it is. Nothing pins it: a later run may propose it again.
    Reject,
}

/// What one decision did, slot by slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupDecideView {
    /// The proposal decided; it is no longer open.
    pub proposal: EntityId,
    /// Every slot's outcome, in proposal order.
    pub items: Vec<CleanupItemOutcome>,
    /// The decision's digest; none when nothing was accepted, as a whole
    /// reject records none.
    pub digest: Option<EntityId>,
}

/// What a decision did to one slot.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CleanupItemOutcome {
    /// The slot's place in the proposal.
    pub slot: usize,
    /// What it named; none for an erased slot.
    pub entity: Option<EntityId>,
    /// Its arm; none for an erased slot.
    pub kind: Option<CleanupKind>,
    /// What happened to it.
    pub outcome: CleanupItemResult,
}

/// What a decision did to one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CleanupItemResult {
    /// Accepted and archived.
    Archived,
    /// Accepted, but its arm's rule no longer held: left as it is.
    Skipped,
    /// Rejected: left as it is, and recorded as rejected.
    Rejected,
    /// An erase reached it: nothing was looked up or archived.
    Erased,
}
