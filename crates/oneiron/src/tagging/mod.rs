//! The tagging marker and its drain: the write path's outbox rule applied to
//! the Oneironer slot (ARCH-0036, serving the tagger; the write-path hub).
//!
//! A base witness, and the promotion of an off-record turn into base, commit
//! one marker per touched turn inside their own write transaction, when the
//! vault is armed ([`crate::VaultConfig::tagging`]). The marker is an ordinary
//! row of the job tables (`job_records`, `job_ready`, `job_dedupe`) of kind
//! [`TAGGING_MARKER_KIND`], deduplicated by the turn and the tagger
//! checkpoint. An edit that moves a turn's indexed frontier marks the turn
//! again, whether its text is published at idle or written through an entity
//! document. A host worker drains the markers through
//! [`TaggingReconciler`]: it reads the turn's MESSAGE rows with a bounded
//! window of the conversation's earlier text (the live register, sized by
//! [`TaggingMarkerConfig::live_window_tokens`]), calls the host-served tagger
//! outside any write transaction, checks the answer and settles the marker. A
//! failed call or a refused answer is a trace and a retry with backoff, never
//! a failed write. An importer that already holds a turn's tags lands the
//! turn with them ([`crate::memory::Memory::witness_with_held_tags`]): they
//! are checked, and saved, and the marker settles, in the turn's own write,
//! so no worker calls the tagger for that turn.
//!
//! Markers and their tries are job state. Each attempt's trace is recorded in
//! the transaction that settles or retries it, and a settled marker leaves
//! the job ledger there with every try it retried. What stays is the trace
//! history, bounded per turn and by age ([`TaggingTraceHistory`],
//! [`crate::Vault::tagging_trace_history`]). Content-side cleanup never
//! proposes a marker, and no scan of another job kind counts one.
//!
//! A vault with a tagger saves its tags ([`TaggingMode::Save`]): the answer
//! a marker settles on becomes the turn's tag set in the settling
//! transaction ([`TurnTags`]). What is saved is derived and local: the tag
//! set, its unconfirmed mentions, and the provisional entities an identity
//! key miss mints ([`ProvisionalEntity`]) live in `vault_meta`, never sync,
//! and are rebuilt by tagging the turn again. The Dreamer or an actor
//! confirms a provisional entity into a real, synced one. Shadow
//! ([`TaggingMode::Shadow`]) is the test switch: the marker settles and
//! nothing else is written.

mod body;
mod held;
mod history;
mod input;
mod marker;
mod output;
mod provisional;
mod reconciler;
mod save;
mod tags;
mod trace;

pub use held::HeldTagsOutcome;
pub use history::TaggingTraceRecord;
pub use marker::{
    DEFAULT_LIVE_WINDOW_TOKENS, DEFAULT_TRACE_MAX_AGE_SECS, DEFAULT_TRACES_PER_TURN,
    MAX_LIVE_WINDOW_TOKENS, MAX_TRACES_PER_TURN, TAGGING_MARKER_KIND, TaggingMarkerConfig,
    TaggingMode, TaggingTraceHistory, label_kind_admitted,
};
pub use output::OutputRefusal;
pub use provisional::ProvisionalEntity;
pub use reconciler::{TaggingBackoff, TaggingPass, TaggingReconciler};
pub use tags::{
    DerivationEnvelope, MentionHit, MentionLink, MergeEvidence, TaggedMention, TurnTags,
};
pub use trace::{HandBackReason, SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};

pub(crate) use held::settle_held_tags_in_txn;
#[cfg(feature = "sync")]
pub(crate) use marker::text_entity_type_in_txn;
pub(crate) use marker::{mark_on_publication_in_txn, mark_turn_in_txn};
pub(crate) use provisional::hold_id_in_txn;
pub(crate) use save::save_shadow_output_in_txn;
pub(crate) use tags::{
    erase_in_txn, erase_scope_exists_in_txn, saved_turn_mood_in_txn, tear_in_txn,
};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_save;
