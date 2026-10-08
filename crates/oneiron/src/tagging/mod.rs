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
//! a failed write. An importer that already holds a turn's tags completes its
//! marker with no tagger call
//! ([`crate::Vault::complete_tagging_with_held_tags`]).
//!
//! Markers and their tries are job state. Each attempt's trace is recorded in
//! the transaction that settles or retries it, and a settled marker leaves
//! the job ledger there with every try it retried. What stays is the trace
//! history, bounded per turn and by age ([`TaggingTraceHistory`],
//! [`crate::Vault::tagging_trace_history`]). Content-side cleanup never
//! proposes a marker, and no scan of another job kind counts one.
//!
//! This build settles in shadow: a checked answer completes its marker and
//! nothing else is written. Saving the tags lands with ONE-2167.

mod body;
mod held;
mod history;
mod input;
mod marker;
mod output;
mod reconciler;
mod trace;

pub use held::HeldTagsOutcome;
pub use history::TaggingTraceRecord;
pub use marker::{
    DEFAULT_LIVE_WINDOW_TOKENS, DEFAULT_TRACE_MAX_AGE_SECS, DEFAULT_TRACES_PER_TURN,
    MAX_LIVE_WINDOW_TOKENS, MAX_TRACES_PER_TURN, TAGGING_MARKER_KIND, TaggingMarkerConfig,
    TaggingTraceHistory,
};
pub use output::{OutputRefusal, spans_only_answers_admitted};
pub use reconciler::{TaggingBackoff, TaggingPass, TaggingReconciler};
pub use trace::{HandBackReason, SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};

#[cfg(feature = "sync")]
pub(crate) use marker::text_entity_type_in_txn;
pub(crate) use marker::{mark_on_publication_in_txn, mark_turn_in_txn};

#[cfg(test)]
mod tests;
