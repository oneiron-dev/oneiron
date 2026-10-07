//! The tagging marker and its drain: the write path's outbox rule applied to
//! the Oneironer slot (ARCH-0036, serving the tagger; the write-path hub).
//!
//! A base witness commits one marker per touched turn inside its own write
//! transaction, when the vault is armed ([`crate::VaultConfig::tagging`]). The
//! marker is an ordinary row of the job tables (`job_records`, `job_ready`,
//! `job_dedupe`) of kind [`TAGGING_MARKER_KIND`], deduplicated by the turn and
//! the tagger checkpoint. An edit that moves a turn's indexed frontier marks
//! the turn again. A host worker drains the markers through
//! [`TaggingReconciler`]: it reads the turn's MESSAGE rows, calls the
//! host-served tagger outside any write transaction, checks the answer and
//! settles the marker. A failed call or a refused answer is a trace and a retry
//! with backoff, never a failed write. An importer that already holds a turn's
//! tags completes its marker with no tagger call
//! ([`crate::Vault::complete_tagging_with_held_tags`]).
//!
//! This build settles in shadow: a checked answer completes its marker and
//! nothing else is written. Saving the tags lands with ONE-2167.

mod held;
mod input;
mod marker;
mod output;
mod reconciler;
mod trace;

pub use held::HeldTagsOutcome;
pub use marker::{TAGGING_MARKER_KIND, TaggingMarkerConfig};
pub use output::{OutputRefusal, spans_only_answers_admitted};
pub use reconciler::{TaggingBackoff, TaggingPass, TaggingReconciler};
pub use trace::{SkipReason, TaggingFailure, TaggingOutcome, TaggingTrace};

pub(crate) use marker::{mark_on_publication_in_txn, mark_turn_in_txn};

#[cfg(test)]
mod tests;
