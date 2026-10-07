//! An importer completes a turn's marker with tags it already holds: no
//! tagger call.

use super::input::{TurnInput, turn_input_in_txn};
use super::marker::{TAGGING_MARKER_KIND, dedupe_key};
use super::output::{AnswerMood, OutputRefusal, check_output};
use super::trace::{SkipReason, TaggingOutcome, TaggingTrace, attempt_hex};
use crate::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use crate::error::{Error, Result};
use crate::memory::extraction::EncoderOutput;
use crate::{EntityId, Vault};

const IMPORT_LEASE_OWNER: &str = "oneironer-import";

/// What an importer's held tags did to a turn's marker.
#[derive(Debug, Clone, PartialEq)]
pub enum HeldTagsOutcome {
    /// The marker completed with no tagger call.
    Completed(TaggingTrace),
    /// The tags break a contract rule for the turn's current text; nothing
    /// changed and the marker still waits for the tagger.
    Refused(OutputRefusal),
    /// No live marker is owed for the turn under the active checkpoint.
    NoMarker,
    /// The worker holds the marker's lease or has scheduled its retry; its own
    /// pass settles it.
    WorkerOwned,
}

impl Vault {
    /// Completes the turn's tagging marker with tags the importer already
    /// holds, in one write transaction and with no tagger call.
    ///
    /// The tags are checked against the turn's current text exactly as a
    /// tagger's answer is. This build settles in shadow: the marker completes
    /// and nothing else is written; saving the tags lands with ONE-2167.
    pub fn complete_tagging_with_held_tags(
        &self,
        turn: &EntityId,
        tags: &EncoderOutput,
    ) -> Result<HeldTagsOutcome> {
        let checkpoint = self
            .config
            .tagging
            .as_ref()
            .map(|tagging| tagging.checkpoint.clone())
            .ok_or_else(|| {
                Error::InvalidConfig("tagging markers are not armed on this vault".to_owned())
            })?;
        let queue = AttemptQueue::from_store(&self.store);
        self.try_with_write_txn(|txn| -> Result<HeldTagsOutcome> {
            let key = dedupe_key(turn, &checkpoint);
            let Some(record) = queue.pending_dedupe_in_txn(txn, TAGGING_MARKER_KIND, &key)? else {
                return Ok(HeldTagsOutcome::NoMarker);
            };
            if record.state != AttemptState::Queued {
                return Ok(match record.state {
                    AttemptState::Leased | AttemptState::Landing | AttemptState::Scheduled => {
                        HeldTagsOutcome::WorkerOwned
                    }
                    _ => HeldTagsOutcome::NoMarker,
                });
            }
            let (outcome, input_hash) = match turn_input_in_txn(self, txn, turn)? {
                TurnInput::Gone => (
                    TaggingOutcome::Skipped {
                        reason: SkipReason::TurnGone,
                    },
                    None,
                ),
                TurnInput::Empty => (
                    TaggingOutcome::Skipped {
                        reason: SkipReason::NoText,
                    },
                    None,
                ),
                TurnInput::Ready { input, hash } => {
                    if let Err(refusal) = check_output(&input, tags) {
                        return Ok(HeldTagsOutcome::Refused(refusal));
                    }
                    (
                        TaggingOutcome::Imported {
                            spans: tags.spans.len(),
                            links: tags.links.len(),
                            mood: tags.vad.present(),
                        },
                        Some(hash),
                    )
                }
            };
            // Stamped from the store clock without persisting its floor, as
            // the worker's settlements are: shadow writes only the job tables.
            let now = self.store.clock.peek_recorded_at();
            let claimed = queue.claim_id_storage_in_txn(
                txn,
                record.id,
                ClaimAttempt {
                    lease_owner: IMPORT_LEASE_OWNER.to_owned(),
                    now,
                },
                now,
            )?;
            let ClaimOutcome::Claimed(leased) = claimed else {
                return Ok(HeldTagsOutcome::WorkerOwned);
            };
            queue.complete_storage_in_txn(
                txn,
                CompleteAttempt {
                    id: leased.id,
                    lease_owner: IMPORT_LEASE_OWNER.to_owned(),
                    attempt_count: leased.attempt_count,
                    now,
                },
            )?;
            Ok(HeldTagsOutcome::Completed(TaggingTrace {
                attempt: attempt_hex(&leased.id),
                turn: Some(*turn),
                checkpoint: checkpoint.clone(),
                model: None,
                input_hash,
                try_number: 1,
                call_micros: None,
                outcome,
            }))
        })
    }
}
