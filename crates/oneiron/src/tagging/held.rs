//! An importer completes a turn's marker with tags it already holds: no
//! tagger call.

use super::history::record_in_txn;
use super::input::{TurnInput, turn_text_in_txn};
use super::marker::{TAGGING_MARKER_KIND, TaggingMode, dedupe_key};
use super::output::{OutputRefusal, check_output};
use super::save::{self, Answer};
use super::trace::{SkipReason, TaggingOutcome, TaggingTrace, attempt_hex};
use crate::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use crate::error::{Error, Result};
use crate::memory::extraction::EncoderOutput;
use crate::{EntityId, Vault};

const IMPORT_LEASE_OWNER: &str = "oneironer-import";
/// What made held tags, as their envelope names it.
const HELD_BY: &str = "held";

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
    /// Completes the tagging marker of a turn already in the vault with tags
    /// the importer holds, in one write transaction and with no tagger call:
    /// the tags are checked against the turn's current text exactly as a
    /// tagger's answer is, and in save mode they are saved in that write.
    ///
    /// A worker may claim the marker between the turn's write and this call;
    /// an importer that holds the tags when it lands the turn uses
    /// [`crate::memory::Memory::witness_with_held_tags`], which settles the
    /// marker in the turn's own write.
    pub fn complete_tagging_with_held_tags(
        &self,
        turn: &EntityId,
        tags: &EncoderOutput,
    ) -> Result<HeldTagsOutcome> {
        if self.config.tagging.is_none() {
            return Err(Error::InvalidConfig(
                "tagging markers are not armed on this vault".to_owned(),
            ));
        }
        self.try_with_write_txn(|txn| settle_held_tags_in_txn(self, txn, turn, tags))
    }
}

/// Settles the turn's marker on held tags in the caller's transaction: the
/// tags are checked against the turn's text as that transaction sees it,
/// saved in save mode, and the marker completes and leaves the job ledger
/// with its trace recorded. A vault with no tagger owes no marker.
pub(crate) fn settle_held_tags_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    turn: &EntityId,
    tags: &EncoderOutput,
) -> Result<HeldTagsOutcome> {
    let Some(config) = vault.config.tagging.as_ref() else {
        return Ok(HeldTagsOutcome::NoMarker);
    };
    let checkpoint = &config.checkpoint;
    let queue = AttemptQueue::from_store(&vault.store);
    let key = dedupe_key(turn, checkpoint);
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
    // Stamped from the store clock without persisting its floor, as the
    // worker's settlements are.
    let now = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    // Held tags were made from the turn's own text, not from this vault's
    // window, so they are checked against it and its digest names it.
    let read = turn_text_in_txn(vault, txn, turn)?;
    if let TurnInput::Ready { input, .. } = &read
        && let Err(refusal) = check_output(input, tags)
    {
        return Ok(HeldTagsOutcome::Refused(refusal));
    }
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
    let (outcome, input_hash) = match read {
        TurnInput::Gone => (
            TaggingOutcome::Skipped {
                reason: SkipReason::TurnGone,
            },
            None,
        ),
        TurnInput::Empty => {
            // A turn with no text keeps no tags read from text it lost.
            if config.mode == TaggingMode::Save {
                super::tags::replace_in_txn(vault, txn, turn, None)?;
            }
            (
                TaggingOutcome::Skipped {
                    reason: SkipReason::NoText,
                },
                None,
            )
        }
        TurnInput::Ready { input, hash, .. } => {
            if config.mode == TaggingMode::Save {
                let answer = Answer {
                    turn: *turn,
                    input: &input,
                    output: tags,
                    envelope: save::envelope(&hash, HELD_BY, config),
                };
                save::save_in_txn(vault, txn, answer, &config.labels, now)?;
            }
            (
                TaggingOutcome::Imported {
                    spans: tags.spans.len(),
                    links: tags.links.len(),
                    mood: tags.vad.is_some(),
                },
                Some(hash),
            )
        }
    };
    // A retry the worker scheduled, or a lease it lost, is a later try.
    let try_number = queue
        .retry_chain_depth_in_txn(txn, leased.id)?
        .saturating_add(1);
    queue.complete_storage_in_txn(
        txn,
        CompleteAttempt {
            id: leased.id,
            lease_owner: IMPORT_LEASE_OWNER.to_owned(),
            attempt_count: leased.attempt_count,
            now,
        },
    )?;
    let trace = TaggingTrace {
        attempt: attempt_hex(&leased.id),
        turn: Some(*turn),
        checkpoint: checkpoint.clone(),
        model: None,
        input_hash,
        try_number,
        call_micros: None,
        outcome,
    };
    // As a worker's settlement: the trace is recorded and the marker leaves
    // the job ledger with every try it retried.
    record_in_txn(vault, txn, &trace, now)?;
    queue.prune_settled_in_txn(txn, leased.id)?;
    Ok(HeldTagsOutcome::Completed(trace))
}
