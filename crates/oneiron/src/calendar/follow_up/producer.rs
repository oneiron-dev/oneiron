//! The producer of meeting follow-up drafts (CAL-08; Engine RULINGs
//! CAL-08-FOLLOWUP-OWNER-SPEAKER = A and CAL-08-FOLLOWUP-UNKNOWN-RECIPIENT =
//! A, Sun 15 Nov 14:49).
//!
//! A transcript SESSION's landing queues one
//! [`MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND`] attempt in its own writer. A host
//! worker that holds a model claims it, reads the SESSION for its model
//! destination ([`Vault::meeting_follow_up_source_for`]), asks the model
//! which follow-ups the owner promised to send ([`MeetingFollowUpDrafter`],
//! with [`MEETING_FOLLOW_UP_INSTRUCTION`]), and files the reply
//! ([`Vault::file_meeting_follow_up_drafts_attempt`]). Each follow-up becomes
//! one draft through [`super::write_meeting_follow_up_draft`]'s door, written
//! as the vault's Dreamer in that attempt, so it waits for the owner like
//! every other draft.
//!
//! Only the owner's own promises become drafts. No transcript says which
//! speaker is the owner (every imported TURN is a counterparty's), so the
//! engine matches each TURN's speaker label against the owner's names; a
//! transcript with no speaker under one of them yields no model call and no
//! draft. Until the owner's name is in the vault, no transcript does. A
//! draft's recipient is one of the PERSONs the engine listed, those the vault
//! knows by a name the transcript says; a promise to anyone else yields no
//! draft. A draft cites the TURNs it came from, and at least one of them is
//! the owner's.

mod reply;
mod source;

pub use source::{
    MeetingFollowUpRead, MeetingFollowUpRecipient, MeetingFollowUpRequest, MeetingFollowUpSilence,
    MeetingFollowUpSource, MeetingFollowUpTurn,
};

use serde::{Deserialize, Serialize};

use super::write_meeting_follow_up_draft_in_txn;
use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, AttemptState, EnqueueAttempt};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::settings::{ReadDestination, ReleaseHold};

/// Attempt kind for one transcript SESSION's follow-up drafting.
pub const MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND: &str = "calendar.follow_up.draft";

/// The most drafts one transcript yields; a reply's later items are not
/// read.
pub const MEETING_FOLLOW_UP_MAX_DRAFTS: usize = 8;

/// The most bytes of rendered transcript a model is asked to read. A longer
/// transcript yields no draft ([`MeetingFollowUpSilence::TooLong`]): it is
/// never cut, since a cut drops the promises past the cut.
pub const MEETING_FOLLOW_UP_MAX_TRANSCRIPT_BYTES: usize = 192 * 1_024;

/// The most PERSONs a request lists as recipients, in the order the
/// transcript first names them.
pub const MEETING_FOLLOW_UP_MAX_RECIPIENTS: usize = 32;

/// The instruction the engine ships for the drafting model. The reply
/// contract it states is the engine's ([`Vault::file_meeting_follow_up_drafts_attempt`]
/// reads only that), so a host may reword it but must keep the contract.
pub const MEETING_FOLLOW_UP_INSTRUCTION: &str = include_str!("producer/instruction.md");

/// One queued drafting: the transcript SESSION it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeetingFollowUpDraftPayload {
    /// The SESSION's id, 32 lowercase hex.
    pub session_ref: String,
}

/// The host's drafting model.
pub trait MeetingFollowUpDrafter {
    /// The model's reply to `request`, as text in the reply contract of
    /// [`MEETING_FOLLOW_UP_INSTRUCTION`].
    ///
    /// # Errors
    ///
    /// Any reason the host could not ask; the attempt runs again later.
    fn draft(&self, request: &MeetingFollowUpRequest) -> Result<String>;
}

/// What one run of a drafting attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeetingFollowUpRunOutcome {
    /// The reply was filed: the drafts it wrote or found, possibly none.
    Filed(Vec<EntityId>),
    /// Nothing to ask: the SESSION is gone or not a transcript, or the read
    /// was silent ([`MeetingFollowUpSilence`]).
    Nothing,
    /// The destination may not receive the transcript now.
    Held(ReleaseHold),
}

/// Queues `session`'s follow-up drafting in its landing's writer, once per
/// SESSION. Nothing is read or checked here: the SESSION's TURNs, the owner's
/// speaker and the recipients are judged when the attempt runs.
pub(crate) fn enqueue_meeting_follow_up_drafting_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    now: u64,
) -> Result<()> {
    let session_ref = session.to_hex();
    let payload = serde_json::to_vec(&MeetingFollowUpDraftPayload {
        session_ref: session_ref.clone(),
    })
    .map_err(|_| Error::InvalidClaimBody("meeting follow-up payload did not encode"))?;
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        wtxn,
        EnqueueAttempt {
            kind: MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(format!(
                "{MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND}:{session_ref}"
            )),
            run_id: None,
            now,
        },
    )?;
    Ok(())
}

/// Runs the leased drafting `attempt` through `drafter` toward `destination`
/// and files the reply, as a host worker does: read, ask, file. The lease
/// stays the caller's to settle.
///
/// # Errors
///
/// The payload is not a drafting payload, the read failed, the drafter
/// failed, or the filing refused ([`Vault::file_meeting_follow_up_drafts_attempt`]).
pub fn run_meeting_follow_up_drafting(
    vault: &Vault,
    drafter: &dyn MeetingFollowUpDrafter,
    destination: &ReadDestination,
    attempt: &AttemptRecord,
    lease_owner: &str,
) -> Result<MeetingFollowUpRunOutcome> {
    let payload: MeetingFollowUpDraftPayload = serde_json::from_slice(&attempt.payload)
        .map_err(|_| Error::InvalidClaimBody("meeting follow-up payload is invalid"))?;
    let source = match vault.meeting_follow_up_source_for(&payload, destination)? {
        MeetingFollowUpRead::Missing | MeetingFollowUpRead::Silent(_) => {
            return Ok(MeetingFollowUpRunOutcome::Nothing);
        }
        MeetingFollowUpRead::Held(hold) => return Ok(MeetingFollowUpRunOutcome::Held(hold)),
        MeetingFollowUpRead::Ready(source) => source,
    };
    let reply = drafter.draft(&source.request)?;
    vault
        .file_meeting_follow_up_drafts_attempt(
            attempt.id,
            lease_owner,
            attempt.attempt_count,
            &source,
            &reply,
        )
        .map(MeetingFollowUpRunOutcome::Filed)
}

fn transition(state: &'static str) -> Error {
    ArtifactError::InvalidAttemptQueueTransition {
        action: "file_meeting_follow_up_drafts_attempt",
        state,
    }
    .into()
}

impl Vault {
    /// Files the drafting model's `reply` for the read `source` of this exact
    /// live lease, and returns the drafts written or found, in reply order.
    ///
    /// The reply is read whole first: text that is not one JSON object in
    /// the reply contract is refused, and nothing is written. Each item is
    /// then read alone, and one that names an unlisted recipient or label,
    /// cites no owner TURN, or holds empty or oversized words is skipped,
    /// never cut or guessed. The lease and the source revision are checked
    /// beside the writes in one writer; each draft writes in its own
    /// savepoint, so a draft the door refuses leaves its siblings written.
    ///
    /// # Errors
    ///
    /// A reply outside the contract, a lease that changed, a pending
    /// cancellation, a transcript or recipient changed since the read, and
    /// every store error.
    pub fn file_meeting_follow_up_drafts_attempt(
        &self,
        id: AttemptId,
        lease_owner: &str,
        generation: u32,
        source: &MeetingFollowUpSource,
        reply: &str,
    ) -> Result<Vec<EntityId>> {
        let drafts = reply::decode_reply(source, reply)?;
        self.with_write_txn_grouped(|txn| {
            let record = AttemptQueue::new(self)
                .get_in_txn(txn, id)?
                .ok_or_else(|| transition("missing"))?;
            if record.kind != MEETING_FOLLOW_UP_DRAFT_ATTEMPT_KIND {
                return Err(ArtifactError::InvalidAttemptQueueRecord(
                    "meeting follow-up attempt kind mismatch",
                )
                .into());
            }
            if record.state != AttemptState::Leased {
                return Err(transition(record.state.as_str()));
            }
            if record.lease_owner.as_deref() != Some(lease_owner) {
                return Err(transition("leased_by_other"));
            }
            if record.attempt_count != generation {
                return Err(transition("stale_attempt"));
            }
            if record.cancel_state.landing.is_some()
                || record.cancel_state.cancellation.is_some()
                || record.cancel_state.pressure.pending > 0
            {
                return Err(transition("cancel_pending"));
            }
            if source::source_revision_in_txn(self, txn, source)? != source.revision {
                return Err(transition("source_changed"));
            }
            let author = self.dreamer_authority_in_txn(txn, self.now_recorded_at())?;
            let mut written = Vec::with_capacity(drafts.len());
            for draft in &drafts {
                let mut savepoint = self.store.env.nested_write_txn(txn)?;
                match write_meeting_follow_up_draft_in_txn(self, &mut savepoint, author, id, draft)
                {
                    Ok(claim_id) => {
                        savepoint.commit()?;
                        written.push(claim_id);
                    }
                    Err(Error::InvalidClaimBody(reason)) => {
                        drop(savepoint);
                        tracing::warn!(reason, "a meeting follow-up draft was refused");
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(written)
        })
    }
}
