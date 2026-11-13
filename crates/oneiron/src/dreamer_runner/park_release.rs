//! The owner's release of a parked Dreamer attempt that no resumer frees (untangle slice 3, WAKE-D1; lead 14:3x and
//! 15:2x, 9 Nov).
//!
//! An ExecutorError park and a private Other park wait on an owner act: a budget, a consent, a seat or a peer. No
//! resumer retries them blindly (constraint C5), boot included. Each such park raises one notice for each live owner
//! (recipient set, so no other reader sees the try) in its own write, and the vault's authenticated owner releases
//! it, against the exact park a read showed him (its cause, when it was parked and the try's lease generation, as
//! `vault.consolidation.status` and the owner's lineage show them), so a park that changed since refuses and nothing
//! moves. A try parks only under a lease, so a later park of the same try is a later generation, even within the same
//! second (review 6910 P1). The release resumes the park as the same try and resolves its notices. In slice 6.5 typed waits replace this door for budget, consent, seat and peer:
//! the matching signal resumes the park.
//!
//! The same door stops a parked try (Engine 08:3x, 10 Nov). A parked try keeps its lease, and the run tree's cancel
//! refuses a leased row, so before this the owner had no stop for it: a pass the host's drain cancelled parks
//! Cancelled, and the next pass resumes it. Stop ends the try on the owner's grounds through the queue's owner
//! force-cancel, clears its park and resolves its notices, in one write, for any park of the Dreamer server's own
//! pass. A program hold has its own Stop (`vault.runs.program_hold.release`), and the other owners' parks keep their
//! own doors.
//!
//! The server's pass runs every kind of Dreamer try, so the stop gives the try it ends the settlement any ended try
//! gets, in the same write (`DreamerRunnerStore::settle_stopped_in_txn`): a free-time item takes its Cancelled
//! receipt, the budget the try still holds settles, its paid-step receipts go, and a Coach Issues run's owed
//! successor is queued. A stopped try sends nothing more: its Pending sends are abandoned as a held program's Stop
//! abandons them (FIX 7188), which matters for a turn program's try parked at a checkpoint under the server's pass.
//!
//! The same door frees a try parked at its budget trap on a spent budget, a `Budget`, `PassBudget` or
//! `ResidentShare` wait (BUDGET-TRAP-UNTYPED-NO-SENDER, D2 and D3): such a park has its own sender (a top-up, a
//! later pass with room, the owner's share write), and
//! the owner may free it as well. Resume wakes the park's trap in the release write, so the try runs again
//! as the same try; Stop wakes the trap the same way and ends the try through the owner force-cancel, so the trap
//! is consumed and nothing waits on it. Such a park raises no notice: it does not wait on the owner.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, ForceAttemptCancel, ForceCancelAuthority,
    ForceCancelOutcome, InterveneAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::inbox::{
    NotificationEvent, NotificationKind, NotificationSource, decode_notification_body,
};
use crate::memory::DreamerParkCauseView;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::store::PARKED;
use super::{
    DreamerParkWaitClass, DreamerParkedAttemptRecord, DreamerRunnerStore, ParkOwnerClass,
    ParkResumer,
};

/// The producer of the owner notice a park waiting on the owner's release raises.
pub const PARK_RELEASE_OWED_PRODUCER: &str = "dreamer.park.release_owed";
/// The notice's detail code.
const PARK_RELEASE_OWED_DETAIL: &str = "dreamer.park.owner_release";
/// The note the release's intervention carries when the owner gave none.
const RELEASE_NOTE: &str = "the owner released the parked try";

/// The owner's release of one parked Dreamer try: a resume or a stop.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReleaseParkedAttemptRequest {
    /// 32-hex id of the parked try (`job:` prefix allowed).
    pub attempt: String,
    pub action: ParkReleaseAction,
    /// The park's cause and the time it was parked, as a read showed them (`vault.consolidation.status`, the
    /// owner's lineage): a park that changed since refuses.
    pub cause: DreamerParkCauseView,
    pub parked_at: u64,
    /// The try's lease generation (`attempt_count`) as the same read showed it: a release of an earlier park of
    /// the same try refuses, even when both parks fall in the same second.
    pub attempt_count: u32,
    /// The owner's note: a resume's intervention note on the try's queue row, or a stop's cancellation reason.
    #[serde(default)]
    pub note: Option<String>,
}

/// What the owner does with a parked try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ParkReleaseAction {
    /// Queue the same try again: a park that waits on an owner act and that no other resumer frees (an
    /// ExecutorError or a private Other park), or a park at its budget trap on a spent budget, whose trap the
    /// release wakes.
    Resume,
    /// End the try on the owner's grounds and clear its park: any park of the Dreamer server's own pass, whatever
    /// its cause, or a park at its budget trap on a spent budget, whose trap the stop consumes.
    Stop,
}

impl ParkReleaseAction {
    /// Whether this action serves `park`.
    fn serves(self, park: &DreamerParkedAttemptRecord) -> bool {
        match self {
            Self::Resume => park.resumable_by(ParkResumer::OwnerRelease),
            Self::Stop => {
                ParkOwnerClass::of(&park.park_owner) == ParkOwnerClass::DreamerServer
                    || waits_on_budget_trap(park)
            }
        }
    }
}

/// Whether `park` waits at its budget trap on a spent budget: a `Budget`, `PassBudget` or
/// `ResidentShare` wait under a trap owner.
fn waits_on_budget_trap(park: &DreamerParkedAttemptRecord) -> bool {
    ParkOwnerClass::of(&park.park_owner) == ParkOwnerClass::Trap
        && matches!(
            park.wait.as_ref().map(|wait| wait.wait.class()),
            Some(
                DreamerParkWaitClass::Budget
                    | DreamerParkWaitClass::PassBudget
                    | DreamerParkWaitClass::ResidentShare
            )
        )
}

/// What releasing one park did.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ParkReleaseView {
    /// 32-hex try.
    pub attempt: String,
    pub action: ParkReleaseAction,
    /// The released park's exact reason.
    pub released: String,
    /// The released park's cause.
    pub cause: String,
    /// The try's queue state after the release.
    pub state: String,
    /// Whether this release queued or ended the try: a stop of a try already settled only clears its park.
    pub effected: bool,
}

/// What one release committed, and what its commit signals after.
struct Released {
    view: ParkReleaseView,
    /// The try a stop ended, at its lease generation: its running step stops.
    stopped: Option<(AttemptId, u32)>,
}

/// The source of `owner`'s notice for `record`, parked under lease generation `attempt_count`: one per park and
/// owner, its id derived from the try, its generation, its park time and the owner, so a replay finds the row it
/// wrote and a new park of the same try (a later generation) raises its own.
pub(crate) fn park_release_notice_source(
    record: &DreamerParkedAttemptRecord,
    attempt_count: u32,
    owner: &EntityId,
) -> NotificationSource {
    let attempt = bytes_to_hex_lower(record.attempt_id.as_bytes());
    NotificationSource {
        producer: PARK_RELEASE_OWED_PRODUCER.to_owned(),
        event: format!(
            "{attempt}:{attempt_count}:{}:{}",
            record.parked_at,
            owner.to_hex()
        ),
        attempt: Some(attempt),
        detail: Some(PARK_RELEASE_OWED_DETAIL.to_owned()),
        ..NotificationSource::default()
    }
}

/// Raises each live owner's notice for `record` in its park's own write, when only the owner's release resumes it:
/// one notice per owner, for that owner only (review 6910 P1). A notice that is not written is logged; the park
/// still lands.
pub(crate) fn raise_park_release_notice_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &DreamerParkedAttemptRecord,
) {
    // A park at its budget trap has its own sender, so it does not wait on the owner.
    if !record.resumable_by(ParkResumer::OwnerRelease) || waits_on_budget_trap(record) {
        return;
    }
    let raised = (|| -> Result<()> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let Some(attempt) =
            AttemptQueue::new(vault).get_in_write_txn(&savepoint, record.attempt_id)?
        else {
            return Ok(());
        };
        for owner in crate::policy_model::owners_in_txn(vault, &savepoint)? {
            vault.record_notification_in_txn(
                &mut savepoint,
                &NotificationEvent {
                    kind: NotificationKind::Finding,
                    source: park_release_notice_source(record, attempt.attempt_count, &owner),
                    subject_refs: Vec::new(),
                    recipient: Some(owner),
                    created_at: record.parked_at,
                    origin_conversation: None,
                },
            )?;
        }
        savepoint.commit()?;
        Ok(())
    })();
    match raised {
        // The notice's savepoint is not the parent's post-commit scope.
        Ok(()) => crate::batch::queue_notification_change(vault, wtxn),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(record.attempt_id.as_bytes()),
            "a parked try's owner release notice was not raised"
        ),
    }
}

/// Releases one parked try as the vault's authenticated owner, against the exact park the owner's reads show (its
/// cause, park time and the try's lease generation); the owner is revalidated in the writer.
///
/// - Resume: the park must be one the owner's release resumes (the park resume table's OwnerRelease row), and a
///   settled try is never reopened. The owner's intervention is recorded on the queue row, and the park resumes as
///   the same try under its own owner token; a park at its budget trap resumes through its trap's wake.
/// - Stop: the park must be one of the Dreamer server's own pass, of any cause, or one at its budget trap on a spent
///   budget, whose trap is woken first. The queue's owner force-cancel ends the try, its receipt naming the owner;
///   the try it ends is settled as any ended try is; the park is cleared and the try's Pending sends are abandoned.
///   A try already settled only loses its park and its Pending sends.
///
/// Either way the park's notices are resolved for every owner, in the same write. After the commit a stopped try's
/// running step stops, and admission is woken.
///
/// # Errors
///
/// A malformed attempt id ([`Error::InvalidConfig`]); a proof that no longer holds; a try with no park, or a park
/// the action does not serve ([`Error::EntityNotFound`]); a park that changed since it was read
/// ([`Error::ConcurrentWrite`]); a resume of a settled try ([`Error::InvalidConfig`]); a note the queue refuses;
/// storage errors.
pub fn release_parked_attempt_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: &ReleaseParkedAttemptRequest,
) -> Result<ParkReleaseView> {
    let attempt = attempt_id(&input.attempt)?;
    let now = vault.now_recorded_at();
    let released = vault
        .with_write_txn_grouped(|wtxn| release_in_txn(vault, wtxn, owner, attempt, input, now))?;
    // Committed: a stopped try's running step stops (FIX 600), and admission sees the queue as it now stands.
    if let Some((id, generation)) = released.stopped {
        crate::engine_executor::stop_attempt_step(Some(vault), id, generation);
    }
    vault.store.notify_proactivity_changes();
    Ok(released.view)
}

fn release_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &AuthenticatedOwner,
    attempt: AttemptId,
    input: &ReleaseParkedAttemptRequest,
    now: u64,
) -> Result<Released> {
    let actor = owner.revalidate_in_txn(vault, &*wtxn)?;
    let store = DreamerRunnerStore::new(vault);
    let Some((status, Some(park))) = store.status_with_park_in_txn(&*wtxn, attempt)? else {
        return Err(Error::EntityNotFound);
    };
    if !input.action.serves(&park) {
        return Err(Error::EntityNotFound);
    }
    if DreamerParkCauseView::from(park.cause) != input.cause
        || park.parked_at != input.parked_at
        || status.attempt.attempt_count != input.attempt_count
    {
        return Err(Error::ConcurrentWrite(
            "the parked try changed since it was read",
        ));
    }
    let (effected, stopped) = match input.action {
        ParkReleaseAction::Resume => {
            if status.attempt.state.is_terminal() {
                return Err(Error::InvalidConfig(
                    "a settled try is never reopened".to_owned(),
                ));
            }
            resume_in_txn(vault, wtxn, actor, attempt, &park, input, now)?;
            (true, None)
        }
        ParkReleaseAction::Stop => {
            if waits_on_budget_trap(&park) {
                // The trap is consumed before the try ends, so nothing is left waiting on it.
                wake_budget_trap_park_in_txn(vault, wtxn, &park, now)?;
            }
            let (count, stopped) = stop_in_txn(vault, wtxn, actor, attempt, input, now)?;
            (stopped, stopped.then_some((attempt, count)))
        }
    };
    resolve_notices_in_txn(vault, wtxn, &park, input.attempt_count)?;
    let state = store
        .status_with_park_in_txn(&*wtxn, attempt)?
        .map(|(status, _)| status.attempt.state.as_str().to_owned())
        .ok_or(Error::EntityNotFound)?;
    Ok(Released {
        view: ParkReleaseView {
            attempt: bytes_to_hex_lower(attempt.as_bytes()),
            action: input.action,
            released: park.reason,
            cause: park.cause.as_str().to_owned(),
            state,
            effected,
        },
        stopped,
    })
}

/// Records the owner's intervention on the queue row and resumes `park` as the same try under its own owner token.
fn resume_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
    park: &DreamerParkedAttemptRecord,
    input: &ReleaseParkedAttemptRequest,
    now: u64,
) -> Result<()> {
    AttemptQueue::new(vault).intervene_in_txn(
        wtxn,
        InterveneAttempt {
            id: attempt,
            kind: AttemptInterventionKind::Interrupt,
            actor: actor.to_hex(),
            note: Some(
                input
                    .note
                    .clone()
                    .unwrap_or_else(|| RELEASE_NOTE.to_owned()),
            ),
            now,
        },
    )?;
    if waits_on_budget_trap(park) {
        return wake_budget_trap_park_in_txn(vault, wtxn, park, now);
    }
    DreamerRunnerStore::new(vault)
        .resume_parked_in_txn(wtxn, attempt, &park.park_owner, now)?
        .ok_or(Error::EntityNotFound)?;
    Ok(())
}

/// Wakes the budget trap `park` waits at, in the caller's write: the trap is signalled and consumed, and the park
/// resumes as the same try. A trap an earlier wake reached, or a broken park, is not found, and nothing moves.
fn wake_budget_trap_park_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    now: u64,
) -> Result<()> {
    crate::llm::wake_budget_trap_of_park_in_txn(
        vault,
        wtxn,
        &park.park_owner,
        now.saturating_mul(1_000),
    )?
    .ok_or(Error::EntityNotFound)?;
    Ok(())
}

/// Ends `attempt` on the owner's grounds through the queue's owner force-cancel, unless it already settled; gives
/// the try it ends the settlement of an ended try; clears its park and the park's indexes; and abandons its Pending
/// sends, an abandon the ledger refuses being owed rather than refusing the Stop (FIX 7188). Returns the try's lease
/// generation and whether this stop ended it.
fn stop_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    attempt: AttemptId,
    input: &ReleaseParkedAttemptRequest,
    now: u64,
) -> Result<(u32, bool)> {
    let authority = ForceCancelAuthority::owner(actor.to_hex().as_str())?;
    let outcome = AttemptQueue::new(vault).force_cancel_in_txn(
        wtxn,
        ForceAttemptCancel {
            id: attempt,
            authority,
            reason: input.note.clone(),
            now,
        },
    )?;
    let (record, stopped) = match outcome {
        ForceCancelOutcome::Cancelled(record) => (record, true),
        ForceCancelOutcome::AlreadyCancelled(record)
        | ForceCancelOutcome::AlreadySettled(record) => (record, false),
    };
    if stopped {
        // The try ended in this write, so its settlement is this write's too. A try that settled before was
        // settled by the door that ended it.
        DreamerRunnerStore::new(vault).settle_stopped_in_txn(wtxn, &record, now)?;
    }
    if let Some(park) = PARKED.get(&vault.store, &*wtxn, &attempt)? {
        super::outage_due::unindex_outage_due_in_txn(vault, wtxn, &park)?;
        super::program::unindex_program_hold_in_txn(vault, wtxn, &park)?;
        super::seat_wait::unindex_seat_wait_in_txn(vault, wtxn, &park)?;
    }
    PARKED.delete(&vault.store, wtxn, &attempt)?;
    super::program::abandon_stopped_sends_in_txn(vault, wtxn, attempt, now);
    Ok((record.attempt_count, stopped))
}

/// Marks each live owner's notice of `park` (lease generation `attempt_count`) seen and acknowledged for that
/// owner: the park is released for all of them. A notice that was never raised, or is gone, stays as it is.
pub(super) fn resolve_notices_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    attempt_count: u32,
) -> Result<()> {
    let mut resolved = false;
    for owner in crate::policy_model::owners_in_txn(vault, &*wtxn)? {
        let id = crate::inbox::notification_id(&park_release_notice_source(
            park,
            attempt_count,
            &owner,
        ))?;
        let LiveEntityRow::Live { entity_type, body } =
            live_entity_row_in_txn(&vault.store, &*wtxn, &id)?
        else {
            continue;
        };
        if entity_type != ENTITY_TYPE_NOTIFICATION {
            continue;
        }
        let mut body = decode_notification_body(&body)?;
        let reader = owner.to_hex();
        body.seen_by.insert(reader.clone(), true);
        body.acked_by.insert(reader, true);
        vault.put_notification_in_txn(wtxn, &id, &body)?;
        resolved = true;
    }
    if resolved {
        crate::batch::queue_notification_change(vault, wtxn);
    }
    Ok(())
}

fn attempt_id(text: &str) -> Result<AttemptId> {
    let text = text.trim();
    let id = EntityId::from_hex(text.strip_prefix("job:").unwrap_or(text))
        .map_err(|_| Error::InvalidConfig("attempt must be a 32-hex attempt id".to_owned()))?;
    AttemptId::from_bytes(id.as_bytes())
}
