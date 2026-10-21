//! A binder's settlement on the right its bind recorded (FIX 5349). An agent
//! or a member binds a run under a live Grant or credential, which the bind
//! gate proves in the admitting writer; the run's settlement only applies
//! the terminal map to the TASK that bind took. So the settling fence admits
//! on the stored binding the wrapper's fence matched, and the report NOTE
//! lands on that same right, never on a fresh proof of the binder. How the
//! binder's own right stands at settlement is read beside it and gates
//! nothing: the receipt names a right that lapsed or was revoked, and the
//! owner can requeue the TASK. A member's binding keeps the slip their call
//! presented, so a slip revoked or expired after the bind is named too
//! (FIX 5419). The owner's run at his own door settles as it always did.

use crate::Vault;
use crate::agent_dispatch::AgentDispatcher;
use crate::authority::TaskActorVerb;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, MEMORY_CODE_OWNER_BINDING_REQUIRED, Memory,
    MemoryError, MemoryResult,
};
use crate::task_authority::TaskStanding;
use crate::task_verb::highway::{forbidden, not_found};

use super::WorkflowRunEnd;

/// The settlement receipt's field naming a binder's right that no longer
/// held: `lapsed` or `revoked`.
pub(super) const BINDER_RIGHT: &str = "binder_right";
/// The binder's Grant, credential or standing no longer held.
const LAPSED: &str = "lapsed";
/// The binder's authority binding was revoked.
const REVOKED: &str = "revoked";
/// What a binder that is not the TASK's owner reads.
const MOVES_ITS_OWN: &str = "A workflow run moves only the task its binder bound it to.";

/// Why a settlement can never move its TASK (FIX 5291): the TASK no longer
/// stands for its binder, missing or no party of theirs, or the fence
/// refuses the binder for good, no longer its owner or its binding revoked.
/// The run is marked settled with it, so no pass retries it; any other
/// refusal is transient, and the next pass tries again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettleLoss {
    TaskLost,
    FenceLost,
}

impl SettleLoss {
    /// The loss the settling writer's refusal `error` names, if any.
    pub(super) fn of(error: &MemoryError) -> Option<Self> {
        match error.code.as_str() {
            MEMORY_CODE_NOT_FOUND => Some(Self::TaskLost),
            MEMORY_CODE_FORBIDDEN | MEMORY_CODE_OWNER_BINDING_REQUIRED => Some(Self::FenceLost),
            _ => None,
        }
    }

    /// The reason the run's settled mark keeps.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::TaskLost => "task_lost",
            Self::FenceLost => "fence_lost",
        }
    }
}

/// The TASK's standing for a binder that settles on its recorded right: the
/// TASK's own facts under the Owner rule its bind proved, with no fresh
/// proof of the binder. A binder no party to the TASK finds it missing; one
/// no longer its owner, or a cancelled TASK, is refused as that rule
/// refuses them.
pub(super) fn standing_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    binder: EntityId,
) -> MemoryResult<TaskStanding> {
    let standing = vault.task_standing_in(txn, task)?.ok_or_else(not_found)?;
    let party = standing.owner == binder
        || standing.assignee == Some(binder)
        || standing
            .taker
            .as_ref()
            .is_some_and(|taker| taker.actor == binder);
    if !party {
        return Err(not_found());
    }
    if standing.owner != binder {
        return Err(forbidden(
            "only the task's owner runs this verb",
            MOVES_ITS_OWN,
        ));
    }
    if standing.cancelled {
        return Err(forbidden(
            "a cancelled task takes no more work",
            MOVES_ITS_OWN,
        ));
    }
    Ok(standing)
}

/// How the binder's own right stands at settlement, in the settling writer,
/// for a run that settles on its bind: `None` while it holds; `revoked`
/// when its authority binding, or the slip a member presented at bind, was
/// revoked; `lapsed` when a proof the settlement no longer asks now fails:
/// the binder's live proof on the TASK, its standing as a live person, a
/// shared vault's content Grant at the report NOTE's position, or that
/// slip, expired or no longer live. Read only; nothing here refuses.
pub(super) fn binder_right_in(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    end: &WorkflowRunEnd,
    note: EntityId,
) -> Option<&'static str> {
    if !end.settles_on_bind {
        return None;
    }
    let vault = memory.vault();
    let binder = end.bound_by;
    // FIX 5419: the slip a member presented, as their binding keeps it.
    let slip = AgentDispatcher::new(vault)
        .workflow_task_source_in_txn(txn, &end.wrapper)
        .ok()
        .flatten()
        .and_then(|bind| bind.slip)
        .and_then(|slip| slip_right_in(vault, txn, &slip));
    let right = match vault.verify_native_write_actor_in_txn(txn, &binder) {
        Err(Error::Claim(_)) => Some(REVOKED),
        Err(_) => slip.or(Some(LAPSED)),
        Ok(()) => {
            let proved = memory
                .highway_task_actor_in(txn, end.task, TaskActorVerb::Owner, MOVES_ITS_OWN)
                .is_ok();
            let live = binder.actor_class() != EdgeActorClass::Human
                || crate::consent::person_is_live_in_txn(vault, txn, &binder.entity_ref())
                    .unwrap_or(true);
            let granted = !matches!(
                vault.authorize_shared_note_write_in_txn(txn, note, &binder),
                Err(Error::Claim(_))
            );
            slip.or((!proved || !live || !granted).then_some(LAPSED))
        }
    };
    if let Some(right) = right {
        tracing::info!(task = %end.task.to_hex(), right, "a workflow TASK settles on its binder's recorded right, which no longer holds");
    }
    right
}

/// How the slip a member presented at bind stands now (FIX 5419): `None`
/// while it is live, or when its state does not read; `revoked` when the
/// authority log revoked it or a slip it descends from; `lapsed` when it
/// expired or no longer holds otherwise.
fn slip_right_in(vault: &Vault, txn: &heed::RoTxn<'_>, slip: &[u8; 32]) -> Option<&'static str> {
    if vault
        .capability_slip_id_is_live_in_txn(txn, slip)
        .unwrap_or(true)
    {
        return None;
    }
    let revoked = vault
        .authority_view_readonly_in_txn(txn)
        .is_ok_and(|fold| fold.slips.is_revoked(slip));
    Some(if revoked { REVOKED } else { LAPSED })
}
