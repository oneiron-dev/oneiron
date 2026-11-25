//! The check-in of a pin of a workload (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5; NOTE PASS-34-R2-SHAPE): the pin door composes its own mode
//! and rung 0 and judges the pin in its writer, through
//! [`judge_door_act_in_txn`] with the door's [`DoorRungs`]. The door names the
//! class the host read from the pin (P25-SHAPE Q4 = A). The owner's own pin
//! goes on his own proof. On a wait the door opens the keyed pending check-in
//! and answers `CHECK_IN_PENDING` naming it; the same call naming
//! `check_in_ref` spends it once it is approved, whatever the ladder says
//! now: the person's answer settles the pin it was asked over.
//!
//! A pin sits at its project, placed by the project's world
//! ([`workload_pin_scope_in_txn`]): a grant has no project axis. The door
//! admits an agent under the Grant its ask names
//! ([`workload_pin_grant_in_txn`]), so the admission, the ask and the pin's
//! row name one Grant.
//!
//! An agent never answers its own pin: the asker is never a rung of its own
//! ask. The chain's agent-holder seam answers nothing today
//! ([`NoAgentVerdict`]), so in practice a person answers.

use super::act_class::ActClass;
use super::asker::{AskGo, AskVerdict, DoorRungs, agent_door_grant_in_txn, judge_door_act_in_txn};
use super::chain::{NoAgentVerdict, VerifiedChain};
use super::effect::{DoorAct, DoorCheckIn, named_check_in_at_once, spend_in_txn};
use super::pending::{OpenPendingCheckIn, open_keyed_pending_check_in_in_txn};
use super::policy::CheckInScope;
use super::resolve::WaitReason;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::job_workload::PinGoBasis;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// One pin's ask, as the pin door composed it.
pub(crate) struct PinCheckInAsk<'a> {
    /// The pin verb's registered name.
    pub(crate) verb: &'a str,
    /// The class the host read from the pin.
    pub(crate) act: ActClass,
    /// Where the pin sits ([`workload_pin_scope_in_txn`]).
    pub(crate) scope: CheckInScope,
    /// The Grant the door admitted the agent under
    /// ([`workload_pin_grant_in_txn`]); `None` for the owner's own pin.
    pub(crate) grant: Option<EntityId>,
    pub(crate) rungs: DoorRungs<'a>,
    /// The pin's digest: the exact effect an approval names.
    pub(crate) effect_digest: [u8; 32],
    /// The approved ask the call spends, if it names one.
    pub(crate) check_in_ref: Option<&'a EntityId>,
}

/// What a pin's check-in decided.
pub(crate) enum PinCheckIn {
    /// The pin goes now, on `basis`.
    Went { basis: PinGoBasis },
    /// The call spent the approved ask `check_in`: the pin goes.
    Answered { check_in: EntityId },
    /// The pin waits on the pending check-in `check_in`.
    Waits {
        check_in: EntityId,
        reason: WaitReason,
    },
}

/// Where a pin for `project` checks in: at the project, placed by the world
/// the project's slice names, since a grant has no project axis (a project's
/// act is placed by its world). A pin with no project, or for a project this
/// vault does not show, names no world.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn workload_pin_scope_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> crate::Result<CheckInScope> {
    let Some(project) = project else {
        return Ok(CheckInScope::default());
    };
    let world = vault
        .visible_project_in_txn(txn, project)?
        .and_then(|record| record.slice.world);
    Ok(CheckInScope {
        world_ref: world.map(|world| world.to_hex()),
        project_ref: Some(project.to_hex()),
    })
}

/// The Grant `memory`'s agent caller pins under at `scope`: the one its ask
/// names, the first of its live owner Grants listing `verb` whose bounds
/// cover where the pin sits.
///
/// # Errors
///
/// `FORBIDDEN` when no such Grant covers that place; the caller's refusals
/// ([`judge_door_act_in_txn`]); storage errors.
pub(crate) fn workload_pin_grant_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    verb: &str,
    scope: &CheckInScope,
) -> MemoryResult<EntityId> {
    agent_door_grant_in_txn(memory, txn, verb, scope)?.ok_or_else(|| {
        not_granted(
            verb,
            "no live Grant of the caller that lists it covers where the pin sits (its project's world)",
        )
    })
}

/// Judges `memory`'s caller's pin in the pin door's writer `txn`: it goes,
/// spends the approved ask `ask.check_in_ref`, or opens (or finds) its keyed
/// pending check-in. A named ask is spent before the ladder's answer counts:
/// the person's answer settles the pin even where the ladder would now let
/// it go. Check-in rows keep the vault's recording clock, in seconds.
///
/// # Errors
///
/// `FORBIDDEN` for a caller with no power to pin; a `check_in_ref` named
/// for the owner's own pin ([`named_check_in_at_once`]), or that is not
/// this caller's approved ask for this pin; storage errors.
pub(crate) fn workload_pin_check_in_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    ask: &PinCheckInAsk<'_>,
) -> MemoryResult<PinCheckIn> {
    let vault = memory.vault();
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let (verdict, role) =
        judge_door_act_in_txn(memory, txn, ask.verb, ask.act, &ask.scope, &ask.rungs)?;
    let (mode, reason) = match verdict {
        AskVerdict::Go { reason, .. } => {
            match (ask.check_in_ref, ask.grant, ask.rungs.explicit_mode) {
                (None, _, _) => {
                    return Ok(PinCheckIn::Went {
                        basis: go_basis(reason),
                    });
                }
                // The spend settles the pin or refuses; no wait follows it.
                (Some(_), Some(_), Some(mode)) => (mode, WaitReason::AlwaysAsk),
                (Some(_), _, _) => return Err(named_check_in_at_once().into()),
            }
        }
        AskVerdict::Wait {
            grant,
            mode,
            reason,
            ..
        } => {
            if ask.grant != Some(grant) {
                return Err(crate::Error::InvariantViolation(
                    "a pin's ask names the Grant its door admitted",
                )
                .into());
            }
            (mode, reason)
        }
        AskVerdict::Absent { why } => return Err(not_granted(ask.verb, why)),
        AskVerdict::Propose { .. } | AskVerdict::Unstated => {
            return Err(not_granted(
                ask.verb,
                "the caller's Grant does not hold the power to pin",
            ));
        }
    };
    let grant = ask
        .grant
        .ok_or(crate::Error::InvariantViolation("only an agent's pin asks"))?;
    let door = DoorAct {
        person: memory.actor(),
        role,
        grant,
        verb: ask.verb,
        act: ask.act,
        scope: ask.scope.clone(),
        effect_digest: ask.effect_digest,
    };
    if let Some(id) = ask.check_in_ref {
        return Ok(match spend_in_txn(vault, txn, &door, mode, id, now)? {
            DoorCheckIn::Go(_) => PinCheckIn::Answered { check_in: *id },
            DoorCheckIn::Wait(check_in) => PinCheckIn::Waits { check_in, reason },
        });
    }
    let (row, _) = open_keyed_pending_check_in_in_txn(
        vault,
        txn,
        OpenPendingCheckIn {
            asker: door.person,
            grant_ref: grant.to_hex(),
            verb: ask.verb.to_owned(),
            act: ask.act,
            scope: door.scope.clone(),
            effect_digest: ask.effect_digest,
            mode,
            reason,
            asker_wait_secs: None,
            until: None,
            undo_plan: None,
            delay_window: None,
        },
        memory.invocation().map(|invocation| invocation.0),
        &VerifiedChain::new(&NoAgentVerdict),
        now,
    )?;
    Ok(PinCheckIn::Waits {
        check_in: row.id,
        reason,
    })
}

/// The record's basis of a pin the ladder let go for `reason`.
fn go_basis(reason: AskGo) -> PinGoBasis {
    match reason {
        AskGo::NeverAsk => PinGoBasis::NeverAsk,
        AskGo::StandingRow => PinGoBasis::StandingRow,
        AskGo::Sure => PinGoBasis::Sure,
        AskGo::Read | AskGo::OwnProof => PinGoBasis::OwnProof,
    }
}

fn not_granted(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that names it: {why}"
        ),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}
