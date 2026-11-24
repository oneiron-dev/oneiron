//! The check-in of a pin of a workload (pass 34, `34-compute-general/DESIGN.md`
//! section 6.5; NOTE PASS-34-R2-SHAPE): the pin door composes its own mode
//! and rung 0 and judges the pin in its writer, through
//! [`judge_door_act_in_txn`] with the door's [`DoorRungs`]. The door names the
//! class the host read from the pin (P25-SHAPE Q4 = A). The owner's own pin
//! goes on his own proof. On a wait the door opens the keyed pending check-in
//! and answers `CHECK_IN_PENDING` naming it; the same call naming
//! `check_in_ref` once it is approved spends it, as a room add does.
//!
//! An agent never answers its own pin: the asker is never a rung of its own
//! ask. The chain's agent-holder seam answers nothing today
//! ([`NoAgentVerdict`]), so in practice a person answers.

use super::act_class::ActClass;
use super::asker::{AskGo, AskVerdict, DoorRungs, judge_door_act_in_txn};
use super::chain::{NoAgentVerdict, VerifiedChain};
use super::effect::{DoorAct, DoorCheckIn, named_check_in_at_once, spend_in_txn};
use super::pending::{OpenPendingCheckIn, open_keyed_pending_check_in_in_txn};
use super::policy::CheckInScope;
use super::resolve::WaitReason;
use crate::entity_id::EntityId;
use crate::job_workload::PinGoBasis;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// One pin's ask, as the pin door composed it.
pub(crate) struct PinCheckInAsk<'a> {
    /// The pin verb's registered name.
    pub(crate) verb: &'a str,
    /// The class the host read from the pin.
    pub(crate) act: ActClass,
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

/// Judges `memory`'s caller's pin in the pin door's writer `txn`: it goes,
/// spends the approved ask `ask.check_in_ref`, or opens (or finds) its keyed
/// pending check-in.
///
/// # Errors
///
/// `FORBIDDEN` for a caller with no power to pin; a `check_in_ref` named
/// for a pin that goes at once ([`named_check_in_at_once`]), or that is not
/// this caller's approved ask for this pin; storage errors.
pub(crate) fn workload_pin_check_in_in_txn(
    memory: &Memory<'_>,
    txn: &mut heed::RwTxn<'_>,
    ask: &PinCheckInAsk<'_>,
    now: u64,
) -> MemoryResult<PinCheckIn> {
    let vault = memory.vault();
    let scope = CheckInScope::default();
    let (verdict, role) =
        judge_door_act_in_txn(memory, txn, ask.verb, ask.act, &scope, &ask.rungs)?;
    let (asker, grant, mode, reason) = match verdict {
        AskVerdict::Go { reason, .. } => {
            if ask.check_in_ref.is_some() {
                return Err(named_check_in_at_once().into());
            }
            let basis = match reason {
                AskGo::NeverAsk => PinGoBasis::NeverAsk,
                AskGo::StandingRow => PinGoBasis::StandingRow,
                AskGo::Sure => PinGoBasis::Sure,
                AskGo::Read | AskGo::OwnProof => PinGoBasis::OwnProof,
            };
            return Ok(PinCheckIn::Went { basis });
        }
        AskVerdict::Wait {
            asker,
            grant,
            mode,
            reason,
            ..
        } => (asker, grant, mode, reason),
        AskVerdict::Absent { why } => return Err(not_granted(ask.verb, why)),
        AskVerdict::Propose { .. } | AskVerdict::Unstated => {
            return Err(not_granted(
                ask.verb,
                "the caller's Grant does not hold the power to pin",
            ));
        }
    };
    let door = DoorAct {
        person: asker,
        role,
        grant,
        verb: ask.verb,
        act: ask.act,
        scope,
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
            asker,
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

fn not_granted(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner's own proof or an agent's own Grant that names it: {why}"
        ),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}
