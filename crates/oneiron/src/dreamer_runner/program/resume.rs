//! A turn program's holds and their resume (DOOR-141 PR3b, FIX 4382, FIX
//! 5711).
//!
//! A program that stops short is held by the program runtime alone, as its
//! own park (owner `dreamer.turn_program`, cause Other), under one exact
//! reason per kind of hold. Before each selection the program kind's
//! admission chain resumes each hold whose condition is met, as the same try
//! through `resume_parked_in_txn`: a wait once its reply is delivered, a
//! lapsed authority once it stands again with its pin, an uncertain effect
//! once nothing the run did is unsettled, and a run an earlier entry cut.
//! The resumed try re-enters its pinned entry; nothing restarts it from
//! scratch. No other park is touched: a step's signal park resumes through
//! its own consume, a pass's Checkpoint park through the wake that follows
//! it, and a hold for want of a runtime, a moved pin, a gone actor, a run
//! that no longer lines up with its checkpoint or one that ended unfinished
//! stays held.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::code_run::{WaitKey, program_resume_head_in_txn, wait_delivered_in_txn};
use crate::dreamer_runner::{DreamerParkCause, DreamerRunnerStore, ParkDreamerAttempt};
use crate::entity_id::EntityId;
use crate::error::Result;

use super::authority::TurnProgramBound;
use super::run::{STEP, StepState, actor_gone_in_txn, turn_program_code_run};
use super::{ATTEMPT, PROGRAM_PARK_OWNER};

/// Why the program runtime holds a program's try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProgramHold {
    /// This host binds no program runtime for the program's actor.
    Unbound,
    /// The waking actor's authority no longer stands.
    AuthorityLapsed,
    /// The pinned program changed since it was admitted.
    PinMoved,
    /// The run waits on a durable wait's reply.
    Wait,
    /// An effect of the run is not settled: a send whose delivery is not
    /// known, or a step whose end is not.
    Uncertain,
    /// The program's actor is gone: nothing it settled is answered again.
    Withheld,
    /// The pinned source made another call where an earlier entry settled
    /// one, or the run's checkpoint is not the one its record committed.
    Diverged,
    /// The run ended without its pinned entry finishing.
    Unfinished,
    /// A run an entry before DOOR-141 PR3b cut: its exact PR2 reason, matched
    /// to resume it, never written again.
    Cut,
}

const HOLDS: [ProgramHold; 9] = [
    ProgramHold::Unbound,
    ProgramHold::AuthorityLapsed,
    ProgramHold::PinMoved,
    ProgramHold::Wait,
    ProgramHold::Uncertain,
    ProgramHold::Withheld,
    ProgramHold::Diverged,
    ProgramHold::Unfinished,
    ProgramHold::Cut,
];

impl ProgramHold {
    /// The park reason the hold is written under, exactly.
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Unbound => "this host binds no turn program runtime for the program's actor",
            Self::AuthorityLapsed => {
                "the turn program runs nothing new: the waking actor's authority no longer stands"
            }
            Self::PinMoved => {
                "the turn program runs nothing new: the pinned program changed since it was admitted"
            }
            Self::Wait => {
                "the turn program waits on a durable wait; it resumes from its pinned entry once \
                 the wait's reply is delivered"
            }
            Self::Uncertain => {
                "an effect of the turn program is not settled; it resumes from its pinned entry \
                 once nothing it did is uncertain"
            }
            Self::Withheld => {
                "the turn program's actor is gone; nothing it settled is answered again"
            }
            Self::Diverged => {
                "the turn program's pinned entry no longer lines up with its checkpoint; it holds"
            }
            Self::Unfinished => {
                "the turn program's run ended without its pinned entry finishing; it is not complete"
            }
            Self::Cut => {
                "an earlier entry of the turn program stopped before it settled; its resume lands \
                 with DOOR-141 PR3"
            }
        }
    }

    /// The hold a park's exact reason names, if any does.
    fn of_reason(reason: &str) -> Option<Self> {
        HOLDS.into_iter().find(|hold| hold.reason() == reason)
    }
}

impl Vault {
    /// Holds `attempt` as the program runtime's own park for `hold`: it stays
    /// parked until the program kind's resumer finds its condition met, never
    /// on a pass's or a boot's own sweep.
    pub(crate) fn hold_turn_program(
        &self,
        attempt: AttemptId,
        hold: ProgramHold,
        now: u64,
    ) -> Result<()> {
        DreamerRunnerStore::new(self).park_attempt(ParkDreamerAttempt {
            attempt_id: attempt,
            reason: hold.reason().to_owned(),
            cause: DreamerParkCause::Other,
            park_owner: PROGRAM_PARK_OWNER.to_owned(),
            now,
        })?;
        Ok(())
    }

    /// What holds a cut program's resume at the live vault: its actor gone,
    /// a step of its run uncertain, or a send of its try whose delivery is
    /// not settled. `None` when nothing does.
    pub(crate) fn turn_program_resume_preflight(
        &self,
        attempt: AttemptId,
    ) -> Result<Option<ProgramHold>> {
        let txn = self.store.env.read_txn()?;
        resume_preflight_in_txn(self, &txn, attempt)
    }
}

impl DreamerRunnerStore<'_> {
    /// Resumes `attempt`'s program hold, the one its park's exact `reason`
    /// names, once its condition is met, in a savepoint of `txn`. Best
    /// effort: a hold whose check fails is logged and left as it is, and a
    /// park no hold names is never touched.
    pub(super) fn resume_ready_program_hold_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: AttemptId,
        reason: &str,
        now: u64,
    ) {
        let Some(hold) = ProgramHold::of_reason(reason) else {
            return;
        };
        let resumed = (|| -> Result<()> {
            if !hold_ready_in_txn(self.vault, &*txn, attempt, hold)? {
                return Ok(());
            }
            let mut savepoint = self.vault.store.env.nested_write_txn(txn)?;
            self.resume_parked_in_txn(&mut savepoint, attempt, PROGRAM_PARK_OWNER, now)?;
            savepoint.commit()?;
            Ok(())
        })();
        if let Err(error) = resumed {
            tracing::warn!(
                kind = ?error.kind(),
                ?attempt,
                ?hold,
                "a held turn program was not resumed; its hold stands"
            );
        }
    }
}

/// Whether `hold`'s condition is met for `attempt` at `txn`'s revision.
fn hold_ready_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    hold: ProgramHold,
) -> Result<bool> {
    match hold {
        ProgramHold::Cut => Ok(true),
        ProgramHold::AuthorityLapsed => Ok(matches!(
            vault.bind_turn_program_in_txn(txn, attempt)?,
            TurnProgramBound::Bound(_)
        )),
        ProgramHold::Wait => {
            let Some(stamp) = ATTEMPT.get_lenient(vault, txn, &attempt)? else {
                return Ok(false);
            };
            let run = turn_program_code_run(&stamp.admission)?;
            let Some(wait) =
                program_resume_head_in_txn(vault, txn, run)?.and_then(|head| head.wait)
            else {
                return Ok(false);
            };
            let key = WaitKey {
                run,
                wait_id: wait.wait_id,
                generation: wait.generation,
            };
            wait_delivered_in_txn(vault, txn, &key)
        }
        ProgramHold::Uncertain => Ok(resume_preflight_in_txn(vault, txn, attempt)?.is_none()),
        ProgramHold::Unbound
        | ProgramHold::PinMoved
        | ProgramHold::Withheld
        | ProgramHold::Diverged
        | ProgramHold::Unfinished => Ok(false),
    }
}

fn resume_preflight_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<ProgramHold>> {
    let Some(stamp) = ATTEMPT.get_lenient(vault, txn, &attempt)? else {
        return Ok(Some(ProgramHold::Uncertain));
    };
    if actor_gone_in_txn(vault, txn, &stamp.actor) {
        return Ok(Some(ProgramHold::Withheld));
    }
    if run_holds_uncertain_step_in_txn(vault, txn, turn_program_code_run(&stamp.admission)?)? {
        return Ok(Some(ProgramHold::Uncertain));
    }
    match crate::outbound_intent_ledger::attempt_has_pending_intent_in_txn(vault, txn, attempt) {
        Ok(false) => Ok(None),
        Ok(true) => Ok(Some(ProgramHold::Uncertain)),
        Err(error) => {
            tracing::warn!(%error, "a turn program's sends were not read; it holds");
            Ok(Some(ProgramHold::Uncertain))
        }
    }
}

/// Whether a step of `run` is uncertain, or does not decode: nothing resumes
/// past it until it is reconciled.
fn run_holds_uncertain_step_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> Result<bool> {
    for row in STEP.iter_raw_from(vault, txn, run.as_bytes())? {
        let (_, bytes) = row?;
        match STEP.decode_value(&bytes) {
            Ok(step) if !matches!(step.state, StepState::Uncertain { .. }) => {}
            _ => return Ok(true),
        }
    }
    Ok(false)
}
