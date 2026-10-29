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
//!
//! The change that returns a hold's cause resumes it too, not only the next
//! selection (FIX 5874, FIX 5875): a commit that stores an authority row
//! rechecks each lapsed-authority hold, and a host that binds its program
//! runtime resumes each hold for want of it whose waking actor it now lends
//! to. A restore that brings an archived grant or actor back rechecks them
//! in its own commit (FIX 6058). The resumed try binds its authority, its
//! pin and its host again at its entry, and is held again for whatever still
//! holds it. The holds no condition returns are the owner's to release
//! (`release`, FIX 5880).

use crate::attempt_queue::AttemptId;
use crate::code_run::{WaitKey, program_resume_head_in_txn, wait_delivered_in_txn};
use crate::dreamer_runner::{
    DreamerParkCause, DreamerParkedAttemptRecord, DreamerRunnerStore, ParkDreamerAttempt,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::{EdgeActorClass, Vault, WriteActor};

use super::super::store::PARKED;
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
    pub(super) fn of_reason(reason: &str) -> Option<Self> {
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
            carried_spend: None,
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

impl DreamerRunnerStore<'_> {
    /// Resumes, each as the same try, the programs the runtime holds for a
    /// cause that has returned, on the change itself rather than at the next
    /// program admission (FIX 5874, FIX 5875): a lapsed authority that
    /// stands again with its pin, and, where `host` says this host now lends
    /// the waking actor's programs, a want of a host. Each hold is judged
    /// again in the writer; the resumed try binds its authority, its pin and
    /// its host again at its entry, and is held again for whatever still
    /// holds it. No other park is touched, nothing is timed and nothing is
    /// refused. Returns how many it resumed.
    ///
    /// # Errors
    ///
    /// Storage errors reading the holds or committing their resumes. A hold
    /// whose own check or resume fails is logged and left as it is.
    pub fn resume_returned_program_holds(
        &self,
        host: Option<&dyn Fn(WriteActor) -> bool>,
        now: u64,
    ) -> Result<usize> {
        // Read-only first: a vault with no returned hold opens no write.
        let due = {
            let rtxn = self.vault.store.env.read_txn()?;
            returned_holds_in_txn(self.vault, &rtxn, host)?
        };
        if due.is_empty() {
            return Ok(0);
        }
        let mut wtxn = self.vault.store.env.write_txn()?;
        let resumed = self.resume_due_program_holds_in_txn(&mut wtxn, due, host, now)?;
        wtxn.commit()?;
        if resumed > 0 {
            self.vault.store.notify_attempt_observers();
            // The deadline lane arms the queued tries at once.
            self.vault.store.notify_proactivity_changes();
        }
        Ok(resumed)
    }

    /// Whether any program is held for want of a host (FIX 9467): the one
    /// program hold whose return (a run that can now be configured or
    /// seated) no committed change signals, so a bound host keeps rechecking
    /// on its timer while one waits. Every other hold the host monitors
    /// returns on a committed change, which signals attempt observers.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn programs_held_for_host(&self) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        Ok(PARKED
            .scan(&self.vault.store, &rtxn)?
            .into_iter()
            .any(|(_, park)| {
                park.park_owner == PROGRAM_PARK_OWNER
                    && park.cause == DreamerParkCause::Other
                    && ProgramHold::of_reason(&park.reason) == Some(ProgramHold::Unbound)
            }))
    }

    /// Transaction-composable [`Self::resume_returned_program_holds`]: the
    /// holds whose cause has returned at `wtxn`'s revision, each resumed in a
    /// savepoint of the caller's writer, which commits them with its own
    /// change. The caller signals observers after its commit.
    fn resume_returned_program_holds_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        host: Option<&dyn Fn(WriteActor) -> bool>,
        now: u64,
    ) -> Result<usize> {
        let due = returned_holds_in_txn(self.vault, &*wtxn, host)?;
        self.resume_due_program_holds_in_txn(wtxn, due, host, now)
    }

    /// Resumes each of `due` whose hold's cause still returned at `wtxn`'s
    /// revision, each in a savepoint. A hold whose resume fails is logged
    /// and left as it is. Returns how many it resumed.
    fn resume_due_program_holds_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        due: Vec<AttemptId>,
        host: Option<&dyn Fn(WriteActor) -> bool>,
        now: u64,
    ) -> Result<usize> {
        let mut resumed = 0_usize;
        for attempt in due {
            let Some(park) = PARKED.get(&self.vault.store, &*wtxn, &attempt)? else {
                continue;
            };
            if !returned_hold(self.vault, &*wtxn, attempt, &park, host) {
                continue;
            }
            let one = (|| -> Result<bool> {
                let mut savepoint = self.vault.store.env.nested_write_txn(wtxn)?;
                let cleared = self
                    .resume_parked_in_txn(&mut savepoint, attempt, PROGRAM_PARK_OWNER, now)?
                    .is_some();
                savepoint.commit()?;
                Ok(cleared)
            })();
            match one {
                Ok(true) => resumed += 1,
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    kind = ?error.kind(),
                    ?attempt,
                    "a held turn program was not resumed; its hold stands"
                ),
            }
        }
        Ok(resumed)
    }
}

impl Vault {
    /// After a commit that stored an authority row (`noted`), resumes each
    /// program held for a lapsed authority that stands again (FIX 5875).
    /// Best-effort: a failure is logged, and the program kind's admission
    /// chain still judges each hold before its next selection.
    pub(crate) fn resume_turn_programs_after_authority_ingest(&self, noted: bool) {
        if !noted {
            return;
        }
        let resumed = DreamerRunnerStore::new(self)
            .resume_returned_program_holds(None, self.now_recorded_at());
        if let Err(error) = resumed {
            tracing::warn!(
                kind = ?error.kind(),
                "held turn programs were not rechecked after an authority ingest; the next \
                 program admission rechecks them"
            );
        }
    }

    /// In the writer of a change that may return a waking actor's authority
    /// without storing an authority row (FIX 6058: an archived grant or
    /// actor a restore brings back), resumes each program held for a lapsed
    /// authority that stands again at `wtxn`'s revision, under the same
    /// actor and pin checks, so the resume commits with the change and rolls
    /// back with it. A resume stages the proactivity wake its writer's owner
    /// signals after the commit. Best-effort: a recheck that fails is logged
    /// and never fails the caller's change; the program kind's admission
    /// chain still judges each hold before its next selection. Opens no
    /// writer of its own.
    pub(crate) fn resume_turn_programs_after_authority_change_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
    ) {
        let now = self.now_recorded_at();
        let resumed = (|| -> Result<usize> {
            let mut savepoint = self.store.env.nested_write_txn(wtxn)?;
            let resumed = DreamerRunnerStore::new(self).resume_returned_program_holds_in_txn(
                &mut savepoint,
                None,
                now,
            )?;
            savepoint.commit()?;
            Ok(resumed)
        })();
        match resumed {
            Ok(0) => {}
            Ok(_) => crate::batch::queue_proactivity_change(self, wtxn),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "held turn programs were not rechecked after a restore; the next program \
                 admission rechecks them"
            ),
        }
    }
}

/// The program runtime's own holds whose cause has returned at `txn`'s
/// revision, by attempt.
fn returned_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    host: Option<&dyn Fn(WriteActor) -> bool>,
) -> Result<Vec<AttemptId>> {
    Ok(PARKED
        .scan(&vault.store, txn)?
        .into_iter()
        .filter(|(attempt, park)| returned_hold(vault, txn, *attempt, park, host))
        .map(|(attempt, _)| attempt)
        .collect())
}

/// Whether `park` is the program runtime's own hold of `attempt` whose cause
/// has returned at `txn`'s revision: its lapsed authority binds again, or,
/// with `host`, a host now lends its waking actor's programs. A hold whose
/// check fails is logged and read as not returned.
fn returned_hold(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    park: &DreamerParkedAttemptRecord,
    host: Option<&dyn Fn(WriteActor) -> bool>,
) -> bool {
    if park.park_owner != PROGRAM_PARK_OWNER || park.cause != DreamerParkCause::Other {
        return false;
    }
    let judged = match ProgramHold::of_reason(&park.reason) {
        Some(ProgramHold::AuthorityLapsed) => vault
            .bind_turn_program_in_txn(txn, attempt)
            .map(|bound| matches!(bound, TurnProgramBound::Bound(_))),
        // The host judges only whether it lends the actor's programs at all;
        // the entry binds the authority and the run itself.
        Some(ProgramHold::Unbound) => match host {
            Some(lends) => ATTEMPT.get(vault, txn, &attempt).map(|stamp| {
                stamp.is_some_and(|stamp| {
                    EdgeActorClass::try_from_u8(stamp.actor_class)
                        .is_some_and(|class| lends(WriteActor::new(stamp.actor, class)))
                })
            }),
            None => Ok(false),
        },
        _ => Ok(false),
    };
    judged.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            ?attempt,
            "a held turn program's cause was not judged; its hold stands"
        );
        false
    })
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

pub(super) fn resume_preflight_in_txn(
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
