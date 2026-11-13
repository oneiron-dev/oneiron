//! Pause and resume of one run branch (DOOR-100, FIX 4501, Engine 10-20 on
//! the C002 pattern): `vault.runs.pause` and `vault.runs.resume`, and the one
//! admission HTTP run-tree intervention takes for those two kinds.
//!
//! The vault owner pauses and resumes any branch, as the TURN doors serve
//! him: his own key, a host action or a managed owner acting as him, or a
//! narrower credential of his while he is still the bound owner
//! (`ScopedReadActorKey::facets_owner_exempt_in`). His own credential that
//! grants no read keeps both through owner authority, judged by that slip in
//! the same writer. Any other caller needs the TASK binding: the branch
//! realizes a TASK whose Owner standing L02's rule proves for it
//! ([`Memory::highway_task_actor_in`]). A host credential that acts as no
//! person, the host's root or a slip it holds, is admitted as the owner is
//! (FIX 6429), and nothing else of his.
//!
//! Who releases a held branch is keyed on the hold and the caller (Fable 5.2
//! item 2, lead 06:5x). The vault owner overrides any hold. Every other
//! caller, the TASK's owner and the host included, resumes only a person's
//! pause it placed itself; an engine hold (budget, fan-out, hook, annotation)
//! or another caller's pause refuses it, `FORBIDDEN` with one reason code
//! (`awaits:*`) naming the signal the branch waits on and a fix naming the
//! door that gives it. Its pause of a held branch is refused the same way.
//!
//! A running agent run is paused at its next step boundary (Engine RULING
//! PAUSE-BOUNDARY-SCOPE = B, 13 Nov): the pause posts the Pause signal
//! `vault.agents.pause_tree` posts, and answers `pausing_at_next_step`; a
//! repeat while it is pending posts nothing more. Once the run's step
//! commits, its row stands under a person's pause that names the caller,
//! so the caller's resume releases it. A running branch no boundary reaches
//! (a landing one, one of no run) is still refused. Past that, the queue's
//! own pause and resume run as they always did, and a repeat answers
//! `already_paused` or `already_resumed` and writes nothing.

use serde::{Deserialize, Serialize};

use super::run_doors::{RunBranchView, branch_view};
use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, HoldSignal, InterveneAttempt, InterveneOutcome,
};
use crate::authority::{TaskActorVerb, VerifiedSlip};
use crate::claim::ScopedReadActorKey;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult, actor_is_vault_owner_in_txn,
    verify_actor_binding,
};
use crate::run_tree::{
    RunSignalInput, RunSignalKind, RunTreeAdapter, pause_pending, takes_boundary_pause,
};

/// What a caller neither the owner nor the TASK's owner should do instead.
const RUN_CONTROL_FIX: &str =
    "Pause or resume a branch of a TASK you own; the vault owner reaches any branch.";
/// The holder the host root names, and every slip cut from it keeps.
const HOST_HOLDER: &str = "host";

/// One branch to pause or resume, by the attempt id its run tree names.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunControlRequest {
    /// The branch's attempt id, hex, as `vault.runs.branches.get` names it.
    pub branch: String,
    /// Kept on the branch's intervention event.
    #[serde(default)]
    pub note: Option<String>,
}

/// What the pause or resume did, and the branch as it stands after it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunControlReceipt {
    pub effect: RunControlEffect,
    pub branch: RunBranchView,
}

/// The queue's own effect: a repeat answers `already_*` and writes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunControlEffect {
    Paused,
    AlreadyPaused,
    Resumed,
    AlreadyResumed,
    /// A running run pauses at its next step boundary; a repeat answers it
    /// again and posts nothing more.
    PausingAtNextStep,
}

/// The two controls these doors run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunControl {
    Pause,
    Resume,
}

/// How run control admitted its caller, which decides what held branch it
/// releases (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunControlStanding {
    /// The vault owner: overrides any hold.
    Owner,
    /// The host acting as no person, or the TASK's owner: releases only a
    /// person's pause it placed.
    Caller,
}

impl RunControl {
    const fn kind(self) -> AttemptInterventionKind {
        match self {
            Self::Pause => AttemptInterventionKind::Pause,
            Self::Resume => AttemptInterventionKind::Resume,
        }
    }
}

impl Memory<'_> {
    /// `vault.runs.pause`: pauses one queued or scheduled branch for this
    /// surface's caller, or a running run at its next step boundary
    /// ([`Self::control_run`]).
    ///
    /// # Errors
    ///
    /// As [`Self::control_run`] refuses, or a branch that is no attempt id.
    pub fn runs_pause(&self, input: RunControlRequest) -> MemoryResult<RunControlReceipt> {
        self.control_run_door(input, RunControl::Pause)
    }

    /// `vault.runs.resume`: resumes one paused branch for this surface's
    /// caller ([`Self::control_run`]).
    ///
    /// # Errors
    ///
    /// As [`Self::control_run`] refuses, or a branch that is no attempt id.
    pub fn runs_resume(&self, input: RunControlRequest) -> MemoryResult<RunControlReceipt> {
        self.control_run_door(input, RunControl::Resume)
    }

    fn control_run_door(
        &self,
        input: RunControlRequest,
        control: RunControl,
    ) -> MemoryResult<RunControlReceipt> {
        let outcome = self.control_run(branch_id(&input.branch)?, control, input.note)?;
        let effect = match outcome.effect {
            AttemptInterventionEffect::Paused => RunControlEffect::Paused,
            AttemptInterventionEffect::AlreadyPaused => RunControlEffect::AlreadyPaused,
            AttemptInterventionEffect::Resumed => RunControlEffect::Resumed,
            AttemptInterventionEffect::AlreadyResumed => RunControlEffect::AlreadyResumed,
            AttemptInterventionEffect::PausingAtNextStep => RunControlEffect::PausingAtNextStep,
            _ => {
                return Err(MemoryError::from(Error::InvariantViolation(
                    "run control effect",
                )));
            }
        };
        Ok(RunControlReceipt {
            effect,
            branch: branch_view(outcome.record),
        })
    }

    /// Pauses or resumes `branch` for this surface's caller, in one writer
    /// that admits the caller first (module docs), and answers the queue's
    /// own outcome. The doors' one admission: HTTP run-tree intervention
    /// takes it for these two kinds (FIX 4501). The event names this
    /// surface's actor.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a branch no row names, or one of a TASK the caller is
    /// no party to; `FORBIDDEN` for a caller that is neither the vault owner
    /// nor the TASK's owner, or one a hold refuses (module docs); the queue's
    /// refusal of the transition; a broken actor binding; storage errors.
    pub fn control_run(
        &self,
        branch: AttemptId,
        control: RunControl,
        note: Option<String>,
    ) -> MemoryResult<InterveneOutcome> {
        verify_actor_binding(self.vault(), self.actor(), self.actor_class())?;
        // Built before the writer, so its snapshot never nests in it, and
        // judged again there. A credential that grants no read has no key.
        let key = self.read_key().ok();
        intervene_admitted(
            self.vault(),
            branch,
            control,
            self.actor().to_hex(),
            note,
            |txn, record| self.admit_run_control_in(txn, key.as_ref(), record),
        )
    }

    /// The doors' admission of this surface's caller on `record`, in `txn`:
    /// the vault owner by `key`, his credential's own read key, or, for his
    /// credential that grants no read, by that slip; else the TASK binding.
    fn admit_run_control_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: Option<&ScopedReadActorKey>,
        record: &AttemptRecord,
    ) -> MemoryResult<RunControlStanding> {
        if self.vault_owner_standing_in(txn, key)? {
            return Ok(RunControlStanding::Owner);
        }
        let Some(task) = record
            .task_ref
            .as_deref()
            .and_then(|task| EntityId::from_hex(task).ok())
        else {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only the vault owner pauses or resumes a branch that realizes no TASK",
                &[RUN_CONTROL_FIX],
            ));
        };
        self.highway_task_actor_in(txn, task, TaskActorVerb::Owner, RUN_CONTROL_FIX)?;
        Ok(RunControlStanding::Caller)
    }

    /// Whether this surface's caller stands as the vault owner in `txn`: by
    /// `key`, his credential's own read key, or, for his credential that
    /// grants no read, by that slip. Run control and run cancel (FIX 8219)
    /// take the owner override alike.
    pub(super) fn vault_owner_standing_in(
        &self,
        txn: &heed::RoTxn<'_>,
        key: Option<&ScopedReadActorKey>,
    ) -> MemoryResult<bool> {
        Ok(match (key, self.presented_credential()) {
            (Some(key), _) => key.facets_owner_exempt_in(self.vault(), txn)?,
            (None, Some(slip)) => self.slip_is_owner_in(txn, slip)?,
            (None, None) => false,
        })
    }

    /// Whether `slip` is the vault owner's own credential in `txn`, by the
    /// owner rule a credential's read key follows (C002, FIX 6066): a
    /// person's, untransferred, held by this surface's human actor, who is
    /// the live owner, and live itself.
    fn slip_is_owner_in(&self, txn: &heed::RoTxn<'_>, slip: &VerifiedSlip) -> MemoryResult<bool> {
        let claims = slip.claims();
        if self.actor_class() != EdgeActorClass::Human
            || !matches!(claims.actor_class.as_deref(), None | Some("human"))
            || slip.is_transferred()
            || claims.holder_ref != self.actor().to_hex()
        {
            return Ok(false);
        }
        Ok(
            actor_is_vault_owner_in_txn(self.vault(), txn, self.actor(), EdgeActorClass::Human)?
                && self.vault().capability_slip_is_live_in_txn(txn, slip)?,
        )
    }
}

impl crate::Vault {
    /// Pauses or resumes `branch` for a host credential that acts as no
    /// person (FIX 6429): the host's root where it acts as nobody, or a slip
    /// cut from it. For these two controls alone it is admitted as the owner
    /// is, in the writer on `proof`, a slip the host holds that grants a write
    /// and is live there; a held branch it releases as any caller other than
    /// the vault owner does (module docs). The event names `actor`, the label
    /// the door authenticated it under. Every other caller takes
    /// [`Memory::control_run`].
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for a branch no row names; `FORBIDDEN` for a slip the
    /// host does not hold, one that grants no write, or one no longer live,
    /// or a branch a hold keeps (module docs); the queue's refusal of the
    /// transition; storage errors.
    pub fn control_run_as_host(
        &self,
        proof: &VerifiedSlip,
        branch: AttemptId,
        control: RunControl,
        actor: &str,
        note: Option<String>,
    ) -> MemoryResult<InterveneOutcome> {
        intervene_admitted(self, branch, control, actor.to_owned(), note, |txn, _| {
            if proof.claims().holder_ref == HOST_HOLDER
                && (proof.allows_verb("write") || proof.allows_verb("core:write"))
                && self.capability_slip_is_live_in_txn(txn, proof)?
            {
                return Ok(RunControlStanding::Caller);
            }
            Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "only a live host credential that grants a write pauses or resumes as the host",
                &[RUN_CONTROL_FIX],
            ))
        })
    }
}

/// Pauses or resumes `branch` in one writer that admits its caller by
/// `admit` first, and answers the queue's own outcome; a caller other than
/// the vault owner passes the table's caller-class column. The event names
/// `actor`.
fn intervene_admitted(
    vault: &crate::Vault,
    branch: AttemptId,
    control: RunControl,
    actor: String,
    note: Option<String>,
    admit: impl FnOnce(&heed::RoTxn<'_>, &AttemptRecord) -> MemoryResult<RunControlStanding>,
) -> MemoryResult<InterveneOutcome> {
    let queue = AttemptQueue::new(vault);
    let now = vault.store.clock.now_recorded_at();
    let outcome = vault.try_with_write_txn_grouped(|wtxn| {
        let record = queue
            .get_in_write_txn(wtxn, branch)?
            .ok_or(Error::EntityNotFound)?;
        let standing = admit(wtxn, &record)?;
        if control == RunControl::Pause
            && let Some(effect) = boundary_pause_in(vault, wtxn, &record, &actor, note.as_deref())?
        {
            let record = queue
                .get_in_write_txn(wtxn, branch)?
                .ok_or(Error::EntityNotFound)?;
            return Ok(InterveneOutcome { effect, record });
        }
        let input = InterveneAttempt {
            id: branch,
            kind: control.kind(),
            actor,
            note,
            now,
        };
        match standing {
            RunControlStanding::Owner => Ok::<_, MemoryError>(queue.intervene_in_txn(wtxn, input)?),
            RunControlStanding::Caller => queue
                .intervene_as_caller_in_txn(wtxn, input)?
                .map_err(hold_refusal),
        }
    })?;
    vault.store.notify_attempt_observers();
    Ok(outcome)
}

/// The pause of a running run, in the admitting writer (module docs): the
/// Pause signal its run takes at its next step boundary, keyed by the lease
/// generation and the row's event count, so each pause of the row has its
/// own; `PausingAtNextStep`, with nothing posted, while one is pending.
/// `None` for a branch that is not running, or one no boundary reaches: the
/// queue's own pause answers it.
fn boundary_pause_in(
    vault: &crate::Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    actor: &str,
    note: Option<&str>,
) -> crate::Result<Option<AttemptInterventionEffect>> {
    if record.state != AttemptState::Leased {
        return Ok(None);
    }
    if pause_pending(record) {
        return Ok(Some(AttemptInterventionEffect::PausingAtNextStep));
    }
    let Some(run_id) = record
        .run_id
        .clone()
        .filter(|_| takes_boundary_pause(record))
    else {
        return Ok(None);
    };
    RunTreeAdapter::new(vault).signal_in_txn(
        wtxn,
        RunSignalInput {
            branch: record.id,
            run_id,
            key: format!(
                "runs-pause:{}:{}",
                record.attempt_count,
                record.events.len()
            ),
            actor: actor.to_owned(),
            kind: RunSignalKind::Pause {
                note: note.map(str::to_owned),
            },
        },
    )?;
    Ok(Some(AttemptInterventionEffect::PausingAtNextStep))
}

/// The refusal of a caller a hold keeps: `FORBIDDEN`, the signal's reason
/// code, and the door that gives the signal.
fn hold_refusal(signal: HoldSignal) -> MemoryError {
    let (message, fix) = match signal {
        HoldSignal::BudgetResume => (
            "the branch waits under its run's budget hold".to_owned(),
            "The vault owner resumes a budget hold (vault.budgets.hold.resume) once its lease has room.",
        ),
        HoldSignal::FanoutApproval { launch_ref } => (
            format!(
                "the branch waits on the approval of fan-out launch {}",
                launch_ref.to_hex()
            ),
            "Approve the launch with vault.fanout.resume_as if you hold its decision role; the vault owner rules it with vault.fanout.resume.",
        ),
        HoldSignal::HookAnswer => (
            "the branch waits on its verb hook's ask".to_owned(),
            "Answer the ask with tasks.answer if you are one of its members; the run resumes once it is answered.",
        ),
        HoldSignal::AnnotationReattach {
            artifact_id,
            thread_id,
        } => (
            format!(
                "the branch waits for comment thread {} of artifact {} to reattach",
                thread_id.to_hex(),
                artifact_id.to_hex()
            ),
            "Reattach the comment thread at its exact words; the run resumes then.",
        ),
        HoldSignal::Pauser => (
            "another caller paused the branch".to_owned(),
            "Ask whoever paused it, or the vault owner, to resume it.",
        ),
    };
    let mut refusal = MemoryError::new(MEMORY_CODE_FORBIDDEN, message, &[fix]);
    refusal.reason_codes = vec![signal.reason_code().to_owned()];
    refusal
}

/// The attempt id `branch` names: thirty-two hex digits.
fn branch_id(branch: &str) -> MemoryResult<AttemptId> {
    let invalid = || {
        MemoryError::bad_request_with(
            "branch must be a 32-hex attempt id",
            &["Name a branch as vault.runs.branches.get names it."],
        )
    };
    if branch.len() != 32 || !branch.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let mut bytes = [0_u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&branch[at * 2..at * 2 + 2], 16).map_err(|_| invalid())?;
    }
    AttemptId::from_bytes(&bytes).map_err(|_| invalid())
}
