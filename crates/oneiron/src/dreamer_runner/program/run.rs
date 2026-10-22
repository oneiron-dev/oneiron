//! Where a turn program's run stands (DOOR-141 PR2), as execution progress:
//! CONTENT, never authority. The authority stands on the admission and is
//! judged live at each entry (`authority`).
//!
//! Each admitted program runs as one code run its admission fixes, so the
//! callable it calls checks the very run id its queue row carries. Its RUN
//! row maps the attempt to that code run and keeps its lifecycle (entered,
//! then settled with its result) and the checkpoint frontier its code run
//! last committed. Each effect that settles into it keeps one STEP row: the
//! issuing binding committed before the effect (a model step's occurrence
//! and request, a verb write's place and call, an outbound send's intent),
//! then the terminal evidence and exact result after it. An effect whose
//! end is unknown stays uncertain; nothing here resends one.
//!
//! A send's body is the one content a step keeps (FIX 5710). It is admitted
//! as admitted text is, at the side-row wall, before it is kept, and the
//! erase of the program's actor takes it out of every step, leaving the
//! step's evidence whole. A body the wall refuses, or one that settles after
//! its actor's erase, is not kept; the step settles all the same.

use std::collections::BTreeSet;
use std::ops::Bound;

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState, SetAttemptResult,
};
use crate::batch::secret_scan::{SidePart, admit_side_parts};
use crate::code_run::{CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::entity_id::EntityId;
use crate::error::{Error, ErrorKind, Result};
use crate::outbound_intent_ledger::IntentLedgerRecord;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::side_table::{self, Named, SideKey, SideTable};

use super::ATTEMPT;
use super::types::code_run_bytes;

const STEP_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-step:v1";

/// Where a send's body sits, as each custody record the wall mints from it
/// names its origin (with the step's full key): one stable place for every
/// step.
const STEP_BODY_PLACE: &str = "side:DREAMER_TURN_PROGRAM_STEP:result";

/// One program's code run, keyed by the code run.
pub(super) const RUN: SideTable<EntityId, TurnProgramRun, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_RUN);
/// One step of a program's run, keyed by the code run, then the step. A
/// send's inline body is a body instance (FIX 5710, FIX 5719): the actor's
/// erase clears it here, and its custody retires every image's (`bodies`).
pub(super) const STEP: SideTable<(EntityId, EntityId), TurnProgramStep, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_STEP);

fn invalid(why: &'static str) -> Error {
    Error::InvalidClaimBody(why)
}

/// A program's code run: the try that entered it, the admission that fixed
/// it, where it stands, and the frontier its code run last committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramRun {
    pub(super) attempt: [u8; 16],
    pub(super) admission: [u8; 32],
    pub(super) entered_at: u64,
    pub(super) state: RunState,
    pub(super) frontier: Option<RunFrontier>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum RunState {
    /// Entered and not settled: an entry that finds this again was cut.
    Entered,
    /// Finished: the code run's final committed state is its result, and
    /// the queue row names it.
    Settled {
        result_ref: String,
        frontier: RunFrontier,
        settled_at: u64,
    },
}

/// A code run's committed position: its counts and its last state hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct RunFrontier {
    pub(super) bridge_calls: u64,
    pub(super) steps: u64,
    pub(super) outputs: u64,
    pub(super) state_hash: [u8; 32],
}

impl From<&CodeRunReplayGeneration> for RunFrontier {
    fn from(generation: &CodeRunReplayGeneration) -> Self {
        Self {
            bridge_calls: generation.bridge_call_count,
            steps: generation.step_checkpoint_count,
            outputs: generation.output_count,
            state_hash: generation.last_state_hash,
        }
    }
}

/// One step of a program's run: what issued it, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TurnProgramStep {
    pub(super) attempt: [u8; 16],
    pub(super) issued: StepIssue,
    pub(super) state: StepState,
    pub(super) at: u64,
}

/// The issuing binding, committed before the effect runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum StepIssue {
    /// A model step: its logical occurrence in the run and its request.
    Model {
        occurrence: u64,
        request_hash: [u8; 32],
    },
    /// A verb write: its place in its step and the call it makes.
    Write {
        step_start: u64,
        ordinal: u64,
        receipt: EntityId,
        call_digest: [u8; 32],
    },
    /// An outbound send: its frozen intent.
    Outbound { intent: [u8; 32], call_seq: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum StepState {
    /// Bound and not ended.
    Issued,
    /// Ended, with its exact result's digest and, for a send, the body the
    /// transport returned as the side-row wall admitted it. The digest is
    /// over the bytes returned; the body is absent when the wall refused it
    /// or the program's actor is erased.
    Settled {
        result_digest: [u8; 32],
        result: Option<Vec<u8>>,
    },
    /// Its end is unknown: never taken for settled, never sent again.
    Uncertain { why: String },
}

/// How one entry into a program's code run stands.
pub(crate) enum TurnProgramEntered {
    /// The first entry: the run is marked entered.
    Fresh,
    /// The run already settled: its result stands, nothing runs again.
    Settled,
    /// An earlier entry was cut before it settled, or the code run exists
    /// with no entry: the next entry resumes it from its pinned entry
    /// (DOOR-141 PR3b), as the same try.
    Cut,
}

/// The code run an admission's program runs as.
pub(crate) fn turn_program_code_run(admission: &[u8; 32]) -> Result<EntityId> {
    EntityId::from_bytes(code_run_bytes(admission))
}

/// A program's RUN row, for its reads (DOOR-141 PR3a). A row that does not
/// decode reads as absent.
pub(super) fn program_run_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    code_run: &EntityId,
) -> Result<Option<TurnProgramRun>> {
    RUN.get_lenient(vault, txn, code_run)
}

/// One STEP row of a program's run, for its reads. A row that does not
/// decode reads as absent; the erased marker of a retired body that never
/// decoded answers `ResponseErased`, never absent (FIX 6227).
pub(super) fn program_step_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &(EntityId, EntityId),
) -> Result<Option<TurnProgramStep>> {
    let Some(raw) = STEP.get_borrowed(vault, txn, key)? else {
        return Ok(None);
    };
    let family = crate::store::ResponseFamily::ProgramStep;
    let raw = crate::store::ResponseRead::of(family, &STEP.key_bytes(key), &raw).present()?;
    Ok(STEP.decode_value(raw).ok())
}

/// One page of a program run's STEP rows, for its reads.
pub(super) struct ProgramStepPage {
    /// Each step by its ref, in key order.
    pub(super) steps: Vec<(EntityId, TurnProgramStep)>,
    /// Rows of the page that do not decode (FIX 5736): skipped, never a
    /// refusal of the page.
    pub(super) undecodable: u64,
    /// Whether a row follows the page.
    pub(super) more: bool,
}

/// Up to `limit` of `code_run`'s steps in key order, after the step `after`
/// when one is named. Every step id lies between the least and the greatest
/// id that is not reserved, so the range holds this run's rows alone.
pub(super) fn program_steps_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    code_run: EntityId,
    after: Option<EntityId>,
    limit: usize,
) -> Result<ProgramStepPage> {
    let mut least = [0_u8; 16];
    least[15] = 1;
    let mut greatest = [u8::MAX; 16];
    greatest[15] = u8::MAX - 1;
    let from = match after {
        Some(step) => (code_run, step),
        None => (code_run, EntityId::from_bytes(least)?),
    };
    let to = (code_run, EntityId::from_bytes(greatest)?);
    let start = if after.is_some() {
        Bound::Excluded(&from)
    } else {
        Bound::Included(&from)
    };
    let mut page = ProgramStepPage {
        steps: Vec::new(),
        undecodable: 0,
        more: false,
    };
    for row in STEP.iter_range(vault, txn, start, Bound::Included(&to))? {
        if page.steps.len() >= limit {
            page.more = true;
            break;
        }
        match row {
            Ok(((_, step), held)) => page.steps.push((step, held)),
            Err(error) if error.kind() == ErrorKind::SideTableRow => page.undecodable += 1,
            Err(error) => return Err(error),
        }
    }
    Ok(page)
}

/// Whether `attempt` still holds the lease `owner` took at `generation`.
fn lease_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    owner: &str,
    generation: u32,
) -> Result<bool> {
    Ok(AttemptQueue::new(vault)
        .get_in_txn(txn, attempt)?
        .is_some_and(|row| {
            row.state == AttemptState::Leased
                && row.lease_owner.as_deref() == Some(owner)
                && row.attempt_count == generation
        }))
}

fn leased_parts(attempt: &AttemptRecord) -> Result<&str> {
    attempt
        .lease_owner
        .as_deref()
        .ok_or_else(|| invalid("a turn program entry needs its leased try"))
}

fn step_id(parts: &[&[u8]]) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(STEP_DOMAIN);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    EntityId::from_bytes(bytes)
}

impl Vault {
    /// Enters `attempt`'s code run once, under its live lease: a first entry
    /// marks the run entered; a settled run answers settled; a run an
    /// earlier entry left unsettled, or a code run that exists with no
    /// entry, answers cut, which resumes from its pinned entry, never from
    /// scratch.
    pub(crate) fn enter_turn_program_run(
        &self,
        attempt: &AttemptRecord,
        admission: &[u8; 32],
        code_run: EntityId,
        now: u64,
    ) -> Result<TurnProgramEntered> {
        let owner = leased_parts(attempt)?;
        self.with_write_txn_grouped(|wtxn| {
            if !lease_holds_in_txn(self, &*wtxn, attempt.id, owner, attempt.attempt_count)? {
                return Err(invalid("a turn program entry lost its lease"));
            }
            match RUN.get(self, &*wtxn, &code_run)? {
                Some(run) => {
                    if run.admission != *admission {
                        return Err(invalid("a turn program run names another admission"));
                    }
                    Ok(match run.state {
                        RunState::Settled { .. } => TurnProgramEntered::Settled,
                        RunState::Entered => TurnProgramEntered::Cut,
                    })
                }
                None if self
                    .get_code_run_replay_record_in_txn(&*wtxn, &code_run)?
                    .is_some() =>
                {
                    Ok(TurnProgramEntered::Cut)
                }
                None => {
                    RUN.put(
                        self,
                        wtxn,
                        &code_run,
                        &TurnProgramRun {
                            attempt: *attempt.id.as_bytes(),
                            admission: *admission,
                            entered_at: now,
                            state: RunState::Entered,
                            frontier: None,
                        },
                    )?;
                    Ok(TurnProgramEntered::Fresh)
                }
            }
        })
    }

    /// Settles a finished program in one lease-fenced commit: the run's
    /// final committed state is its result, the queue row names it, and the
    /// RUN row keeps it. A lease that moved settles nothing.
    pub(crate) fn settle_turn_program_run(
        &self,
        attempt: &AttemptRecord,
        code_run: EntityId,
        generation: &CodeRunReplayGeneration,
        now: u64,
    ) -> Result<()> {
        let owner = leased_parts(attempt)?.to_owned();
        let result_ref = format!("code-run:{}", code_run.to_hex());
        let frontier = RunFrontier::from(generation);
        self.with_write_txn_grouped(|wtxn| {
            let mut run = RUN
                .get(self, &*wtxn, &code_run)?
                .ok_or_else(|| invalid("a settling turn program has no run"))?;
            if run.attempt != *attempt.id.as_bytes() {
                return Err(invalid("a settling turn program run names another try"));
            }
            AttemptQueue::new(self).set_result_in_txn(
                wtxn,
                SetAttemptResult {
                    id: attempt.id,
                    lease_owner: owner.clone(),
                    attempt_count: attempt.attempt_count,
                    result_ref: AttemptResultRef::new(result_ref.clone())?,
                    now,
                },
            )?;
            run.state = RunState::Settled {
                result_ref: result_ref.clone(),
                frontier,
                settled_at: now,
            };
            run.frontier = Some(frontier);
            RUN.put(self, wtxn, &code_run, &run)
        })?;
        self.store.notify_attempt_observers();
        Ok(())
    }

    /// One model step of a program's run, by its logical occurrence: bound
    /// before the call (`settled` none), settled with its response's digest
    /// after it.
    pub(crate) fn record_turn_program_model_step(
        &self,
        attempt: AttemptId,
        code_run: EntityId,
        occurrence: u64,
        request_hash: [u8; 32],
        settled: Option<[u8; 32]>,
        now: u64,
    ) -> Result<()> {
        let key = (
            code_run,
            step_id(&[b"model", code_run.as_bytes(), &occurrence.to_be_bytes()])?,
        );
        let step = TurnProgramStep {
            attempt: *attempt.as_bytes(),
            issued: StepIssue::Model {
                occurrence,
                request_hash,
            },
            state: match settled {
                Some(result_digest) => StepState::Settled {
                    result_digest,
                    result: None,
                },
                None => StepState::Issued,
            },
            at: now,
        };
        self.with_write_txn_grouped(|wtxn| {
            if let Some(held) = STEP.get(self, &*wtxn, &key)? {
                if held.issued != step.issued {
                    return Err(invalid("a program model step changed its request"));
                }
                // A replayed occurrence binds again before its call: a step
                // that settled stays settled (DOOR-141 PR3b).
                if settled.is_none() && matches!(held.state, StepState::Settled { .. }) {
                    return Ok(());
                }
            }
            STEP.put(self, wtxn, &key, &step)
        })
    }
}

/// One verb write a program's code run makes, at its place in its step.
pub(crate) struct ProgramWrite {
    pub(crate) attempt: AttemptId,
    pub(crate) lease_owner: String,
    pub(crate) generation: u32,
    pub(crate) code_run: EntityId,
    pub(crate) step_start: u64,
    pub(crate) ordinal: u64,
    pub(crate) receipt: EntityId,
    pub(crate) call_digest: [u8; 32],
}

impl ProgramWrite {
    fn issued(&self) -> StepIssue {
        StepIssue::Write {
            step_start: self.step_start,
            ordinal: self.ordinal,
            receipt: self.receipt,
            call_digest: self.call_digest,
        }
    }
}

/// Binds a program's verb write before it runs, in its receipt's own
/// reservation commit and under the program's live lease: a lease that
/// moved refuses the write before any effect. A changed call at a bound
/// place is refused, never written again.
pub(crate) fn bind_program_write_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    write: &ProgramWrite,
    now: u64,
) -> Result<()> {
    if !lease_holds_in_txn(
        vault,
        &*wtxn,
        write.attempt,
        &write.lease_owner,
        write.generation,
    )? {
        return Err(invalid("a program write lost its lease"));
    }
    super::authority::require_program_authority_in_txn(vault, wtxn, write.attempt)?;
    let key = (write.code_run, write.receipt);
    let issued = write.issued();
    if let Some(held) = STEP.get(vault, &*wtxn, &key)?
        && held.issued != issued
    {
        return Err(invalid("a program write changed its call"));
    }
    STEP.put(
        vault,
        wtxn,
        &key,
        &TurnProgramStep {
            attempt: *write.attempt.as_bytes(),
            issued,
            state: StepState::Issued,
            at: now,
        },
    )
}

/// Settles a program's verb write into its step, in the commit that keeps
/// its receipt's answer. The write already ran, so nothing here can fail
/// that commit: a step that cannot be recorded is logged and the receipt
/// stays committed.
pub(crate) fn settle_program_write_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    write: &ProgramWrite,
    result_digest: [u8; 32],
    now: u64,
) {
    let step = TurnProgramStep {
        attempt: *write.attempt.as_bytes(),
        issued: write.issued(),
        state: StepState::Settled {
            result_digest,
            result: None,
        },
        at: now,
    };
    if let Err(error) = put_step_savepoint(vault, wtxn, &(write.code_run, write.receipt), &step) {
        tracing::warn!(
            kind = ?error.kind(),
            receipt = %write.receipt.to_hex(),
            "a program write's step was not settled; its receipt stands"
        );
    }
}

/// A program's write found its receipt empty: it may have committed without
/// its answer. It is never written again; its step stays uncertain.
pub(crate) fn note_program_write_uncertain(vault: &Vault, write: &ProgramWrite, now: u64) {
    let step = TurnProgramStep {
        attempt: *write.attempt.as_bytes(),
        issued: write.issued(),
        state: StepState::Uncertain {
            why: "the write's receipt holds no answer".to_owned(),
        },
        at: now,
    };
    let key = (write.code_run, write.receipt);
    if let Err(error) = vault.with_write_txn_grouped(|wtxn| STEP.put(vault, wtxn, &key, &step)) {
        tracing::warn!(
            kind = ?error.kind(),
            receipt = %write.receipt.to_hex(),
            "a program write's uncertain step was not recorded"
        );
    }
}

/// Joins a program's checkpoint frontier to its code run's own checkpoint
/// commit (DOOR-141 PR2). A code run no program entered holds no RUN row and
/// writes nothing; nothing here can fail the checkpoint's commit.
pub(crate) fn join_program_checkpoint_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
) {
    let joined = (|| -> Result<()> {
        let Some(mut run) = RUN.get(vault, &*wtxn, &record.run_id)? else {
            return Ok(());
        };
        if !matches!(run.state, RunState::Entered) {
            return Ok(());
        }
        run.frontier = Some(RunFrontier::from(&record.generation()?));
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        RUN.put(vault, &mut savepoint, &record.run_id, &run)?;
        savepoint.commit()?;
        Ok(())
    })();
    if let Err(error) = joined {
        tracing::warn!(
            kind = ?error.kind(),
            run = %record.run_id.to_hex(),
            "a program's checkpoint frontier was not joined; the checkpoint stands"
        );
    }
}

/// Settles a program's outbound send into its step, in the transaction that
/// records the send's terminal result, with the body its transport returned
/// when it returned one, as the side-row wall admits it (FIX 5710). A send no
/// program attempt made writes nothing, and nothing here can fail the send's
/// own commit. The step's digest is over the bytes returned, whatever is
/// kept of them: a body the wall refuses, or one whose actor is erased by
/// now, is not kept, and the step settles without it.
pub(crate) fn settle_program_outbound_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &IntentLedgerRecord,
    body: Option<&[u8]>,
    now: u64,
) {
    let settled = (|| -> Result<()> {
        let Some(stamp) = ATTEMPT.get(vault, &*wtxn, &record.attempt_id)? else {
            return Ok(());
        };
        let code_run = turn_program_code_run(&stamp.admission)?;
        let key = (code_run, step_id(&[b"outbound", &record.id])?);
        let result_digest = *blake3::Hasher::new()
            .update(STEP_DOMAIN)
            .update(&record.payload_hash)
            .update(body.unwrap_or_default())
            .finalize()
            .as_bytes();
        let skeleton = TurnProgramStep {
            attempt: *record.attempt_id.as_bytes(),
            issued: StepIssue::Outbound {
                intent: record.id,
                call_seq: record.call_seq,
            },
            state: StepState::Settled {
                result_digest,
                result: None,
            },
            at: now,
        };
        let gone = actor_gone_in_txn(vault, &*wtxn, &stamp.actor);
        let Some(body) = body.filter(|_| !gone) else {
            return put_step_savepoint(vault, wtxn, &key, &skeleton);
        };
        if let Err(error) = put_admitted_step_savepoint(vault, wtxn, &key, &skeleton, body) {
            tracing::warn!(
                kind = ?error.kind(),
                "a program's outbound step body was not kept; the step settles without it"
            );
            return put_step_savepoint(vault, wtxn, &key, &skeleton);
        }
        Ok(())
    })();
    if let Err(error) = settled {
        tracing::warn!(
            kind = ?error.kind(),
            "a program's outbound step was not settled; the send stands"
        );
    }
}

/// Whether `actor` is gone here (FIX 5710, FIX 5738): soft-deleted (its
/// identity's soft-delete marker, or a deletion of its row other than an
/// archive), or hard-deleted and erased (its hard-delete marker). A step
/// body is then never kept, served or injected, so a late answer cannot
/// bring back one the erase scrubbed; the step keeps its skeleton and its
/// original digest. An archive is reversible and withholds nothing. A marker
/// that cannot be read counts as gone.
pub(super) fn actor_gone_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> bool {
    let gone = (|| -> Result<bool> {
        Ok(crate::ports::removed_in_txn(&vault.store, txn, actor)?
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::HardDelete, actor)?
            || vault
                .store
                .port_deletion_marked(txn, DeletionMarker::IdentitySoftDelete, actor)?)
    })();
    gone.unwrap_or_else(|error| {
        tracing::warn!(
            kind = ?error.kind(),
            "a program step's actor deletion markers were not read; its body is withheld"
        );
        true
    })
}

/// One STEP row in a savepoint of `wtxn`, so a row that fails leaves the
/// enclosing commit as it was.
fn put_step_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &(EntityId, EntityId),
    step: &TurnProgramStep,
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    STEP.put(vault, &mut savepoint, key, step)?;
    savepoint.commit()?;
    Ok(())
}

/// `skeleton`, settled, keeping `body` as the side-row wall admits it, in a
/// savepoint of `wtxn`: a clean body is kept as returned, a masked one keeps
/// its handles with the custody they name minted in the same savepoint. A
/// body the wall refuses, or any failure, rolls the savepoint back whole,
/// custody and all.
fn put_admitted_step_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &(EntityId, EntityId),
    skeleton: &TurnProgramStep,
    body: &[u8],
) -> Result<()> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
    let full = STEP.key_bytes(key);
    let mut parts = [SidePart::Body(body.to_vec())];
    admit_side_parts(
        vault,
        &mut savepoint,
        (STEP_BODY_PLACE, full.as_slice()),
        &mut parts,
        |parts| matches!(parts, [SidePart::Body(_)]),
    )?;
    let [SidePart::Body(admitted)] = parts else {
        return Err(Error::InvariantViolation(
            "an admitted step body is no longer a body",
        ));
    };
    let mut step = skeleton.clone();
    if let StepState::Settled { result, .. } = &mut step.state {
        *result = Some(admitted);
    }
    STEP.put(vault, &mut savepoint, key, &step)?;
    savepoint.commit()?;
    Ok(())
}

/// The erase of `actor` takes the body out of each of its programs' steps
/// (FIX 5710), in the erase's own writer. Its programs are found by their
/// attempt stamps, which a disarm leaves, and every try of one admission
/// runs its one code run. A settled step keeps its key, try, issuing
/// binding, digest and time; an issued or uncertain step stays as it is,
/// and nothing is sent again. The erase never fails on a row that does not
/// decode (FIX 5736): a step under one of its code runs whose row does not
/// decode goes whole by key, and a stamp that does not decode names no
/// actor, so its run stays out of reach. Returns how many steps went whole.
pub(super) fn scrub_actor_step_bodies_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<usize> {
    let ActorSteps {
        bodied,
        undecodable,
    } = actor_steps_in_txn(vault, wtxn, actor)?;
    for (key, mut step) in bodied {
        if let StepState::Settled { result, .. } = &mut step.state {
            *result = None;
        }
        STEP.put(vault, wtxn, &key, &step)?;
    }
    for key in &undecodable {
        STEP.delete(vault, wtxn, key)?;
    }
    Ok(undecodable.len())
}

/// How many of `actor`'s programs' steps an erase would remove whole on
/// `txn`, because their rows do not decode (FIX 5736).
pub(super) fn undecodable_actor_steps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<usize> {
    Ok(actor_steps_in_txn(vault, txn, actor)?.undecodable.len())
}

/// The steps an erase of one actor reaches: each settled step that keeps a
/// body, and each step whose row does not decode.
struct ActorSteps {
    bodied: Vec<((EntityId, EntityId), TurnProgramStep)>,
    undecodable: Vec<(EntityId, EntityId)>,
}

/// The steps under each code run `actor`'s attempt stamps name, read on
/// `txn`. A key that does not decode names no step and is left as it is.
fn actor_steps_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<ActorSteps> {
    let mut code_runs = BTreeSet::new();
    for row in ATTEMPT.iter_raw_from(vault, txn, &[])? {
        let (_, bytes) = row?;
        if let Ok(stamp) = ATTEMPT.decode_value(&bytes)
            && stamp.actor == *actor
        {
            code_runs.insert(turn_program_code_run(&stamp.admission)?);
        }
    }
    let mut steps = ActorSteps {
        bodied: Vec::new(),
        undecodable: Vec::new(),
    };
    for code_run in code_runs {
        for row in STEP.iter_raw_from(vault, txn, code_run.as_bytes())? {
            let (key, bytes) = row?;
            let Some(key) = <(EntityId, EntityId) as SideKey>::decode_key(&key) else {
                continue;
            };
            match STEP.decode_value(&bytes) {
                Ok(step)
                    if matches!(
                        step.state,
                        StepState::Settled {
                            result: Some(_),
                            ..
                        }
                    ) =>
                {
                    steps.bodied.push((key, step));
                }
                Ok(_) => {}
                Err(_) => steps.undecodable.push(key),
            }
        }
    }
    Ok(steps)
}
