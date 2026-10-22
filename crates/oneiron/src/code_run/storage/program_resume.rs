//! A turn program's resume checkpoint (DOOR-141 PR3b, FIX 4382): the compact
//! head and keyed pages its pinned entry restarts from, committed beside the
//! code run's own checkpoint.
//!
//! The head pins the program the run replays, the position its last entry
//! committed and the wait it parked on. Each page lists, in the order the
//! pinned source makes them, calls already settled: each by the row of the
//! code run's record that settled it, and by the delivered wait reply that
//! answers it when one does. Nothing here copies an effect's body: the
//! record's rows, the write receipts and the program's steps hold those. A
//! restarter reads the head and its pages, never the record whole.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::code_run::payload::{decode_self_dispatch_outcome, self_call_request_value};
use crate::code_run::replay::{CodeRunBridgeCall, CodeRunReplayRecord};
use crate::code_run::spawn_replay::{ReplayRequestMatch, replay_request_match};
use crate::code_run::types::{SelfCall, SelfDispatchOutcome, SelfDurableWait};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

/// The settled calls one page lists: a CALLS choice.
const PROGRAM_RESUME_PAGE_CALLS: u64 = 64;

/// The key kind of a run's head; its page is always 0.
const HEAD: u64 = 0;
/// The key kind of a run's pages, by page.
const PAGE: u64 = 1;

const CALL_DOMAIN: &[u8] = b"oneiron:code-run:program-resume-call:v1";

/// A code run's resume rows, keyed by the run, the row's kind and its page.
const RESUME: SideTable<(EntityId, u64, u64), ResumeRow, Named> =
    SideTable::new(&side_table::CODE_RUN_PROGRAM_RESUME);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ResumeRow {
    Head(ProgramResumeHead),
    Page(ResumePage),
}

/// The head of a code run's resume checkpoint: the program it replays, how
/// far its entries got, and what the last one waits on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgramResumeHead {
    /// The try whose entry committed it.
    pub(crate) attempt: [u8; 16],
    /// The pinned SKILL the run replays, its revision's content hash and its
    /// call contract's digest.
    pub(crate) skill: EntityId,
    pub(crate) content_hash: String,
    pub(crate) contract_digest: [u8; 32],
    /// How many entries committed.
    pub(crate) entries: u64,
    /// Where the last entry's own rows start in the run's record: its
    /// pinned call's row.
    pub(crate) entry_start: u64,
    /// The record's rows and its last checkpoint's state hash, as the last
    /// entry committed them.
    pub(crate) bridge_calls: u64,
    pub(crate) state_hash: [u8; 32],
    /// How many of the pinned source's calls are settled, the applied
    /// position: the pages list each one.
    pub(crate) applied: u64,
    /// How many of them the last entry answered from an earlier row instead
    /// of issuing them, the committed injection position.
    pub(crate) injected: u64,
    /// The pages that list them.
    pub(crate) pages: u64,
    /// The wait the last entry parked on, when it did.
    pub(crate) wait: Option<ProgramResumeWait>,
    pub(crate) at: u64,
    /// The identity of the JavaScript the pinned call ran as, when its
    /// source is TypeScript (FIX 8276). The code run's record keeps its body
    /// and map; every later entry runs that, never a new preparation.
    pub(crate) preparation: Option<[u8; 32]>,
}

/// The wait one entry parked on: the row of the call that parked, and the
/// wait's key in the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgramResumeWait {
    pub(crate) row: u64,
    pub(crate) wait_id: EntityId,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumePage {
    calls: Vec<ProgramResumeCall>,
}

/// One settled call of the pinned source, as a page lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProgramResumeCall {
    /// The row of the run's record that settled it, or that parked it when
    /// a delivered reply answers it.
    pub(crate) row: u64,
    /// BLAKE3 of that row's canonical request.
    pub(crate) request_digest: [u8; 32],
    /// The wait whose delivered reply answers it, when one does.
    pub(crate) reply: Option<EntityId>,
}

/// What one pinned entry commits beside its checkpoint: every call it
/// answered or made that is settled, in the pinned source's order.
pub(crate) struct ProgramResumeCommit {
    pub(crate) attempt: [u8; 16],
    pub(crate) skill: EntityId,
    pub(crate) content_hash: String,
    pub(crate) contract_digest: [u8; 32],
    pub(crate) entry_start: u64,
    pub(crate) calls: Vec<ProgramResumeCall>,
    pub(crate) injected: u64,
    pub(crate) wait: Option<ProgramResumeWait>,
    pub(crate) at: u64,
    pub(crate) preparation: Option<[u8; 32]>,
}

/// A run's head and every call its pages list, for its restarter.
pub(crate) struct ProgramCheckpointTail {
    pub(crate) head: ProgramResumeHead,
    pub(crate) calls: Vec<ProgramResumeCall>,
}

/// `run`'s resume checkpoint, read in one snapshot over its head and its
/// keyed pages: never the record whole. `None` before an entry committed.
///
/// # Errors
///
/// Storage; a head or a page that does not decode, or a page missing.
pub(crate) fn load_program_checkpoint_tail(
    vault: &Vault,
    run: EntityId,
) -> Result<Option<ProgramCheckpointTail>> {
    let txn = vault.store.env.read_txn()?;
    let Some(head) = program_resume_head_in_txn(vault, &txn, run)? else {
        return Ok(None);
    };
    let calls = program_resume_calls_in_txn(vault, &txn, run, 0, head.applied)?;
    Ok(Some(ProgramCheckpointTail { head, calls }))
}

/// `run`'s resume head at `txn`'s revision.
pub(crate) fn program_resume_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
) -> Result<Option<ProgramResumeHead>> {
    match RESUME.get(vault, txn, &(run, HEAD, 0))? {
        None => Ok(None),
        Some(ResumeRow::Head(head)) => Ok(Some(head)),
        Some(ResumeRow::Page(_)) => {
            Err(Error::CorruptedIndex("a program resume head holds a page"))
        }
    }
}

/// The settled calls `from..to` of `run`'s checkpoint, read page by page.
pub(crate) fn program_resume_calls_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    from: u64,
    to: u64,
) -> Result<Vec<ProgramResumeCall>> {
    let mut calls = Vec::new();
    if from >= to {
        return Ok(calls);
    }
    for page in from / PROGRAM_RESUME_PAGE_CALLS..=(to - 1) / PROGRAM_RESUME_PAGE_CALLS {
        let Some(ResumeRow::Page(held)) = RESUME.get(vault, txn, &(run, PAGE, page))? else {
            return Err(Error::CorruptedIndex("a program resume page is missing"));
        };
        let first = page * PROGRAM_RESUME_PAGE_CALLS;
        for (index, call) in (first..).zip(held.calls) {
            if (from..to).contains(&index) {
                calls.push(call);
            }
        }
    }
    if u64::try_from(calls.len()).ok() != Some(to - from) {
        return Err(Error::CorruptedIndex("a program resume page is short"));
    }
    Ok(calls)
}

/// One settled call as a page lists it: `row`, and the wait whose delivered
/// reply answers it.
///
/// # Errors
///
/// A request that does not encode.
pub(crate) fn program_resume_call(
    row: &CodeRunBridgeCall,
    reply: Option<EntityId>,
) -> Result<ProgramResumeCall> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &row.request)
        .map_err(|_| Error::InvalidConfig("a program call's request does not encode".to_owned()))?;
    Ok(ProgramResumeCall {
        row: row.seq,
        request_digest: *blake3::Hasher::new()
            .update(CALL_DOMAIN)
            .update(&bytes)
            .finalize()
            .as_bytes(),
        reply,
    })
}

/// Joins a pinned entry's resume checkpoint to its code run's checkpoint
/// commit (DOOR-141 PR3b): each page from the first one its calls changed,
/// then the head. Nothing here can fail that commit: a head that cannot be
/// written is logged, and the next entry, which finds the head behind its
/// record, holds instead of replaying past it.
pub(crate) fn join_program_resume_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
    commit: &ProgramResumeCommit,
) {
    let joined = (|| -> Result<()> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        put_resume_in_txn(vault, &mut savepoint, record, commit)?;
        savepoint.commit()?;
        Ok(())
    })();
    if let Err(error) = joined {
        tracing::warn!(
            kind = ?error.kind(),
            run = %record.run_id.to_hex(),
            "a program's resume checkpoint was not joined; the checkpoint stands"
        );
    }
}

fn put_resume_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &CodeRunReplayRecord,
    commit: &ProgramResumeCommit,
) -> Result<()> {
    let run = record.run_id;
    let count = |len: usize| {
        u64::try_from(len).map_err(|_| Error::ArithmeticOverflow("program resume count"))
    };
    let previous = program_resume_head_in_txn(vault, &*txn, run)?;
    let applied = count(commit.calls.len())?;
    let pages = applied.div_ceil(PROGRAM_RESUME_PAGE_CALLS);
    // The calls an earlier head listed are the entry's own first calls, each
    // matched before it was answered, up to the first one that missed its
    // row (FIX 7447) and ran live: only whole pages of the `injected` calls
    // the entry answered stay as written, and the rest are written anew.
    let kept = previous.as_ref().map_or(0, |head| {
        head.applied.min(applied).min(commit.injected) / PROGRAM_RESUME_PAGE_CALLS
    });
    for page in kept..pages {
        let start = usize::try_from(page * PROGRAM_RESUME_PAGE_CALLS)
            .map_err(|_| Error::ArithmeticOverflow("program resume page"))?;
        let end = commit
            .calls
            .len()
            .min(start.saturating_add(PROGRAM_RESUME_PAGE_CALLS as usize));
        let calls = commit.calls[start..end].to_vec();
        RESUME.put(
            vault,
            txn,
            &(run, PAGE, page),
            &ResumeRow::Page(ResumePage { calls }),
        )?;
    }
    for page in pages..previous.as_ref().map_or(0, |head| head.pages) {
        RESUME.delete(vault, txn, &(run, PAGE, page))?;
    }
    let head = ProgramResumeHead {
        attempt: commit.attempt,
        skill: commit.skill,
        content_hash: commit.content_hash.clone(),
        contract_digest: commit.contract_digest,
        entries: previous
            .as_ref()
            .map_or(0, |head| head.entries)
            .saturating_add(1),
        entry_start: commit.entry_start,
        bridge_calls: count(record.bridge_calls.len())?,
        state_hash: record
            .step_checkpoints
            .last()
            .map_or([0; 32], |checkpoint| checkpoint.state_hash),
        applied,
        injected: commit.injected,
        pages,
        wait: commit.wait,
        at: commit.at,
        preparation: commit.preparation,
    };
    RESUME.put(vault, txn, &(run, HEAD, 0), &ResumeRow::Head(head))
}

/// What a settled row answers for the call a resumed entry makes in its
/// place.
pub(crate) enum ProgramRowAnswer {
    /// The very call it recorded: what it answered.
    Settled(Box<SelfDispatchOutcome>),
    /// The same spawn asked for another project or other objectives (FIX
    /// 7447): a replay miss, which the entry issues live.
    Missed,
    /// Another call.
    Drifted,
}

impl CodeRunBridgeCall {
    /// What this settled row answers for `call`: its outcome when `call` is
    /// the very call it recorded, the same effect and canonical request
    /// under the row's own bridge stamp (a request the side-row wall masked
    /// still matches the secrets it holds); a miss for the same spawn asked
    /// for another project or objectives; drift for any other call.
    ///
    /// # Errors
    ///
    /// A request or an outcome that does not encode or decode.
    pub(crate) fn program_answer_for(&self, call: &SelfCall) -> Result<ProgramRowAnswer> {
        if self.effect != call.effect() {
            return Ok(ProgramRowAnswer::Drifted);
        }
        let stamped = call.clone().with_bridge_stamp(self.seq, self.started_at_ms);
        let request = self_call_request_value(&stamped)?;
        Ok(
            match replay_request_match(self.effect, &self.request, &request)? {
                ReplayRequestMatch::Hit => ProgramRowAnswer::Settled(Box::new(
                    decode_self_dispatch_outcome(&self.outcome)?,
                )),
                ReplayRequestMatch::SpawnMiss => ProgramRowAnswer::Missed,
                ReplayRequestMatch::Drift => ProgramRowAnswer::Drifted,
            },
        )
    }

    /// The wait this row's call parked on, when its outcome is one.
    ///
    /// # Errors
    ///
    /// An outcome that does not decode.
    pub(crate) fn program_durable_wait(&self) -> Result<Option<SelfDurableWait>> {
        Ok(match decode_self_dispatch_outcome(&self.outcome)? {
            SelfDispatchOutcome::DurableWait(wait) => Some(wait),
            _ => None,
        })
    }

    /// The answer this settled row keeps, as its call was answered (FIX
    /// 5837): a verb's JSON output, exactly as the row stores it, so a value
    /// the side-row wall masked stays masked. `None` for any other outcome:
    /// a refusal, a failure, a wait, or an answer an erase took. No live call
    /// is matched and no secret is read back.
    ///
    /// # Errors
    ///
    /// An outcome that does not decode.
    pub(crate) fn program_stored_answer(&self) -> Result<Option<serde_json::Value>> {
        Ok(match decode_self_dispatch_outcome(&self.outcome)? {
            SelfDispatchOutcome::AgentVerb(answer) => Some(answer.output),
            _ => None,
        })
    }
}

impl Vault {
    /// Whether `run`'s resume checkpoint lines up with its code run's record
    /// at `txn`'s revision, as a pinned entry of `skill` at `content_hash`
    /// and `contract_digest` finds it before it answers a call (FIX 5880):
    /// with no head, the record holds no call; with one, the head's frontier
    /// is the record's, its pin is this one, every call its pages list is the
    /// record row it names, and the row it parked on holds a wait. `None`
    /// when it does; otherwise the first disagreement. Read-only: nothing is
    /// repaired, resumed or answered here, and a head behind its record stays
    /// behind (its repair is FIX 5881's).
    ///
    /// # Errors
    ///
    /// Storage; a head, a page or a row's outcome that does not decode, or a
    /// page missing.
    pub(crate) fn validate_program_resume_checkpoint_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        run: EntityId,
        skill: EntityId,
        content_hash: &str,
        contract_digest: &[u8; 32],
    ) -> Result<Option<&'static str>> {
        let record = self.get_code_run_replay_record_in_txn(txn, &run)?;
        let Some(head) = program_resume_head_in_txn(self, txn, run)? else {
            let unlisted = record
                .as_ref()
                .is_some_and(|record| !record.bridge_calls.is_empty());
            return Ok(unlisted.then_some("the run's record holds calls no checkpoint lists"));
        };
        let Some(record) = record else {
            return Ok(Some("the checkpoint names a code run with no record"));
        };
        let state_hash = record
            .step_checkpoints
            .last()
            .map_or([0; 32], |checkpoint| checkpoint.state_hash);
        if u64::try_from(record.bridge_calls.len()).ok() != Some(head.bridge_calls)
            || head.state_hash != state_hash
        {
            return Ok(Some(
                "the checkpoint is not the frontier its run's record holds",
            ));
        }
        if head.skill != skill
            || head.content_hash != content_hash
            || head.contract_digest != *contract_digest
        {
            return Ok(Some("the checkpoint replays another pinned program"));
        }
        let row_at = |seq: u64| {
            usize::try_from(seq)
                .ok()
                .and_then(|index| record.bridge_calls.get(index))
                .filter(|row| row.seq == seq)
        };
        for listed in program_resume_calls_in_txn(self, txn, run, 0, head.applied)? {
            if row_at(listed.row).is_none() {
                return Ok(Some("a settled call's record row is missing"));
            }
        }
        if let Some(wait) = head.wait {
            let parks = match row_at(wait.row) {
                Some(row) => row.program_durable_wait()?.is_some(),
                None => false,
            };
            if !parks {
                return Ok(Some(
                    "the record row the checkpoint parked on holds no wait",
                ));
            }
        }
        Ok(None)
    }
}
