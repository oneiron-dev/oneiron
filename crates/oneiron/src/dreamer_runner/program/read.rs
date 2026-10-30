//! A turn program's reads (DOOR-141 PR3a, FIX 4382): what admitting a
//! landed turn's wakes decided and the wakes it still owes, held ones with
//! their hold (`owed`, FIX 12172), where one program's run stands, and one
//! settled step's exact result; PR3b adds the resume checkpoint its
//! restarter reads (`checkpoint`).
//!
//! Each reads as its caller, on the caller's own verified read key: a
//! program's rows read for its waking actor or the verified owner, and
//! every record a field derives from (the turn, its conversation, the pinned
//! SKILL, a step's terminal claim and the rows a write's answer was served
//! from) must read on the caller's own lane, or that field is withheld while
//! the rest of the answer stands. An actor id or a digest is never a Grant.
//! A historical read judges no live authority: nothing here executes,
//! admits, resumes or leases. Each side-table snapshot closes before the
//! lane reads.

mod answer;
mod checkpoint;
mod owed;
mod views;

use std::collections::BTreeSet;
use std::ops::Bound;

use base64::Engine as _;

use crate::attempt_queue::{AttemptId, AttemptResultRef, AttemptState};
use crate::dreamer_runner::{DreamerAttemptStatus, DreamerParkedAttemptRecord, DreamerRunnerStore};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, ErrorKind, Result};
use crate::llm::{CallerSettledStep, settled_step_for_caller};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::run_tree::{RunTreeAdapter, RunTreeNode, RunTreeStatus};
use crate::{EdgeActorClass, Vault};

use super::run::{
    RunState, StepIssue, StepState, TurnProgramRun, TurnProgramStep, actor_gone_in_txn,
    program_run_in_txn, program_step_in_txn, program_steps_page_in_txn, turn_program_code_run,
};
use super::types::{ProgramRecipePin, TurnProgramAdmissionRecord, TurnProgramAttemptStamp, run_id};
use super::{ADMISSION, ATTEMPT};

use self::answer::{ReceiptAnswer, answer_body_base64, receipt_answer_in_txn};
use self::owed::{owed_wake_item, owed_wakes_in_txn};

pub use self::checkpoint::program_checkpoint;
pub use self::views::{
    OwedWakeHoldView, ProgramAdmissionOutcomeView, ProgramCheckpointCallView,
    ProgramCheckpointConsentView, ProgramCheckpointHeadView, ProgramCheckpointRequest,
    ProgramCheckpointView, ProgramCheckpointWaitView, ProgramFrontierView, ProgramHeldView,
    ProgramQueueView, ProgramResultAvailability, ProgramRunLifecycle, ProgramRunRequest,
    ProgramRunStateView, ProgramRunView, ProgramStepIssueView, ProgramStepState, ProgramStepView,
    ProgramTryView, SettledProgramStepRequest, SettledProgramStepView, TurnProgramAdmissionItem,
    TurnProgramAdmissionRequest, TurnProgramAdmissionView, TurnProgramOwedWakeItem,
};

/// Items a page carries when the request names no limit, and the most one
/// carries.
const PAGE_LIMIT: u32 = 64;
/// Decoded admissions one page of [`turn_program_admission`] examines at
/// most. A turn's admissions are read by their turn index (FIX 5838), in
/// admission order from the page's cursor.
const ADMISSION_SCAN_ROWS: usize = 256;

/// Reads the admissions the wakes of one landed turn decided, one page at a
/// time: each one the caller reads (it is the waking actor, or the verified
/// owner), with the turn, its conversation and the pinned SKILL withheld
/// unless they read on the caller's own lane. The first page also lists the
/// wakes the turn still owes those programs, each held one with its hold's
/// reason and expiry (FIX 12172). `None` when the first page finds neither.
///
/// # Errors
///
/// A request that does not parse; the caller's read key refused; storage.
pub fn turn_program_admission(
    memory: &Memory<'_>,
    input: &TurnProgramAdmissionRequest,
) -> MemoryResult<Option<TurnProgramAdmissionView>> {
    let caller = Caller::of(memory)?;
    let turn = entity_ref(&input.turn_ref, "turn_ref must be a 32-hex TURN id")?;
    let registration = input
        .registration
        .as_deref()
        .map(|text| entity_ref(text, "registration must be a 32-hex id"))
        .transpose()?;
    let cursor = input
        .cursor
        .as_deref()
        .map(|text| digest_ref(text, "cursor must be 64 hex characters"))
        .transpose()?;
    let limit = page_limit(input.limit)?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let page = TurnPage {
        turn,
        registration,
        cursor,
        limit,
    };
    let (records, next, undecodable) = admissions_of_turn_in_txn(vault, &txn, &page, &caller)?;
    let owed = if cursor.is_none() {
        owed_wakes_in_txn(vault, &txn, turn, registration, &caller)?
    } else {
        Vec::new()
    };
    drop(txn);
    if records.is_empty() && owed.is_empty() && next.is_none() && cursor.is_none() {
        return Ok(None);
    }
    let readable = readable_on_lane(
        memory,
        records
            .iter()
            .flat_map(|record| {
                [
                    Some(record.wake.turn.turn),
                    Some(record.wake.turn.conversation),
                    record.definition.as_ref().map(|pin| pin.skill),
                ]
                .into_iter()
                .flatten()
            })
            .chain((!owed.is_empty()).then_some(turn)),
    )?;
    let turn_reads = readable.contains(&turn);
    Ok(Some(TurnProgramAdmissionView {
        turn_ref: turn.to_hex(),
        admissions: records
            .into_iter()
            .map(|record| admission_item(record, &readable))
            .collect(),
        owed: owed
            .into_iter()
            .map(|wake| owed_wake_item(wake, turn_reads))
            .collect(),
        next_cursor: next.map(|key| bytes_to_hex_lower(&key)),
        undecodable_admission_rows_examined: undecodable,
    }))
}

/// Reads where one program's run stands: its admission's binding, its queue
/// tries, its held park (FIX 5712), the program runtime's record of its code
/// run and one page of its steps. `None` when no program stamped the attempt,
/// or the caller is neither its waking actor nor the verified owner.
///
/// # Errors
///
/// A request that does not parse; the caller's read key refused; storage.
pub fn program_run(
    memory: &Memory<'_>,
    input: &ProgramRunRequest,
) -> MemoryResult<Option<ProgramRunView>> {
    let caller = Caller::of(memory)?;
    let asked = attempt_ref(&input.root, "root must be a 32-hex attempt id")?;
    let cursor = input
        .cursor
        .as_deref()
        .map(|text| entity_ref(text, "cursor must be a 32-hex step ref"))
        .transpose()?;
    let limit = page_limit(input.limit)?;
    let Some(program) = program_for(memory, &caller, asked)? else {
        return Ok(None);
    };
    let vault = memory.vault();
    let store = DreamerRunnerStore::new(vault);
    // Each of these opens a snapshot of its own.
    let root_created_at = store.run_tree(program.root)?.map(|row| row.created_at);
    let tree = RunTreeAdapter::new(vault).read_run(&run_id(&program.admission))?;
    let tries = tries_of(&tree.roots);
    let current = tries
        .last()
        .map(|newest| attempt_ref(&newest.attempt, "a run-tree attempt id did not parse"))
        .transpose()?
        .unwrap_or(program.root);
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let status = store.status_with_park_in_txn(&txn, current)?;
    let held_by_try = held_by_try_in_txn(&store, &txn, &tries)?;
    let run = program_run_in_txn(vault, &txn, &program.code_run)?
        .filter(|run| run.admission == program.admission);
    let page = program_steps_page_in_txn(vault, &txn, program.code_run, cursor, limit)?;
    drop(txn);
    let readable = readable_on_lane(memory, program.definition.as_ref().map(|pin| pin.skill))?;
    let mut withheld = Vec::new();
    let definition = withhold_definition(program.definition, &readable, &mut withheld);
    let (queue, held) = queue_and_held(current, status);
    // The cursor moves past the page's last step, an erased one too, so a
    // page of erased steps alone still moves on (FIX 9391).
    let next_cursor = if page.more {
        page.last.map(|step| step.to_hex())
    } else {
        None
    };
    Ok(Some(ProgramRunView {
        root: attempt_hex(program.root),
        admission: bytes_to_hex_lower(&program.admission),
        actor: program.actor,
        actor_class: class_name(program.actor_class),
        code_run: program.code_run.to_hex(),
        definition,
        root_created_at,
        tries,
        queue,
        held,
        held_by_try,
        run: run.map(run_view),
        steps: page
            .steps
            .into_iter()
            .map(|(step, row)| step_view(step, row))
            .collect(),
        erased_steps: page.erased.iter().map(EntityId::to_hex).collect(),
        undecodable_steps: page.undecodable,
        next_cursor,
        withheld,
    }))
}

/// Reads one settled step of a program's run and its exact result, as far
/// as the caller reads it: a model step's terminal claim and stored response
/// on the caller's own lane (never a response made up from progress), a
/// write's receipt with the rows its answer was served from and, once each
/// of them reads, the verb's JSON output the receipt keeps (FIX 5837), a
/// send's body as the side-row wall admitted it. A step's body is withheld, never
/// refused, once the program's actor is soft-deleted, hard-deleted or erased
/// (FIX 5710, FIX 5738); an archived actor's bodies still read. `None` for an
/// issued or uncertain step (the run read shows those), an unknown one, or a
/// caller who is neither the waking actor nor the owner.
///
/// # Errors
///
/// A request that does not parse; the caller's read key refused; storage.
pub fn settled_program_step(
    memory: &Memory<'_>,
    input: &SettledProgramStepRequest,
) -> MemoryResult<Option<SettledProgramStepView>> {
    let caller = Caller::of(memory)?;
    let asked = attempt_ref(&input.root, "root must be a 32-hex attempt id")?;
    let step = entity_ref(&input.step_ref, "step_ref must be a 32-hex step ref")?;
    let Some(program) = program_for(memory, &caller, asked)? else {
        return Ok(None);
    };
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some(row) = program_step_in_txn(vault, &txn, &(program.code_run, step))? else {
        return Ok(None);
    };
    let StepState::Settled {
        result_digest,
        result,
    } = row.state
    else {
        return Ok(None);
    };
    let deleted = actor_gone_in_txn(vault, &txn, &program.actor);
    let answer = match &row.issued {
        StepIssue::Write { receipt, .. } => receipt_answer_in_txn(vault, &txn, receipt)?,
        StepIssue::Model { .. } | StepIssue::Outbound { .. } => ReceiptAnswer::Absent,
    };
    drop(txn);
    let mut view = SettledProgramStepView {
        root: attempt_hex(program.root),
        attempt: bytes_to_hex_lower(&row.attempt),
        actor: program.actor,
        code_run: program.code_run.to_hex(),
        step_ref: step.to_hex(),
        issue: issue_view(&row.issued),
        settled_at: row.at,
        result_digest: bytes_to_hex_lower(&result_digest),
        result_ref: None,
        availability: ProgramResultAvailability::Absent,
        model_step: None,
        body_base64: None,
    };
    match row.issued {
        StepIssue::Model { .. } if deleted => {
            view.availability = ProgramResultAvailability::Withheld;
        }
        StepIssue::Model { request_hash, .. } => {
            let attempt = AttemptId::from_bytes(&row.attempt)?;
            match settled_step_for_caller(memory, attempt, request_hash)? {
                None => {}
                Some(CallerSettledStep::Withheld { claim }) => {
                    view.result_ref = Some(claim.to_hex());
                    view.availability = ProgramResultAvailability::Withheld;
                }
                Some(CallerSettledStep::Readable(settled)) => {
                    view.result_ref = Some(settled.claim_ref.clone());
                    view.availability = ProgramResultAvailability::Readable;
                    view.model_step = Some(*settled);
                }
            }
        }
        StepIssue::Write { receipt, .. } => {
            view.result_ref = Some(receipt.to_hex());
            view.availability = match answer {
                ReceiptAnswer::Absent => ProgramResultAvailability::Absent,
                ReceiptAnswer::Rows { .. } | ReceiptAnswer::Unlisted if deleted => {
                    ProgramResultAvailability::Withheld
                }
                ReceiptAnswer::Unlisted => ProgramResultAvailability::Withheld,
                ReceiptAnswer::Rows { rows, output } => {
                    let wanted = rows.iter().copied().collect::<BTreeSet<_>>();
                    if readable_on_lane(memory, rows)? == wanted {
                        view.body_base64 = output.as_ref().and_then(answer_body_base64);
                        ProgramResultAvailability::Readable
                    } else {
                        ProgramResultAvailability::Withheld
                    }
                }
            };
        }
        StepIssue::Outbound { intent, .. } => {
            view.result_ref = Some(bytes_to_hex_lower(&intent));
            match result {
                None => {}
                Some(_) if deleted => view.availability = ProgramResultAvailability::Withheld,
                Some(body) => {
                    view.availability = ProgramResultAvailability::Readable;
                    view.body_base64 = Some(base64::engine::general_purpose::STANDARD.encode(body));
                }
            }
        }
    }
    Ok(Some(view))
}

/// Who reads: the bound actor, and whether it reads as the verified owner.
struct Caller {
    actor: EntityId,
    class: EdgeActorClass,
    owner: bool,
}

impl Caller {
    /// The caller as its own read key verifies it: credential, locality and
    /// room, in the key's own snapshot.
    fn of(memory: &Memory<'_>) -> MemoryResult<Self> {
        let key = memory.read_key()?;
        Ok(Self {
            actor: memory.actor(),
            class: memory.actor_class(),
            owner: key.reads_as_vault_owner(),
        })
    }

    /// Whether this caller reads a program's rows: it is the program's
    /// waking actor at its class, or the verified owner. This is not a
    /// Grant: every record a field derives from still reads on the lane.
    fn reads(&self, actor: EntityId, class: u8) -> bool {
        self.owner || (self.actor == actor && self.class as u8 == class)
    }
}

/// One program as a try of it names it.
struct Program {
    root: AttemptId,
    admission: [u8; 32],
    actor: EntityId,
    actor_class: u8,
    code_run: EntityId,
    definition: Option<ProgramRecipePin>,
}

/// The program `asked` is a try of, as `caller` reads it: `None` when no
/// program stamped `asked`, its rows do not bind, or the caller is neither
/// its waking actor nor the owner. Its snapshot closes before it answers.
fn program_for(
    memory: &Memory<'_>,
    caller: &Caller,
    asked: AttemptId,
) -> MemoryResult<Option<Program>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let found = program_of_in_txn(vault, &txn, asked)?;
    drop(txn);
    let Some((stamp, record)) = found else {
        return Ok(None);
    };
    let Some(root) = record.attempt else {
        return Ok(None);
    };
    if !caller.reads(stamp.actor, stamp.actor_class) {
        return Ok(None);
    }
    Ok(Some(Program {
        root,
        admission: record.admission,
        actor: stamp.actor,
        actor_class: stamp.actor_class,
        code_run: turn_program_code_run(&record.admission)?,
        definition: record.definition,
    }))
}

/// `attempt`'s stamp and the admission it binds, in `txn`. A row that does
/// not decode reads as absent.
fn program_of_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
) -> Result<Option<(TurnProgramAttemptStamp, TurnProgramAdmissionRecord)>> {
    let Some(stamp) = ATTEMPT.get_lenient(vault, txn, &attempt)? else {
        return Ok(None);
    };
    let Some(record) = ADMISSION.get_lenient(vault, txn, &stamp.admission)? else {
        return Ok(None);
    };
    let binds =
        stamp.attempt_id == *attempt.as_bytes() && record.wake.authority.actor() == stamp.actor;
    Ok(binds.then_some((stamp, record)))
}

/// What one page of a turn's admissions asks for.
struct TurnPage {
    turn: EntityId,
    registration: Option<EntityId>,
    cursor: Option<[u8; 32]>,
    limit: usize,
}

/// One page of the admissions `page.turn`'s wakes decided that `caller`
/// reads, in admission-id order after the cursor: at most `limit` of them,
/// out of at most [`ADMISSION_SCAN_ROWS`] decoded rows examined, the id the
/// next page goes on after while a row is left, and how many rows that do
/// not decode the page passed over (FIX 5839). Such a row is skipped, and
/// counted only once a later decoded row is examined or the scan ends, so
/// one past the page's cursor is counted by the next page alone.
fn admissions_of_turn_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    page: &TurnPage,
    caller: &Caller,
) -> Result<(Vec<TurnProgramAdmissionRecord>, Option<[u8; 32]>, u64)> {
    let from = (page.turn, page.cursor.unwrap_or([0; 32]));
    let to = (page.turn, [0xFF; 32]);
    let start = match page.cursor {
        Some(_) => Bound::Excluded(&from),
        None => Bound::Included(&from),
    };
    let mut matched = Vec::new();
    let mut examined = 0_usize;
    let mut last = None;
    let (mut undecodable, mut pending) = (0_u64, 0_u64);
    let rows = super::index::TURN_ADMISSION.iter_range(vault, txn, start, Bound::Included(&to))?;
    for row in rows {
        let ((_, key), ()) = row?;
        let record = match ADMISSION.get(vault, txn, &key) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) if error.kind() == ErrorKind::SideTableRow => {
                pending = pending.saturating_add(1);
                continue;
            }
            Err(error) => return Err(error),
        };
        if matched.len() >= page.limit || examined >= ADMISSION_SCAN_ROWS {
            return Ok((matched, last, undecodable));
        }
        examined += 1;
        last = Some(key);
        undecodable = undecodable.saturating_add(std::mem::take(&mut pending));
        let wake = &record.wake;
        if wake.turn.turn == page.turn
            && page
                .registration
                .is_none_or(|registration| registration == wake.registration)
            && caller.reads(wake.authority.actor(), wake.authority.class_byte())
        {
            matched.push(record);
        }
    }
    Ok((matched, None, undecodable.saturating_add(pending)))
}

fn admission_item(
    record: TurnProgramAdmissionRecord,
    readable: &BTreeSet<EntityId>,
) -> TurnProgramAdmissionItem {
    let TurnProgramAdmissionRecord {
        admission,
        wake,
        definition,
        receipt_id,
        attempt,
        refused,
        decided_at,
    } = record;
    let mut withheld = Vec::new();
    let turn_reads = readable.contains(&wake.turn.turn);
    let conversation = (turn_reads && readable.contains(&wake.turn.conversation))
        .then_some(wake.turn.conversation);
    if conversation.is_none() {
        withheld.push("conversation".to_owned());
    }
    if !turn_reads {
        withheld.push("landed_at".to_owned());
    }
    let definition = withhold_definition(definition, readable, &mut withheld);
    let outcome = match attempt {
        Some(root) => ProgramAdmissionOutcomeView::Queued {
            root: attempt_hex(root),
            code_run: run_id(&admission),
        },
        None => ProgramAdmissionOutcomeView::Refused {
            reason: refused.unwrap_or_default(),
        },
    };
    TurnProgramAdmissionItem {
        admission: bytes_to_hex_lower(&admission),
        registration: wake.registration,
        actor: wake.authority.actor(),
        actor_class: class_name(wake.authority.class_byte()),
        conversation,
        landed_at: turn_reads.then_some(wake.turn.landed_at),
        revision: bytes_to_hex_lower(&wake.revision),
        definition,
        sealed_scope: wake
            .authority
            .scope_digest()
            .map(|digest| bytes_to_hex_lower(&digest)),
        gate_receipt: bytes_to_hex_lower(&receipt_id),
        outcome,
        decided_at,
        withheld,
    }
}

/// `definition`, unless its SKILL does not read on the caller's lane: then
/// none, and `definition` is named withheld.
fn withhold_definition(
    definition: Option<ProgramRecipePin>,
    readable: &BTreeSet<EntityId>,
    withheld: &mut Vec<String>,
) -> Option<ProgramRecipePin> {
    let pin = definition?;
    if readable.contains(&pin.skill) {
        return Some(pin);
    }
    withheld.push("definition".to_owned());
    None
}

/// The newest try's queue row, and its park when it is held: parked and
/// not terminal, work the program still owes (FIX 5712).
fn queue_and_held(
    current: AttemptId,
    status: Option<(DreamerAttemptStatus, Option<DreamerParkedAttemptRecord>)>,
) -> (Option<ProgramQueueView>, Option<ProgramHeldView>) {
    let Some((status, parked)) = status else {
        return (None, None);
    };
    let held = held_view(current, &status, parked);
    let row = status.attempt;
    let queue = ProgramQueueView {
        attempt: attempt_hex(current),
        state: row.state.as_str().to_owned(),
        lease_generation: row.attempt_count,
        result_ref: row.result_ref.map(AttemptResultRef::into_string),
        updated_at: row.updated_at,
    };
    (Some(queue), held)
}

/// `attempt`'s park while its queue row is not terminal: work the program
/// still owes, held.
fn held_view(
    attempt: AttemptId,
    status: &DreamerAttemptStatus,
    parked: Option<DreamerParkedAttemptRecord>,
) -> Option<ProgramHeldView> {
    let pending = matches!(
        status.attempt.state,
        AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled
            | AttemptState::Landing
    );
    parked.filter(|_| pending).map(|park| ProgramHeldView {
        attempt: attempt_hex(attempt),
        cause: park.cause.as_str().to_owned(),
        owner: park.park_owner,
        reason: park.reason,
        parked_at: park.parked_at,
    })
}

/// Each of `tries` held at `txn`'s revision, in their order (FIX 5840).
fn held_by_try_in_txn(
    store: &DreamerRunnerStore<'_>,
    txn: &heed::RoTxn<'_>,
    tries: &[ProgramTryView],
) -> MemoryResult<Vec<ProgramHeldView>> {
    let mut held = Vec::new();
    for one in tries {
        let attempt = attempt_ref(&one.attempt, "a run-tree attempt id did not parse")?;
        if let Some((status, parked)) = store.status_with_park_in_txn(txn, attempt)?
            && let Some(view) = held_view(attempt, &status, parked)
        {
            held.push(view);
        }
    }
    Ok(held)
}

/// Every try in the run's tree, in the order the queue made them: by
/// creation, then id.
fn tries_of(roots: &[RunTreeNode]) -> Vec<ProgramTryView> {
    let mut tries = Vec::new();
    let mut nodes: Vec<&RunTreeNode> = roots.iter().collect();
    while let Some(node) = nodes.pop() {
        tries.push(ProgramTryView {
            attempt: node.attempt_id.clone(),
            status: tree_status(node.status).to_owned(),
            result_ref: node.result_ref.clone(),
            created_at: node.timestamps.created_at,
            updated_at: node.timestamps.updated_at,
        });
        nodes.extend(&node.children);
    }
    tries.sort_by_cached_key(|one| (one.created_at, one.attempt.clone()));
    tries
}

const fn tree_status(status: RunTreeStatus) -> &'static str {
    match status {
        RunTreeStatus::Queued => "queued",
        RunTreeStatus::Running => "running",
        RunTreeStatus::Paused => "paused",
        RunTreeStatus::Completed => "completed",
        RunTreeStatus::Failed => "failed",
        RunTreeStatus::Cancelled => "cancelled",
        RunTreeStatus::Abandoned => "abandoned",
    }
}

fn run_view(run: TurnProgramRun) -> ProgramRunStateView {
    let (lifecycle, result_ref, settled_at) = match run.state {
        RunState::Entered => (ProgramRunLifecycle::Entered, None, None),
        RunState::Settled {
            result_ref,
            settled_at,
            ..
        } => (
            ProgramRunLifecycle::Settled,
            Some(result_ref),
            Some(settled_at),
        ),
    };
    ProgramRunStateView {
        entered_by: bytes_to_hex_lower(&run.attempt),
        entered_at: run.entered_at,
        lifecycle,
        result_ref,
        settled_at,
        frontier: run.frontier.map(|frontier| ProgramFrontierView {
            bridge_calls: frontier.bridge_calls,
            steps: frontier.steps,
            outputs: frontier.outputs,
            state_hash: bytes_to_hex_lower(&frontier.state_hash),
        }),
    }
}

fn step_view(step: EntityId, row: TurnProgramStep) -> ProgramStepView {
    let (state, result_digest, uncertain) = match row.state {
        StepState::Issued => (ProgramStepState::Issued, None, None),
        StepState::Settled { result_digest, .. } => (
            ProgramStepState::Settled,
            Some(bytes_to_hex_lower(&result_digest)),
            None,
        ),
        StepState::Uncertain { why } => (ProgramStepState::Uncertain, None, Some(why)),
    };
    ProgramStepView {
        step_ref: step.to_hex(),
        attempt: bytes_to_hex_lower(&row.attempt),
        issue: issue_view(&row.issued),
        state,
        result_digest,
        uncertain,
        at: row.at,
    }
}

fn issue_view(issue: &StepIssue) -> ProgramStepIssueView {
    match issue {
        StepIssue::Model {
            occurrence,
            request_hash,
        } => ProgramStepIssueView::Model {
            occurrence: *occurrence,
            request_hash: bytes_to_hex_lower(request_hash),
        },
        StepIssue::Write {
            step_start,
            ordinal,
            receipt,
            call_digest,
        } => ProgramStepIssueView::Write {
            step_start: *step_start,
            ordinal: *ordinal,
            receipt: receipt.to_hex(),
            call_digest: bytes_to_hex_lower(call_digest),
        },
        StepIssue::Outbound { intent, call_seq } => ProgramStepIssueView::Outbound {
            intent: bytes_to_hex_lower(intent),
            call_seq: *call_seq,
        },
    }
}

/// Of `ids`, the ones that read on the caller's own lane, each read listed
/// as a producer. An unknown or withheld row does not read; it never fails
/// the read.
fn readable_on_lane(
    memory: &Memory<'_>,
    ids: impl IntoIterator<Item = EntityId>,
) -> MemoryResult<BTreeSet<EntityId>> {
    let mut asked = BTreeSet::new();
    let mut readable = BTreeSet::new();
    for id in ids {
        if asked.insert(id) && memory.get_entity_tolerant(&id.to_hex())?.value.is_some() {
            readable.insert(id);
        }
    }
    Ok(readable)
}

fn page_limit(limit: Option<u32>) -> MemoryResult<usize> {
    let limit = match limit {
        Some(0) => return Err(MemoryError::bad_request("limit must be positive")),
        Some(limit) => limit.min(PAGE_LIMIT),
        None => PAGE_LIMIT,
    };
    Ok(usize::try_from(limit).unwrap_or(usize::MAX))
}

fn entity_ref(text: &str, refusal: &'static str) -> MemoryResult<EntityId> {
    EntityId::from_hex(text.trim()).map_err(|_| MemoryError::bad_request(refusal))
}

fn attempt_ref(text: &str, refusal: &'static str) -> MemoryResult<AttemptId> {
    let text = text.trim();
    let id = entity_ref(text.strip_prefix("job:").unwrap_or(text), refusal)?;
    Ok(AttemptId::from_bytes(id.as_bytes())?)
}

fn digest_ref(text: &str, refusal: &'static str) -> MemoryResult<[u8; 32]> {
    blake3::Hash::from_hex(text.trim())
        .map(|hash| *hash.as_bytes())
        .map_err(|_| MemoryError::bad_request(refusal))
}

fn attempt_hex(attempt: AttemptId) -> String {
    bytes_to_hex_lower(attempt.as_bytes())
}

fn class_name(class: u8) -> String {
    EdgeActorClass::try_from_u8(class)
        .map_or("unknown", EdgeActorClass::gate_actor_class)
        .to_owned()
}
