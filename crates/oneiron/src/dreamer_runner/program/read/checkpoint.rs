//! A turn program's fourth read (DOOR-141 PR3b): the resume checkpoint its
//! restarter reads, as the caller reads it. The same head and keyed pages
//! the restarter loads, the frontier the program's run record joined, each
//! settled call by its record row and request digest, the committed
//! injection position and the wait the last entry parked on, with whether
//! its reply is delivered. An injection is never inferred from an
//! acknowledgement: it is the position the entry committed. Nothing here
//! executes, resumes or leases, and no record is read whole.

use crate::code_run::{
    ProgramResumeCall, ProgramResumeHead, WaitKey, program_resume_calls_in_txn,
    program_resume_head_in_txn, wait_delivered_in_txn,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::super::run::program_run_in_txn;
use super::views::{
    ProgramCheckpointCallView, ProgramCheckpointHeadView, ProgramCheckpointRequest,
    ProgramCheckpointView, ProgramCheckpointWaitView, ProgramFrontierView,
};
use super::{
    Caller, attempt_hex, attempt_ref, page_limit, program_for, readable_on_lane,
    withhold_definition,
};

/// Reads the resume checkpoint of one program's run, one page of its settled
/// calls at a time: for the program's waking actor or the verified owner,
/// the pinned definition withheld unless its SKILL reads on the caller's own
/// lane. `None` when no program stamped the attempt, or the caller is
/// neither its waking actor nor the owner.
///
/// # Errors
///
/// A request that does not parse; the caller's read key refused; storage; a
/// checkpoint page that does not decode.
pub fn program_checkpoint(
    memory: &Memory<'_>,
    input: &ProgramCheckpointRequest,
) -> MemoryResult<Option<ProgramCheckpointView>> {
    let caller = Caller::of(memory)?;
    let asked = attempt_ref(&input.root, "root must be a 32-hex attempt id")?;
    let from = input
        .cursor
        .as_deref()
        .map(|text| {
            text.trim()
                .parse::<u64>()
                .map_err(|_| MemoryError::bad_request("cursor must be a call index"))
        })
        .transpose()?
        .unwrap_or(0);
    let limit = u64::try_from(page_limit(input.limit)?).unwrap_or(u64::MAX);
    let Some(program) = program_for(memory, &caller, asked)? else {
        return Ok(None);
    };
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let frontier = program_run_in_txn(vault, &txn, &program.code_run)?
        .filter(|run| run.admission == program.admission)
        .and_then(|run| run.frontier);
    let head = program_resume_head_in_txn(vault, &txn, program.code_run)?;
    let page = match &head {
        Some(head) => Some(page_in_txn(
            vault,
            &txn,
            program.code_run,
            head,
            from,
            limit,
        )?),
        None => None,
    };
    drop(txn);
    let readable = readable_on_lane(memory, program.definition.as_ref().map(|pin| pin.skill))?;
    let mut withheld = Vec::new();
    let definition = withhold_definition(program.definition, &readable, &mut withheld);
    let (calls, next_cursor, delivered) = page.map_or((Vec::new(), None, false), |page| {
        (page.calls, page.next_cursor, page.delivered)
    });
    let code_run = program.code_run.to_hex();
    Ok(Some(ProgramCheckpointView {
        root: attempt_hex(program.root),
        actor: program.actor,
        checkpoint: head.map(|head| head_view(head, delivered)),
        frontier: frontier.map(|frontier| ProgramFrontierView {
            bridge_calls: frontier.bridge_calls,
            steps: frontier.steps,
            outputs: frontier.outputs,
            state_hash: bytes_to_hex_lower(&frontier.state_hash),
        }),
        calls: calls
            .into_iter()
            .map(|(index, call, injected)| call_view(&code_run, index, call, injected))
            .collect(),
        code_run,
        definition,
        next_cursor,
        withheld,
    }))
}

/// One page of a checkpoint's settled calls, each with its index and
/// whether the last entry answered it, and whether its wait is delivered.
struct CheckpointPage {
    calls: Vec<(u64, ProgramResumeCall, bool)>,
    next_cursor: Option<String>,
    delivered: bool,
}

fn page_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    run: EntityId,
    head: &ProgramResumeHead,
    from: u64,
    limit: u64,
) -> Result<CheckpointPage> {
    let to = head.applied.min(from.saturating_add(limit));
    let from = from.min(to);
    let listed = program_resume_calls_in_txn(vault, txn, run, from, to)?;
    let delivered = match head.wait {
        Some(wait) => wait_delivered_in_txn(
            vault,
            txn,
            &WaitKey {
                run,
                wait_id: wait.wait_id,
                generation: wait.generation,
            },
        )?,
        None => false,
    };
    Ok(CheckpointPage {
        calls: (from..)
            .zip(listed)
            .map(|(index, call)| (index, call, index < head.injected))
            .collect(),
        next_cursor: (to < head.applied).then(|| to.to_string()),
        delivered,
    })
}

fn head_view(head: ProgramResumeHead, delivered: bool) -> ProgramCheckpointHeadView {
    ProgramCheckpointHeadView {
        committed_by: bytes_to_hex_lower(&head.attempt),
        content_hash: head.content_hash,
        contract_digest: bytes_to_hex_lower(&head.contract_digest),
        entries: head.entries,
        entry_start: head.entry_start,
        bridge_calls: head.bridge_calls,
        state_hash: bytes_to_hex_lower(&head.state_hash),
        applied: head.applied,
        injected: head.injected,
        wait: head.wait.map(|wait| ProgramCheckpointWaitView {
            row: wait.row,
            wait_id: wait.wait_id.to_hex(),
            generation: wait.generation,
            delivered,
        }),
        at: head.at,
    }
}

fn call_view(
    code_run: &str,
    index: u64,
    call: ProgramResumeCall,
    injected: bool,
) -> ProgramCheckpointCallView {
    ProgramCheckpointCallView {
        index,
        result_ref: format!("code-run:{code_run}#{}", call.row),
        row: call.row,
        request_digest: bytes_to_hex_lower(&call.request_digest),
        answered_by_wait: call.reply.as_ref().map(EntityId::to_hex),
        injected,
    }
}
