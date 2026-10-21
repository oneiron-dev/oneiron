//! A turn program's fourth read (DOOR-141 PR3b): the resume checkpoint its
//! restarter reads, as the caller reads it. The same head and keyed pages
//! the restarter loads, the frontier the program's run record joined, each
//! settled call by its record row and request digest, the committed
//! injection position and the wait the last entry parked on, with whether
//! its reply is delivered. An injection is never inferred from an
//! acknowledgement: it is the position the entry committed. Nothing here
//! executes, resumes or leases, and no record is read whole. A reply an
//! erase of the program's actor took still reads as delivered, and is
//! withheld by name (FIX 5718). A wait a code consent binds carries its
//! consent evidence, read in the same snapshot (FIX 5883): refs and digests
//! of its binding, the owner's answer, the settlement and the run's
//! consumption, withheld by name alone when it does not read.

use crate::code_run::{
    CodeConsentWaitState, CodeConsentWaitView, ProgramResumeCall, ProgramResumeHead, WaitKey,
    WaitReply, program_resume_calls_in_txn, program_resume_head_in_txn, wait_reply_in_txn,
};
use crate::consent::CodeWaitReceiptLinks;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryError, MemoryResult};

use super::super::run::program_run_in_txn;
use super::views::{
    ProgramCheckpointCallView, ProgramCheckpointConsentView, ProgramCheckpointHeadView,
    ProgramCheckpointRequest, ProgramCheckpointView, ProgramCheckpointWaitView,
    ProgramFrontierView,
};
use super::{
    Caller, attempt_hex, attempt_ref, page_limit, program_for, readable_on_lane,
    withhold_definition,
};

/// The withheld field a checkpoint whose wait's reply an erase took names
/// (FIX 5718): the wait settled, and its reply is erased for this run.
const WAIT_REPLY_ERASED: &str = "checkpoint.wait.reply";

/// The withheld field a checkpoint whose wait's consent evidence did not
/// read, or does not read on the caller's lane, names (FIX 5883). The rest
/// of the checkpoint stands.
const WAIT_CONSENT_WITHHELD: &str = "checkpoint.wait.consent";

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
    let (calls, next_cursor, reply, consent) = match page {
        Some(page) => (page.calls, page.next_cursor, page.reply, page.consent),
        None => (Vec::new(), None, WaitReply::Pending, WaitConsent::Unbound),
    };
    let consent_rows = match &consent {
        WaitConsent::Bound { rows, .. } => rows.clone(),
        WaitConsent::Unbound | WaitConsent::Unread => Vec::new(),
    };
    let readable = readable_on_lane(
        memory,
        program
            .definition
            .as_ref()
            .map(|pin| pin.skill)
            .into_iter()
            .chain(consent_rows),
    )?;
    let mut withheld = Vec::new();
    let definition = withhold_definition(program.definition, &readable, &mut withheld);
    if reply == WaitReply::Erased {
        withheld.push(WAIT_REPLY_ERASED.to_owned());
    }
    let consent = match consent {
        WaitConsent::Unbound => None,
        WaitConsent::Bound { view, rows } if rows.iter().all(|row| readable.contains(row)) => {
            Some(*view)
        }
        WaitConsent::Bound { .. } | WaitConsent::Unread => {
            withheld.push(WAIT_CONSENT_WITHHELD.to_owned());
            None
        }
    };
    let delivered = reply != WaitReply::Pending;
    let code_run = program.code_run.to_hex();
    Ok(Some(ProgramCheckpointView {
        root: attempt_hex(program.root),
        actor: program.actor,
        checkpoint: head.map(|head| head_view(head, delivered, consent)),
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
/// whether the last entry answered it, and where its wait stands.
struct CheckpointPage {
    calls: Vec<(u64, ProgramResumeCall, bool)>,
    next_cursor: Option<String>,
    reply: WaitReply,
    consent: WaitConsent,
}

/// The consent evidence of the wait a checkpoint parked on, as its page's
/// snapshot holds it.
enum WaitConsent {
    /// No code consent wait binds it, or there is no wait.
    Unbound,
    /// The bound wait's evidence, and the records it names that must read
    /// on the caller's lane before it is shown: its ask and the owner's word.
    Bound {
        view: Box<ProgramCheckpointConsentView>,
        rows: Vec<EntityId>,
    },
    /// Its evidence did not read: withheld by name.
    Unread,
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
    let (reply, consent) = match head.wait {
        Some(wait) => {
            let key = WaitKey {
                run,
                wait_id: wait.wait_id,
                generation: wait.generation,
            };
            (
                wait_reply_in_txn(vault, txn, &key)?,
                wait_consent_in_txn(vault, txn, &key, wait.row),
            )
        }
        None => (WaitReply::Pending, WaitConsent::Unbound),
    };
    Ok(CheckpointPage {
        calls: (from..)
            .zip(listed)
            .map(|(index, call)| (index, call, index < head.injected))
            .collect(),
        next_cursor: (to < head.applied).then(|| to.to_string()),
        reply,
        consent,
    })
}

/// The consent evidence of the wait `key` the call at record row `row`
/// parked on, in `txn`. Evidence that does not read is logged and reads as
/// [`WaitConsent::Unread`]: it never fails the checkpoint read.
fn wait_consent_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    key: &WaitKey,
    row: u64,
) -> WaitConsent {
    match vault.code_consent_checkpoint_evidence_in_txn(txn, key, row) {
        Ok(None) => WaitConsent::Unbound,
        Ok(Some((wait, binding_digest))) => WaitConsent::Bound {
            rows: wait.ask.into_iter().chain(wait.word_ref).collect(),
            view: Box::new(consent_view(&wait, &binding_digest)),
        },
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                run = %key.run.to_hex(),
                wait = %key.wait_id.to_hex(),
                "a program checkpoint's consent evidence did not read; it is withheld"
            );
            WaitConsent::Unread
        }
    }
}

/// The wire view of a bound wait's evidence: refs and digests only.
fn consent_view(
    wait: &CodeConsentWaitView,
    binding_digest: &[u8; 32],
) -> ProgramCheckpointConsentView {
    let facts = |links: Option<&CodeWaitReceiptLinks>| {
        links.map(|links| bytes_to_hex_lower(&links.facts_digest))
    };
    ProgramCheckpointConsentView {
        binding_digest: bytes_to_hex_lower(binding_digest),
        effect_digest: bytes_to_hex_lower(&wait.effect_digest),
        state: wait_state_name(wait.state).to_owned(),
        ask: wait.ask.as_ref().map(EntityId::to_hex),
        choice: wait.answer.map(|choice| choice.as_str().to_owned()),
        word: wait.word_ref.as_ref().map(EntityId::to_hex),
        answer_receipt: wait.answer_receipt.clone(),
        outcome: wait.outcome.map(|outcome| outcome.as_str().to_owned()),
        settlement_receipt: wait.settlement_receipt.clone(),
        consumption_receipt: wait.consumption_receipt.clone(),
        settlement_facts_digest: facts(wait.settlement_links.as_ref()),
        consumption_facts_digest: facts(wait.consumption_links.as_ref()),
    }
}

const fn wait_state_name(state: CodeConsentWaitState) -> &'static str {
    match state {
        CodeConsentWaitState::Provisional => "provisional",
        CodeConsentWaitState::Waiting => "waiting",
        CodeConsentWaitState::Settling => "settling",
        CodeConsentWaitState::Settled => "settled",
        CodeConsentWaitState::Consumed => "consumed",
    }
}

fn head_view(
    head: ProgramResumeHead,
    delivered: bool,
    consent: Option<ProgramCheckpointConsentView>,
) -> ProgramCheckpointHeadView {
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
            consent,
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
