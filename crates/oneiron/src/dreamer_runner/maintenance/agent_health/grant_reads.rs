//! The agent health rows any granted agent reads (untangle 6.6c): the health
//! cards of a period, an agent's call receipts, and one attempt's failure
//! evidence. Each verb admits the vault's owner or a holder of a live
//! Steward grant naming `read`, checked at each call
//! ([`crate::federation::admit_scoped_substrate_read`]); the Coach holds it
//! by default. The rows are the ones the Coach's own review reads.
//!
//! A grant narrowed to some projects reads the rows that lie where the
//! attempts they name ran, inside its projects
//! ([`SubstrateReach::holds_attempts_in_txn`]; DEC-0005 #scope; FIX
//! [SUBSTRATE-READS-NO-SCOPE-FILTER]): a card by the attempts it names and
//! every row it cites, a call receipt by the attempt it held, and the
//! failure evidence by its attempt. A row whose attempt is unknown, a card
//! citing a row that names no attempt, and a card whose measure is held
//! against rows of other attempts read only for a grant across the whole
//! vault.

use serde::{Deserialize, Serialize};

use super::call_evidence::agent_calls;
use super::environment::{HealthCauseSource, attempt_sources};
use super::pipeline::replay_attempt;
use super::vocabulary::AgentHealthCard;
use crate::agent_dispatch::{AgentDispatcher, SpendScope};
use crate::attempt_queue::AttemptId;
use crate::federation::{
    SubstrateReach, SubstrateRead, admit_scoped_substrate_read, outside_reach,
};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};
use crate::receipt::CallReceipt;
use crate::store::diagnostic_record::{AgentHealthSignal, decode_diagnostic_event_body};
use crate::{EntityId, Result, Vault};

/// The most rows one read answers.
const READ_LIMIT: usize = 500;

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::grant_reads::{
    AgentHealthCallsRequest, AgentHealthCardsRequest, DiagnosticEvidenceRequest,
};

/// One call receipt and its row.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentCallReceipt {
    pub receipt_ref: String,
    pub call: CallReceipt,
}

/// One attempt's failure evidence: what its skills were attributed to, the
/// spend scope it ran under, and its completed checks' diagnostics.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiagnosticEvidence {
    /// The attribution causes its sealed pack receipt names.
    pub causes: Vec<HealthCauseSource>,
    /// The spend scope it ran under; none when unmetered.
    pub spend: Option<SpendScope>,
    /// Each completed check of the run, with its action digest and
    /// diagnostics.
    pub step_feedback: Vec<serde_json::Value>,
}

fn limit(asked: Option<usize>) -> usize {
    asked.unwrap_or(READ_LIMIT).min(READ_LIMIT)
}

fn read_txn(vault: &Vault) -> MemoryResult<heed::RoTxn<'_>> {
    vault
        .store
        .env
        .read_txn()
        .map_err(|error| MemoryError::from(crate::Error::from(error)))
}

/// The rows of `rows` that `inside` holds, in their order.
fn keep_inside<T>(
    rows: Vec<T>,
    mut inside: impl FnMut(&T) -> Result<bool>,
) -> MemoryResult<Vec<T>> {
    let mut kept = Vec::with_capacity(rows.len());
    for row in rows {
        if inside(&row).map_err(MemoryError::from)? {
            kept.push(row);
        }
    }
    Ok(kept)
}

/// The attempts `card`'s findings named, each read off its DIAGNOSTIC's
/// replay coordinate as the trend rollup joins them; None when a finding's
/// row is deleted or does not decode, or it named no attempt.
fn card_attempts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    card: &AgentHealthCard,
) -> Result<Option<Vec<AttemptId>>> {
    let mut attempts = Vec::with_capacity(card.diagnostics.len());
    for id in &card.diagnostics {
        let state = vault.store.port_deletion_state(txn, id)?;
        let event = match vault.store.port_entity_record(txn, id)? {
            Some(row) if !state.deleted && !state.stale => {
                decode_diagnostic_event_body(&row.body).ok()
            }
            _ => None,
        };
        let Some(attempt) = event
            .as_ref()
            .and_then(replay_attempt)
            .and_then(|attempt| AttemptId::from_bytes(attempt.as_bytes()).ok())
        else {
            return Ok(None);
        };
        attempts.push(attempt);
    }
    Ok(Some(attempts))
}

/// Whether a `signal` card's measure reads its own attempt's rows alone. A
/// cost spike is held against the p90 spend of every closed run of its task
/// type and unit, in any project; a silence against its actor's calls that
/// name no attempt. Either card says what lies outside its attempts.
const fn measured_on_its_own_rows(signal: AgentHealthSignal) -> bool {
    !matches!(
        signal,
        AgentHealthSignal::CostSpike | AgentHealthSignal::Silent
    )
}

/// Whether `card` lies inside the narrowed reach `reach`: its measure reads
/// its own attempts' rows alone, and each attempt its findings named and
/// every row it cites (its evidence, the attempts it witnessed, the one
/// holding a confession) is an attempt that ran in a project inside it. A
/// card that names no attempt at all, one whose finding's attempt is
/// unknown, and one citing a row that is no such attempt (another project's
/// duplicate run, a receipt, a task, a trap's anchor) do not.
fn card_inside_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    reach: &SubstrateReach,
    card: &AgentHealthCard,
) -> Result<bool> {
    if !measured_on_its_own_rows(card.signal) {
        return Ok(false);
    }
    let Some(mut attempts) = card_attempts_in_txn(vault, txn, card)? else {
        return Ok(false);
    };
    let cited = card
        .evidence
        .iter()
        .chain(&card.witnessed_attempts)
        .chain(card.attempt.as_ref())
        .chain(card.confession.as_ref());
    for row in cited {
        let Ok(attempt) = AttemptId::from_bytes(row.as_bytes()) else {
            return Ok(false);
        };
        attempts.push(attempt);
    }
    reach.holds_attempts_in_txn(vault, txn, &attempts)
}

/// The attempt `call` held, as its host witnessed it; None when it held no
/// single attempt, or its actor is erased.
fn call_attempt(call: &CallReceipt) -> Option<AttemptId> {
    let held = call.attempt_ref.as_ref()?;
    AttemptId::from_bytes(held.attempt.as_bytes()).ok()
}

fn entity_ref(field: &str, hex: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(hex).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            &format!("{field} is not an entity id"),
            &["Pass the entity id as 32 hex characters."],
        )
    })
}

/// The health cards of `[from, to)` (`vault.agent_health.cards`), as far
/// as the caller's grant reaches.
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder; a store
/// failure.
pub fn agent_health_cards(
    memory: &Memory<'_>,
    input: &AgentHealthCardsRequest,
) -> MemoryResult<Vec<AgentHealthCard>> {
    let reach =
        admit_scoped_substrate_read(memory, "vault.agent_health.cards", SubstrateRead::Evidence)?;
    let vault = memory.vault();
    let mut cards = vault
        .agent_health_cards_between(input.from, input.to)
        .map_err(MemoryError::from)?;
    if reach != SubstrateReach::WholeVault {
        let txn = read_txn(vault)?;
        cards = keep_inside(cards, |card| card_inside_in_txn(vault, &txn, &reach, card))?;
    }
    cards.truncate(limit(input.limit));
    Ok(cards)
}

/// One agent's call receipts since `since` (`vault.agent_health.calls`),
/// oldest first, as far as the caller's grant reaches.
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder; an agent
/// ref that is not an entity id; a store failure.
pub fn agent_health_calls(
    memory: &Memory<'_>,
    input: &AgentHealthCallsRequest,
) -> MemoryResult<Vec<AgentCallReceipt>> {
    let reach =
        admit_scoped_substrate_read(memory, "vault.agent_health.calls", SubstrateRead::Evidence)?;
    let agent = entity_ref("agent_ref", &input.agent_ref)?;
    let vault = memory.vault();
    let (mut calls, _) = agent_calls(vault, input.since).map_err(MemoryError::from)?;
    let mut calls = calls.remove(&agent).unwrap_or_default();
    if reach != SubstrateReach::WholeVault {
        let txn = read_txn(vault)?;
        calls = keep_inside(calls, |(_, call)| {
            reach.holds_attempts_in_txn(vault, &txn, call_attempt(call).as_slice())
        })?;
    }
    let mut receipts: Vec<AgentCallReceipt> = calls
        .into_iter()
        .map(|(id, call)| AgentCallReceipt {
            receipt_ref: id.to_hex(),
            call,
        })
        .collect();
    let keep = limit(input.limit);
    if receipts.len() > keep {
        receipts.drain(..receipts.len() - keep);
    }
    Ok(receipts)
}

/// One attempt's failure evidence (`vault.diagnostics.evidence`). A grant
/// narrowed to some projects reads it for an attempt that ran inside them,
/// with that attempt's own run's checks (a code run keyed by its id, as the
/// check review reads it); another run records no project.
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder, or reads
/// outside its reach; a run ref that is not an entity id; a store failure.
pub fn diagnostic_evidence(
    memory: &Memory<'_>,
    input: &DiagnosticEvidenceRequest,
) -> MemoryResult<DiagnosticEvidence> {
    const VERB: &str = "vault.diagnostics.evidence";
    let reach = admit_scoped_substrate_read(memory, VERB, SubstrateRead::Evidence)?;
    let run = input
        .run_ref
        .as_deref()
        .map(|hex| entity_ref("run_ref", hex))
        .transpose()?;
    let vault = memory.vault();
    let (causes, spend) = {
        let txn = read_txn(vault)?;
        if reach != SubstrateReach::WholeVault {
            let own_run = run.is_none_or(|run| run.as_bytes() == input.attempt.as_bytes());
            if !own_run
                || !reach
                    .holds_attempts_in_txn(vault, &txn, &[input.attempt])
                    .map_err(MemoryError::from)?
            {
                return Err(outside_reach(VERB));
            }
        }
        let causes = attempt_sources(vault, &txn, &input.attempt, input.generation)
            .map_err(MemoryError::from)?;
        let spend = AgentDispatcher::new(vault)
            .attempt_spend_scope_in_txn(&txn, input.attempt)
            .map_err(MemoryError::from)?;
        (causes, spend)
    };
    let mut step_feedback = Vec::new();
    if let Some(run) = run {
        for (key, row) in vault
            .type_diagnostics_rows(run)
            .map_err(MemoryError::from)?
        {
            step_feedback.extend(super::check_repeat::check_report(vault, key, &row));
        }
    }
    Ok(DiagnosticEvidence {
        causes,
        spend,
        step_feedback,
    })
}
