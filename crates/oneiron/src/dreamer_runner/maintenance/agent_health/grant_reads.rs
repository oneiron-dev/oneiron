//! The agent health rows any granted agent reads (untangle 6.6c): the health
//! cards of a period, an agent's call receipts, and one attempt's failure
//! evidence. Each verb admits the vault's owner or a holder of a live
//! Steward grant naming `read`, checked at each call
//! ([`crate::federation::admit_substrate_read`]); the Coach holds it by
//! default. The rows are the ones the Coach's own review reads.

use serde::{Deserialize, Serialize};

use super::call_evidence::agent_calls;
use super::environment::{HealthCauseSource, attempt_sources};
use super::vocabulary::AgentHealthCard;
use crate::EntityId;
use crate::agent_dispatch::{AgentDispatcher, SpendScope};
use crate::federation::{SubstrateRead, admit_substrate_read};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, Memory, MemoryError, MemoryResult};
use crate::receipt::CallReceipt;

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

fn entity_ref(field: &str, hex: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(hex).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_BAD_REQUEST,
            &format!("{field} is not an entity id"),
            &["Pass the entity id as 32 hex characters."],
        )
    })
}

/// The health cards of `[from, to)` (`vault.agent_health.cards`).
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder; a store
/// failure.
pub fn agent_health_cards(
    memory: &Memory<'_>,
    input: &AgentHealthCardsRequest,
) -> MemoryResult<Vec<AgentHealthCard>> {
    admit_substrate_read(memory, "vault.agent_health.cards", SubstrateRead::Evidence)?;
    let mut cards = memory
        .vault()
        .agent_health_cards_between(input.from, input.to)
        .map_err(MemoryError::from)?;
    cards.truncate(limit(input.limit));
    Ok(cards)
}

/// One agent's call receipts since `since` (`vault.agent_health.calls`),
/// oldest first.
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder; an agent
/// ref that is not an entity id; a store failure.
pub fn agent_health_calls(
    memory: &Memory<'_>,
    input: &AgentHealthCallsRequest,
) -> MemoryResult<Vec<AgentCallReceipt>> {
    admit_substrate_read(memory, "vault.agent_health.calls", SubstrateRead::Evidence)?;
    let agent = entity_ref("agent_ref", &input.agent_ref)?;
    let (mut calls, _) = agent_calls(memory.vault(), input.since).map_err(MemoryError::from)?;
    let mut receipts: Vec<AgentCallReceipt> = calls
        .remove(&agent)
        .unwrap_or_default()
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

/// One attempt's failure evidence (`vault.diagnostics.evidence`).
///
/// # Errors
///
/// A caller who is neither the owner nor a Steward `read` holder; a run ref
/// that is not an entity id; a store failure.
pub fn diagnostic_evidence(
    memory: &Memory<'_>,
    input: &DiagnosticEvidenceRequest,
) -> MemoryResult<DiagnosticEvidence> {
    admit_substrate_read(
        memory,
        "vault.diagnostics.evidence",
        SubstrateRead::Evidence,
    )?;
    let run = input
        .run_ref
        .as_deref()
        .map(|hex| entity_ref("run_ref", hex))
        .transpose()?;
    let vault = memory.vault();
    let (causes, spend) = {
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
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
