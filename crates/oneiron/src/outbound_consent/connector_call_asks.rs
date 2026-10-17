//! The owner ask a held connector call queues (ONE-2510).
//!
//! A hold tells the owner once, through the decision-ask queue: which
//! connector and tool the call names and why it is held, never its
//! arguments or any credential. The ask carries the call ref as its
//! correlation. Answering it grants nothing: the owner still allows the call
//! through the connector consent door (naming the held call) or the key and
//! manifest doors, and the settler's next resume sends it. The ask is queued
//! after the hold commits, outside any write transaction; its arrival number
//! is kept on the call's row, so the call asks once. An ask that failed to
//! queue keeps the reasons on the row, and the settler's repair pass queues
//! it again. A crash between the hold and that write leaves neither, and the
//! call's next resume meets its hold again and asks then.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::connector_call::{PENDING_CALLS, PendingConnectorCall};
use super::connector_call_pending::CONNECTOR_CALL_PENDING_TTL_MS;

/// The host-issued queue identity of a held connector call's ask.
const CONNECTOR_CALL_ASK_QUEUE: &str = "outbound.connector_call_held";
const CONNECTOR_CALL_ASK_QUEUE_VERSION: &str = "v1";

/// The version of the ask's question; bump it with its wording.
const CONNECTOR_CALL_ASK_VERSION: u32 = 1;

/// The most characters of a connector or tool name the ask quotes.
const ASK_NAME_MAX_CHARS: usize = 120;

/// The most hold reasons the ask lists.
const ASK_MAX_REASONS: usize = 16;

/// The wording of a held call's owner ask: the one place it lives. It names
/// the connector, the tool, the call ref and the hold's reason codes, says
/// that answering grants nothing, and where the call is allowed instead.
fn connector_call_ask_text(
    call_ref: &EntityId,
    name: &str,
    tool: &str,
    reasons: &[String],
) -> String {
    let days = CONNECTOR_CALL_PENDING_TTL_MS / (24 * 60 * 60 * 1000);
    let reasons = if reasons.is_empty() {
        "no reason recorded".to_owned()
    } else {
        reasons
            .iter()
            .take(ASK_MAX_REASONS)
            .map(|reason| clip(reason.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "A connector call waits for you: tool \"{tool}\" on connector \"{name}\" (held call {call}) \
         is held because: {reasons}. Answering this ask allows nothing. To let it run, grant the \
         tool through the connector's consent for this held call, or approve the connector's key \
         or manifest. A call nobody allows expires {days} days after it was first held. Will you \
         review it?",
        tool = clip(tool),
        name = clip(name),
        call = call_ref.to_hex(),
    )
}

/// `text`, cut to [`ASK_NAME_MAX_CHARS`] characters.
fn clip(text: &str) -> String {
    text.chars().take(ASK_NAME_MAX_CHARS).collect()
}

/// The owner ask for the held call `call_ref`, by its original principal.
fn connector_call_ask(
    call_ref: &EntityId,
    principal: EntityId,
    pending: &PendingConnectorCall,
    reasons: &[String],
) -> HumanDecisionRequest {
    HumanDecisionRequest {
        question: DecisionQuestion {
            // One question per held call: its own ref names it.
            id: *call_ref,
            version: CONNECTOR_CALL_ASK_VERSION,
            text: connector_call_ask_text(call_ref, &pending.name, &pending.tool, reasons),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal,
        evidence: vec![*call_ref],
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: CONNECTOR_CALL_ASK_QUEUE.to_owned(),
            version: CONNECTOR_CALL_ASK_QUEUE_VERSION.to_owned(),
        },
        to: AskTo::owner(),
        correlation: Some(*call_ref),
    }
}

impl Vault {
    /// Queues the owner's ask about the held call `call_ref`, once, and
    /// returns its arrival number; `None` when the call is gone, settled,
    /// already asked about, or names no principal an ask can carry.
    /// `reasons` are the hold's reason codes. Never call it inside a write
    /// transaction: the ask queue opens its own.
    pub(super) fn queue_connector_call_owner_ask(
        &self,
        call_ref: &EntityId,
        reasons: &[String],
    ) -> Result<Option<u64>, IntentLedgerError> {
        let pending = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.get(&self.store, &txn, call_ref)?
        };
        let Some(pending) = pending else {
            return Ok(None);
        };
        if pending.settled.is_some() || pending.owner_ask_seq.is_some() {
            return Ok(None);
        }
        let Ok(principal) = EntityId::from_hex(&pending.principal_ref) else {
            return Ok(None);
        };
        let queued =
            self.queue_decision_ask(&connector_call_ask(call_ref, principal, &pending, reasons));
        let seq = queued.as_ref().ok().copied();
        self.with_write_txn(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(());
            };
            if row.settled.is_some() || row.owner_ask_seq.is_some() {
                return Ok(());
            }
            row.held_reasons = reasons.to_vec();
            row.owner_ask_seq = seq;
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)
        })?;
        Ok(Some(queued?))
    }

    /// Queues the owner ask of every held call whose ask was tried and did
    /// not queue, and returns how many it queued. A call none was tried for
    /// asks when its next resume meets the hold.
    pub fn repair_connector_call_owner_asks(&self) -> Result<usize, IntentLedgerError> {
        let rows = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.scan(&self.store, &txn)?
        };
        let mut queued = 0;
        for (call_ref, pending) in rows {
            if pending.settled.is_some()
                || pending.owner_ask_seq.is_some()
                || pending.held_reasons.is_empty()
            {
                continue;
            }
            if self
                .queue_connector_call_owner_ask(&call_ref, &pending.held_reasons)?
                .is_some()
            {
                queued += 1;
            }
        }
        Ok(queued)
    }
}
