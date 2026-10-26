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
//! call's next resume meets its hold again and asks then. A hold the Gate
//! named an approve-once digest for (FIX 6424 part 3) also names that digest:
//! the owner's press on it, at the consent door, releases exactly the call
//! as it was prepared. The answer to the ask still grants nothing. A newer
//! approvable ask's question withdraws the one it replaces once it is
//! queued, in the write that records it (FIX 6906 (c)).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::llm::decision::{
    AnswerContract, AskTo, DecisionClass, DecisionQuestion, DecisionRung, HumanAskReason,
    HumanDecisionRequest, ProviderPin,
};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::approval::ConnectorCallApproval;
use super::connector_call::{PENDING_CALLS, PendingConnectorCall};
use super::connector_call_pending::CONNECTOR_CALL_PENDING_TTL_MS;

/// The host-issued queue identity of a held connector call's ask.
const CONNECTOR_CALL_ASK_QUEUE: &str = "outbound.connector_call_held";
const CONNECTOR_CALL_ASK_QUEUE_VERSION: &str = "v1";

/// The version of the ask's question; bump it with its wording.
const CONNECTOR_CALL_ASK_VERSION: u32 = 1;

/// The version of the question that also names the approve-once digest to
/// press (FIX 6424 part 3): its wording adds that one sentence, and names the
/// call-ref door that presses it (FIX 990). A call's later approvable asks
/// put it again at the next versions.
const CONNECTOR_CALL_ASK_DIGEST_VERSION: u32 = 2;

/// The most characters of a connector or tool name the ask quotes.
const ASK_NAME_MAX_CHARS: usize = 120;

/// The most hold reasons the ask lists.
const ASK_MAX_REASONS: usize = 16;

/// The policy hook of CALLS "FIX 6906 superseded MCP owner question"
/// (Engine 10-21 06:3x): the question a newer approvable ask re-puts is
/// withdrawn in the write that records the new question's arrival number,
/// never before it queued. `false` is the earlier path, where the earlier
/// question stays open.
const SUPERSEDED_OWNER_ASK_WITHDRAWN: bool = true;

/// FIX 2551: a held call's owner questions are withdrawn in the write that
/// ends its wait on them, when it settles or meets its connector's questions,
/// and so is a question that queued just as the call stopped waiting.
/// Cleanup, never a cancellation: the call's outcome stands either way.
/// `false` is the earlier path, where those questions stay open.
const TERMINAL_CONNECTOR_OWNER_ASK_WITHDRAWN: bool = true;

/// The wording of a held call's owner ask: the one place it lives. It names
/// the connector, the tool, the call ref and the hold's reason codes, says
/// that answering grants nothing, and where the call is allowed instead,
/// with the approve-once digest the Gate's hold named when it named one.
fn connector_call_ask_text(
    call_ref: &EntityId,
    name: &str,
    tool: &str,
    reasons: &[String],
    approval_digest: Option<&str>,
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
    let press = approval_digest.map_or_else(String::new, |digest| {
        format!(
            " Or approve once, for exactly this call as it was prepared, by pressing approve-once \
             digest {digest} (vault.connectors.calls.approve_once, with this held call's \
             ref)."
        )
    });
    format!(
        "A connector call waits for you: tool \"{tool}\" on connector \"{name}\" (held call {call}) \
         is held because: {reasons}. Answering this ask allows nothing. To let it run, grant the \
         tool through the connector's consent for this held call, or approve the connector's key \
         or manifest.{press} A call nobody allows expires {days} days after it was first held. \
         Will you review it?",
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
    // FIX 6424 part 3: the call's current ask only; each new one is the
    // next version of the question.
    let approval = pending.approval.as_ref();
    let approval_digest = ConnectorCallApproval::current_digest(approval);
    HumanDecisionRequest {
        question: DecisionQuestion {
            // One question per held call: its own ref names it.
            id: *call_ref,
            version: match approval.filter(|_| approval_digest.is_some()) {
                Some(approval) => CONNECTOR_CALL_ASK_DIGEST_VERSION
                    .saturating_add(approval.revision.saturating_sub(1)),
                None => CONNECTOR_CALL_ASK_VERSION,
            },
            text: connector_call_ask_text(
                call_ref,
                &pending.name,
                &pending.tool,
                reasons,
                approval_digest,
            ),
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
        // A call whose connector asked for input was sent: no hold to ask
        // about (FIX 3837).
        if pending.settled.is_some() || pending.owner_ask_seq.is_some() || pending.input.is_some() {
            return Ok(None);
        }
        let Ok(principal) = EntityId::from_hex(&pending.principal_ref) else {
            return Ok(None);
        };
        let queued =
            self.queue_decision_ask(&connector_call_ask(call_ref, principal, &pending, reasons));
        let seq = queued.as_ref().ok().copied();
        let withdrawn = self.with_write_txn(|txn| {
            let row = PENDING_CALLS.get(&self.store, txn, call_ref)?;
            let Some(mut row) = row.filter(|row| row.settled.is_none() && row.input.is_none())
            else {
                // The call stopped waiting while its question queued: the
                // fresh question has no hold to ask about (FIX 2551).
                return Ok(
                    seq.and_then(|seq| self.withdraw_stranded_ask_in_txn(txn, call_ref, seq))
                );
            };
            if row.owner_ask_seq.is_some() {
                return Ok(None);
            }
            row.held_reasons = reasons.to_vec();
            row.owner_ask_seq = seq;
            let withdrawn = self.withdraw_superseded_ask_in_txn(txn, call_ref, &mut row, seq);
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            Ok(withdrawn)
        })?;
        // Its waiters wake once the withdrawal committed.
        if let Some(superseded) = withdrawn {
            self.signal_decision_answer(superseded);
        }
        Ok(Some(queued?))
    }

    /// FIX 6906 (c): in the write that records `seq`, the newly queued
    /// question of the held call `row`, withdraws the earlier question that
    /// a newer approvable ask replaced, and clears it from the row either
    /// way, so it is never retried. Returns it when the withdrawal closed
    /// it, for its waiters' signal once the write committed. A question that
    /// did not queue withdraws nothing and keeps it for the repair pass's
    /// later queue. A withdrawal that fails is logged and the write goes on
    /// as it would without it.
    fn withdraw_superseded_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        call_ref: &EntityId,
        row: &mut PendingConnectorCall,
        seq: Option<u64>,
    ) -> Option<u64> {
        if !SUPERSEDED_OWNER_ASK_WITHDRAWN {
            return None;
        }
        let new = seq?;
        let superseded = row.approval.as_mut()?.superseded_ask_seq.take()?;
        if superseded == new {
            return None;
        }
        match self.withdraw_decision_ask_in_txn(txn, superseded) {
            Ok(withdrawn) => withdrawn.then_some(superseded),
            Err(error) => {
                tracing::warn!(
                    reason = "connector_call_superseded_ask_not_withdrawn",
                    call = %call_ref.to_hex(),
                    ask = superseded,
                    error = %error,
                    "the owner question a newer approvable ask replaced was not withdrawn; the \
                     newer question is recorded as before"
                );
                None
            }
        }
    }

    /// In `txn`, the write that ends the held call `call_ref`'s wait (it
    /// settles, or meets its connector's questions), withdraws the owner
    /// questions `row` and the stored row still name, and clears them from
    /// `row`. Returns those it withdrew, for
    /// [`Self::signal_withdrawn_call_asks`] once the write committed. A
    /// withdrawal that fails is logged and the write goes on as it would
    /// without it, as a superseded question's does (FIX 2551).
    pub(super) fn withdraw_call_owner_asks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        call_ref: &EntityId,
        row: &mut PendingConnectorCall,
    ) -> Vec<u64> {
        if !TERMINAL_CONNECTOR_OWNER_ASK_WITHDRAWN {
            return Vec::new();
        }
        let mut seqs = take_owner_ask_seqs(row);
        if let Ok(Some(mut stored)) = PENDING_CALLS.get(&self.store, &*txn, call_ref) {
            seqs.extend(take_owner_ask_seqs(&mut stored));
        }
        seqs.sort_unstable();
        seqs.dedup();
        seqs.into_iter()
            .filter_map(|seq| self.withdraw_stranded_ask_in_txn(txn, call_ref, seq))
            .collect()
    }

    /// Withdraws the owner question `seq` of the call `call_ref`, which no
    /// longer waits on it; `Some(seq)` when the withdrawal closed it. A
    /// question already answered or withdrawn stays as it is.
    fn withdraw_stranded_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        call_ref: &EntityId,
        seq: u64,
    ) -> Option<u64> {
        if !TERMINAL_CONNECTOR_OWNER_ASK_WITHDRAWN {
            return None;
        }
        match self.withdraw_decision_ask_in_txn(txn, seq) {
            Ok(withdrawn) => withdrawn.then_some(seq),
            Err(error) => {
                tracing::warn!(
                    reason = "connector_call_owner_ask_not_withdrawn",
                    call = %call_ref.to_hex(),
                    ask = seq,
                    error = %error,
                    "the owner question of a call that stopped waiting on it was not \
                     withdrawn; the call's outcome is recorded as before"
                );
                None
            }
        }
    }

    /// Wakes the waiters of the owner questions a committed write withdrew.
    pub(super) fn signal_withdrawn_call_asks(&self, withdrawn: &[u64]) {
        for seq in withdrawn {
            self.signal_decision_answer(*seq);
        }
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

/// Takes the owner questions a call row names: its own and the one a newer
/// approvable ask superseded.
fn take_owner_ask_seqs(row: &mut PendingConnectorCall) -> Vec<u64> {
    let superseded = row
        .approval
        .as_mut()
        .and_then(|approval| approval.superseded_ask_seq.take());
    row.owner_ask_seq
        .take()
        .into_iter()
        .chain(superseded)
        .collect()
}
