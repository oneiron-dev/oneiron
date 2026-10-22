//! A connector call whose connector asked for input, kept on the call's own
//! row (ONE-2510, FIX 3837; canon ARCH-0028 "a consent-scale wait returns a
//! durable handle the caller polls, and the pending queue holds the truth").
//!
//! The send that met the questions was delivered, so its ledger intent is
//! Done; the logical call is not. Its row in the held-call table keeps the
//! round: the questions' handle, generation, how many there are and the
//! live lease, until the connector answers the call; then the row keeps the
//! delivery, receipt-only. Never the questions' text: foreign content stays
//! out of the canonical row, as a reply's bytes do (the caller's own reply,
//! or its wait, carried them). `connector.call_status` reads the row, so a
//! caller polls the round by the call's ref. The settler never resumes such
//! a row and the hold expiry never settles it: nothing re-sends it.
//!
//! The live exchange is the host's. Its lease ([`PendingConnectorInput::
//! live_until_ms`]) is how long a synchronous answer waits, never an expiry:
//! an answer after it still lands while the exchange lives. An exchange that
//! ends unanswered (a restart, a lost stream) leaves the questions standing
//! and their delivery uncertain; nothing refuses and nothing is re-sent.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::connector_call::{
    ACKNOWLEDGED_CALLS, AcknowledgedConnectorCall, ConnectorAwaitingInput, ConnectorCallOutcome,
    PENDING_CALLS, PendingConnectorCall, SettledConnectorCall,
};

/// The round of questions one call's connector asked, on the call's row:
/// ids and counts, never the questions' text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingConnectorInput {
    /// The live question set's handle, the one its caller answers by.
    pub(super) handle: String,
    /// The round the questions belong to, from 0.
    pub(super) generation: u64,
    /// How many questions the round asks.
    pub(super) asked: usize,
    /// The original send's ledger intent: Done, the send delivered.
    pub(super) intent: Option<[u8; 32]>,
    /// The end of the round's live lease (unix ms).
    pub(super) live_until_ms: u64,
    /// The live exchange ended unanswered: the questions stand, and their
    /// delivery is uncertain.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) uncertain: bool,
}

impl PendingConnectorInput {
    /// The first round of questions a send of the call met.
    pub(super) fn kept(intent: Option<[u8; 32]>, input: &ConnectorAwaitingInput) -> Self {
        Self {
            handle: input.handle.clone(),
            generation: 0,
            asked: input.questions.len(),
            intent,
            live_until_ms: input.live_until_ms,
            uncertain: false,
        }
    }

    /// The round as a reply carries it from the row: its handle and lease,
    /// with no questions, which the row never keeps.
    fn awaiting(&self) -> ConnectorAwaitingInput {
        ConnectorAwaitingInput {
            handle: self.handle.clone(),
            questions: Vec::new(),
            live_until_ms: self.live_until_ms,
        }
    }

    /// The status read's view of the round.
    pub(super) fn view(&self) -> ConnectorCallInput {
        ConnectorCallInput {
            handle: self.handle.clone(),
            generation: self.generation,
            asked: self.asked,
            live_until_ms: self.live_until_ms,
            uncertain: self.uncertain,
        }
    }
}

/// The round of questions a call waits on, as its status read shows it
/// (FIX 3837): its handle, generation, how many questions it asks, the end
/// of its live lease, and whether its live exchange ended unanswered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorCallInput {
    pub handle: String,
    pub generation: u64,
    pub asked: usize,
    pub live_until_ms: u64,
    pub uncertain: bool,
}

impl PendingConnectorCall {
    /// What a call whose connector asked for input stands at, from its row
    /// alone: its delivery once the connector answered, else its questions.
    /// `None` for a call that met no questions. Nothing is sent.
    pub(super) fn input_outcome(&self, call_ref: EntityId) -> Option<ConnectorCallOutcome> {
        let input = self.input.as_ref()?;
        Some(match &self.settled {
            Some(settled) => settled.outcome(),
            None => ConnectorCallOutcome::AwaitingInput {
                call_ref,
                intent: input.intent,
                input: input.awaiting(),
            },
        })
    }
}

impl Vault {
    /// Keeps round `generation` of the questions `handle` names, `asked` of
    /// them, on the call `call_ref`'s row; `true` when it kept it. A row
    /// whose round is another handle's, a later one, or answered keeps what
    /// it has.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn keep_connector_input_round(
        &self,
        call_ref: &EntityId,
        handle: &str,
        generation: u64,
        asked: usize,
        live_until_ms: u64,
    ) -> Result<bool, IntentLedgerError> {
        self.update_connector_input(call_ref, handle, |input, _| {
            if input.generation >= generation {
                return false;
            }
            input.generation = generation;
            input.asked = asked;
            input.live_until_ms = live_until_ms;
            input.uncertain = false;
            true
        })
    }

    /// Settles the call `call_ref` whose connector answered it after the
    /// questions `handle` names: its row keeps the delivery, receipt-only,
    /// beside the questions it met. `true` when it settled it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn settle_connector_input(
        &self,
        call_ref: &EntityId,
        handle: &str,
    ) -> Result<bool, IntentLedgerError> {
        self.update_connector_input(call_ref, handle, |input, settled| {
            *settled = Some(SettledConnectorCall::Delivered {
                intent: input.intent,
            });
            input.uncertain = false;
            true
        })
    }

    /// Settles the call `call_ref` whose questions `handle` names as
    /// refused for `reason`: the answer's re-send of the original call never
    /// went, because the call's grant no longer admits it (FIX 8226). `true`
    /// when it settled it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn refuse_connector_input(
        &self,
        call_ref: &EntityId,
        handle: &str,
        reason: &str,
    ) -> Result<bool, IntentLedgerError> {
        self.update_connector_input(call_ref, handle, |input, settled| {
            *settled = Some(SettledConnectorCall::Refused {
                decision_ref: None,
                reasons: vec![reason.to_owned()],
            });
            input.uncertain = false;
            true
        })
    }

    /// Marks the questions `handle` names on the call `call_ref` uncertain:
    /// their live exchange ended unanswered. `true` when it marked them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mark_connector_input_uncertain(
        &self,
        call_ref: &EntityId,
        handle: &str,
    ) -> Result<bool, IntentLedgerError> {
        self.update_connector_input(call_ref, handle, |input, _| {
            let marked = !input.uncertain;
            input.uncertain = true;
            marked
        })
    }

    /// Drops the row of the call `call_ref` whose connector asked for input
    /// once its settled status has been read (FIX 9158): who called it, its
    /// receipt-only outcome and the rows it picked stay on its acknowledged
    /// caller, which its status reads from then on. An unanswered round
    /// stays. `true` when it dropped the row.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn consume_settled_connector_input(
        &self,
        call_ref: &EntityId,
    ) -> Result<bool, IntentLedgerError> {
        Ok(self.with_write_txn(|txn| {
            let Some(row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(false);
            };
            if row.input.is_none() || row.settled.is_none() {
                return Ok(false);
            }
            let kept = AcknowledgedConnectorCall {
                principal_ref: row.principal_ref,
                name: row.name,
                tool: row.tool,
                settled: row.settled,
                source_rows: row.source_rows,
            };
            ACKNOWLEDGED_CALLS.put(&self.store, txn, call_ref, &kept)?;
            PENDING_CALLS.delete(&self.store, txn, call_ref)
        })?)
    }

    /// Marks every unanswered call's questions uncertain, and returns how
    /// many it marked: what a server starting with no live exchange calls
    /// before it serves, since none of their exchanges survived.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn mark_connector_inputs_uncertain(&self) -> Result<usize, IntentLedgerError> {
        let rows = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.scan(&self.store, &txn)?
        };
        let mut marked = 0;
        for (call_ref, row) in rows {
            let Some(input) = row.input.filter(|_| row.settled.is_none()) else {
                continue;
            };
            if self.mark_connector_input_uncertain(&call_ref, &input.handle)? {
                marked += 1;
            }
        }
        Ok(marked)
    }

    /// Applies `change` to the unanswered questions `handle` names on the
    /// call `call_ref`'s row, read again in the writer, and writes the row
    /// when it changed something. Anything else (no row, no questions,
    /// another handle's, an answered call) is left as it is.
    fn update_connector_input(
        &self,
        call_ref: &EntityId,
        handle: &str,
        change: impl FnOnce(&mut PendingConnectorInput, &mut Option<SettledConnectorCall>) -> bool,
    ) -> Result<bool, IntentLedgerError> {
        Ok(self.with_write_txn(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(false);
            };
            if row.settled.is_some() {
                return Ok(false);
            }
            let Some(input) = row.input.as_mut().filter(|input| input.handle == handle) else {
                return Ok(false);
            };
            if !change(input, &mut row.settled) {
                return Ok(false);
            }
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            Ok(true)
        })?)
    }
}
