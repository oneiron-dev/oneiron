//! A live connector exchange's resume state, kept on its call's row beside
//! the round it waits on (FIX 9157, ruled by the Engine 07:49).
//!
//! The host keeps, each round, what a restart needs to take the exchange up
//! again: for 2026-07-28 the protocol Retry's request state, the round's key
//! aliases and the next request id; for 2025-06-18 and 2025-11-25 the
//! session, the reply stream's last event id, the outstanding request's id
//! and the aliases. A connector may put the presented secret in any of
//! them, so the state goes sealed under the call's own custody, at the
//! round's custody generation (from 1: 0 is an off-record caller's
//! arguments), is opened only by this vault, and is retired with the
//! PENDING_CALLS row. The row keeps the protocol, the generation and the
//! sealed bytes, never the state. A round whose state cannot be opened
//! stands uncertain, as before. An exchange that ended leaves no state: its
//! round has nothing to take up again.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentLedgerError, read_intent_for_attempt_in_txn,
};
use crate::secret_custody::{open_connector_resume_in_txn, seal_connector_resume_in_txn};
use crate::secret_lease::SecretGrantRef;

use super::connector_call::PENDING_CALLS;

/// How a live exchange is taken up again after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorResumeProtocol {
    /// 2026-07-28: the protocol Retry, re-sent from its request state once
    /// the round is answered.
    Retry,
    /// 2025-06-18 and 2025-11-25: the reply stream, reattached after its
    /// last event id.
    Stream,
}

/// A round's sealed resume state, as the call's row keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectorInputResume {
    protocol: ConnectorResumeProtocol,
    /// The custody generation the state is sealed at: the round's, plus 1.
    generation: u32,
    sealed: Vec<u8>,
}

/// One unanswered round's resume state, opened by the vault: what a server
/// starting takes the exchange up again from.
pub struct OpenedConnectorResume {
    pub call_ref: EntityId,
    /// The live question set's handle.
    pub handle: String,
    /// The round, from 0.
    pub generation: u64,
    pub protocol: ConnectorResumeProtocol,
    /// The state the host kept, in zeroizing storage.
    pub state: Zeroizing<Vec<u8>>,
    /// The custody record the call presents in place of the route's own
    /// secret, as its row keeps it: the door presents it again.
    pub credential: Option<EntityId>,
    /// The secret grant the call redeems at each send, as its row keeps it.
    pub grant: Option<SecretGrantRef>,
    /// The original send as the ledger keeps it, for a Retry: what each
    /// answer re-sends, its grant checked again first (FIX 8226). `None`
    /// for a stream, or when the ledger does not read it.
    pub original: Option<FrozenOutboundCall>,
}

/// The custody generation round `round`'s state is sealed at.
fn custody_generation(round: u64) -> Option<u32> {
    u32::try_from(round.checked_add(1)?).ok()
}

impl Vault {
    /// Keeps `state`, sealed inside this writer, as the resume state of
    /// round `generation` of the questions `handle` names on the call
    /// `call_ref`'s row, replacing any earlier round's; `true` when it kept
    /// it. A row whose round is another handle's, another round, or
    /// answered keeps what it has.
    ///
    /// # Errors
    ///
    /// Storage and custody errors.
    pub fn keep_connector_input_resume(
        &self,
        call_ref: &EntityId,
        handle: &str,
        generation: u64,
        protocol: ConnectorResumeProtocol,
        state: &[u8],
    ) -> Result<bool, IntentLedgerError> {
        let Some(sealed_at) = custody_generation(generation) else {
            return Ok(false);
        };
        Ok(self.with_write_txn(|txn| {
            let Some(mut row) = PENDING_CALLS.get(&self.store, txn, call_ref)? else {
                return Ok(false);
            };
            if row.settled.is_some() {
                return Ok(false);
            }
            // An uncertain round's exchange ended, or did not survive a
            // restart: there is nothing live to keep a state for.
            let Some(input) = row.input.as_mut().filter(|input| {
                input.handle == handle && input.generation == generation && !input.uncertain
            }) else {
                return Ok(false);
            };
            let sealed =
                seal_connector_resume_in_txn(&self.store, txn, call_ref, sealed_at, state)?;
            input.resume = Some(ConnectorInputResume {
                protocol,
                generation: sealed_at,
                sealed,
            });
            PENDING_CALLS.put(&self.store, txn, call_ref, &row)?;
            Ok(true)
        })?)
    }

    /// The resume state of every unanswered round standing uncertain with
    /// one, opened (FIX 9157): what a server starting takes up again. Only
    /// the rounds `wanted` names by call and handle are opened. A state that
    /// cannot be opened is left out and logged; its round stays uncertain.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn open_connector_input_resumes(
        &self,
        wanted: impl Fn(&EntityId, &str) -> bool,
    ) -> Result<Vec<OpenedConnectorResume>, IntentLedgerError> {
        let rows = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.scan(&self.store, &txn)?
        };
        let snapshot = self.store.custody_snapshot()?;
        let mut opened = Vec::new();
        for (call_ref, row) in rows {
            let Some(input) = row
                .input
                .filter(|input| row.settled.is_none() && input.uncertain)
            else {
                continue;
            };
            let Some(resume) = input.resume.filter(|_| wanted(&call_ref, &input.handle)) else {
                continue;
            };
            let state = match open_connector_resume_in_txn(
                &self.store,
                &snapshot,
                &call_ref,
                resume.generation,
                &resume.sealed,
            ) {
                Ok(state) => state,
                Err(error) => {
                    tracing::warn!(%error, "connector call resume state not opened");
                    continue;
                }
            };
            let original = match resume.protocol {
                ConnectorResumeProtocol::Retry => {
                    self.connector_input_original(row.attempt_id, row.call_seq, input.intent)
                }
                ConnectorResumeProtocol::Stream => None,
            };
            opened.push(OpenedConnectorResume {
                call_ref,
                handle: input.handle,
                generation: input.generation,
                protocol: resume.protocol,
                state,
                credential: row.credential,
                grant: row.grant,
                original,
            });
        }
        Ok(opened)
    }

    /// The original send of a call whose connector asked for input, as the
    /// ledger keeps it under the call's attempt: the Done intent `intent`
    /// its row names. `None`, logged when the read failed, otherwise.
    fn connector_input_original(
        &self,
        attempt_id: AttemptId,
        call_seq: u64,
        intent: Option<[u8; 32]>,
    ) -> Option<FrozenOutboundCall> {
        let record = self
            .store
            .env
            .read_txn()
            .map_err(|error| IntentLedgerError::from(Error::from(error)))
            .and_then(|txn| read_intent_for_attempt_in_txn(self, &txn, attempt_id, call_seq));
        match record {
            Ok(record) => record
                .map(|record| FrozenOutboundCall::from_record(&record))
                .filter(|original| original.intent_id() == intent.as_ref()),
            Err(error) => {
                tracing::warn!(%error, "connector call original send not read");
                None
            }
        }
    }

    /// Takes the questions `handle` names on the call `call_ref` out of
    /// uncertain: their exchange was taken up again after a restart
    /// (FIX 9157). `true` when it changed them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn resume_connector_input(
        &self,
        call_ref: &EntityId,
        handle: &str,
    ) -> Result<bool, IntentLedgerError> {
        self.update_connector_input(call_ref, handle, |input, _| {
            let changed = input.uncertain;
            input.uncertain = false;
            changed
        })
    }
}
