//! The pass that retries a held call's typed code consent ask when its
//! first ask did not open (#5367). Moved here from `connector_call_code`;
//! the connector settler calls it.

use crate::Vault;
use crate::code_run::read_code_consent_wait_in_txn;
use crate::error::Error;
use crate::outbound_intent_ledger::IntentLedgerError;

use super::super::connector_call::PENDING_CALLS;

impl Vault {
    /// Retries the typed code consent ask of every held call whose wait
    /// never got its question, and returns how many it asked (an attach to
    /// a question that landed between the read and the ask counts too).
    /// Record-keeping rows only: a sealed row (FIX 9159, the stored NoRecord
    /// signal) keeps its exact status quo of generic fallback, release and
    /// expiry, since a rebuilt surface would alter its hook and receipt
    /// retention. A failed retry warns and leaves the held-call ask
    /// standing in; it never refuses, withdraws, answers, sends, or resets
    /// the row's hold.
    pub fn repair_connector_code_consent_asks(&self) -> Result<usize, IntentLedgerError> {
        let rows = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.scan(&self.store, &txn)?
        };
        let mut asked = 0;
        for (call_ref, pending) in rows {
            let Some(wait_id) = pending.code_consent_wait else {
                continue;
            };
            if pending.settled.is_some()
                || pending.input_outcome(call_ref).is_some()
                || pending.sealed_arguments.is_some()
            {
                continue;
            }
            let row = {
                let txn = match self.store.env.read_txn().map_err(Error::from) {
                    Ok(txn) => txn,
                    Err(error) => {
                        tracing::warn!(
                            wait = %wait_id.to_hex(),
                            %error,
                            "code consent ask not retried; the wait was not read"
                        );
                        continue;
                    }
                };
                match read_code_consent_wait_in_txn(self, &txn, wait_id) {
                    Ok(row) => row,
                    Err(error) => {
                        tracing::warn!(
                            wait = %wait_id.to_hex(),
                            %error,
                            "code consent ask not retried; the wait was not read"
                        );
                        continue;
                    }
                }
            };
            let Some(row) = row else { continue };
            if row.ask.is_some()
                || row.settlement.is_some()
                || row.binding.pending.connector_call().is_none()
            {
                continue;
            }
            let class =
                match crate::edge::EdgeActorClass::try_from_u8(row.binding.original.actor_class) {
                    Some(class) => class,
                    None => {
                        tracing::warn!(
                            wait = %wait_id.to_hex(),
                            class = row.binding.original.actor_class,
                            "code consent ask not retried; the stored class byte names no class"
                        );
                        continue;
                    }
                };
            let memory = self.memory(row.binding.original.actor_ref, class);
            let retry = self
                .code_consent_question_text(wait_id)
                .map_err(oneiron_contracts::memory::MemoryError::from)
                .and_then(|text| memory.ask_code_consent(wait_id, &text));
            if let Err(error) = retry {
                tracing::warn!(
                    wait = %wait_id.to_hex(),
                    code = %error.code,
                    message = %error.message,
                    "code consent ask not retried; the held-call ask stands in"
                );
            } else {
                asked += 1;
            }
        }
        Ok(asked)
    }
}
