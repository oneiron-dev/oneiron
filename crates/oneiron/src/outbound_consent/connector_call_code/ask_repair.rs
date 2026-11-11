//! The pass that retries a held call's typed code consent ask when its
//! first ask did not open (#5367). Moved here from `connector_call_code`;
//! the connector settler calls it.
//!
//! FIX 4520: a sealed (NoRecord) call keeps no caller context on disk. Its
//! caller's live session binding is captured before the first ask can
//! fail, and its session keeps it in RAM when that ask fails.

use crate::Vault;
use crate::code_run::read_code_consent_wait_in_txn;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, Memory, MemoryResult, SessionWitnessBinding, SessionWitnessContext,
};
use crate::outbound_intent_ledger::IntentLedgerError;

use super::super::connector_call::PENDING_CALLS;

/// The live session binding of a sealed held call's caller, captured from
/// the caller's own surface before its first ask can fail (FIX 4520).
/// `None` when the surface binds no session that keeps no record. It opens
/// nothing and stores nothing.
pub(super) fn capture_caller_binding(
    memory: &Memory<'_>,
) -> MemoryResult<Option<SessionWitnessBinding>> {
    let binding = memory
        .session_witness_context()?
        .map(SessionWitnessContext::into_binding)
        .transpose()?;
    Ok(binding.filter(SessionWitnessBinding::keeps_no_record))
}

impl Vault {
    /// Keeps a sealed held call's captured caller binding in its session's
    /// RAM after the call's first ask did not open (FIX 4520). A binding
    /// that was not captured or is not kept leaves the generic fallback, as
    /// before.
    pub(super) fn retain_code_consent_caller(
        &self,
        captured: MemoryResult<Option<SessionWitnessBinding>>,
        wait_id: EntityId,
        call_ref: EntityId,
    ) {
        let kept = captured.and_then(|binding| match binding {
            Some(binding) => binding.retain_for_code_consent_ask(self, wait_id, call_ref),
            None => Ok(()),
        });
        if let Err(error) = kept {
            tracing::warn!(
                wait = %wait_id.to_hex(),
                code = %error.code,
                message = %error.message,
                "code consent caller binding not kept; the held-call ask stands in"
            );
        }
    }

    /// Retries the typed code consent ask of every held call whose wait
    /// never got its question, and returns how many it asked (an attach to
    /// a question that landed between the read and the ask counts too).
    /// A record-keeping row asks again as its stored actor and class. A
    /// sealed row (FIX 9159, the stored NoRecord signal) asks again only
    /// through the live caller binding its session kept (FIX 4520), never
    /// through a rebuilt surface, which would alter its hook and receipt
    /// retention. With no kept binding it keeps its generic fallback,
    /// release and expiry. A failed retry warns and leaves the held-call
    /// ask standing in; it never refuses, withdraws, answers, sends, or
    /// resets the row's hold.
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
        Ok(asked + self.repair_kept_code_consent_asks())
    }

    /// Retries the typed ask of every sealed held call whose session kept
    /// its caller's live binding (FIX 4520), and returns how many it asked.
    /// The kept binding goes once the ask is attached, once the call or its
    /// wait is terminal, or once the caller no longer holds; the session's
    /// close drops the rest. A failed retry warns, keeps the binding for
    /// the next pass and leaves the held-call ask standing in.
    fn repair_kept_code_consent_asks(&self) -> usize {
        let kept = match self.store.off_record_sessions.retained_code_consent_asks() {
            Ok(kept) => kept,
            Err(error) => {
                tracing::warn!(%error, "kept code consent caller bindings not read");
                return 0;
            }
        };
        let mut asked = 0;
        for ask in kept {
            let wait_id = ask.wait_id;
            match self.code_consent_ask_owed(wait_id, &ask.call_ref) {
                Ok(true) => {}
                Ok(false) => {
                    self.release_code_consent_caller(wait_id);
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        wait = %wait_id.to_hex(),
                        %error,
                        "code consent ask not retried; the wait was not read"
                    );
                    continue;
                }
            }
            // The caller's proof, its session instance and the captured
            // route, as the binding checks them before each use.
            if let Err(error) = ask.binding.revalidate(self) {
                tracing::warn!(
                    wait = %wait_id.to_hex(),
                    code = %error.code,
                    message = %error.message,
                    "code consent ask not retried; the caller binding does not hold"
                );
                if error.code == MEMORY_CODE_FORBIDDEN {
                    self.release_code_consent_caller(wait_id);
                }
                continue;
            }
            let retry = self
                .code_consent_question_text(wait_id)
                .map_err(oneiron_contracts::memory::MemoryError::from)
                .and_then(|text| ask.binding.retry_code_consent_ask(self, wait_id, &text));
            match retry {
                Ok(_) => {
                    asked += 1;
                    self.release_code_consent_caller(wait_id);
                }
                Err(error) => {
                    tracing::warn!(
                        wait = %wait_id.to_hex(),
                        code = %error.code,
                        message = %error.message,
                        "code consent ask not retried; the held-call ask stands in"
                    );
                }
            }
        }
        asked
    }

    /// Whether the held call `call_ref` still owes wait `wait_id` its typed
    /// ask (FIX 4520): the row is there, still bound to that wait, and not
    /// terminal, and the wait has no ask and no settlement.
    fn code_consent_ask_owed(
        &self,
        wait_id: EntityId,
        call_ref: &EntityId,
    ) -> Result<bool, IntentLedgerError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        let Some(pending) = PENDING_CALLS.get(&self.store, &txn, call_ref)? else {
            return Ok(false);
        };
        if pending.code_consent_wait != Some(wait_id)
            || pending.settled.is_some()
            || pending.input_outcome(*call_ref).is_some()
        {
            return Ok(false);
        }
        Ok(
            read_code_consent_wait_in_txn(self, &txn, wait_id)?.is_some_and(|row| {
                row.ask.is_none()
                    && row.settlement.is_none()
                    && row.binding.pending.connector_call().is_some()
            }),
        )
    }

    /// Drops the caller binding a session kept for wait `wait_id` (FIX
    /// 4520). Only the repair pass and session close drop one.
    fn release_code_consent_caller(&self, wait_id: EntityId) {
        if let Err(error) = self
            .store
            .off_record_sessions
            .release_code_consent_ask(wait_id)
        {
            tracing::warn!(
                wait = %wait_id.to_hex(),
                %error,
                "kept code consent caller binding not dropped"
            );
        }
    }
}
