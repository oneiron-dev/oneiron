//! Authorized recovery sweep, report, and best-effort lease.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentRecoveryReport, IntentState, OutboundSendOutcome,
};

use super::authority::OutboundBindingAuthority;
use super::execution::ScopedResultTransport;
use super::result_scrub::OutboundResultSender;

const AUTHORIZED_RECOVERY_LEASE_KEY: &[u8] = b"outbound:authorized_recovery_lease:v1";

const AUTHORIZED_RECOVERY_LEASE_VALUE_LEN: usize = 24;

/// Recovery result plus final-boundary authorization/scrub counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRecoveryReport {
    pub ledger: IntentRecoveryReport,
    pub effectful_sends: usize,
    pub authorization_rejections: usize,
    pub scrubbable_result_fields: usize,
    pub scrubbed_result_fields: usize,
}

/// Failure surface for lease-protected authorized recovery.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizedRecoveryError {
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Ledger(#[from] IntentLedgerError),
    #[error("outbound recovery lease is already held")]
    LeaseHeld,
    #[error("outbound recovery lease duration must be nonzero")]
    InvalidLeaseDuration,
}

/// Recovers pending intents under a device-local best-effort sweep lease and
/// re-validates every persisted binding before transport. Exactly-once resend
/// authority comes from the ledger's durable row state and replay fence, not
/// this lease; `now_ms` is the engine's trusted clock.
pub fn recover_authorized_outbound_intents<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    sender: &mut S,
    now_ms: u64,
    lease_duration_ms: u64,
) -> std::result::Result<AuthorizedRecoveryReport, AuthorizedRecoveryError> {
    if lease_duration_ms == 0 {
        return Err(AuthorizedRecoveryError::InvalidLeaseDuration);
    }
    let token = AttemptId::now();
    let lease_until_ms = now_ms
        .checked_add(lease_duration_ms)
        .ok_or(AuthorizedRecoveryError::InvalidLeaseDuration)?;
    if !acquire_authorized_recovery_lease(vault, token, now_ms, lease_until_ms)? {
        return Err(AuthorizedRecoveryError::LeaseHeld);
    }

    let mut transport = ScopedResultTransport::new(sender);
    let recovered = (|| -> std::result::Result<_, AuthorizedRecoveryError> {
        let entries = crate::outbound_intent_ledger::intent_recovery_entries(vault)?;
        let mut report = IntentRecoveryReport {
            scanned: entries.len(),
            ..IntentRecoveryReport::default()
        };
        let mut authorization_rejections = 0_usize;
        for entry in entries {
            let record = match entry {
                crate::outbound_intent_ledger::IntentRecoveryEntry::Valid(record) => record,
                crate::outbound_intent_ledger::IntentRecoveryEntry::Corrupt(intent_id) => {
                    report
                        .escalations
                        .push(crate::outbound_intent_ledger::IntentEscalation {
                        intent_id,
                        reason:
                            crate::outbound_intent_ledger::IntentEscalationReason::CorruptLedgerRow,
                    });
                    continue;
                }
            };
            // This authorized sweep resumes every row it touches through the
            // scoped-MCP result transport. Connector-send rows carry no scoped
            // authorization binding and are driven forward (and replayed) by the
            // connector-task attempt queue instead; resuming one here would push
            // a connector payload through the MCP result sender. Skip them so the
            // scoped transport only ever sees scoped-authorized intents.
            if record.authorization_binding.is_none() {
                continue;
            }
            let original_state = record.state;
            let sends_before = transport.effectful_sends;
            let result = crate::outbound_chokepoint::execute_outbound_effect(
                vault,
                authority,
                crate::outbound_chokepoint::OutboundEffectCommand::Resume(record.id),
                now_ms,
                &mut transport,
            )?;
            let sent = transport.effectful_sends > sends_before;
            match original_state {
                IntentState::Done => report.skipped_done = report.skipped_done.saturating_add(1),
                IntentState::Abandoned => {
                    report.skipped_abandoned = report.skipped_abandoned.saturating_add(1);
                    if let Some(escalation) = result.dispatch.escalation {
                        report.escalations.push(escalation);
                    }
                }
                IntentState::Pending => {
                    if sent {
                        report.resent = report.resent.saturating_add(1);
                    }
                    match result.dispatch.state {
                        Some(IntentState::Done) => {
                            report.completed = report.completed.saturating_add(1);
                        }
                        Some(IntentState::Pending) => {
                            report.pending = report.pending.saturating_add(1);
                            if !sent && result.dispatch.send_outcome.is_none() {
                                authorization_rejections =
                                    authorization_rejections.saturating_add(1);
                            }
                            if let Some(OutboundSendOutcome::Failed(failure)) =
                                result.dispatch.send_outcome
                            {
                                report.failures.push(
                                    crate::outbound_intent_ledger::IntentRecoveryFailure {
                                        intent_id: record.id,
                                        failure,
                                    },
                                );
                            }
                        }
                        Some(IntentState::Abandoned) => {
                            authorization_rejections = authorization_rejections.saturating_add(1);
                            if let Some(escalation) = result.dispatch.escalation {
                                report.escalations.push(escalation);
                            }
                        }
                        None => {
                            return Err(IntentLedgerError::InvalidRecord(
                                "resume returned no durable state",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        Ok((report, authorization_rejections))
    })();
    let release = release_authorized_recovery_lease(vault, token);
    let (ledger, authorization_rejections) = recovered?;
    release?;
    Ok(AuthorizedRecoveryReport {
        ledger,
        effectful_sends: transport.effectful_sends,
        authorization_rejections,
        scrubbable_result_fields: transport.scrubbable_result_fields,
        scrubbed_result_fields: transport.scrubbed_result_fields,
    })
}

/// Best-effort de-duplication for concurrent recovery sweeps. Exactly-once
/// resend authority remains the ledger state and replay fence; `now_ms` is the
/// engine's trusted clock.
fn acquire_authorized_recovery_lease(
    vault: &Vault,
    token: AttemptId,
    now_ms: u64,
    lease_until_ms: u64,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        if let Some(raw) = vault
            .store
            .vault_meta
            .get(&*wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?
        {
            let raw: &[u8] = &raw;
            if raw.len() != AUTHORIZED_RECOVERY_LEASE_VALUE_LEN {
                return Err(Error::CorruptedIndex("outbound recovery lease row"));
            }
            let expires_at = u64::from_le_bytes(
                raw[16..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("outbound recovery lease row"))?,
            );
            if expires_at > now_ms {
                return Ok(false);
            }
        }
        let mut encoded = Vec::with_capacity(AUTHORIZED_RECOVERY_LEASE_VALUE_LEN);
        encoded.extend_from_slice(token.as_bytes());
        encoded.extend_from_slice(&lease_until_ms.to_le_bytes());
        vault
            .store
            .vault_meta
            .put(wtxn, AUTHORIZED_RECOVERY_LEASE_KEY, &encoded)?;
        Ok(true)
    })
}

/// Releases only this sweep's best-effort lease token. The lease is not an
/// exactly-once authority; durable ledger state and its replay fence are.
fn release_authorized_recovery_lease(vault: &Vault, token: AttemptId) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        let Some(raw) = vault
            .store
            .vault_meta
            .get(&*wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?
        else {
            return Ok(());
        };
        let raw: &[u8] = &raw;
        if raw.len() != AUTHORIZED_RECOVERY_LEASE_VALUE_LEN {
            return Err(Error::CorruptedIndex("outbound recovery lease row"));
        }
        if &raw[..16] == token.as_bytes() {
            vault
                .store
                .vault_meta
                .delete(wtxn, AUTHORIZED_RECOVERY_LEASE_KEY)?;
        }
        Ok(())
    })
}
