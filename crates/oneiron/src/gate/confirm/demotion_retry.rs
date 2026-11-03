//! The expiry walk's backoff for a timeout demotion that keeps failing (FIX
//! 12079). A row whose demotion failed waits before the walk tries it again,
//! the wait doubling with each failure in a row up to a cap; a row that has
//! failed [`CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM`] times in a row
//! files one healer item. The walk always tries the row again once its wait
//! ends: nothing is dropped. In memory only: a reopened vault tries each row
//! at once, and its healer item is stored at most once, at its own id.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rmpv::Value;

use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::self_heal::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::vault::Vault;

use super::CriticalWriteConfirmBinding;

/// The wait after a timeout demotion's first failure; each further failure
/// in a row doubles it.
pub(crate) const CONFIRM_DEMOTION_RETRY_BASE_SECS: u64 = 120;
/// The longest wait between two tries of a failing timeout demotion.
pub(crate) const CONFIRM_DEMOTION_RETRY_CAP_SECS: u64 = 3_600;
/// The failures in a row after which a timeout demotion files its healer
/// item.
pub(crate) const CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM: u32 = 4;
/// The detector token of a failing timeout demotion's healer item.
const CONFIRM_DEMOTION_DETECTOR: &str = "gate.confirm_demotion.v1";

/// One failing row's retry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfirmDemotionRetry {
    /// Failures in a row.
    failures: u32,
    /// The walk tries the row again at or after this time.
    retry_at: u64,
    /// Whether the row's healer item is stored.
    filed: bool,
}

/// What one page of the walk learned of a row it tried, by its confirm id:
/// `None` once it demoted or had nothing to demote, else its retry state.
pub(super) type ConfirmDemotionOutcome = ([u8; 32], Option<ConfirmDemotionRetry>);

/// Each failing timeout demotion's retry state, by its confirm id, and the
/// confirms the running expiry walk has read still in the tray (FIX 12288).
#[derive(Debug, Default)]
pub(crate) struct ConfirmDemotionRetries {
    retries: Mutex<BTreeMap<[u8; 32], ConfirmDemotionRetry>>,
    seen: Mutex<BTreeSet<[u8; 32]>>,
}

impl ConfirmDemotionRetries {
    fn rows(&self) -> MutexGuard<'_, BTreeMap<[u8; 32], ConfirmDemotionRetry>> {
        self.retries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn walked(&self) -> MutexGuard<'_, BTreeSet<[u8; 32]>> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the walk tries the row `confirm` at `now`: one with no failure
    /// on record, or one whose wait has ended.
    pub(super) fn due(&self, confirm: &[u8; 32], now: u64) -> bool {
        self.rows()
            .get(confirm)
            .is_none_or(|retry| retry.retry_at <= now)
    }

    /// The row `confirm`'s retry state after one more failure at `now`.
    fn after_failure(&self, confirm: &[u8; 32], now: u64) -> ConfirmDemotionRetry {
        let prior = self.rows().get(confirm).copied();
        let failures = prior.map_or(0, |retry| retry.failures).saturating_add(1);
        ConfirmDemotionRetry {
            failures,
            retry_at: now.saturating_add(retry_wait(failures)),
            filed: prior.is_some_and(|retry| retry.filed),
        }
    }

    /// Keeps what a committed page learned: a row it settled leaves the map,
    /// a row that failed takes its new state. Every confirm the page read is
    /// noted as still in the tray; once the walk ends, every entry whose row
    /// left the tray another way (owner settle, replicated overwrite) is
    /// dropped (FIX 12288). Rows still in the tray keep their state.
    pub(super) fn record(
        &self,
        outcomes: Vec<ConfirmDemotionOutcome>,
        seen: Vec<[u8; 32]>,
        complete: bool,
    ) {
        let mut rows = self.rows();
        for (confirm, retry) in outcomes {
            match retry {
                Some(retry) => {
                    rows.insert(confirm, retry);
                }
                None => {
                    rows.remove(&confirm);
                }
            }
        }
        let mut walked = self.walked();
        walked.extend(seen);
        if complete {
            rows.retain(|confirm, _| walked.contains(confirm));
            walked.clear();
        }
    }
}

/// The wait after `failures` failures in a row: the base, doubled per
/// failure after the first, at most the cap.
fn retry_wait(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(u64::BITS - 1);
    CONFIRM_DEMOTION_RETRY_BASE_SECS
        .saturating_mul(1_u64 << doublings)
        .min(CONFIRM_DEMOTION_RETRY_CAP_SECS)
}

impl Vault {
    /// Records that the timeout demotion of `binding`'s row failed with
    /// `error` at `now`: a key-only WARN with the failures in a row and the
    /// retry time, and, once the row has failed
    /// [`CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM`] times in a row, its
    /// one healer item, in a savepoint of `wtxn`. Returns the row's new
    /// retry state, which the caller keeps once its page commits. Only a
    /// store failure fails.
    pub(super) fn confirm_demotion_failed_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        binding: &CriticalWriteConfirmBinding,
        error: &Error,
        now: u64,
    ) -> Result<ConfirmDemotionRetry> {
        let mut retry = self
            .confirm_demotion_retries
            .after_failure(&binding.confirm_id, now);
        tracing::warn!(
            claim = %binding.claim_id.to_hex(),
            kind = ?error.kind(),
            failures = retry.failures,
            retry_at = retry.retry_at,
            "a timeout demotion did not land: the expiry walk tries it again later"
        );
        if retry.filed || retry.failures < CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM {
            return Ok(retry);
        }
        let filed = self
            .store
            .env
            .nested_write_txn(wtxn)
            .map_err(Error::from)
            .and_then(|mut savepoint| {
                self.file_confirm_demotion_healer_item_in_txn(&mut savepoint, binding)?;
                savepoint.commit()?;
                Ok(())
            });
        match filed {
            Ok(()) => retry.filed = true,
            Err(error @ (Error::Storage(_) | Error::Io(_) | Error::MapFull)) => {
                return Err(error);
            }
            Err(error) => tracing::warn!(
                claim = %binding.claim_id.to_hex(),
                kind = ?error.kind(),
                "a failing timeout demotion's healer item did not store: its next failure files it"
            ),
        }
        Ok(retry)
    }

    /// Stores the healer item of the row `binding` whose timeout demotion
    /// keeps failing: a system self-report in the pending-consent class the
    /// tray's own findings use, addressed by the confirm, valid from the
    /// confirm's expiry and evidenced by its claim. Its body depends on the
    /// row alone, so its id does too: a row already filed stores nothing.
    fn file_confirm_demotion_healer_item_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        binding: &CriticalWriteConfirmBinding,
    ) -> Result<()> {
        let failures = u64::from(CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM);
        let event = DiagnosticEvent {
            detector_id: CONFIRM_DEMOTION_DETECTOR.to_owned(),
            event_class: DiagnosticEventClass::ConsentDenied,
            signal: None,
            actor_class: "system".to_owned(),
            actor_ref: None,
            source: DiagnosticSourceKind::SelfReport,
            criticality: DiagnosticCriticality::Critical,
            // The demotion should land with no failure; it failed this many
            // times in a row.
            expected: Value::from(0_u64),
            actual: Value::from(failures),
            delta: Value::from(failures),
            replay: DiagnosticReplayCoordinate {
                content_hash: binding.confirm_id,
                run_ref: Some(binding.claim_id.to_hex()),
                checkpoint_ref: None,
            },
            evidence_refs: vec![binding.claim_id],
            valid_from: binding.expires_at,
            valid_to: None,
        };
        let body = encode_diagnostic_event_body(&event)?;
        let id = diagnostic_event_id(CONFIRM_DEMOTION_DETECTOR, &body);
        if self.store.port_entity_raw(&*wtxn, &id)?.is_some() {
            return Ok(());
        }
        self.emit_diagnostic_event_in_txn(wtxn, &id, &event)
    }
}
