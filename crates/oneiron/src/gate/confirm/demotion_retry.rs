//! The expiry walk's backoff for a timeout demotion that keeps failing (FIX
//! 12079). A row whose demotion failed waits before the walk tries it again,
//! the wait doubling with each failure in a row up to a cap; a row that has
//! failed [`CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM`] times in a row
//! files one healer item. The walk always tries the row again once its wait
//! ends: nothing is dropped. In memory only: a reopened vault tries each row
//! at once, and its healer item is stored at most once, at its own id.

use rmpv::Value;

use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::diagnostic_record::{
    DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
    DiagnosticSourceKind, diagnostic_event_id, encode_diagnostic_event_body,
};
use crate::vault::Vault;

use super::CriticalWriteConfirmBinding;

use oneiron_store::critical_confirm_retry::ConfirmDemotionRetry;

/// The failures in a row after which a timeout demotion files its healer
/// item.
pub(crate) const CONFIRM_DEMOTION_FAILURES_BEFORE_HEALER_ITEM: u32 = 4;
/// The detector token of a failing timeout demotion's healer item.
const CONFIRM_DEMOTION_DETECTOR: &str = "gate.confirm_demotion.v1";

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
