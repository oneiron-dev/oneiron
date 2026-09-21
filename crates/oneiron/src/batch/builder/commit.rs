//! Commit terminal: validation short-circuit, preflight, apply, VAD postcommit.

use super::super::*;
use super::BatchBuilder;
use super::preflight::preflight_gate_decisions_in_txn;

use std::collections::HashMap;

use heed::RwTxn;

use crate::error::Result;
use crate::llm::BoundedAutoChecker;

impl BatchBuilder<'_> {
    /// Commits all queued operations atomically in a single LMDB write transaction.
    ///
    /// Gate decisions for local claim writes are appended by the same
    /// transaction, so a later validation failure cannot leave an orphan
    /// receipt behind.
    ///
    /// Approved bound Dreamer consents then run canonical VAD consolidation
    /// after commit. A population error is returned with the batch retained;
    /// retry [`Vault::consolidate_claim_vad`](crate::Vault::consolidate_claim_vad) on the approved member ids.
    ///
    /// Returns any validation error captured during builder calls before
    /// opening the LMDB write transaction, avoiding unnecessary I/O on bad
    /// input.
    pub fn commit(self) -> Result<()> {
        self.commit_inner(None, |_| Ok(()), |_| Ok(()))
    }

    /// Runs an app-door target guard in the same writer snapshot as admission.
    /// The guard runs before policy preflight and mutates nothing. Ordinary
    /// commit semantics, including retained denial receipts, stay unchanged.
    pub(crate) fn commit_with_target_guard(
        self,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(None, guard, |_| Ok(()))
    }

    /// Promotion's checker-aware terminal owns the transaction so a preflight
    /// refusal commits only its actual receipt through the ordinary batch path.
    /// The checker runs once, before any batch writes. Promotion's `after_apply`
    /// performs supersession and checks claim presence and Auto approval in the
    /// same transaction as the claim. Errors during batch apply or `after_apply`
    /// roll back those writes and their allow receipts. Full landed verification
    /// of predicate, source, and taint runs after commit; its failures cannot
    /// roll back the committed transaction.
    pub(crate) fn commit_with_checker_and_then(
        self,
        checker: &BoundedAutoChecker,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(Some(checker), |_| Ok(()), after_apply)
    }

    fn commit_inner(
        self,
        checker: Option<&BoundedAutoChecker>,
        target_guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        if let Some(err) = self.validation_error {
            return Err(err);
        }
        let text_index_trusted = if contains_text_op(&self.ops) {
            self.vault.ensure_text_index_trusted()?;
            true
        } else {
            self.vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire)
        };
        let mut wtxn = self.vault.store.env.write_txn()?;
        target_guard(&wtxn)?;
        let mut staged_gate_decisions = Vec::new();
        let mut preflight_gate_decision_ids = HashMap::new();
        if let Err(err) = preflight_gate_decisions_in_txn(
            &self.vault.store,
            &self.ops,
            &mut wtxn,
            &mut staged_gate_decisions,
            &mut preflight_gate_decision_ids,
            checker,
        ) {
            // A gate rejection is itself an intentional ledger event. Keep
            // that denial receipt, matching the historical gate semantics;
            // later phase-2 failures drop this transaction and its receipt.
            wtxn.commit()?;
            for decision in staged_gate_decisions {
                decision.record_metrics(&self.vault.store.diagnostics.gate);
            }
            return Err(err);
        }

        // Enforce the verdicts recorded by this same transaction, once per
        // operation receipt. Retain the records for post-commit metrics.
        let staged_claim_gate = staged_claim_gate_outcomes(&staged_gate_decisions);

        let pending_vad_ids =
            super::vad_postcommit::pending_dreamer_vad_approvals(self.vault, &wtxn, &self.ops)?;

        // ONE-1741: batch deletes no longer pre-scan for scan-verdict
        // relocation. The content-hash index row is maintained by
        // `deindex_entity` inside `apply_ops`, and verdicts anchor to the
        // content bytes rather than to any departing holder.
        apply_ops_with_gate_mode(
            &self.vault.store,
            &self.vault.config,
            &self.vault.analyzer,
            &mut wtxn,
            self.ops,
            text_index_trusted,
            ApplyOpsGateMode::new(false, true)
                .with_preflight_gate_decision_ids(preflight_gate_decision_ids)
                .with_staged_claim_gate(staged_claim_gate),
        )?;
        after_apply(&mut wtxn)?;
        let approved_vad_ids = self
            .vault
            .resolved_dreamer_vad_approvals_in_txn(&wtxn, pending_vad_ids)?;
        wtxn.commit()?;
        while self.vault.collect_lfs_garbage(32)? != 0 {}
        for decision in staged_gate_decisions {
            decision.record_metrics(&self.vault.store.diagnostics.gate);
        }
        // The canonical wrapper starts a separate write transaction. Never run
        // it during apply or preflight, and never turn a population error into
        // success merely because the approval is already durable.
        let now = crate::unix_seconds_now();
        for id in approved_vad_ids {
            self.vault.consolidate_claim_vad_now(&id, now)?;
        }
        Ok(())
    }
}
