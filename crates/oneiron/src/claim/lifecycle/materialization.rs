//! Lifecycle Put materialization for the supersede and retract doors: the
//! checked deferred closure and the plain consent/Gate materialization.

use super::*;

impl Vault {
    /// Recheck the closing old head with the same bounded checker in the
    /// closure transaction. Its preflight receipt binds the exact old-row Put;
    /// phase-2 repeats the policy check without another checker consult.
    pub(super) fn apply_checked_deferred_closure_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
        binding: crate::batch::ClaimMaterialization,
        old_body: &ClaimBody,
        checker: &crate::llm::BoundedAutoChecker,
    ) -> Result<Option<crate::gate::RecordedClaimGateDecision>> {
        let BatchOp::Put { id, .. } = &ops[0] else {
            return Err(Error::InvariantViolation(
                "deferred closure has no old-head Put",
            ));
        };
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        let mut decision = None;
        crate::gate::check_claim_policy_for_write_with_record(
            &self.store,
            txn,
            id,
            crate::gate::ClaimGateWrite {
                body: old_body,
                envelope: Some(binding.envelope()),
                auto_checker: Some(checker),
                defer_metrics_until_commit: true,
            },
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
            &mut decision,
        )?;
        let ids = std::collections::HashMap::from([(
            *id,
            std::collections::VecDeque::from([decision
                .as_ref()
                .map(crate::gate::RecordedClaimGateDecision::decision_id)]),
        )]);
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            crate::batch::ApplyOpsGateMode::new(false, true)
                .with_claim_materializations(vec![binding])
                .with_preflight_gate_decision_ids(ids),
        )?;
        Ok(decision)
    }

    pub(super) fn apply_lifecycle_materialization(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
        binding: Option<crate::batch::ClaimMaterialization>,
        persist_pending: bool,
    ) -> Result<()> {
        if let Some(binding) = binding {
            crate::batch::apply_owner_bound_claim_puts(
                self,
                wtxn,
                ops,
                vec![binding],
                persist_pending,
            )
        } else {
            // Legacy/raw claims have no host-authored actor authority. Keep the
            // unattributed gate path; never infer authority from their evidence.
            apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                false,
                persist_pending,
            )
        }
    }
}
