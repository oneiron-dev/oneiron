//! Committing terminal: builder-time checks, index preparation, its share of
//! the group commit, preflight, apply, commit, VAD postcommit.

use super::super::*;
use super::preflight::preflight_gate_decisions_in_txn;
use super::{BatchBuilder, CommitCheck};

use crate::store::Rows;

use std::collections::HashMap;

use heed::RwTxn;

use crate::error::Result;
use crate::llm::BoundedAutoChecker;

impl BatchBuilder<'_> {
    /// Commits all queued operations atomically in a single LMDB write transaction.
    ///
    /// The transaction is this batch's share of the vault's group commit
    /// (OF-536): concurrent writes commit together with one fsync, and this
    /// returns once the shared commit is durable. BM25 analysis and the first
    /// fresh vector's HNSW neighbour search run before the transaction opens.
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

    /// [`Self::commit`] for a writer below owner grade. A put that turns an
    /// agent definition back on, moves its approval up, makes it active again
    /// or brings a deleted one back on is the owner's
    /// ([`Vault::update_agent_definition_as`](crate::Vault::update_agent_definition_as)),
    /// so it is refused, judged in the transaction the batch writes in. Every
    /// other put commits as it does through [`Self::commit`], turning a
    /// definition off included.
    ///
    /// # Errors
    ///
    /// [`GateError::ConsentOwnerNotAuthenticated`](crate::error::GateError::ConsentOwnerNotAuthenticated)
    /// for such a put; otherwise as [`Self::commit`].
    pub fn commit_below_owner(self) -> Result<()> {
        let vault = self.vault;
        let agent_puts: Vec<(crate::entity_id::EntityId, Vec<u8>)> = self
            .ops
            .iter()
            .filter_map(|op| match op {
                BatchOp::Put {
                    id,
                    entity_type,
                    data,
                    ..
                } if *entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF => {
                    Some((*id, data.clone()))
                }
                _ => None,
            })
            .collect();
        self.commit_with_target_guard(move |txn| {
            for (id, body) in &agent_puts {
                if crate::agent_def::agent_definition_put_widens_in_txn(
                    &vault.store,
                    txn,
                    id,
                    body,
                )? {
                    return Err(crate::error::Error::Gate(
                        crate::error::GateError::ConsentOwnerNotAuthenticated(
                            "only the vault owner turns an agent definition back on",
                        ),
                    ));
                }
            }
            Ok(())
        })
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
    /// roll back the committed transaction. `before_apply` reads the writer
    /// snapshot first, in the same transaction, before policy preflight; it
    /// mutates nothing.
    pub(crate) fn commit_with_checker_guard_and_then(
        self,
        checker: &BoundedAutoChecker,
        before_apply: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(Some(checker), before_apply, after_apply)
    }

    /// [`Self::commit_with_checker_guard_and_then`] with nothing read first.
    #[cfg(test)]
    pub(crate) fn commit_with_checker_and_then(
        self,
        checker: &BoundedAutoChecker,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(Some(checker), |_| Ok(()), after_apply)
    }

    fn commit_inner(
        mut self,
        checker: Option<&BoundedAutoChecker>,
        target_guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        let vault = self.vault;
        // The group holds its transaction open for this write while it does
        // its checks and index preparation below.
        let announced = vault.store.group_commit.announce();
        CommitCheck::run_all(&self.commit_checks, vault, &self.ops)?;
        if let Some(err) = self.validation_error.take() {
            return Err(err);
        }
        let text_index_trusted = if contains_text_op(&self.ops) {
            vault.ensure_text_index_trusted()?;
            true
        } else {
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire)
        };
        // BM25 analysis and the HNSW neighbour search run here, before the
        // transaction, so the shared critical section only writes.
        let prepared = PreparedIndexWork::for_ops(vault, &self.ops);
        #[cfg(feature = "sync")]
        let mut ops = std::mem::take(&mut self.ops);
        #[cfg(not(feature = "sync"))]
        let ops = std::mem::take(&mut self.ops);
        let (origin, birth_mask) = (self.origin, self.birth_mask);
        let text_births = std::mem::take(&mut self.text_births);
        let births = std::mem::take(&mut self.births);
        #[cfg(feature = "sync")]
        let federated_puts = std::mem::take(&mut self.federated_puts);
        let stale_sweep = crate::federation::StaleSweepWatch::begin(vault);
        let committed = vault.store.group_write(Some(announced), |wtxn| {
            if let Err(err) = target_guard(wtxn) {
                return Rows::Discard(Err(err.into()));
            }
            #[cfg(feature = "sync")]
            if let Err(err) =
                super::apply::admit_federated_puts(vault, wtxn, &mut ops, &federated_puts)
            {
                return Rows::Discard(Err(err.into()));
            }
            let mut staged_gate_decisions = Vec::new();
            let mut preflight_gate_decision_ids = HashMap::new();
            if let Err(err) = preflight_gate_decisions_in_txn(
                &vault.store,
                &ops,
                wtxn,
                &mut staged_gate_decisions,
                &mut preflight_gate_decision_ids,
                checker,
                origin,
            ) {
                // A gate rejection is itself an intentional ledger event. Keep
                // that denial receipt, matching the historical gate semantics;
                // later phase-2 failures drop this transaction and its receipt.
                return match crate::ports::recorded_at_in_txn(&vault.store, wtxn) {
                    Ok(_) => Rows::Refuse(Refused {
                        err,
                        staged_gate_decisions,
                    }),
                    Err(err) => Rows::Discard(Err(err.into())),
                };
            }
            let applied = apply_admitted(
                vault,
                wtxn,
                AdmittedBatch {
                    ops,
                    text_index_trusted,
                    gate_mode: ApplyOpsGateMode::new(false, true)
                        .with_preflight_gate_decision_ids(preflight_gate_decision_ids)
                        .with_birth_mask(birth_mask)
                        .with_text_births(text_births)
                        .with_births(births)
                        .with_prepared(prepared),
                    origin,
                },
                after_apply,
            );
            match applied {
                Ok((changes_claims, tasks, approved_vad_ids)) => Rows::Commit(Committed {
                    changes_claims,
                    tasks,
                    staged_gate_decisions,
                    approved_vad_ids,
                }),
                Err(err) => Rows::Discard(Err(Refused::from(err))),
            }
        });
        let Committed {
            changes_claims,
            tasks,
            staged_gate_decisions,
            approved_vad_ids,
        } = match committed {
            Ok(committed) => committed,
            Err(refused) => {
                for decision in refused.staged_gate_decisions {
                    decision.record_metrics(&vault.store.diagnostics.gate);
                }
                return Err(refused.err);
            }
        };
        if changes_claims {
            vault.store.notify_proactivity_changes();
        }
        vault.store.notify_task_updates(tasks);
        stale_sweep.finish()?;
        while vault.collect_lfs_garbage(32)? != 0 {}
        // A delete in this batch released the result bodies it owned.
        #[cfg(unix)]
        vault.collect_released_result_bodies(256)?;
        // A delete in this batch staged its claim-key retirement.
        vault.finish_gate_decision_retirements_after_commit();
        for decision in staged_gate_decisions {
            decision.record_metrics(&vault.store.diagnostics.gate);
        }
        // The canonical wrapper starts a separate write transaction. Never run
        // it during apply or preflight, and never turn a population error into
        // success merely because the approval is already durable.
        let now = vault.store.clock.now_recorded_at();
        for id in approved_vad_ids {
            vault.consolidate_claim_vad_now(&id, now)?;
        }
        Ok(())
    }
}

/// A batch past its gate preflight, ready to apply in the writer.
struct AdmittedBatch<'a> {
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'a>,
}

/// Phase 2 in the writer: apply, the caller's `after_apply`, and the Dreamer
/// approvals to consolidate after commit. Returns whether claims changed, the
/// TASKs written, and those approvals.
fn apply_admitted(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    batch: AdmittedBatch<'_>,
    after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
) -> Result<(
    bool,
    Vec<crate::entity_id::EntityId>,
    Vec<crate::entity_id::EntityId>,
)> {
    let pending_vad_ids =
        super::vad_postcommit::pending_dreamer_vad_approvals(vault, wtxn, &batch.ops)?;
    // ONE-1741: batch deletes no longer pre-scan for scan-verdict
    // relocation. The content-hash index row is maintained by
    // `deindex_entity` inside `apply_ops`, and verdicts anchor to the
    // content bytes rather than to any departing holder.
    let changes_claims = super::super::vad_postcommit::ops_change_proactivity(&batch.ops);
    let tasks = super::super::vad_postcommit::ops_put_tasks(&batch.ops);
    apply_ops_with_origin(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        batch.ops,
        batch.text_index_trusted,
        batch.gate_mode,
        batch.origin,
    )?;
    after_apply(wtxn)?;
    let approved_vad_ids = vault.resolved_dreamer_vad_approvals_in_txn(wtxn, pending_vad_ids)?;
    crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    Ok((changes_claims, tasks, approved_vad_ids))
}

/// What a committed batch still owes after its group commits.
struct Committed {
    changes_claims: bool,
    tasks: Vec<crate::entity_id::EntityId>,
    staged_gate_decisions: Vec<crate::gate::RecordedClaimGateDecision>,
    approved_vad_ids: Vec<crate::entity_id::EntityId>,
}

/// A batch's refusal, with the gate receipts it committed when the refusal is
/// a gate denial.
struct Refused {
    err: crate::error::Error,
    staged_gate_decisions: Vec<crate::gate::RecordedClaimGateDecision>,
}

impl From<crate::error::Error> for Refused {
    fn from(err: crate::error::Error) -> Self {
        Self {
            err,
            staged_gate_decisions: Vec::new(),
        }
    }
}
