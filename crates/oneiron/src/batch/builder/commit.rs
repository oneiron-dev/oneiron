//! Committing terminal: builder-time checks, index preparation, its share of
//! the group commit, preflight, apply, commit, VAD postcommit.

use super::super::*;
use super::preflight::{DeferredPreflight, preflight_gate_decisions_in_txn};
use super::reference_read;
use super::{BatchBuilder, CommitCheck};

use crate::store::Rows;

use std::collections::{BTreeSet, HashMap};

use heed::RwTxn;

use crate::claim::ScopedRead;
use crate::core_write::{CoreBatchCommit, CoreWriteLane};
use crate::error::{Error, Result};
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
        self.commit_inner(None, None, |_| Ok(()), |_| Ok(()), None)
    }

    /// [`Self::commit`] for a writer its host bound to `reader` (OF-063, FIX
    /// 1223, 6068). Each row a put would take must be one `reader` reads,
    /// judged against its original in the writer before any op stages; one
    /// it does not read refuses as missing. Each CLAIM's typed record refs
    /// must resolve under `reader` once the batch's own rows are staged; one
    /// that does not is the claim gate's hard deny, receipted once.
    pub(crate) fn commit_read_by(self, reader: &ScopedRead<'_>) -> Result<()> {
        self.commit_inner(None, Some(reader), |_| Ok(()), |_| Ok(()), None)
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
        self.commit_below_owner_with_guard(|_| Ok(()))
    }

    /// [`Self::commit_below_owner`] once `guard` passes, run first in the
    /// same writer snapshot: a bound caller's raw write proves its actor
    /// there (OF-063, FIX 3387).
    pub(crate) fn commit_below_owner_with_guard(
        self,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_below_owner_inner(None, guard)
    }

    /// [`Self::commit_below_owner_with_guard`] for a writer its host bound
    /// to `reader`, held to it as [`Self::commit_read_by`] holds a writer.
    pub(crate) fn commit_below_owner_read_by(
        self,
        reader: &ScopedRead<'_>,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_below_owner_inner(Some(reader), guard)
    }

    /// [`Self::commit`] / [`Self::commit_below_owner`] held to `lane`
    /// (OF-063, FIX 1216): the batch door's lane rule
    /// ([`Vault::write_core_batch_in_lane`](crate::Vault::write_core_batch_in_lane))
    /// for an already-staged batch. A read lane takes a stored row a put
    /// names only when it reads that row, judged against the row in the
    /// batch's own writer before any put lands, and each CLAIM's typed
    /// record refs must resolve under it. A target lane takes a stored row
    /// only inside the bounds of what its credential may write to, judged
    /// over the same put ids in that same writer snapshot; its CLAIMs
    /// commit as an unbound writer's do. An unbound lane commits as the
    /// grade's plain terminal does. `commit` selects the grade, as the
    /// batch door's does.
    pub fn commit_in_core_lane(
        self,
        lane: &CoreWriteLane<'_>,
        commit: CoreBatchCommit,
    ) -> Result<()> {
        match (lane, commit) {
            (CoreWriteLane::Read(reader), CoreBatchCommit::Owner) => self.commit_read_by(reader),
            (CoreWriteLane::Read(reader), CoreBatchCommit::BelowOwner) => {
                self.commit_below_owner_read_by(reader, |_| Ok(()))
            }
            (CoreWriteLane::Target(_), commit) => {
                let ids: Vec<crate::entity_id::EntityId> = self
                    .ops
                    .iter()
                    .filter_map(|op| match op {
                        BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. } => Some(*id),
                        _ => None,
                    })
                    .collect();
                let guard = |txn: &heed::RoTxn<'_>| -> Result<()> {
                    if lane.admits_puts_in(txn, &ids)? {
                        return Ok(());
                    }
                    // As missing: the row's kind, body and scope stay unsaid.
                    Err(Error::EntityNotFound)
                };
                match commit {
                    CoreBatchCommit::Owner => self.commit_with_target_guard(guard),
                    CoreBatchCommit::BelowOwner => self.commit_below_owner_with_guard(guard),
                }
            }
            (CoreWriteLane::Unbound, CoreBatchCommit::Owner) => self.commit(),
            (CoreWriteLane::Unbound, CoreBatchCommit::BelowOwner) => self.commit_below_owner(),
        }
    }

    fn commit_below_owner_inner(
        self,
        reader: Option<&ScopedRead<'_>>,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<()> {
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
        let guard = move |txn: &heed::RoTxn<'_>| -> Result<()> {
            guard(txn)?;
            for (id, body) in &agent_puts {
                if crate::agent_def::agent_definition_put_widens_in_txn(
                    &vault.store,
                    txn,
                    id,
                    body,
                )? {
                    return Err(crate::error::Error::Gate(
                        crate::error::GateError::ConsentOwnerNotAuthenticated(
                            "only the vault owner turns an agent definition back on or changes its models",
                        ),
                    ));
                }
            }
            Ok(())
        };
        self.commit_inner(None, reader, guard, |_| Ok(()), None)
    }

    /// Runs an app-door target guard in the same writer snapshot as admission.
    /// The guard runs before policy preflight and mutates nothing. Ordinary
    /// commit semantics, including retained denial receipts, stay unchanged.
    pub(crate) fn commit_with_target_guard(
        self,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(None, None, guard, |_| Ok(()), None)
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
        writer_hold_site: Option<&'static str>,
    ) -> Result<()> {
        self.commit_inner(
            Some(checker),
            None,
            before_apply,
            after_apply,
            writer_hold_site,
        )
    }

    /// [`Self::commit_with_checker_guard_and_then`] with nothing read first.
    #[cfg(test)]
    pub(crate) fn commit_with_checker_and_then(
        self,
        checker: &BoundedAutoChecker,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    ) -> Result<()> {
        self.commit_inner(Some(checker), None, |_| Ok(()), after_apply, None)
    }

    fn commit_inner(
        mut self,
        checker: Option<&BoundedAutoChecker>,
        reader: Option<&ScopedRead<'_>>,
        target_guard: impl FnOnce(&heed::RoTxn<'_>) -> Result<()>,
        after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
        writer_hold_site: Option<&'static str>,
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
        let mut ops = std::mem::take(&mut self.ops);
        let (origin, birth_mask) = (self.origin, self.birth_mask);
        let text_births = std::mem::take(&mut self.text_births);
        let births = std::mem::take(&mut self.births);
        let asset_files = std::mem::take(&mut self.asset_files);
        let replicated_puts = std::mem::take(&mut self.replicated_puts);
        let caller_envelopes = std::mem::take(&mut self.caller_envelopes);
        #[cfg(feature = "sync")]
        let federated_puts = std::mem::take(&mut self.federated_puts);
        #[cfg(feature = "sync")]
        let mut rows = super::super::vad_postcommit::ops_written_rows(&ops);
        #[cfg(feature = "sync")]
        let removed_edges = super::super::vad_postcommit::ops_removed_edges(&ops);
        let stale_sweep = crate::federation::StaleSweepWatch::begin(vault);
        let committed = vault.store.group_write(Some(announced), |wtxn| {
            // The caller's writer-hold site, when it named one: started
            // here so the span is this closure's hold only (FIX 12511).
            let _hold = writer_hold_site.map(crate::store::writer_hold::WriterHold::start);
            if let Err(err) = target_guard(wtxn) {
                return Rows::Discard(Err(err.into()));
            }
            #[cfg(feature = "sync")]
            if let Err(err) =
                super::apply::admit_federated_puts(vault, wtxn, &mut ops, &federated_puts)
            {
                return Rows::Discard(Err(err.into()));
            }
            // A bound writer takes only rows its read reads, judged against
            // their originals before anything stages (FIX 6068); its CLAIMs'
            // record refs are judged over the staged batch below (FIX 1223).
            let admitted = reader
                .map(|reader| reference_read::admit_before_staging(vault, reader, &*wtxn, &ops))
                .transpose();
            let gated = match admitted {
                Ok(None) => Vec::new(),
                Ok(Some(Some(gated))) => gated,
                // As missing: the row's kind, body and scope stay unsaid.
                Ok(Some(None)) => return Rows::Discard(Err(Error::EntityNotFound.into())),
                Err(err) => return Rows::Discard(Err(err.into())),
            };
            // Trusted routing keeps its existing path. A bound input stays
            // through its original caller policy/source preflight first.
            let routed = if reader.is_none() {
                match crate::comm::take_projector_only_batch_puts_in_txn(vault, &*wtxn, &mut ops) {
                    Ok(routed) => routed,
                    Err(err) => return Rows::Discard(Err(err.into())),
                }
            } else {
                None
            };
            let mut staged_gate_decisions = Vec::new();
            let mut preflight_gate_decision_ids = HashMap::new();
            let mut deferred = match preflight_gate_decisions_in_txn(
                &vault.store,
                &ops,
                wtxn,
                &mut staged_gate_decisions,
                &mut preflight_gate_decision_ids,
                checker,
                origin,
                &caller_envelopes,
                &births,
                reader.is_some() && !gated.is_empty(),
            ) {
                Ok(deferred) => deferred,
                Err(err) => {
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
            };
            let probes = deferred
                .as_mut()
                .map(|pending| std::mem::take(&mut pending.probes))
                .unwrap_or_default();
            let routed = if reader.is_some() {
                match crate::comm::take_projector_only_batch_puts_preserving_births_in_txn(
                    vault, &*wtxn, &mut ops, &births,
                ) {
                    Ok(routed) => routed,
                    Err(err) => return Rows::Discard(Err(err.into())),
                }
            } else {
                routed
            };
            #[cfg(feature = "sync")]
            {
                rows = super::super::vad_postcommit::ops_written_rows(&ops);
            }
            let batch = AdmittedBatch {
                routed,
                bound_inputs: reader.is_some(),
                ops,
                text_index_trusted,
                gate_mode: ApplyOpsGateMode::new(false, true)
                    .with_preflight_gate_decision_ids(preflight_gate_decision_ids)
                    .with_pending_auto_probes(probes)
                    .with_birth_mask(birth_mask)
                    .with_text_births(text_births)
                    .with_births(births)
                    .with_asset_files(asset_files)
                    .with_replicated_puts(replicated_puts)
                    .with_caller_envelopes(caller_envelopes)
                    .with_prepared(prepared),
                origin,
            };
            let applied = match reader.filter(|_| !gated.is_empty() || batch.routed.is_some()) {
                None => apply_admitted(vault, wtxn, batch, after_apply, None).map(Judged::Applied),
                Some(reader) => {
                    apply_judged(vault, wtxn, batch, after_apply, reader, gated, deferred)
                }
            };
            let applied = match applied {
                Ok(Judged::Applied(applied)) => Ok(applied),
                // The gate's one denial stays; nothing the batch staged does,
                // nor any preflight receipt.
                Ok(Judged::Denied(denial)) => {
                    let settled = reference_read::settle_denial_in(
                        &vault.store,
                        wtxn,
                        &staged_gate_decisions,
                        *denial,
                    );
                    return match settled {
                        Ok((err, Some(decision))) => Rows::Refuse(Refused {
                            err,
                            staged_gate_decisions: vec![decision],
                        }),
                        Ok((err, None)) => Rows::Discard(Err(err.into())),
                        Err(err) => Rows::Discard(Err(err.into())),
                    };
                }
                Ok(Judged::Pended(pending)) => {
                    let settled =
                        settle_pending_in(&vault.store, wtxn, staged_gate_decisions, *pending);
                    return match settled {
                        Ok(refused) => Rows::Refuse(refused),
                        Err(err) => Rows::Discard(Err(err.into())),
                    };
                }
                Err(err) => Err(err),
            };
            match applied {
                Ok((changes_claims, tasks, approved_vad_ids, pad_windows, routed_rows)) => {
                    #[cfg(feature = "sync")]
                    rows.extend(routed_rows);
                    #[cfg(not(feature = "sync"))]
                    drop(routed_rows);
                    // FIX 7957, 9599: the rows this batch changed and the
                    // edges it removed leave their windows durable markers.
                    #[cfg(feature = "sync")]
                    if let Err(err) = vault.mark_pending_mirrors_in_txn(wtxn, &rows) {
                        return Rows::Discard(Err(Refused::from(err)));
                    }
                    #[cfg(feature = "sync")]
                    if let Err(err) = vault.mark_pending_edge_removals_in_txn(wtxn, &removed_edges)
                    {
                        return Rows::Discard(Err(Refused::from(err)));
                    }
                    Rows::Commit(Committed {
                        changes_claims,
                        tasks,
                        staged_gate_decisions,
                        approved_vad_ids,
                        pad_windows,
                    })
                }
                Err(err) => Rows::Discard(Err(Refused::from(err))),
            }
        });
        let Committed {
            changes_claims,
            tasks,
            staged_gate_decisions,
            approved_vad_ids,
            pad_windows,
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
            vault.verb_hook_bindings_changed();
        }
        vault.store.notify_task_updates(tasks);
        vault.store.notify_attempt_observers();
        #[cfg(feature = "sync")]
        vault.note_committed_rows(rows);
        // A WORLD delete in this batch staged its pads' tombstones; they
        // publish now, not at each window's next load (FIX 3334).
        vault.publish_pad_tombstones_after_commit(&pad_windows);
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
    routed: Option<crate::comm::RoutedBatchPuts>,
    bound_inputs: bool,
    ops: Vec<BatchOp>,
    text_index_trusted: bool,
    gate_mode: ApplyOpsGateMode,
    origin: BaseWriteOrigin<'a>,
}

/// Phase 2 in the writer: apply, the caller's `after_apply`, and the Dreamer
/// approvals to consolidate after commit. Returns whether claims changed, the
/// TASKs written, those approvals, and the windows of the pad tombstones the
/// apply staged.
fn apply_admitted(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    mut batch: AdmittedBatch<'_>,
    after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    admission: Option<&mut dyn crate::comm::ProjectedHeadAdmission>,
) -> Result<Applied> {
    let routed_rows = match batch.routed {
        Some(routed) => {
            if batch.bound_inputs {
                super::comm_input::admit_routed_inputs(
                    vault,
                    wtxn,
                    routed.inputs(),
                    &mut batch.gate_mode,
                )?;
            }
            routed.record_with_admission_in_txn(vault, wtxn, admission)?
        }
        None => BTreeSet::new(),
    };
    let rekeys = crate::channel_identity::AssignmentRekeys::begin(&vault.store);
    let pending_vad_ids =
        super::vad_postcommit::pending_dreamer_vad_approvals(vault, wtxn, &batch.ops)?;
    // ONE-1741: batch deletes no longer pre-scan for scan-verdict
    // relocation. The content-hash index row is maintained by
    // `deindex_entity` inside `apply_ops`, and verdicts anchor to the
    // content bytes rather than to any departing holder.
    // A write to a watched unit queues the proactivity wake too, as the
    // caller-transaction terminal does (FIX 11705).
    let changes_claims = !routed_rows.is_empty()
        || super::super::vad_postcommit::ops_change_proactivity(&batch.ops)
        || super::super::vad_postcommit::ops_touch_watched_units(vault, wtxn, &batch.ops)?;
    let tasks = super::super::vad_postcommit::ops_put_tasks(&batch.ops);
    // A WORLD delete stages its pads' tombstones under this scope (FIX 3334).
    // Only their windows are taken from it: this terminal reads the rest of
    // its post-commit work from the ops.
    let pad_scope = super::super::vad_postcommit::VadPostcommitScope::new(vault, wtxn);
    let put_roots: BTreeSet<_> = batch
        .ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::Put { id, .. } => Some(*id),
            _ => None,
        })
        .collect();
    let mut derived = crate::embed::repo_derived_batch(&batch.ops);
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
    let pad_windows = pad_scope.finish().pad_windows;
    after_apply(wtxn)?;
    derived.include_source_dependents_in(&vault.store, wtxn, &put_roots)?;
    crate::embed::finalize_repo_derived_index_copies_in_txn(vault, wtxn, derived)?;
    crate::secret_custody::raise_found_key_notices_in_txn(vault, wtxn)?;
    // OF-533: a delegated TASK's terminal result reaches its parked runs here.
    for task in &tasks {
        crate::task_verb::deliver_task_result_in_txn(vault, wtxn, *task)?;
    }
    rekeys.finish(&vault.store, wtxn)?;
    let rederive_scope = super::super::vad_postcommit::VadPostcommitScope::new(vault, wtxn);
    crate::scope_summary::rederive_changed_in_txn(vault, wtxn)?;
    let changes_claims = rederive_scope.finish().proactivity_changed || changes_claims;
    let approved_vad_ids = vault.resolved_dreamer_vad_approvals_in_txn(wtxn, pending_vad_ids)?;
    // The approval's commit carries its consolidation debt (FIX 9598).
    if !approved_vad_ids.is_empty() {
        let now = vault.store.clock.now_recorded_at();
        crate::store::owe_claim_vad_in_txn(&vault.store, wtxn, &approved_vad_ids, now)?;
    }
    crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    Ok((
        changes_claims,
        tasks,
        approved_vad_ids,
        pad_windows,
        routed_rows,
    ))
}

/// The changes a batch's apply leaves: whether claims changed, the TASKs
/// written, the Dreamer approvals to consolidate, and the pad tombstone
/// windows.
type Applied = (
    bool,
    Vec<crate::entity_id::EntityId>,
    Vec<crate::entity_id::EntityId>,
    BTreeSet<String>,
    BTreeSet<crate::entity_id::EntityId>,
);

/// A bound writer's apply, judged.
enum Judged {
    Applied(Applied),
    /// The claim gate's denial of a record ref the writer's read does not
    /// resolve; nothing the apply staged stays.
    Denied(Box<reference_read::StagedDenial>),
    /// No reference denied, so the first preflight Pending remains; the
    /// complete probe is discarded rather than committed.
    Pended(Box<DeferredPreflight>),
}

/// [`apply_admitted`] for a bound writer whose batch gates CLAIMs: the batch
/// applies in a savepoint of `wtxn`, the claim gate judges each CLAIM's
/// record refs under `reader` over the staged rows, and the savepoint joins
/// `wtxn` only when every ref resolves (OF-063, FIX 1223).
fn apply_judged(
    vault: &crate::Vault,
    wtxn: &mut RwTxn<'_>,
    batch: AdmittedBatch<'_>,
    after_apply: impl FnOnce(&mut RwTxn<'_>) -> Result<()>,
    reader: &ScopedRead<'_>,
    mut gated: Vec<reference_read::GatedClaim>,
    deferred: Option<DeferredPreflight>,
) -> Result<Judged> {
    let mut staged = vault.store.env.nested_write_txn(wtxn)?;
    let mut admission = super::comm_projection::CommHeadWrites::reader(reader);
    let applied = apply_admitted(vault, &mut staged, batch, after_apply, Some(&mut admission))?;
    gated.extend(admission.gated_claims(vault, &staged)?);
    let denial = reference_read::staged_reference_denial(vault, &mut staged, reader, &gated)?;
    if let Some(denial) = denial {
        return Ok(Judged::Denied(Box::new(denial)));
    }
    if let Some(pending) = deferred {
        return Ok(Judged::Pended(Box::new(pending)));
    }
    staged.commit()?;
    Ok(Judged::Applied(applied))
}

/// The rollback-only probe left all preflight receipts in the outer writer.
/// Keep only its first native Pending, as an ordinary preflight refusal does.
fn settle_pending_in(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    mut decisions: Vec<crate::gate::RecordedClaimGateDecision>,
    pending: DeferredPreflight,
) -> Result<Refused> {
    for decision in &decisions {
        if decision.decision_id() != pending.first_decision {
            store.delete_gate_decision_in_txn(txn, decision.decision_id())?;
        }
    }
    decisions.retain(|decision| decision.decision_id() == pending.first_decision);
    crate::ports::recorded_at_in_txn(store, txn)?;
    Ok(Refused {
        err: pending.err,
        staged_gate_decisions: decisions,
    })
}

/// What a committed batch still owes after its group commits.
struct Committed {
    changes_claims: bool,
    tasks: Vec<crate::entity_id::EntityId>,
    staged_gate_decisions: Vec<crate::gate::RecordedClaimGateDecision>,
    approved_vad_ids: Vec<crate::entity_id::EntityId>,
    /// Windows of the pad tombstones a WORLD delete staged (FIX 3334).
    pad_windows: BTreeSet<String>,
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
