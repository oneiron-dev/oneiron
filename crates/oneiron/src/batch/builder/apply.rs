//! Caller-transaction terminal: stages the batch into a transaction the
//! caller owns and commits.

use super::super::*;
use super::BatchBuilder;

use heed::RwTxn;

#[cfg(feature = "sync")]
use crate::Vault;
use crate::error::{Error, Result};

impl BatchBuilder<'_> {
    /// Applies all queued operations to the given write transaction without committing.
    ///
    /// Within [`Vault::with_write_txn`](crate::Vault::with_write_txn) or
    /// [`Vault::try_with_write_txn`](crate::Vault::try_with_write_txn),
    /// explicit Dreamer approvals queue canonical VAD work for the owner after
    /// commit. A postcommit failure retains Approved and is returned by that
    /// owner.
    ///
    /// Note: operations are staged eagerly into `wtxn`. If this returns an
    /// error, earlier writes may already be present in the transaction, so
    /// callers must abort the transaction (drop without committing) to discard
    /// it.
    pub fn apply(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(false, true), None, None, None)
    }

    /// [`Self::apply`] for the replicated put a sync window's ingest door
    /// admitted, with what that door judged beside it. A replicated
    /// AUTHORITY_LOG put is judged beside `authority_beside`, the other
    /// authority rows the window carries (FIX 11764), so history that arrives
    /// in two or more rows together lands as the ingest door admitted it. A
    /// replicated MESSAGE put meets the witness check with `own_device`, the
    /// lane the door gave its row when one of the owner's own machines sent
    /// it, which counts only for that row and its exact bytes (FIX 9600).
    #[cfg(feature = "sync")]
    pub(crate) fn apply_ingested(
        self,
        wtxn: &mut RwTxn<'_>,
        authority_beside: Option<crate::authority::RowsBeside<'_>>,
        own_device: Option<&crate::sync::VerifiedOwnDeviceLane>,
    ) -> Result<()> {
        self.apply_with_gate_mode(
            wtxn,
            ApplyOpsGateMode::new(false, true),
            None,
            authority_beside,
            own_device,
        )
    }

    /// Applies queued promotion operations while recording their gate decisions
    /// in the caller's transaction.
    pub(crate) fn apply_recording_gate_decisions(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(true, true), None, None, None)
    }

    /// Local actor-bound batch: every direct record and reducer-touched parent
    /// is captured from the operation set, then gated before commit.
    pub(crate) fn apply_actor(self, wtxn: &mut RwTxn<'_>, actor: &crate::WriteActor) -> Result<()> {
        self.apply_with_gate_mode(
            wtxn,
            ApplyOpsGateMode::new(false, true),
            Some(actor),
            None,
            None,
        )
    }

    fn apply_with_gate_mode(
        mut self,
        wtxn: &mut RwTxn<'_>,
        gate_mode: ApplyOpsGateMode,
        actor: Option<&crate::WriteActor>,
        authority_beside: Option<crate::authority::RowsBeside<'_>>,
        own_device: Option<&VerifiedOwnDeviceLane>,
    ) -> Result<()> {
        // The commit-only checks stay behind: this terminal's puts meet the
        // same gates inside `wtxn` (see `CommitCheck`).
        if let Some(error) = self.validation_error.take() {
            return Err(error);
        }
        let vault = self.vault;
        #[cfg(feature = "sync")]
        admit_federated_puts(vault, wtxn, &mut self.ops, &self.federated_puts)?;
        // A batch inside an actor-bound transaction cannot silently choose the
        // trusted/raw apply path. The in-flight writer is transaction-local,
        // never a process-global flag or a reusable preflight token.
        let active_actor = crate::federation::actor_for_txn(vault, wtxn)?;
        let actor = match (actor.copied(), active_actor) {
            (Some(requested), Some(active)) if requested != active => {
                return Err(Error::InvalidClaimBody(
                    "batch actor differs from transaction actor",
                ));
            }
            (Some(requested), _) => Some(requested),
            (None, active) => active,
        };
        let text_index_trusted = if contains_text_op(&self.ops) {
            vault.ensure_text_index_trusted()?;
            true
        } else {
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire)
        };
        let pending_vad_ids = if super::vad_postcommit::has_vad_postcommit_owner(vault, wtxn) {
            super::vad_postcommit::pending_dreamer_vad_approvals(vault, wtxn, &self.ops)?
        } else {
            Vec::new()
        };
        let changes_claims = super::vad_postcommit::ops_change_proactivity(&self.ops)
            || super::vad_postcommit::ops_touch_watched_units(vault, wtxn, &self.ops)?;
        let tasks = super::vad_postcommit::ops_put_tasks(&self.ops);
        let rows = super::vad_postcommit::ops_written_rows(&self.ops);
        #[cfg(feature = "sync")]
        let removed_edges = super::vad_postcommit::ops_removed_edges(&self.ops);
        let gate_mode = gate_mode
            .with_birth_mask(self.birth_mask)
            .with_text_births(std::mem::take(&mut self.text_births))
            .with_births(std::mem::take(&mut self.births))
            .with_asset_files(std::mem::take(&mut self.asset_files))
            .with_replicated_puts(std::mem::take(&mut self.replicated_puts));
        // Taken only now: until here a refusal leaves a promotion replay's
        // ops to the builder's drop, which wipes them (Sol on engine-prs-30).
        let ops = std::mem::take(&mut self.ops);
        let derived = crate::embed::repo_derived_batch(&ops);
        if let Some(actor) = actor {
            apply_actor_ops(
                vault,
                wtxn,
                &actor,
                ops,
                text_index_trusted,
                gate_mode,
                self.origin,
            )?;
        } else {
            apply_ops_with_authority_beside(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                ops,
                text_index_trusted,
                gate_mode,
                self.origin,
                authority_beside,
                own_device,
            )?;
        }
        crate::embed::finalize_repo_derived_index_copies_in_txn(vault, wtxn, derived)?;
        // Queue only after admitted apply. The owner checks the final body and
        // redeemed consent after ALL of its batches, then commits before VAD.
        super::vad_postcommit::queue_dreamer_vad_approvals(vault, wtxn, pending_vad_ids);
        if changes_claims {
            super::vad_postcommit::queue_proactivity_change(vault, wtxn);
        }
        // OF-533: a delegated TASK's terminal result reaches its parked runs here.
        for task in &tasks {
            crate::task_verb::deliver_task_result_in_txn(vault, wtxn, *task)?;
        }
        super::vad_postcommit::queue_task_updates(vault, wtxn, tasks);
        super::vad_postcommit::queue_committed_rows(vault, wtxn, rows);
        // FIX 9599: each edge the batch removed leaves its window a durable
        // marker; the write door marks the rows.
        #[cfg(feature = "sync")]
        vault.mark_pending_edge_removals_in_txn(wtxn, &removed_edges)?;
        Ok(())
    }
}

/// Federation admission for the replicated puts a federated import tier
/// queued: each body is replaced by what the policy admits, inside the
/// transaction that applies it, before any op stages.
#[cfg(feature = "sync")]
pub(super) fn admit_federated_puts(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    ops: &mut [BatchOp],
    federated_puts: &[usize],
) -> Result<()> {
    if federated_puts.is_empty() {
        return Ok(());
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, wtxn)?;
    for index in federated_puts {
        if let BatchOp::Put {
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            ..
        } = &mut ops[*index]
        {
            let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
            blob.push(*entity_type);
            blob.extend_from_slice(&occurred.start.to_be_bytes());
            blob.extend_from_slice(&occurred.end.to_be_bytes());
            blob.extend_from_slice(&learned_at.to_be_bytes());
            blob.extend_from_slice(data);
            let admitted = crate::sync::selector::admit_federated_entity_blob(
                vault,
                &policy,
                wtxn,
                &id.to_hex(),
                Some(&blob),
            )?;
            *data = admitted[ENTITY_METADATA_HEADER_LEN..].to_vec();
        }
    }
    Ok(())
}
