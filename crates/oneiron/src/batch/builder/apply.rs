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
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(false, true), None)
    }

    /// Applies queued promotion operations while recording their gate decisions
    /// in the caller's transaction.
    pub(crate) fn apply_recording_gate_decisions(self, wtxn: &mut RwTxn<'_>) -> Result<()> {
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(true, true), None)
    }

    /// Local actor-bound batch: every direct record and reducer-touched parent
    /// is captured from the operation set, then gated before commit.
    pub(crate) fn apply_actor(self, wtxn: &mut RwTxn<'_>, actor: &crate::WriteActor) -> Result<()> {
        self.apply_with_gate_mode(wtxn, ApplyOpsGateMode::new(false, true), Some(actor))
    }

    fn apply_with_gate_mode(
        mut self,
        wtxn: &mut RwTxn<'_>,
        gate_mode: ApplyOpsGateMode,
        actor: Option<&crate::WriteActor>,
    ) -> Result<()> {
        // The commit-only checks stay behind: this terminal's puts meet the
        // same gates inside `wtxn` (see `CommitCheck`).
        if let Some(error) = self.validation_error.take() {
            return Err(error);
        }
        let vault = self.vault;
        #[cfg(feature = "sync")]
        let mut ops = std::mem::take(&mut self.ops);
        #[cfg(not(feature = "sync"))]
        let ops = std::mem::take(&mut self.ops);
        #[cfg(feature = "sync")]
        admit_federated_puts(vault, wtxn, &mut ops, &self.federated_puts)?;
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
        let text_index_trusted = if contains_text_op(&ops) {
            vault.ensure_text_index_trusted()?;
            true
        } else {
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire)
        };
        let pending_vad_ids = if super::vad_postcommit::has_vad_postcommit_owner(vault, wtxn) {
            super::vad_postcommit::pending_dreamer_vad_approvals(vault, wtxn, &ops)?
        } else {
            Vec::new()
        };
        let changes_claims = super::vad_postcommit::ops_change_proactivity(&ops);
        let gate_mode = gate_mode.with_birth_mask(self.birth_mask);
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
            apply_ops_with_origin(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                ops,
                text_index_trusted,
                gate_mode,
                self.origin,
            )?;
        }
        // Queue only after admitted apply. The owner checks the final body and
        // redeemed consent after ALL of its batches, then commits before VAD.
        super::vad_postcommit::queue_dreamer_vad_approvals(vault, wtxn, pending_vad_ids);
        if changes_claims {
            super::vad_postcommit::queue_proactivity_change(vault, wtxn);
        }
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
                &id.to_hex(),
                Some(&blob),
            )?;
            *data = admitted[ENTITY_METADATA_HEADER_LEN..].to_vec();
        }
    }
    Ok(())
}
