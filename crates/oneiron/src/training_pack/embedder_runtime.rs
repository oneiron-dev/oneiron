//! Exact returned and owner-approved embedder checkpoints for host runtimes.

use crate::embed::{
    BindingMoveState, BindingSource, EmbeddingSpace, KindSlotBindings, PendingEmbedderBinding,
    declare_embedding_space_in_txn, embedding_space_in_txn, kind_slot_bindings_in_txn,
    live_binding_move_in,
};
use crate::llm::manifest::{ModelBinding, ModelRole, read_manifest};
use crate::{EntityId, Result, Vault};

use super::{
    PinnedCheckpoint, RoleSwapReceipt, TrainingState, role_swap_receipt_in, training_run_in,
    training_runs_in,
};

impl PinnedCheckpoint {
    /// One spelling for runtime declaration and native training move matching.
    pub(crate) fn embedding_space_id(&self) -> Result<String> {
        Ok(format!(
            "{}@training-{}",
            self.model,
            blake3::Hash::from(self.content_hash()?).to_hex(),
        ))
    }

    /// Cached bytes remain usable only while every original immutable version
    /// and its native body-readability state are live in this transaction.
    pub(crate) fn custody_live_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
        for file in &self.files {
            let Some(version) = vault.blob_artifact_version_metadata_in_txn(
                txn,
                &file.content.artifact,
                file.content.version,
            )?
            else {
                return Ok(false);
            };
            if version.content_hash != file.content.blake3
                || !vault.blob_artifact_bytes_readable_in_txn(txn, &file.content.artifact)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// One actual returned checkpoint and the setup its loader observed. Loading
/// confers no approval: only `approved` or `bound` sources may fill a space.
#[derive(Clone, Debug, PartialEq)]
pub struct TrainingEmbedderSource {
    pub run: EntityId,
    pub checkpoint: PinnedCheckpoint,
    pub binding: ModelBinding,
    pub state: TrainingState,
    pub pending: Option<PendingEmbedderBinding>,
    pub bound: Option<RoleSwapReceipt>,
    pub manifest: Option<ModelBinding>,
    pub slots: KindSlotBindings,
    pub space: Option<EmbeddingSpace>,
}

impl TrainingEmbedderSource {
    /// A private custody load set, not a stock provider or a hub revision.
    pub fn space_id(&self) -> Result<String> {
        self.checkpoint.embedding_space_id()
    }

    /// The native pending receipt still authorizes filling over this manifest.
    #[must_use]
    pub fn approved(&self) -> bool {
        self.pending.as_ref().is_some_and(|pending| {
            pending.previous == self.manifest
                && pending.binding == self.binding
                && matches!(
                    pending.state,
                    BindingMoveState::Waiting | BindingMoveState::Filling
                )
                && matches!(&pending.source, BindingSource::Training { receipt }
                    if receipt.run == self.run
                        && receipt.role == ModelRole::RetrievalEmbedder
                        && receipt.binding == self.binding
                        && receipt.checkpoint == self.checkpoint)
        })
    }

    /// The actual role receipt, not just a matching model id, still serves.
    #[must_use]
    pub fn bound(&self) -> bool {
        self.state == TrainingState::Bound
            && self.manifest.as_ref() == Some(&self.binding)
            && self.bound.as_ref().is_some_and(|receipt| {
                receipt.run == self.run
                    && receipt.role == ModelRole::RetrievalEmbedder
                    && receipt.binding == self.binding
                    && receipt.checkpoint == self.checkpoint
            })
    }
}

fn source_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<TrainingEmbedderSource>> {
    let Some(run) = training_run_in(vault, txn, id)? else {
        return Ok(None);
    };
    let Some((ModelRole::RetrievalEmbedder, binding)) = run.plan.target.role_binding() else {
        return Ok(None);
    };
    if !matches!(
        run.state,
        TrainingState::Returned | TrainingState::Scored | TrainingState::Bound
    ) {
        return Ok(None);
    }
    let Some(result) = run.result else {
        return Ok(None);
    };
    if result.exported_checkpoint.model != binding.model
        || !result.exported_checkpoint.custody_live_in_txn(vault, txn)?
    {
        return Ok(None);
    }
    let mut source = TrainingEmbedderSource {
        run: *id,
        checkpoint: result.exported_checkpoint,
        binding: binding.clone(),
        state: run.state,
        pending: live_binding_move_in(vault, txn, id)?,
        bound: role_swap_receipt_in(vault, txn, ModelRole::RetrievalEmbedder)?,
        manifest: read_manifest(&vault.store, txn)?
            .and_then(|manifest| manifest.roles.get(&ModelRole::RetrievalEmbedder).cloned()),
        slots: kind_slot_bindings_in_txn(&vault.store, txn)?,
        space: None,
    };
    source.space = embedding_space_in_txn(&vault.store, txn, &source.space_id()?)?;
    Ok(Some(source))
}

impl Vault {
    /// The checkpoint and setup in one snapshot, including pre-bound eval candidates.
    /// No checkpoint bytes are loaded and no approval is minted.
    pub fn training_embedder_source(
        &self,
        id: &EntityId,
    ) -> Result<Option<TrainingEmbedderSource>> {
        source_in(self, &self.store.env.read_txn()?, id)
    }

    /// The same snapshot for all returned embedder runs, in native run order.
    pub fn training_embedder_sources(&self) -> Result<Vec<TrainingEmbedderSource>> {
        let txn = self.store.env.read_txn()?;
        let mut sources = Vec::new();
        for run in training_runs_in(self, &txn)? {
            if let Some(source) = source_in(self, &txn, &run.id)? {
                sources.push(source);
            }
        }
        Ok(sources)
    }

    /// Declares an actually loaded space only if the full observed approval,
    /// run, checkpoint, manifest, slots and declaration still match in this writer.
    /// A changed observation writes nothing; the ordinary worker retries it.
    pub fn declare_training_embedder_space(
        &self,
        expected: &TrainingEmbedderSource,
        space: &EmbeddingSpace,
    ) -> Result<bool> {
        let setup = self.with_write_txn_grouped(|txn| {
            let Some(current) = source_in(self, txn, &expected.run)? else {
                return Ok(None);
            };
            if &current != expected || !current.approved() || space.id != current.space_id()? {
                return Ok(None);
            }
            if let Some(declared) = &current.space {
                return if declared == space {
                    Ok(None)
                } else {
                    Err(super::invalid(
                        "trained checkpoint space differs from its declaration",
                    ))
                };
            }
            declare_embedding_space_in_txn(&self.store, txn, space)?;
            self.publish_embedding_setup_in_txn(txn).map(Some)
        })?;
        if let Some(setup) = setup {
            self.embedding_setup_committed(setup);
            return Ok(true);
        }
        Ok(false)
    }
}
