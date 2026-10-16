//! Training artifacts use the existing versioned blob store, not another file store.
use std::collections::BTreeSet;

use crate::Vault;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

use super::{
    ArtifactPin, CheckpointFileKind, CheckpointFilePin, CheckpointUpload, PinnedCheckpoint,
    SourcePin, hash_json, invalid,
};

impl SourcePin {
    pub(super) fn validate(&self) -> Result<()> {
        if self.repository.trim().is_empty()
            || self.revision.trim().is_empty()
            || matches!(
                self.revision.as_str(),
                "main" | "master" | "latest" | "HEAD"
            )
        {
            return Err(invalid(
                "training sources need a repository and an immutable revision",
            ));
        }
        Ok(())
    }
}

fn file_name(name: &str, kind: CheckpointFileKind) -> Result<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(char::is_control)
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
        || (kind == CheckpointFileKind::Weights && !name.ends_with(".safetensors"))
    {
        return Err(invalid(
            "checkpoint files need relative names; weights must be safetensors",
        ));
    }
    Ok(())
}

pub(super) fn keep_bytes(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    run: EntityId,
    name: &str,
    bytes: &[u8],
) -> Result<ArtifactPin> {
    let artifact = vault.store.clock.entity_id()?;
    let at = vault.store.clock.now_recorded_at();
    let occurred = TimeRange { start: at, end: at };
    let body = encode_blob_artifact_body(&BlobArtifactBody::new(name, "application/octet-stream"))?;
    vault
        .batch_in()
        .put(&artifact, ENTITY_TYPE_BLOB_ARTIFACT, occurred, at, &body)
        .apply(txn)?;
    let version = vault.append_blob_artifact_version_in_txn(
        txn,
        &artifact,
        bytes,
        &BlobVersionProvenance::AgentRun {
            run_ref: format!("training_pack:{}", run.to_hex()),
        },
        WriteActor::new(actor, EdgeActorClass::Human),
        occurred,
        at,
    )?;
    Ok(ArtifactPin {
        artifact,
        version: version.version,
        blake3: version.content_hash,
        bytes: bytes.len() as u64,
    })
}

pub(super) fn read_pin(vault: &Vault, txn: &heed::RoTxn<'_>, pin: &ArtifactPin) -> Result<Vec<u8>> {
    let metadata = vault
        .blob_artifact_version_metadata_in_txn(txn, &pin.artifact, pin.version)?
        .ok_or(Error::EntityNotFound)?;
    if metadata.content_hash != pin.blake3 {
        return Err(invalid(
            "training artifact pin differs from its stored version",
        ));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(txn, &pin.artifact, pin.version)?
        .ok_or(Error::EntityNotFound)?;
    if bytes.len() as u64 != pin.bytes || blake3::hash(&bytes).as_bytes() != &pin.blake3 {
        return Err(invalid("training artifact content hash or length mismatch"));
    }
    Ok(bytes)
}

pub(super) fn keep_checkpoint(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    run: EntityId,
    upload: &CheckpointUpload,
) -> Result<PinnedCheckpoint> {
    if upload.files.is_empty() {
        return Err(invalid("a checkpoint must pin every loaded file"));
    }
    let mut names = BTreeSet::new();
    let mut has_weights = false;
    let mut files = Vec::new();
    for file in &upload.files {
        file.source.validate()?;
        file_name(&file.name, file.kind)?;
        if !names.insert(&file.name) {
            return Err(invalid("duplicate checkpoint file name"));
        }
        has_weights |= file.kind == CheckpointFileKind::Weights;
        let content = keep_bytes(vault, txn, actor, run, &file.name, &file.bytes)?;
        files.push(CheckpointFilePin {
            name: file.name.clone(),
            kind: file.kind,
            source: file.source.clone(),
            content,
            declared_blake3: file.blake3,
        });
    }
    if !has_weights {
        return Err(invalid(
            "a checkpoint needs at least one safetensors weight shard",
        ));
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(PinnedCheckpoint {
        model: upload.model.clone(),
        files,
    })
}

impl PinnedCheckpoint {
    /// Pins the complete load set, including tokenizer, config, templates and any adapter/base.
    pub fn content_hash(&self) -> Result<[u8; 32]> {
        let mut files: Vec<_> = self
            .files
            .iter()
            .map(|file| {
                (
                    &file.name,
                    file.kind,
                    &file.source,
                    file.content.blake3,
                    file.content.bytes,
                )
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(b.0));
        hash_json(&(&self.model, files))
    }

    pub(super) fn verify(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        let mut names = BTreeSet::new();
        if self.files.is_empty()
            || !self
                .files
                .iter()
                .any(|f| f.kind == CheckpointFileKind::Weights)
        {
            return Err(invalid("checkpoint has no weight shards"));
        }
        for file in &self.files {
            file.source.validate()?;
            file_name(&file.name, file.kind)?;
            if !names.insert(&file.name) {
                return Err(invalid("checkpoint contains duplicate files"));
            }
            read_pin(vault, txn, &file.content)?;
        }
        Ok(())
    }
}

impl Vault {
    /// Import the owner's chosen starting checkpoint. This never changes a role.
    pub fn keep_training_checkpoint(
        &self,
        owner: &AuthenticatedOwner,
        upload: &CheckpointUpload,
    ) -> Result<PinnedCheckpoint> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let id = self.store.clock.entity_id()?;
            let checkpoint = keep_checkpoint(self, txn, actor, id, upload)?;
            checkpoint.verify(self, txn)?;
            if checkpoint
                .files
                .iter()
                .any(|file| file.declared_blake3 != file.content.blake3)
            {
                return Err(invalid("starting checkpoint hash mismatch"));
            }
            Ok(checkpoint)
        })
    }

    /// Retain verifier logs through the same custody used by corpus and weights.
    pub fn keep_training_verifier_log(
        &self,
        owner: &AuthenticatedOwner,
        name: &str,
        bytes: &[u8],
    ) -> Result<ArtifactPin> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let id = self.store.clock.entity_id()?;
            keep_bytes(self, txn, actor, id, name, bytes)
        })
    }

    /// Host loaders resolve an immutable version; repository code is never run here.
    pub fn read_training_artifact(&self, pin: &ArtifactPin) -> Result<Vec<u8>> {
        read_pin(self, &self.store.env.read_txn()?, pin)
    }
}

impl CheckpointUpload {
    /// The same identity as a custodied checkpoint, independent of its storage ids.
    pub fn content_hash(&self) -> Result<[u8; 32]> {
        let mut files: Vec<_> = self
            .files
            .iter()
            .map(|file| {
                (
                    &file.name,
                    file.kind,
                    &file.source,
                    *blake3::hash(&file.bytes).as_bytes(),
                    file.bytes.len() as u64,
                )
            })
            .collect();
        files.sort_by(|a, b| a.0.cmp(b.0));
        hash_json(&(&self.model, files))
    }
}
