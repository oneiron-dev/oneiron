//! Undo after Keep (ARCH-0077 "Post-settle undo"): a new operation, never a
//! reversal. The kept version stays in the tree and the settle token stays
//! consumed; undo appends the version the Keep was appended onto as the next
//! version, once per Keep, with its own made_by receipt.

use serde::{Deserialize, Serialize};

use super::codec::{RECORD, settlement_key_parts};
use super::records::{SettleConsent, SettleOutcomeKind};
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::blob_artifact::{
    BlobArtifactVersion, BlobVersionProvenance, hash_hex, read_blob_artifact_head_in_txn,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

/// Key: id16 + hash32 (blake3 of the kept proposal's ref).
const UNDO: SideTable<(EntityId, [u8; 32]), KeepUndo, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_UNDO);

/// The once-only undo of one kept proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeepUndo {
    pub proposal_ref: String,
    /// The version the Keep appended.
    pub kept_version: u64,
    /// The version the Keep was appended onto, whose bytes the undo restored.
    pub restored_version: u64,
    /// The new version the undo appended.
    pub version: u64,
    pub actor: EntityId,
    pub at: u64,
}

/// The result of undoing one Keep.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct KeepUndoOutcome {
    pub undo: KeepUndo,
    pub version: BlobArtifactVersion,
    /// Threads carried from the kept version onto the undo version.
    pub reanchor: ReanchorSummary,
}

impl Vault {
    /// Undoes one Keep by appending the version it was kept onto as the
    /// next version. Refused when the proposal was not kept, was already
    /// undone, kept no new version, or when a later version sits on the
    /// kept one: undo never clobbers later work.
    pub fn undo_kept_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
        consent: &SettleConsent,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<KeepUndoOutcome> {
        self.authorize_settle(consent, actor)?;
        let key = settlement_key_parts(artifact_id, proposal_ref);
        self.with_write_txn_grouped(|wtxn| {
            self.authorize_settle_in_txn(wtxn, consent, actor)?;
            let settled = RECORD
                .get(&self.store, wtxn, &key)?
                .ok_or(Error::EntityNotFound)?;
            let (SettleOutcomeKind::Selected, Some(kept), Some(restored)) =
                (settled.outcome, settled.version, settled.before_version)
            else {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "only a kept proposal that appended a version can be undone",
                )));
            };
            if kept <= restored {
                return Err(Error::Artifact(ArtifactError::InvalidEditManifest(
                    "the Keep appended no new version to undo",
                )));
            }
            if UNDO.contains(&self.store, wtxn, &key)? {
                return Err(Error::Artifact(ArtifactError::EditProposalAlreadySettled {
                    outcome: "undone",
                }));
            }
            let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .ok_or(Error::EntityNotFound)?;
            if head.version != kept {
                return Err(Error::Artifact(ArtifactError::EditProposalStale));
            }
            let restored_record = self
                .blob_artifact_version_metadata_in_txn(wtxn, artifact_id, restored)?
                .ok_or(Error::EntityNotFound)?;
            let bytes = self
                .read_blob_artifact_version_in_txn(wtxn, artifact_id, restored)?
                .ok_or(Error::EntityNotFound)?;
            let human = actor.actor_class() == EdgeActorClass::Human;
            let provenance = if human {
                BlobVersionProvenance::UserUpload
            } else {
                BlobVersionProvenance::AgentRun {
                    run_ref: format!(
                        "undo:{}",
                        hash_hex(blake3::hash(proposal_ref.as_bytes()).as_bytes())
                    ),
                }
            };
            let made_by = MadeBy {
                inputs: [head.claim_id, restored_record.claim_id]
                    .into_iter()
                    .map(|row| MadeByInput {
                        row,
                        role: MadeByInputRole::Input,
                    })
                    .collect(),
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class: if human {
                        MadeByClass::Stated
                    } else {
                        MadeByClass::Concluded
                    },
                    identity: "artifact.undo".to_owned(),
                    version: "1".to_owned(),
                    params_hash: hash_hex(blake3::hash(proposal_ref.as_bytes()).as_bytes()),
                },
                at: learned_at,
                trigger: None,
            };
            let version = self.append_blob_artifact_version_made_by_in_txn(
                wtxn,
                artifact_id,
                None,
                &bytes,
                &provenance,
                &made_by,
                actor,
                occurred,
                learned_at,
            )?;
            if version.version <= kept {
                return Err(Error::CorruptedIndex("undo appended no version"));
            }
            // The undo version is the restored version's bytes: threads that
            // stood on it, or drifted off it, reattach by exact stored identity.
            let reanchor = self.reattach_restored_threads_in_txn(
                wtxn,
                artifact_id,
                restored,
                version.version,
                actor,
                occurred,
                learned_at,
            )?;
            let undo = KeepUndo {
                proposal_ref: proposal_ref.to_owned(),
                kept_version: kept,
                restored_version: restored,
                version: version.version,
                actor: actor.entity_ref(),
                at: learned_at,
            };
            UNDO.put(&self.store, wtxn, &key, &undo)?;
            Ok(KeepUndoOutcome {
                undo,
                version,
                reanchor,
            })
        })
        .inspect(|outcome| {
            if !outcome.reanchor.remapped.is_empty() {
                self.store.notify_attempt_observers();
            }
        })
    }

    /// Restores an earlier version (ARCH-0078 "Versions and forks"): its bytes
    /// become the next version, with an `artifact.restore` made_by naming the
    /// restored and replaced versions. Comments that stood on the restored
    /// version, or drifted off it, reattach by exact stored identity.
    pub fn restore_blob_artifact_version(
        &self,
        artifact_id: &EntityId,
        version: u64,
        actor: WriteActor,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<KeepUndoOutcome> {
        self.with_write_txn_grouped(|wtxn| {
            let head = read_blob_artifact_head_in_txn(&self.store, wtxn, artifact_id)?
                .ok_or(Error::EntityNotFound)?;
            if version >= head.version {
                return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                    "restore names an earlier version than the head",
                )));
            }
            let restored = self
                .blob_artifact_version_metadata_in_txn(wtxn, artifact_id, version)?
                .ok_or(Error::EntityNotFound)?;
            let bytes = self
                .read_blob_artifact_version_in_txn(wtxn, artifact_id, version)?
                .ok_or(Error::EntityNotFound)?;
            let human = actor.actor_class() == EdgeActorClass::Human;
            let key = hash_hex(blake3::hash(&version.to_be_bytes()).as_bytes());
            let provenance = if human {
                BlobVersionProvenance::UserUpload
            } else {
                BlobVersionProvenance::AgentRun {
                    run_ref: format!("restore:{key}"),
                }
            };
            let made_by = MadeBy {
                inputs: [restored.claim_id, head.claim_id]
                    .into_iter()
                    .map(|row| MadeByInput {
                        row,
                        role: MadeByInputRole::Input,
                    })
                    .collect(),
                process: MadeByProcess {
                    actor: actor.entity_ref(),
                    class: if human {
                        MadeByClass::Stated
                    } else {
                        MadeByClass::Concluded
                    },
                    identity: "artifact.restore".to_owned(),
                    version: "1".to_owned(),
                    params_hash: key,
                },
                at: learned_at,
                trigger: None,
            };
            let appended = self.append_blob_artifact_version_made_by_in_txn(
                wtxn,
                artifact_id,
                None,
                &bytes,
                &provenance,
                &made_by,
                actor,
                occurred,
                learned_at,
            )?;
            if appended.version <= head.version {
                return Err(Error::Artifact(ArtifactError::InvalidBlobArtifactBody(
                    "the head already holds that version's bytes",
                )));
            }
            let reanchor = self.reattach_restored_threads_in_txn(
                wtxn,
                artifact_id,
                version,
                appended.version,
                actor,
                occurred,
                learned_at,
            )?;
            Ok(KeepUndoOutcome {
                undo: KeepUndo {
                    proposal_ref: String::new(),
                    kept_version: head.version,
                    restored_version: version,
                    version: appended.version,
                    actor: actor.entity_ref(),
                    at: learned_at,
                },
                version: appended,
                reanchor,
            })
        })
        .inspect(|outcome| {
            if !outcome.reanchor.remapped.is_empty() {
                self.store.notify_attempt_observers();
            }
        })
    }

    /// The undo of one kept proposal, if it was undone.
    pub fn kept_proposal_undo(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<KeepUndo>> {
        let rtxn = self.store.env.read_txn()?;
        UNDO.get(
            &self.store,
            &rtxn,
            &settlement_key_parts(artifact_id, proposal_ref),
        )
    }
}
