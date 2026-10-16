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
            // Threads on the kept version carry over by identity; OF-368's
            // exact-identity reattachment owns the detached ones.
            let reanchor = self.reanchor_annotation_threads_in_txn(
                wtxn,
                artifact_id,
                kept,
                version.version,
                &[],
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
