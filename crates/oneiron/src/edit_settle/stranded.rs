//! Stale retained outputs stay durable proposals against the observed new head.

use crate::Vault;
use crate::blob_artifact::BlobArtifactVersion;
use crate::edit_roundtrip::{EditManifest, EditProposal};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::write_envelope::WriteActor;
use serde::{Deserialize, Serialize};

/// Recovery payload. The original manifest is not replayed on the newer head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrandedEditProposal {
    pub artifact_ref: String,
    pub proposal_ref: String,
    pub base_version: Option<u64>,
    pub base_content_hash: [u8; 32],
    pub head_version: u64,
    pub head_content_hash: [u8; 32],
    pub new_bytes: Vec<u8>,
    pub manifest_bytes: Vec<u8>,
    pub actor_ref: String,
    pub actor_class: u8,
    pub retained_at: u64,
}

impl StrandedEditProposal {
    pub fn manifest(&self) -> Result<EditManifest> {
        EditManifest::from_msgpack(&self.manifest_bytes)
    }
}

/// Recovery payload for a stale-base retained proposal. Key: id16 + hash32(blake3 of the
/// proposal ref).
const STRANDED: SideTable<(EntityId, [u8; 32]), StrandedEditProposal, Named> =
    SideTable::new(&side_table::EDIT_SETTLE_STRANDED_PROPOSAL);

fn key_parts(artifact_id: &EntityId, proposal_ref: &str) -> (EntityId, [u8; 32]) {
    (
        *artifact_id,
        *blake3::hash(proposal_ref.as_bytes()).as_bytes(),
    )
}

impl Vault {
    /// Reads a stale output without making it the head or rebasing its ops.
    pub fn stranded_edit_proposal(
        &self,
        artifact_id: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<StrandedEditProposal>> {
        let txn = self.store.env.read_txn()?;
        let Some(row) = STRANDED.get(&self.store, &txn, &key_parts(artifact_id, proposal_ref))?
        else {
            return Ok(None);
        };
        if row.artifact_ref != artifact_id.to_hex() || row.proposal_ref != proposal_ref {
            return Err(corrupt());
        }
        row.manifest()?;
        Ok(Some(row))
    }

    pub(super) fn retain_stale_edit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        artifact_id: &EntityId,
        proposal: &EditProposal,
        head: &BlobArtifactVersion,
        actor: WriteActor,
        at: u64,
    ) -> Result<StrandedEditProposal> {
        let row = StrandedEditProposal {
            artifact_ref: artifact_id.to_hex(),
            proposal_ref: proposal.run_ref.clone(),
            base_version: proposal.base_version,
            base_content_hash: proposal.base_content_hash,
            head_version: head.version,
            head_content_hash: head.content_hash,
            new_bytes: proposal.new_bytes.clone(),
            manifest_bytes: proposal.manifest.to_msgpack()?,
            actor_ref: actor.entity_ref().to_hex(),
            actor_class: actor.actor_class() as u8,
            retained_at: at,
        };
        STRANDED.put(
            &self.store,
            txn,
            &key_parts(artifact_id, &proposal.run_ref),
            &row,
        )?;
        Ok(row)
    }
}

fn corrupt() -> Error {
    Error::CorruptedIndex("stranded edit proposal")
}
