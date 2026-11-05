//! Reviewed file-operation identity and received bundle input vocabulary.

use std::collections::BTreeMap;

use crate::code_snapshot::ids::entity_id_from_hash_material;
use crate::git_wire::ids::GitOid;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum RepoProposalStatus {
    Proposed,
    Approved,
    Applied,
    Failed,
    Rejected,
    /// Its handles were resolved into a successor proposal (FIX 2938),
    /// which `resolves` is named from here backwards: the successor lands,
    /// this row never does.
    Superseded,
}

/// The complete reviewed operation identity. File bytes remain on `RepoProposal`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepoProposalOperation {
    CommitFile,
    ResolveConflictFile {
        #[serde(with = "entity_serde")]
        branch_subject: EntityId,
        #[serde(with = "entity_serde")]
        open_conflict_claim_id: EntityId,
        branch_name: String,
    },
    /// Every file of one accepted pushed ref update, as ONE reviewed
    /// bundle (G4 PR2): it lands through its merge queue only.
    ReceivedFiles {
        #[serde(with = "entity_serde")]
        candidate: EntityId,
    },
    /// Every file of one native reviewed bundle (FIX 7608 slice 5), each
    /// with its exact state change: it lands through its merge queue only.
    CommitFiles,
}

/// One reviewed file of a proposal. An ordinary operation's file has its
/// bytes and no source; a received bundle's names its source operation
/// and its exact Git state change, and `None` bytes remove it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoProposedFile {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub source_operation: Option<EntityId>,
    pub metadata_edit: Option<crate::code_document_values::CodeFileMetadataEdit>,
    /// A secret remediation's file its base withholds: the BLAKE3 of the
    /// bytes the remediation read at the pinned commit, which the merge
    /// queue checks the tested tree against, so no old byte is stored
    /// (FIX 10974).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_base_blake3: Option<[u8; 32]>,
}

impl RepoProposedFile {
    /// An ordinary operation's one file.
    #[must_use]
    pub fn ordinary(path: String, content: Vec<u8>) -> Self {
        Self {
            path,
            content: Some(content),
            source_operation: None,
            metadata_edit: None,
            withheld_base_blake3: None,
        }
    }
}

/// What one resolved candidate proposes: its deterministic identities,
/// the queue's folder and the exact base commit, its pusher, fork and push
/// provenance, and every file with its exact state change.
pub struct ReceivedFilesProposalInput {
    pub candidate: EntityId,
    pub proposal: EntityId,
    pub folder: String,
    pub base_commit: GitOid,
    pub pusher: EntityId,
    pub session: EntityId,
    pub provenance: EntityId,
    pub message: String,
    pub files: Vec<RepoProposedFile>,
    pub created_at: u64,
    /// Each file translated from a masked copy, by path, with its canonical
    /// ORIGINAL's own key bytes (FIX 10276): the only secret its custody
    /// check admits. Empty for every ordinary push.
    pub original_spans: BTreeMap<String, Vec<Vec<u8>>>,
}

/// The deterministic id of a received bundle's proposal.
///
/// # Errors
/// An id derivation failure.
pub fn received_proposal_id(candidate: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:push-candidate-proposal:v1",
        &[candidate.as_bytes()],
    )
}

/// The deterministic document operation one bundle file lowers to, distinct
/// from the receive audit's own operation ids.
///
/// # Errors
/// An id derivation failure.
pub fn received_file_operation(proposal: EntityId, source: EntityId) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:push-candidate-file-op:v1",
        &[proposal.as_bytes(), source.as_bytes()],
    )
}

/// One entry of a received bundle's tree change: its path, its exact new
/// bytes (`None` removes it) and its Git mode once present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedTreeEdit {
    pub path: String,
    pub content: Option<Vec<u8>>,
    pub mode: u32,
}

pub mod entity_serde {
    use oneiron_contracts::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(id: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&id.to_hex())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        EntityId::from_hex(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
