//! Commit-hash keyed LEDGER change identities. Trailers are hints, never keys.
use crate::code_snapshot::ids::entity_id_from_hash_material;
use crate::git_wire::ids::GitOid;
use crate::origin::actor_erase::ORIGIN_ACTOR_ERASE_PROOF;
use crate::origin::actor_erase::OriginProofErase;
use crate::origin::publication::publication_codec::origin_published_commit_id;
use crate::origin::publication::publication_types::OriginActor;
use crate::origin::publication::publication_types::OriginPublicationRecord;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::claim_body::ClaimSubject;
use crate::write_envelope::claim_body::encode_claim_body;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use oneiron_contracts::entity_id::EntityId;
use rmpv::Value;

pub const ORIGIN_CHANGE_PREDICATE: &str = "repo.change";
pub const ORIGIN_CHANGE_VALUE_KEYS: [&str; 7] = [
    "schema_version",
    "change_id",
    "commit_hash",
    "actor_id",
    "provenance_claim_id",
    "source",
    "ref_name",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginChange {
    pub change_id: EntityId,
    pub claim_id: EntityId,
    pub commit: GitOid,
    pub repo_id: EntityId,
    pub actor_id: OriginActor,
    pub provenance_claim_id: EntityId,
    pub source: String,
    pub ref_name: String,
}
pub fn origin_change_id(repo: EntityId, commit: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:origin-change:v1",
        &[repo.as_bytes(), commit.as_str().as_bytes()],
    )
}
pub fn claim_id(repo: EntityId, commit: &GitOid) -> Result<EntityId> {
    entity_id_from_hash_material(
        b"oneiron:origin-change-claim:v1",
        &[repo.as_bytes(), commit.as_str().as_bytes()],
    )
}
