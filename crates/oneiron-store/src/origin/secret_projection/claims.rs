//! A masked Git copy's record (FIX 7608 slice 2b-i, CALL M): value-free
//! `repo.secret_projection` claims at schema 1, one claim per record, no
//! table and no restore row.
//!
//! The graph record names the copy: the canonical store, the frozen roots
//! it copies (each Published ref's original, and a lease's private original
//! when one is admitted), the audience, the payload policy and lifetime,
//! and every readable mark it was made under. Its id is derived from all of
//! that, so a copy made under other roots or other marks is another copy.
//! Its subject is the edge `graph PartOf store`, as a mark's is, in the
//! masked-file band. Every other record (an object's original and copy, a
//! root ref's copy, the private root's copy, and each place a changed
//! object occurs in a changed parent) is about the graph claim itself, so
//! the graph's erasure reaches each of them, and each is idempotent at its
//! derived id: the same record writes nothing, another under its id
//! refuses.
//!
//! No record carries a secret byte, an excerpt, a hash of a key, or a hash
//! of any content: object ids, ref names, tree entry names, mark ids and
//! the store identity only. Identity mappings are recorded too, so every
//! copy object names its original; a copy object may stand for several
//! originals, and nothing reads a newest or equal-content guess into it.
//! Each copy commit also names every original it stands for in one keyed
//! record (FIX 10275), so a received push's base is one read.

#![allow(
    dead_code,
    reason = "FIX 7608: some records are read only by later slices"
)]

use heed::{RoTxn, RwTxn};

pub mod codec;
use rmpv::Value;

use crate::origin::secret_projection::claims::codec::decode_place;
use crate::origin::secret_projection::claims::codec::digest_of;
use crate::origin::secret_projection::claims::codec::digest_value;
use crate::origin::secret_projection::claims::codec::entity;
use crate::origin::secret_projection::claims::codec::field;
use crate::origin::secret_projection::claims::codec::fields;
use crate::origin::secret_projection::claims::codec::git_oid;
use crate::origin::secret_projection::claims::codec::occurrence_value;
use crate::origin::secret_projection::claims::codec::oid;
use crate::origin::secret_projection::claims::codec::packed;
use crate::origin::secret_projection::claims::codec::place_value;
use crate::origin::secret_projection::claims::codec::text;

use crate::code_snapshot::ids::entity_id_from_hash_material;
use crate::git_wire::ids::GitOid;
use crate::git_wire::retained_object::GitObjectKind;
use crate::write_envelope::claim_body::ClaimBody;
use crate::write_envelope::claim_body::ClaimSubject;
use oneiron_base::edge::EdgeKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::temporal::TimeRange;

/// The predicate of every masked Git copy record.
pub const REPO_SECRET_PROJECTION_PREDICATE: &str = "repo.secret_projection";

/// The derivation domain of a record's id.
pub const REPO_SECRET_PROJECTION_DOMAIN: &[u8] = b"oneiron:repo-secret-projection:v1";

/// Where a changed object occurs in a changed parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoProjectionPlace {
    /// A tree entry, by its stored mode and name bytes.
    TreeEntry { mode: u32, name: Vec<u8> },
    /// A commit's tree.
    CommitTree,
    /// A commit's parent at this position.
    CommitParent { index: u32 },
    /// A tag's target.
    TagTarget,
}

/// A checkout lease bound to a copy: the lease's checkout and epoch, its
/// holder, the ORIGINAL it pins and the copy commit it checks out. Its id
/// is derived from the checkout and epoch alone, so the lease finds it;
/// it is about the graph, so the graph's erasure reaches it. Ids only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionCheckout {
    pub checkout: String,
    pub epoch: u64,
    pub holder: String,
    pub original: GitOid,
    pub copy: GitOid,
}

/// The private ingress seeded from a copy: its object-store identity and
/// the canonical store it stands for. Its id is derived from the ingress
/// identity alone, so a received row's store finds its copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionIngressStore {
    pub ingress_store: String,
    pub canonical_store: EntityId,
}

/// A received copy change's translation: its candidate and operation, the
/// submitted COPY tip, the ORIGINAL base it maps onto, the canonical
/// target tree it resolved (none while it holds) and its pins' digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionTranslation {
    pub candidate: EntityId,
    pub operation: EntityId,
    pub submitted_new: GitOid,
    pub canonical_base: GitOid,
    pub canonical_target: Option<GitOid>,
    pub pins: [u8; 32],
}

/// The owner's settlement of one held projected edit: the candidate, the
/// cause, the digest of the exact file set it settles, the canonical
/// target it approved and the owner who approved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionClearance {
    pub candidate: EntityId,
    pub cause: String,
    pub files: [u8; 32],
    pub target: Option<GitOid>,
    pub owner: EntityId,
}

/// One exact forward: the receive operation, the ref, its canonical old
/// and new tips and the marks carried to the canonical store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProjectionExactForward {
    pub operation: EntityId,
    pub ref_name: String,
    pub old: Option<GitOid>,
    pub new: GitOid,
    pub marks: Vec<EntityId>,
}

pub fn corrupt() -> Error {
    Error::CorruptedIndex("a masked copy record does not decode")
}

/// The identity an object record's id is derived from.
pub fn object_key(original: &GitOid, occurrence: Option<&[u8]>) -> Value {
    Value::Array(vec![
        Value::from("object"),
        oid(original),
        occurrence_value(occurrence),
    ])
}

/// The identity a copy commit's originals record's id is derived from.
pub fn commit_originals_key(copy: &GitOid) -> Value {
    Value::Array(vec![Value::from("commit_originals"), oid(copy)])
}

/// The identity a checkout recipient's id is derived from.
pub fn checkout_recipient_key(checkout: &str, epoch: u64) -> Value {
    Value::Array(vec![
        Value::from("checkout_recipient"),
        Value::from(checkout),
        Value::from(epoch),
    ])
}

/// The identity a checkout binding's id is derived from.
pub fn checkout_key(checkout: &str, epoch: u64) -> Value {
    Value::Array(vec![
        Value::from("checkout"),
        Value::from(checkout),
        Value::from(epoch),
    ])
}

/// The identity an ingress store's record id is derived from.
pub fn ingress_store_key(ingress_store: &str) -> Value {
    Value::Array(vec![
        Value::from("ingress_store"),
        Value::from(ingress_store),
    ])
}
