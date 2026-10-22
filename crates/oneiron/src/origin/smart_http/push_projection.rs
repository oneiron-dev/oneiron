//! A push from a masked copy, received into its own private ingress (FIX
//! 7608 slice 2b-ii-A, ASK S).
//!
//! Only an exchange whose ADMITTED caller is bound to a projection (a
//! copy-issued lease, or a masked `git_push` holder) is staged here; the
//! owner, an exact recipient and a store with no readable mark stay on
//! today's receive path byte for byte, chosen before any projection IO.
//! The ingress is seeded from the immutable copy graph and is distinct from
//! the canonical store and from the copy store; the canonical coordinator,
//! anchor, refs, Grant, lease and host epoch stay the authority.
//!
//! Its proof is a `repo.secret_projection` record about the copy graph,
//! durable before any admission evidence: the receive operation, the
//! canonical store, the ingress store and a digest of the canonical
//! authority the G1 admission bound (principal, push arm, Grant, CODE
//! anchor, lease and host authority). Every later seam validates it against
//! the stamp it holds; the physical ingress never stands in for the
//! canonical store. A received update is classified by its old tip and by
//! the copy objects its incoming history reaches: an update that reaches a
//! changed copy object is a proposal; one that reaches none is forwarded
//! exactly to the canonical store. Identity mappings alone prove nothing
//! about a changed copy's ancestry.

#![allow(
    dead_code,
    reason = "FIX 7608: the exact-forward classification waits for its forward arm (FIX line)"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use heed::{RoTxn, RwTxn};

use super::door::DoorAdmissionStamp;
use super::serve_cmd::ServeCommand;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::git_push::GitPushStamp;
use crate::git_wire::GitOid;
use crate::origin::residence::OriginAuthorityStamp;
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionIngress, RepoProjectionRecord,
};
use crate::origin::secret_projection::git::RepoGitProjection;

pub(crate) mod forward;
pub(crate) mod recovery;

use self::recovery::RepoProjectionIngressRecovery;

/// Domain of the canonical authority digest an ingress proof binds.
const INGRESS_AUTHORITY_DOMAIN: &[u8] = b"oneiron.repo_projection.ingress_authority.v1";

/// The proof a projection-bound push is received under: its record about
/// the copy graph, and the private ingress root it names. Only
/// [`prepare_projection_ingress`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoProjectionIngressProof {
    claim: RepoProjectionClaim,
    ingress: RepoProjectionIngress,
    ingress_root: PathBuf,
}

impl RepoProjectionIngressProof {
    /// The proof record's id, which the intent and stamp carry.
    ///
    /// # Errors
    /// A failed id derivation.
    pub(crate) fn id(&self) -> Result<EntityId> {
        self.claim.id()
    }

    /// The copy graph the push was made from.
    pub(crate) const fn graph(&self) -> EntityId {
        self.claim.graph
    }

    /// The private ingress the push is received into.
    pub(crate) fn ingress_root(&self) -> &Path {
        &self.ingress_root
    }

    /// The canonical store the copy stands for.
    pub(crate) const fn canonical_store(&self) -> EntityId {
        self.ingress.canonical_store
    }

    /// The proof recovery reopened from its record, at the physical
    /// ingress `ingress_root` the caller observed (FIX 7608 2b-ii-B2): only
    /// [`validate_projection_ingress_in_txn`] then says whether it stands.
    pub(crate) fn reopen(recovered: RepoProjectionIngressRecovery, ingress_root: &Path) -> Self {
        Self {
            claim: RepoProjectionClaim::of(
                recovered.graph,
                RepoProjectionRecord::Ingress(recovered.ingress.clone()),
            ),
            ingress: recovered.ingress,
            ingress_root: ingress_root.to_path_buf(),
        }
    }

    /// The private ingress store's identity the proof names.
    pub(crate) fn ingress_store(&self) -> &str {
        &self.ingress.ingress_store
    }
}

/// The digest of the canonical authority `stamp` was admitted under: its
/// principal, its push authority (arm, Grant, CODE anchor, checkout and
/// slip binding) and its host authority (lease epoch and writer).
///
/// # Errors
/// An evidence value that does not encode.
fn authority_digest(stamp: &DoorAdmissionStamp) -> Result<[u8; 32]> {
    let mut packed = Vec::new();
    for value in [
        GitPushStamp::evidence_value(stamp.push.as_ref()),
        OriginAuthorityStamp::evidence_value(stamp.origin_authority.as_ref()),
    ] {
        let mut part = Vec::new();
        rmpv::encode::write_value(&mut part, &value)
            .map_err(|_| Error::InvariantViolation("an ingress authority did not encode"))?;
        packed.push(part);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(INGRESS_AUTHORITY_DOMAIN);
    for field in [
        stamp.principal_ref.as_bytes(),
        packed[0].as_slice(),
        packed[1].as_slice(),
    ] {
        hasher.update(&(field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The proof `stamp`, an admitted push on the canonical store
/// `canonical_store`, is received into the private ingress `ingress_store`
/// at `ingress_root` under, for the copy `projection`. Nothing is written.
///
/// # Errors
/// A stamp that admitted no push: only an admitted push is staged.
pub(crate) fn prepare_projection_ingress(
    projection: &RepoGitProjection,
    stamp: &DoorAdmissionStamp,
    canonical_store: EntityId,
    ingress_store: &str,
    ingress_root: &Path,
) -> Result<RepoProjectionIngressProof> {
    if stamp.push.is_none() {
        return Err(Error::InvariantViolation(
            "only an admitted push is received into a projection ingress",
        ));
    }
    let ingress = RepoProjectionIngress {
        operation: stamp.operation_id,
        canonical_store,
        ingress_store: ingress_store.to_owned(),
        authority: authority_digest(stamp)?,
    };
    Ok(RepoProjectionIngressProof {
        claim: RepoProjectionClaim::of(
            projection.graph_id(),
            RepoProjectionRecord::Ingress(ingress.clone()),
        ),
        ingress,
        ingress_root: ingress_root.to_path_buf(),
    })
}

/// Writes `proof`'s record, before any admission evidence of its exchange,
/// and gives its id for the intent to bind.
///
/// # Errors
/// A store failure, or another record under its id.
pub(crate) fn bind_projection_ingress_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proof: &RepoProjectionIngressProof,
    at: u64,
) -> Result<EntityId> {
    proof.claim.put_in_txn(vault, wtxn, at)?;
    proof.id()
}

/// Whether `proof` stands in `txn` exactly as written, for the very
/// operation and canonical authority `stamp` holds.
///
/// # Errors
/// A store failure, or a stamp whose authority does not encode.
pub(crate) fn validate_projection_ingress_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    proof: &RepoProjectionIngressProof,
    stamp: &DoorAdmissionStamp,
) -> Result<bool> {
    Ok(proof.ingress.operation == stamp.operation_id
        && proof.ingress.authority == authority_digest(stamp)?
        && proof.claim.stands_in_txn(vault, txn)?)
}

/// The writable invocation over `proof`'s private ingress: the canonical
/// door's own frozen command, door hook and pinned git, pointed at the
/// ingress the proof names. No new spawn or argv.
///
/// # Errors
/// As [`ServeCommand::http_backend`].
pub(crate) fn ingress_serve_command(
    proof: &RepoProjectionIngressProof,
    project_root: &Path,
    door_hooks_dir: &Path,
) -> Result<ServeCommand> {
    ServeCommand::http_backend_ingress(proof.ingress_root(), project_root, door_hooks_dir)
}

/// What a received update from a masked copy is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceivedProjectionClass {
    /// Its old tip or its incoming history reaches a changed copy object:
    /// a native proposal translated onto the ORIGINAL.
    CopyDerived,
    /// It reaches no changed copy object: forwarded exactly to the
    /// canonical store under its own CAS.
    ExactForward,
}

/// The class of one received update whose old tip is `old`, whose
/// incoming history's boundary parents (the first commits it names that
/// the ingress already held) are `boundary_parents`, given `changed_copies`,
/// every copy object whose bytes differ from its original's. A null old
/// tip with no changed copy parent is a new branch forwarded exactly, as
/// today's rule for a new branch reads it.
pub(crate) fn classify_received_projection(
    changed_copies: &BTreeSet<GitOid>,
    old: Option<&GitOid>,
    boundary_parents: &[GitOid],
) -> ReceivedProjectionClass {
    let copy_derived = old.is_some_and(|old| changed_copies.contains(old))
        || boundary_parents
            .iter()
            .any(|parent| changed_copies.contains(parent));
    if copy_derived {
        ReceivedProjectionClass::CopyDerived
    } else {
        ReceivedProjectionClass::ExactForward
    }
}

/// Where a received update must complete before its final status: the
/// ingress publication a proposal stands on, or the canonical store an
/// exact forward lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReceivedPushTarget {
    /// The private ingress: the push is a proposal's source.
    Ingress,
    /// The canonical store, under the canonical coordinator and CAS.
    Canonical,
}

/// [`ReceivedPushTarget`] of an update of `class`.
pub(crate) const fn complete_received_push_target(
    class: ReceivedProjectionClass,
) -> ReceivedPushTarget {
    match class {
        ReceivedProjectionClass::CopyDerived => ReceivedPushTarget::Ingress,
        ReceivedProjectionClass::ExactForward => ReceivedPushTarget::Canonical,
    }
}
