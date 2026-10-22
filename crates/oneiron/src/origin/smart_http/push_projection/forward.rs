//! A projection-bound update proved not copy-derived, forwarded exactly
//! (FIX 7608 slice 2b-ii-A).
//!
//! Only an update the classification proved reaches no changed copy
//! object, carrying the canonical CAS triple it was pushed with, comes
//! here; the owner and an unmarked store never do. Its record and its
//! marks, carried to the canonical store from the ingress operation that
//! saw the bytes, are written before the canonical publication, which then
//! runs the ordinary canonical intent, authority and CAS under the
//! canonical coordinator. The actual ingress evidence stays linked, never
//! replaced, and each ref's Pending, NotApplied or Superseded is reported
//! as it lands.

use heed::RwTxn;

use super::RepoProjectionIngressProof;
use crate::Vault;
use crate::error::Result;
use crate::git_wire::GitOid;
use crate::origin::secret_marks::{RepoSecretMark, readdress_forward_secret_marks_in_txn};
use crate::origin::secret_projection::claims::{
    RepoProjectionClaim, RepoProjectionExactForward, RepoProjectionRecord,
};

/// One exact forward: the canonical ref and the old and new tips the push
/// named, the old one the canonical CAS expects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactForwardPlan {
    pub(crate) ref_name: String,
    pub(crate) old: Option<GitOid>,
    pub(crate) new: GitOid,
}

/// Records `plan` under `proof` and carries the ingress's `marks` to the
/// canonical store (`canonical_identity`), in the writer that precedes the
/// canonical publication. Says whether the forward record was new.
///
/// # Errors
/// A store failure, a failed id derivation, or another record under an id.
pub(crate) fn forward_exact_received_push_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    proof: &RepoProjectionIngressProof,
    plan: &ExactForwardPlan,
    marks: &[RepoSecretMark],
    canonical_identity: &str,
    at: u64,
) -> Result<bool> {
    // The marks land on the canonical store first, in this same writer.
    let mark_ids = readdress_forward_secret_marks_in_txn(
        vault,
        wtxn,
        marks,
        proof.canonical_store(),
        canonical_identity,
    )?;
    let record = RepoProjectionClaim::of(
        proof.graph(),
        RepoProjectionRecord::ExactForward(RepoProjectionExactForward {
            operation: proof.ingress.operation,
            ref_name: plan.ref_name.clone(),
            old: plan.old.clone(),
            new: plan.new.clone(),
            marks: mark_ids,
        }),
    );
    record.put_in_txn(vault, wtxn, at)
}
