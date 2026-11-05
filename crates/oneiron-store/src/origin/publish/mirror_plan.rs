//! Freezing one automatic mirror push plan (FIX 6866 part 2; CALLS "FIX 6866
//! automatic review record" and "FIX 6866 automatic unknown tip").
//!
//! Before anything goes out, a `schedule` or `full_auto` run reads every ref
//! it would touch at the mirror with the mirror's own credential, reviews
//! each update (`mirror_review`), cuts the refs into the mirror push's
//! batches (updates first, then deletions, at most 256 a batch), binds it
//! all in one digest and writes it in one transaction, fenced on the mirror
//! row it read and refused while another plan is open. No approval step:
//! the strategy is the standing authority, and the review is its record. A
//! read that fails marks each ref `unknown`, so it goes unleased and its
//! section covers the whole closure: never a guessed absence and never a
//! hold. A review or plan write that fails ends the run before any ref goes
//! out (the caller's hold).

use std::path::Path;

use crate::git_wire::ids::GitOid;
use crate::git_wire::ids::GitRefName;
use crate::git_wire::mirror_push::MIRROR_PUSH_REFSPECS;
use crate::git_wire::repo::GitWireRepo;
use crate::origin::mirror::OriginMirrorTarget;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use crate::origin::publish::mirror_plan_types::MirrorBatchClaim;
use crate::origin::publish::mirror_plan_types::MirrorBatchProgress;
use crate::origin::publish::mirror_plan_types::MirrorObservedTip;
use crate::origin::publish::mirror_plan_types::MirrorPendingHead;
use crate::origin::publish::mirror_plan_types::MirrorRefOutcome;
use crate::origin::publish::review::field;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// A plan digest's BLAKE3 derive-key context.
pub const ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-plan:v1";

/// A vector digest's BLAKE3 derive-key context.
const ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-vector:v1";

/// What one run would send: each `(ref, object)` pushed, in published order,
/// each ref deleted, and each full-auto head held for checks with the green
/// ancestor sent in its place, if any.
pub struct MirrorSelection {
    pub vector: Vec<(GitRefName, GitOid)>,
    pub deletions: Vec<GitRefName>,
    pub pending: Vec<(GitRefName, GitOid, Option<GitOid>)>,
}

impl MirrorSelection {
    /// The digest of what the selection sends, which a full-auto mirror
    /// compares with the plan it settled last.
    pub fn vector_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT);
        for (name, oid) in &self.vector {
            field(&mut hasher, name.as_str().as_bytes());
            field(&mut hasher, oid.as_str().as_bytes());
        }
        hasher.update(b"d");
        for name in &self.deletions {
            field(&mut hasher, name.as_str().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

pub fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
