//! Door for `tests/fingerprint_keep_git_wire.rs` (PLAN-UC-04 3.3): the two git-wire digests
//! the engine computes in private code, and what the plan hash reads of a plan.

use std::path::Path;

use oneiron_store::git_wire::plan::PlannedPublication;

use crate::git_wire::{GitOid, GitWireObjectWrite, GitWireOperation, GitWirePlan, GitWireResult};

/// The plan hash staging keys `plan` by.
///
/// # Errors
/// As staging: an object write whose argv does not build.
pub fn plan_hash(plan: &GitWirePlan) -> GitWireResult<[u8; 32]> {
    plan.plan_hash_for_test()
}

/// What the plan hash reads of `plan`: its object writes, its existing objects and its
/// publications.
#[must_use]
pub fn plan_parts(plan: &GitWirePlan) -> (&[GitWireObjectWrite], &[GitOid], &[PlannedPublication]) {
    plan.parts_for_test()
}

/// What the plan hash reads of one object write's frozen argv: its operation and its stdin.
///
/// # Errors
/// An argv that does not build.
pub fn object_argv(
    write: &GitWireObjectWrite,
) -> GitWireResult<(GitWireOperation, Option<Vec<u8>>)> {
    write.argv_parts_for_test()
}

/// A worktree handle's scope hash.
#[must_use]
pub fn worktree_scope(path: &Path) -> [u8; 32] {
    crate::git_wire::worktree_scope_for_test(path)
}
