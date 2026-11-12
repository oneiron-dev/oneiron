//! Doors for `tests/claim_facet_birth.rs` to CLAIM birth sites whose writers
//! are crate-private: the native mailbox record, a native mail reputation
//! report through a client that never connected, and the repo conflict open
//! and resolution claims without git.

use crate::channel_identity_provider::stalwart::{
    NativeMailReputationReport, NativeMailWarmupPolicy, StalwartClient, StalwartConfig,
};
use crate::codebase::RepoRef;
use crate::error::Result;
use crate::{EntityId, Vault};

/// Records `address` as the native mailbox of `identity_ref`.
///
/// # Errors
///
/// The vault's write error, or the mailbox record's own refusal.
#[doc(hidden)]
pub fn record_native_mailbox(
    vault: &Vault,
    identity_ref: EntityId,
    address: &str,
    now: u64,
) -> Result<()> {
    vault.record_native_mailbox_for_test(identity_ref, address, now)
}

/// Publishes `report` for `identity_ref` through a Stalwart client built
/// from `config` that never connected; answers the claim ids written.
///
/// # Errors
///
/// The reputation door's refusal or the vault's write error.
#[doc(hidden)]
pub fn record_reputation(
    vault: &Vault,
    config: StalwartConfig,
    identity_ref: EntityId,
    report: &NativeMailReputationReport,
) -> Result<Vec<EntityId>> {
    StalwartClient::unconnected(config)
        .record_reputation(
            vault,
            identity_ref,
            report,
            NativeMailWarmupPolicy::default(),
            100,
        )
        .map(|update| update.claim_refs)
}

/// Records an open conflict on `branch_subject` between the given base,
/// ours and theirs trees; answers the claim id.
///
/// # Errors
///
/// The conflict value's validation or the vault's write error.
#[doc(hidden)]
pub fn record_open_repo_conflict(
    vault: &Vault,
    repo_ref: &RepoRef,
    branch_subject: EntityId,
    branch: &str,
    trees: [&str; 3],
    paths: Vec<String>,
) -> Result<EntityId> {
    vault.record_open_repo_conflict_for_test(repo_ref, branch_subject, branch, trees, paths)
}

/// Records the resolution of the open conflict `open_conflict` on
/// `branch_subject` at `resolved_tree`; answers the claim id.
///
/// # Errors
///
/// The resolution value's validation or the vault's write error.
#[doc(hidden)]
pub fn put_repo_conflict_resolution(
    vault: &Vault,
    repo_ref: &RepoRef,
    branch_subject: EntityId,
    branch: &str,
    open_conflict: EntityId,
    resolved_tree: &str,
    paths: Vec<String>,
) -> Result<EntityId> {
    vault.put_repo_conflict_resolution_for_test(
        repo_ref,
        branch_subject,
        branch,
        open_conflict,
        resolved_tree,
        paths,
    )
}
