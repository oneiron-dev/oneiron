//! The owner's promote of a task-type tree onto the vault team-shape head
//! (`vault.task_types.promote`; ARCH-0079 #seed-pin; lead
//! COORD-E2E-TREE-PIN = A, 24 Nov 2026 22:45). The owner's pin is fixed, a
//! seed of infinite weight, so it goes in force at once and waits on no
//! gate: one write reads the tree, mints a same-skill revision of the head
//! carrying it, marks that revision owner-pinned and supersedes the head
//! ([`crate::Vault::admit_owner_tree_revision_in_txn`]). The Coach proposes
//! over a pinned head and never replaces it; the owner reverts through this
//! same door, and the restored tree stays pinned.

use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::skill::SkillLifecycle;
use crate::skill_hub::OwnerTreeOrigin;
use crate::task_type::{TaskTypeTree, TreeScope};

use super::{
    Reads, in_lineage_in_txn, invalid, same_structure, stored_tree_in_txn,
    stored_tree_unchecked_in_txn, supersession_chain_in_txn, team_shape_root_in_txn,
    vault_head_in_txn,
};

/// Where a promoted tree comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreePromoteSource {
    /// The tree the owner's `vault.task_types.pin` stored on the open fork
    /// `fork`, at the version that pin stored it at, unchanged since.
    Pin { fork: EntityId, tree_version: u64 },
    /// The tree the earlier revision `revision` on the vault's team-shape
    /// chain carried; the seed when it carried none.
    Restore { revision: EntityId },
}

/// What one promote put in force.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TreePromoted {
    /// The head the promote superseded.
    pub(crate) previous: EntityId,
    /// The new head, owner-pinned.
    pub(crate) head: EntityId,
    /// The tree the new head carries, in force for the vault.
    pub(crate) tree: TaskTypeTree,
}

/// Puts the tree `source` names in force for the vault as `owner`, in one
/// write: the tree is read and checked in that write, then
/// [`crate::Vault::admit_owner_tree_revision_in_txn`] admits the owner's
/// revision of the head in force and supersedes it. A pin takes the fork's
/// stored tree at exactly the version named, scoped to the vault, not behind
/// the tree in force, and with a version no other structure on the vault
/// chain or the seed holds. A restore takes an earlier revision's tree as it
/// was placed in, at its own version.
///
/// # Errors
///
/// [`ArtifactError::InvalidAgentDispatchInput`] when the vault has no head
/// in force or a check above fails; [`ArtifactError::SkillPackageUnavailable`]
/// for a revision whose package this vault no longer holds; the admission's
/// refusals, a stale or non-owner proof among them; storage errors.
pub(crate) fn promote_team_type_tree(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    source: TreePromoteSource,
    at: u64,
) -> Result<TreePromoted> {
    vault.with_write_txn_grouped(|txn| {
        let root = team_shape_root_in_txn(vault, txn)?;
        let previous = vault_head_in_txn(vault, txn, root, &mut Reads::Off)?
            .ok_or_else(|| invalid("the vault has no team-shape skill in force to promote onto"))?;
        let chain = supersession_chain_in_txn(vault, txn, root)?;
        let (tree, origin) = match source {
            TreePromoteSource::Pin { fork, tree_version } => {
                let in_force = stored_tree_in_txn(vault, txn, &previous, &mut Reads::Off)?
                    .unwrap_or_else(TaskTypeTree::seeded);
                let tree = staged_tree_in_txn(vault, txn, root, fork, tree_version)?;
                if tree.version < in_force.version {
                    return Err(invalid(
                        "a promoted tree never moves the vault tree's version backwards; a revert restores an earlier revision",
                    ));
                }
                for kept in chain_trees_in_txn(vault, txn, &chain)? {
                    if kept.version == tree.version && !same_structure(&kept, &tree) {
                        return Err(invalid(
                            "the tree's version already names another structure on the vault chain; pin it again",
                        ));
                    }
                }
                (tree, OwnerTreeOrigin::Pin(fork))
            }
            TreePromoteSource::Restore { revision } => {
                if revision == previous || !chain.contains(&revision) {
                    return Err(invalid(
                        "a revert restores an earlier revision on the vault's team-shape chain",
                    ));
                }
                let tree = kept_tree_in_txn(vault, txn, &revision)?;
                (tree, OwnerTreeOrigin::Restore(revision))
            }
        };
        let head = vault.admit_owner_tree_revision_in_txn(txn, owner, &previous, &tree, origin, at)?;
        Ok(TreePromoted {
            previous,
            head,
            tree,
        })
    })
}

/// [`super::store_team_type_tree`] as the owner's `vault.task_types.pin` stores
/// it: in the same write, the stored tree is staged as the owner's, the one
/// tree `vault.task_types.promote` takes from `fork` while the fork's
/// package stays as this write left it. The Coach's own fork writes store
/// through [`super::store_team_type_tree`] and stage nothing.
///
/// # Errors
///
/// As [`super::store_team_type_tree`].
pub(crate) fn store_owner_team_type_tree(
    vault: &Vault,
    fork: EntityId,
    tree: &TaskTypeTree,
    project: Option<EntityId>,
    at: u64,
) -> Result<u64> {
    super::validate_tree(tree)?;
    vault.with_write_txn_grouped(|txn| {
        let version = super::store_team_type_tree_in_txn(vault, txn, fork, tree, project, at)?;
        vault.stage_owner_tree_in_txn(txn, &fork, version)?;
        Ok(version)
    })
}

/// The tree `vault.task_types.pin` stored on `fork`: an open local fork in
/// the team-shape lineage holding a vault-scoped tree at `tree_version`,
/// which the owner's last pin on that fork stored at that version and which
/// no write has changed since (the pin's stage, checked against the fork's
/// package hash). A tree the fork holds some other way, the seed copied at
/// its birth or a tree the Coach stored there, is never promoted.
fn staged_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    fork: EntityId,
    tree_version: u64,
) -> Result<TaskTypeTree> {
    let record = vault.read_skill_record_in_txn(txn, &fork)?;
    if record.forked_from.is_none() || record.lifecycle_status != SkillLifecycle::Candidate {
        return Err(invalid(
            "a promoted tree comes from the open fork vault.task_types.pin stored it on",
        ));
    }
    if !in_lineage_in_txn(vault, txn, fork, root)? {
        return Err(invalid("fork is not in the team-shape skill's lineage"));
    }
    if !vault.owner_staged_tree_in_txn(txn, &fork, &record, tree_version)? {
        return Err(invalid(
            "a promoted tree is the one the owner's vault.task_types.pin stored on this fork at this version, unchanged since; pin it again",
        ));
    }
    let tree = stored_tree_unchecked_in_txn(vault, txn, &fork, &mut Reads::Off)?
        .ok_or_else(|| invalid("the fork holds no stored task-type tree"))?;
    if tree.version != tree_version {
        return Err(invalid(
            "the fork's tree is at another version; promote the version vault.task_types.pin returned",
        ));
    }
    if !matches!(tree.scope, TreeScope::Vault) {
        return Err(invalid("a promoted tree is scoped to the vault"));
    }
    Ok(tree)
}

/// The seed and every tree a revision on `chain` carries, each as it was
/// placed in. A revision whose tree does not read is skipped: it names no
/// version.
fn chain_trees_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    chain: &[EntityId],
) -> Result<Vec<TaskTypeTree>> {
    let mut trees = vec![TaskTypeTree::seeded()];
    for revision in chain {
        if vault.get_skill_record_in_txn(txn, revision)?.is_some()
            && let Ok(Some(tree)) =
                stored_tree_unchecked_in_txn(vault, txn, revision, &mut Reads::Off)
        {
            trees.push(tree);
        }
    }
    Ok(trees)
}

/// The tree `revision` carried, the seed when its package carries none.
fn kept_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    revision: &EntityId,
) -> Result<TaskTypeTree> {
    let record = vault.read_skill_record_in_txn(txn, revision)?;
    if record.content_hash.is_some()
        && vault
            .runtime_skill_package_in_txn(txn, revision, &record)?
            .is_none()
    {
        // A revision whose package is gone has no tree to restore; the seed
        // would be a guess.
        return Err(Error::Artifact(ArtifactError::SkillPackageUnavailable {
            revision: *revision,
        }));
    }
    Ok(
        stored_tree_unchecked_in_txn(vault, txn, revision, &mut Reads::Off)?
            .unwrap_or_else(TaskTypeTree::seeded),
    )
}
