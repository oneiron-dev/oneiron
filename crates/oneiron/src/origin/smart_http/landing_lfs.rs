//! LFS pointer admission and the per-ref tree walk that attaches pointers to the
//! refs that carry them.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use super::door_window::printable_ref_name;
use super::evidence::RefUpdate;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitTreeEntry, GitWire, GitWireRepo};
use crate::origin::lfs::{
    DefaultRepositoryLargeLfsPathPolicy, LfsAdmission, LfsOid, LfsPointerIntent, LfsPushedPointer,
};

/// The admitted LFS objects one advancing ref's own tree actually carries.
///
/// The publication gate is per-REF, so an object that another branch of the
/// same push introduced must not gate this one: over-requiring would record a
/// false dependency and could later de-advertise a head for bytes it never
/// needed. Empty for every push that carries no LFS content, which is the
/// common case and reads no tree at all.
pub(super) fn ref_required_lfs_oids(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    admitted: &[LfsPointerIntent],
    tip: &GitOid,
) -> Result<Vec<(LfsOid, u64)>> {
    if admitted.is_empty() || !ref_tip_is_tree_ish(wire, handle, tip)? {
        return Ok(Vec::new());
    }
    let mut trees = BTreeMap::new();
    let mut required = Vec::new();
    for intent in admitted {
        if ref_tree_carries_path(wire, handle, &mut trees, tip, &intent.path)? {
            required.push((intent.oid, intent.size_bytes));
        }
    }
    Ok(required)
}

/// Classifies this landing's pointers and returns the ones that publish.
///
/// `KeepInGit` is dropped silently and on purpose: a build-required asset stays
/// ordinary Git content, so it publishes as itself, gets no durable ref
/// attachment, and any staged upload of it stays unreferenced and collectible.
/// `StoreInLfs` demands its bytes: publishing a pointer whose object is absent
/// would advertise a head that fails checkout, which is the one outcome
/// ARCH-0068 forbids outright.
pub(super) fn admit_landing_lfs_pointers(
    vault: &Vault,
    repo_id: EntityId,
    pointers: &[LfsPushedPointer],
) -> Result<Vec<LfsPointerIntent>> {
    if pointers.is_empty() {
        return Ok(Vec::new());
    }
    let policy = DefaultRepositoryLargeLfsPathPolicy;
    let mut admitted = Vec::new();
    for pointer in pointers {
        let intent = pointer.intent(repo_id);
        match vault.admit_lfs_pointer(&policy, &intent)? {
            LfsAdmission::KeepInGit => continue,
            LfsAdmission::StoreInLfs => {
                if !vault.has_lfs_object(intent.oid, intent.size_bytes)? {
                    return Err(Error::ReceivePackLandingRefused {
                        reason: format!(
                            "lfs object for {} is not stored in this vault",
                            printable_ref_name(&intent.path)
                        ),
                    });
                }
                admitted.push(intent);
            }
        }
    }
    Ok(admitted)
}

/// Records which refs now reference which LFS objects, and unrecords the ones
/// a ref stopped referencing by ceasing to exist.
///
/// The attachment family is a per-REF index, so this function owns both
/// directions of it:
///
/// - **A realized deletion detaches.** The ref the update names is gone from
///   the repository, so every row that named it is now a claim about nothing.
///   Only rows go: an object another ref still references keeps its bytes, and
///   so does an object no ref references at all — this is not a collector.
/// - **An update attaches by the ref's OWN tree.** An admitted pointer belongs
///   to the refs whose new tree actually carries its path, which is why the new
///   tree is walked rather than assumed. Attaching every admitted object to
///   every moved ref would let one branch's asset become a permanent claim on
///   every other branch that happened to travel in the same push.
///
/// An update never REMOVES a row. `admitted` is what THIS push introduced, not
/// an inventory of what the ref's tree carries: a commit that touches no
/// pointer admits nothing, and replacing a ref's rows with that empty set would
/// erase attachments that are still true. Rows are dropped when the ref itself
/// goes, and there only.
///
/// A `BuildRequired` path is absent from `admitted` and so stays unattached,
/// whatever tree carries it.
pub(super) fn attach_landing_lfs_pointers(
    vault: &Vault,
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    repo_id: EntityId,
    updates: &[RefUpdate],
    admitted: &[LfsPointerIntent],
    learned_at: u64,
) -> Result<()> {
    let mut trees = BTreeMap::new();
    for update in updates {
        let Some(new_oid) = update.new_oid.as_ref() else {
            vault.detach_lfs_objects_from_git_ref(repo_id, &update.name)?;
            continue;
        };
        // A push that introduced no publishable pointer reads no tree at all,
        // which is every push that carries no LFS content.
        if admitted.is_empty() || !ref_tip_is_tree_ish(wire, handle, new_oid)? {
            continue;
        }
        for intent in admitted {
            if !ref_tree_carries_path(wire, handle, &mut trees, new_oid, &intent.path)? {
                continue;
            }
            vault.attach_lfs_object_to_git_ref(repo_id, &update.name, intent.oid, learned_at)?;
        }
    }
    Ok(())
}

/// The tree-entry mode of a subdirectory.
const GIT_TREE_MODE: u32 = 0o040_000;

/// The tree-entry mode of a gitlink: a commit that lives in another repository,
/// so this repository holds no blob for that path.
const GIT_GITLINK_MODE: u32 = 0o160_000;

/// Whether a ref's post-image can be read as a tree at all.
///
/// A commit and an annotated tag both peel to the tree the ref publishes. A ref
/// that names a blob has no tree and therefore carries no path — an answer,
/// deliberately, rather than a failure: the refs have already moved by the time
/// this runs, and an odd but legal ref value must not turn a landed push into
/// an error.
fn ref_tip_is_tree_ish(wire: &GitWire<'_>, handle: &GitWireRepo, tip: &GitOid) -> Result<bool> {
    let kinds = wire.object_info(handle, std::slice::from_ref(tip))?;
    Ok(matches!(
        kinds.get(tip).map(String::as_str),
        Some("commit" | "tag" | "tree")
    ))
}

/// Whether the tree `tip` publishes carries `path` as a file of this
/// repository.
///
/// Component by component, so a path is present only where the directories
/// leading to it are directories and the leaf is a blob this repository holds:
/// a directory of that name, or a gitlink of that name, is not the pointer
/// file.
fn ref_tree_carries_path(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    trees: &mut BTreeMap<String, Vec<GitTreeEntry>>,
    tip: &GitOid,
    path: &str,
) -> Result<bool> {
    let mut current = tip.clone();
    let mut components = path.split('/').peekable();
    while let Some(component) = components.next() {
        if component.is_empty() {
            return Ok(false);
        }
        let entries = read_tree_entries(wire, handle, trees, &current)?;
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.name == component.as_bytes())
        else {
            return Ok(false);
        };
        let mode = entry.mode;
        if components.peek().is_none() {
            return Ok(mode != GIT_TREE_MODE && mode != GIT_GITLINK_MODE);
        }
        if mode != GIT_TREE_MODE {
            return Ok(false);
        }
        current = entry.oid.clone();
    }
    Ok(false)
}

/// The direct entries of one tree, read once per landing.
///
/// Refs pushed together share directories, and so do the pointers within one
/// ref. The memo is what keeps a many-pointer push from re-reading the same
/// tree once per pointer per ref; it lives for the one landing that built it
/// and asserts nothing about any later one.
fn read_tree_entries<'trees>(
    wire: &GitWire<'_>,
    handle: &GitWireRepo,
    trees: &'trees mut BTreeMap<String, Vec<GitTreeEntry>>,
    tree: &GitOid,
) -> Result<&'trees [GitTreeEntry]> {
    let entries = match trees.entry(tree.as_str().to_owned()) {
        Entry::Occupied(occupied) => occupied.into_mut(),
        Entry::Vacant(vacant) => vacant.insert(wire.read_tree(handle, tree)?),
    };
    Ok(entries.as_slice())
}
