//! A proven recipient's granted Git copy (FIX 7608 pre-flip, FIX 9328;
//! CALLs GIT-REVEAL-OPT-IN, GIT-REVEAL-OCCURRENCES).
//!
//! A masked reader that says why it needs a marked file's real bytes, and
//! whose host proved who it is, may read a sibling of its masked copy:
//! the same roots and marks, with each file a live standing grant covers
//! for that recipient at its stored bytes and every other marked blob
//! masked. The plan is found from the masked copy's own records (each
//! changed link and marked blob it recorded), so no object is read to
//! find it, and each file is the exact byte path and ORIGINAL blob it
//! occurs at across history: the same path and blob are planned once, and
//! one blob at two paths is two files, each judged by its own grant. A
//! path that is not text, a tag's direct target and a blob no readable
//! mark names in this store are files no grant target can name; they stay
//! masked, and nothing is refused.
//!
//! The sibling is keyed by the recipient and its sorted released files,
//! never by a reason or a receipt, so an advertisement and the exchange
//! after it read the one copy. Making it releases nothing: every exchange
//! that sends objects first delivers each released file afresh through
//! the shipped file reveal (`recipient_serve::delivery`), and a file whose
//! grant is gone by then is masked in another sibling. Checkout, index,
//! sync, hydrate and every other masked reader keep the masked copy.
//!
//! A file's keys are its marks' and, past them, each custody record whose
//! value custody knows now reads in its stored bytes (FIX 8966): a grant
//! must cover every class among them before the file is released, so a
//! value learned after the grant leaves the file masked. Planning reads
//! each planned file's stored bytes once for this, and nothing else.

use std::collections::{BTreeSet, HashSet};

use zeroize::Zeroizing;

use super::super::claims::{
    RepoProjectionAudience, RepoProjectionClaim, RepoProjectionPlace, RepoProjectionRecord,
};
use super::super::graph_objects::{RepoProjectionRelease, copy_repo_projection_objects};
use super::super::recipient::RepoProjectionRevealBinding;
use super::super::repo_file_keys_in_txn;
use super::{
    RepoGitProjection, RepoGitProjectionRoots, building_dir, building_lock,
    closure_marks_stand_in_txn, land_copy, require_store_not_erased, standing_projection,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::GitPushRepo;
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo};
use crate::origin::RepoPortableId;
use crate::origin::secret_marks::{
    RepoBlobAddress, RepoBlobMarks, RepoMarkFacts, RepoSecretMarkLookup,
};
use crate::origin::secret_projection::RepoRevealRecipient;
use crate::secret_custody::RepoFileRevealTarget;
use crate::secret_record::{RepoFileKeys, RepoFileOriginal};

/// One marked file a recipient's live grant covers: its exact byte path
/// and ORIGINAL blob, the ORIGINAL its grant target names, its marks, and
/// the keys a release of its stored bytes shows (FIX 8966), value-free.
#[derive(Debug, Clone)]
pub(crate) struct RepoGitReleasedFile {
    pub(crate) path: Vec<u8>,
    pub(crate) blob: GitOid,
    pub(crate) original: RepoFileOriginal,
    pub(crate) marks: RepoBlobMarks,
    pub(crate) keys: RepoFileKeys,
}

impl RepoGitReleasedFile {
    /// The grant target this file is judged and delivered under.
    pub(crate) fn target(&self, binding: &RepoProjectionRevealBinding) -> RepoFileRevealTarget {
        RepoFileRevealTarget::new(&self.original, &binding.asker())
    }

    /// Its keys, value-free: its marks' and each known holder past them.
    pub(crate) fn keys(&self) -> RepoFileKeys {
        self.keys.clone()
    }
}

/// What one recipient's exchange on a masked copy may release.
#[derive(Debug, Clone)]
pub(crate) struct RepoGitReleasePlan {
    binding: RepoProjectionRevealBinding,
    files: Vec<RepoGitReleasedFile>,
}

impl RepoGitReleasePlan {
    /// The recipient it is planned for.
    pub(crate) const fn binding(&self) -> &RepoProjectionRevealBinding {
        &self.binding
    }

    /// Each released file, by path then blob.
    pub(crate) fn files(&self) -> &[RepoGitReleasedFile] {
        &self.files
    }

    /// This plan keeping only the files `keep` answers yes for.
    pub(crate) fn retain<F: FnMut(&RepoGitReleasedFile) -> bool>(mut self, keep: F) -> Self {
        self.files.retain(keep);
        self
    }

    /// Whether it releases nothing: the recipient reads the masked copy.
    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Each released file's exact byte path and ORIGINAL blob, sorted:
    /// what its copy is keyed by.
    pub(crate) fn release(&self) -> RepoProjectionRelease {
        self.files
            .iter()
            .map(|file| (file.path.clone(), file.blob.clone()))
            .collect()
    }
}

/// The files of the masked copy `masked` of `canonical` a live standing
/// grant covers for `binding` now, each its exact path and blob, judged by
/// its marks' keys and the holders of the values custody knows in its
/// stored bytes (module docs); `None` when it covers none, which keeps the
/// masked read.
///
/// # Errors
/// A store or git failure, or a record or mark that does not decode.
pub(crate) fn plan_repo_git_release(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    masked: &RepoGitProjection,
    binding: RepoProjectionRevealBinding,
) -> Result<Option<RepoGitReleasePlan>> {
    let RepoProjectionRecord::Graph {
        store_identity,
        store_id,
        audience: RepoProjectionAudience::Masked,
        ..
    } = &masked.graph.record
    else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    let found = RepoProjectionClaim::masked_links_in_txn(vault, &txn, &masked.graph.graph)?;
    if found.marked_blobs.is_empty() {
        return Ok(None);
    }
    let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
    let asker = binding.asker();
    let mut occurrences: BTreeSet<(Vec<u8>, GitOid)> = BTreeSet::new();
    let mut seen: HashSet<(GitOid, Option<Vec<u8>>)> = HashSet::new();
    let mut walk: Vec<(GitOid, Option<Vec<u8>>)> = masked
        .refs()
        .iter()
        .map(|(_, original, _)| (original.clone(), None))
        .chain(
            masked
                .private_root()
                .map(|(original, _)| (original.clone(), None)),
        )
        .collect();
    while let Some(at) = walk.pop() {
        if !seen.insert(at.clone()) {
            continue;
        }
        let (parent, path) = at;
        for (place, child) in found.links.get(&parent).into_iter().flatten() {
            let child_path = match (place, &path) {
                (RepoProjectionPlace::CommitTree, None) => Some(Vec::new()),
                (RepoProjectionPlace::CommitParent { .. }, None) => None,
                (RepoProjectionPlace::TreeEntry { name, .. }, Some(path)) => {
                    let mut joined = path.clone();
                    if !joined.is_empty() {
                        joined.push(b'/');
                    }
                    joined.extend_from_slice(name);
                    Some(joined)
                }
                // A tag's target names no path.
                _ => continue,
            };
            match child_path {
                Some(child_path) if found.marked_blobs.contains(child) => {
                    occurrences.insert((child_path, child.clone()));
                }
                child_path => walk.push((child.clone(), child_path)),
            }
        }
    }
    let files = vault.with_known_values(|known| {
        let mut files = Vec::new();
        for (path, blob) in occurrences {
            let Ok(text_path) = std::str::from_utf8(&path) else {
                continue;
            };
            let marks = facts.for_blob(&RepoBlobAddress {
                store: *store_id,
                blob: blob.clone(),
            });
            if marks.is_empty() {
                continue;
            }
            let keys = match known {
                Some(known) => {
                    let object = wire.read_object_to_spool(canonical, &blob)?;
                    let bytes = Zeroizing::new(object.read_bytes()?);
                    repo_file_keys_in_txn(vault, &txn, &marks, &bytes, Some(known))?
                }
                None => repo_file_keys_in_txn(vault, &txn, &marks, &[], None)?,
            };
            let original = RepoFileOriginal {
                repo: binding.repo,
                store: store_identity.clone(),
                snapshot: None,
                path: text_path.to_owned(),
                blob: blob.clone(),
                source: None,
                marks: marks.ids()?,
            };
            let file = RepoGitReleasedFile {
                path,
                blob,
                original,
                marks,
                keys,
            };
            let target = RepoFileRevealTarget::new(&file.original, &asker);
            if vault.repo_file_reveal_granted_in_txn(&txn, &asker, &target, &file.keys())? {
                files.push(file);
            }
        }
        Ok(files)
    })?;
    Ok((!files.is_empty()).then_some(RepoGitReleasePlan { binding, files }))
}

/// Makes the granted sibling of the masked copy `masked` that `plan`
/// releases, or loads the one that already stands for it (module docs);
/// `None` when the masked copy's sources moved, which the caller answers
/// with the masked copy's own admission. It is built and lands as a masked
/// copy does, under the masked copy's closure marks.
///
/// # Errors
/// An erased store, an object the canonical store lacks, a failed git
/// effect or write, or a mark that does not decode.
pub(crate) fn materialize_recipient_git_graph(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    masked: &RepoGitProjection,
    plan: &RepoGitReleasePlan,
    now: u64,
) -> Result<Option<RepoGitProjection>> {
    let RepoProjectionRecord::Graph {
        store_identity,
        store_id,
        roots,
        private_root,
        marks,
        known_history,
        ..
    } = &masked.graph.record
    else {
        return Ok(None);
    };
    let store_id = *store_id;
    require_store_not_erased(vault, store_id)?;
    let graph = RepoProjectionClaim::graph(RepoProjectionRecord::Graph {
        store_identity: store_identity.clone(),
        store_id,
        roots: roots.clone(),
        private_root: private_root.clone(),
        marks: marks.clone(),
        known_history: *known_history,
        audience: RepoProjectionAudience::Recipient {
            binding: plan.binding.clone(),
            released: plan.release().into_iter().collect(),
        },
    })?;
    let published = roots
        .iter()
        .map(|(name, original)| Ok((GitRefName::parse_full(name.clone())?, original.clone())))
        .collect::<Result<Vec<_>>>()?;
    let roots = RepoGitProjectionRoots::new(published, private_root.clone())?;
    let _building_lock = building_lock(vault, store_id, graph.graph)?;
    if let Some(standing) = standing_projection(vault, wire, &graph, store_id, &roots)? {
        return Ok(Some(standing));
    }
    let facts = {
        let txn = vault.store.env.read_txn()?;
        let facts = RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?;
        // FIX 8966: the sibling is masked against the values custody knows
        // now; the masked copy's own witness must still name them.
        if *known_history != vault.store.known_history_witness_in_txn(&txn)?
            || !closure_marks_stand_in_txn(vault, &txn, &masked.graph, &facts)?
        {
            return Ok(None);
        }
        facts
    };
    let building = building_dir(vault, store_id, graph.graph)?;
    // A building directory is an interrupted copy: it starts over.
    if building.exists() {
        std::fs::remove_dir_all(&building)?;
    }
    let copy_store = wire.init_projection_store(&building)?;
    let release = plan.release();
    let copy = vault.with_known_values(|known| {
        copy_repo_projection_objects(
            vault,
            wire,
            canonical,
            &copy_store,
            &roots.tips(),
            &facts,
            store_id,
            Some(&release),
            known,
        )
    })?;
    land_copy(vault, wire, &building, &graph, store_id, &roots, &copy, now).map(Some)
}

/// The CODE anchor a recipient's reads of the canonical store `canonical`
/// name as their repo: the anchor the owner bound for its PROJECT. A
/// recipient that names no project, or a project with no anchor, has no
/// grant target to read under and reads masked.
///
/// # Errors
/// A store failure.
pub(crate) fn recipient_repo_anchor(
    vault: &Vault,
    canonical: &GitWireRepo,
    project: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let Some(project) = project else {
        return Ok(None);
    };
    let txn = vault.store.env.read_txn()?;
    vault.served_repo_anchor_in_txn(&txn, &canonical.identity().as_hex(), project)
}

/// The recipient's repo binding for this same canonical store. A known
/// portable repo must name the requested live project and stored folder;
/// it never falls through to a different private anchor. An unknown id
/// keeps the recipient's original project and served-anchor lookup.
/// Neither selection grants a read: the live per-file grants still decide.
pub(crate) fn recipient_repo_binding(
    vault: &Vault,
    canonical: &GitWireRepo,
    recipient: &RepoRevealRecipient,
    portable: Option<(&RepoPortableId, EntityId)>,
) -> Result<Option<RepoProjectionRevealBinding>> {
    if let Some((portable, project)) = portable {
        let txn = vault.store.env.read_txn()?;
        if let Some(repo) = vault.resolve_repo_anchor_by_portable_in_txn(&txn, portable)? {
            let Some(path) = vault.git_push_anchor_in_txn(&txn, &GitPushRepo { repo, project })?
            else {
                return Ok(None);
            };
            let identity = canonical.identity().as_hex();
            if vault.git_push_store_identity(&path).as_deref() != Some(identity.as_str()) {
                return Ok(None);
            }
            let mut binding = RepoProjectionRevealBinding::of(repo, recipient);
            binding.project = binding.project.or(Some(project));
            return Ok(Some(binding));
        }
    }
    Ok(
        recipient_repo_anchor(vault, canonical, recipient.project())?
            .map(|repo| RepoProjectionRevealBinding::of(repo, recipient)),
    )
}
