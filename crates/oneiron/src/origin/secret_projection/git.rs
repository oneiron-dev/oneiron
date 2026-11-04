//! The Git side of a marked repo's projection.
//!
//! The exact-source identity (FIX 7608, owner ruling A2): an export back to
//! a repo's own original source is exact, public or private. Slice 2a names
//! the witness only; it checks nothing, gates no send and changes no
//! export. A later slice proves it from a G7 external source claim or a G4
//! import anchor, and a `None` there means "not proved the original
//! source", never "refuse the owner's export".
//!
//! The masked Git copy (FIX 7608 slice 2b-i, CALLs P2, P3, M, L): a
//! physically distinct bare store holding the closure of a canonical
//! store's frozen roots, each marked blob masked and each object above one
//! re-encoded, every other object at its original id. It lives under
//! [`REPO_SECRET_PROJECTION_DIR`] in the vault's own environment directory,
//! beside the served stores, one directory per canonical store and graph.
//! Its value-free records are `repo.secret_projection` claims. It is bound
//! to its sources (CALL P3): it stands only while its graph claim stands
//! and the readable marks naming a blob of its closure are the ones it was
//! made under (FIX 9105: a mark on another blob or store keeps it), and it
//! is admitted again before any byte of it is released. No TTL, size or
//! count ends it. A vault with no readable mark, or roots whose closure no
//! mark touches, gets no copy at all: the caller keeps the canonical path,
//! and nothing is written.
//!
//! A copy is built in its own building directory, its graph id unknown
//! until its walk has found its closure's marks; its records land next,
//! the graph's first and the rest in bounded transactions (FIX 9106), then
//! the directory moves to the graph's and its refs are published. A reader
//! admits only a copy whose refs stand, so it never reads a partial one.

#![allow(
    dead_code,
    reason = "FIX 7608: the exact-source proof and some accessors wait for later slices"
)]

use std::path::{Path, PathBuf};

use heed::RoTxn;

use super::super::lfs::lfs_repo_id;
use super::super::secret_marks::{RepoMarkFacts, RepoSecretMarkLookup};
use super::claims::{RepoProjectionAudience, RepoProjectionClaim, RepoProjectionRecord};
use super::graph_objects::{RepoProjectionCopy, copy_repo_projection_objects};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{
    GitOid, GitRefExpectation, GitRefName, GitRefPublication, GitWire, GitWireRepo,
};

mod closure;
mod landing;
pub(crate) mod recipient;

use self::closure::{closure_marks, graph_record_with, same_base};
pub(crate) use self::closure::{closure_marks_stand_in_txn, masked_sibling};
use self::landing::land_copy;
pub(crate) use self::recipient::{
    RepoGitReleasePlan, materialize_recipient_git_graph, plan_repo_git_release,
    recipient_repo_anchor,
};

/// One canonical export OID proved to return to the source it came from.
#[allow(
    dead_code,
    reason = "FIX 7608 slice 2a: the identity is named here; its check lands with slice 9"
)]
#[derive(Debug)]
pub(crate) struct ExactSourceExportProof {
    source_claim: EntityId,
    original: GitOid,
}

/// CALL L: the directory every masked Git copy lives under, inside the
/// vault's own environment directory beside `origin/` and `origin-door/`.
pub(crate) const REPO_SECRET_PROJECTION_DIR: &str = "repo-secret-projections";

/// The copy store's ref for an admitted lease's private original: never
/// advertised (a copy's advertisement names only its Published roots).
const PRIVATE_ROOT_REF: &str = "refs/oneiron-projection/private-root";

/// CALL P2: what a copy does with each object's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoGitProjectionObjectPolicy {
    /// An object nothing it reaches changed keeps its bytes and its id; a
    /// changed one is re-encoded structurally, drops the signatures it can
    /// no longer carry and says `signature_not_preserved`. Never re-signed.
    PreservePayload,
}

/// CALL P3: how long a copy lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoGitProjectionLifetime {
    /// While its sources stand: its graph claim, the readable marks it was
    /// made under, and the roots it copies. No TTL, size or count.
    SourceBound,
}

/// The frozen roots a copy is made for: each Published ref at the original
/// it was frozen at, and an already admitted lease's original pin as a
/// private root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoGitProjectionRoots {
    published: Vec<(GitRefName, GitOid)>,
    private_root: Option<GitOid>,
}

impl RepoGitProjectionRoots {
    /// The roots, sorted by ref name.
    ///
    /// # Errors
    /// One ref named twice, or no root at all.
    pub(crate) fn new(
        mut published: Vec<(GitRefName, GitOid)>,
        private_root: Option<GitOid>,
    ) -> Result<Self> {
        published.sort_by(|left, right| left.0.cmp(&right.0));
        if published.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::InvariantViolation(
                "a masked copy names one root ref twice",
            ));
        }
        if published.is_empty() && private_root.is_none() {
            return Err(Error::InvariantViolation("a masked copy needs a root"));
        }
        Ok(Self {
            published,
            private_root,
        })
    }

    fn tips(&self) -> Vec<GitOid> {
        self.published
            .iter()
            .map(|(_, original)| original.clone())
            .chain(self.private_root.clone())
            .collect()
    }
}

/// One masked Git copy, as it stands.
#[derive(Debug, Clone)]
pub(crate) struct RepoGitProjection {
    graph: RepoProjectionClaim,
    store_root: PathBuf,
    refs: Vec<(GitRefName, GitOid, GitOid)>,
    private_root: Option<(GitOid, GitOid)>,
    policy: RepoGitProjectionObjectPolicy,
    lifetime: RepoGitProjectionLifetime,
}

impl RepoGitProjection {
    /// The graph claim's id.
    pub(crate) const fn graph_id(&self) -> EntityId {
        self.graph.graph
    }

    /// The copy's bare store.
    pub(crate) const fn store_root(&self) -> &PathBuf {
        &self.store_root
    }

    /// Each root ref with its original and its copy.
    pub(crate) fn refs(&self) -> &[(GitRefName, GitOid, GitOid)] {
        &self.refs
    }

    /// The private root's original and copy.
    pub(crate) const fn private_root(&self) -> Option<&(GitOid, GitOid)> {
        self.private_root.as_ref()
    }

    pub(crate) const fn policy(&self) -> RepoGitProjectionObjectPolicy {
        self.policy
    }

    pub(crate) const fn lifetime(&self) -> RepoGitProjectionLifetime {
        self.lifetime
    }

    /// The canonical store the copy stands for.
    pub(crate) fn store_id(&self) -> Option<EntityId> {
        match &self.graph.record {
            RepoProjectionRecord::Graph { store_id, .. } => Some(*store_id),
            _ => None,
        }
    }

    /// Each root's copy whose bytes differ from its original's (FIX 7608
    /// 2b-ii): the copy commits a received push's old tip and incoming
    /// history are classified against. An identity root names none.
    pub(crate) fn changed_root_copies(&self) -> std::collections::BTreeSet<GitOid> {
        self.refs
            .iter()
            .map(|(_, original, copy)| (original, copy))
            .chain(
                self.private_root
                    .iter()
                    .map(|(original, copy)| (original, copy)),
            )
            .filter(|(original, copy)| original != copy)
            .map(|(_, copy)| copy.clone())
            .collect()
    }
}

/// The directory every masked copy lives under, made when absent.
///
/// # Errors
/// A directory that cannot be made.
pub(crate) fn repo_secret_projection_root(vault: &Vault) -> Result<PathBuf> {
    let root = vault.store.env.path().join(REPO_SECRET_PROJECTION_DIR);
    std::fs::create_dir_all(&root)?;
    Ok(root.canonicalize()?)
}

/// The prefix of a copy's building directory, beside its store's copies;
/// never a graph id, so no graph's sweep takes it.
const BUILDING_DIR_PREFIX: &str = "building-";

/// What one materialization is keyed by, read once: the masked graph
/// record `roots` would be made under with its marks still empty (they are
/// its closure's, FIX 9105), and the readable marks.
struct ProjectionInputs {
    base: RepoProjectionRecord,
    store_id: EntityId,
    facts: RepoMarkFacts,
}

/// The inputs `roots` of `canonical` would be copied under now; `None`
/// when no mark is readable, which needs no copy.
fn projection_inputs(
    vault: &Vault,
    canonical: &GitWireRepo,
    roots: &RepoGitProjectionRoots,
) -> Result<Option<ProjectionInputs>> {
    let facts = {
        let txn = vault.store.env.read_txn()?;
        RepoMarkFacts::read_in_txn(vault, &txn, RepoSecretMarkLookup::ReadableClaims)?
    };
    if facts.is_empty() {
        return Ok(None);
    }
    let store_identity = canonical.identity().as_hex();
    let store_id = lfs_repo_id(&store_identity)?;
    let base = RepoProjectionRecord::Graph {
        store_identity,
        store_id,
        roots: roots
            .published
            .iter()
            .map(|(name, original)| (name.as_str().to_owned(), original.clone()))
            .collect(),
        private_root: roots.private_root.clone(),
        marks: Vec::new(),
        audience: RepoProjectionAudience::Masked,
    };
    Ok(Some(ProjectionInputs {
        base,
        store_id,
        facts,
    }))
}

/// FIX 10274: no copy of a canonical store the owner erased is made or
/// served; its masked reader is answered with the erase, never with the
/// canonical bytes.
///
/// # Errors
/// The erased store's refusal, or a store failure.
fn require_store_not_erased(vault: &Vault, store_id: EntityId) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    if vault.local_hard_delete_marker_exists_in_txn(&txn, &store_id)? {
        return Err(crate::error::Error::Code(
            crate::error::CodeError::GitHttpServeFailed {
                reason: "this repository's store was erased; it has no masked copy".to_owned(),
            },
        ));
    }
    Ok(())
}

fn graph_dir(vault: &Vault, store_id: EntityId, graph: EntityId) -> Result<PathBuf> {
    Ok(repo_secret_projection_root(vault)?
        .join(store_id.to_hex())
        .join(graph.to_hex()))
}

/// The directory the copy keyed by `key` (its graph id, or a masked copy's
/// base id while its marks are unknown) is built in before it lands.
fn building_dir(vault: &Vault, store_id: EntityId, key: EntityId) -> Result<PathBuf> {
    Ok(repo_secret_projection_root(vault)?
        .join(store_id.to_hex())
        .join(format!("{BUILDING_DIR_PREFIX}{}", key.to_hex())))
}

/// The directory every copy of the canonical store `store_id` would live
/// under, made by nothing here.
pub(crate) fn existing_projection_store_dir(vault: &Vault, store_id: EntityId) -> PathBuf {
    vault
        .store
        .env
        .path()
        .join(REPO_SECRET_PROJECTION_DIR)
        .join(store_id.to_hex())
}

/// The id a copy directory's strict 32-hex name is, or `None` for anything
/// else (a private ingress root, a building directory, a file).
pub(crate) fn projection_dir_id(path: &Path) -> Option<EntityId> {
    if !path.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    if name.len() != 32 || !name.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    EntityId::from_hex(name).ok()
}

/// The masked copy of `base` that stands now, found among its store's copy
/// directories by their graph records (FIX 9105): its graph id names its
/// closure's marks, which only its walk learns, so it is never derived
/// ahead of one.
///
/// # Errors
/// A directory that cannot be listed, a store failure, or a record that
/// does not decode.
fn standing_for_base(
    vault: &Vault,
    wire: &GitWire<'_>,
    base: &RepoProjectionRecord,
    store_id: EntityId,
    roots: &RepoGitProjectionRoots,
) -> Result<Option<RepoGitProjection>> {
    let Ok(entries) = std::fs::read_dir(existing_projection_store_dir(vault, store_id)) else {
        return Ok(None);
    };
    let mut candidates = Vec::new();
    {
        let txn = vault.store.env.read_txn()?;
        for entry in entries {
            let Some(graph) = projection_dir_id(&entry?.path()) else {
                continue;
            };
            if let Some(claim) = RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph)?
                && same_base(&claim.record, base)
            {
                candidates.push(claim);
            }
        }
    }
    for claim in candidates {
        if let Some(standing) = standing_projection(vault, wire, &claim, store_id, roots)? {
            return Ok(Some(standing));
        }
    }
    Ok(None)
}

/// Makes the masked copy of `roots` of the canonical store `canonical`,
/// or loads the one that already stands for them (module docs). `None`
/// when no readable mark touches the closure: the caller keeps the
/// canonical path, and nothing is written.
///
/// # Errors
/// An object the canonical store lacks, a failed git effect or write, or
/// a mark that does not decode.
pub(crate) fn materialize_masked_git_graph(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    roots: &RepoGitProjectionRoots,
    now: u64,
) -> Result<Option<RepoGitProjection>> {
    let Some(inputs) = projection_inputs(vault, canonical, roots)? else {
        return Ok(None);
    };
    require_store_not_erased(vault, inputs.store_id)?;
    if let Some(standing) = standing_for_base(vault, wire, &inputs.base, inputs.store_id, roots)? {
        return Ok(Some(standing));
    }
    let key = RepoProjectionClaim::graph(inputs.base.clone())?.graph;
    let building = building_dir(vault, inputs.store_id, key)?;
    // A building directory is an interrupted copy: it starts over.
    if building.exists() {
        std::fs::remove_dir_all(&building)?;
    }
    let copy_store = wire.init_projection_store(&building)?;
    let copy = copy_repo_projection_objects(
        vault,
        wire,
        canonical,
        &copy_store,
        &roots.tips(),
        &inputs.facts,
        inputs.store_id,
        None,
    )?;
    if !copy.changed_any() {
        std::fs::remove_dir_all(&building)?;
        return Ok(None);
    }
    let marks = closure_marks(&inputs.facts, &copy)?;
    let graph = RepoProjectionClaim::graph(graph_record_with(
        &inputs.base,
        marks,
        RepoProjectionAudience::Masked,
    ))?;
    land_copy(
        vault,
        wire,
        &building,
        &graph,
        inputs.store_id,
        roots,
        &copy,
        now,
    )
    .map(Some)
}

/// The masked copy that stands for `roots` of `canonical` now, admitted
/// afresh; `None` when none does (no readable mark, no copy made, or one
/// whose sources moved).
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn load_repo_git_projection(
    vault: &Vault,
    wire: &GitWire<'_>,
    canonical: &GitWireRepo,
    roots: &RepoGitProjectionRoots,
) -> Result<Option<RepoGitProjection>> {
    match projection_inputs(vault, canonical, roots)? {
        Some(inputs) => standing_for_base(vault, wire, &inputs.base, inputs.store_id, roots),
        None => Ok(None),
    }
}

/// Whether `projection` still stands in `txn`: its graph claim is there,
/// approved and unchanged, its canonical store was not erased (FIX 10274:
/// the owner's erase, carried out, whatever its marks still say), and the
/// readable marks naming a blob of its closure are exactly the ones it was
/// made under (FIX 9105). A copy is admitted again here before any byte of
/// it is released.
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn admit_repo_git_projection_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    projection: &RepoGitProjection,
) -> Result<bool> {
    let Some(stored) = RepoProjectionClaim::load_graph_in_txn(vault, txn, &projection.graph.graph)?
    else {
        return Ok(false);
    };
    let RepoProjectionRecord::Graph { store_id, .. } = &stored.record else {
        return Ok(false);
    };
    if stored != projection.graph || vault.local_hard_delete_marker_exists_in_txn(txn, store_id)? {
        return Ok(false);
    }
    let facts = RepoMarkFacts::read_in_txn(vault, txn, RepoSecretMarkLookup::ReadableClaims)?;
    closure_marks_stand_in_txn(vault, txn, &stored, &facts)
}

/// The masked copy the graph record `graph` names, reopened from its own
/// record (its roots and the marks it was made under) and admitted afresh
/// (FIX 7608 2b-ii-B2): a lease's or an ingress's copy, which today's
/// Published roots may no longer key. `None` when its record or its store
/// no longer stands, or the readable marks moved.
///
/// # Errors
/// A store failure, or a record that does not decode.
pub(crate) fn reopen_repo_git_projection(
    vault: &Vault,
    wire: &GitWire<'_>,
    graph: &EntityId,
) -> Result<Option<RepoGitProjection>> {
    let claim = {
        let txn = vault.store.env.read_txn()?;
        RepoProjectionClaim::load_graph_in_txn(vault, &txn, graph)?
    };
    let Some(claim) = claim else {
        return Ok(None);
    };
    let RepoProjectionRecord::Graph {
        store_id,
        roots,
        private_root,
        ..
    } = &claim.record
    else {
        return Ok(None);
    };
    let published = roots
        .iter()
        .map(|(name, original)| Ok((GitRefName::parse_full(name.clone())?, original.clone())))
        .collect::<Result<Vec<_>>>()?;
    let roots = RepoGitProjectionRoots::new(published, private_root.clone())?;
    standing_projection(vault, wire, &claim, *store_id, &roots)
}

/// The private ingress directory of the copy `graph` of the canonical store
/// `store_id` (FIX 7608 2b-ii-B2): beside its copies, one per copy, kept
/// while a push it received is pending.
///
/// # Errors
/// A directory that cannot be made.
pub(crate) fn projection_ingress_dir(
    vault: &Vault,
    store_id: EntityId,
    graph: EntityId,
) -> Result<PathBuf> {
    Ok(projection_ingress_root(vault, store_id)?.join(graph.to_hex()))
}

/// The directory every private ingress of the canonical store `store_id`
/// lives under.
///
/// # Errors
/// A directory that cannot be made.
pub(crate) fn projection_ingress_root(vault: &Vault, store_id: EntityId) -> Result<PathBuf> {
    Ok(repo_secret_projection_root(vault)?
        .join(store_id.to_hex())
        .join(PROJECTION_INGRESS_DIR))
}

/// The directory every private ingress of the canonical store `store_id`
/// would live under, made by nothing here: a store none was ever made for
/// has none.
pub(crate) fn existing_projection_ingress_root(vault: &Vault, store_id: EntityId) -> PathBuf {
    vault
        .store
        .env
        .path()
        .join(REPO_SECRET_PROJECTION_DIR)
        .join(store_id.to_hex())
        .join(PROJECTION_INGRESS_DIR)
}

/// The directory a store's private ingresses live under, beside its copies.
const PROJECTION_INGRESS_DIR: &str = "ingress";

/// The directory of the copy `graph` of the canonical store `store_id`.
///
/// # Errors
/// A directory that cannot be made.
pub(crate) fn projection_graph_dir(
    vault: &Vault,
    store_id: EntityId,
    graph: EntityId,
) -> Result<PathBuf> {
    graph_dir(vault, store_id, graph)
}

fn standing_projection(
    vault: &Vault,
    wire: &GitWire<'_>,
    graph: &RepoProjectionClaim,
    store_id: EntityId,
    roots: &RepoGitProjectionRoots,
) -> Result<Option<RepoGitProjection>> {
    {
        let txn = vault.store.env.read_txn()?;
        if RepoProjectionClaim::load_graph_in_txn(vault, &txn, &graph.graph)?.is_none() {
            return Ok(None);
        }
    }
    let dir = graph_dir(vault, store_id, graph.graph)?;
    let Some(copy_store) = wire.existing_projection_store(&dir)? else {
        return Ok(None);
    };
    let mut names: Vec<GitRefName> = roots
        .published
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let private = GitRefName::parse_full(PRIVATE_ROOT_REF)?;
    if roots.private_root.is_some() {
        names.push(private.clone());
    }
    let observed = wire.read_refs(&copy_store, &names)?;
    let mut refs = Vec::with_capacity(roots.published.len());
    let mut private_root = None;
    for seen in observed {
        let Some(copy) = seen.oid else {
            return Ok(None);
        };
        if seen.name == private {
            private_root = roots.private_root.clone().map(|original| (original, copy));
            continue;
        }
        let Some((_, original)) = roots.published.iter().find(|(name, _)| *name == seen.name)
        else {
            return Ok(None);
        };
        refs.push((seen.name, original.clone(), copy));
    }
    let projection = RepoGitProjection {
        graph: graph.clone(),
        store_root: copy_store.repo_root().to_path_buf(),
        refs,
        private_root,
        policy: RepoGitProjectionObjectPolicy::PreservePayload,
        lifetime: RepoGitProjectionLifetime::SourceBound,
    };
    let txn = vault.store.env.read_txn()?;
    if admit_repo_git_projection_in_txn(vault, &txn, &projection)? {
        Ok(Some(projection))
    } else {
        Ok(None)
    }
}

/// The copy store's refs: each Published root at its copy, and the private
/// root under its own unadvertised ref, each created where nothing stood.
fn publish_copy_refs(
    wire: &GitWire<'_>,
    copy_store: &GitWireRepo,
    roots: &RepoGitProjectionRoots,
    copy: &RepoProjectionCopy,
    now: u64,
) -> Result<()> {
    let mut publications: Vec<GitRefPublication> = roots
        .published
        .iter()
        .map(|(name, original)| {
            GitRefPublication::update(
                name.clone(),
                GitRefExpectation::Absent,
                copy.copy_of(original),
            )
        })
        .collect();
    if let Some(original) = &roots.private_root {
        publications.push(GitRefPublication::update(
            GitRefName::parse_full(PRIVATE_ROOT_REF)?,
            GitRefExpectation::Absent,
            copy.copy_of(original),
        ));
    }
    wire.publish_projection_refs(copy_store, publications, now)
}

fn projection_of(
    graph: RepoProjectionClaim,
    copy_store: &GitWireRepo,
    roots: &RepoGitProjectionRoots,
    copy: &RepoProjectionCopy,
) -> RepoGitProjection {
    RepoGitProjection {
        graph,
        store_root: copy_store.repo_root().to_path_buf(),
        refs: roots
            .published
            .iter()
            .map(|(name, original)| (name.clone(), original.clone(), copy.copy_of(original)))
            .collect(),
        private_root: roots.private_root.clone().map(|original| {
            let copied = copy.copy_of(&original);
            (original, copied)
        }),
        policy: RepoGitProjectionObjectPolicy::PreservePayload,
        lifetime: RepoGitProjectionLifetime::SourceBound,
    }
}
