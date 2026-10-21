//! The live task-type tree (ARCH-0079 #task-type, OF-541): data inside the
//! team-shape skill, so it forks and merges like one.
//!
//! The tree is one file, [`TASK_TYPE_TREE_FILE`], in the team-shape skill's
//! ordinary package. The tree in force for a project is its admitted
//! team-shape fork's (found by lineage among the project's skill forks),
//! else the vault skill's newest admitted revision, else the seeded tree. A
//! skill whose package carries no tree reads the seed: nothing is written on
//! a placement. A structural change is stored into an open local fork
//! through the existing fork/update door and goes in force once the
//! ordinary gate admits it; old stamps keep naming the version they were
//! placed at. There is no tree head table: the skill lineage is the head.
//!
//! [`load_vault_type_tree_sourced`] reads the vault tree with its head and
//! the entity rows it read them from, in one snapshot (FIX 7103).

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillLifecycle, SkillRecord, resident_of, skill_loadable};
use crate::skill_hub::{HubFile, HubPackage};
use crate::task_type::{
    PlacementDecisions, PlacementRequest, TaskTypeRef, TaskTypeTree, ensure_type_ref,
};
use crate::temporal::TimeRange;

use super::team_shape::team_shape_skill;
use super::widen_record::invalid;

/// The tree file inside the team-shape skill's package.
pub const TASK_TYPE_TREE_FILE: &str = "task-type-tree.json";

/// The tree in force for `project` (`None` is the vault tree).
///
/// # Errors
///
/// Storage errors, or a stored tree file that does not decode.
pub fn load_team_type_tree(vault: &Vault, project: Option<EntityId>) -> Result<TaskTypeTree> {
    let txn = vault.store.env.read_txn()?;
    load_team_type_tree_in_txn(vault, &txn, project)
}

/// [`load_team_type_tree`] in the caller's snapshot, so a placement and
/// the write it stamps read one tree.
pub(crate) fn load_team_type_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<TaskTypeTree> {
    tree_in_force_in_txn(vault, txn, project, &mut Reads::Off)
}

/// [`load_team_type_tree_in_txn`], noting the rows it reads in `reads`.
fn tree_in_force_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    reads: &mut Reads,
) -> Result<TaskTypeTree> {
    let vault_skill = team_shape_skill()?;
    if project.is_some() {
        // A project's visibility folds rows this module cannot name.
        reads.unknown();
    }
    if let Some(project) = project
        && let Some(fork) = project_fork_in_txn(vault, txn, project, vault_skill)?
        && let Some(tree) = stored_tree_in_txn(vault, txn, &fork, reads)?
    {
        return Ok(tree);
    }
    Ok(match vault_head_in_txn(vault, txn, vault_skill, reads)? {
        Some(head) => {
            stored_tree_in_txn(vault, txn, &head, reads)?.unwrap_or_else(TaskTypeTree::seeded)
        }
        None => TaskTypeTree::seeded(),
    })
}

/// The vault's task-type tree in force as one read loaded it (FIX 7103):
/// the tree, the team-shape head it came from and the entity rows the read
/// took them from, with the head in force for each asked project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcedTypeTree {
    /// What [`load_team_type_tree`] loads for the vault.
    pub tree: TaskTypeTree,
    /// What [`team_shape_skill_in_force`] names for the vault.
    pub head: Option<EntityId>,
    /// The rows the head's selection and the tree's load read: each entity
    /// the walk along the vault skill's supersession chain read, the head,
    /// and the replicated source carrier its package came from, if one did.
    /// `None` when a row read cannot be named. The seed tree is code and
    /// adds none.
    pub source_rows: Option<Vec<EntityId>>,
    /// Each asked project's team-shape head in force, with the rows its
    /// selection read: `None`, since a project's visibility folds rows this
    /// read cannot name.
    pub project_heads: BTreeMap<EntityId, (Option<EntityId>, Option<Vec<EntityId>>)>,
}

/// [`SourcedTypeTree`] for the vault, and the head in force for each of
/// `projects`, all from one read transaction.
///
/// # Errors
///
/// As [`load_team_type_tree`].
pub fn load_vault_type_tree_sourced(
    vault: &Vault,
    projects: &BTreeSet<EntityId>,
) -> Result<SourcedTypeTree> {
    let txn = vault.store.env.read_txn()?;
    let mut reads = Reads::Named(BTreeSet::new());
    let tree = tree_in_force_in_txn(vault, &txn, None, &mut reads)?;
    let head = head_in_force_in_txn(vault, &txn, None, &mut reads)?;
    let mut project_heads = BTreeMap::new();
    for project in projects {
        let mut project_reads = Reads::Named(BTreeSet::new());
        let project_head = head_in_force_in_txn(vault, &txn, Some(*project), &mut project_reads)?;
        project_heads.insert(*project, (project_head, project_reads.into_rows()));
    }
    Ok(SourcedTypeTree {
        tree,
        head,
        source_rows: reads.into_rows(),
        project_heads,
    })
}

/// The entity rows one read of the tree read, for a caller that names them
/// (FIX 7103). Every other read passes [`Reads::Off`] and keeps nothing.
enum Reads {
    Off,
    /// Every entity row read so far.
    Named(BTreeSet<EntityId>),
    /// A row was read that this module cannot name.
    Unknown,
}

impl Reads {
    const fn naming(&self) -> bool {
        matches!(self, Self::Named(_))
    }

    fn note(&mut self, id: EntityId) {
        if let Self::Named(rows) = self {
            rows.insert(id);
        }
    }

    fn unknown(&mut self) {
        if self.naming() {
            *self = Self::Unknown;
        }
    }

    fn into_rows(self) -> Option<Vec<EntityId>> {
        match self {
            Self::Named(rows) => Some(rows.into_iter().collect()),
            Self::Off | Self::Unknown => None,
        }
    }
}

/// The tree `project` placed in at `version` (`None` is the vault tree): the
/// tree in force when it is at that version, else the kept revision whose
/// tree is (the project's team-shape forks first, then the vault skill's
/// supersession chain, newest first), else the seed tree when it is. `None`
/// when no kept tree is at that version. A stamp placed before a tree change
/// reads the tree it was placed in.
///
/// # Errors
///
/// Storage errors, or a stored tree file that does not decode.
pub fn load_team_type_tree_at(
    vault: &Vault,
    project: Option<EntityId>,
    version: u64,
) -> Result<Option<TaskTypeTree>> {
    let txn = vault.store.env.read_txn()?;
    load_team_type_tree_at_in_txn(vault, &txn, project, version)
}

/// [`load_team_type_tree_at`] in the caller's snapshot, so a read pairs the
/// kept tree with what else that snapshot holds.
pub(crate) fn load_team_type_tree_at_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    version: u64,
) -> Result<Option<TaskTypeTree>> {
    let in_force = load_team_type_tree_in_txn(vault, txn, project)?;
    if in_force.version == version {
        return Ok(Some(in_force));
    }
    for skill in kept_revisions_in_txn(vault, txn, project, team_shape_skill()?)? {
        if vault.get_skill_record_in_txn(txn, &skill)?.is_some()
            && let Some(tree) = stored_tree_unchecked_in_txn(vault, txn, &skill, &mut Reads::Off)?
            && tree.version == version
        {
            return Ok(Some(tree));
        }
    }
    let seed = TaskTypeTree::seeded();
    Ok((seed.version == version).then_some(seed))
}

/// The kept revisions [`load_team_type_tree_at`] searches for `project`, in
/// its order: the project's team-shape forks, then the vault skill's
/// supersession chain, each newest first.
fn kept_revisions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    vault_skill: EntityId,
) -> Result<Vec<EntityId>> {
    let mut revisions = Vec::new();
    if let Some(project) = project
        && let Some(record) = vault.visible_project_in_txn(txn, project)?
    {
        for fork in record.skill_forks.iter().rev() {
            if let Ok(fork) = EntityId::from_hex(fork)
                && in_lineage_in_txn(vault, txn, fork, vault_skill)?
            {
                revisions.push(fork);
            }
        }
    }
    revisions.extend(supersession_chain_in_txn(vault, txn, vault_skill)?);
    Ok(revisions)
}

/// Every revision on the vault skill's supersession chain, each step a
/// [`skill_succession_in_txn`], newest first.
fn supersession_chain_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_skill: EntityId,
) -> Result<Vec<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut chain = Vec::new();
    let mut cursor = vault_skill;
    while seen.insert(cursor) {
        chain.push(cursor);
        let mut next = None;
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &vault.store,
            txn,
            &cursor,
            crate::ports::EdgeDirection::In,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if !seen.contains(&peer)
                && skill_succession_in_txn(vault, txn, peer, cursor, &mut Reads::Off)?
            {
                next = Some(peer);
                break;
            }
        }
        match next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    chain.reverse();
    Ok(chain)
}

/// The team-shape skill in force for `project`: its admitted fork, else the
/// vault skill's newest admitted revision. `None` when neither is loadable.
///
/// # Errors
///
/// Storage errors.
pub fn team_shape_skill_in_force(
    vault: &Vault,
    project: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    team_shape_skill_in_force_in_txn(vault, &txn, project)
}

/// [`team_shape_skill_in_force`] in the caller's snapshot.
pub(crate) fn team_shape_skill_in_force_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
) -> Result<Option<EntityId>> {
    head_in_force_in_txn(vault, txn, project, &mut Reads::Off)
}

/// [`team_shape_skill_in_force_in_txn`], noting the rows it reads in
/// `reads`.
fn head_in_force_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    reads: &mut Reads,
) -> Result<Option<EntityId>> {
    let vault_skill = team_shape_skill()?;
    if project.is_some() {
        // A project's visibility folds rows this module cannot name.
        reads.unknown();
    }
    if let Some(project) = project
        && let Some(fork) = project_fork_in_txn(vault, txn, project, vault_skill)?
    {
        return Ok(Some(fork));
    }
    vault_head_in_txn(vault, txn, vault_skill, reads)
}

/// Places a spawn once against `tree`: a requested stamp the tree accepts
/// is kept, anything else is placed through the placement skill's ladder
/// (the host's `decisions`, else its rule rung alone), and unsure is the
/// root.
pub(crate) fn place_in_tree(
    tree: &TaskTypeTree,
    requested: Option<&TaskTypeRef>,
    label: Option<String>,
    text: Option<String>,
    project: Option<EntityId>,
    decisions: Option<&PlacementDecisions<'_>>,
) -> TaskTypeRef {
    let mut request = PlacementRequest::new(label, text);
    if let Some(project) = project {
        request = request.with_project(project.to_hex());
    }
    ensure_type_ref(tree, requested, &request, decisions)
}

/// Writes `tree` into `fork`, an open local fork of the team-shape skill,
/// through the shared fork-package door: the fork keeps its own skill id and
/// parent edge, and re-enters the admission gate like any edit. The tree's
/// version must not fall behind the tree its parent carries; stamps placed
/// against older versions are never restamped.
///
/// One version names one structure in the tree's lookup scope: the fork's
/// own prior tree, its parent's, the seed and every kept revision
/// [`load_team_type_tree_at`] searches for `project` (`None` is the vault,
/// with the sibling forks of each project that lists the fork).
/// A requested version a tree of another structure already uses there is
/// stored at the next free version instead; the same structure at the same
/// version stays at it. The version is chosen in the write that stores the
/// tree. Returns the version stored.
///
/// # Errors
///
/// [`crate::error::ArtifactError::InvalidAgentDispatchInput`] for a fork
/// outside the team-shape lineage, a malformed tree or a version that moves
/// backwards; the fork door's own refusals; storage errors.
pub fn store_team_type_tree(
    vault: &Vault,
    fork: EntityId,
    tree: &TaskTypeTree,
    project: Option<EntityId>,
    at: u64,
) -> Result<u64> {
    validate_tree(tree)?;
    vault.with_write_txn_grouped(|txn| {
        let record = vault.read_skill_record_in_txn(txn, &fork)?;
        let parent = record
            .forked_from
            .ok_or_else(|| invalid("a stored type tree goes into a local fork"))?;
        if record.lifecycle_status != SkillLifecycle::Candidate {
            return Err(invalid("a stored type tree goes into an open fork"));
        }
        let vault_skill = team_shape_skill()?;
        if !in_lineage_in_txn(vault, txn, fork, vault_skill)? {
            return Err(invalid("fork is not in the team-shape skill's lineage"));
        }
        let parent_tree = match vault.get_skill_record_in_txn(txn, &parent)? {
            Some(_) => stored_tree_unchecked_in_txn(vault, txn, &parent, &mut Reads::Off)?
                .unwrap_or_else(TaskTypeTree::seeded),
            None => TaskTypeTree::seeded(),
        };
        if tree.version < parent_tree.version {
            return Err(invalid(
                "a stored type tree never moves its version backwards",
            ));
        }
        let package = vault
            .runtime_skill_package_in_txn(txn, &fork, &record)?
            .ok_or_else(|| invalid("team-shape fork has no stored source"))?;
        // A kept tree that does not read stays out of the scope, which never
        // fails the write it serves.
        let mut scope = vec![parent_tree, TaskTypeTree::seeded()];
        let mut revisions =
            kept_revisions_in_txn(vault, txn, project, vault_skill).unwrap_or_default();
        // FIX 5215: a pin naming no project is checked against the fork's
        // actual siblings too, as its project's lookup would read them.
        if project.is_none() {
            revisions
                .extend(fork_siblings_in_txn(vault, txn, fork, vault_skill).unwrap_or_default());
        }
        for skill in std::iter::once(fork).chain(revisions) {
            if let Ok(Some(kept)) =
                stored_tree_unchecked_in_txn(vault, txn, &skill, &mut Reads::Off)
            {
                scope.push(kept);
            }
        }
        let mut stored = tree.clone();
        if scope
            .iter()
            .any(|kept| kept.version == tree.version && !same_structure(kept, tree))
        {
            let highest = scope.iter().map(|kept| kept.version).max();
            stored.version = version_on_clash(tree.version, highest.unwrap_or(tree.version));
        }
        let content =
            serde_json::to_vec_pretty(&stored).map_err(|_| invalid("type tree does not encode"))?;
        let mut files: Vec<HubFile> = package
            .files
            .into_iter()
            .filter(|file| file.path != TASK_TYPE_TREE_FILE)
            .collect();
        files.push(HubFile::new(TASK_TYPE_TREE_FILE, content));
        vault.write_shared_skill_fork_package_in_txn(
            txn,
            &fork,
            &HubPackage::new(record, files, package.capabilities),
            TimeRange { start: at, end: at },
            at,
        )?;
        Ok(stored.version)
    })
}

/// The version a pin is stored at when its requested version names another
/// structure in its lookup scope: the next free one, one past the highest
/// version the scope uses, counted in `u64` past `u32::MAX` too (FIX 5216),
/// so a clashing pin never reuses an occupied version. Only a scope already
/// at `u64::MAX`, which has no next version, keeps the requested one. The
/// one place a later ruling on clashing pins changes.
fn version_on_clash(requested: u64, highest_used: u64) -> u64 {
    highest_used.checked_add(1).unwrap_or(requested)
}

/// Whether two trees are one structure: the same node ids, parents and
/// names, and the same split and merge marks placement reads. Seeds, scope
/// and the receipt, holdout and decision counters are not structure.
fn same_structure(a: &TaskTypeTree, b: &TaskTypeTree) -> bool {
    a.nodes.len() == b.nodes.len()
        && a.nodes.iter().zip(&b.nodes).all(|((a_id, a), (b_id, b))| {
            a_id == b_id
                && a.parent == b.parent
                && a.name == b.name
                && a.split_axis == b.split_axis
                && a.split_winner == b.split_winner
                && a.merged_into == b.merged_into
        })
}

/// The other team-shape forks of every visible project that lists `fork`
/// among its skill forks: the siblings its tree is looked up beside when a
/// pin names no project, as nothing else maps a fork back to its project.
fn fork_siblings_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fork: EntityId,
    vault_skill: EntityId,
) -> Result<Vec<EntityId>> {
    let Some(reader) =
        crate::workspace_roster::ProjectReader::new(&vault.store, txn, vault.privacy_posture())?
    else {
        return Ok(Vec::new());
    };
    let mut siblings = Vec::new();
    for (_, record, verdict) in reader.all()? {
        let listed: Vec<EntityId> = record
            .skill_forks
            .iter()
            .filter_map(|listed| EntityId::from_hex(listed).ok())
            .collect();
        if verdict != crate::workspace_roster::ProjectVerdict::Visible || !listed.contains(&fork) {
            continue;
        }
        for sibling in listed {
            if sibling != fork && in_lineage_in_txn(vault, txn, sibling, vault_skill)? {
                siblings.push(sibling);
            }
        }
    }
    Ok(siblings)
}

/// The newest admitted team-shape fork among the project's skill forks.
fn project_fork_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    vault_skill: EntityId,
) -> Result<Option<EntityId>> {
    let Some(record) = vault.visible_project_in_txn(txn, project)? else {
        return Ok(None);
    };
    for fork in record.skill_forks.iter().rev() {
        let Ok(fork) = EntityId::from_hex(fork) else {
            continue;
        };
        if vault
            .get_skill_record_in_txn(txn, &fork)?
            .is_some_and(|skill| skill_loadable(&skill))
            && in_lineage_in_txn(vault, txn, fork, vault_skill)?
        {
            return Ok(Some(fork));
        }
    }
    Ok(None)
}

/// Whether `skill`'s ancestry reaches `root`: each skill's fork parent and
/// each admitted revision it superseded (its outgoing `Supersedes` edges
/// that are a [`skill_succession_in_txn`]), walked with one visited set and
/// no depth bound. A fork of an optimizer revision, which names no fork
/// parent, reaches the root through the revisions that revision superseded.
/// A revisited skill ends only its own branch.
fn in_lineage_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: EntityId,
    root: EntityId,
) -> Result<bool> {
    let mut seen = BTreeSet::new();
    let mut pending = vec![skill];
    while let Some(id) = pending.pop() {
        if id == root {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        let Some(record) = vault.get_skill_record_in_txn(txn, &id)? else {
            continue;
        };
        if let Some(parent) = record.forked_from {
            pending.push(parent);
        }
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &vault.store,
            txn,
            &id,
            crate::ports::EdgeDirection::Out,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if skill_succession_in_txn(vault, txn, id, peer, &mut Reads::Off)? {
                pending.push(peer);
            }
        }
    }
    Ok(false)
}

/// Whether the `Supersedes` edge `successor → predecessor` is a succession
/// the supersession door admitted: two distinct live SKILL entities of one
/// skill id and resident at different versions, the successor admitted (any
/// state past candidate, so one later superseded or staled still counts)
/// and the predecessor frozen superseded. Any other edge of the kind, to an
/// entity of another type included, is not ancestry: a walk skips it.
fn skill_succession_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    successor: EntityId,
    predecessor: EntityId,
    reads: &mut Reads,
) -> Result<bool> {
    if successor == predecessor {
        return Ok(false);
    }
    let (Some(new), Some(old)) = (
        live_skill_in_txn(vault, txn, &successor, reads)?,
        live_skill_in_txn(vault, txn, &predecessor, reads)?,
    ) else {
        return Ok(false);
    };
    Ok(new.skill_id == old.skill_id
        && new.version != old.version
        && new.lifecycle_status != SkillLifecycle::Candidate
        && old.lifecycle_status == SkillLifecycle::Superseded
        && matches!((resident_of(&new), resident_of(&old)), (Ok(a), Ok(b)) if a == b))
}

/// `id`'s SKILL record when it is a live SKILL; `None` for an entity of
/// another type, a deleted one or none. An entity whose type it read is
/// noted in `reads`.
fn live_skill_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    reads: &mut Reads,
) -> Result<Option<SkillRecord>> {
    let entity_type = vault.get_entity_type_in_txn(txn, id)?;
    if entity_type.is_some() {
        reads.note(*id);
    }
    if entity_type != Some(ENTITY_TYPE_SKILL) {
        return Ok(None);
    }
    vault.get_skill_record_in_txn(txn, id)
}

/// The vault skill's newest admitted revision, following its supersession
/// chain forward, each step a [`skill_succession_in_txn`]. `None` when no
/// revision on the chain is loadable.
fn vault_head_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    vault_skill: EntityId,
    reads: &mut Reads,
) -> Result<Option<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut cursor = vault_skill;
    let mut head = None;
    while seen.insert(cursor) {
        let Some(record) = vault.get_skill_record_in_txn(txn, &cursor)? else {
            break;
        };
        reads.note(cursor);
        if skill_loadable(&record) {
            head = Some(cursor);
        }
        let mut next = None;
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &vault.store,
            txn,
            &cursor,
            crate::ports::EdgeDirection::In,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if !seen.contains(&peer) && skill_succession_in_txn(vault, txn, peer, cursor, reads)? {
                next = Some(peer);
                break;
            }
        }
        match next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    Ok(head)
}

/// The tree an admitted skill carries, if its package has one.
fn stored_tree_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<TaskTypeTree>> {
    let record = vault.get_skill_record_in_txn(txn, skill)?;
    if record.is_some() {
        reads.note(*skill);
    }
    match record {
        Some(record) if skill_loadable(&record) => {
            stored_tree_unchecked_in_txn(vault, txn, skill, reads)
        }
        _ => Ok(None),
    }
}

/// The tree file in `skill`'s stored package, whatever its lifecycle: the
/// version floor a fork's new tree is checked against.
fn stored_tree_unchecked_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<TaskTypeTree>> {
    let record = vault.read_skill_record_in_txn(txn, skill)?;
    reads.note(*skill);
    let package = vault.runtime_skill_package_in_txn(txn, skill, &record)?;
    if reads.naming() {
        note_carrier_in_txn(vault, txn, skill, &record, package.is_some(), reads);
    }
    let Some(package) = package else {
        return Ok(None);
    };
    let Some(file) = package
        .files
        .iter()
        .find(|file| file.path == TASK_TYPE_TREE_FILE)
    else {
        return Ok(None);
    };
    let tree: TaskTypeTree = serde_json::from_slice(&file.content)
        .map_err(|_| invalid("team-shape type tree does not decode"))?;
    validate_tree(&tree)?;
    Ok(Some(tree))
}

/// Notes the replicated source carrier that served `skill`'s package, when
/// one did, by the probe an export names it by (SCAN C022), in the same
/// read. The skill's own package row is the skill's. A carrier looked up
/// that served nothing, or a probe that fails, leaves the rows unknown: the
/// lookup may have read a row it then refused (FIX 7103).
fn note_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
    served: bool,
    reads: &mut Reads,
) {
    match vault.export_hub_package_carrier_in_txn(txn, skill, record) {
        Ok(None) => {}
        Ok(Some(carrier)) if served => reads.note(carrier),
        Ok(Some(_)) | Err(_) => reads.unknown(),
    }
}

/// A tree is structurally whole: a root, and every parent a stored node.
fn validate_tree(tree: &TaskTypeTree) -> Result<()> {
    if tree.version == 0 {
        return Err(invalid("a type tree version starts at 1"));
    }
    if !tree.nodes.contains_key(crate::task_type::ROOT_NODE_ID) {
        return Err(invalid("a type tree has a root"));
    }
    if tree.nodes.iter().any(|(id, node)| {
        node.node_id != *id
            || node
                .parent
                .as_ref()
                .is_some_and(|parent| !tree.nodes.contains_key(parent))
    }) {
        return Err(invalid("every type node names a stored parent"));
    }
    Ok(())
}
