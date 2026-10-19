//! Imported and hub-derived instruction authority at the single SKILL materialization door.
use std::collections::BTreeMap;

use super::HubPackage;
use super::package_codec::invalid;
use crate::agent_dispatch::{TASK_TYPE_TREE_FILE, team_shape_skill};
use crate::side_table::{self, Raw, SideTable, StagedRow};
use crate::task_type::{TaskTypeTree, TreeScope};
use crate::{
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    claim::ClaimSource,
    entity_id::EntityId,
    error::{Error, Result},
    skill::{SkillLifecycle, SkillRecord},
    store::Store,
};

/// Origin marker for a hub-materialized skill (imported flag, optional
/// forked-from parent id); survives deletion so it cannot be laundered by
/// delete/recreate.
///
/// The write half of this table is a [`StagedRow`] built here for
/// [`crate::batch::put_apply::apply`] (outside this module) to commit inside
/// its own put transaction alongside the rest of the entity write.
const ORIGIN: SideTable<EntityId, Vec<u8>, Raw> = SideTable::new(&side_table::SKILL_HUB_ORIGIN);

/// An exact-body activation authorization. Post-fit proof alone may suppress
/// the advisory scan's independent approval rewrite; other doors keep it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HubAdmissionKind {
    MarketplacePostFit(crate::skill::SkillContentHash),
    PackPostFit(crate::skill::SkillContentHash),
    OwnerConsent,
    HeldOut,
    Bootstrap,
    Optimized,
    Refined,
    Rollback,
    ProjectTreeFork,
}
#[derive(Debug)]
pub(crate) struct HubAdmissionProof {
    id: EntityId,
    binding: blake3::Hash,
    kind: HubAdmissionKind,
}
impl HubAdmissionProof {
    fn new(id: EntityId, data: &[u8], kind: HubAdmissionKind) -> Self {
        Self {
            id,
            binding: blake3::hash(data),
            kind,
        }
    }
    pub(in crate::skill_hub) fn marketplace(
        id: EntityId,
        data: &[u8],
        hash: crate::skill::SkillContentHash,
    ) -> Self {
        Self::new(id, data, HubAdmissionKind::MarketplacePostFit(hash))
    }
    pub(in crate::skill_hub) fn post_fit(
        id: EntityId,
        data: &[u8],
        hash: crate::skill::SkillContentHash,
    ) -> Self {
        Self::new(id, data, HubAdmissionKind::PackPostFit(hash))
    }
    pub(in crate::skill_hub) fn bootstrap(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Bootstrap)
    }
    pub(in crate::skill_hub) fn optimized(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Optimized)
    }
    /// A shared merge's activation, minted only beside the refinement proof
    /// that binds its useful-upstream yes and held-out win to these bytes.
    pub(in crate::skill_hub) fn refined(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Refined)
    }
    /// A rollback revision's activation, minted only by the rollback door
    /// over the displaced revision's own content.
    pub(in crate::skill_hub) fn rollback(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::Rollback)
    }
    /// A project tree fork's activation, minted only by
    /// [`crate::Vault::admit_project_tree_fork_in_txn`] once the fork passed
    /// its four checks, or by
    /// [`crate::Vault::admit_project_tree_revision_in_txn`] once a later
    /// revision of the project's own tree passed its checks.
    pub(in crate::skill_hub) fn project_tree_fork(id: EntityId, data: &[u8]) -> Self {
        Self::new(id, data, HubAdmissionKind::ProjectTreeFork)
    }
    pub(in crate::skill_hub) fn consent(
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: &[u8],
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        crate::consent::spend_approve_once_in_txn(store, txn, authorization)?;
        Ok(Self::new(id, data, HubAdmissionKind::OwnerConsent))
    }
    pub(in crate::skill_hub) fn held_out(
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        data: &[u8],
        authorization: &crate::consent::ApproveOnceAuthorization,
    ) -> Result<Self> {
        crate::consent::spend_approve_once_in_txn(store, txn, authorization)?;
        Ok(Self::new(id, data, HubAdmissionKind::HeldOut))
    }
    pub(in crate::skill_hub) fn id(&self) -> EntityId {
        self.id
    }
    pub(crate) fn binds(&self, id: &EntityId, data: &[u8]) -> bool {
        self.id == *id && self.binding == blake3::hash(data)
    }
    /// Called after the SKILL materialization guard verified this exact proof.
    /// A post-fit signal was already resolved by the host; scan is not consent.
    pub(crate) fn resolved_post_fit(
        &self,
        id: &EntityId,
        data: &[u8],
        record: &SkillRecord,
    ) -> bool {
        let hash = match self.kind {
            HubAdmissionKind::MarketplacePostFit(hash) | HubAdmissionKind::PackPostFit(hash) => {
                hash
            }
            _ => return false,
        };
        self.binds(id, data)
            && record.content_hash == Some(hash)
            && record.source == ClaimSource::Imported
    }
}

/// Post-fit proof has already resolved advisory signals; all other writes
/// retain the existing scan consent escalation at the batch chokepoint.
pub(crate) fn scan_skill_admission(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &mut SkillRecord,
    proof: Option<&HubAdmissionProof>,
) -> Result<bool> {
    let encoded = crate::skill::encode_skill_record(record)?;
    if proof.is_some_and(|proof| proof.resolved_post_fit(id, &encoded, record)) {
        Ok(false)
    } else {
        crate::skill_scan::escalate_activation_approval_in_txn(store, txn, id, record)
    }
}

impl crate::Vault {
    pub(in crate::skill_hub) fn admit_hub_skill_record_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: crate::TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        proof: HubAdmissionProof,
    ) -> Result<()> {
        self.admit_hub_skill_record_with_refinement_in_txn(
            txn, occurred, learned_at, data, proof, None,
        )
    }

    pub(in crate::skill_hub) fn admit_hub_skill_record_with_refinement_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        occurred: crate::TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        proof: HubAdmissionProof,
        refinement: Option<super::refinement_admission::RefinementAdmissionProof>,
    ) -> Result<()> {
        let candidate = proof.id();
        let mode = crate::batch::ApplyOpsGateMode::new(false, true).with_hub_admission(proof);
        let mode = match refinement {
            Some(refinement) => mode.with_refinement_admission(refinement),
            None => mode,
        };
        crate::batch::apply_ops_with_gate_mode(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id: candidate,
                entity_type: crate::registry::ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            mode,
        )
    }

    /// Puts `fork`, a project's fork of the vault team-shape skill, in force
    /// (ARCH-0079 #task-type, OF-420), in the caller's write. It admits only
    /// when all four hold: (a) the fork is a Candidate cut from the vault's
    /// in-force team-shape head; (b) its package is the head's with only
    /// `task-type-tree.json` and SKILL.md's `name:` and `version:` lines
    /// changed; (c) its tree is scoped to `project`; (d) `held_out`, the
    /// head's and the fork's scores on the project's held-out runs, is a
    /// strict win, both finite in [0, 1]. The scoring runs before the write,
    /// outside it. The admitted fork must load: an approval the owner has not
    /// given keeps it a Candidate. The caller attaches it to the project.
    ///
    /// # Errors
    ///
    /// [`crate::error::ArtifactError::InvalidSkillBody`] when a check fails;
    /// the materialization door's refusals; storage errors.
    pub(crate) fn admit_project_tree_fork_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fork: &EntityId,
        project: EntityId,
        held_out: (f32, f32),
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let (before, after) = held_out;
        if !(0.0..=1.0).contains(&before) || !(0.0..=1.0).contains(&after) || after <= before {
            return Err(invalid(
                "a project tree fork goes in force only on a strict held-out win",
            ));
        }
        let staged = self.read_skill_record_in_txn(txn, fork)?;
        let Some(head) = team_shape_head_in_txn(self, txn)?
            .filter(|head| staged.forked_from == Some(*head))
            .filter(|_| staged.lifecycle_status == SkillLifecycle::Candidate)
        else {
            return Err(invalid(
                "a project tree fork is an open fork of the in-force team-shape head",
            ));
        };
        let head_record = self.read_skill_record_in_txn(txn, &head)?;
        let (Some(base), Some(package)) = (
            self.runtime_skill_package_in_txn(txn, &head, &head_record)?,
            self.runtime_skill_package_in_txn(txn, fork, &staged)?,
        ) else {
            return Err(invalid(
                "a project tree fork and its head both carry a package",
            ));
        };
        if !tree_only_edit(&base, &package)? {
            return Err(invalid(
                "a project tree fork changes only its tree and its SKILL.md name and version",
            ));
        }
        let project_ref = project.to_hex();
        let scoped = package
            .files
            .iter()
            .find(|file| file.path == TASK_TYPE_TREE_FILE)
            .and_then(|file| serde_json::from_slice::<TaskTypeTree>(&file.content).ok())
            .is_some_and(|tree| {
                matches!(
                    &tree.scope,
                    TreeScope::Project { project_ref: Some(scope), .. } if *scope == project_ref
                )
            });
        if !scoped {
            return Err(invalid(
                "a project tree fork's tree is scoped to its project",
            ));
        }
        let mut admitted = staged;
        admitted.lifecycle_status = SkillLifecycle::Active;
        if !crate::skill::skill_loadable(&admitted) {
            return Err(invalid(
                "a project tree fork the owner has not approved stays a Candidate",
            ));
        }
        let data = crate::skill::encode_skill_record(&admitted)?;
        let proof = HubAdmissionProof::project_tree_fork(*fork, &data);
        self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)
    }

    /// Puts `revision`, a later revision of a project's own team-shape tree,
    /// in force for `project` (ARCH-0079 #task-type, OF-420), in the caller's
    /// write. It admits only when all hold: (a) `incumbent` is the team-shape
    /// skill in force for `project`, a fork of the project's own whose tree
    /// is scoped to it, never the vault head the project falls back to; (b)
    /// `revision` is an open Candidate forked from `incumbent`; (c) its
    /// package is the incumbent's with only `task-type-tree.json` and
    /// SKILL.md's `name:` and `version:` lines changed; (d) its tree is
    /// scoped to `project`; (e) `held_out`, the incumbent's and the
    /// revision's scores on the project's held-out runs, is a strict win,
    /// both finite in [0, 1]. The scoring runs before the write, outside it.
    /// The admitted revision must load: an approval the owner has not given
    /// keeps it a Candidate. The caller attaches it to the project; the
    /// incumbent stays as it is, for a revert to fall back to. A project's
    /// first fork, of the vault head, goes through
    /// [`Self::admit_project_tree_fork_in_txn`] instead.
    ///
    /// # Errors
    ///
    /// [`crate::error::ArtifactError::InvalidSkillBody`] when a check fails;
    /// the materialization door's refusals; storage errors.
    #[expect(
        clippy::too_many_arguments,
        reason = "one revision, its project, the incumbent it revises and its scores"
    )]
    pub(crate) fn admit_project_tree_revision_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        revision: &EntityId,
        project: EntityId,
        incumbent: &EntityId,
        held_out: (f32, f32),
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let (before, after) = held_out;
        if !(0.0..=1.0).contains(&before) || !(0.0..=1.0).contains(&after) || after <= before {
            return Err(invalid(
                "a project tree revision goes in force only on a strict held-out win",
            ));
        }
        let project_ref = project.to_hex();
        let in_force =
            crate::agent_dispatch::team_shape_skill_in_force_in_txn(self, txn, Some(project))?;
        if in_force != Some(*incumbent) || team_shape_head_in_txn(self, txn)? == Some(*incumbent) {
            return Err(invalid(
                "a project tree revision revises the project's own tree in force",
            ));
        }
        let incumbent_record = self.read_skill_record_in_txn(txn, incumbent)?;
        let staged = self.read_skill_record_in_txn(txn, revision)?;
        if staged.forked_from != Some(*incumbent)
            || staged.lifecycle_status != SkillLifecycle::Candidate
        {
            return Err(invalid(
                "a project tree revision is an open fork of the project's tree in force",
            ));
        }
        let (Some(base), Some(package)) = (
            self.runtime_skill_package_in_txn(txn, incumbent, &incumbent_record)?,
            self.runtime_skill_package_in_txn(txn, revision, &staged)?,
        ) else {
            return Err(invalid(
                "a project tree revision and the tree it revises both carry a package",
            ));
        };
        if !tree_scoped_to(&base, &project_ref) {
            return Err(invalid(
                "a project tree revision revises a tree scoped to its project",
            ));
        }
        if !tree_only_edit(&base, &package)? {
            return Err(invalid(
                "a project tree revision changes only its tree and its SKILL.md name and version",
            ));
        }
        if !tree_scoped_to(&package, &project_ref) {
            return Err(invalid(
                "a project tree revision's tree is scoped to its project",
            ));
        }
        let mut admitted = staged;
        admitted.lifecycle_status = SkillLifecycle::Active;
        if !crate::skill::skill_loadable(&admitted) {
            return Err(invalid(
                "a project tree revision the owner has not approved stays a Candidate",
            ));
        }
        let data = crate::skill::encode_skill_record(&admitted)?;
        let proof = HubAdmissionProof::project_tree_fork(*revision, &data);
        self.admit_hub_skill_record_in_txn(txn, occurred, learned_at, data, proof)
    }
}

/// Whether `package` carries a task-type tree scoped to the project
/// `project_ref` names.
fn tree_scoped_to(package: &HubPackage, project_ref: &str) -> bool {
    package
        .files
        .iter()
        .find(|file| file.path == TASK_TYPE_TREE_FILE)
        .and_then(|file| serde_json::from_slice::<TaskTypeTree>(&file.content).ok())
        .is_some_and(|tree| {
            matches!(
                &tree.scope,
                TreeScope::Project { project_ref: Some(scope), .. } if scope == project_ref
            )
        })
}

/// The vault team-shape skill's newest admitted revision in `txn`, read as
/// the tree loader reads it: the bootstrap skill's supersession chain,
/// followed forward to its last loadable revision.
fn team_shape_head_in_txn(vault: &crate::Vault, txn: &heed::RoTxn<'_>) -> Result<Option<EntityId>> {
    let mut seen = std::collections::BTreeSet::new();
    let mut cursor = team_shape_skill()?;
    let mut head = None;
    while seen.insert(cursor) {
        let Some(record) = vault.get_skill_record_in_txn(txn, &cursor)? else {
            break;
        };
        if crate::skill::skill_loadable(&record) {
            head = Some(cursor);
        }
        let mut next = None;
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &vault.store,
            txn,
            &cursor,
            crate::ports::EdgeDirection::In,
            crate::edge::EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if !seen.contains(&peer) {
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

/// Whether `fork`'s package is `head`'s with only the task-type tree and
/// SKILL.md's `name:` and `version:` lines changed, and carries a tree.
fn tree_only_edit(head: &HubPackage, fork: &HubPackage) -> Result<bool> {
    let (base, edited) = (files_beside_tree(head), files_beside_tree(fork));
    if base.len() != edited.len()
        || !fork
            .files
            .iter()
            .any(|file| file.path == TASK_TYPE_TREE_FILE)
    {
        return Ok(false);
    }
    for (path, content) in base {
        let Some(other) = edited.get(path) else {
            return Ok(false);
        };
        let same = if path == "SKILL.md" {
            without_identity(content)? == without_identity(other)?
        } else {
            content == *other
        };
        if !same {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A package's files other than its task-type tree, by path.
fn files_beside_tree(package: &HubPackage) -> BTreeMap<&str, &[u8]> {
    package
        .files
        .iter()
        .filter(|file| file.path != TASK_TYPE_TREE_FILE)
        .map(|file| (file.path.as_str(), file.content.as_slice()))
        .collect()
}

/// SKILL.md without its frontmatter `name:` and `version:` lines, the two a
/// project tree fork may change; a SKILL.md with no frontmatter as it is.
fn without_identity(content: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(content).map_err(|_| invalid("SKILL.md is not UTF-8"))?;
    let Some(front) = super::folder::source_frontmatter(text)? else {
        return Ok(text.to_owned());
    };
    let kept: Vec<&str> = front
        .split('\n')
        .filter(|line| !line.starts_with("name:") && !line.starts_with("version:"))
        .collect();
    Ok(format!(
        "{}\n---\n{}",
        kept.join("\n"),
        &text[4 + front.len() + 5..]
    ))
}
fn origin(record: &SkillRecord) -> Vec<u8> {
    let mut out = vec![u8::from(record.source == ClaimSource::Imported)];
    if let Some(parent) = record.forked_from {
        out.extend_from_slice(parent.as_bytes());
    }
    out
}
/// Read-only preflight. Its optional marker is staged only after all remote-refusal checks.
/// Markers survive deletion, so delete/recreate cannot launder a governed id into owner-authored content.
pub(crate) fn check_hub_skill_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    record: &SkillRecord,
    replaces_source: bool,
    proof: Option<&HubAdmissionProof>,
) -> Result<Option<StagedRow>> {
    super::package_codec::check_source_binding_update(store, txn, id, record, replaces_source)?;
    let marked = ORIGIN.get(store, txn, id)?;
    let current_origin = origin(record);
    if let Some(marked) = &marked
        && marked.as_slice() != current_origin.as_slice()
    {
        return Err(invalid(
            "hub or fork origin cannot be removed, including after deletion",
        ));
    }
    if marked.is_none() && !has_import_origin(store, txn, record)? {
        return Ok(None);
    }
    let prior = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .map(|raw| {
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
                return Err(invalid("skill id type changed"));
            }
            crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
        })
        .transpose()?;
    if let Some(prior) = &prior
        && origin(prior) != current_origin
    {
        return Err(invalid("hub or fork origin is immutable"));
    }
    let unchanged_active = prior
        .as_ref()
        .is_some_and(|prior| prior.lifecycle_status == SkillLifecycle::Active)
        && prior
            .as_ref()
            .map(crate::skill_optimize::skill_body_binding_digest)
            .transpose()?
            == Some(crate::skill_optimize::skill_body_binding_digest(record)?);
    if record.lifecycle_status == SkillLifecycle::Active && !unchanged_active {
        // Code-bearing hub source stays Candidate until a foreign microVM can
        // execute and return its typed result. The in-process JS runtime
        // deliberately refuses Foreign; a held-out text score is not that
        // sandbox qualification. Imported ancestry keeps this guard on forks.
        if record.role == crate::skill::SkillRole::Callable {
            return Err(invalid(
                "imported callable activation requires foreign sandbox qualification",
            ));
        }
        if record.source == ClaimSource::Imported
            && let Some(hash) = record.content_hash
            && super::import_receipt::marketplace_hash_blocked_in_txn(store, txn, hash)?
        {
            return Err(invalid("marketplace hash rule blocks activation"));
        }
        let proof = proof.ok_or_else(|| {
            invalid("hub or fork activation requires local consent and held-out replay")
        })?;
        let encoded = crate::skill::encode_skill_record(record)?;
        if !proof.binds(id, &encoded) {
            return Err(invalid(
                "hub admission proof does not bind this exact record",
            ));
        }
    }
    marked
        .is_none()
        .then(|| ORIGIN.stage(id, &current_origin))
        .transpose()
}

/// A local owner-authored fork is not a marketplace import. Imported ancestry
/// stays governed across arbitrary forks; missing or cyclic ancestry refuses.
fn has_import_origin(store: &Store, txn: &heed::RoTxn<'_>, record: &SkillRecord) -> Result<bool> {
    if record.source == ClaimSource::Imported {
        return Ok(true);
    }
    let mut parent = record.forked_from;
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = parent {
        if !seen.insert(id) {
            return Err(invalid("invalid skill fork ancestry"));
        }
        if ORIGIN.contains(store, txn, &id)? {
            return Ok(true);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
            .ok_or_else(|| invalid("skill fork ancestry is missing"))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("skill ancestor header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_SKILL {
            return Err(invalid("skill ancestor changed type"));
        }
        let prior = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if prior.source == ClaimSource::Imported {
            return Ok(true);
        }
        parent = prior.forked_from;
    }
    Ok(false)
}
