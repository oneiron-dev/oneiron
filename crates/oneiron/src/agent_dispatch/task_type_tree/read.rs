//! One tree-selection algorithm over canonical or composed content.

use super::*;

pub(super) enum TreeRead<'a> {
    Canonical(&'a Vault),
    Composed(crate::store::StoreRead<'a>, crate::HostingPrivacyPosture),
}

impl TreeRead<'_> {
    fn rows(&self) -> crate::store::StoreRead<'_> {
        match self {
            Self::Canonical(vault) => vault.store.read(),
            Self::Composed(rows, _) => *rows,
        }
    }

    fn visible_project_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        project: EntityId,
    ) -> Result<Option<crate::workspace_roster::ProjectRecord>> {
        match self {
            Self::Canonical(vault) => vault.visible_project_in_txn(txn, project),
            Self::Composed(rows, posture) => {
                crate::workspace_roster::visible_project_in_read(rows, txn, *posture, project)
            }
        }
    }

    fn get_skill_record_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<SkillRecord>> {
        crate::skill::get_skill_record_on(&self.rows(), txn, id)
    }

    fn read_skill_record_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<SkillRecord> {
        crate::skill::read_skill_record_on(&self.rows(), txn, id)
    }

    fn get_entity_type_in_txn(&self, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Option<u8>> {
        Ok(
            crate::ports::EntityStoreRead::port_entity_record(&self.rows(), txn, id)?
                .map(|row| row.entity_type),
        )
    }

    fn runtime_skill_package_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        skill: &EntityId,
        record: &SkillRecord,
    ) -> Result<Option<HubPackage>> {
        match self {
            Self::Canonical(vault) => vault.runtime_skill_package_in_txn(txn, skill, record),
            Self::Composed(rows, _) => {
                crate::skill_hub::runtime_skill_package_in_read(rows, txn, skill, record)
            }
        }
    }
}

pub(super) fn tree_in_force_with_root_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    project: Option<EntityId>,
    vault_skill: EntityId,
    reads: &mut Reads,
) -> Result<TaskTypeTree> {
    if project.is_some() {
        // A project's visibility folds rows this module cannot name.
        reads.unknown();
    }
    if let Some(project) = project
        && let Some(fork) = project_fork_in_read(read, txn, project, vault_skill)?
        && let Some(tree) = stored_tree_in_read(read, txn, &fork, reads)?
    {
        return Ok(tree);
    }
    Ok(match vault_head_in_read(read, txn, vault_skill, reads)? {
        Some(head) => {
            stored_tree_in_read(read, txn, &head, reads)?.unwrap_or_else(TaskTypeTree::seeded)
        }
        None => TaskTypeTree::seeded(),
    })
}

pub(super) fn project_fork_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    vault_skill: EntityId,
) -> Result<Option<EntityId>> {
    let Some(record) = read.visible_project_in_txn(txn, project)? else {
        return Ok(None);
    };
    for fork in record.skill_forks.iter().rev() {
        let Ok(fork) = EntityId::from_hex(fork) else {
            continue;
        };
        if read
            .get_skill_record_in_txn(txn, &fork)?
            .is_some_and(|skill| skill_loadable(&skill))
            && in_lineage_in_read(read, txn, fork, vault_skill)?
        {
            return Ok(Some(fork));
        }
    }
    Ok(None)
}

pub(super) fn in_lineage_in_read(
    read: &TreeRead<'_>,
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
        let Some(record) = read.get_skill_record_in_txn(txn, &id)? else {
            continue;
        };
        if let Some(parent) = record.forked_from {
            pending.push(parent);
        }
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &read.rows(),
            txn,
            &id,
            crate::ports::EdgeDirection::Out,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if skill_succession_in_read(read, txn, id, peer, &mut Reads::Off)? {
                pending.push(peer);
            }
        }
    }
    Ok(false)
}

pub(super) fn skill_succession_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    successor: EntityId,
    predecessor: EntityId,
    reads: &mut Reads,
) -> Result<bool> {
    if successor == predecessor {
        return Ok(false);
    }
    let (Some(new), Some(old)) = (
        live_skill_in_read(read, txn, &successor, reads)?,
        live_skill_in_read(read, txn, &predecessor, reads)?,
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
fn live_skill_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    reads: &mut Reads,
) -> Result<Option<SkillRecord>> {
    let entity_type = read.get_entity_type_in_txn(txn, id)?;
    if entity_type.is_some() {
        reads.note(*id);
    }
    if entity_type != Some(ENTITY_TYPE_SKILL) {
        return Ok(None);
    }
    read.get_skill_record_in_txn(txn, id)
}

pub(super) fn vault_head_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    vault_skill: EntityId,
    reads: &mut Reads,
) -> Result<Option<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut cursor = vault_skill;
    let mut head = None;
    while seen.insert(cursor) {
        let Some(record) = read.get_skill_record_in_txn(txn, &cursor)? else {
            break;
        };
        reads.note(cursor);
        if skill_loadable(&record) {
            head = Some(cursor);
        }
        let mut next = None;
        for peer in crate::ports::EdgeStoreRead::port_edge_peers(
            &read.rows(),
            txn,
            &cursor,
            crate::ports::EdgeDirection::In,
            EdgeKind::Supersedes,
        )? {
            let peer = peer?;
            if !seen.contains(&peer) && skill_succession_in_read(read, txn, peer, cursor, reads)? {
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
fn stored_tree_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<TaskTypeTree>> {
    let record = read.get_skill_record_in_txn(txn, skill)?;
    if record.is_some() {
        reads.note(*skill);
    }
    match record {
        Some(record) if skill_loadable(&record) => {
            stored_tree_unchecked_in_read(read, txn, skill, reads)
        }
        _ => Ok(None),
    }
}

pub(super) fn stored_tree_unchecked_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    reads: &mut Reads,
) -> Result<Option<TaskTypeTree>> {
    let record = read.read_skill_record_in_txn(txn, skill)?;
    reads.note(*skill);
    let package = read.runtime_skill_package_in_txn(txn, skill, &record)?;
    if reads.naming() {
        note_carrier_in_read(read, txn, skill, &record, package.is_some(), reads);
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
/// lookup may have read a row it then refused (FIX 7103). A composed read
/// cannot use the canonical export probe and keeps its sources unknown.
fn note_carrier_in_read(
    read: &TreeRead<'_>,
    txn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
    served: bool,
    reads: &mut Reads,
) {
    let TreeRead::Canonical(vault) = read else {
        reads.unknown();
        return;
    };
    match vault.export_hub_package_carrier_in_txn(txn, skill, record) {
        Ok(None) => {}
        Ok(Some(carrier)) if served => reads.note(carrier),
        Ok(Some(_)) | Err(_) => reads.unknown(),
    }
}
