//! Private canonical type-input source over the admitted ASSET replica.
//!
//! Selection data only: [`SelectedTeamType`] (asked-vs-effective included)
//! never grants reads and never proves a full fact. Admitted bodies are the
//! only decoded input; native reads are identity comparison only. Caller
//! pins bodies and prepares its grant clock before `txn`; this helper
//! opens no txn, persists no clock, and pins nothing.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::claim::{PointRead, ReadRow, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::Error;

use crate::task_type::TaskTypeRef;

/// Selection DATA (asked-vs-effective included), never a read grant or
/// full proof. Adds no project/type/actor to any published CLAIM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SelectedTeamType {
    pub asked_project: Option<EntityId>,
    pub project: EntityId,
    pub requested_type: Option<TaskTypeRef>,
    pub placed_type: TaskTypeRef,
    pub file: Option<SelectedTeamTypeFile>,
    pub entity_rows: Option<Vec<EntityId>>,
    pub root_lookup: Option<crate::skill_hub::HubRef>,
}

/// `None` file = code seed with no byte witness: skip this optional
/// source, never a fake `Some` with empty hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SelectedTeamTypeFile {
    pub head: EntityId,
    pub package_hash: [u8; 32],
    pub file_hash: [u8; 32],
}

/// Admitted snapshot: selection plus one body hash and row metadata per
/// read id. No plaintext body, grant, or authority is copied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CapturedTeamType {
    selection: SelectedTeamType,
    carrier: EntityId,
    rows: Vec<CapturedTeamTypeRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CapturedTeamTypeRow {
    id: EntityId,
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
    body_hash: [u8; 32],
}

impl CapturedTeamType {
    /// Original capture: one point read over entity rows + head + carrier.
    /// `None` (including `file`/`entity_rows` `None`) means skip this
    /// optional source. Ordinary birth/existing-source rows must not refuse.
    pub(crate) fn capture(
        reader: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        selection: &SelectedTeamType,
    ) -> Option<Self> {
        let file = selection.file.as_ref()?;
        let wanted = selection.entity_rows.as_ref()?;
        let expected = crate::skill::SkillContentHash::from_bytes(file.package_hash);
        let carrier =
            crate::store::skill_source_carrier::source_carrier_id(&file.head, &expected).ok()?;
        let mut set = BTreeSet::new();
        for id in wanted {
            set.insert(*id);
        }
        set.insert(file.head);
        set.insert(carrier);
        let ids: Vec<EntityId> = set.into_iter().collect();
        let reads: Vec<_> = ids.iter().map(|id| PointRead::id(*id)).collect();
        let rows = reader
            .read_projected_in_txn(txn, &reads, None, |_, rows| Ok::<_, Error>(rows))
            .ok()?
            .value;
        let vault = reader.vault();
        let mut by_id = BTreeMap::new();
        for (id, row) in ids.iter().zip(rows) {
            let row = row?;
            if row.id != *id || row.body.is_none() || row.deletion.is_some() {
                return None;
            }
            // Native identity only; the admitted body stays authoritative.
            // File-plane raw bytes hold a pointer, so the comparator is the
            // hydrated live row (same supplier as `read_source_carrier_in_txn`).
            let crate::vault::LiveEntityRow::Live {
                entity_type: native_type,
                body: native_body,
            } = crate::vault::live_entity_row_in_txn(&vault.store, txn, id).ok()?
            else {
                return None;
            };
            let body = row.body.as_deref()?;
            if native_type != row.entity_type || native_body.as_slice() != body {
                return None;
            }
            let raw =
                crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id).ok()??;
            let header = crate::batch::EntityMetadataHeader::parse(&raw)?;
            if header.entity_type != row.entity_type
                || header.learned_at != row.learned_at
                || header.occurred_start != row.occurred.start
                || header.occurred_end != row.occurred.end
            {
                return None;
            }
            by_id.insert(*id, row);
        }
        validate_file_rows(by_id.get(&file.head)?, by_id.get(&carrier)?, file)?;
        let mut snap = Vec::with_capacity(ids.len());
        for id in &ids {
            let row = by_id.get(id)?;
            snap.push(CapturedTeamTypeRow {
                id: *id,
                entity_type: row.entity_type,
                occurred_start: row.occurred.start,
                occurred_end: row.occurred.end,
                learned_at: row.learned_at,
                body_hash: *blake3::hash(row.body.as_deref()?).as_bytes(),
            });
        }
        Some(Self {
            selection: selection.clone(),
            carrier,
            rows: snap,
        })
    }

    /// Later Coach check under an independent key in the same snapshot:
    /// same ids, exact body+metadata equality, same full carrier/head/file
    /// check. Never trusts the original admitted key; no Memory/Owner/
    /// System shortcut. `root_lookup: Some` is always unknown (`None`).
    /// Returns only this canonical type-input contribution. Other receipt
    /// cohorts, including the inherited project, remain independently unknown.
    pub(crate) fn admitted_in_txn(
        &self,
        reader: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> Option<Vec<EntityId>> {
        if self.selection.root_lookup.is_some() {
            return None;
        }
        let complete = self.selection.entity_rows.as_ref()?;
        let file = self.selection.file.as_ref()?;
        let expected = crate::skill::SkillContentHash::from_bytes(file.package_hash);
        let carrier =
            crate::store::skill_source_carrier::source_carrier_id(&file.head, &expected).ok()?;
        if carrier != self.carrier {
            return None;
        }
        let ids: Vec<EntityId> = self.rows.iter().map(|row| row.id).collect();
        let reads: Vec<_> = ids.iter().map(|id| PointRead::id(*id)).collect();
        let live = reader
            .read_projected_in_txn(txn, &reads, None, |_, rows| Ok::<_, Error>(rows))
            .ok()?
            .value;
        let mut by_id = BTreeMap::new();
        for (snap, row) in self.rows.iter().zip(live) {
            let row = row?;
            if row.id != snap.id
                || row.entity_type != snap.entity_type
                || row.occurred.start != snap.occurred_start
                || row.occurred.end != snap.occurred_end
                || row.learned_at != snap.learned_at
                || row.deletion.is_some()
            {
                return None;
            }
            let body = row.body.as_deref()?;
            if *blake3::hash(body).as_bytes() != snap.body_hash {
                return None;
            }
            by_id.insert(snap.id, row);
        }
        validate_file_rows(by_id.get(&file.head)?, by_id.get(&carrier)?, file)?;
        for id in complete {
            if !by_id.contains_key(id) {
                return None;
            }
        }
        let mut out = complete.clone();
        if !out.contains(&carrier) {
            out.push(carrier);
        }
        Some(out)
    }
}

/// Full carrier/head/file check over admitted bodies only: holder binding,
/// exact derived carrier id, package hash, head-record metadata match, and
/// the complete `TASK_TYPE_TREE_FILE` bytes. Pointer/hash-only, native
/// PACKAGE without an admitted body, and unreadable rows all fail closed.
fn validate_file_rows(
    head: &ReadRow,
    carrier_row: &ReadRow,
    file: &SelectedTeamTypeFile,
) -> Option<()> {
    if head.entity_type != crate::registry::ENTITY_TYPE_SKILL
        || carrier_row.entity_type != crate::registry::ENTITY_TYPE_ASSET
    {
        return None;
    }
    let head_body = head.body.as_deref()?;
    let carrier_body = carrier_row.body.as_deref()?;
    let expected = crate::skill::SkillContentHash::from_bytes(file.package_hash);
    let record = crate::skill::decode_skill_record(head_body).ok()?;
    if record.content_hash.as_ref() != Some(&expected) {
        return None;
    }
    let (holder, package) = crate::skill_hub::decode_source_carrier(carrier_body).ok()??;
    if holder != file.head {
        return None;
    }
    let hash = package.content_hash().ok()?;
    let derived = crate::store::skill_source_carrier::source_carrier_id(&holder, &hash).ok()?;
    if derived != carrier_row.id || hash != expected {
        return None;
    }
    if package.record.skill_id != record.skill_id
        || package.record.version != record.version
        || package.record.desc != record.desc
        || package.record.role != record.role
        || package.record.call != record.call
    {
        return None;
    }
    let tree = package
        .files
        .iter()
        .find(|entry| entry.path == crate::agent_dispatch::TASK_TYPE_TREE_FILE)?;
    if *blake3::hash(&tree.content).as_bytes() != file.file_hash {
        return None;
    }
    Some(())
}
