//! Export-time withholding for worlds flagged device-only.
//!
//! Rows in a device-local world never leave the device that holds the flag
//! (DEC-0005). Packing skips them, but a carrier packed while its world was
//! still portable stays resident in the stored window. So every export reads
//! the flag again, in one read transaction, and cuts what it would ship. The
//! cut runs on a fork, never on the stored window: clearing the flag ships the
//! row again on the next export.

use std::collections::{BTreeSet, HashMap, HashSet};

use heed::RoTxn;
use loro::json::{JsonOpContent, JsonSchema, MapOp};
use loro::{CommitOptions, ContainerID, ContainerType, LoroDoc, LoroMap, LoroValue, VersionVector};

use super::super::bridge::{BRIDGE_ORIGIN, parse_edge_key};
use super::super::loro_support::{map_delete, map_for_each_value_bytes};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};

/// The root maps whose keys name a row: entity carriers, edges, and the world
/// witnesses of retained claim shells.
const ENTITIES: &str = "entities";
const EDGES: &str = "edges";
const WITNESSES: &str = "retained_claim_worlds";

/// `device_only_withholds` over one read transaction, remembered per id.
struct Withheld<'a, 't> {
    vault: &'a Vault,
    rtxn: &'a RoTxn<'t>,
    flagged: BTreeSet<EntityId>,
    known: HashMap<EntityId, bool>,
}

impl<'a, 't> Withheld<'a, 't> {
    fn read(vault: &'a Vault, rtxn: &'a RoTxn<'t>) -> Result<Self> {
        Ok(Self {
            vault,
            rtxn,
            flagged: crate::settings::device_only_worlds_in(&vault.store, rtxn)?,
            known: HashMap::new(),
        })
    }

    fn id(&mut self, id: EntityId) -> Result<bool> {
        if let Some(&known) = self.known.get(&id) {
            return Ok(known);
        }
        let withheld = crate::settings::device_only_withholds(
            &self.vault.store,
            self.rtxn,
            &self.flagged,
            &id,
        )?;
        self.known.insert(id, withheld);
        Ok(withheld)
    }

    /// The body decides first: a CLAIM carrier naming a flagged world stays
    /// here whatever its map key or stored row says.
    fn carrier(&mut self, key: &str, blob: Option<&[u8]>) -> Result<bool> {
        let id = EntityId::from_hex(key).ok();
        if blob.is_some_and(|raw| claim_in_flagged_world(raw, &self.flagged)) {
            if let Some(id) = id {
                self.known.insert(id, true);
            }
            return Ok(true);
        }
        id.map_or(Ok(false), |id| self.id(id))
    }

    /// Either endpoint withheld withholds the edge.
    fn edge(&mut self, key: &str) -> Result<bool> {
        let Some((src, _, tgt)) = parse_edge_key(key) else {
            return Ok(false);
        };
        Ok(self.id(src)? || self.id(tgt)?)
    }

    fn witness(&mut self, key: &str) -> Result<bool> {
        EntityId::from_hex(key).map_or(Ok(false), |id| self.id(id))
    }
}

fn claim_in_flagged_world(raw: &[u8], flagged: &BTreeSet<EntityId>) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            .is_ok_and(|body| body.world.is_some_and(|world| flagged.contains(&world)))
}

/// Ids among `entities` and the endpoints of `edges` (wherever those rows
/// live) that a device-only world keeps on this device. Read inside the
/// caller's export transaction.
pub(in crate::sync) fn device_only_ids(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    entities: &LoroMap,
    edges: &LoroMap,
) -> Result<HashSet<EntityId>> {
    let mut check = Withheld::read(vault, rtxn)?;
    let mut ids = HashSet::new();
    if check.flagged.is_empty() {
        return Ok(ids);
    }
    for (key, blob) in rows(entities) {
        if let Ok(id) = EntityId::from_hex(&key)
            && check.carrier(&key, blob.as_deref())?
        {
            ids.insert(id);
        }
    }
    for (key, _) in rows(edges) {
        if let Some((src, _, tgt)) = parse_edge_key(&key) {
            for id in [src, tgt] {
                if check.id(id)? {
                    ids.insert(id);
                }
            }
        }
    }
    Ok(ids)
}

/// The map keys one export must not carry.
#[derive(Default)]
struct Cut {
    entities: BTreeSet<String>,
    edges: BTreeSet<String>,
    witnesses: BTreeSet<String>,
}

impl Cut {
    fn is_empty(&self) -> bool {
        self.entities.is_empty() && self.edges.is_empty() && self.witnesses.is_empty()
    }

    /// Every operation in `json` on a row-naming map that names a withheld row.
    fn ops(&mut self, check: &mut Withheld<'_, '_>, json: &JsonSchema) -> Result<()> {
        let entities = ContainerID::new_root(ENTITIES, ContainerType::Map);
        let edges = ContainerID::new_root(EDGES, ContainerType::Map);
        let witnesses = ContainerID::new_root(WITNESSES, ContainerType::Map);
        for op in json.changes.iter().flat_map(|change| &change.ops) {
            let JsonOpContent::Map(map_op) = &op.content else {
                continue;
            };
            let (key, blob) = match map_op {
                MapOp::Insert {
                    key,
                    value: LoroValue::Binary(blob),
                } => (key, Some(blob.as_slice())),
                MapOp::Insert { key, .. } | MapOp::Delete { key } => (key, None),
            };
            if op.container == entities {
                if check.carrier(key, blob)? {
                    self.entities.insert(key.clone());
                }
            } else if op.container == edges {
                if check.edge(key)? {
                    self.edges.insert(key.clone());
                }
            } else if op.container == witnesses && check.witness(key)? {
                self.witnesses.insert(key.clone());
            }
        }
        Ok(())
    }

    /// Every withheld body and witness in the live state. Edges only when
    /// `all_edges`: otherwise an edge is cut only where an operation the
    /// receiver lacks names it.
    fn state(
        &mut self,
        check: &mut Withheld<'_, '_>,
        doc: &LoroDoc,
        all_edges: bool,
    ) -> Result<()> {
        for (key, blob) in rows(&doc.get_map(ENTITIES)) {
            if check.carrier(&key, blob.as_deref())? {
                self.entities.insert(key);
            }
        }
        for (key, _) in rows(&doc.get_map(WITNESSES)) {
            if check.witness(&key)? {
                self.witnesses.insert(key);
            }
        }
        if all_edges {
            for (key, _) in rows(&doc.get_map(EDGES)) {
                if check.edge(&key)? {
                    self.edges.insert(key);
                }
            }
        }
        Ok(())
    }
}

fn rows(map: &LoroMap) -> Vec<(String, Option<Vec<u8>>)> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(map, |key, blob| {
        rows.push((key.to_owned(), blob.map(<[u8]>::to_vec)));
    });
    rows
}

/// Cuts a window export down to what may leave this device.
///
/// `bytes` is the export already built for a receiver at `remote`. With no
/// world flagged, or nothing withheld in what the bytes carry or the receiver
/// lacks, it ships unchanged. Otherwise the export becomes a history-free
/// snapshot of a fork with every withheld body removed. A withheld edge is
/// removed only when the receiver lacks it: a bare edge removal deletes the
/// receiver's own stored edge, and an edge the receiver already holds tells it
/// nothing new. When the receiver's gap cannot be read in full (a shallow
/// window), every withheld edge is removed.
pub(super) fn cut_device_only_export(
    vault: &Vault,
    doc: &LoroDoc,
    remote: &VersionVector,
    bytes: Vec<u8>,
) -> Result<Vec<u8>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut check = Withheld::read(vault, &rtxn)?;
    if check.flagged.is_empty() {
        return Ok(bytes);
    }
    let meta = LoroDoc::decode_import_blob_meta(&bytes, false).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "device-only export",
            source,
        })
    })?;
    let mut cut = Cut::default();
    let current = doc.oplog_vv();
    let lacked = doc.export_json_updates(remote, &current);
    let complete = matches!(
        (op_count(&lacked), missing_count(remote, &current)),
        (Some(have), Some(want)) if have == want
    );
    cut.ops(&mut check, &lacked)?;
    if meta.mode.is_snapshot() {
        // A snapshot's retained history can reach behind the receiver's gap.
        cut.ops(
            &mut check,
            &doc.export_json_updates(&meta.partial_start_vv, &meta.partial_end_vv),
        )?;
    }
    if meta.mode.is_snapshot() || !cut.is_empty() {
        cut.state(&mut check, doc, !complete)?;
    }
    if cut.is_empty() {
        return Ok(bytes);
    }
    drop(rtxn);
    let fork = doc.fork();
    let entities = fork.get_map(ENTITIES);
    for key in &cut.entities {
        map_delete(&entities, key)?;
        if let Ok(id) = EntityId::from_hex(key) {
            crate::sync::note::deleted(&fork, &id)?;
        }
    }
    let edges = fork.get_map(EDGES);
    for key in &cut.edges {
        map_delete(&edges, key)?;
    }
    let witnesses = fork.get_map(WITNESSES);
    for key in &cut.witnesses {
        map_delete(&witnesses, key)?;
    }
    // One commit after every head: the snapshot's retained history is this
    // commit alone, never an older operation that set a withheld row.
    fork.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    super::egress::export_history_free_window_snapshot(&fork)
}

fn op_count(json: &JsonSchema) -> Option<usize> {
    json.changes
        .iter()
        .flat_map(|change| &change.ops)
        .try_fold(0_usize, |total, op| total.checked_add(op.content.op_len()))
}

fn missing_count(remote: &VersionVector, current: &VersionVector) -> Option<usize> {
    current.iter().try_fold(0_usize, |total, (peer, end)| {
        let start = remote.get(peer).copied().unwrap_or(0);
        total.checked_add(usize::try_from(end.saturating_sub(start).max(0)).ok()?)
    })
}
