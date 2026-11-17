//! Durable pending-mirror markers (FIX 7957, FIX 9599).
//!
//! A local write that changes a row leaves a marker in its own transaction:
//! the window that holds the row owes it the row's carrier. A write that
//! removes an edge leaves one for the edge's key: the window that holds the
//! edge owes its removal, which no upsert of the source's remaining edges
//! makes. A marker stays until its window's change is durable, so a crash
//! between the commit and the live mirror loses neither.
//!
//! A loaded window takes what its markers owe in the live mirror's next pass,
//! beside the rows the commit handed over; Observer A persists each bridge
//! commit's update inside the commit, and the markers go after the pass. A
//! window that opens takes them in its recovery, before the forward pass can
//! read a stale carrier or a removed edge back into the store; the markers go
//! once the recovered delta is persisted. At start the live mirror opens each
//! window a marker names, so what a stopped process owed reaches peers
//! without waiting for the window's next use.
//!
//! A sync import that lands a row merged with the row held here
//! (ROOM-PINS-LWW-MERGE) leaves a merged-carrier marker, which names the
//! carrier the merge read by its content hash: the window owes the stored
//! row only while it still holds that carrier ([`Owed::rows_in`]). A newer
//! carrier that came since lands through its own import, merged again, and
//! the stored row is never written over it.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, LoroDoc};
use oneiron_contracts::fingerprint::ContentHash;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_DIAGNOSTIC, ENTITY_TYPE_SECRET_CUSTODY};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::sync::bridge::{BRIDGE_ORIGIN, format_edge_key, parse_edge_key};
use crate::sync::loro_support::{map_contains_binary, map_delete, map_get_bytes};
use crate::sync::residence::residence_window_for_blob;
use crate::sync::types::WindowKey;

/// One marker's key: the window, then what the window owes: a row's
/// entities-map key (its id in hex), a removed edge's edges-map key, or a
/// merged row's entities-map key and the content hash of the carrier its
/// merge read, joined by [`MERGED_CARRIER_SEPARATOR`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwedKey {
    window: String,
    carrier: String,
}

/// Joins a merged-carrier marker's row key and carrier hash; neither a row
/// key nor an edge key holds it.
const MERGED_CARRIER_SEPARATOR: char = '@';

impl OwedKey {
    /// The window map key the marker names: a merged-carrier marker's row
    /// key, every other marker's whole carrier.
    fn map_key(&self) -> &str {
        self.carrier
            .split_once(MERGED_CARRIER_SEPARATOR)
            .map_or(self.carrier.as_str(), |(row, _)| row)
    }
}

impl SideKey for OwedKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.window.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.carrier.as_bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        // A window key holds no `:`; an edge key after it does.
        let (window, carrier) = std::str::from_utf8(bytes).ok()?.split_once(':')?;
        Some(Self {
            window: window.to_owned(),
            carrier: carrier.to_owned(),
        })
    }
}

/// The markers. A marker's value is the stamp of the write that left it: a
/// retirement deletes only the marker it read, never one a later write left
/// on the same key.
const PENDING_MIRROR: SideTable<OwedKey, u64, Raw> =
    SideTable::new(&side_table::SYNC_PENDING_MIRROR);

/// Whether a row can ride a window: a diagnostic or a credential never does.
fn rides_window(raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw).is_some_and(|header| {
        header.entity_type != ENTITY_TYPE_DIAGNOSTIC
            && header.entity_type != ENTITY_TYPE_SECRET_CUSTODY
    })
}

impl Vault {
    /// Leaves, in `wtxn`, a pending-mirror marker for each of `rows` the
    /// transaction's local write changed (FIX 7957): the window that holds
    /// the row owes its carrier until the change is durable there. A sync
    /// import's rows leave none, as the window already holds what it brought;
    /// nor does a row gone by now, whose delete publishes its own tombstone,
    /// nor a live off-record overlay member, which stays on this device.
    pub(crate) fn mark_pending_mirrors_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        rows: &BTreeSet<EntityId>,
    ) -> Result<()> {
        if rows.is_empty() || super::live_mirror::importing() {
            return Ok(());
        }
        let mut owed = Vec::new();
        for id in rows {
            let Some(raw) = self.get_raw_in(wtxn, id)? else {
                continue;
            };
            if !rides_window(&raw) || self.store.off_record_sessions.contains_entity(id)? {
                continue;
            }
            if let Ok(window) = residence_window_for_blob(&raw) {
                owed.push(OwedKey {
                    window: window.as_str().to_owned(),
                    carrier: id.to_hex(),
                });
            }
        }
        self.put_pending_mirrors(wtxn, &owed)
    }

    /// Leaves, in `wtxn`, a merged-carrier marker for the row `id`, whose
    /// carried copy `blob` a sync import in `window` merged with the row
    /// held here (ROOM-PINS-LWW-MERGE): the row lands as the merge, which the
    /// carrier lacks, so `window` owes the merged carrier while it still
    /// holds `blob` ([`Owed::rows_in`]). The live mirror then writes the
    /// stored row over it, as it writes a local edit; a sync import's other
    /// rows leave no marker.
    pub(crate) fn mark_merged_carrier_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        window: &str,
        id: &EntityId,
        blob: &[u8],
    ) -> Result<()> {
        if !rides_window(blob) || self.store.off_record_sessions.contains_entity(id)? {
            return Ok(());
        }
        self.put_pending_mirrors(
            wtxn,
            &[OwedKey {
                window: window.to_owned(),
                carrier: format!(
                    "{}{MERGED_CARRIER_SEPARATOR}{}",
                    id.to_hex(),
                    ContentHash::of(blob).to_hex()
                ),
            }],
        )
    }

    /// Leaves, in `wtxn`, a pending-mirror marker for each edge in `removed`
    /// the transaction's local write deleted (FIX 9599): the window that held
    /// the edge owes the removal of its key. A `blocks` edge never rode one.
    pub(crate) fn mark_pending_edge_removals_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        removed: &[(EntityId, EdgeKind, EntityId)],
    ) -> Result<()> {
        if removed.is_empty() || super::live_mirror::importing() {
            return Ok(());
        }
        let mut owed = Vec::new();
        for (src, kind, tgt) in removed {
            if *kind == EdgeKind::Blocks {
                continue;
            }
            if let Some(window) = self.edge_window_in(wtxn, src, tgt)? {
                owed.push(OwedKey {
                    window: window.as_str().to_owned(),
                    carrier: format_edge_key(src, *kind, tgt),
                });
            }
        }
        self.put_pending_mirrors(wtxn, &owed)
    }

    /// Writes the markers `owed` under one stamp for this write.
    fn put_pending_mirrors(&self, wtxn: &mut RwTxn<'_>, owed: &[OwedKey]) -> Result<()> {
        if owed.is_empty() {
            return Ok(());
        }
        let stamp = rand::random::<u64>();
        for key in owed {
            PENDING_MIRROR.put(&self.store, wtxn, key, &stamp)?;
        }
        Ok(())
    }

    /// The window that carries the edge `src`→`tgt`: a base row's edge to a
    /// world's row rides that world's window of the target's month, every
    /// other edge its source's window (as `edge_belongs_to_window` places
    /// them). `None` when the source is gone: its delete takes its edges.
    fn edge_window_in(
        &self,
        txn: &RoTxn<'_>,
        src: &EntityId,
        tgt: &EntityId,
    ) -> Result<Option<WindowKey>> {
        let Some(src_raw) = self.get_raw_in(txn, src)? else {
            return Ok(None);
        };
        let Ok(window) = residence_window_for_blob(&src_raw) else {
            return Ok(None);
        };
        if window.world().is_none()
            && let Some(tgt_raw) = self.get_raw_in(txn, tgt)?
            && let Ok(target) = residence_window_for_blob(&tgt_raw)
            && target.world().is_some()
        {
            return Ok(Some(target));
        }
        Ok(Some(window))
    }

    /// Mirrors into `doc`, the old window a replacement of `key` carries over
    /// from, what the markers of `key` owe it, as an open mirrors them
    /// (FIX 11822): the carry-over then judges each like any other unseen
    /// write, and the install retires the markers ([`Owed::retire_in_txn`]).
    pub(in crate::sync) fn mirror_owed_into_replaced(
        &self,
        doc: &LoroDoc,
        key: &WindowKey,
    ) -> Result<Owed> {
        Owed::mirror_on_open(self, doc, key)
    }
}

/// What one window's pending-mirror markers owe it, as one pass read them.
#[derive(Default)]
pub(in crate::sync) struct Owed {
    /// Rows whose carrier the window owes.
    rows: BTreeSet<EntityId>,
    /// Rows a sync import merged, each with the content hash (hex) of the
    /// carrier its merge read: the window owes the row only while it holds
    /// that carrier.
    merged: Vec<(EntityId, String)>,
    /// Removed edges: the edges-map key, and the edge it names.
    removed_edges: Vec<(String, (EntityId, EdgeKind, EntityId))>,
    /// Every marker read, with its stamp.
    read: Vec<(OwedKey, u64)>,
}

impl Owed {
    /// Reads what the markers of `window` owe it. A marker that does not
    /// decode is passed over, as the `pm:` replay passes one over.
    pub(super) fn read(vault: &Vault, window: &WindowKey) -> Result<Self> {
        let rtxn = vault.store.env.read_txn()?;
        let prefix = format!("{}:", window.as_str());
        let mut owed = Self::default();
        for (key, stamp) in PENDING_MIRROR
            .iter_from(&vault.store, &rtxn, prefix.as_bytes())?
            .filter_map(Result::ok)
        {
            if let Ok(id) = EntityId::from_hex(&key.carrier) {
                owed.rows.insert(id);
            } else if let Some(edge) = parse_edge_key(&key.carrier) {
                owed.removed_edges.push((key.carrier.clone(), edge));
            } else if let Some((row, hash)) = key.carrier.split_once(MERGED_CARRIER_SEPARATOR)
                && let Ok(id) = EntityId::from_hex(row)
            {
                owed.merged.push((id, hash.to_owned()));
            }
            owed.read.push((key, stamp));
        }
        Ok(owed)
    }

    /// Mirrors what the markers of `key` owe into `doc`, the window being
    /// opened, before its forward pass: each owed row ([`Self::rows_in`])
    /// replaces the carrier it differs from, and each removed edge's key
    /// goes. The caller persists the recovered delta, then retires the
    /// markers ([`Self::retire`]).
    pub(super) fn mirror_on_open(vault: &Vault, doc: &LoroDoc, key: &WindowKey) -> Result<Self> {
        let owed = Self::read(vault, key)?;
        let rows = owed.rows_in(doc);
        if !rows.is_empty() {
            crate::sync::window::reverse_rematerialize_rows(vault, doc, key, &rows, &rows)?;
        }
        owed.remove_edges(vault, doc)?;
        Ok(owed)
    }

    /// The rows whose carrier `doc` owes: each one a local write changed,
    /// and each one a sync import merged while `doc` still holds the carrier
    /// that merge read. A merged row whose carrier changed since is owed
    /// nothing: the newer carrier lands through its own import, which merges
    /// it with the stored row again, so the stored row written over it would
    /// drop what it changed (ROOM-PINS-LWW-MERGE).
    pub(super) fn rows_in(&self, doc: &LoroDoc) -> BTreeSet<EntityId> {
        let mut rows = self.rows.clone();
        if self.merged.is_empty() {
            return rows;
        }
        let entities = doc.get_map("entities");
        for (id, hash) in &self.merged {
            if map_get_bytes(&entities, &id.to_hex())
                .is_some_and(|carrier| ContentHash::of(&carrier).to_hex() == *hash)
            {
                rows.insert(*id);
            }
        }
        rows
    }

    /// Every row the markers name, owed or not: what a wake hands the live
    /// mirror, whose pass judges each one ([`Self::rows_in`]).
    pub(super) fn named_rows(&self) -> BTreeSet<EntityId> {
        let mut rows = self.rows.clone();
        rows.extend(self.merged.iter().map(|(id, _)| *id));
        rows
    }

    /// Deletes from `doc` the key of each removed edge the store still
    /// lacks, in one bridge commit; Observer B leaves a bridge commit alone.
    /// An edge a later write put back keeps its key, which that write's own
    /// mirror carries.
    pub(super) fn remove_edges(&self, vault: &Vault, doc: &LoroDoc) -> Result<()> {
        let edges = doc.get_map("edges");
        let mut removed = false;
        for (key, (src, kind, tgt)) in &self.removed_edges {
            if !map_contains_binary(&edges, key) || vault.edge_exists(src, *kind, tgt)? {
                continue;
            }
            map_delete(&edges, key)?;
            removed = true;
        }
        if removed {
            doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        }
        Ok(())
    }

    /// Retires every marker read, in one write, unless a later write left
    /// its key again since. A marker that stays is read by the next pass,
    /// whose mirror finds nothing more to change.
    pub(super) fn retire(self, vault: &Vault) {
        if self.read.is_empty() {
            return;
        }
        let retired =
            vault.with_write_txn_grouped(|wtxn| self.retire_in_txn(vault, wtxn, |_| false));
        if let Err(error) = retired {
            tracing::warn!(%error, "pending-mirror markers kept for the next pass");
        }
    }

    /// Retires, in `wtxn`, every marker read but those whose carrier `stays`
    /// names, unless a later write left its key again since. A replacement
    /// retires them in the write that persists it, and keeps owed each one
    /// whose value the installed window does not hold (FIX 11822).
    pub(in crate::sync) fn retire_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut RwTxn<'_>,
        stays: impl Fn(&str) -> bool,
    ) -> Result<()> {
        for (key, stamp) in &self.read {
            if !stays(key.map_key()) && PENDING_MIRROR.get(&vault.store, wtxn, key)? == Some(*stamp)
            {
                PENDING_MIRROR.delete(&vault.store, wtxn, key)?;
            }
        }
        Ok(())
    }
}

/// Whether a local write still owes `window` a row's carrier or an edge's
/// removal (FIX 14534): until the mirror takes it, the window's persisted
/// document lacks it, so a copy dropped now would lose it.
///
/// # Errors
/// Store errors.
pub(crate) fn window_owes_mirror_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    window: &WindowKey,
) -> Result<bool> {
    let prefix = format!("{}:", window.as_str());
    let mut owed = PENDING_MIRROR.iter_raw_from(&vault.store, txn, prefix.as_bytes())?;
    Ok(owed.next().transpose()?.is_some())
}

/// Deletes every marker that names `window`, in `wtxn`: the owner discarded
/// this install's copy of the window, and what its local writes owed it goes
/// with it (FIX 14534). Returns how many went.
///
/// # Errors
/// Store errors.
pub(crate) fn discard_window_mirrors_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    window: &WindowKey,
) -> Result<usize> {
    let prefix = format!("{}:", window.as_str());
    PENDING_MIRROR.delete_from(&vault.store, wtxn, prefix.as_bytes())
}

/// The windows the pending-mirror markers name, each once, in key order.
pub(super) fn owed_windows(vault: &Vault) -> Result<Vec<WindowKey>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut windows: Vec<WindowKey> = Vec::new();
    for row in PENDING_MIRROR.iter_raw_from(&vault.store, &rtxn, &[])? {
        let (key, _) = row?;
        let Some(window) = OwedKey::decode_key(&key).and_then(|key| WindowKey::try_new(key.window))
        else {
            continue;
        };
        if windows.last() != Some(&window) {
            windows.push(window);
        }
    }
    Ok(windows)
}
