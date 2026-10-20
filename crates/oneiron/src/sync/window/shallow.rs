//! Strict shallow cuts of a window document (FIX 6520).
//!
//! Loro roots a shallow snapshot only at a single-head version. A window with several heads,
//! from concurrent edits or independent histories, is cut at the newest version every operation
//! is ordered against, empty when there is none, and the snapshot keeps every operation past that
//! root: a value a scrub took out rides along. A strict cut first commits one payload-free
//! operation over every head, the barrier: the removal of a key no row can take, which changes no
//! value. The window then has one head, a root nothing runs concurrent with. The cut is read back
//! and proved only when the root Loro encoded is that head and the version it ends at is the
//! window's own. The sweep writes nothing from a cut that fails the proof; a persist stores it as
//! before and owes the erasure sweep a compaction of the window.
//!
//! The doc identity is kept and the version vector extended by exactly one barrier op, for a
//! window with more than one head only. A peer's echo of an older operation stays a dominated
//! no-op. No peer writes under a barrier key: window admission refuses a value there.

use loro::{
    CommitOptions, ContainerID, ContainerType, ExportMode, Frontiers, LoroDoc, VersionVector,
};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::map_delete;
use super::types::WindowKey;
use crate::Vault;
use crate::error::{Error, Result, SyncEngineContext, SyncError};

/// The map the barrier removes a key from.
const BARRIER_MAP: &str = "entities";

/// The keys the barrier may remove: the lowercase spellings of the reserved all-zero and all-one
/// entity ids, which `EntityId::from_hex` refuses, so no row is ever written under one. The first
/// the map does not hold is the one removed.
const BARRIER_KEYS: [&str; 2] = [
    "00000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
];

/// A shallow snapshot of a window and the root Loro actually encoded.
pub(super) struct EncodedCut {
    pub(super) bytes: Vec<u8>,
    /// The version the retained operations start after.
    pub(super) start: VersionVector,
    /// The root's frontiers.
    pub(super) frontiers: Frontiers,
    /// The version the snapshot ends at.
    pub(super) end: VersionVector,
}

/// A snapshot of `doc` rooted at its newest operation, with the root Loro actually encoded. Loro
/// roots it earlier while several heads remain, so the root read back is the one to trust.
pub(super) fn tip_rooted_cut(doc: &LoroDoc) -> Result<EncodedCut> {
    doc.commit();
    let bytes = doc
        .export(ExportMode::shallow_snapshot(&doc.oplog_frontiers()))
        .map_err(|e| Error::sync_engine(SyncEngineContext::LoroExportShallowSnapshot, e))?;
    let meta = LoroDoc::decode_import_blob_meta(&bytes, false).map_err(|source| {
        Error::Sync(SyncError::CrdtDecodeError {
            context: "decode history-free snapshot root",
            source,
        })
    })?;
    Ok(EncodedCut {
        bytes,
        start: meta.partial_start_vv,
        frontiers: meta.start_frontiers,
        end: meta.partial_end_vv,
    })
}

/// A strict cut: the snapshot and the version it ends at, the barrier's operation included, and
/// whether it passed its proof. The two are stored together, never the bytes beside an older
/// version.
pub(crate) struct StrictCut {
    pub(crate) bytes: Vec<u8>,
    pub(crate) version: VersionVector,
    /// Whether the root Loro encoded is the window's one head and the snapshot ends at its
    /// version.
    pub(crate) proved: bool,
}

/// Commits the barrier on `doc` when it has more than one head. The removal depends on every
/// head, so the window is left with one. It is a bridge commit: no observer materializes it, and
/// Observer A persists and routes it as any local update.
pub(crate) fn merge_window_heads(doc: &LoroDoc) -> Result<()> {
    doc.commit();
    if doc.oplog_frontiers().len() < 2 {
        return Ok(());
    }
    let map = doc.get_map(BARRIER_MAP);
    // A crafted value under every key leaves the heads as they are: the cut then fails its proof.
    let Some(key) = BARRIER_KEYS.into_iter().find(|key| map.get(key).is_none()) else {
        return Ok(());
    };
    map_delete(&map, key)?;
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(())
}

/// The strict cut of `doc`: the barrier when it has several heads, then the snapshot at its one
/// head, proved by reading back the root Loro encoded and the version the snapshot ends at. Either
/// is not the window's own when an import lands between the barrier and the export: the sweep
/// then writes nothing, and a persist stores the cut and owes the sweep the window.
pub(crate) fn strict_window_cut(doc: &LoroDoc) -> Result<StrictCut> {
    merge_window_heads(doc)?;
    tip_window_cut(doc)
}

/// [`strict_window_cut`] without the barrier, for a caller that merged the heads before it opened
/// a write transaction, where no commit may run the observers. Proved as the strict cut is.
pub(crate) fn tip_window_cut(doc: &LoroDoc) -> Result<StrictCut> {
    doc.commit();
    let (tip, version) = (doc.oplog_frontiers(), doc.oplog_vv());
    let cut = tip_rooted_cut(doc)?;
    Ok(StrictCut {
        proved: cut.frontiers == tip && cut.end == version,
        bytes: cut.bytes,
        version: cut.end,
    })
}

/// Owes the erasure sweep a compaction of window `key` when `cut` failed its proof, in a write
/// transaction of its own before the caller stores the cut: the stored root may keep history
/// behind it until the sweep proves a cut of its own.
pub(super) fn owe_unproved_cut(vault: &Vault, key: &WindowKey, cut: &StrictCut) -> Result<()> {
    if cut.proved {
        return Ok(());
    }
    tracing::warn!(
        window = %key,
        "shallow cut not rooted at the window's tip — stored, compaction owed"
    );
    vault.with_write_txn_grouped(|wtxn| {
        crate::sweep::owed::owe_window_compaction_in_txn(vault, wtxn, key)
    })
}

/// Refuses a peer's write under a barrier key: no peer has a use for one, and a value there would
/// leave the barrier no key to remove.
pub(super) fn refuse_barrier_write(container: &ContainerID, map_key: &str) -> Result<()> {
    if *container == ContainerID::new_root(BARRIER_MAP, ContainerType::Map)
        && BARRIER_KEYS.contains(&map_key)
    {
        return Err(barrier_key_refused(map_key));
    }
    Ok(())
}

/// Refuses a snapshot whose state holds a value under a barrier key.
pub(super) fn refuse_held_barrier_keys(doc: &LoroDoc) -> Result<()> {
    let map = doc.get_map(BARRIER_MAP);
    match BARRIER_KEYS.into_iter().find(|key| map.get(key).is_some()) {
        Some(key) => Err(barrier_key_refused(key)),
        None => Ok(()),
    }
}

fn barrier_key_refused(key: &str) -> Error {
    Error::InvalidConfig(format!(
        "write under reserved barrier key {BARRIER_MAP}/{key}"
    ))
}
