//! Server-side `sync_state` persistence per the ARCH-0023b key layout.
//!
//! The sync server (Fly vault) hosts the root Doc and per-window Docs OVER
//! LMDB: `d:root` / `d:w:{key}` snapshots, `u:root:*` / `u:w:{key}:*` pending
//! updates, and `sv:` / `svf:` state vectors + freshness flags (ARCH-0023b
//! "sync_state key layout"). The in-RAM Loro Docs are a cache; every imported
//! update MUST be persisted synchronously (Observer A duty: "Append u:*
//! update, mark sv stale. MUST persist synchronously") or a server restart
//! silently discards every relayed update — INCLUDING tombstones, which would
//! make durable cross-device delete propagation impossible.
//!
//! These helpers are the server-side Observer-A-equivalent:
//! `subscribe_local_update` (see [`super::bridge::register_observer_a`]) does
//! not fire for imported remote updates, so the server persists imported
//! update bytes explicitly, between their admission on a fork and the observed
//! `import_with`. All multi-key writes are
//! atomic (single LMDB write transaction), matching the sync-state access
//! convention used by the bridge.

use loro::LoroDoc;

use super::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_from, import_doc,
};
use super::types::WindowKey;
use crate::Vault;
use crate::error::{Error, Result, SyncProtocolValidation};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::sync::window_rows::{
    ROOT_SHALLOW_FENCE, ROOT_SNAPSHOT, ROOT_STATE_VECTOR, ROOT_UPDATE, WINDOW_SHALLOW_FENCE,
    WINDOW_SNAPSHOT, WINDOW_STATE_VECTOR, WINDOW_UPDATE, WINDOW_UPDATE_SEQ, WindowUpdateKey,
    WindowUpdateSeq,
};

/// Persists an imported window update (Observer-A-equivalent).
///
/// The bytes must already have passed the window's admission on a fork; the
/// caller imports them into the window's observed document once this commits,
/// and its Observer B applies or fences the deletes they carry, so this half
/// writes no deletion state of its own.
///
/// Atomically (one LMDB write txn), per the ARCH-0023b key layout:
/// - bumps `m:u_seq:w:{key}` (u64 LE, crash-safe monotonic counter),
/// - appends the raw update bytes at `u:w:{key}:{seq:016x}`,
/// - marks the window state vector stale: `svf:w:{key}` = `[0]`.
///
/// Returns the sequence number assigned to the update. A missing seq row
/// starts at 0 (fresh window); a present-but-malformed row is on-disk
/// corruption and errors instead of silently resetting (which would let
/// `next_seq = 1` overwrite an already-persisted update) — same policy as
/// Observer A in `bridge::register_observer_a`.
///
/// `inserts`, the entity ids the update's history inserts as admission read
/// them ([`crate::sync::window::admit_window_update_residence_with_vault`]),
/// owe the erasure sweep a compaction of the window in the same transaction
/// when one names a row hard-deleted here (census L6-05).
pub fn persist_imported_window_update(
    vault: &Vault,
    key: &WindowKey,
    update_bytes: &[u8],
    inserts: &crate::sync::window::UpdateInserts,
) -> Result<u64> {
    persist_admitted_window_update(
        vault,
        key,
        update_bytes,
        inserts,
        &super::selector::RepoSyncLandings::default(),
        |_| true,
    )
}

/// [`persist_imported_window_update`] for a peer's write: `session_is_live`
/// rechecks the writer's credential in the committing transaction, before a
/// sequence number is taken (FIX 5999), and `landings`, the new bytes its
/// translated copy edits land, are marked in it (FIX 10732). A refusal
/// writes nothing and is `DocumentAdmissionDenied`.
pub fn persist_admitted_window_update(
    vault: &Vault,
    key: &WindowKey,
    update_bytes: &[u8],
    inserts: &crate::sync::window::UpdateInserts,
    landings: &super::selector::RepoSyncLandings,
    session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
) -> Result<u64> {
    persist_window_update_in(vault, key, update_bytes, inserts, landings, |wtxn| {
        if !session_is_live(wtxn) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
        Ok(())
    })
}

/// [`persist_admitted_window_update`] for a promoted window's write: the
/// entities `update_bytes` lands on `source` must still reach `peer`'s
/// machine in the committing transaction, judged as a document's writer
/// judges its destination (world privacy may have changed since the
/// pre-write check).
pub fn persist_promoted_window_update(
    vault: &Vault,
    key: &WindowKey,
    update_bytes: &[u8],
    inserts: &crate::sync::window::UpdateInserts,
    landings: &super::selector::RepoSyncLandings,
    session_is_live: impl FnOnce(&heed::RwTxn<'_>) -> bool,
    peer: crate::authority::PeerMachine,
    source: &LoroDoc,
) -> Result<u64> {
    let rows = super::residence::promoted_window_update_rows(source, update_bytes)?;
    persist_window_update_in(vault, key, update_bytes, inserts, landings, |wtxn| {
        if !session_is_live(wtxn) {
            return Err(Error::sync_protocol(
                SyncProtocolValidation::DocumentAdmissionDenied,
            ));
        }
        super::residence::admit_promoted_window_destination_in_txn(vault, wtxn, peer, &rows)
    })
}

/// The writer behind [`persist_imported_window_update`] and
/// [`persist_promoted_window_update`]: `admit` judges the write in the
/// committing transaction, before a sequence number is taken, then the
/// update appends as today and `inserts` owe their compaction in it. A
/// refusal writes nothing.
fn persist_window_update_in(
    vault: &Vault,
    key: &WindowKey,
    update_bytes: &[u8],
    inserts: &crate::sync::window::UpdateInserts,
    landings: &super::selector::RepoSyncLandings,
    admit: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<()>,
) -> Result<u64> {
    vault.with_write_txn_grouped(|wtxn| {
        admit(wtxn)?;
        // FIX 7608 slice 4 (FIX 10732, L04 05:5x): the new bytes a translated
        // copy edit lands carry its mark in this writer, never committed
        // unmarked.
        landings.mark_in_txn(vault, wtxn)?;
        let seq_key = key.as_str().to_owned();
        let seq: u64 = match WINDOW_UPDATE_SEQ.get(&vault.store, wtxn, &seq_key)? {
            None => 0,
            Some(WindowUpdateSeq(seq)) => seq,
        };
        let next_seq = seq
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("imported update u_seq"))?;
        WINDOW_UPDATE_SEQ.put(&vault.store, wtxn, &seq_key, &WindowUpdateSeq(next_seq))?;

        WINDOW_UPDATE.put(
            &vault.store,
            wtxn,
            &WindowUpdateKey {
                window: key.as_str().to_owned(),
                seq: next_seq,
            },
            &update_bytes.to_vec(),
        )?;

        WINDOW_SHALLOW_FENCE.put(&vault.store, wtxn, &key.as_str().to_owned(), &[0u8])?;
        inserts.owe_in_txn(vault, wtxn, key)?;

        Ok(next_seq)
    })
}

/// Persists a full window Doc snapshot.
///
/// Atomically writes `d:w:{key}` (Loro snapshot), `sv:w:{key}` (state
/// vector), and `svf:w:{key}` = `[1]` (fresh). Returns the snapshot bytes.
///
/// `doc` need not be observed: in the same transaction, each stored row its
/// tombstones delete is fenced as an observed import would fence it, so the
/// persisted deletes read deleted at once.
pub fn persist_window_snapshot(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> Result<Vec<u8>> {
    // The export reads the pin; a legal hold read in the writer keeps the
    // history a pinned export dropped (census L6-05).
    let state = crate::sync::window::export_scrubbed_window_state(vault, key, doc)?;
    let vv = doc_version_vector(doc);
    // Its pads persist by reference where custody here holds them (FIX 7107).
    let pads = |bytes: &[u8]| {
        crate::sync::window::persisted_window_pads(vault, key, bytes, None).into_owned()
    };
    let persisted = pads(&state.bytes);
    let persisted_whole = state.whole_bytes().map(pads);

    let keeps_whole = vault.with_write_txn_grouped(|wtxn| {
        vault.fence_published_deletes_in_txn(wtxn, key.as_str(), doc)?;
        let keeps_whole = state.keeps_whole_in_txn(vault, wtxn)?;
        let (stored, history_free) = match (&persisted_whole, keeps_whole) {
            (Some(whole), true) => (whole, false),
            _ => (&persisted, state.history_free),
        };
        crate::sync::window::owe_compaction_if_pinned_since_export_in_txn(
            vault,
            wtxn,
            key,
            history_free,
        )?;
        WINDOW_SNAPSHOT.put(&vault.store, wtxn, &key.as_str().to_owned(), stored)?;
        WINDOW_STATE_VECTOR.put(&vault.store, wtxn, &key.as_str().to_owned(), &vv)?;
        WINDOW_SHALLOW_FENCE.put(&vault.store, wtxn, &key.as_str().to_owned(), &[1u8])?;
        Ok(keeps_whole)
    })?;
    if keeps_whole && let Some(whole) = state.whole_bytes() {
        return Ok(whole.to_vec());
    }
    Ok(state.bytes)
}

/// Whether window `key` has a persisted snapshot (`d:w:{key}`), read in its own transaction
/// without copying the snapshot.
pub fn window_snapshot_present(vault: &Vault, key: &WindowKey) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .port_window_doc_with_raw(&rtxn, WindowAddress::new(key.as_str()), |_| Ok(()))?
        .is_some())
}

/// Persists the root Doc snapshot inside the CALLER's write txn (ONE-1140).
///
/// Atomically writes `d:root` (Loro snapshot, server-write-only
/// `meta.windows`), `sv:root`, and `svf:root` = `[1]` (fresh) into `wtxn`.
///
/// The rows keep every op the stored root holds: where `doc` lacks one, the
/// two are joined and the join is written (`stored_root_joined_with`). On a
/// device whose server runs beside its link to home, the server and the
/// link's client each hold a root doc and each put a whole snapshot over the
/// one row (FIX DEVICE-LINK-ROOT-PERSIST-DROPS-SERVER-ROOT-OPS).
///
/// NESTED-TXN HAZARD: do NOT call [`persist_root_snapshot`] from inside a
/// write txn — two write txns on one LMDB env deadlock. This in-txn body is
/// the composition point; keep [`persist_root_snapshot`] as the default
/// stand-alone entry.
///
/// MISUSE SURFACE: a root that carries a lease change goes through
/// [`persist_root_with_lease_mirror_in_txn`], never through this and a
/// mirror of the caller's own doc: the mirror must read the root this wrote.
#[doc(hidden)]
pub fn persist_root_snapshot_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
) -> Result<()> {
    put_root_joined_in_txn(vault, wtxn, doc)?;
    Ok(())
}

/// [`persist_root_snapshot_in_txn`], then the `ls:` mirror of the root it
/// wrote (`lease::mirror_leases_from_root_in_txn`), in the CALLER's one write
/// txn (ONE-1140): a crash or failure after the `d:root` put rolls back every
/// key, never leaving a stale or missing `ls:` mirror over a new `d:root` (a
/// revoked lease must not appear active at a replay door).
///
/// The mirror reads the written root, so a lease the other root writer
/// revoked or expired keeps its status in `ls:` when this caller's doc still
/// holds the older record. The callers are the server's lease registrar
/// (`oneiron-server`) and the link client's root persist.
#[doc(hidden)]
pub fn persist_root_with_lease_mirror_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
) -> Result<()> {
    let joined = put_root_joined_in_txn(vault, wtxn, doc)?;
    super::lease::mirror_leases_from_root_in_txn(vault, wtxn, joined.as_ref().unwrap_or(doc))
}

/// Writes the three root rows from `doc`, or from its join with the stored
/// root where that holds ops `doc` lacks; returns the join it wrote, if any.
/// The snapshot and state vector are in-memory reads of the written doc.
fn put_root_joined_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
) -> Result<Option<LoroDoc>> {
    let joined = stored_root_joined_with(vault, wtxn, doc)?;
    let root = joined.as_ref().unwrap_or(doc);
    let state = export_snapshot(root)?;
    let vv = doc_version_vector(root);

    ROOT_SNAPSHOT.put(&vault.store, wtxn, &(), &state)?;
    ROOT_STATE_VECTOR.put(&vault.store, wtxn, &(), &vv)?;
    ROOT_SHALLOW_FENCE.put(&vault.store, wtxn, &(), &[1u8])?;
    Ok(joined)
}

/// The stored root with the ops of `doc` it lacks, or `None` when `doc`
/// already holds every op the stored root does (or none is stored): then the
/// caller writes `doc` itself, the bytes it wrote before the join existed.
///
/// Read inside the caller's write txn. The vault has one writer, so the root
/// read here holds every earlier put, and nothing lands between this read and
/// the caller's put: no root put drops another writer's ops, in either order.
/// `doc` itself is not changed. A failed persist reverts its doc by writing
/// new ops (`LoroDoc::revert_to`), and those would undo the other writer's
/// ops had the doc taken them in here. A stored root that does not decode
/// fails the put, as it fails a start ([`load_root_from_state`]).
fn stored_root_joined_with(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
) -> Result<Option<LoroDoc>> {
    let Some(stored) = load_root_in_txn(vault, txn)? else {
        return Ok(None);
    };
    let stored_vv = stored.oplog_vv();
    if doc.oplog_vv().includes_vv(&stored_vv) {
        return Ok(None);
    }
    import_doc(&stored, &export_updates_from(doc, &stored_vv)?)?;
    Ok(Some(stored))
}

/// Persists the root Doc snapshot.
///
/// Atomically writes `d:root` (Loro snapshot, server-write-only
/// `meta.windows`), `sv:root`, and `svf:root` = `[1]` (fresh). Thin own-txn
/// wrapper over [`persist_root_snapshot_in_txn`].
pub fn persist_root_snapshot(vault: &Vault, doc: &LoroDoc) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| persist_root_snapshot_in_txn(vault, wtxn, doc))
}

/// Loads the root Doc from persisted state (ARCH-0023b startup step 1:
/// read `d:root` → apply pending `u:root:*`).
///
/// Returns `Ok(None)` when no root snapshot has been persisted yet (fresh
/// vault). A present-but-undecodable snapshot or pending update is an error
/// (fail-closed): the server must not boot with an empty root doc over
/// corrupt state, silently hiding every historical window from clients.
pub fn load_root_from_state(vault: &Vault) -> Result<Option<LoroDoc>> {
    let rtxn = vault.store.env.read_txn()?;
    load_root_in_txn(vault, &rtxn)
}

/// [`load_root_from_state`] as `txn` reads the rows: a write txn sees the
/// puts of every write before it.
fn load_root_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<LoroDoc>> {
    let Some(state) = ROOT_SNAPSHOT.get(&vault.store, txn, &())? else {
        return Ok(None);
    };
    let doc = doc_from_snapshot(&state)?;

    for entry in ROOT_UPDATE.iter_from(&vault.store, txn, &[])? {
        let (_k, v) = entry?;
        import_doc(&doc, &v)?;
    }

    Ok(Some(doc))
}

/// Lists the window keys that have a persisted snapshot (`d:w:*`).
///
/// Used at boot to reconcile the root doc's `meta.windows` against the
/// persisted windows, so a crash between window-snapshot persistence and
/// root persistence cannot permanently hide a window from clients. Keys
/// that fail `YYYY-MM` validation are skipped with a warning.
pub fn persisted_window_keys(vault: &Vault) -> Result<Vec<WindowKey>> {
    let rtxn = vault.store.env.read_txn()?;

    let mut keys = Vec::new();
    for entry in vault
        .store
        .port_window_doc_rows_raw(&rtxn, |window, _| window.as_str().to_owned())?
        .collect::<Result<Vec<_>>>()?
    {
        match WindowKey::try_new(entry.clone()) {
            Some(key) => keys.push(key),
            None => {
                tracing::warn!(
                    key = %entry,
                    "sync server_state: ignoring invalid persisted window snapshot key"
                );
            }
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::super::loro_support::{export_all_updates, map_get_bytes, map_insert_bytes};
    use super::*;
    use crate::config::VaultConfig;
    use crate::error::SyncError;

    use core::assert_matches;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        (dir, vault)
    }

    #[test]
    fn persist_imported_window_update_writes_contract_key_literals() {
        // ARCH-0023b "sync_state key layout" literals:
        //   u:w:2026-02:{seq:016x}  Loro update (pending window update)
        //   m:u_seq:w:2026-02      u64 LE (8 bytes) monotonic counter
        //   svf:w:2026-02          1 byte (1 = fresh, 0 = stale)
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-02");

        let seq = persist_imported_window_update(&vault, &key, b"update-one", &Default::default())
            .unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:0000000000000001")
                .unwrap()
                .unwrap(),
            b"update-one"
        );
        assert_eq!(
            vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
            1u64.to_le_bytes()
        );
        assert_eq!(
            vault.sync_state_get("svf:w:2026-02").unwrap().unwrap(),
            vec![0u8],
            "an appended update must mark the state vector stale (0)"
        );

        let seq = persist_imported_window_update(&vault, &key, b"update-two", &Default::default())
            .unwrap();
        assert_eq!(seq, 2);
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:0000000000000002")
                .unwrap()
                .unwrap(),
            b"update-two"
        );
        assert_eq!(
            vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
            2u64.to_le_bytes()
        );
    }

    #[test]
    fn persist_imported_window_update_rejects_corrupt_seq_row() {
        // A malformed seq row must NOT silently reset to 0 — next_seq = 1
        // would overwrite whatever was already persisted at
        // u:w:{key}:0000000000000001. Same policy as Observer A.
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-02");

        persist_imported_window_update(&vault, &key, b"first", &Default::default()).unwrap();
        vault
            .sync_state_put("m:u_seq:w:2026-02", &[1, 2, 3])
            .unwrap();

        let err = persist_imported_window_update(&vault, &key, b"second", &Default::default())
            .unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_), "got {err:?}");
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:0000000000000001")
                .unwrap()
                .unwrap(),
            b"first",
            "the already-persisted update must remain untouched"
        );
    }

    #[test]
    fn persist_window_snapshot_writes_contract_key_literals() {
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-03");

        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("entities"), "e1", b"v1").unwrap();
        doc.commit();

        let state = persist_window_snapshot(&vault, &key, &doc).unwrap();

        assert_eq!(vault.sync_state_get("d:w:2026-03").unwrap().unwrap(), state);
        assert_eq!(
            vault.sync_state_get("sv:w:2026-03").unwrap().unwrap(),
            doc.oplog_vv().encode()
        );
        assert_eq!(
            vault.sync_state_get("svf:w:2026-03").unwrap().unwrap(),
            vec![1u8],
            "a fresh snapshot must mark the state vector fresh (1)"
        );

        let reloaded = doc_from_snapshot(&state).unwrap();
        assert_eq!(
            map_get_bytes(&reloaded.get_map("entities"), "e1").unwrap(),
            b"v1"
        );
    }

    #[test]
    fn root_snapshot_round_trips_and_applies_pending_root_updates() {
        let (_dir, vault) = test_vault();

        assert!(
            load_root_from_state(&vault).unwrap().is_none(),
            "fresh vault has no d:root"
        );

        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("meta"), "windows", b"2026-01").unwrap();
        doc.commit();
        persist_root_snapshot(&vault, &doc).unwrap();

        assert!(vault.sync_state_get("d:root").unwrap().is_some());
        assert_eq!(
            vault.sync_state_get("sv:root").unwrap().unwrap(),
            doc.oplog_vv().encode()
        );
        assert_eq!(
            vault.sync_state_get("svf:root").unwrap().unwrap(),
            vec![1u8]
        );

        // A pending u:root:* update (ARCH-0023b startup step 1: read d:root
        // → apply pending u:root:*) must be applied on load.
        let pending_doc = LoroDoc::new();
        map_insert_bytes(&pending_doc.get_map("meta"), "vault_id", b"v-1").unwrap();
        pending_doc.commit();
        let pending = export_all_updates(&pending_doc).unwrap();
        vault.sync_state_put("u:root:00000001", &pending).unwrap();

        let loaded = load_root_from_state(&vault).unwrap().unwrap();
        let meta = loaded.get_map("meta");
        assert_eq!(map_get_bytes(&meta, "windows").unwrap(), b"2026-01");
        assert_eq!(
            map_get_bytes(&meta, "vault_id").unwrap(),
            b"v-1",
            "pending u:root:* update must be applied on load"
        );
    }

    #[test]
    fn load_root_from_state_fails_closed_on_corrupt_snapshot() {
        let (_dir, vault) = test_vault();
        vault
            .sync_state_put("d:root", b"not-a-loro-snapshot")
            .unwrap();

        let err = load_root_from_state(&vault).unwrap_err();
        assert!(
            matches!(err, Error::Sync(SyncError::CrdtDecodeError { .. })),
            "corrupt d:root must error, not boot empty — got {err:?}"
        );
    }
}
