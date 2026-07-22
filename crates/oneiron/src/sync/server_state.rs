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
//! update bytes explicitly after `import_with`. All multi-key writes are
//! atomic (single LMDB write transaction), matching the sync-state access
//! convention used by the bridge.

use loro::LoroDoc;

use super::loro_support::{doc_from_snapshot, doc_version_vector, export_snapshot, import_doc};
use super::types::WindowKey;
use crate::Vault;
use crate::error::{Error, Result};

/// Persists an imported window update (Observer-A-equivalent).
///
/// Atomically (one LMDB write txn), per the ARCH-0023b key layout:
/// - bumps `m:u_seq:w:{key}` (u32 LE, crash-safe monotonic counter),
/// - appends the raw update bytes at `u:w:{key}:{seq:08x}`,
/// - marks the window state vector stale: `svf:w:{key}` = `[0]`.
///
/// Returns the sequence number assigned to the update. A missing seq row
/// starts at 0 (fresh window); a present-but-malformed row is on-disk
/// corruption and errors instead of silently resetting (which would let
/// `next_seq = 1` overwrite an already-persisted update) — same policy as
/// Observer A in `bridge::register_observer_a`.
pub fn persist_imported_window_update(
    vault: &Vault,
    key: &WindowKey,
    update_bytes: &[u8],
) -> Result<u32> {
    vault.with_write_txn(|wtxn| {
        let seq_key = format!("m:u_seq:w:{key}");
        let seq: u32 = match vault.store.sync_state.get(wtxn, &seq_key)? {
            None => 0,
            Some(raw) if raw.len() == 4 => u32::from_le_bytes(
                raw.as_ref()
                    .try_into()
                    .expect("match guard ensures raw.len() == 4"),
            ),
            Some(_) => return Err(Error::CorruptedIndex("imported update u_seq row")),
        };
        let next_seq = seq
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("imported update u_seq"))?;
        vault
            .store
            .sync_state
            .put(wtxn, &seq_key, &next_seq.to_le_bytes())?;

        let update_key = format!("u:w:{key}:{next_seq:08x}");
        vault
            .store
            .sync_state
            .put(wtxn, &update_key, update_bytes)?;

        let svf_key = format!("svf:w:{key}");
        vault.store.sync_state.put(wtxn, &svf_key, &[0u8])?;

        Ok(next_seq)
    })
}

/// Persists a full window Doc snapshot.
///
/// Atomically writes `d:w:{key}` (Loro snapshot), `sv:w:{key}` (state
/// vector), and `svf:w:{key}` = `[1]` (fresh). Returns the snapshot bytes.
pub fn persist_window_snapshot(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> Result<Vec<u8>> {
    let state = crate::sync::window::export_scrubbed_window_snapshot(vault, key, doc)?;
    let vv = doc_version_vector(doc);

    vault.with_write_txn(|wtxn| {
        let doc_key = format!("d:w:{key}");
        vault.store.sync_state.put(wtxn, &doc_key, &state)?;

        let sv_key = format!("sv:w:{key}");
        vault.store.sync_state.put(wtxn, &sv_key, &vv)?;

        let svf_key = format!("svf:w:{key}");
        vault.store.sync_state.put(wtxn, &svf_key, &[1u8])?;
        Ok(())
    })?;

    Ok(state)
}

/// Persists the root Doc snapshot inside the CALLER's write txn (ONE-1140).
///
/// Atomically writes `d:root` (Loro snapshot, server-write-only
/// `meta.windows`), `sv:root`, and `svf:root` = `[1]` (fresh) into `wtxn`.
/// The snapshot and state vector are computed FIRST as pure in-memory reads
/// (no nested txn), then the three puts go into the passed `wtxn`, so this
/// can be combined with the lease mirror (`mirror_leases_from_root_in_txn`)
/// in ONE write txn — a crash/failure after the `d:root` put rolls back
/// every key, never leaving a stale/missing `ls:` mirror over a new `d:root`
/// (a revoked lease must not appear active at a replay door).
///
/// NESTED-TXN HAZARD: do NOT call [`persist_root_snapshot`] from inside a
/// write txn — two write txns on one LMDB env deadlock. This in-txn body is
/// the composition point; keep [`persist_root_snapshot`] as the default
/// stand-alone entry.
///
/// MISUSE SURFACE: callers MUST wrap this in a single write txn together
/// with any companion mirror write (e.g. `lease::mirror_leases_from_root_in_txn`).
/// Using it outside that atomic boundary re-opens the split-write bug
/// (a committed `d:root` over a stale/missing `ls:` mirror). The cross-crate
/// caller is `oneiron-server`'s lease registrar (ONE-1140).
#[doc(hidden)]
pub fn persist_root_snapshot_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
) -> Result<()> {
    let state = export_snapshot(doc)?;
    let vv = doc_version_vector(doc);

    vault.store.sync_state.put(wtxn, "d:root", &state)?;
    vault.store.sync_state.put(wtxn, "sv:root", &vv)?;
    vault.store.sync_state.put(wtxn, "svf:root", &[1u8])?;
    Ok(())
}

/// Persists the root Doc snapshot.
///
/// Atomically writes `d:root` (Loro snapshot, server-write-only
/// `meta.windows`), `sv:root`, and `svf:root` = `[1]` (fresh). Thin own-txn
/// wrapper over [`persist_root_snapshot_in_txn`].
pub fn persist_root_snapshot(vault: &Vault, doc: &LoroDoc) -> Result<()> {
    vault.with_write_txn(|wtxn| persist_root_snapshot_in_txn(vault, wtxn, doc))
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

    let Some(state) = vault.store.sync_state.get(&rtxn, "d:root")? else {
        return Ok(None);
    };
    let doc = doc_from_snapshot(&state)?;

    let iter = vault.store.sync_state.prefix_iter(&rtxn, "u:root:")?;
    for entry in iter {
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
    const PREFIX: &str = "d:w:";
    let rtxn = vault.store.env.read_txn()?;

    let mut keys = Vec::new();
    let iter = vault.store.sync_state.prefix_iter(&rtxn, PREFIX)?;
    for entry in iter {
        let (k, _) = entry?;
        match WindowKey::try_new(&k[PREFIX.len()..]) {
            Some(key) => keys.push(key),
            None => {
                tracing::warn!(
                    key = %k,
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
    use crate::edge::EdgeKind;
    use crate::entity_id::EntityId;
    use crate::off_record::OffRecordBackendClass;
    use crate::sync::bridge::format_edge_key;
    use core::assert_matches;

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
        (dir, vault)
    }

    #[test]
    fn persist_imported_window_update_writes_contract_key_literals() {
        // ARCH-0023b "sync_state key layout" literals:
        //   u:w:2026-02:{seq:08x}  Loro update (pending window update)
        //   m:u_seq:w:2026-02      u32 LE (4 bytes) monotonic counter
        //   svf:w:2026-02          1 byte (1 = fresh, 0 = stale)
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-02");

        let seq = persist_imported_window_update(&vault, &key, b"update-one").unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:00000001")
                .unwrap()
                .unwrap(),
            b"update-one"
        );
        assert_eq!(
            vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
            1u32.to_le_bytes()
        );
        assert_eq!(
            vault.sync_state_get("svf:w:2026-02").unwrap().unwrap(),
            vec![0u8],
            "an appended update must mark the state vector stale (0)"
        );

        let seq = persist_imported_window_update(&vault, &key, b"update-two").unwrap();
        assert_eq!(seq, 2);
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:00000002")
                .unwrap()
                .unwrap(),
            b"update-two"
        );
        assert_eq!(
            vault.sync_state_get("m:u_seq:w:2026-02").unwrap().unwrap(),
            2u32.to_le_bytes()
        );
    }

    #[test]
    fn persist_imported_window_update_rejects_corrupt_seq_row() {
        // A malformed seq row must NOT silently reset to 0 — next_seq = 1
        // would overwrite whatever was already persisted at
        // u:w:{key}:00000001. Same policy as Observer A.
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-02");

        persist_imported_window_update(&vault, &key, b"first").unwrap();
        vault
            .sync_state_put("m:u_seq:w:2026-02", &[1, 2, 3])
            .unwrap();

        let err = persist_imported_window_update(&vault, &key, b"second").unwrap_err();
        assert_matches!(err, Error::CorruptedIndex(_), "got {err:?}");
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:00000001")
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
    fn persist_window_snapshot_scrubs_fenced_carriers_and_keeps_controls() {
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-03");
        let fenced = EntityId::from_bytes([0x73; 16]).unwrap();
        let ordinary = EntityId::from_bytes([0x74; 16]).unwrap();
        vault
            .enter_off_record_session("sess-server-snapshot", OffRecordBackendClass::Local)
            .unwrap();
        vault
            .tag_turn_off_record("sess-server-snapshot", &fenced)
            .unwrap();

        let doc = LoroDoc::new();
        map_insert_bytes(&doc.get_map("entities"), &fenced.to_hex(), b"private").unwrap();
        map_insert_bytes(&doc.get_map("entities"), &ordinary.to_hex(), b"ordinary").unwrap();
        let incident_edge = format_edge_key(&ordinary, EdgeKind::Mentions, &fenced);
        map_insert_bytes(&doc.get_map("edges"), &incident_edge, b"carrier").unwrap();
        doc.commit();

        let state = persist_window_snapshot(&vault, &key, &doc).unwrap();
        let reloaded = doc_from_snapshot(&state).unwrap();
        assert!(map_get_bytes(&reloaded.get_map("entities"), &fenced.to_hex()).is_none());
        assert!(map_get_bytes(&reloaded.get_map("edges"), &incident_edge).is_none());
        assert_eq!(
            map_get_bytes(&reloaded.get_map("entities"), &ordinary.to_hex()).as_deref(),
            Some(b"ordinary".as_slice())
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
            matches!(err, Error::CrdtDecodeError { .. }),
            "corrupt d:root must error, not boot empty — got {err:?}"
        );
    }

    #[test]
    fn persisted_window_keys_lists_valid_window_snapshots_only() {
        let (_dir, vault) = test_vault();

        let doc = LoroDoc::new();
        doc.commit();
        persist_window_snapshot(&vault, &WindowKey::new("2026-01"), &doc).unwrap();
        persist_window_snapshot(&vault, &WindowKey::new("2026-02"), &doc).unwrap();
        // Invalid key written out-of-band must be skipped, not panicked on.
        vault.sync_state_put("d:w:2026-13", b"junk").unwrap();
        // Root snapshot must not be picked up by the d:w: scan.
        persist_root_snapshot(&vault, &doc).unwrap();

        let keys = persisted_window_keys(&vault).unwrap();
        assert_eq!(
            keys,
            vec![WindowKey::new("2026-01"), WindowKey::new("2026-02")]
        );
    }
}
