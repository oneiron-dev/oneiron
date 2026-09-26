use super::*;
use oneiron::sync::transport::window_sub_tags;

fn test_vault() -> (tempfile::TempDir, Arc<oneiron::Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    (dir, vault)
}

fn persist_empty_window(vault: &Arc<oneiron::Vault>, key: &WindowKey) {
    let doc = oneiron::sync::schema::create_window_doc(SERVER_USER_ID, key);
    oneiron::sync::server_state::persist_window_snapshot(vault, key, &doc).unwrap();
}

fn tombstone_value(request_byte: u8) -> [u8; oneiron::deletion::TOMBSTONE_VALUE_V2_LEN] {
    oneiron::deletion::TombstoneValueV2 {
        reason: oneiron::deletion::TombstoneReason::GdprDelete,
        deleted_at: 1_700_000_000,
        request_id: [request_byte; 16],
    }
    .encode()
}

fn deep_map_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
    let deep = doc.get_deep_value();
    let root = deep.as_map()?;
    let inner = root.get(map)?.as_map()?;
    let value = inner.get(key)?.as_binary()?;
    Some(value.to_vec())
}

pub(super) fn seed_historical_lease(
    server: &SyncServer,
    vault_id: u64,
    client: u64,
    pubkey: [u8; 32],
    status: LeaseStatus,
) {
    let record = LeaseRecord {
        vault_id,
        status,
        pubkey,
        granted_at: 1,
        renewed_at: 2,
        expires_at: u64::MAX,
    };
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(
            &lease::lease_registry_key(vault_id, client),
            lease::encode_lease_record(&record).as_slice(),
        )
        .unwrap();
    server.root_doc.commit();
    oneiron::sync::server_state::persist_root_snapshot(&server.vault, &server.root_doc).unwrap();
    lease::mirror_leases_from_root(&server.vault, &server.root_doc).unwrap();
}

fn deep_map_has_map(doc: &LoroDoc, map: &str, key: &str) -> bool {
    let deep = doc.get_deep_value();
    let Some(root) = deep.as_map() else {
        return false;
    };
    let Some(inner) = root.get(map).and_then(LoroValue::as_map) else {
        return false;
    };
    inner.get(key).and_then(LoroValue::as_map).is_some()
}

#[test]
fn window_key_for_known_timestamps() {
    assert_eq!(SyncServer::window_key_for_timestamp(1771027200), "2026-02");
    assert_eq!(SyncServer::window_key_for_timestamp(1764547200), "2025-12");
    assert_eq!(SyncServer::window_key_for_timestamp(0), "1970-01");
}

#[tokio::test]
async fn world_window_creation_announces_root_index_after_persistence() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
    let world = oneiron::EntityId::from_bytes([0x42; 16]).unwrap();
    let key = WindowKey::for_world(1_771_027_200, world);
    let replica = LoroDoc::from_snapshot(&server.export_root_snapshot().unwrap()).unwrap();
    let mut updates = server.broadcast_tx.subscribe();
    server.get_or_create_window(&key).await.unwrap();
    let message = tokio::time::timeout(std::time::Duration::from_secs(5), updates.recv())
        .await
        .unwrap()
        .unwrap();
    let BroadcastPayload::Frame(0, frame) = message else {
        panic!("expected root index notice");
    };
    assert_eq!(frame[0], crate::protocol::TAG_SYNC_UPDATE);
    replica.import(&frame[1..]).unwrap();
    assert_eq!(read_window_list(&replica), vec![key.clone()]);
    assert!(server.vault.sync_state_get("d:root").unwrap().is_some());
}

#[test]
fn root_doc_initialization() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();

    // schema_version must be i64-LE bytes (Loro Binary), matching the
    // shared schema writer (`schema::create_root_doc`).
    assert_eq!(
        deep_map_bytes(&server.root_doc, "meta", "schema_version").unwrap(),
        schema_version_bytes()
    );
    assert!(deep_map_has_map(&server.root_doc, "meta", "windows"));
    assert!(read_window_list(&server.root_doc).is_empty());
}

#[test]
fn server_rejects_non_positive_ephemeral_timeout() {
    let (_dir, vault) = test_vault();
    let result = SyncServer::new(
        vault,
        SyncServerConfig {
            ephemeral_timeout_ms: 0,
            ..Default::default()
        },
    );

    assert!(matches!(result, Err(error) if error
                    .to_string()
                    .contains("ephemeral_timeout_ms must be positive")));
}

#[test]
fn window_materializer_uses_configured_lease_vault_id() {
    let (_dir, vault) = test_vault();
    let lease_vault_id = 0x0a0b_0c0d_0e0f_1011u64;
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            lease_vault_id,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        server.reassert_manager.materializer().lease_vault_id(),
        lease_vault_id
    );
}

#[tokio::test]
async fn window_creation() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();

    let doc = server
        .get_or_create_window(&WindowKey::new("2026-03"))
        .await
        .unwrap();
    let deep = doc.get_deep_value();
    let map = deep.as_map().unwrap();
    assert!(map.contains_key("entities"));
    assert!(map.contains_key("edges"));
    assert!(map.contains_key("tombstones"));
}

#[tokio::test]
async fn window_creation_persists_snapshot_and_registers_in_root() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    server
        .get_or_create_window(&WindowKey::new("2026-03"))
        .await
        .unwrap();

    // ARCH-0023b sync_state key layout literals.
    assert!(vault.sync_state_get("d:w:2026-03").unwrap().is_some());
    assert!(vault.sync_state_get("sv:w:2026-03").unwrap().is_some());
    assert_eq!(
        vault.sync_state_get("svf:w:2026-03").unwrap().unwrap(),
        vec![1u8]
    );
    assert!(vault.sync_state_get("d:root").unwrap().is_some());

    let windows = read_window_list(&server.root_doc);
    assert_eq!(windows, vec![WindowKey::new("2026-03")]);
}

#[tokio::test]
async fn window_open_root_write_serializes_with_lease_registrar() {
    use std::time::Duration;

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let guard = server.lease_registrar.lock().await;
    let key = WindowKey::new("2026-07");
    let open = server.get_or_create_window(&key);
    tokio::pin!(open);

    let wait_for_window_snapshot = async {
        loop {
            if vault.sync_state_get("d:w:2026-07").unwrap().is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    };
    tokio::select! {
        _ = &mut open => panic!("window open completed without lease_registrar serialization"),
        _ = wait_for_window_snapshot => {}
    }

    assert!(
        read_window_list(&server.root_doc).is_empty(),
        "the root_doc write must wait behind lease_registrar"
    );
    drop(guard);

    let doc = tokio::time::timeout(Duration::from_secs(1), &mut open)
        .await
        .expect("window open must complete once lease_registrar is released")
        .unwrap();
    let deep = doc.get_deep_value();
    let map = deep.as_map().unwrap();
    assert!(map.contains_key("entities"));
    assert_eq!(read_window_list(&server.root_doc), vec![key.clone()]);
}

#[tokio::test]
async fn imported_updates_and_root_windows_survive_server_recreation() {
    let (_dir, vault) = test_vault();

    // ── Server instance 1: create a window, import an update (entity +
    //    tombstone), persist via the Observer-A-equivalent path.
    {
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
        let key = WindowKey::new("2026-02");
        let doc = server.get_or_create_window(&key).await.unwrap();

        let author = LoroDoc::new();
        author
            .get_map("entities")
            .insert("e1", b"v1".as_slice())
            .unwrap();
        author
            .get_map("tombstones")
            .insert("deadbeef", b"1".as_slice())
            .unwrap();
        author.commit();
        let update = author.export(ExportMode::all_updates()).unwrap();

        doc.import_with(&update, "conn:1").unwrap();
        server.persist_imported_update(&key, &update).unwrap();
    }

    // ── Server instance 2 over the same vault: RAM state is gone;
    //    everything must come back from sync_state.
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    // Root doc reloaded from d:root — meta.windows still lists the key.
    assert_eq!(
        read_window_list(&server.root_doc),
        vec![WindowKey::new("2026-02")]
    );

    // Window doc reloaded from d:w: + pending u:w: — the relayed entity
    // AND the tombstone (delete propagation) survive the restart.
    let doc = server
        .get_or_create_window(&WindowKey::new("2026-02"))
        .await
        .unwrap();
    assert_eq!(deep_map_bytes(&doc, "entities", "e1").unwrap(), b"v1");
    assert_eq!(
        deep_map_bytes(&doc, "tombstones", "deadbeef").unwrap(),
        b"1",
        "a relayed tombstone must survive a server restart"
    );
}

/// ONE-519: imported state is durable without a server-side `commit()`.
///
/// The companion of `imported_updates_and_root_windows_survive_server_recreation`
/// for the commit question: `import_with` + the Observer-A-equivalent durable
/// append is the WHOLE contract. No `doc.commit()` runs here — `commit()`
/// finalizes locally authored ops, and relayed bytes have none — yet entity,
/// edge and tombstone content plus the oplog VV must all come back from
/// `d:w:` + pending `u:w:` state on a fresh server over the same vault.
#[tokio::test]
async fn imported_update_vv_and_content_survive_server_recreation_without_commit() {
    let (_dir, vault) = test_vault();
    let key = WindowKey::new("2026-08");
    let entity = oneiron::EntityId::from_bytes([0x71; 16]).unwrap();
    let target = oneiron::EntityId::from_bytes([0x72; 16]).unwrap();
    let deleted = oneiron::EntityId::from_bytes([0x73; 16]).unwrap();
    let edge_key = format!(
        "{}:{:02}:{}",
        entity.to_hex(),
        oneiron::EdgeKind::Supports as u8,
        target.to_hex()
    );
    let edge_value = oneiron::sync::bridge::encode_edge_value_for_crdt(
        oneiron::EdgeKind::Supports,
        0.7,
        1,
        Some(oneiron::Vad::NEUTRAL),
        None,
    )
    .unwrap();
    let tombstone = tombstone_value(0x74);

    // ── Server instance 1: import a remote update, persist it, never commit.
    let vv_imported = {
        let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
        let doc = server.get_or_create_window(&key).await.unwrap();

        let author = LoroDoc::new();
        author
            .get_map("entities")
            .insert(entity.to_hex().as_str(), b"v1".as_slice())
            .unwrap();
        author
            .get_map("edges")
            .insert(edge_key.as_str(), edge_value.as_slice())
            .unwrap();
        author
            .get_map("tombstones")
            .insert(deleted.to_hex().as_str(), tombstone.as_slice())
            .unwrap();
        author.commit();
        let update = author.export(ExportMode::all_updates()).unwrap();

        doc.import_with(&update, "conn:1").unwrap();
        // Deliberately NO doc.commit(): the import already advanced state and
        // oplog, and a commit here would author a server-side boundary.
        server.persist_imported_update(&key, &update).unwrap();

        assert_eq!(
            deep_map_bytes(&doc, "entities", entity.to_hex().as_str()).as_deref(),
            Some(b"v1".as_slice()),
            "the import must be visible pre-restart without a commit"
        );
        doc.oplog_vv()
    };

    // ── Server instance 2 over the same vault: RAM state is gone.
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let doc = server.get_or_create_window(&key).await.unwrap();

    assert_eq!(
        deep_map_bytes(&doc, "entities", entity.to_hex().as_str()).as_deref(),
        Some(b"v1".as_slice()),
        "the relayed entity must survive the restart"
    );
    assert_eq!(
        deep_map_bytes(&doc, "edges", &edge_key).as_deref(),
        Some(edge_value.as_slice()),
        "the relayed edge must survive the restart"
    );
    assert_eq!(
        deep_map_bytes(&doc, "tombstones", deleted.to_hex().as_str()).as_deref(),
        Some(tombstone.as_slice()),
        "a relayed tombstone must survive the restart — an uncommitted import \
         cannot be allowed to strand delete propagation"
    );

    // VV convergence by Loro's partial order, never encoded-VV bytes: the
    // reloaded doc must dominate the pre-restart imported version.
    let vv_restored = doc.oplog_vv();
    assert!(
        vv_restored.includes_vv(&vv_imported),
        "the reloaded oplog must include every imported op: {vv_restored:?} vs {vv_imported:?}"
    );
    assert!(
        matches!(
            vv_restored.partial_cmp(&vv_imported),
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater)
        ),
        "the reloaded VV must dominate the imported VV: {vv_restored:?} vs {vv_imported:?}"
    );
}

#[tokio::test]
async fn boot_reconciles_root_windows_with_persisted_snapshots() {
    let (_dir, vault) = test_vault();

    // Simulate a crash between window-snapshot persistence and root
    // persistence: a d:w: snapshot exists but meta.windows never
    // learned the key.
    {
        let doc = LoroDoc::new();
        doc.commit();
        oneiron::sync::server_state::persist_window_snapshot(
            &vault,
            &WindowKey::new("2026-06"),
            &doc,
        )
        .unwrap();
    }

    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
    assert_eq!(
        read_window_list(&server.root_doc),
        vec![WindowKey::new("2026-06")],
        "boot must self-heal meta.windows from persisted d:w:* snapshots"
    );
}

#[tokio::test]
async fn corrupt_window_snapshot_fails_closed() {
    let (_dir, vault) = test_vault();
    vault.sync_state_put("d:w:2026-04", b"garbage").unwrap();

    // Boot-time reconcile sees the key but get_or_create_window must
    // refuse to serve a fresh empty window over the corrupt snapshot.
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
    let err = server
        .get_or_create_window(&WindowKey::new("2026-04"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            oneiron::Error::Sync(oneiron::error::SyncError::CrdtDecodeError { .. })
        ),
        "corrupt persisted window must error, got {err:?}"
    );
}

/// ONE-1140 lease lifecycle at the registrar (OD-3/OD-4/OD-7/OD-8):
/// register writes the pinned 66 B record into the root-doc `leases`
/// map AND the vault's vault-scoped `ls:` mirror row (byte-identical, OD-3);
/// renewal refreshes `renewed_at`/`expires_at` and flips an expired
/// binding back to active; a same-client/different-key request is
/// REJECTED with the binding untouched (first-binding-wins); revocation
/// is terminal; an invalid proof of possession never touches state.
#[tokio::test]
async fn retired_device_enrollment_refuses_fresh_and_residual_keys_without_mutation() {
    use ed25519_dalek::{Signer, SigningKey};
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let signer = SigningKey::from_bytes(&[7; 32]);
    let pubkey = signer.verifying_key().to_bytes();
    for (client, status) in [
        (1, None),
        (2, Some(LeaseStatus::Active)),
        (3, Some(LeaseStatus::Expired)),
        (4, Some(LeaseStatus::Revoked)),
    ] {
        if let Some(status) = status {
            seed_historical_lease(&server, 0, client, pubkey, status);
        }
        let row = vault.sync_state_get(&lease::lease_key(0, client)).unwrap();
        let proof = signer
            .sign(&lease::lease_pop_transcript(client, &pubkey))
            .to_bytes();
        let decision = server
            .register_lease(client, &pubkey, &proof)
            .await
            .unwrap();
        assert!(!decision.granted);
        assert_eq!(decision.expires_at, 0);
        assert!(decision.root_update.is_none());
        assert_eq!(
            vault.sync_state_get(&lease::lease_key(0, client)).unwrap(),
            row
        );
    }
    assert!(vault.authority_fold().unwrap().vault_id.is_none());
}

#[tokio::test]
async fn historical_lease_revocation_remains_tenant_local_but_neither_tenant_can_renew() {
    use ed25519_dalek::{Signer, SigningKey};
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let signer = SigningKey::from_bytes(&[42; 32]);
    let key = signer.verifying_key().to_bytes();
    let client = 17;
    for tenant in [10, 20] {
        seed_historical_lease(&server, tenant, client, key, LeaseStatus::Active);
    }
    let before = vault.sync_state_get(&lease::lease_key(20, client)).unwrap();
    assert!(
        server
            .revoke_lease_for_vault(10, client)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        lease::decode_lease_record(
            &vault
                .sync_state_get(&lease::lease_key(10, client))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .status,
        LeaseStatus::Revoked
    );
    assert_eq!(
        vault.sync_state_get(&lease::lease_key(20, client)).unwrap(),
        before
    );
    let proof = signer
        .sign(&lease::lease_pop_transcript(client, &key))
        .to_bytes();
    for tenant in [10, 20] {
        assert!(
            !server
                .register_lease_for_vault(tenant, client, &key, &proof)
                .await
                .unwrap()
                .granted
        );
    }
}

#[tokio::test]
async fn lease_expiry_tick_flips_only_active_expired_rows_and_is_idempotent() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let now = 10_000;

    let active_client = 0x1000_0000_0000_0001u64;
    let revoked_client = 0x1000_0000_0000_0002u64;
    let expired_client = 0x1000_0000_0000_0003u64;
    let active_future_client = 0x1000_0000_0000_0004u64;
    let lease_row = |status: LeaseStatus, expires_at: u64, pubkey_byte: u8| LeaseRecord {
        vault_id: SERVER_LEASE_VAULT_ID,
        status,
        pubkey: [pubkey_byte; 32],
        granted_at: 1,
        renewed_at: 2,
        expires_at,
    };

    let active = lease_row(LeaseStatus::Active, now - 1, 1);
    let revoked = lease_row(LeaseStatus::Revoked, now - 1, 2);
    let expired = lease_row(LeaseStatus::Expired, now - 1, 3);
    let active_future = lease_row(LeaseStatus::Active, now + 1, 4);
    let revoked_before = lease::encode_lease_record(&revoked);
    let expired_before = lease::encode_lease_record(&expired);
    let active_future_before = lease::encode_lease_record(&active_future);
    let leases = server.root_doc.get_map(ROOT_LEASES_MAP);
    for (client, record) in [
        (active_client, active),
        (revoked_client, revoked),
        (expired_client, expired),
        (active_future_client, active_future),
    ] {
        leases
            .insert(
                lease::client_id_hex(client).as_str(),
                lease::encode_lease_record(&record).as_slice(),
            )
            .unwrap();
    }
    server.root_doc.commit();

    let report = server.expire_leases_once_at(now).await.unwrap();
    assert!(!report.skipped);
    assert_eq!(report.expired_rows, 1);
    assert!(report.root_update.is_some());

    let active_after = vault
        .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, active_client))
        .unwrap()
        .unwrap();
    assert_eq!(active_after[1], 0x02, "status byte 0x01 -> 0x02");
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, revoked_client))
            .unwrap()
            .unwrap(),
        revoked_before,
        "revoked rows stay byte-identical"
    );
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, expired_client))
            .unwrap()
            .unwrap(),
        expired_before,
        "already-expired rows stay byte-identical"
    );
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(
                SERVER_LEASE_VAULT_ID,
                active_future_client
            ))
            .unwrap()
            .unwrap(),
        active_future_before,
        "unexpired active rows stay byte-identical"
    );

    let report = server.expire_leases_once_at(now).await.unwrap();
    assert_eq!(report.expired_rows, 0, "second tick is a no-op");
    assert!(report.root_update.is_none());
}

#[tokio::test]
async fn concurrent_lease_expiry_tick_skips_in_flight_job() {
    let (_dir, vault) = test_vault();
    let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap());
    let now = 10_000;
    let client_id = 0x2000_0000_0000_0001u64;
    let record = LeaseRecord {
        vault_id: SERVER_LEASE_VAULT_ID,
        status: LeaseStatus::Active,
        pubkey: [9; 32],
        granted_at: 1,
        renewed_at: 2,
        expires_at: now - 1,
    };
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(
            lease::client_id_hex(client_id).as_str(),
            lease::encode_lease_record(&record).as_slice(),
        )
        .unwrap();
    server.root_doc.commit();

    let registrar_guard = server.lease_registrar.lock().await;
    let first = {
        let server = Arc::clone(&server);
        tokio::spawn(async move { server.expire_leases_once_at(now).await.unwrap() })
    };
    let expiry_key = server.lifecycle_job_key(LifecycleJobKind::LeaseExpiry);
    loop {
        if server
            .lifecycle_in_flight
            .lock()
            .await
            .contains(&expiry_key)
        {
            break;
        }
        tokio::task::yield_now().await;
    }

    let second = server.expire_leases_once_at(now).await.unwrap();
    assert!(second.skipped, "overlapping tick is skipped, not queued");
    drop(registrar_guard);
    let first = first.await.unwrap();
    assert_eq!(first.expired_rows, 1);
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_id))
            .unwrap()
            .unwrap()[1],
        0x02,
        "the row is flipped exactly once"
    );
}

#[tokio::test]
async fn ra_drain_tick_clears_only_fully_reasserted_windows() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let complete_window = WindowKey::new("2026-03");
    let partial_window = WindowKey::new("2026-04");
    persist_empty_window(&vault, &complete_window);
    persist_empty_window(&vault, &partial_window);
    let loaded_complete_doc = server.get_or_create_window(&complete_window).await.unwrap();

    let complete_id = oneiron::EntityId::now();
    let partial_id = oneiron::EntityId::now();
    let complete_value = tombstone_value(0x11);
    let partial_value = tombstone_value(0x22);
    let malformed_value = tombstone_value(0x33);
    vault
        .sync_state_put(
            &format!("ra:w:{}:{}", complete_window.as_str(), complete_id.to_hex()),
            &complete_value,
        )
        .unwrap();
    vault
        .sync_state_put(
            &format!("ra:w:{}:{}", partial_window.as_str(), partial_id.to_hex()),
            &partial_value,
        )
        .unwrap();
    vault
        .sync_state_put(
            &format!("ra:w:{}:not-hex", partial_window.as_str()),
            &malformed_value,
        )
        .unwrap();

    let report = server.drain_reassert_markers_once().await.unwrap();
    assert!(!report.skipped);
    assert_eq!(
        report.report.drained,
        vec![complete_window.as_str().to_owned()]
    );
    assert_eq!(
        report.report.still_pending,
        vec![partial_window.as_str().to_owned()]
    );
    assert!(
        vault
            .sync_state_get(&format!(
                "ra:w:{}:{}",
                complete_window.as_str(),
                complete_id.to_hex()
            ))
            .unwrap()
            .is_none(),
        "complete window marker is cleared"
    );
    assert!(
        vault
            .sync_state_get(&format!("ra:w:{}:not-hex", partial_window.as_str()))
            .unwrap()
            .is_some(),
        "malformed partial-window marker stays pending"
    );
    assert_eq!(
        deep_map_bytes(
            &loaded_complete_doc,
            "tombstones",
            complete_id.to_hex().as_str()
        )
        .as_deref(),
        Some(complete_value.as_slice()),
        "loaded server window receives the reasserted tombstone"
    );
    assert_eq!(
        report.window_updates.len(),
        1,
        "loaded-window drain emits one client-visible update"
    );
    let (window_key, update) = &report.window_updates[0];
    let encoded = crate::protocol::encode_window_sync(window_key, window_sub_tags::UPDATE, update)
        .into_result()
        .unwrap();
    let crate::protocol::SyncMessage::WindowSync {
        window_key,
        sub_tag,
        payload,
    } = crate::protocol::parse_message(&encoded).unwrap()
    else {
        panic!("expected WindowSync update");
    };
    assert_eq!(window_key, complete_window.as_str());
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert_eq!(payload.as_slice(), update.as_slice());

    assert!(
        server
            .begin_lifecycle_job(LifecycleJobKind::ReassertDrain)
            .await
    );
    let skipped = server.drain_reassert_markers_once().await.unwrap();
    assert!(skipped.skipped, "overlapping ra drain is skipped");
    server
        .end_lifecycle_job(LifecycleJobKind::ReassertDrain)
        .await;
}

/// Historical withdrawal still commits or rolls back its durable root and mirror together.
#[tokio::test]
async fn historical_lease_revoke_root_and_mirror_roll_back_together_on_failure() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let client = 42;
    seed_historical_lease(&server, 0, client, [42; 32], LeaseStatus::Active);
    let root_before = vault.sync_state_get("d:root").unwrap().unwrap();
    let row_before = vault
        .sync_state_get(&lease::lease_key(0, client))
        .unwrap()
        .unwrap();
    oneiron::sync::lease::test_hooks::arm_mirror_failure();
    assert!(matches!(
        server.revoke_lease(client).await,
        Err(oneiron::Error::CorruptedIndex(_))
    ));
    assert_eq!(
        vault.sync_state_get("d:root").unwrap().unwrap(),
        root_before
    );
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(0, client))
            .unwrap()
            .unwrap(),
        row_before
    );
    assert_eq!(
        deep_map_bytes(
            &server.root_doc,
            "leases",
            &lease::lease_registry_key(0, client)
        )
        .unwrap(),
        row_before
    );
    drop(server);
    let rebooted = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    assert_eq!(
        deep_map_bytes(
            &rebooted.root_doc,
            "leases",
            &lease::lease_registry_key(0, client)
        )
        .unwrap(),
        row_before
    );
    assert!(rebooted.revoke_lease(client).await.unwrap().is_some());
    assert_eq!(
        lease::decode_lease_record(
            &vault
                .sync_state_get(&lease::lease_key(0, client))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .status,
        LeaseStatus::Revoked
    );
}

/// Retired enrollment never writes, even when the old registry is corrupt.
#[tokio::test]
async fn register_refuses_on_non_binary_lease_entry() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    // Inject a NON-binary value into the root leases map (e.g. an i64),
    // simulating local registry corruption.
    let corrupt_key = lease::client_id_hex(0x00cc_00cc_00cc_00ccu64);
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(corrupt_key.as_str(), LoroValue::I64(7))
        .unwrap();
    server.root_doc.commit();

    // A fully valid registration (valid PoP) must still be refused.
    let key = SigningKey::from_bytes(&[55u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let client_id = 0x00dd_00dd_00dd_00ddu64;
    let pop = key
        .sign(&lease::lease_pop_transcript(client_id, &pubkey))
        .to_bytes();

    let refused = server
        .register_lease(client_id, &pubkey, &pop)
        .await
        .unwrap();
    assert!(!refused.granted);
    assert!(refused.root_update.is_none());

    // Fail-closed-hard: NO ls:/active row for the attempted registration,
    // and no existing lease altered (no row was written at all).
    assert!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_id))
            .unwrap()
            .is_none(),
        "a refused registration writes NO ls: row"
    );
    assert!(
        deep_map_bytes(
            &server.root_doc,
            "leases",
            &lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_id),
        )
        .is_none(),
        "no leases-map entry for the refused registration"
    );
    // The corrupt entry is left exactly as-is (never silently rewritten).
    assert!(
        matches!(
            server.root_doc.get_map(ROOT_LEASES_MAP).get(&corrupt_key),
            Some(ValueOrContainer::Value(LoroValue::I64(7)))
        ),
        "the non-binary entry is not silently mutated"
    );
}

/// B5: revoke distinguishes absent from corrupt. A non-binary root lease
/// entry is local registry corruption and must fail closed with
/// `CorruptedIndex(_)`, not masquerade as Ok(None).
#[tokio::test]
async fn revoke_refuses_on_non_binary_lease_entry() {
    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
    let client_id = 0x00ee_00ee_00ee_00eeu64;
    let key_hex = lease::client_id_hex(client_id);
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(key_hex.as_str(), LoroValue::I64(7))
        .unwrap();
    server.root_doc.commit();

    let err = server.revoke_lease(client_id).await.unwrap_err();
    assert!(matches!(err, oneiron::Error::CorruptedIndex(_)));
    assert!(
        matches!(
            server.root_doc.get_map(ROOT_LEASES_MAP).get(&key_hex),
            Some(ValueOrContainer::Value(LoroValue::I64(7)))
        ),
        "the corrupt lease entry must not be mutated by revoke"
    );
}

#[test]
fn used_window_sub_tags_are_pinned() {
    // The handler relies on these wire literals; keep them pinned here
    // so the server crate notices a transport renumbering.
    assert_eq!(window_sub_tags::UPDATE, 0);
    assert_eq!(window_sub_tags::VV_REQUEST, 2);
    assert_eq!(window_sub_tags::VV_RESPONSE, 3);
}
