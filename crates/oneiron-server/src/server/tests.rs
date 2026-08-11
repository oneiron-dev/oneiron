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

fn tombstone_value(request_byte: u8) -> [u8; oneiron::TOMBSTONE_VALUE_V2_LEN] {
    oneiron::TombstoneValueV2 {
        reason: oneiron::TombstoneReason::GdprDelete,
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
        matches!(err, oneiron::Error::CrdtDecodeError { .. }),
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
async fn lease_lifecycle_register_renew_conflict_revoke() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let client_id = 0x0123_4567_89ab_cdefu64;
    let registry_key = lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_id);
    let pop = |signer: &SigningKey, cid: u64, pk: &[u8; 32]| {
        signer
            .sign(&lease::lease_pop_transcript(cid, pk))
            .to_bytes()
    };

    // ── Register: granted, record layout literals on BOTH surfaces.
    let decision = server
        .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
        .await
        .unwrap();
    assert!(decision.granted);
    assert!(decision.root_update.is_some(), "registry change broadcasts");
    let map_record = deep_map_bytes(&server.root_doc, "leases", &registry_key).unwrap();
    let ls_row = vault
        .sync_state_get("ls:0000000000000000:0123456789abcdef")
        .unwrap()
        .unwrap();
    assert_eq!(
        map_record, ls_row,
        "OD-3: map value ≡ ls: row, byte-identical"
    );
    assert_eq!(ls_row.len(), 66, "OD-4 record length");
    assert_eq!(ls_row[0], 0x02, "version byte");
    assert_eq!(ls_row[1], 0x01, "status active");
    assert_eq!(&ls_row[2..34], &pubkey);
    let granted_at = u64::from_le_bytes(ls_row[34..42].try_into().unwrap());
    let renewed_at = u64::from_le_bytes(ls_row[42..50].try_into().unwrap());
    let expires_at = u64::from_le_bytes(ls_row[50..58].try_into().unwrap());
    let vault_id = u64::from_be_bytes(ls_row[58..66].try_into().unwrap());
    assert_eq!(vault_id, SERVER_LEASE_VAULT_ID, "vault_id u64 BE");
    assert_eq!(granted_at, renewed_at);
    assert_eq!(
        LEASE_DURATION_SECS, 7_776_000,
        "90-day lease literal (OD-4)"
    );
    assert_eq!(
        expires_at,
        renewed_at + LEASE_DURATION_SECS,
        "90-day lease literal (OD-4)"
    );
    assert_eq!(decision.expires_at, expires_at);

    // ── Renew: simulate an old, EXPIRED binding (server is sole
    // writer, so the test rewrites the registry record directly), then
    // re-request with the SAME key: flips back to active, renewed_at
    // and expires_at refresh, granted_at is preserved.
    let stale = lease::LeaseRecord {
        vault_id: SERVER_LEASE_VAULT_ID,
        status: lease::LeaseStatus::Expired,
        pubkey,
        granted_at: 1_000,
        renewed_at: 2_000,
        expires_at: 3_000,
    };
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .delete(&registry_key)
        .unwrap();
    server
        .root_doc
        .get_map(ROOT_LEASES_MAP)
        .insert(
            lease::client_id_hex(client_id).as_str(),
            lease::encode_lease_record(&stale).as_slice(),
        )
        .unwrap();
    server.root_doc.commit();
    let decision = server
        .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
        .await
        .unwrap();
    assert!(
        decision.granted,
        "expired + same key = renewal, not rejection"
    );
    let renewed_row = vault
        .sync_state_get("ls:0000000000000000:0123456789abcdef")
        .unwrap()
        .unwrap();
    assert!(
        deep_map_bytes(&server.root_doc, "leases", &lease::client_id_hex(client_id)).is_none(),
        "renewal migrates legacy client-only root keys to scoped registry keys"
    );
    assert!(
        deep_map_bytes(&server.root_doc, "leases", &registry_key).is_some(),
        "renewal keeps the active binding under the scoped registry key"
    );
    assert_eq!(renewed_row[1], 0x01, "expired flips back to active");
    assert_eq!(
        u64::from_le_bytes(renewed_row[34..42].try_into().unwrap()),
        1_000,
        "granted_at preserved across renewal"
    );
    let renewed_at2 = u64::from_le_bytes(renewed_row[42..50].try_into().unwrap());
    assert!(renewed_at2 > 2_000, "renewed_at refreshed");
    assert_eq!(
        u64::from_le_bytes(renewed_row[50..58].try_into().unwrap()),
        renewed_at2 + 7_776_000
    );

    // ── Conflict: same client id, DIFFERENT key → rejected, binding
    // bytes untouched (first-binding-wins).
    let intruder = SigningKey::from_bytes(&[9u8; 32]);
    let intruder_pk = intruder.verifying_key().to_bytes();
    let decision = server
        .register_lease(
            client_id,
            &intruder_pk,
            &pop(&intruder, client_id, &intruder_pk),
        )
        .await
        .unwrap();
    assert!(!decision.granted);
    assert_eq!(
        decision.expires_at, 0,
        "rejected ack carries expires_at = 0"
    );
    assert_eq!(
        vault
            .sync_state_get("ls:0000000000000000:0123456789abcdef")
            .unwrap()
            .unwrap(),
        renewed_row,
        "a binding conflict must not modify the existing binding"
    );

    // ── Invalid PoP (valid key, signature over the WRONG client id):
    // rejected, no state change.
    let other_client = client_id + 1;
    let decision = server
        .register_lease(other_client, &pubkey, &pop(&key, client_id, &pubkey))
        .await
        .unwrap();
    assert!(
        !decision.granted,
        "PoP transcript binds the claimed client id"
    );
    assert!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, other_client))
            .unwrap()
            .is_none(),
        "an invalid PoP never reaches the registry"
    );

    // ── Revoke: terminal (OD-8). Status flips on both surfaces and a
    // later re-request with the ORIGINAL key is rejected.
    let update = server.revoke_lease(client_id).await.unwrap();
    assert!(update.is_some(), "revocation broadcasts a registry change");
    let revoked_row = vault
        .sync_state_get("ls:0000000000000000:0123456789abcdef")
        .unwrap()
        .unwrap();
    assert_eq!(revoked_row[1], 0x03, "status revoked");
    let decision = server
        .register_lease(client_id, &pubkey, &pop(&key, client_id, &pubkey))
        .await
        .unwrap();
    assert!(!decision.granted, "revoked is terminal — no re-activation");
    // Unknown binding: revoke is a no-op (no phantom records).
    assert!(server.revoke_lease(0xffff).await.unwrap().is_none());
}

#[tokio::test]
async fn tenant_isolation_replay_cache_fixtures_keep_grants_separate() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    let tenant_a = 0x0a0b_0c0d_0e0f_1011u64;
    let tenant_b = 0x1110_0f0e_0d0c_0b0au64;
    let client_id = 0x0123_4567_89ab_cdefu64;
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let pop = key
        .sign(&lease::lease_pop_transcript(client_id, &pubkey))
        .to_bytes();

    let grant_a = server
        .register_lease_for_vault(tenant_a, client_id, &pubkey, &pop)
        .await
        .unwrap();
    let grant_b = server
        .register_lease_for_vault(tenant_b, client_id, &pubkey, &pop)
        .await
        .unwrap();

    assert!(grant_a.granted);
    assert!(grant_b.granted);
    assert!(
        deep_map_bytes(&server.root_doc, "leases", &lease::client_id_hex(client_id)).is_none(),
        "new hosted writes must not use the legacy subscriber-only root key"
    );
    for tenant in [tenant_a, tenant_b] {
        let registry_key = lease::lease_registry_key(tenant, client_id);
        let mirror_key = lease::lease_key(tenant, client_id);
        let map_record = deep_map_bytes(&server.root_doc, "leases", &registry_key)
            .expect("scoped root lease entry");
        let mirror_record = vault
            .sync_state_get(&mirror_key)
            .unwrap()
            .expect("scoped ls mirror row");
        assert_eq!(
            map_record, mirror_record,
            "root grant cache and replay-door mirror stay byte-identical per tenant"
        );
        assert_eq!(
            lease::decode_lease_record(&mirror_record).unwrap().vault_id,
            tenant
        );
    }

    assert!(
        server
            .revoke_lease_for_vault(tenant_a, client_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        lease::decode_lease_record(
            &vault
                .sync_state_get(&lease::lease_key(tenant_a, client_id))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .status,
        LeaseStatus::Revoked
    );
    assert_eq!(
        lease::decode_lease_record(
            &vault
                .sync_state_get(&lease::lease_key(tenant_b, client_id))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .status,
        LeaseStatus::Active,
        "tenant A revoke must not mutate tenant B's grant cache row"
    );

    let tenant_b_renewal = server
        .register_lease_for_vault(tenant_b, client_id, &pubkey, &pop)
        .await
        .unwrap();
    assert!(
        tenant_b_renewal.granted,
        "same subscriber and pubkey revoked in tenant A must still renew in tenant B"
    );
    let tenant_a_retry = server
        .register_lease_for_vault(tenant_a, client_id, &pubkey, &pop)
        .await
        .unwrap();
    assert!(
        !tenant_a_retry.granted,
        "tenant A's own revoked row remains terminal"
    );
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

/// ONE-1140 RULING A (OD-8 amended, pubkey-bound; delete-safety adjacent,
/// cap-exempt): `register_lease` refuses a FRESH active lease for a
/// pubkey that ANY `ls:` row has revoked. A revoked pubkey is terminal
/// across ALL client_ids, so a device rotating client_id while reusing
/// its key cannot recover (recovery requires a fresh KEYPAIR). The
/// None-arm guard writes NO row and grants nothing. A wrong impl that
/// grants any absent client_id would write `ls:{vault}:{B}` active and FAIL here.
#[tokio::test]
async fn register_lease_refuses_active_lease_for_already_revoked_pubkey() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    let key = SigningKey::from_bytes(&[23u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let pop = |signer: &SigningKey, cid: u64, pk: &[u8; 32]| {
        signer
            .sign(&lease::lease_pop_transcript(cid, pk))
            .to_bytes()
    };

    // Client A binds pubkey P, then the owner revokes it.
    let client_a = 0x0a0a_0a0a_0a0a_0a0au64;
    assert!(
        server
            .register_lease(client_a, &pubkey, &pop(&key, client_a, &pubkey))
            .await
            .unwrap()
            .granted
    );
    assert!(server.revoke_lease(client_a).await.unwrap().is_some());
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_a))
            .unwrap()
            .unwrap()[1],
        0x03,
        "client A's binding is revoked"
    );

    // A FRESH client B presents the SAME (revoked) pubkey with a valid
    // proof of possession.
    let client_b = 0x0b0b_0b0b_0b0b_0b0bu64;
    assert_ne!(client_a, client_b);
    let decision = server
        .register_lease(client_b, &pubkey, &pop(&key, client_b, &pubkey))
        .await
        .unwrap();
    assert!(
        !decision.granted,
        "a revoked pubkey can never obtain a fresh active lease under any client_id"
    );
    assert_eq!(
        decision.expires_at, 0,
        "rejected ack carries expires_at = 0"
    );
    assert!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_b))
            .unwrap()
            .is_none(),
        "no ls: row is written for the refused fresh client_id"
    );
    assert!(
        deep_map_bytes(
            &server.root_doc,
            "leases",
            &lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_b)
        )
        .is_none(),
        "no leases-map entry exists for the refused fresh client_id"
    );
}

/// OD-8 pubkey floor also applies to RENEWAL: if client B is active with
/// pubkey P but a sibling client A has already revoked P, B cannot
/// refresh the lease. A wrong impl that guards only the None/fresh arm
/// grants the renewal and mutates B's `renewed_at`/`expires_at`.
#[tokio::test]
async fn renew_lease_refuses_when_sibling_revoked_same_pubkey() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    let key = SigningKey::from_bytes(&[31u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let pop = |cid: u64| {
        key.sign(&lease::lease_pop_transcript(cid, &pubkey))
            .to_bytes()
    };
    let client_a = 0x0c0c_0c0c_0c0c_0c0cu64;
    let client_b = 0x0d0d_0d0d_0d0d_0d0du64;

    assert!(
        server
            .register_lease(client_a, &pubkey, &pop(client_a))
            .await
            .unwrap()
            .granted
    );
    assert!(
        server
            .register_lease(client_b, &pubkey, &pop(client_b))
            .await
            .unwrap()
            .granted
    );
    assert!(server.revoke_lease(client_a).await.unwrap().is_some());
    let b_row_before = vault
        .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_b))
        .unwrap()
        .unwrap();
    assert_eq!(
        lease::decode_lease_record(&b_row_before).unwrap().status,
        LeaseStatus::Active,
        "client B starts active before the sibling floor is applied"
    );

    let decision = server
        .register_lease(client_b, &pubkey, &pop(client_b))
        .await
        .unwrap();
    assert!(
        !decision.granted,
        "renewal must refuse when any sibling revoked the same pubkey"
    );
    assert_eq!(decision.expires_at, 0);
    assert!(
        decision.root_update.is_none(),
        "a refused renewal with no expiry flips broadcasts no registry delta"
    );
    assert_eq!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_b))
            .unwrap()
            .unwrap(),
        b_row_before,
        "the refused renewal must not refresh B's lease row"
    );
    assert_eq!(
        lease::decode_lease_record(
            &vault
                .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_a))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .status,
        LeaseStatus::Revoked,
        "the sibling revocation evidence remains terminal"
    );
}

/// ONE-1140 R3 (delete-safety adjacent, cap-exempt): the `d:root`
/// snapshot persist and the `ls:` mirror must commit or roll back
/// together in ONE write txn. If the mirror fails mid-txn, the `d:root`
/// put rolls back — never a new `d:root` over a stale/missing `ls:`
/// mirror, which would let a revoked lease appear active at a replay
/// door reading `ls:`. A two-txn impl commits `d:root` BEFORE the mirror
/// failure → reopen shows the new `d:root` while `ls:` stays stale →
/// revoked-appears-active → fails the "d:root UNCHANGED" assertion.
#[tokio::test]
async fn lease_root_and_mirror_atomic_on_mirror_failure() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = test_vault();
    let server = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();

    let key = SigningKey::from_bytes(&[42u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let pop = |signer: &SigningKey, cid: u64, pk: &[u8; 32]| {
        signer
            .sign(&lease::lease_pop_transcript(cid, pk))
            .to_bytes()
    };

    // ── Bind client A, then revoke it (both surfaces successfully
    //    committed). ls:A now classifies Revoked.
    let client_a = 0x00aa_00aa_00aa_00aau64;
    assert!(
        server
            .register_lease(client_a, &pubkey, &pop(&key, client_a, &pubkey))
            .await
            .unwrap()
            .granted
    );
    assert!(server.revoke_lease(client_a).await.unwrap().is_some());
    let ls_a_revoked = vault
        .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_a))
        .unwrap()
        .unwrap();
    assert_eq!(ls_a_revoked[1], 0x03, "client A is revoked on ls:");

    // Durable d:root baseline AFTER the revoke (no client B yet).
    let d_root_before = vault.sync_state_get("d:root").unwrap().unwrap();

    // ── Arm a one-shot mirror failure, then attempt to register a FRESH
    //    client B with a distinct key (changes d:root AND would re-mirror
    //    ls:). The combined txn must roll back the d:root put.
    let key_b = SigningKey::from_bytes(&[43u8; 32]);
    let pubkey_b = key_b.verifying_key().to_bytes();
    let client_b = 0x00bb_00bb_00bb_00bbu64;
    oneiron::sync::lease::test_hooks::arm_mirror_failure();
    let err = server
        .register_lease(client_b, &pubkey_b, &pop(&key_b, client_b, &pubkey_b))
        .await
        .unwrap_err();
    assert!(
        matches!(err, oneiron::Error::CorruptedIndex(_)),
        "the injected mirror failure must propagate, got {err:?}"
    );

    // ── Inspect durable sync_state: the combined txn rolled back, so the
    //    committed `d:root` is the post-revoke baseline (no client B) and
    //    the door still classifies client A's lease Revoked (ls: intact).
    //    `sync_state_get` opens a fresh LMDB read txn, so it reflects the
    //    last COMMITTED state — exactly what a server restart would reload.
    //    A two-txn impl would have committed the new `d:root` (with B) in
    //    its own txn BEFORE the mirror failure → `d:root` would differ
    //    from `d_root_before` → fails the "UNCHANGED" assertion.
    assert_eq!(
        vault.sync_state_get("d:root").unwrap().unwrap(),
        d_root_before,
        "a mirror failure must roll back the d:root put (single txn)"
    );
    assert!(
        vault
            .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_b))
            .unwrap()
            .is_none(),
        "no ls: row for the rolled-back fresh client_id"
    );
    assert!(
        deep_map_bytes(
            &server.root_doc,
            "leases",
            &lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_b)
        )
        .is_none(),
        "the live in-memory root_doc must roll back client B after mirror failure"
    );
    let ls_a_after = vault
        .sync_state_get(&lease::lease_key(SERVER_LEASE_VAULT_ID, client_a))
        .unwrap()
        .unwrap();
    assert_eq!(
        lease::decode_lease_record(&ls_a_after).unwrap().status,
        LeaseStatus::Revoked,
        "the door still classifies the prior lease Revoked"
    );

    // Restart fidelity: a fresh SyncServer over the same Arc<Vault> boots
    // from the durable `d:root` — meta.windows is intact and no phantom
    // client B leaked into the reloaded root doc (the rollback held).
    drop(server);
    let rebooted = SyncServer::new(vault.clone(), SyncServerConfig::default()).unwrap();
    assert!(
        deep_map_bytes(
            &rebooted.root_doc,
            "leases",
            &lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_b)
        )
        .is_none(),
        "the rolled-back client B must not reappear after a server reboot"
    );
}

/// ONE-1140 R4 (fail-closed-hard): the server is the SOLE registry
/// writer and always stores BINARY lease records, so any non-binary
/// entry in the `leases` map is local corruption that could hide a
/// revoked-pubkey row from the registration floor. `register_lease` must
/// refuse the WHOLE registration with `CorruptedIndex("non-binary root
/// lease entry")` BEFORE any expiry flip / registration decision — never
/// best-effort skip the entry. A filter-and-skip impl would return
/// granted and write an `ls:`/active row → fails here.
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

    let err = server
        .register_lease(client_id, &pubkey, &pop)
        .await
        .unwrap_err();
    match err {
        oneiron::Error::CorruptedIndex(msg) => {
            assert_eq!(msg, "non-binary root lease entry");
        }
        other => panic!("expected CorruptedIndex, got {other:?}"),
    }

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
            &lease::lease_registry_key(SERVER_LEASE_VAULT_ID, client_id)
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
/// entry is local registry corruption and must fail closed with the same
/// literal as registration, not masquerade as Ok(None).
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
    match err {
        oneiron::Error::CorruptedIndex(msg) => {
            assert_eq!(msg, "non-binary root lease entry");
        }
        other => panic!("expected CorruptedIndex, got {other:?}"),
    }
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
