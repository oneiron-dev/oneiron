use super::*;
use crate::config::SyncServerConfig;
use core::assert_matches;
use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use tokio::sync::mpsc;

fn test_server() -> (tempfile::TempDir, SyncServer) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(vault, SyncServerConfig::default()).unwrap();
    (dir, server)
}

fn test_server_with_lease_vault_id(vault: Arc<oneiron::Vault>, lease_vault_id: u64) -> SyncServer {
    SyncServer::new(
        vault,
        SyncServerConfig {
            lease_vault_id,
            ..Default::default()
        },
    )
    .unwrap()
}

/// Client-side stand-in window doc with the schema containers.
fn client_window_doc() -> LoroDoc {
    let doc = LoroDoc::new();
    let _ = doc.get_map("entities");
    let _ = doc.get_map("edges");
    let _ = doc.get_map("tombstones");
    doc.commit();
    doc
}

fn expect_window_sync(data: &[u8]) -> (String, u8, Vec<u8>) {
    let parsed = protocol::parse_message(data).unwrap();
    let SyncMessage::WindowSync {
        window_key,
        sub_tag,
        payload,
    } = parsed
    else {
        panic!("expected WindowSync, got {parsed:?}");
    };
    (window_key, sub_tag, payload)
}

fn test_legacy_conn_state() -> ConnState {
    let config = SyncServerConfig::default();
    ConnState::new(
        config.max_messages_per_sec,
        protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION,
        FederationQuotaConfig::new(
            config.max_federation_windows_per_connection,
            config.federation_flood_pause_secs,
        ),
    )
}

fn test_selector_conn_state() -> ConnState {
    let config = SyncServerConfig::default();
    ConnState::new(
        config.max_messages_per_sec,
        protocol::PROTOCOL_VERSION,
        FederationQuotaConfig::new(
            config.max_federation_windows_per_connection,
            config.federation_flood_pause_secs,
        ),
    )
}

#[test]
fn oversized_late_join_ephemeral_snapshot_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            max_ephemeral_snapshot_bytes: 1,
            ..Default::default()
        },
    )
    .unwrap();
    server.ephemeral_store.set("presence:device-a", "online");

    let snapshot = encode_late_join_ephemeral_snapshot(&server, 1);

    assert!(
        snapshot.is_none(),
        "oversized hub snapshots should be skipped, not connection-fatal"
    );
}

fn test_selector_conn_state_with_config(config: &SyncServerConfig) -> ConnState {
    ConnState::new(
        config.max_messages_per_sec,
        protocol::PROTOCOL_VERSION,
        FederationQuotaConfig::new(
            config.max_federation_windows_per_connection,
            config.federation_flood_pause_secs,
        ),
    )
}

fn entity_id(byte: u8) -> oneiron::EntityId {
    oneiron::EntityId::from_bytes([byte; 16]).unwrap()
}

fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + body.len());
    blob.push(entity_type);
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(body);
    blob
}

fn insert_entity(doc: &LoroDoc, id: oneiron::EntityId, entity_type: u8, body: &[u8]) {
    doc.get_map("entities")
        .insert(
            id.to_hex().as_str(),
            entity_blob(entity_type, body).as_slice(),
        )
        .unwrap();
}

fn insert_edge(
    doc: &LoroDoc,
    src: oneiron::EntityId,
    kind: oneiron::EdgeKind,
    tgt: oneiron::EntityId,
) {
    let key = format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex());
    let value = oneiron::sync::bridge::encode_edge_value_for_crdt(
        kind,
        0.7,
        1,
        Some(oneiron::Vad::NEUTRAL),
        None,
    )
    .unwrap();
    doc.get_map("edges")
        .insert(key.as_str(), value.as_slice())
        .unwrap();
}

fn test_selector_scope() -> oneiron::FederationGrantScope {
    selector_grant_scope()
}

async fn submit_lease_request(
    server: &SyncServer,
    client_id: u64,
    pubkey: [u8; 32],
    pop_sig: [u8; 64],
) -> bool {
    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_sync_message(
        server,
        1,
        SyncMessage::LeaseRequest {
            client_id,
            pubkey,
            pop_sig,
        },
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let ack = direct_rx.try_recv().expect("lease request must ack");
    assert_eq!(ack[0], oneiron::sync::transport::TAG_LEASE_GRANTED);
    let (status, ack_client_id, expires_at) =
        oneiron::sync::transport::decode_lease_granted(&ack[1..]).unwrap();
    assert_eq!(ack_client_id, client_id);
    if status == oneiron::sync::transport::LEASE_STATUS_GRANTED {
        assert_ne!(expires_at, 0, "granted leases carry an expiry");
        true
    } else {
        assert_eq!(expires_at, 0, "rejected leases carry no expiry");
        false
    }
}

fn root_lease_record(
    server: &SyncServer,
    vault_id: u64,
    client_id: u64,
) -> oneiron::sync::LeaseRecord {
    let key = oneiron::sync::lease::lease_registry_key(vault_id, client_id);
    match server
        .root_doc
        .get_map(oneiron::sync::ROOT_LEASES_MAP)
        .get(&key)
    {
        Some(ValueOrContainer::Value(LoroValue::Binary(raw))) => {
            oneiron::sync::decode_lease_record(&raw).unwrap()
        }
        other => panic!("missing scoped root lease record {key}: {other:?}"),
    }
}

fn mirror_lease_record(
    vault: &oneiron::Vault,
    vault_id: u64,
    client_id: u64,
) -> oneiron::sync::LeaseRecord {
    let key = oneiron::sync::lease_key(vault_id, client_id);
    let raw = vault
        .sync_state_get(&key)
        .unwrap()
        .unwrap_or_else(|| panic!("missing mirrored lease row {key}"));
    oneiron::sync::decode_lease_record(&raw).unwrap()
}

#[tokio::test]
async fn hosted_lease_production_path_isolates_same_client_id_by_configured_vault() {
    use ed25519_dalek::{Signer, SigningKey};

    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let tenant_a = 0x0a0b_0c0d_0e0f_1011u64;
    let tenant_b = 0x1110_0f0e_0d0c_0b0au64;
    let client_id = 0x0123_4567_89ab_cdefu64;
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let pubkey = key.verifying_key().to_bytes();
    let pop_sig = key
        .sign(&oneiron::sync::lease_pop_transcript(client_id, &pubkey))
        .to_bytes();

    let server_a = test_server_with_lease_vault_id(vault.clone(), tenant_a);
    assert!(submit_lease_request(&server_a, client_id, pubkey, pop_sig).await);

    let server_b = test_server_with_lease_vault_id(vault.clone(), tenant_b);
    assert!(submit_lease_request(&server_b, client_id, pubkey, pop_sig).await);
    assert!(
        server_b
            .root_doc
            .get_map(oneiron::sync::ROOT_LEASES_MAP)
            .get(&oneiron::sync::client_id_hex(client_id))
            .is_none(),
        "production registration must not write the legacy subscriber-only root key"
    );
    assert_eq!(
        root_lease_record(&server_b, tenant_a, client_id).status,
        oneiron::sync::LeaseStatus::Active
    );
    assert_eq!(
        root_lease_record(&server_b, tenant_b, client_id).status,
        oneiron::sync::LeaseStatus::Active
    );
    assert_eq!(
        mirror_lease_record(&vault, tenant_a, client_id).status,
        oneiron::sync::LeaseStatus::Active
    );
    assert_eq!(
        mirror_lease_record(&vault, tenant_b, client_id).status,
        oneiron::sync::LeaseStatus::Active
    );

    let server_a_revoke = test_server_with_lease_vault_id(vault.clone(), tenant_a);
    assert!(
        server_a_revoke
            .revoke_lease(client_id)
            .await
            .unwrap()
            .is_some()
    );

    let server_b_renew = test_server_with_lease_vault_id(vault.clone(), tenant_b);
    assert!(submit_lease_request(&server_b_renew, client_id, pubkey, pop_sig).await);
    assert_eq!(
        root_lease_record(&server_b_renew, tenant_a, client_id).status,
        oneiron::sync::LeaseStatus::Revoked
    );
    assert_eq!(
        root_lease_record(&server_b_renew, tenant_b, client_id).status,
        oneiron::sync::LeaseStatus::Active,
        "tenant A's revocation floor must not block tenant B renewal"
    );

    let server_a_retry = test_server_with_lease_vault_id(vault.clone(), tenant_a);
    assert!(!submit_lease_request(&server_a_retry, client_id, pubkey, pop_sig).await);
    assert_eq!(
        root_lease_record(&server_a_retry, tenant_a, client_id).status,
        oneiron::sync::LeaseStatus::Revoked,
        "tenant A's own revoked row remains terminal"
    );
}

#[tokio::test]
async fn vv_request_sends_delta_and_vv_response() {
    let (_dir, server) = test_server();
    let key = "2026-03";

    // Server window doc: chunky shared base + a server-only divergence.
    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    server_doc
        .get_map("entities")
        .insert("base", vec![7u8; 2048].as_slice())
        .unwrap();
    server_doc.commit();

    // Client doc shares the base...
    let client_doc = client_window_doc();
    client_doc
        .import(&server_doc.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    // ...then the server moves ahead.
    server_doc
        .get_map("entities")
        .insert("server-only", b"s".as_slice())
        .unwrap();
    server_doc.commit();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::VV_REQUEST,
        &client_doc.oplog_vv().encode(),
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    // Message 1: the delta — a true ExportMode::updates delta, not all_updates.
    let (k0, sub0, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
    assert_eq!(k0, key);
    assert_eq!(sub0, window_sub_tags::UPDATE);
    let server_all = server_doc.export(ExportMode::all_updates()).unwrap();
    assert!(
        delta.len() < server_all.len(),
        "delta ({}) must be smaller than all_updates ({}) for the diverged case",
        delta.len(),
        server_all.len()
    );
    client_doc.import(&delta).unwrap();
    assert_eq!(client_doc.get_deep_value(), server_doc.get_deep_value());

    // Message 2: the server's VV so the client can push its local diff.
    let (k1, sub1, vv_payload) = expect_window_sync(&direct_rx.try_recv().unwrap());
    assert_eq!(k1, key);
    assert_eq!(sub1, window_sub_tags::VV_RESPONSE);
    let server_vv =
        VersionVector::decode(&vv_payload).expect("VV_RESPONSE payload must be Loro binary VV");
    assert_eq!(server_vv, server_doc.oplog_vv());

    assert!(direct_rx.try_recv().is_err(), "exactly two messages");
}

#[tokio::test]
async fn vv_request_scrubs_fenced_carrier_before_server_export() {
    let (_dir, server) = test_server();
    let key = "2026-03";
    let fenced = oneiron::EntityId::from_bytes([0x75; 16]).unwrap();
    let ordinary = oneiron::EntityId::from_bytes([0x76; 16]).unwrap();
    server
        .vault()
        .enter_off_record_session("sess-server-vv", oneiron::OffRecordBackendClass::Local)
        .unwrap();
    server
        .vault()
        .tag_turn_off_record("sess-server-vv", &fenced)
        .unwrap();

    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    server_doc
        .get_map("entities")
        .insert(&fenced.to_hex(), b"private".as_slice())
        .unwrap();
    server_doc
        .get_map("entities")
        .insert(&ordinary.to_hex(), b"ordinary".as_slice())
        .unwrap();
    server_doc.commit();

    let client_doc = client_window_doc();
    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::VV_REQUEST,
        &client_doc.oplog_vv().encode(),
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (_, sub_tag, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert!(
        !delta
            .windows(b"private".len())
            .any(|bytes| bytes == b"private"),
        "a peer behind the original set must not receive the private op bytes"
    );
    assert_eq!(
        LoroDoc::decode_import_blob_meta(&delta, false)
            .unwrap()
            .mode,
        loro::EncodedBlobMode::ShallowSnapshot
    );
    client_doc.import(&delta).unwrap();
    assert!(
        client_doc
            .get_map("entities")
            .get(&fenced.to_hex())
            .is_none(),
        "server VV delta must not carry the fenced body"
    );
    assert!(
        client_doc
            .get_map("entities")
            .get(&ordinary.to_hex())
            .is_some(),
        "legitimate non-fenced body remains exportable"
    );
}

#[tokio::test]
async fn inbound_update_with_fenced_carrier_is_not_relayed_verbatim() {
    let (_dir, server) = test_server();
    let key = "2026-03";
    let fenced = entity_id(0x77);
    let ordinary = entity_id(0x78);
    server
        .vault()
        .enter_off_record_session("sess-server-relay", oneiron::OffRecordBackendClass::Local)
        .unwrap();
    server
        .vault()
        .tag_turn_off_record("sess-server-relay", &fenced)
        .unwrap();

    let incoming = client_window_doc();
    insert_entity(
        &incoming,
        fenced,
        oneiron::registry::ENTITY_TYPE_TASK,
        b"private relay sentinel",
    );
    insert_entity(
        &incoming,
        ordinary,
        oneiron::registry::ENTITY_TYPE_TASK,
        b"ordinary relay control",
    );
    incoming.commit();
    let payload = incoming.export(ExportMode::all_updates()).unwrap();

    let mut broadcast_rx = server.broadcast_tx.subscribe();
    let (direct_tx, _direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::UPDATE,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (_sender, relayed) = broadcast_rx.try_recv().expect("scrub update broadcast");
    let (_, sub_tag, relayed_payload) = expect_window_sync(&relayed);
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert!(
        !relayed_payload
            .windows(b"private relay sentinel".len())
            .any(|window| window == b"private relay sentinel"),
        "the rejected inbound body bytes must not be relayed"
    );
    assert_eq!(
        LoroDoc::decode_import_blob_meta(&relayed_payload, false)
            .unwrap()
            .mode,
        loro::EncodedBlobMode::ShallowSnapshot,
        "privacy scrub must travel as a history-free snapshot"
    );
    for row in server
        .vault()
        .sync_state_keys_with_prefix(&format!("u:w:{key}:"))
        .unwrap()
    {
        let bytes = server.vault().sync_state_get(&row).unwrap().unwrap();
        assert!(
            !bytes
                .windows(b"private relay sentinel".len())
                .any(|window| window == b"private relay sentinel"),
            "raw rejected payload must never become a durable u:w carrier"
        );
    }
    let durable = server
        .vault()
        .sync_state_get(&format!("d:w:{key}"))
        .unwrap()
        .unwrap();
    assert!(
        !durable
            .windows(b"private relay sentinel".len())
            .any(|window| window == b"private relay sentinel"),
        "persisted snapshot must omit the rejected historical body bytes"
    );
    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    assert!(
        server_doc
            .get_map("entities")
            .get(&fenced.to_hex())
            .is_none()
    );
    assert!(
        server_doc
            .get_map("entities")
            .get(&ordinary.to_hex())
            .is_some()
    );
}

#[tokio::test]
async fn inbound_set_then_delete_fenced_body_relays_and_persists_history_free() {
    let (_dir, server) = test_server();
    let key = "2026-03";
    let fenced = entity_id(0x79);
    let ordinary = entity_id(0x7A);
    let private_sentinel = b"private server history sentinel";
    server
        .vault()
        .enter_off_record_session("sess-server-history", oneiron::OffRecordBackendClass::Local)
        .unwrap();
    server
        .vault()
        .tag_turn_off_record("sess-server-history", &fenced)
        .unwrap();

    let incoming = client_window_doc();
    insert_entity(
        &incoming,
        fenced,
        oneiron::registry::ENTITY_TYPE_TASK,
        private_sentinel,
    );
    insert_entity(
        &incoming,
        ordinary,
        oneiron::registry::ENTITY_TYPE_TASK,
        b"ordinary server history control",
    );
    incoming.commit();
    incoming
        .get_map("entities")
        .delete(&fenced.to_hex())
        .unwrap();
    incoming.commit();
    let payload = incoming.export(ExportMode::all_updates()).unwrap();
    assert!(
        payload
            .windows(private_sentinel.len())
            .any(|window| window == private_sentinel),
        "hostile update must carry the deleted fenced body in Loro history"
    );

    let mut broadcast_rx = server.broadcast_tx.subscribe();
    let (direct_tx, _direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::UPDATE,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (_sender, relayed) = broadcast_rx.try_recv().expect("history-free broadcast");
    let (_, sub_tag, relayed_payload) = expect_window_sync(&relayed);
    assert_eq!(sub_tag, window_sub_tags::UPDATE);
    assert_eq!(
        LoroDoc::decode_import_blob_meta(&relayed_payload, false)
            .unwrap()
            .mode,
        loro::EncodedBlobMode::ShallowSnapshot
    );
    assert!(
        !relayed_payload
            .windows(private_sentinel.len())
            .any(|window| window == private_sentinel)
    );
    let peer = client_window_doc();
    peer.import(&relayed_payload).unwrap();
    assert!(peer.get_map("entities").get(&fenced.to_hex()).is_none());
    assert!(peer.get_map("entities").get(&ordinary.to_hex()).is_some());

    assert!(
        server
            .vault()
            .sync_state_keys_with_prefix(&format!("u:w:{key}:"))
            .unwrap()
            .is_empty(),
        "server must replace the raw frame with a sanitized snapshot"
    );
    let durable = server
        .vault()
        .sync_state_get(&format!("d:w:{key}"))
        .unwrap()
        .expect("history-free server snapshot");
    assert!(
        !durable
            .windows(private_sentinel.len())
            .any(|window| window == private_sentinel)
    );
}

#[tokio::test]
async fn vv_request_malformed_vv_fails_closed_no_fallback() {
    let (_dir, server) = test_server();
    let key = "2026-03";
    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    server_doc
        .get_map("entities")
        .insert("secret", b"data".as_slice())
        .unwrap();
    server_doc.commit();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    // The dead JSON encoding and garbage must both be rejected.
    for payload in [&b"{}"[..], &[0xFFu8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF][..]] {
        let result = handle_window_sync(
            &server,
            1,
            key,
            window_sub_tags::VV_REQUEST,
            payload,
            &direct_tx,
            &mut conn_state,
        )
        .await;
        assert!(
            matches!(result, Err(ProtocolError::VvDecode(_))),
            "malformed VV must return the typed VvDecode error"
        );
        assert!(
            direct_rx.try_recv().is_err(),
            "fail-closed: no full-export fallback may be sent for a malformed VV"
        );
    }
}

#[tokio::test]
async fn vv_response_sends_local_diff_only() {
    let (_dir, server) = test_server();
    let key = "2026-04";
    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    server_doc
        .get_map("entities")
        .insert("ahead", b"x".as_slice())
        .unwrap();
    server_doc.commit();

    let client_doc = client_window_doc();
    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::VV_RESPONSE,
        &client_doc.oplog_vv().encode(),
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (k, sub, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
    assert_eq!(k, key);
    assert_eq!(sub, window_sub_tags::UPDATE);
    client_doc.import(&delta).unwrap();
    assert_eq!(client_doc.get_deep_value(), server_doc.get_deep_value());

    assert!(
        direct_rx.try_recv().is_err(),
        "VV_RESPONSE must NOT trigger another VV message (no ping-pong loop)"
    );
}

#[tokio::test]
async fn selector_vv_request_sends_filtered_update_only() {
    let (_dir, server) = test_server();
    let key = "2026-06";
    let window_key = WindowKey::new(key);
    let server_doc = server.get_or_create_window(&window_key).await.unwrap();

    let member = entity_id(0x31);
    let grant_id = oneiron::EntityId::now();
    let grant = oneiron::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::FederationGrantRole::Viewer,
        oneiron::FederationGrantPreset::ReadOnly,
    );
    oneiron::sync::put_selector_test_federation_grant(server.vault.as_ref(), &grant_id, &grant, 1)
        .unwrap();

    let facet_allowed = entity_id(0x51);
    let facet_denied = entity_id(0xB1);
    let claim_allowed = entity_id(0x60);
    let claim_denied = entity_id(0x12);
    let person = entity_id(0x21);
    insert_entity(
        &server_doc,
        facet_allowed,
        oneiron::registry::ENTITY_TYPE_FACET,
        b"facet-a",
    );
    insert_entity(
        &server_doc,
        facet_denied,
        oneiron::registry::ENTITY_TYPE_FACET,
        b"facet-b",
    );
    insert_entity(
        &server_doc,
        claim_allowed,
        oneiron::registry::ENTITY_TYPE_CLAIM,
        b"allowed-claim",
    );
    insert_entity(
        &server_doc,
        claim_denied,
        oneiron::registry::ENTITY_TYPE_CLAIM,
        b"denied-claim",
    );
    insert_entity(
        &server_doc,
        person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        b"person",
    );
    insert_edge(
        &server_doc,
        claim_allowed,
        oneiron::EdgeKind::FacetOf,
        facet_allowed,
    );
    insert_edge(
        &server_doc,
        claim_denied,
        oneiron::EdgeKind::FacetOf,
        facet_denied,
    );
    insert_edge(
        &server_doc,
        claim_allowed,
        oneiron::EdgeKind::Supports,
        person,
    );
    insert_edge(
        &server_doc,
        claim_denied,
        oneiron::EdgeKind::Supports,
        person,
    );
    server_doc.commit();

    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let client_doc = client_window_doc();
    let payload =
        oneiron::sync::encode_selector_vv_request(&selector, &client_doc.oplog_vv().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (k, sub, delta) = expect_window_sync(&direct_rx.try_recv().unwrap());
    assert_eq!(k, key);
    assert_eq!(sub, window_sub_tags::UPDATE);
    assert!(
        direct_rx.try_recv().is_err(),
        "selector fetch must not ask the client to push a reverse diff"
    );

    client_doc.import(&delta).unwrap();
    let entities = client_doc.get_map("entities");
    assert!(entities.get(claim_allowed.to_hex().as_str()).is_some());
    assert!(entities.get(facet_allowed.to_hex().as_str()).is_some());
    assert!(entities.get(person.to_hex().as_str()).is_some());
    assert!(entities.get(claim_denied.to_hex().as_str()).is_none());
    assert!(entities.get(facet_denied.to_hex().as_str()).is_none());
}

#[tokio::test]
async fn federated_selector_window_quota_exceeded_pauses_connection() {
    let config = SyncServerConfig {
        max_federation_windows_per_connection: 1,
        federation_flood_pause_secs: 30,
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(vault, config.clone()).unwrap();

    let member = entity_id(0x45);
    let grant_id = oneiron::EntityId::now();
    let grant = oneiron::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::FederationGrantRole::Viewer,
        oneiron::FederationGrantPreset::ReadOnly,
    );
    oneiron::sync::put_selector_test_federation_grant(server.vault.as_ref(), &grant_id, &grant, 1)
        .unwrap();
    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let payload =
        oneiron::sync::encode_selector_vv_request(&selector, &VersionVector::new().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state_with_config(&config);
    handle_window_sync(
        &server,
        1,
        "2026-03",
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();
    let _ = direct_rx
        .try_recv()
        .expect("first selector request replies");

    handle_window_sync(
        &server,
        1,
        "2026-04",
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    assert!(
        direct_rx.try_recv().is_err(),
        "paused selector connection must not load or reply for the churned window"
    );
    let snapshot = conn_state.federation_quota_snapshot();
    assert_eq!(
        snapshot.decision,
        AllowBlock::Pause(oneiron::sync::FederationPauseReason::FloodPauseActive)
    );
    assert_eq!(snapshot.windows_touched, 1);
    assert!(snapshot.pause_remaining.is_some());
}

#[tokio::test]
async fn own_device_window_cap_still_rejects_second_distinct_window() {
    let config = SyncServerConfig {
        max_windows_per_connection: 1,
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(vault, config).unwrap();
    let (direct_tx, _direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    let vv = VersionVector::new().encode();

    handle_window_sync(
        &server,
        1,
        "2026-03",
        window_sub_tags::VV_RESPONSE,
        &vv,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let result = handle_window_sync(
        &server,
        1,
        "2026-04",
        window_sub_tags::VV_RESPONSE,
        &vv,
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
}

#[tokio::test]
async fn selector_connection_rejects_full_window_bypass() {
    let (_dir, server) = test_server();
    let key = "2026-07";
    let window_key = WindowKey::new(key);
    let server_doc = server.get_or_create_window(&window_key).await.unwrap();
    server_doc
        .get_map("entities")
        .insert("secret", b"full-window-only".as_slice())
        .unwrap();
    server_doc.commit();

    let member = entity_id(0x41);
    let grant_id = oneiron::EntityId::now();
    let grant = oneiron::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::FederationGrantRole::Viewer,
        oneiron::FederationGrantPreset::ReadOnly,
    );
    oneiron::sync::put_selector_test_federation_grant(server.vault.as_ref(), &grant_id, &grant, 1)
        .unwrap();

    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let payload =
        oneiron::sync::encode_selector_vv_request(&selector, &VersionVector::new().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();
    let _ = direct_rx.try_recv().unwrap();

    let result = handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::VV_REQUEST,
        &VersionVector::new().encode(),
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
    assert!(
        direct_rx.try_recv().is_err(),
        "selector-scoped connection must not receive full-window fallback data"
    );
}

#[tokio::test]
async fn selector_protocol_rejects_first_message_full_window_sync() {
    let (_dir, server) = test_server();
    let key = "2026-10";
    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state();

    let result = handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::VV_REQUEST,
        &VersionVector::new().encode(),
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
    assert!(
        direct_rx.try_recv().is_err(),
        "selector-capable connections must not receive full-window data"
    );
}

#[tokio::test]
async fn legacy_protocol_rejects_selector_sync() {
    let (_dir, server) = test_server();
    let key = "2026-12";
    let member = entity_id(0x43);
    let grant_id = oneiron::EntityId::now();
    let grant = oneiron::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::FederationGrantRole::Viewer,
        oneiron::FederationGrantPreset::ReadOnly,
    );
    oneiron::sync::put_selector_test_federation_grant(server.vault.as_ref(), &grant_id, &grant, 1)
        .unwrap();
    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let payload =
        oneiron::sync::encode_selector_vv_request(&selector, &VersionVector::new().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    let result = handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
    assert!(
        direct_rx.try_recv().is_err(),
        "full-window connections must not receive selector data"
    );
}

#[tokio::test]
async fn selector_request_authorizes_before_window_creation() {
    let (_dir, server) = test_server();
    let key = "2027-01";
    let member = entity_id(0x44);
    let missing_grant_id = oneiron::EntityId::now();
    let selector = oneiron::sync::SyncSelector::new(
        missing_grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let payload =
        oneiron::sync::encode_selector_vv_request(&selector, &VersionVector::new().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state();
    let result = handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &payload,
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
    assert!(
        direct_rx.try_recv().is_err(),
        "unauthorized selector requests must not receive data"
    );
    assert!(
        server
            .vault
            .sync_state_get(&format!("d:w:{key}"))
            .unwrap()
            .is_none(),
        "selector auth must run before durable window snapshot creation"
    );
    assert!(
        !oneiron::sync::schema::read_window_list(&server.root_doc).contains(&WindowKey::new(key)),
        "selector auth must run before registering the window in root"
    );
}

#[tokio::test]
async fn selector_vv_request_rejects_incremental_remote_vv() {
    let (_dir, server) = test_server();
    let key = "2026-08";
    let window_key = WindowKey::new(key);
    let server_doc = server.get_or_create_window(&window_key).await.unwrap();

    let member = entity_id(0x62);
    let grant_id = oneiron::EntityId::now();
    let grant = oneiron::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::FederationGrantRole::Viewer,
        oneiron::FederationGrantPreset::ReadOnly,
    );
    oneiron::sync::put_selector_test_federation_grant(server.vault.as_ref(), &grant_id, &grant, 1)
        .unwrap();

    let facet_allowed = entity_id(0xC1);
    let claim_allowed = entity_id(0xC2);
    insert_entity(
        &server_doc,
        facet_allowed,
        oneiron::registry::ENTITY_TYPE_FACET,
        b"facet",
    );
    insert_entity(
        &server_doc,
        claim_allowed,
        oneiron::registry::ENTITY_TYPE_CLAIM,
        b"claim",
    );
    insert_edge(
        &server_doc,
        claim_allowed,
        oneiron::EdgeKind::FacetOf,
        facet_allowed,
    );
    server_doc.commit();

    let selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let client_doc = client_window_doc();
    let empty_payload =
        oneiron::sync::encode_selector_vv_request(&selector, &client_doc.oplog_vv().encode())
            .unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_selector_conn_state();
    handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &empty_payload,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let (_, _, snapshot) = expect_window_sync(&direct_rx.try_recv().unwrap());
    client_doc.import(&snapshot).unwrap();
    assert!(!client_doc.oplog_vv().is_empty());

    let narrowed_selector = oneiron::sync::SyncSelector::new(
        grant_id,
        member,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let incremental_payload = oneiron::sync::encode_selector_vv_request(
        &narrowed_selector,
        &client_doc.oplog_vv().encode(),
    )
    .unwrap();
    let result = handle_window_sync(
        &server,
        1,
        key,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &incremental_payload,
        &direct_tx,
        &mut conn_state,
    )
    .await;

    assert!(matches!(result, Err(ProtocolError::InvalidPayload(_))));
    assert!(
        direct_rx.try_recv().is_err(),
        "unsafe selector deltas must be rejected instead of sent"
    );
}

#[test]
fn selector_protocol_drops_window_sync_broadcasts() {
    let window_update = protocol::encode_window_sync("2026-11", window_sub_tags::UPDATE, b"window")
        .into_result()
        .unwrap();
    assert!(
        should_forward_broadcast(
            protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION,
            &window_update
        ),
        "full-window clients keep receiving WindowSync broadcasts"
    );
    assert!(
        !should_forward_broadcast(protocol::PROTOCOL_VERSION, &window_update),
        "selector-capable clients must not receive full-window WindowSync broadcasts"
    );

    let root_update = protocol::encode_root_update(b"root");
    assert!(
        should_forward_broadcast(protocol::PROTOCOL_VERSION, &root_update),
        "non-window broadcasts remain available to selector-capable clients"
    );
}

#[tokio::test]
async fn root_vv_replies_with_delta_and_rejects_malformed() {
    let (_dir, server) = test_server();

    // Client bootstrapped from the snapshot, then the server moves ahead.
    let client_root = LoroDoc::new();
    client_root
        .import(&server.export_root_snapshot().unwrap())
        .unwrap();
    server
        .root_doc
        .get_map("meta")
        .insert("windows", "2026-03".as_bytes())
        .unwrap();
    server.root_doc.commit();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_sync_message(
        &server,
        1,
        SyncMessage::RootVersionVector(client_root.oplog_vv().encode()),
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    let msg = direct_rx.try_recv().unwrap();
    assert_eq!(msg[0], protocol::TAG_SYNC_UPDATE);
    client_root.import(&msg[1..]).unwrap();
    assert_eq!(
        client_root.get_deep_value(),
        server.root_doc.get_deep_value()
    );

    // Malformed root VV → typed error, nothing sent.
    let result = handle_sync_message(
        &server,
        1,
        SyncMessage::RootVersionVector(b"{}".to_vec()),
        &direct_tx,
        &mut conn_state,
    )
    .await;
    assert_matches!(result, Err(ProtocolError::VvDecode(_)));
    assert!(direct_rx.try_recv().is_err());
}

// ─── outbound chokepoint (GuardedTransport) ───────────────────────────────────────

/// A `Sink` whose two backpressure phases the test controls independently,
/// recording what actually reaches the wire.
///
/// Backpressure is the whole point: a real peer socket blocks for an
/// unbounded interval, and a frame parked in that block is precisely what an
/// operator's `token revoke` is meant to stop. Which phase blocks matters,
/// because a real `tokio-tungstenite` sink parks in each for different
/// reasons:
///
/// - `poll_ready` gates whether the sink will ACCEPT another frame;
/// - `start_send` QUEUES the frame — it is not wire handover, and it never
///   blocks;
/// - `poll_flush` is where the peer's socket backpressure actually surfaces.
///
/// So `written` records only what `poll_flush` completes, never what
/// `start_send` queued: a frame sitting in `queued` has crossed no wire and
/// is still refusable. `ready_blocked` and `flush_blocked` are set
/// separately so a test can pin exactly one phase and prove the guard covers
/// it — a harness that blocks only `poll_ready` models the wrong phase and
/// would pass a flush-phase hole.
///
/// It is a `Stream` as well as a `Sink` because the two halves are ONE
/// transport, and the read half writes: tungstenite queues an automatic pong
/// for an inbound Ping and flushes the shared out-buffer — application frames
/// included — before `read` returns. `poll_next` therefore drains `queued` onto
/// the wire exactly like the real thing, which turns "a read was polled while a
/// guarded frame was pending" into observable escaped bytes rather than a
/// reviewer's assertion. `read_polls_while_pending` records the structural
/// violation directly, so a regression names the cause and not just the symptom.
#[derive(Clone)]
struct BlockableTransport {
    ready_blocked: Arc<std::sync::atomic::AtomicBool>,
    flush_blocked: Arc<std::sync::atomic::AtomicBool>,
    /// Accepted by `start_send` but not yet flushed: in the sink, off the wire.
    queued: Arc<std::sync::Mutex<Vec<WsMessage>>>,
    written: Arc<std::sync::Mutex<Vec<WsMessage>>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    /// Frames the peer has sent, awaiting a read poll.
    inbound: Arc<std::sync::Mutex<std::collections::VecDeque<WsMessage>>>,
    /// Times the read half was polled while an application frame sat pending.
    /// Must stay zero: that window is the side channel.
    read_polls_while_pending: Arc<std::sync::atomic::AtomicUsize>,
    /// Fires inside `start_send`, standing in for a revocation that lands in
    /// the instant between the pre-handover consult and the first flush poll.
    #[expect(clippy::type_complexity)]
    on_start_send: Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>,
}

impl BlockableTransport {
    /// Blocks the capacity wait — the frame never reaches the sink at all.
    fn ready_blocked() -> Self {
        Self::new(true, false)
    }

    /// Blocks the flush wait — the frame is QUEUED, then stalls before the
    /// wire. This is the shape of a real sink against a peer that stopped
    /// reading.
    fn flush_blocked() -> Self {
        Self::new(false, true)
    }

    fn open() -> Self {
        Self::new(false, false)
    }

    fn new(ready_blocked: bool, flush_blocked: bool) -> Self {
        Self {
            ready_blocked: Arc::new(std::sync::atomic::AtomicBool::new(ready_blocked)),
            flush_blocked: Arc::new(std::sync::atomic::AtomicBool::new(flush_blocked)),
            queued: Arc::default(),
            written: Arc::default(),
            closed: Arc::default(),
            waker: Arc::default(),
            inbound: Arc::default(),
            read_polls_while_pending: Arc::default(),
            on_start_send: Arc::default(),
        }
    }

    /// Queues a frame from the peer for the read half to pick up.
    fn push_inbound(&self, msg: WsMessage) {
        self.inbound.lock().unwrap().push_back(msg);
        self.wake();
    }

    /// Runs `f` inside `start_send`, i.e. after the pre-handover consult has
    /// already passed and before any flush poll.
    fn on_start_send(&self, f: impl FnOnce() + Send + 'static) {
        *self.on_start_send.lock().unwrap() = Some(Box::new(f));
    }

    fn read_polls_while_pending(&self) -> usize {
        self.read_polls_while_pending
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether an application frame is queued but not yet on the wire.
    fn has_pending_application_frame(&self) -> bool {
        !self.queued.lock().unwrap().is_empty()
    }

    fn unblock(&self) {
        self.ready_blocked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.flush_blocked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    /// What crossed the wire. Queued-but-unflushed frames are excluded on
    /// purpose: they are the bytes this leg must still be able to withhold.
    fn written(&self) -> Vec<WsMessage> {
        self.written.lock().unwrap().clone()
    }

    fn queued(&self) -> Vec<WsMessage> {
        self.queued.lock().unwrap().clone()
    }

    fn was_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn park(
        &self,
        cx: &std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::convert::Infallible>> {
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        std::task::Poll::Pending
    }

    /// Moves queued frames onto the wire, or parks if the peer is not reading.
    fn drain(
        &self,
        cx: &std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::convert::Infallible>> {
        if self.flush_blocked.load(std::sync::atomic::Ordering::SeqCst) {
            return self.park(cx);
        }
        let drained = std::mem::take(&mut *self.queued.lock().unwrap());
        self.written.lock().unwrap().extend(drained);
        std::task::Poll::Ready(Ok(()))
    }
}

impl futures_util::Sink<WsMessage> for BlockableTransport {
    type Error = std::convert::Infallible;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.ready_blocked.load(std::sync::atomic::Ordering::SeqCst) {
            return self.park(cx);
        }
        std::task::Poll::Ready(Ok(()))
    }

    /// Queues only. A real sink hands nothing to the socket here.
    fn start_send(self: std::pin::Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
        self.queued.lock().unwrap().push(item);
        // The revocation window this leg closes: the pre-handover consult has
        // passed, the frame is now IN the sink, and no flush poll has run yet.
        if let Some(hook) = self.on_start_send.lock().unwrap().take() {
            hook();
        }
        Ok(())
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.drain(cx)
    }

    /// A graceful close flushes on its way out, exactly like the real sink —
    /// which is why the revoked-at-flush path must NOT take this route.
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.drain(cx).is_pending() {
            return std::task::Poll::Pending;
        }
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready(Ok(()))
    }
}

/// The read half — same transport, and it FLUSHES.
///
/// This is the side channel in miniature. tungstenite's `read` writes and
/// flushes queued automatic responses (`Context::read` calls `flush`, which
/// calls `write_out_buffer`) before it returns a message, and that buffer is
/// shared with the write half. So polling a read while an application frame is
/// pending delivers that frame — no matter what the write half was about to
/// decide. Modelling the drain here rather than asserting a flag is the point:
/// if the handler ever polls a read in that window, bytes actually escape and
/// the assertions catch it.
impl futures_util::Stream for BlockableTransport {
    type Item = Result<WsMessage, std::convert::Infallible>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pending_before = self.has_pending_application_frame();
        if pending_before {
            self.read_polls_while_pending
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let next = self.inbound.lock().unwrap().pop_front();
        let Some(msg) = next else {
            return self.park(cx).map(|_| None);
        };
        // A Ping (or Close) queues an automatic response, and emitting it
        // flushes everything else sitting in the out-buffer with it.
        if matches!(msg, WsMessage::Ping(_) | WsMessage::Close(_)) {
            let drained = std::mem::take(&mut *self.queued.lock().unwrap());
            self.written.lock().unwrap().extend(drained);
        }
        std::task::Poll::Ready(Some(Ok(msg)))
    }
}

/// A registry the test mutates mid-send, standing in for the operator act.
#[derive(Default)]
struct MutableRevocations {
    revoked: std::sync::Mutex<std::collections::BTreeSet<String>>,
    unreadable: std::sync::atomic::AtomicBool,
}

impl MutableRevocations {
    fn revoke(&self, jti: &str) {
        self.revoked.lock().unwrap().insert(jti.to_owned());
    }

    fn make_unreadable(&self) {
        self.unreadable
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl crate::auth::RevokedTokenJtis for MutableRevocations {
    fn is_revoked(&self, jti: &str) -> Result<bool, ()> {
        if self.unreadable.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(());
        }
        Ok(self.revoked.lock().unwrap().contains(jti))
    }
}

const TEST_JTI: &str = "0123456789abcdef0123456789abcdef";

fn guarded(
    sink: &BlockableTransport,
    registry: &Arc<MutableRevocations>,
) -> GuardedTransport<BlockableTransport> {
    GuardedTransport::new(
        sink.clone(),
        Arc::clone(registry) as Arc<dyn crate::auth::RevokedTokenJtis + Send + Sync>,
        Some(TEST_JTI.to_owned()),
        7,
    )
}

/// Drives one `send_binary` to the point where it is parked on backpressure,
/// then applies `revoke` and releases the sink.
///
/// The revocation lands strictly inside whichever wait `sink` blocks — the
/// capacity wait or the flush wait. Returns whether the send reported "keep
/// going".
async fn send_racing_a_revocation(
    sink: &BlockableTransport,
    registry: &Arc<MutableRevocations>,
    revoke: impl FnOnce(&MutableRevocations),
) -> bool {
    let mut guarded = guarded(sink, registry);
    let mut send = Box::pin(guarded.send_binary(vec![1, 2, 3]));

    // The send stalls on the blocked sink.
    assert!(
        futures_util::poll!(send.as_mut()).is_pending(),
        "the sink must actually block, or this test proves nothing"
    );
    assert!(
        sink.written().is_empty(),
        "nothing may reach the wire while the sink is blocked"
    );

    revoke(registry);
    sink.unblock();
    send.await
}

/// The revocation lands while the frame is still OUTSIDE the sink.
#[tokio::test]
async fn frame_is_refused_when_revocation_lands_during_the_capacity_wait() {
    let sink = BlockableTransport::ready_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going = send_racing_a_revocation(&sink, &registry, |r| r.revoke(TEST_JTI)).await;

    assert!(!keep_going, "a revoked session must not continue");
    assert!(
        sink.written().is_empty(),
        "a frame awaiting capacity before the revocation still reached the client"
    );
    assert!(sink.queued().is_empty(), "the frame never entered the sink");
    assert!(sink.was_closed(), "the socket must close, not idle");
}

#[tokio::test]
async fn frame_is_refused_when_the_registry_becomes_unreadable_during_the_capacity_wait() {
    let sink = BlockableTransport::ready_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going =
        send_racing_a_revocation(&sink, &registry, MutableRevocations::make_unreadable).await;

    assert!(
        !keep_going,
        "an unreadable registry is not evidence the token is live"
    );
    assert!(
        sink.written().is_empty(),
        "a frame drained despite an unreadable registry"
    );
    assert!(sink.was_closed());
}

#[tokio::test]
async fn frame_drains_normally_while_the_credential_stays_live() {
    let sink = BlockableTransport::ready_blocked();
    let registry = Arc::new(MutableRevocations::default());

    // Same race, no revocation: the consult must not be a blanket refusal.
    let keep_going = send_racing_a_revocation(&sink, &registry, |_| {}).await;

    assert!(keep_going);
    assert_eq!(
        sink.written(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "a live credential's queued frame must still be delivered"
    );
    assert!(!sink.was_closed());
}

/// Revoking a SIBLING token must not disturb this session.
///
/// The consult is keyed by `jti`; a registry that refused on any populated
/// row would pass every test above for the wrong reason.
#[tokio::test]
async fn a_different_jti_revocation_does_not_close_this_session() {
    let sink = BlockableTransport::ready_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going = send_racing_a_revocation(&sink, &registry, |r| {
        r.revoke("ffffffffffffffffffffffffffffffff");
    })
    .await;

    assert!(keep_going);
    assert_eq!(sink.written().len(), 1);
}

// ─── the FLUSH phase ─────────────────────────────────────────────────────────
//
// The capacity wait above is the shorter of the two windows. A real
// `tokio-tungstenite` sink is almost always ready to ACCEPT a frame — it
// queues it in `start_send` and returns — and then parks in `poll_flush`
// until the peer reads. That flush is where a socket stalls for an unbounded
// interval, so it is where an operator's `token revoke` most often lands.
//
// The rows below therefore pin the harder shape: `poll_ready` READY,
// `start_send` accepting into `queued`, `poll_flush` blocked. Nothing may be
// reported as WRITTEN, and the transport must be dropped rather than closed
// gracefully — a graceful close flushes the queue on its way out, which is
// the delivery being refused.

/// Drives `send_binary` until the frame is queued in the sink and the flush
/// has parked, then revokes and releases.
async fn send_racing_a_revocation_at_flush(
    sink: &BlockableTransport,
    registry: &Arc<MutableRevocations>,
    revoke: impl FnOnce(&MutableRevocations),
) -> bool {
    let mut guarded = guarded(sink, registry);
    let mut send = Box::pin(guarded.send_binary(vec![1, 2, 3]));

    assert!(
        futures_util::poll!(send.as_mut()).is_pending(),
        "the flush must actually block, or this test proves nothing"
    );
    // The distinguishing precondition: the sink ACCEPTED the frame. A harness
    // that blocked `poll_ready` instead would fail this and be testing the
    // phase already covered above.
    assert_eq!(
        sink.queued(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "the frame must be QUEUED IN the sink — this row models the flush wait, \
         not the capacity wait"
    );
    assert!(
        sink.written().is_empty(),
        "queuing is not wire handover; nothing may be written yet"
    );

    revoke(registry);
    sink.unblock();
    send.await
}

/// A frame already sitting in the sink's queue must not reach the wire when
/// the credential is revoked mid-flush.
#[tokio::test]
async fn queued_frame_is_refused_when_revocation_lands_during_the_flush_wait() {
    let sink = BlockableTransport::flush_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going =
        send_racing_a_revocation_at_flush(&sink, &registry, |r| r.revoke(TEST_JTI)).await;

    assert!(!keep_going, "a revoked session must not continue");
    assert!(
        sink.written().is_empty(),
        "a frame queued in the sink drained to the client after its token was revoked"
    );
    assert!(
        !sink.was_closed(),
        "a graceful close flushes the queue — the transport must be DROPPED instead"
    );
}

#[tokio::test]
async fn queued_frame_is_refused_when_the_registry_becomes_unreadable_during_the_flush_wait() {
    let sink = BlockableTransport::flush_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going =
        send_racing_a_revocation_at_flush(&sink, &registry, MutableRevocations::make_unreadable)
            .await;

    assert!(
        !keep_going,
        "an unreadable registry is not evidence the token is live"
    );
    assert!(
        sink.written().is_empty(),
        "a queued frame drained despite an unreadable registry"
    );
    assert!(
        !sink.was_closed(),
        "the transport must be dropped, not closed"
    );
}

/// The flush-phase guard must not become a blanket refusal: a live credential's
/// queued frame still has to reach the wire once the peer resumes reading.
#[tokio::test]
async fn queued_frame_reaches_the_wire_when_the_flush_unblocks_and_the_token_is_live() {
    let sink = BlockableTransport::flush_blocked();
    let registry = Arc::new(MutableRevocations::default());

    let keep_going = send_racing_a_revocation_at_flush(&sink, &registry, |_| {}).await;

    assert!(keep_going);
    assert_eq!(
        sink.written(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "a live credential's queued frame must still be delivered"
    );
    assert!(sink.queued().is_empty());
    assert!(!sink.was_closed());
}

/// A peer that stops reading never wakes the sink, so the park alone cannot be
/// the only re-consult trigger — the bounded tick has to fire.
///
/// Here the flush stays blocked for the whole test and the sink is NEVER
/// woken: a guard that re-consults only on a sink wakeup would park forever,
/// which the timeout below turns into a failure.
#[tokio::test]
async fn a_silent_peer_still_gets_re_consulted_on_the_tick() {
    let sink = BlockableTransport::flush_blocked();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = guarded(&sink, &registry);
    let mut send = Box::pin(guarded.send_binary(vec![1, 2, 3]));

    assert!(futures_util::poll!(send.as_mut()).is_pending());
    assert_eq!(sink.queued().len(), 1);

    // The operator revokes. No socket event accompanies it: revocation is a
    // vault write, possibly from another process entirely.
    registry.revoke(TEST_JTI);

    let keep_going = tokio::time::timeout(FLUSH_RECONSULT_INTERVAL * 20, send)
        .await
        .expect("the guard must re-consult on its own tick, not wait on the peer");

    assert!(!keep_going);
    assert!(
        sink.written().is_empty(),
        "the frame reached a peer whose token had been revoked"
    );
}

// ─── the FIRST flush poll ────────────────────────────────────────────────────
//
// Every row above has the sink BLOCKED, so the guard always gets a park to
// re-consult at. That hid a hole: consulting only at a park means the check
// runs only when the peer is slow. A peer that IS reading makes the first
// `poll_flush` immediately ready, and a revocation landing in the instant
// between the pre-handover consult and that poll — `start_send` sits in that
// gap — was never seen at all. The fast peer got the frame.
//
// The rows below pin the unblocked sink and drop the revocation inside
// `start_send`, which is exactly that instant.

/// Drives one `send_binary` over an OPEN sink whose `start_send` revokes.
///
/// No park ever happens here — that is the point. The only opportunity to
/// refuse is a consult before the first flush poll. Returns the "keep going"
/// verdict and the transport, so callers can pin that the socket itself was
/// dropped.
async fn send_racing_a_revocation_at_the_first_flush_poll(
    sink: &BlockableTransport,
    registry: &Arc<MutableRevocations>,
    revoke: impl FnOnce(&MutableRevocations) + Send + 'static,
) -> (bool, GuardedTransport<BlockableTransport>) {
    let registry_for_hook = Arc::clone(registry);
    sink.on_start_send(move || revoke(&registry_for_hook));

    let mut guarded = guarded(sink, registry);
    let keep_going = guarded.send_binary(vec![1, 2, 3]).await;
    (keep_going, guarded)
}

/// Asserts the refusal withheld the frame and took the whole socket with it.
///
/// `queued` is checked against `written`, not emptied: the harness hands out
/// `Arc`-shared buffers so a test handle outlives the transport's own copy. A
/// real socket's buffer dies with it — what is provable here, and what actually
/// matters, is that the frame never crossed to `written` and that no live
/// transport remains that could ever move it there.
fn assert_refused_without_delivery(
    sink: &BlockableTransport,
    guarded: &GuardedTransport<BlockableTransport>,
) {
    assert!(
        sink.written().is_empty(),
        "a peer that was READING got the frame: the first flush poll ran with no consult \
         before it"
    );
    assert_eq!(
        sink.queued(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "the frame must have been accepted into the sink — otherwise this row is testing \
         the capacity wait, not the first flush poll"
    );
    assert!(
        guarded.socket.is_none(),
        "the transport must be dropped, so nothing can ever drain the pending frame"
    );
    assert!(
        !sink.was_closed(),
        "a graceful close flushes the queue — the transport must be DROPPED instead"
    );
}

/// A revocation landing between the handover consult and an immediately-ready
/// first flush must still withhold the frame.
#[tokio::test]
async fn queued_frame_is_refused_when_revocation_lands_before_the_first_flush_poll() {
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, guarded) =
        send_racing_a_revocation_at_the_first_flush_poll(&sink, &registry, |r| r.revoke(TEST_JTI))
            .await;

    assert!(!keep_going, "a revoked session must not continue");
    assert_refused_without_delivery(&sink, &guarded);
}

#[tokio::test]
async fn queued_frame_is_refused_when_the_registry_becomes_unreadable_before_the_first_flush_poll()
{
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, guarded) = send_racing_a_revocation_at_the_first_flush_poll(
        &sink,
        &registry,
        MutableRevocations::make_unreadable,
    )
    .await;

    assert!(
        !keep_going,
        "an unreadable registry is not evidence the token is live"
    );
    assert_refused_without_delivery(&sink, &guarded);
}

/// The pre-first-poll consult must not become a blanket refusal on the fast
/// path — the overwhelmingly common case is a live token and a ready sink.
#[tokio::test]
async fn an_immediately_ready_flush_still_delivers_while_the_credential_is_live() {
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, _guarded) =
        send_racing_a_revocation_at_the_first_flush_poll(&sink, &registry, |_| {}).await;

    assert!(keep_going);
    assert_eq!(
        sink.written(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "a live credential's frame must still be delivered without a park"
    );
    assert!(!sink.was_closed());
}

// ─── the READ-half flush side channel ────────────────────────────────────────
//
// Guarding the write half is not guarding the socket. The two halves share one
// transport and the READ half writes: on an inbound Ping, tungstenite queues
// the automatic pong and its `read` flushes the out-buffer — `write_out_buffer`
// drains everything there, application frames included — before returning the
// message. A peer that pings and resumes reading pulls a guarded frame out
// through a path the write-half guard never sees.
//
// No consult fixes this, because the flush happens INSIDE the read poll, after
// any flag a poller could check. The fix is that one task owns the unsplit
// socket, so a read cannot be polled while a frame is pending: `&mut self` is
// held by the send for that whole window. The row below is the finder's spec.

/// A peer that pings mid-flush and then resumes reading gets ZERO application
/// bytes once its credential is refused.
#[tokio::test]
async fn a_ping_cannot_drain_a_pending_frame_through_the_read_half() {
    let sink = BlockableTransport::flush_blocked();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = guarded(&sink, &registry);

    // Park an application flush: the frame is queued, off the wire.
    let mut send = Box::pin(guarded.send_binary(vec![1, 2, 3]));
    assert!(futures_util::poll!(send.as_mut()).is_pending());
    assert_eq!(
        sink.queued(),
        vec![WsMessage::Binary(vec![1, 2, 3].into())],
        "the frame must be pending in the transport for this row to mean anything"
    );

    // The peer pings, so the stream side now has an automatic response to
    // generate — the flush that would carry the pending frame out with it.
    sink.push_inbound(WsMessage::Ping(Vec::new().into()));

    // The credential is refused, and the peer becomes writable.
    registry.revoke(TEST_JTI);
    sink.unblock();

    let keep_going = tokio::time::timeout(FLUSH_RECONSULT_INTERVAL * 20, send)
        .await
        .expect("the guard must resolve on its own tick");

    assert!(!keep_going, "a revoked session must not continue");
    assert_eq!(
        sink.read_polls_while_pending(),
        0,
        "a read was polled while an application frame was pending — that poll is the side \
         channel, and in the real transport it flushes the frame out"
    );
    assert!(
        sink.written().is_empty(),
        "application bytes escaped through the read half's automatic-response flush"
    );
    assert!(
        !sink.was_closed(),
        "the refusal must drop the full transport, not close it gracefully"
    );

    // Full transport drop: the socket is gone, so no later poll of either half
    // can reach it. Dropping only the sink would leave a stream half alive over
    // the same connection with those bytes still in the shared out-buffer.
    assert!(
        guarded.socket.is_none(),
        "the whole transport must be dropped, not just the write half"
    );
    assert!(
        guarded.read_next().await.is_none(),
        "no further stream poll may reach the transport after the refusal"
    );
    assert!(
        sink.written().is_empty(),
        "a post-refusal read poll drained the pending frame"
    );
}

/// The read half must still work normally when nothing is pending — the guard
/// is a window, not a shutdown of inbound traffic.
#[tokio::test]
async fn reads_flow_normally_when_no_application_frame_is_pending() {
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = guarded(&sink, &registry);

    sink.push_inbound(WsMessage::Ping(Vec::new().into()));
    let got = guarded.read_next().await;
    assert!(matches!(got, Some(Ok(WsMessage::Ping(_)))));
    assert_eq!(sink.read_polls_while_pending(), 0);

    assert!(guarded.send_binary(vec![7]).await);
    assert_eq!(sink.written(), vec![WsMessage::Binary(vec![7].into())]);
}

/// A session with no revocable identity skips the registry entirely.
///
/// The bare trust root and the dev fallthrough carry no `jti`; they are
/// retired by rotating `auth_secret`, and an unreadable registry must not
/// take them down with it.
#[tokio::test]
async fn a_session_without_a_jti_is_unaffected_by_an_unreadable_registry() {
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());
    registry.make_unreadable();

    let mut guarded = GuardedTransport::new(
        sink.clone(),
        Arc::clone(&registry) as Arc<dyn crate::auth::RevokedTokenJtis + Send + Sync>,
        None,
        7,
    );

    assert!(guarded.send_binary(vec![9]).await);
    assert_eq!(sink.written(), vec![WsMessage::Binary(vec![9].into())]);
    assert!(!sink.was_closed());
}

#[test]
fn protocol_hello_validation_literals() {
    // Contract literals: FED-005 scoped lease keys reject old v2/v3 peers
    // before root `leases` payloads flow, while the current full-window
    // and selector-capable versions stay distinct for broadcast filtering.
    assert_eq!(
        validate_protocol_hello(&[3, 6]),
        Ok(protocol::LEGACY_FULL_WINDOW_PROTOCOL_VERSION)
    );
    assert_eq!(
        validate_protocol_hello(&[3, 7]),
        Ok(protocol::PROTOCOL_VERSION)
    );

    let cases: &[(&str, &[u8])] = &[
        ("v1_peer", &[3, 1]),
        ("old_full_window_v2_peer", &[3, 2]),
        ("old_selector_v3_peer", &[3, 3]),
        ("old_full_window_v4_peer", &[3, 4]),
        ("old_selector_v5_peer", &[3, 5]),
        ("future_version", &[3, 8]),
        ("zero_version", &[3, 0]),
        ("wrong_tag", &[2, 7]),
        ("empty", &[]),
        ("tag_only", &[3]),
        ("trailing_bytes", &[3, 7, 0]),
    ];
    for (case_name, frame) in cases {
        assert_eq!(
            validate_protocol_hello(frame),
            Err(4006),
            "case {case_name}: must close with VERSION_MISMATCH (4006)"
        );
    }
}
