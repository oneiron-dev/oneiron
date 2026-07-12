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

    let facet_allowed = entity_id(0xA1);
    let facet_denied = entity_id(0xB1);
    let claim_allowed = entity_id(0x11);
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

    let member = entity_id(0x42);
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
