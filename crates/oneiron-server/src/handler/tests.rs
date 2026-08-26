use super::*;
use crate::config::SyncServerConfig;
use core::assert_matches;
use loro::{ExportMode, LoroDoc, LoroValue, ValueOrContainer};
use rmpv::Value;
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

fn edge_map_key(src: oneiron::EntityId, kind: oneiron::EdgeKind, tgt: oneiron::EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}

fn insert_edge(
    doc: &LoroDoc,
    src: oneiron::EntityId,
    kind: oneiron::EdgeKind,
    tgt: oneiron::EntityId,
) {
    let key = edge_map_key(src, kind, tgt);
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

fn tombstone_bytes(request_byte: u8) -> [u8; oneiron::deletion::TOMBSTONE_VALUE_V2_LEN] {
    oneiron::deletion::TombstoneValueV2 {
        reason: oneiron::deletion::TombstoneReason::GdprDelete,
        deleted_at: 1_700_000_000,
        request_id: [request_byte; 16],
    }
    .encode()
}

/// Reads a binary value out of a doc's LIVE state (not a snapshot), which is
/// what "visible without a commit" has to mean for a relayed update.
fn window_map_bytes(doc: &LoroDoc, map: &str, key: &str) -> Option<Vec<u8>> {
    match doc.get_map(map).get(key) {
        Some(ValueOrContainer::Value(LoroValue::Binary(raw))) => Some(raw.to_vec()),
        _ => None,
    }
}

/// Takes every frame currently queued on a broadcast subscriber.
fn drain_broadcasts(
    rx: &mut tokio::sync::broadcast::Receiver<crate::server::BroadcastPayload>,
) -> Vec<(u32, Vec<u8>)> {
    let mut frames = Vec::new();
    while let Ok(frame) = rx.try_recv() {
        frames.push(frame);
    }
    frames
}

/// The WindowSync UPDATE frames a given connection fanned out for `key`.
fn update_fanout_for(frames: &[(u32, Vec<u8>)], conn_id: u32, key: &str) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter(|(sender, _)| *sender == conn_id)
        .filter_map(|(_, data)| {
            let (window_key, sub_tag, payload) = expect_window_sync(data);
            (window_key == key && sub_tag == window_sub_tags::UPDATE).then_some(payload)
        })
        .collect()
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

/// ONE-519: a relayed update goes live on `import_with` alone — no `commit()`.
///
/// Loro 1.13.9 semantics the UPDATE arm rests on: `import_with` finalizes any
/// open local transaction, applies the remote ops, advances document state AND
/// the oplog, and emits the change event under the supplied origin. `commit()`
/// is for LOCALLY authored pending ops, so there is deliberately none after the
/// import in `handle_window_sync` — adding one would only stamp a
/// server-authored transaction boundary onto bytes the server merely relays.
///
/// Every property the omission depends on is pinned here: live visibility for
/// entities, edges and tombstones; an oplog VV that advances by the Loro
/// partial order (never a byte compare of the encoded VV); exportability to a
/// peer that has never seen this doc; and the `conn:{id}` origin that Loro-level
/// echo suppression keys on, with no local op standing in for the relay.
#[tokio::test]
async fn imported_update_is_visible_exportable_and_vv_advanced_without_commit() {
    let (_dir, server) = test_server();
    let key = "2026-05";
    let conn_id = 7u32;
    let server_doc = server
        .get_or_create_window(&WindowKey::new(key))
        .await
        .unwrap();
    let server_peer = server_doc.peer_id();
    let vv_before = server_doc.oplog_vv();

    // Origin/trigger of every event the import emits, captured at the source
    // rather than inferred from the fan-out.
    let events: Arc<std::sync::Mutex<Vec<(String, loro::EventTriggerKind)>>> = Arc::default();
    let sink = Arc::clone(&events);
    let subscriber: loro::event::Subscriber = Arc::new(move |event| {
        sink.lock()
            .unwrap()
            .push((event.origin.to_string(), event.triggered_by));
    });
    let _sub = server_doc.subscribe_root(subscriber);

    // A remote peer authors and commits LOCALLY, then ships the bytes.
    let entity = entity_id(0x51);
    let target = entity_id(0x52);
    let deleted = entity_id(0x53);
    let tombstone = tombstone_bytes(0x54);
    let author = client_window_doc();
    insert_entity(&author, entity, 1, b"imported-body");
    insert_edge(&author, entity, oneiron::EdgeKind::Supports, target);
    author
        .get_map("tombstones")
        .insert(deleted.to_hex().as_str(), tombstone.as_slice())
        .unwrap();
    author.commit();
    let update = author.export(ExportMode::all_updates()).unwrap();
    let author_vv = author.oplog_vv();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    handle_window_sync(
        &server,
        conn_id,
        key,
        window_sub_tags::UPDATE,
        &update,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    // 1. Live state, with no commit anywhere on the server side.
    assert_eq!(
        window_map_bytes(&server_doc, "entities", entity.to_hex().as_str()).as_deref(),
        Some(entity_blob(1, b"imported-body").as_slice()),
        "an imported entity must be readable from live state without doc.commit()"
    );
    assert!(
        window_map_bytes(
            &server_doc,
            "edges",
            &edge_map_key(entity, oneiron::EdgeKind::Supports, target)
        )
        .is_some(),
        "an imported edge must be readable from live state without doc.commit()"
    );
    assert_eq!(
        window_map_bytes(&server_doc, "tombstones", deleted.to_hex().as_str()).as_deref(),
        Some(tombstone.as_slice()),
        "an imported tombstone must be readable from live state without doc.commit() — \
         delete propagation cannot depend on a server-authored boundary"
    );

    // 2. The oplog advanced, by Loro's partial order (NOT encoded-VV bytes).
    let vv_after = server_doc.oplog_vv();
    assert_eq!(
        vv_after.partial_cmp(&vv_before),
        Some(std::cmp::Ordering::Greater),
        "import_with must advance the oplog VV: {vv_after:?} vs {vv_before:?}"
    );
    assert!(
        vv_after.includes_vv(&author_vv),
        "the imported ops must be in the server oplog: {vv_after:?} does not include {author_vv:?}"
    );
    assert_eq!(
        vv_after.get(&server_peer),
        vv_before.get(&server_peer),
        "relaying must not author a server-side op — the update stays the remote peer's"
    );

    // 3. A peer that has never seen this doc reconstructs it from the export,
    //    so the imported ops are in the oplog and not merely in state.
    let fresh = LoroDoc::new();
    fresh
        .import(
            &server_doc
                .export(ExportMode::updates(&VersionVector::new()))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        fresh.get_deep_value(),
        server_doc.get_deep_value(),
        "a fresh peer must reconstruct the imported state with no intervening local commit"
    );

    // 4. Echo suppression keys on the connection origin, and nothing local
    //    stood in for the relayed ops.
    let events = events.lock().unwrap();
    assert!(
        events
            .iter()
            .any(|(origin, by)| origin == &format!("conn:{conn_id}") && by.is_import()),
        "the import must carry the conn:{conn_id} origin echo suppression keys on, got {events:?}"
    );
    assert!(
        events.iter().all(|(_, by)| !by.is_local()),
        "no locally authored server op may accompany a pure relay, got {events:?}"
    );

    assert!(
        direct_rx.try_recv().is_err(),
        "UPDATE answers over the broadcast fan-out, never with a direct reply"
    );
}

/// ONE-519: durability strictly precedes fan-out for an imported update.
///
/// ARCH-0023b Observer A duty: the server must never relay an update — a
/// tombstone above all — that a restart would drop. The success path asserts
/// the `u:w:` row and stale `svf:w:` flag are on disk with the fan-out frame
/// carrying the same bytes; the failure path corrupts the `m:u_seq:w:` counter
/// so the durable append fails AFTER `import_with` already ran, and asserts the
/// blast radius: typed `Persistence` error, no fan-out, and a window evicted so
/// the next read reloads durable state instead of serving the lost update.
#[tokio::test]
async fn imported_update_persists_before_broadcast() {
    let (_dir, server) = test_server();
    let durable_key = "2026-05";
    let failing_key = "2026-06";
    let conn_id = 7u32;

    let entity = entity_id(0x61);
    let author = client_window_doc();
    insert_entity(&author, entity, 1, b"relayed");
    author.commit();
    let update = author.export(ExportMode::all_updates()).unwrap();

    let (direct_tx, mut direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_state = test_legacy_conn_state();
    let mut broadcast_rx = server.broadcast_tx.subscribe();

    // ── Success path: persisted, then fanned out.
    handle_window_sync(
        &server,
        conn_id,
        durable_key,
        window_sub_tags::UPDATE,
        &update,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap();

    assert_eq!(
        server
            .vault
            .sync_state_get(&format!("u:w:{durable_key}:00000001"))
            .unwrap()
            .as_deref(),
        Some(update.as_slice()),
        "the relayed bytes must be durable at the ARCH-0023b u:w: key"
    );
    assert_eq!(
        server
            .vault
            .sync_state_get(&format!("svf:w:{durable_key}"))
            .unwrap(),
        Some(vec![0u8]),
        "the durable append must mark the window state vector stale"
    );

    let fanout = update_fanout_for(&drain_broadcasts(&mut broadcast_rx), conn_id, durable_key);
    assert_eq!(
        fanout,
        vec![update.clone()],
        "exactly one fan-out frame, carrying the imported bytes verbatim"
    );
    assert!(
        direct_rx.try_recv().is_err(),
        "UPDATE fans out over broadcast, never as a direct reply"
    );

    // ── Failure path: a corrupt u_seq row makes the durable append fail after
    //    the doc already imported (same shape as an out-of-space write).
    server
        .vault
        .sync_state_put(&format!("m:u_seq:w:{failing_key}"), &[1, 2, 3])
        .unwrap();
    let err = handle_window_sync(
        &server,
        conn_id,
        failing_key,
        window_sub_tags::UPDATE,
        &update,
        &direct_tx,
        &mut conn_state,
    )
    .await
    .unwrap_err();
    assert_matches!(err, ProtocolError::Persistence(_), "got {err:?}");

    assert!(
        update_fanout_for(&drain_broadcasts(&mut broadcast_rx), conn_id, failing_key).is_empty(),
        "an update the server cannot replay after a restart must never be fanned out"
    );
    assert!(
        server
            .vault
            .sync_state_get(&format!("u:w:{failing_key}:00000001"))
            .unwrap()
            .is_none(),
        "the failed append must leave no partial durable row"
    );

    // The window was evicted, so the next access reloads durable state — the
    // unpersisted import must be gone rather than served to a later VV_REQUEST.
    let reloaded = server
        .get_or_create_window(&WindowKey::new(failing_key))
        .await
        .unwrap();
    assert!(
        window_map_bytes(&reloaded, "entities", entity.to_hex().as_str()).is_none(),
        "a window whose update failed to persist must reload without it"
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
    let grant = oneiron::federation::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
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
    let claim_body = |predicate: &str| {
        let claim = oneiron::claim::ClaimBody::new(
            predicate,
            oneiron::claim::ClaimSubject::Entity(person),
            Value::from("value"),
            0.8,
            oneiron::claim::ClaimApprovalStatus::Proposed,
            oneiron::claim::ClaimLifecycleStatus::Active,
        );
        let body = Value::Map(vec![
            (Value::from("pred"), Value::from(claim.predicate.as_str())),
            (Value::from("val"), claim.value),
            (Value::from("conf"), Value::F32(claim.confidence)),
            (
                Value::from("subj"),
                Value::Binary(person.as_bytes().to_vec()),
            ),
            (Value::from("appr"), Value::from(claim.approval.as_str())),
            (Value::from("life"), Value::from(claim.lifecycle.as_str())),
        ]);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &body).unwrap();
        encoded
    };
    insert_entity(
        &server_doc,
        claim_allowed,
        oneiron::registry::ENTITY_TYPE_CLAIM,
        &claim_body("selector.test"),
    );
    insert_entity(
        &server_doc,
        claim_denied,
        oneiron::registry::ENTITY_TYPE_CLAIM,
        &claim_body("selector.denied"),
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
    let grant = oneiron::federation::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
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

/// Cap is per-connection: saturating one ConnState must not block a sibling connection.
#[tokio::test]
async fn window_cap_is_per_connection_second_conn_unaffected() {
    let config = SyncServerConfig {
        max_windows_per_connection: 1,
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = SyncServer::new(vault, config).unwrap();
    let (direct_tx, _direct_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut conn_a = test_legacy_conn_state();
    let mut conn_b = test_legacy_conn_state();
    let vv = VersionVector::new().encode();

    handle_window_sync(
        &server,
        1,
        "2026-03",
        window_sub_tags::VV_RESPONSE,
        &vv,
        &direct_tx,
        &mut conn_a,
    )
    .await
    .unwrap();

    let saturated = handle_window_sync(
        &server,
        1,
        "2026-04",
        window_sub_tags::VV_RESPONSE,
        &vv,
        &direct_tx,
        &mut conn_a,
    )
    .await;
    assert!(matches!(saturated, Err(ProtocolError::InvalidPayload(_))));

    // Sibling connection still admits its first distinct window.
    handle_window_sync(
        &server,
        2,
        "2026-05",
        window_sub_tags::VV_RESPONSE,
        &vv,
        &direct_tx,
        &mut conn_b,
    )
    .await
    .unwrap();
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
    let grant = oneiron::federation::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
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
    let grant = oneiron::federation::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
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
    let grant = oneiron::federation::FederationGrant::new(
        test_selector_scope(),
        member,
        oneiron::federation::FederationGrantRole::Viewer,
        oneiron::federation::FederationGrantPreset::ReadOnly,
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
/// - `start_send` normally queues the frame, but it CAN write — see below;
/// - `poll_flush` is where the peer's socket backpressure actually surfaces.
///
/// So `written` records what actually crossed the wire, from either path: a
/// frame sitting only in `queued` has crossed no wire and is still refusable.
/// `ready_blocked` and `flush_blocked` are set separately so a test can pin
/// exactly one phase and prove the guard covers it — a harness that blocks
/// only `poll_ready` models the wrong phase and would pass a flush-phase hole.
///
/// # `start_send` writes, and this double models it
///
/// Treating `start_send` as a pure queue is the assumption that produced the
/// hole this harness now covers. tungstenite writes from inside it in two
/// cases, both reproduced here because a double that only queues would let a
/// regression pass:
///
/// - the out-buffer passes `write_buffer_size` (128 KiB by default), so
///   `buffer_frame` writes it through — [`Self::write_through_over`];
/// - a pong is owed for a peer Ping, so `_write` reports "should flush" and
///   the application frame is flushed out alongside it —
///   [`Self::owed_control`].
///
/// Both land BETWEEN the pre-handover consult and the first flush poll, which
/// is why modelling them is what makes the rows below mean anything.
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
    /// Frame size at or above which `start_send` writes through, standing in
    /// for tungstenite's `write_buffer_size`. `None` = the buffer is never
    /// exceeded, which is what the production config now guarantees.
    write_through_over: Arc<std::sync::Mutex<Option<usize>>>,
    /// Control frames the codec owes the peer — an automatic pong for a Ping.
    ///
    /// Held apart from `queued` because the two are refusable on opposite
    /// terms: a pong carries no vault state and is owed by the protocol, while
    /// an application frame is exactly what a revocation must withhold. While
    /// this is non-empty `start_send` flushes eagerly, which is mechanism 2.
    owed_control: Arc<std::sync::Mutex<Vec<WsMessage>>>,
    /// Turns `flush_blocked` on the moment `start_send` accepts a frame.
    ///
    /// Models the peer that was reading when the send began — so the pre-drain
    /// completed — and stopped before the flush. See
    /// [`Self::flush_blocked_after_handover`].
    block_flush_at_handover: Arc<std::sync::atomic::AtomicBool>,
}

impl BlockableTransport {
    /// Blocks the capacity wait — the frame never reaches the sink at all.
    fn ready_blocked() -> Self {
        Self::new(true, false)
    }

    /// Blocks the flush wait, but only ONCE THE FRAME HAS BEEN HANDED OVER.
    ///
    /// The peer is still reading when the send begins, so the pre-drain
    /// completes and `start_send` queues; the peer then stops reading and the
    /// flush parks. That ordering is what the flush-wait rows are about, and it
    /// has to be stated explicitly now that `send_binary` drains to completion
    /// BEFORE handing over: a sink blocked from the very start parks in the
    /// drain instead, with nothing queued and nothing to withhold. Both are
    /// real; this is the one where a frame is at risk.
    fn flush_blocked_after_handover() -> Self {
        let this = Self::new(false, false);
        this.block_flush_at_handover
            .store(true, std::sync::atomic::Ordering::SeqCst);
        this
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
            write_through_over: Arc::default(),
            owed_control: Arc::default(),
            block_flush_at_handover: Arc::default(),
        }
    }

    /// Models tungstenite's `write_buffer_size`: a frame of `bytes` or more
    /// is written straight to the wire inside `start_send`.
    fn with_write_through_over(self, bytes: usize) -> Self {
        *self.write_through_over.lock().unwrap() = Some(bytes);
        self
    }

    /// The library's default write-through threshold — what the codec uses
    /// when the upgrade handler does not raise it. Named so the rows below can
    /// state which regime they are in.
    const DEFAULT_WRITE_BUFFER: usize = 128 * 1024;

    /// A double configured the way `ws_upgrade_handler` configures the real
    /// socket.
    ///
    /// The disarm for the buffer-exceeded write-through is a CONFIG value, not
    /// a branch in `GuardedTransport`, so a row that hard-codes a threshold
    /// tests a socket this server never builds. Reading the production
    /// constant is what makes the mutation probe bite: restore the library
    /// default and the frame below is written through inside `start_send`.
    fn as_configured_by_the_upgrade_handler() -> Self {
        Self::open().with_write_through_over(WS_WRITE_BUFFER_SIZE)
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
        // An explicit flush emits the owed control frames FIRST — they were
        // queued before the application frame — and that is precisely how the
        // pre-drain disarms mechanism 2: afterwards nothing is left to force a
        // write inside the next `start_send`.
        let owed = std::mem::take(&mut *self.owed_control.lock().unwrap());
        let drained = std::mem::take(&mut *self.queued.lock().unwrap());
        let mut written = self.written.lock().unwrap();
        written.extend(owed);
        written.extend(drained);
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

    /// Queues — and WRITES, exactly where the real codec does.
    ///
    /// Modelling only the queue is what let the previous leg's guard look
    /// sound: both branches below put application bytes on the wire between
    /// the pre-handover consult and the first flush poll, so a double that
    /// omitted them would score a hole as a pass.
    fn start_send(self: std::pin::Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
        let item_len = match &item {
            WsMessage::Binary(data) => data.len(),
            _ => 0,
        };
        self.queued.lock().unwrap().push(item);
        if self
            .block_flush_at_handover
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.flush_blocked
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        // The revocation window this leg closes: the pre-handover consult has
        // passed, the frame is now IN the sink, and no flush poll has run yet.
        if let Some(hook) = self.on_start_send.lock().unwrap().take() {
            hook();
        }
        // Mechanism 1 — the out-buffer is exceeded, so `buffer_frame` writes it
        // through. Independent of `flush_blocked`: this is a synchronous write
        // from inside `start_send`, not the flush the peer's backpressure gates.
        let exceeds_buffer = self
            .write_through_over
            .lock()
            .unwrap()
            .is_some_and(|limit| item_len >= limit);
        // Mechanism 2 — a pong is owed, so `_write` emits it and reports
        // "should flush"; the application frame goes out alongside it.
        let owed = std::mem::take(&mut *self.owed_control.lock().unwrap());
        let pong_forces_flush = !owed.is_empty();
        if exceeds_buffer || pong_forces_flush {
            let drained = std::mem::take(&mut *self.queued.lock().unwrap());
            let mut written = self.written.lock().unwrap();
            written.extend(owed);
            written.extend(drained);
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
            // The pong is now OWED, not yet sent: tungstenite queues it here
            // and the next write emits it — dragging any application frame
            // handed over in the meantime out with it. That is mechanism 2,
            // and it survives until something flushes.
            self.owed_control
                .lock()
                .unwrap()
                .push(WsMessage::Pong(Vec::new().into()));
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
    let sink = BlockableTransport::flush_blocked_after_handover();
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
    let sink = BlockableTransport::flush_blocked_after_handover();
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
    let sink = BlockableTransport::flush_blocked_after_handover();
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
    let sink = BlockableTransport::flush_blocked_after_handover();
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

// ─── `start_send` WRITES ─────────────────────────────────────────────────────
//
// Every row above was scored by a double that only queued in `start_send`,
// which encoded the assumption the guard rested on. The real codec writes from
// inside `start_send` in two cases, and each puts application bytes on the wire
// AFTER the pre-handover consult and BEFORE the first flush poll — the one
// stretch no consult covers, because there is no await in it to consult at.
//
// Consulting harder cannot close either: the write is synchronous and already
// done by the time control returns. Both are therefore disarmed at the source —
// the buffer threshold is put out of reach, and owed control frames are drained
// while nothing application-level is pending. The rows below are the finder's
// spec, and each fails if its disarm is removed.

/// A frame larger than the write buffer must not reach the wire inside
/// `start_send`.
///
/// The sink is OPEN and the revocation lands in `start_send` — after the
/// handover consult, before any flush. With the library's 128-KiB default this
/// frame would be written through on the spot; the production config raises the
/// threshold past `max_frame_size`, so nothing is written until the guarded
/// flush, which consults first.
#[tokio::test]
async fn a_frame_larger_than_the_write_buffer_is_refused_inside_start_send() {
    let sink = BlockableTransport::as_configured_by_the_upgrade_handler();
    let registry = Arc::new(MutableRevocations::default());
    let registry_for_hook = Arc::clone(&registry);
    sink.on_start_send(move || registry_for_hook.revoke(TEST_JTI));

    // Comfortably over the LIBRARY default, so a default-configured socket
    // writes this through inside `start_send` — and this one must not.
    let oversized = vec![4u8; 2 * BlockableTransport::DEFAULT_WRITE_BUFFER];
    let mut guarded = guarded(&sink, &registry);
    let keep_going = guarded.send_binary(oversized).await;

    assert!(!keep_going, "a revoked session must not continue");
    assert!(
        sink.written().is_empty(),
        "a frame over the write buffer was written to the wire from inside start_send, \
         before any flush-time consult could refuse it"
    );
    assert!(
        guarded.socket.is_none(),
        "the refusal must drop the full transport"
    );
    assert!(
        !sink.was_closed(),
        "a graceful close flushes the queue — the transport must be DROPPED instead"
    );
}

/// A pong owed to the peer must not drag an application frame out with it.
///
/// The peer pings first, so the codec owes an automatic pong; that pending
/// control frame is what makes the next `start_send` flush eagerly, however
/// small the application frame is. The pre-drain empties it while nothing
/// application-level is queued, so the eager flush has nothing left to trigger
/// on and the revocation is still honoured.
#[tokio::test]
async fn a_pong_owed_to_the_peer_cannot_drag_a_small_frame_out_inside_start_send() {
    let sink = BlockableTransport::open();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = guarded(&sink, &registry);

    // Read the Ping FIRST: this is what leaves a pong owed. Nothing is pending
    // at this point, so the read is legitimate.
    sink.push_inbound(WsMessage::Ping(Vec::new().into()));
    assert!(matches!(
        guarded.read_next().await,
        Some(Ok(WsMessage::Ping(_)))
    ));

    // The revocation lands in the same instant as before — inside `start_send`,
    // with a pong still owed.
    let registry_for_hook = Arc::clone(&registry);
    sink.on_start_send(move || registry_for_hook.revoke(TEST_JTI));

    let keep_going = guarded.send_binary(vec![1, 2, 3]).await;

    assert!(!keep_going, "a revoked session must not continue");
    assert_eq!(
        sink.written(),
        vec![WsMessage::Pong(Vec::new().into())],
        "the only bytes owed here are the automatic pong: an application frame rode the \
         pong-triggered eager flush out of start_send"
    );
    assert!(
        guarded.socket.is_none(),
        "the refusal must drop the full transport"
    );
    assert!(!sink.was_closed());
}

/// Neither disarm may become a blanket refusal: an oversized frame and a
/// pong-owing socket must both still deliver while the credential is live.
#[tokio::test]
async fn oversized_and_pong_owing_sends_still_deliver_while_the_credential_is_live() {
    let sink = BlockableTransport::as_configured_by_the_upgrade_handler();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = guarded(&sink, &registry);

    let big = vec![4u8; 2 * BlockableTransport::DEFAULT_WRITE_BUFFER];
    assert!(guarded.send_binary(big.clone()).await);
    assert_eq!(
        sink.written(),
        vec![WsMessage::Binary(big.into())],
        "a live credential's oversized frame must still be delivered"
    );

    sink.push_inbound(WsMessage::Ping(Vec::new().into()));
    assert!(matches!(
        guarded.read_next().await,
        Some(Ok(WsMessage::Ping(_)))
    ));
    assert!(guarded.send_binary(vec![1, 2, 3]).await);
    assert_eq!(
        sink.written().last(),
        Some(&WsMessage::Binary(vec![1, 2, 3].into())),
        "a live credential's frame must still be delivered on a pong-owing socket"
    );
    assert!(!sink.was_closed());
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
    let sink = BlockableTransport::flush_blocked_after_handover();
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
    assert_eq!(
        sink.written(),
        vec![
            // The pong owed for the Ping above, emitted by the pre-drain.
            WsMessage::Pong(Vec::new().into()),
            WsMessage::Binary(vec![7].into()),
        ],
        "a live credential's frame must be delivered, after the owed pong"
    );
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

// ─── the REAL codec ──────────────────────────────────────────────────────────
//
// Every row above is scored by `BlockableTransport`, which is a MODEL of
// tungstenite and drifts from it in ways that matter here:
//
// - its write-through test is `payload >= threshold`, while the codec's is
//   `encoded_frame + whatever is already in the out-buffer > write_buffer_size`
//   — a header and an owed pong the double never counts;
// - its `written()` is message-level, so "no application bytes reached the
//   wire" is asserted about enum values rather than bytes. A partial write of
//   a binary frame would be invisible to it;
// - it is OUR code, so a tungstenite upgrade that changes when `start_send`
//   writes moves the real behaviour and leaves every row green.
//
// The rows below therefore run the same properties against the real
// `tokio-tungstenite` codec PRODUCTION resolves — reached through the
// `production-ws-codec` dev-dependency alias, whose version must track axum's
// (0.28), not the older copy the `oneiron` crate pulls in — over a socket that
// captures raw bytes, with the write-through threshold lowered to a value a
// test frame can actually cross. The double stays for the phase-model rows it
// is good at; the byte properties are pinned here.

/// `write_buffer_size` for the real-codec rows, low enough that a test frame
/// crosses it.
///
/// Production sets [`WS_WRITE_BUFFER_SIZE`] out of reach, which is exactly why
/// it cannot be exercised: no admissible frame gets near `usize::MAX`. Lowering
/// it here is the mutation the P1 finding described — and the guard must hold
/// anyway, by refusing rather than by the threshold being unreachable.
const REAL_CODEC_WRITE_BUFFER: usize = 4096;

/// A payload the guard must REFUSE at this threshold: encoded plus the
/// control-frame reserve is over it, and the codec would write it through from
/// inside `start_send`.
const OVER_THRESHOLD_PAYLOAD: usize = REAL_CODEC_WRITE_BUFFER;

/// A payload that fits with room to spare, so the refusal is not blanket.
const UNDER_THRESHOLD_PAYLOAD: usize = 8;

/// A raw masked Ping from a client, on the wire exactly as RFC 6455 has it:
/// FIN + opcode 0x9, the mask bit set with a zero-length payload, then the
/// 4-byte masking key. A server codec rejects an UNMASKED client frame, so
/// this has to be the real thing for the pong to ever be owed — a fixture the
/// double never needed, and a dependency contract it therefore never checked.
const CLIENT_PING_FRAME: [u8; 6] = [0x89, 0x80, 0x01, 0x02, 0x03, 0x04];

/// The server's automatic Pong, unmasked (servers never mask): opcode 0xA,
/// FIN, zero-length payload.
const SERVER_PONG_BYTES: [u8; 2] = [0x8a, 0x00];

/// A socket under the real codec that records every byte written to it.
///
/// `written` is the wire. Nothing else in these rows is: the codec's own
/// out-buffer, the sink's queue and the message enums are all in-process state
/// this leg exists to keep revocable. Only bytes that arrive HERE have escaped.
///
/// `write_blocked` models the peer that stopped reading — a `Pending` write,
/// which is what makes the one-shot pre-drain return `Pending` and leaves the
/// pong owed.
#[derive(Clone, Default)]
struct CapturingSocket {
    written: Arc<std::sync::Mutex<Vec<u8>>>,
    inbound: Arc<std::sync::Mutex<std::collections::VecDeque<u8>>>,
    write_blocked: Arc<std::sync::atomic::AtomicBool>,
    /// Woken when a block is lifted, so a parked poll retries.
    waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    /// Fires once, right after the codec's FIRST write reaches the wire.
    ///
    /// That write is the pre-drain emitting the owed pong, so a hook here
    /// lands in the stretch between the pre-drain and the pre-first-flush
    /// consult — where `start_send` sits, and where the finding says a
    /// revocation has no gate.
    #[expect(clippy::type_complexity)]
    after_first_write: Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>,
    /// Fires once, the first time a write PARKS on a blocked socket.
    ///
    /// This is the instant the drain-to-empty finding turns on. A one-shot
    /// pre-drain that sees `Pending` here proceeds to `start_send` anyway — and
    /// if the socket has become writable in the meantime (which a peer reading,
    /// or the kernel draining its send buffer, does without any cooperation
    /// from this task), `start_send` writes the out-buffer through, application
    /// frame included, before any consult. A hook here models exactly that
    /// external event, with no `await` needed on this side.
    #[expect(clippy::type_complexity)]
    on_write_park: Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>,
}

impl CapturingSocket {
    fn push_inbound(&self, bytes: &[u8]) {
        self.inbound.lock().unwrap().extend(bytes.iter().copied());
        self.wake();
    }

    fn after_first_write(&self, f: impl FnOnce() + Send + 'static) {
        *self.after_first_write.lock().unwrap() = Some(Box::new(f));
    }

    fn on_write_park(&self, f: impl FnOnce() + Send + 'static) {
        *self.on_write_park.lock().unwrap() = Some(Box::new(f));
    }

    fn block_writes(&self) {
        self.write_blocked
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn unblock_writes(&self) {
        self.write_blocked
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.wake();
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    /// Every byte the server has put on the wire, in order.
    fn wire(&self) -> Vec<u8> {
        self.written.lock().unwrap().clone()
    }
}

impl tokio::io::AsyncWrite for CapturingSocket {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_blocked.load(std::sync::atomic::Ordering::SeqCst) {
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            // The park is reported to the caller FIRST, then the socket turns
            // writable — the ordering a kernel produces on its own. A one-shot
            // drain has already decided to proceed by the time this lands.
            let hook = self.on_write_park.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            return Poll::Pending;
        }
        self.written.lock().unwrap().extend_from_slice(buf);
        if let Some(hook) = self.after_first_write.lock().unwrap().take() {
            hook();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_blocked.load(std::sync::atomic::Ordering::SeqCst) {
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncRead for CapturingSocket {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut inbound = self.inbound.lock().unwrap();
        if inbound.is_empty() {
            // Never EOF: an EOF would end the stream and let the codec take
            // paths a live peer never triggers.
            *self.waker.lock().unwrap() = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(inbound.len());
        for byte in inbound.drain(..n) {
            buf.put_slice(&[byte]);
        }
        Poll::Ready(Ok(()))
    }
}

/// Bridges axum's `Message` to tungstenite's over a real `WebSocketStream`.
///
/// [`GuardedTransport`] speaks axum's message type because that is what the
/// production socket is; the real codec speaks tungstenite's. axum's own
/// `WebSocket` is this same 1:1 passthrough — `poll_ready`, `start_send`,
/// `poll_flush` and `poll_close` each delegate straight through, converting
/// only the enum — so wrapping here reproduces the production stack rather
/// than substituting for it. The conversion is a move: both sides carry
/// `bytes::Bytes`.
struct TungsteniteBridge(production_ws_codec::WebSocketStream<CapturingSocket>);

impl TungsteniteBridge {
    fn to_tungstenite(msg: WsMessage) -> production_ws_codec::tungstenite::Message {
        use production_ws_codec::tungstenite::Message as TsMessage;
        use production_ws_codec::tungstenite::protocol::CloseFrame as TsCloseFrame;
        match msg {
            WsMessage::Text(text) => TsMessage::Text(text.as_str().into()),
            WsMessage::Binary(data) => TsMessage::Binary(data),
            WsMessage::Ping(data) => TsMessage::Ping(data),
            WsMessage::Pong(data) => TsMessage::Pong(data),
            WsMessage::Close(frame) => TsMessage::Close(frame.map(|frame| TsCloseFrame {
                code: frame.code.into(),
                reason: frame.reason.as_str().into(),
            })),
        }
    }

    fn from_tungstenite(msg: production_ws_codec::tungstenite::Message) -> Option<WsMessage> {
        use production_ws_codec::tungstenite::Message as TsMessage;
        match msg {
            TsMessage::Text(text) => Some(WsMessage::Text(Utf8Bytes::from(text.as_str()))),
            TsMessage::Binary(data) => Some(WsMessage::Binary(data)),
            TsMessage::Ping(data) => Some(WsMessage::Ping(data)),
            TsMessage::Pong(data) => Some(WsMessage::Pong(data)),
            TsMessage::Close(frame) => Some(WsMessage::Close(frame.map(|frame| CloseFrame {
                code: frame.code.into(),
                reason: Utf8Bytes::from(frame.reason.as_str()),
            }))),
            // Raw frames never surface from a decoded read.
            TsMessage::Frame(_) => None,
        }
    }
}

impl futures_util::Sink<WsMessage> for TungsteniteBridge {
    type Error = production_ws_codec::tungstenite::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_ready(cx)
    }

    fn start_send(mut self: std::pin::Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
        std::pin::Pin::new(&mut self.0).start_send(Self::to_tungstenite(item))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_close(cx)
    }
}

impl futures_util::Stream for TungsteniteBridge {
    type Item = Result<WsMessage, production_ws_codec::tungstenite::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            return match std::task::ready!(self.0.poll_next_unpin(cx)) {
                Some(Ok(msg)) => match Self::from_tungstenite(msg) {
                    Some(msg) => Poll::Ready(Some(Ok(msg))),
                    None => continue,
                },
                Some(Err(err)) => Poll::Ready(Some(Err(err))),
                None => Poll::Ready(None),
            };
        }
    }
}

/// A real `tokio-tungstenite` server socket over a byte-capturing transport,
/// wrapped in the production guard.
///
/// `write_buffer_size` and the guard's threshold are set from the SAME value:
/// that pairing is the invariant P1 is about, and a test that let them drift
/// would be proving something about a socket this server never builds.
async fn real_codec_guarded(
    socket: &CapturingSocket,
    registry: &Arc<MutableRevocations>,
    write_buffer_size: usize,
) -> GuardedTransport<TungsteniteBridge> {
    let config = production_ws_codec::tungstenite::protocol::WebSocketConfig::default()
        .write_buffer_size(write_buffer_size);
    let stream = production_ws_codec::WebSocketStream::from_raw_socket(
        socket.clone(),
        production_ws_codec::tungstenite::protocol::Role::Server,
        Some(config),
    )
    .await;
    GuardedTransport::with_write_through_threshold(
        TungsteniteBridge(stream),
        Arc::clone(registry) as Arc<dyn crate::auth::RevokedTokenJtis + Send + Sync>,
        Some(TEST_JTI.to_owned()),
        7,
        write_buffer_size,
    )
}

/// A server Close frame with no payload: opcode 0x8, FIN, zero length.
///
/// A refusal that is caught while nothing is queued closes GRACEFULLY, and a
/// graceful close is two bytes of control frame — never application data.
const SERVER_CLOSE_BYTES: [u8; 2] = [0x88, 0x00];

/// Asserts the wire holds the automatic Pong, optionally a Close, and no
/// application byte.
///
/// Byte-level and order-bearing on purpose: message-level `written()` cannot
/// see a PARTIAL application frame, and a partial frame is precisely what a
/// write that parked mid-way would leave.
///
/// The Close is admitted because the drain-to-empty ordering moves WHERE a
/// revocation is caught. Draining to completion means the fresh consult that
/// follows it runs while nothing application-level is queued, so a revocation
/// landing during the drain takes the graceful-close path rather than the
/// abort path. That is the better outcome — the peer learns the session ended
/// instead of seeing a severed socket — and it is still a refusal: a close
/// frame carries no vault state, and `poll_close` can only flush an out-buffer
/// the drain already emptied. What must never appear is a payload byte.
fn assert_wire_is_pong_only(socket: &CapturingSocket) {
    let wire = socket.wire();
    let acceptable: &[&[u8]] = &[
        &SERVER_PONG_BYTES,
        &[SERVER_PONG_BYTES.as_slice(), SERVER_CLOSE_BYTES.as_slice()].concat(),
    ];
    assert!(
        acceptable.iter().any(|expected| wire == *expected),
        "the wire must hold the automatic Pong (and at most a Close) and NOTHING else — \
         extra bytes are application-frame bytes (whole or partial) that escaped before \
         the consult: {wire:?}"
    );
}

/// Asserts not one byte reached the wire.
fn assert_wire_is_empty(socket: &CapturingSocket) {
    assert!(
        socket.wire().is_empty(),
        "bytes reached the wire before any consult could refuse them: {:?}",
        socket.wire()
    );
}

/// Feeds a real masked client Ping and decodes it, leaving a Pong OWED.
///
/// The codec's `read` returns as soon as it has a message, having only
/// `set_additional(pong)` — so `additional_send` is non-empty and no byte has
/// been written. That is the state the P2 finding is about: the double could
/// not reach it, because its `poll_next` moves queued frames straight to the
/// wire.
async fn owe_a_pong(socket: &CapturingSocket, guarded: &mut GuardedTransport<TungsteniteBridge>) {
    socket.push_inbound(&CLIENT_PING_FRAME);
    assert!(
        matches!(guarded.read_next().await, Some(Ok(WsMessage::Ping(_)))),
        "the real codec must decode the masked client Ping — otherwise no pong is owed \
         and this row is not testing the pong path at all"
    );
    assert_wire_is_empty(socket);
}

/// Drives the real codec into the exact state the P2 finding names: a pong
/// owed, the application frame handed over, and the registry flipped between
/// the pre-drain and the pre-first-flush consult.
///
/// The sequencing matters and is not incidental:
///
/// 1. the peer's masked Ping is read, so `additional_send` holds a Pong;
/// 2. `send_binary` runs. Its capacity-wait consult sees a live credential;
/// 3. the pre-drain flushes the owed Pong — the FIRST write to reach the wire,
///    which is where the hook fires and the registry flips;
/// 4. `start_send` then buffers the application frame, and the consult before
///    the first flush poll is the only thing between the peer and its bytes.
///
/// Step 3 is what the double models as a message-level `written` entry; here it
/// is real bytes in real order, so a partial application write would be visible.
async fn real_codec_send_racing_a_revocation(
    socket: &CapturingSocket,
    registry: &Arc<MutableRevocations>,
    payload_len: usize,
    revoke: impl FnOnce(&MutableRevocations) + Send + 'static,
) -> (bool, GuardedTransport<TungsteniteBridge>) {
    let mut guarded = real_codec_guarded(socket, registry, REAL_CODEC_WRITE_BUFFER).await;
    owe_a_pong(socket, &mut guarded).await;

    let registry_for_hook = Arc::clone(registry);
    socket.after_first_write(move || revoke(&registry_for_hook));

    let keep_going = guarded.send_binary(vec![7u8; payload_len]).await;
    (keep_going, guarded)
}

/// Asserts a refused transport can never deliver application bytes again.
///
/// Stated as behaviour rather than as `socket.is_none()`, because the refusal
/// has TWO shapes and both are final. A revocation seen while a frame is
/// queued must ABORT (dropping the socket is the only way to withhold bytes
/// already handed over), but one seen while nothing is queued — which the
/// drain-to-empty ordering makes the common case — closes gracefully, leaving
/// the socket `Some` and the codec in a state that refuses further writes.
/// Asserting on the field would pin the mechanism and miss the property.
async fn assert_refusal_is_final(
    socket: &CapturingSocket,
    guarded: &mut GuardedTransport<TungsteniteBridge>,
) {
    let before = socket.wire().len();
    assert!(
        !guarded
            .send_binary(vec![9u8; UNDER_THRESHOLD_PAYLOAD])
            .await,
        "a refused transport must not accept a later send"
    );
    let after = socket.wire();
    assert!(
        !after[before..].contains(&9u8),
        "a refused transport delivered application bytes on a later send: {:?}",
        &after[before..]
    );
}

/// REAL CODEC: a revocation between the two consults must leave the wire
/// holding only the Pong.
///
/// This is the byte-level statement the double cannot make. `written()` there
/// is a list of message enums; here it is the actual octets, so a partially
/// written binary frame — which is what a write that parked mid-payload
/// leaves — would show up as trailing bytes past the 2-byte Pong.
#[tokio::test]
async fn real_codec_withholds_every_application_byte_when_the_credential_is_revoked() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, mut guarded) =
        real_codec_send_racing_a_revocation(&socket, &registry, UNDER_THRESHOLD_PAYLOAD, |r| {
            r.revoke(TEST_JTI);
        })
        .await;

    assert!(!keep_going, "a revoked session must not continue");
    assert_wire_is_pong_only(&socket);
    assert_refusal_is_final(&socket, &mut guarded).await;
}

/// REAL CODEC: an unreadable registry is refused on the same terms.
#[tokio::test]
async fn real_codec_withholds_every_application_byte_when_the_registry_is_unreadable() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, mut guarded) = real_codec_send_racing_a_revocation(
        &socket,
        &registry,
        UNDER_THRESHOLD_PAYLOAD,
        MutableRevocations::make_unreadable,
    )
    .await;

    assert!(
        !keep_going,
        "an unreadable registry is not evidence the token is live"
    );
    assert_wire_is_pong_only(&socket);
    assert_refusal_is_final(&socket, &mut guarded).await;
}

/// REAL CODEC: the guard must not be a blanket refusal — a live credential's
/// frame reaches the wire, after the pong, in that order.
#[tokio::test]
async fn real_codec_delivers_after_the_pong_while_the_credential_is_live() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());

    let (keep_going, _guarded) =
        real_codec_send_racing_a_revocation(&socket, &registry, UNDER_THRESHOLD_PAYLOAD, |_| {})
            .await;

    assert!(keep_going);
    let wire = socket.wire();
    let mut expected = SERVER_PONG_BYTES.to_vec();
    // Binary, FIN, unmasked, 8-byte payload — the server's own encoding.
    expected.push(0x82);
    expected.push(UNDER_THRESHOLD_PAYLOAD as u8);
    expected.extend(std::iter::repeat_n(7u8, UNDER_THRESHOLD_PAYLOAD));
    assert_eq!(
        wire, expected,
        "a live credential's frame must be delivered, and the owed Pong must precede it"
    );
}

/// REAL CODEC, the P1 property: a frame that would cross the write-through
/// threshold is REFUSED, not written.
///
/// The threshold is lowered to a value a test frame can cross — the exact
/// mutation the finding describes. Under the old `debug_assert` this frame
/// would be handed to `buffer_frame`, push the out-buffer past
/// `write_buffer_size`, and be written to the socket synchronously inside
/// `start_send`, before any consult. The wire assertion is the proof: not one
/// byte, not even a partial frame.
///
/// The credential is LIVE throughout. That is the sharp form of the property:
/// the refusal is not a revocation firing early, it is the transport declining
/// to hold bytes it could not withhold.
#[tokio::test]
async fn real_codec_refuses_a_frame_that_would_reach_the_write_through_threshold() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    let keep_going = guarded.send_binary(vec![7u8; OVER_THRESHOLD_PAYLOAD]).await;

    assert!(
        !keep_going,
        "a frame that cannot be held below the write-through threshold must end the \
         connection, not be queued"
    );
    assert_wire_is_empty(&socket);
    assert!(
        guarded.socket.is_none(),
        "the refusal is fail-closed: the transport is aborted, so no later poll can \
         drain anything"
    );
}

/// REAL CODEC: the same oversized frame, with a revoked credential and an
/// unreadable registry — still zero application bytes.
///
/// The finding's regression asks for the revoked and unreadable rows over a
/// lowered threshold specifically, because the pre-leg failure mode was a
/// consult that ran AFTER the bytes were already gone. A revocation that lands
/// while the frame is over the threshold must not be able to observe a wire
/// that already has it.
#[tokio::test]
async fn real_codec_refuses_an_over_threshold_frame_on_a_revoked_credential() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    registry.revoke(TEST_JTI);
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    assert!(!guarded.send_binary(vec![7u8; OVER_THRESHOLD_PAYLOAD]).await);
    assert_wire_is_empty(&socket);
    assert!(guarded.socket.is_none());
}

#[tokio::test]
async fn real_codec_refuses_an_over_threshold_frame_on_an_unreadable_registry() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    registry.make_unreadable();
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    assert!(!guarded.send_binary(vec![7u8; OVER_THRESHOLD_PAYLOAD]).await);
    assert_wire_is_empty(&socket);
    assert!(guarded.socket.is_none());
}

/// REAL CODEC: the refusal must be a THRESHOLD, not a size phobia — a frame
/// that fits below it is delivered whole and byte-exact.
///
/// Without this row the P1 fix could be "refuse everything" and every
/// withholding assertion above would still pass.
#[tokio::test]
async fn real_codec_delivers_a_frame_that_stays_below_the_write_through_threshold() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    // The largest payload the guard admits at this threshold: the ENCODED
    // frame exactly equals it, with no reserve subtracted. The drain leaves the
    // out-buffer empty, so this boundary is the codec's own arithmetic rather
    // than a guess with slack in it — one more byte is refused.
    let admissible = REAL_CODEC_WRITE_BUFFER - 4;
    assert!(guarded.send_binary(vec![7u8; admissible]).await);

    let wire = socket.wire();
    // Binary, FIN, unmasked, 16-bit extended length.
    let mut expected = vec![0x82, 126];
    expected.extend_from_slice(&(admissible as u16).to_be_bytes());
    expected.extend(std::iter::repeat_n(7u8, admissible));
    assert_eq!(
        wire, expected,
        "a frame below the threshold must be delivered whole, header and payload"
    );

    assert!(
        !guarded.send_binary(vec![7u8; admissible + 1]).await,
        "one byte past the admissible size must be refused — the boundary is exact"
    );
    assert_eq!(
        socket.wire(),
        expected,
        "the refused frame added bytes to the wire"
    );
}

/// The codec's write-through arithmetic, restated and pinned.
///
/// [`encoded_frame_len`] is the guard's model of `Frame::len` for a server's
/// unmasked binary frame. If tungstenite changes its header encoding, the
/// guard's threshold arithmetic silently under-counts and frames slip through
/// — so the model is checked against boundaries the RFC fixes rather than
/// against the library's private types.
#[test]
fn encoded_frame_len_matches_the_rfc_header_boundaries() {
    // 7-bit length: 2-byte header, no extension.
    assert_eq!(encoded_frame_len(0), 2);
    assert_eq!(encoded_frame_len(125), 127);
    // 16-bit extension kicks in at 126.
    assert_eq!(encoded_frame_len(126), 126 + 4);
    assert_eq!(encoded_frame_len(65_535), 65_535 + 4);
    // 64-bit extension at 65_536.
    assert_eq!(encoded_frame_len(65_536), 65_536 + 10);
    // Saturating rather than wrapping: an absurd length stays absurd, so the
    // comparison refuses instead of wrapping to something admissible.
    assert_eq!(encoded_frame_len(usize::MAX), usize::MAX);
}

/// The production threshold admits every frame the server can actually build.
///
/// This is the relationship the deleted `debug_assert` was reaching for, said
/// correctly and in a test that runs in every profile: the point is not that
/// `max_frame_size` (an INBOUND bound) sits below the threshold, it is that a
/// realistic outbound export is admissible — so the fail-closed refusal above
/// cannot degrade into refusing normal service.
#[tokio::test]
async fn the_production_threshold_admits_a_realistic_outbound_export() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, WS_WRITE_BUFFER_SIZE).await;

    // Larger than the library's default write buffer and larger than the
    // default `max_frame_size` for inbound frames: a window export is not
    // bounded by either on the way out.
    let export = 2 * BlockableTransport::DEFAULT_WRITE_BUFFER;
    assert!(
        guarded.send_binary(vec![7u8; export]).await,
        "the production threshold must admit an ordinary export — a guard that refuses \
         real traffic is not a guard, it is an outage"
    );
    assert_eq!(
        socket.wire().len(),
        encoded_frame_len(export),
        "the delivered frame must be exactly one encoded binary frame"
    );
}

/// REAL CODEC, the flush-park shape: a peer that stops reading mid-flush and
/// resumes after the revocation gets no application byte.
///
/// The double covers this phase-wise; here it is the real sink parking on a
/// `Pending` write, so the partial-write question is answered in bytes. The
/// codec has ALREADY buffered the application frame when the park happens —
/// that is precisely the state where a message-level `written()` proves
/// nothing and a byte capture proves everything.
#[tokio::test]
async fn real_codec_withholds_a_parked_frame_when_the_peer_resumes_after_revocation() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    socket.block_writes();
    let mut send = Box::pin(guarded.send_binary(vec![7u8; UNDER_THRESHOLD_PAYLOAD]));
    assert!(
        futures_util::poll!(send.as_mut()).is_pending(),
        "the blocked socket must park the flush, or this row is not testing the flush wait"
    );
    assert_wire_is_empty(&socket);

    // The operator revokes while the frame sits in the codec's out-buffer, and
    // only then does the peer start reading again.
    registry.revoke(TEST_JTI);
    socket.unblock_writes();

    let keep_going = tokio::time::timeout(FLUSH_RECONSULT_INTERVAL * 20, send)
        .await
        .expect("the guard must re-consult on its own tick, not wait on the peer");

    assert!(!keep_going, "a revoked session must not continue");
    assert_wire_is_empty(&socket);
    assert!(
        guarded.socket.is_none(),
        "the refusal must drop the whole real transport"
    );
}

/// The package id a package's named dependency EDGE resolves to.
///
/// `resolve.nodes[].deps[].name` is the extern-crate name the dependent's code
/// writes, so a renamed dependency is found under `production_ws_codec` while
/// `deps[].pkg` names the package cargo actually bound there. Following the
/// edge is the whole point: a package NAME is ambiguous the moment two
/// versions of it are in the graph, and an edge never is.
fn resolved_dep(metadata: &serde_json::Value, package_id: &str, dep_name: &str) -> String {
    let node = metadata["resolve"]["nodes"]
        .as_array()
        .expect("cargo metadata must carry a resolve graph")
        .iter()
        .find(|node| node["id"] == package_id)
        .unwrap_or_else(|| panic!("{package_id} must have a resolve node"));
    node["deps"]
        .as_array()
        .expect("a resolve node must list its deps")
        .iter()
        .find(|dep| dep["name"] == dep_name)
        .unwrap_or_else(|| panic!("{package_id} must depend on {dep_name}"))["pkg"]
        .as_str()
        .expect("a resolved dep must name a package")
        .to_owned()
}

/// The two codec packages the alignment invariant compares, by resolved id.
///
/// `.0` is the codec PRODUCTION builds — reached by walking `oneiron-server`'s
/// `axum` edge and then that axum's own `tokio_tungstenite` edge. `.1` is what
/// the aliased dev-dependency the real-codec rows drive resolved to. Ids
/// rather than versions because an id names one package unambiguously.
fn codec_packages(metadata: &serde_json::Value) -> (String, String) {
    let server = metadata["packages"]
        .as_array()
        .expect("cargo metadata must list packages")
        .iter()
        .find(|package| package["name"] == "oneiron-server")
        .expect("oneiron-server must be in the graph")["id"]
        .as_str()
        .expect("a package must have an id")
        .to_owned();
    let axum = resolved_dep(metadata, &server, "axum");
    (
        resolved_dep(metadata, &axum, "tokio_tungstenite"),
        resolved_dep(metadata, &server, "production_ws_codec"),
    )
}

/// The workspace's own resolution, as cargo computed it.
fn workspace_metadata() -> serde_json::Value {
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .output()
        .expect("cargo metadata must be runnable");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON")
}

/// The real-codec rows must run the SAME codec package production runs.
///
/// The byte properties above — when `start_send` writes through, what an owed
/// pong leaves in the out-buffer — are statements about a specific codec. The
/// leg that introduced them pinned the dev-dependency to 0.26 while `axum`
/// resolved 0.28, so every row was green about a codec this server never
/// builds. Nothing in the type system catches that: both versions export the
/// same names, so the bridge compiles either way.
///
/// This follows dependency EDGES rather than matching package NAMES, and it
/// asks cargo rather than parsing the lockfile. A name is ambiguous the moment
/// two versions of a package are in the graph — a name-keyed lookup would take
/// whichever `axum` came first and could compare the alias against a version
/// production stopped building. `--locked` keeps the answer the one that was
/// actually built rather than a fresh resolution.
#[test]
fn the_real_codec_rows_run_the_same_codec_package_axum_resolves() {
    let (production, ours) = codec_packages(&workspace_metadata());
    assert_eq!(
        ours, production,
        "the real-codec rows must exercise the codec axum resolves — a byte-property row \
         pinned to a different package proves nothing about production while staying green"
    );
}

/// A resolve graph with TWO `axum` versions, production on the newer codec and
/// the alias left on the older one — the drift the row above must catch.
///
/// This is the shape a caret bump produces: `oneiron-server` moves to axum 0.9
/// (tokio-tungstenite 0.29) while some other crate in the workspace still
/// pulls axum 0.8 (0.28), and the dev-dependency alias stays at 0.28. Every
/// byte property would then be proven about a codec production stopped
/// building.
///
/// The stale axum is listed FIRST on purpose. A name-keyed lookup takes the
/// first `axum` it finds, reports 0.28, matches the alias, and passes — which
/// is exactly why the check follows `oneiron-server`'s own axum EDGE instead.
fn two_axum_versions_with_a_stale_alias() -> serde_json::Value {
    const SERVER: &str = "path+file:///w#oneiron-server@0.1.0";
    const STALE_AXUM: &str = "registry+x#axum@0.8.8";
    const LIVE_AXUM: &str = "registry+x#axum@0.9.0";
    const OLD_CODEC: &str = "registry+x#tokio-tungstenite@0.28.0";
    const NEW_CODEC: &str = "registry+x#tokio-tungstenite@0.29.0";

    serde_json::json!({
        "packages": [{ "name": "oneiron-server", "id": SERVER }],
        "resolve": { "nodes": [
            { "id": STALE_AXUM, "deps": [
                { "name": "tokio_tungstenite", "pkg": OLD_CODEC }] },
            { "id": LIVE_AXUM, "deps": [
                { "name": "tokio_tungstenite", "pkg": NEW_CODEC }] },
            { "id": SERVER, "deps": [
                { "name": "axum", "pkg": LIVE_AXUM },
                { "name": "production_ws_codec", "pkg": OLD_CODEC }] },
        ]},
    })
}

/// The alignment check must FAIL on that graph.
///
/// Without this row the check could resolve names instead of edges and stay
/// green through the very drift it exists to catch.
#[test]
fn the_codec_alignment_check_catches_a_second_axum_version_the_alias_missed() {
    let (production, ours) = codec_packages(&two_axum_versions_with_a_stale_alias());
    assert_ne!(
        ours, production,
        "the alignment check followed a package NAME, not oneiron-server's own axum edge: \
         it compared against the stale axum and would pass while production ran {production}"
    );
}

/// A masked client Ping carrying the RFC's MAXIMUM control payload, 125 bytes.
///
/// Each one makes the server owe a 127-byte Pong (2-byte header + 125). While
/// writes are blocked those pongs accumulate in the codec's out-buffer, so a
/// peer that sends five of them puts 635 bytes there — past the 512-byte
/// reserve the previous leg used as its bound. The peer chooses how many to
/// send, which is why a fixed reserve was never a bound at all.
fn max_payload_client_ping() -> Vec<u8> {
    let mut frame = vec![0x89, 0xFD, 0x01, 0x02, 0x03, 0x04];
    frame.extend(std::iter::repeat_n(0u8, 125));
    frame
}

/// Bytes one owed Pong occupies in the out-buffer for the ping above.
const MAX_PAYLOAD_PONG_BYTES: usize = 127;

/// Enough Pings that the accumulated pongs exceed any 512-byte reserve.
const PONGS_PAST_THE_OLD_RESERVE: usize = 8;

/// Feeds `count` max-payload Pings while writes are blocked, leaving that many
/// Pongs' worth of bytes in the codec's out-buffer and none on the wire.
async fn accumulate_owed_pongs(
    socket: &CapturingSocket,
    guarded: &mut GuardedTransport<TungsteniteBridge>,
    count: usize,
) {
    for i in 0..count {
        socket.push_inbound(&max_payload_client_ping());
        assert!(
            matches!(guarded.read_next().await, Some(Ok(WsMessage::Ping(_)))),
            "the real codec must decode masked client Ping {i}"
        );
    }
    assert_wire_is_empty(socket);
}

/// REAL CODEC, the P1 regression: pongs accumulated past ANY fixed reserve must
/// not let `start_send` write an application frame through pre-consult.
///
/// This is the row the 512-byte reserve could not pass. The sequence:
///
/// 1. writes are blocked and the peer sends 8 max-payload Pings, so the codec
///    holds 8 x 127 = 1016 bytes of owed Pongs — well past 512;
/// 2. a `send_binary` starts. The old one-shot pre-drain returns `Pending`
///    (writes are blocked) and proceeds anyway, leaving that residue in place;
/// 3. the socket becomes writable — which a peer or the kernel can do at any
///    instant, and needs no cooperation from this task;
/// 4. under the old code `start_send` then buffers the application frame on top
///    of the residue, crosses `write_buffer_size`, and writes the whole
///    out-buffer to the socket SYNCHRONOUSLY, before the flush-time consult.
///
/// The payload is sized to be admissible under the OLD arithmetic
/// (`encoded + 512 <= threshold`) and to cross the threshold once the residue
/// is added — so the frame is one the guard accepted and could not withhold.
///
/// With the drain-to-empty fix the send parks in the drain instead, the
/// revocation is seen there, and the transport aborts with no application byte
/// written. The assertion is on BYTES, because a partial write is the failure
/// mode a message-level check cannot see.
#[tokio::test]
async fn real_codec_withholds_bytes_when_owed_pongs_accumulate_past_any_fixed_reserve() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    socket.block_writes();
    accumulate_owed_pongs(&socket, &mut guarded, PONGS_PAST_THE_OLD_RESERVE).await;

    let residue = PONGS_PAST_THE_OLD_RESERVE * MAX_PAYLOAD_PONG_BYTES;
    assert!(
        residue > 512,
        "the accumulated pongs must exceed the reserve this regression retires, or the row \
         is not reproducing the finding: {residue} bytes"
    );
    // Admissible under the retired arithmetic, over the threshold once the
    // residue is counted: exactly the frame the reserve mis-classified.
    let payload = REAL_CODEC_WRITE_BUFFER - 512 - 4;
    assert!(
        encoded_frame_len(payload) + residue > REAL_CODEC_WRITE_BUFFER,
        "the frame must cross the real write-through point once the residue is added"
    );

    // The revocation lands, and the socket becomes writable, at the instant the
    // drain parks — before `start_send` would run. This is the interleaving the
    // finding describes, and it needs no `await` on this side because a socket
    // turning writable is an external event.
    //
    // A one-shot drain reaches `start_send` with the residue still buffered and
    // a now-writable socket, and the codec writes the whole out-buffer —
    // application frame included — synchronously, before the flush-time
    // consult. Draining to completion cannot: the drain re-consults on this
    // same wakeup, sees the revocation, and aborts with nothing handed over.
    let socket_for_hook = socket.clone();
    let registry_for_hook = Arc::clone(&registry);
    socket.on_write_park(move || {
        registry_for_hook.revoke(TEST_JTI);
        socket_for_hook.unblock_writes();
    });

    let keep_going = tokio::time::timeout(
        FLUSH_RECONSULT_INTERVAL * 20,
        guarded.send_binary(vec![7u8; payload]),
    )
    .await
    .expect("the guard must re-consult on its own tick, not wait on the peer");

    assert!(!keep_going, "a revoked session must not continue");
    let wire = socket.wire();
    assert!(
        !wire.contains(&7u8),
        "application payload bytes reached the wire before the consult could refuse them: \
         {} of {payload} bytes escaped",
        wire.iter().filter(|b| **b == 7u8).count()
    );
    assert!(
        guarded.socket.is_none(),
        "the refusal must drop the whole real transport"
    );
}

/// REAL CODEC control: the drain is a WAIT, not a refusal — a pong-owing send
/// on a LIVE credential still delivers once the peer reads again.
///
/// Without this row the P1 fix could be "abort whenever anything is owed" and
/// the withholding row above would still pass. The order is also pinned: the
/// accumulated pongs go out first (the drain completes), then the application
/// frame, byte-exact.
#[tokio::test]
async fn real_codec_delivers_a_pong_owing_send_after_the_drain_on_a_live_credential() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    socket.block_writes();
    accumulate_owed_pongs(&socket, &mut guarded, PONGS_PAST_THE_OLD_RESERVE).await;

    let mut send = Box::pin(guarded.send_binary(vec![7u8; UNDER_THRESHOLD_PAYLOAD]));
    assert!(
        futures_util::poll!(send.as_mut()).is_pending(),
        "the blocked socket must park the drain"
    );

    // The peer resumes reading with the credential still live.
    socket.unblock_writes();
    let keep_going = tokio::time::timeout(FLUSH_RECONSULT_INTERVAL * 20, send)
        .await
        .expect("the drain must complete once the peer reads");

    assert!(
        keep_going,
        "a live credential's pong-owing send must be delivered, not refused — a drain that \
         aborts on a slow peer is an outage wearing a security fix's clothes"
    );

    // The codec coalesces owed pongs: `set_additional` REPLACES a pending pong
    // rather than queueing another, so the peer's 8 Pings leave one Pong owed
    // per read that actually reached the buffer. What this row pins is the
    // ORDER and the tail — every pong byte precedes the application frame, and
    // the frame arrives whole.
    let wire = socket.wire();
    let mut frame = vec![0x82, UNDER_THRESHOLD_PAYLOAD as u8];
    frame.extend(std::iter::repeat_n(7u8, UNDER_THRESHOLD_PAYLOAD));
    assert!(
        wire.ends_with(&frame),
        "the application frame must arrive whole, after the drained control frames"
    );
    let head = &wire[..wire.len() - frame.len()];
    assert!(
        !head.is_empty() && head.len() % MAX_PAYLOAD_PONG_BYTES == 0,
        "the bytes preceding the frame must be whole owed Pongs, drained to completion: \
         {} bytes",
        head.len()
    );
    assert!(
        head.chunks(MAX_PAYLOAD_PONG_BYTES)
            .all(|pong| pong[0] == 0x8a && pong[1] == 125),
        "every drained control frame must be an unmasked 125-byte Pong"
    );
}

/// REAL CODEC: the PRE-HANDOVER drain must re-consult on its OWN TICK, with a
/// peer that never reads again and never wakes the sink.
///
/// The drain is an unbounded wait that a send now crosses BEFORE `start_send`,
/// so a silent peer can park a send there indefinitely. Every other
/// silent-peer row parks the POST-handover flush, which has its own tick — so
/// removing the drain's re-consultation leaves all of them green.
///
/// What makes this row load-bearing is what it withholds. Nothing unblocks the
/// socket, nothing fires its waker, and — crucially — nothing in this test ever
/// polls the send again. That last one is not a detail: `poll!` followed by
/// `tokio::time::timeout` would NOT work here, because both hand the drain a
/// free re-poll (a `Timeout` polls its inner future first when it expires), and
/// a drain that re-consults only at parks rides that free poll to a refusal and
/// passes. Measured: the park-only mutation below survives a `timeout`-shaped
/// row and dies here.
///
/// So the send runs in its OWN task and the verdict is `is_finished` after a
/// wait in the test task, which wakes the send task not at all. The only thing
/// that can complete it is [`FLUSH_RECONSULT_INTERVAL`] elapsing inside the
/// guard. Both degradations therefore fail: a naive unbounded
/// `poll_flush().await` and a park-only loop each leave the task unfinished.
///
/// `start_paused` makes the clock virtual, so the wait costs no wall time —
/// the runtime auto-advances to the guard's own tick, and the absence of that
/// tick is what the assertion sees.
///
/// The live-peer control for the same shape is
/// `real_codec_delivers_a_pong_owing_send_after_the_drain_on_a_live_credential`
/// above: there the peer resumes and the send completes, so this is a bounded
/// wait rather than a refusal to serve slow peers.
#[tokio::test(start_paused = true)]
async fn a_silent_peer_gets_re_consulted_on_the_tick_during_the_pre_handover_drain() {
    let socket = CapturingSocket::default();
    let registry = Arc::new(MutableRevocations::default());
    let mut guarded = real_codec_guarded(&socket, &registry, REAL_CODEC_WRITE_BUFFER).await;

    // A pong is owed and writes are blocked, so the send parks in the drain —
    // before any application byte has been handed to the codec.
    socket.block_writes();
    owe_a_pong(&socket, &mut guarded).await;

    // The operator revokes at the instant the drain parks, from another
    // process: no socket event accompanies it, the socket stays blocked, and
    // the waker is never fired. The hook is installed only now, so it can only
    // fire for the drain's own park.
    let registry_for_hook = Arc::clone(&registry);
    socket.on_write_park(move || registry_for_hook.revoke(TEST_JTI));

    let send = tokio::spawn(async move {
        let keep_going = guarded
            .send_binary(vec![7u8; UNDER_THRESHOLD_PAYLOAD])
            .await;
        (keep_going, guarded)
    });
    tokio::time::sleep(FLUSH_RECONSULT_INTERVAL * 20).await;
    assert!(
        send.is_finished(),
        "the drain parked past twenty re-consult intervals on a silent peer — it is \
         waiting on the peer instead of re-consulting on its own tick"
    );

    let (keep_going, guarded) = send.await.expect("the send task must not panic");
    assert!(!keep_going, "a revoked session must not continue");
    assert_wire_is_empty(&socket);
    assert!(
        guarded.socket.is_none(),
        "the refusal must end the transport: nothing may remain that could drain the \
         application frame later"
    );
}
