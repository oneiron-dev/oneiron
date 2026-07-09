use super::*;
use core::assert_matches;
use loro::{Container, ExportMode, LoroMap, ValueOrContainer};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::sync::bridge::Materializer;
use crate::sync::loro_support::export_snapshot;
use crate::sync::schema::create_root_doc;
use crate::temporal::TimeRange;

fn test_manager() -> Arc<WindowManager> {
    let dir = tempfile::tempdir().unwrap();
    let config = crate::types::VaultConfig::device();
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    Arc::new(WindowManager::new(
        vault,
        Arc::new(Materializer::new()),
        "test-user",
    ))
}

fn test_client(manager: &Arc<WindowManager>) -> (SyncClient, mpsc::UnboundedReceiver<SyncEvent>) {
    SyncClient::new(Arc::clone(manager), SyncClientConfig::default()).unwrap()
}

/// Builds a simulated server-side window doc with the schema containers.
fn server_window_doc() -> LoroDoc {
    let doc = LoroDoc::new();
    let _ = doc.get_map("entities");
    let _ = doc.get_map("edges");
    let _ = doc.get_map("tombstones");
    doc.commit();
    doc
}

fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    blob.push(entity_type);
    blob.extend_from_slice(&occurred.start.to_be_bytes());
    blob.extend_from_slice(&occurred.end.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(data);
    blob
}

fn sync_state_values_with_prefix(vault: &Vault, prefix: &str) -> Vec<(String, Vec<u8>)> {
    vault
        .sync_state_keys_with_prefix(prefix)
        .unwrap()
        .into_iter()
        .map(|key| {
            let value = vault.sync_state_get(&key).unwrap().unwrap();
            (key, value)
        })
        .collect()
}

fn root_windows_map(doc: &LoroDoc) -> LoroMap {
    let meta = doc.get_map("meta");
    match meta.get("windows").expect("meta.windows must exist") {
        ValueOrContainer::Container(Container::Map(windows)) => windows,
        other => panic!("meta.windows must be a LoroMap, got {other:?}"),
    }
}

fn read_u_seq(vault: &Vault, key: &str) -> Option<u32> {
    vault
        .sync_state_get(&format!("m:u_seq:w:{key}"))
        .unwrap()
        .map(|raw| u32::from_le_bytes(raw.try_into().unwrap()))
}

fn task_body() -> Vec<u8> {
    crate::types::task_body_for_test(crate::types::TaskRole::Task)
}

fn commit_local_entity(
    window: &LoadedWindow,
    id: &EntityId,
    learned_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let vv_before = window.doc.oplog_vv();
    let blob = entity_blob(
        ENTITY_TYPE_TASK,
        TimeRange { start: 1, end: 1 },
        learned_at,
        body,
    );
    window
        .doc
        .get_map("entities")
        .insert(id.to_hex().as_str(), blob.as_slice())
        .unwrap();
    window.doc.commit();
    export_updates_since(&window.doc, &vv_before.encode()).unwrap()
}

fn test_entity_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("valid test entity id")
}

fn encode_policy_manifest(extra_entries: Vec<(rmpv::Value, rmpv::Value)>) -> Vec<u8> {
    use rmpv::Value;

    let mut entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("client-test")),
        (Value::from("pack_version"), Value::from("v1")),
        (
            Value::from("min_engine_version"),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from("defaults"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
        (
            Value::from("rules"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("prefix"), Value::from("health.")),
                (
                    Value::from("axes"),
                    Value::Map(vec![
                        (Value::from("criticality"), Value::from("critical")),
                        (Value::from("sensitivity"), Value::from("sensitive")),
                    ]),
                ),
            ])]),
        ),
        (
            Value::from("actor_ceilings"),
            Value::Array(vec![Value::Map(vec![
                (Value::from("actor_class"), Value::from("first_party")),
                (Value::from("ceiling"), Value::from("auto")),
            ])]),
        ),
    ];
    entries.extend(extra_entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
    out
}

fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (rmpv::Value, rmpv::Value) {
    use rmpv::Value;

    let row = Value::Map(vec![
        (
            Value::from("max_auto_sensitivity"),
            Value::from(u64::from(max_auto_sensitivity)),
        ),
        (Value::from("receipted"), Value::Boolean(true)),
        (Value::from("warned"), Value::Boolean(true)),
    ]);
    (
        Value::from("source_trust"),
        Value::Map(vec![(Value::from(source.as_str()), row)]),
    )
}

fn put_policy_manifest_bytes(vault: &Vault, seed: u8, data: &[u8]) {
    let id = test_entity_id(seed);
    let payload = entity_blob(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    );
    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
        .expect("put policy manifest");
}

fn source_trust_claim(source: ClaimSource) -> ClaimBody {
    let mut body = ClaimBody::new(
        "profile.name",
        ClaimSubject::Entity(test_entity_id(0x21)),
        rmpv::Value::from("Ada"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    body
}

fn internal_source_trust_claim(source: ClaimSource) -> ClaimBody {
    let mut body = source_trust_claim(source);
    body.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("internal"),
    )]));
    body
}

fn test_selector() -> SyncSelector {
    SyncSelector::new(
        test_entity_id(0xA1),
        test_entity_id(0xA2),
        crate::sync::SyncSelectorWorld::All,
        vec![],
        vec![],
    )
}

fn federated_claim_update(id: &EntityId, body: &ClaimBody) -> Vec<u8> {
    let data = crate::claim::encode_claim_body(body).expect("claim encode");
    let blob = entity_blob(ENTITY_TYPE_CLAIM, TimeRange { start: 5, end: 5 }, 5, &data);
    let doc = server_window_doc();
    doc.get_map("entities")
        .insert(id.to_hex().as_str(), blob.as_slice())
        .expect("insert claim");
    doc.commit();
    doc.export(ExportMode::all_updates())
        .expect("export update")
}

fn federated_tombstone_update(id: &EntityId) -> Vec<u8> {
    let doc = server_window_doc();
    doc.get_map("tombstones")
        .insert(id.to_hex().as_str(), b"deleted".as_slice())
        .expect("insert tombstone");
    doc.commit();
    doc.export(ExportMode::all_updates())
        .expect("export update")
}

#[test]
fn sync_client_rejects_invalid_window_creation() {
    let manager = test_manager();
    let (client, _rx) = test_client(&manager);
    let Err(err) = client.ensure_window("2026-13") else {
        panic!("expected invalid window key");
    };
    assert_matches!(err, TransportError::InvalidWindowKey);
    let Err(err) = client.ensure_window("1969-12") else {
        panic!("expected invalid window key");
    };
    assert_matches!(err, TransportError::InvalidWindowKey);
}

#[test]
fn sync_client_generate_initial_sync() {
    let manager = test_manager();
    let (client, _rx) = test_client(&manager);
    let messages = client.generate_initial_sync();
    // hello + lease request + root VV + 2 window VV requests
    // (current + prev) — the OD-5 connect-sequence literal
    // `[hello][lease_request][…existing]` (ONE-1140).
    assert_eq!(messages.len(), 5);

    // Frame 0: protocol hello. The in-tree sync client uses the
    // full-window VV_REQUEST flow; selector-capable callers use the
    // current selector protocol.
    // It MUST be the first frame.
    assert_eq!(
        messages[0],
        transport::encode_legacy_full_window_protocol_hello()
    );

    // Frame 1: lease request — 105 B pinned layout, client_id BE at
    // offset 1, and the embedded PoP signature verifies over the OD-6
    // transcript (a frame signed for a different client id would not).
    assert_eq!(messages[1].len(), 105);
    assert_eq!(messages[1][0], transport::TAG_LEASE_REQUEST);
    let (cid, pubkey, pop_sig) = transport::decode_lease_request(&messages[1][1..]).unwrap();
    assert_eq!(cid, client.client_id());
    assert!(
        crate::sync::lease::verify_lease_pop(cid, &pubkey, &pop_sig),
        "the lease request must carry a valid proof of possession"
    );

    // Frame 2: root VV — Loro binary encoding, decodable, NOT JSON.
    assert_eq!(messages[2][0], TAG_VERSION_VECTOR);
    VersionVector::decode(&messages[2][1..]).expect("root VV must be Loro binary encoding");
    assert!(
        serde_json::from_slice::<serde_json::Value>(&messages[2][1..]).is_err(),
        "the serde_json VV wire encoding is dead (ONE-1127)"
    );

    // Frames 3..: window VV_REQUEST frames carrying binary VV payloads.
    for msg in &messages[3..] {
        assert_eq!(msg[0], TAG_WINDOW_SYNC);
        let (key, sub_tag, payload) = transport::decode_window_sync(&msg[1..]).unwrap();
        assert!(parse_window_key_str(key).is_some());
        assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
        VersionVector::decode(payload).expect("window VV must be Loro binary encoding");
        assert!(
            serde_json::from_slice::<serde_json::Value>(payload).is_err(),
            "the serde_json VV wire encoding is dead (ONE-1127)"
        );
    }
}

/// AC6 (ONE-1127): two docs diverge → exchange binary VVs → each imports
/// ONLY the delta → deep values converge, and each delta payload is
/// asserted smaller than the corresponding `all_updates` export.
#[test]
fn binary_vv_delta_round_trip_converges_with_smaller_payloads() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    client.ensure_window(key).unwrap();

    // Shared chunky base so all_updates is meaningfully larger than a delta.
    let server_doc = server_window_doc();
    server_doc
        .get_map("entities")
        .insert("base", vec![7u8; 2048].as_slice())
        .unwrap();
    server_doc.commit();
    let base = server_doc.export(ExportMode::all_updates()).unwrap();
    let base_msg = transport::encode_window_sync(key, window_sub_tags::UPDATE, &base);
    assert!(client.handle_server_message(&base_msg).unwrap().is_empty());

    // Diverge: client writes one key, server writes another.
    let client_window = client.window(key).unwrap();
    client_window
        .doc
        .get_map("entities")
        .insert("client-only", b"c".as_slice())
        .unwrap();
    client_window.doc.commit();
    server_doc
        .get_map("entities")
        .insert("server-only", b"s".as_slice())
        .unwrap();
    server_doc.commit();

    // Server → client SyncStep1: VV_REQUEST carrying the server's binary VV.
    let request = transport::encode_window_sync(
        key,
        window_sub_tags::VV_REQUEST,
        &server_doc.oplog_vv().encode(),
    );
    let responses = client.handle_server_message(&request).unwrap();
    assert_eq!(
        responses.len(),
        2,
        "VV_REQUEST → [UPDATE delta, VV_RESPONSE]"
    );

    // responses[0]: the client→server delta — a true delta, not all_updates.
    let (k0, sub0, client_delta) = transport::decode_window_sync(&responses[0][1..]).unwrap();
    assert_eq!(k0, key);
    assert_eq!(sub0, window_sub_tags::UPDATE);
    let client_all = client
        .window(key)
        .unwrap()
        .doc
        .export(ExportMode::all_updates())
        .unwrap();
    assert!(
        client_delta.len() < client_all.len(),
        "delta ({}) must be smaller than all_updates ({}) for the diverged case",
        client_delta.len(),
        client_all.len()
    );
    server_doc.import(client_delta).unwrap();

    // responses[1]: client VV for the reverse leg.
    let (k1, sub1, client_vv) = transport::decode_window_sync(&responses[1][1..]).unwrap();
    assert_eq!(k1, key);
    assert_eq!(sub1, window_sub_tags::VV_RESPONSE);
    VersionVector::decode(client_vv).expect("VV_RESPONSE payload must be binary VV");

    // Server computes ITS delta via the same single delta-export entry point.
    let server_delta = export_updates_since(&server_doc, client_vv).unwrap();
    let server_all = server_doc.export(ExportMode::all_updates()).unwrap();
    assert!(
        server_delta.len() < server_all.len(),
        "server delta ({}) must be smaller than all_updates ({})",
        server_delta.len(),
        server_all.len()
    );
    let update_msg = transport::encode_window_sync(key, window_sub_tags::UPDATE, &server_delta);
    assert!(
        client
            .handle_server_message(&update_msg)
            .unwrap()
            .is_empty()
    );

    // Deep-value convergence on both sides.
    assert_eq!(
        client.window(key).unwrap().doc.get_deep_value(),
        server_doc.get_deep_value()
    );
}

#[test]
fn noop_echo_after_hard_delete_writes_no_uw_carrier() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let learned_at = 1_772_400_000u64;
    let seq_key = format!("m:u_seq:w:{key}");
    vault.sync_state_put(&seq_key, b"bad").unwrap();

    let window = client.ensure_window(key).unwrap();
    let id = EntityId::now();
    let payload_update = commit_local_entity(&window, &id, learned_at, &task_body());
    assert!(
        sync_state_values_with_prefix(&vault, &format!("u:w:{key}:")).is_empty(),
        "corrupt m:u_seq makes Observer A fail before any u:w row is written"
    );
    assert!(
        vault.get(&id).unwrap().is_some(),
        "Observer B materialized the live payload before the hard delete"
    );

    vault.sync_state_put(&seq_key, &0u32.to_le_bytes()).unwrap();
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(vault.get(&id).unwrap().is_none());
    assert!(
        vault
            .sync_state_get(&format!("fr:w:{key}"))
            .unwrap()
            .is_some(),
        "hard delete marks the window for full resync"
    );

    let prefix = format!("u:w:{key}:");
    let rows_before_echo = sync_state_values_with_prefix(&vault, &prefix);
    let seq_before_echo = read_u_seq(&vault, key);
    let echo = transport::encode_window_sync(key, window_sub_tags::UPDATE, &payload_update);
    assert!(client.handle_server_message(&echo).unwrap().is_empty());

    let rows_after_echo = sync_state_values_with_prefix(&vault, &prefix);
    assert_eq!(
        rows_after_echo, rows_before_echo,
        "the no-op echo must not add any u:w row after hard-delete scrub"
    );
    assert_eq!(
        read_u_seq(&vault, key),
        seq_before_echo,
        "m:u_seq must not bump for a covered post-scrub no-op echo"
    );
    assert!(
        rows_after_echo
            .iter()
            .all(|(_, value)| value != &payload_update),
        "the pre-delete payload update must not reappear as a u:w carrier"
    );
    assert!(
        vault.get(&id).unwrap().is_none(),
        "the entity stays tombstoned after the no-op echo"
    );
}

#[test]
fn noop_echo_after_snapshot_subsumes_writes_no_uw_row() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let learned_at = 1_772_400_000u64;
    let window = client.ensure_window(key).unwrap();
    let id = EntityId::now();
    let payload_update = commit_local_entity(&window, &id, learned_at, &task_body());
    let prefix = format!("u:w:{key}:");
    assert!(
        sync_state_values_with_prefix(&vault, &prefix)
            .iter()
            .any(|(_, value)| value == &payload_update),
        "precondition: the local op initially has a u:w row"
    );

    window.persist_state(&vault).unwrap();
    assert!(
        sync_state_values_with_prefix(&vault, &prefix).is_empty(),
        "snapshot persistence prunes the subsumed u:w row"
    );
    let seq_before_echo = read_u_seq(&vault, key);
    assert_eq!(
        vault
            .sync_state_get(&format!("svf:w:{key}"))
            .unwrap()
            .as_deref(),
        Some(&[SVF_FRESH][..]),
        "all rows subsumed leaves svf fresh"
    );

    let echo = transport::encode_window_sync(key, window_sub_tags::UPDATE, &payload_update);
    assert!(client.handle_server_message(&echo).unwrap().is_empty());
    assert!(
        sync_state_values_with_prefix(&vault, &prefix).is_empty(),
        "a no-op echo of snapshot-subsumed bytes must not re-grow u:w"
    );
    assert_eq!(
        read_u_seq(&vault, key),
        seq_before_echo,
        "m:u_seq must not bump for a covered snapshot no-op echo"
    );
    assert_eq!(
        vault
            .sync_state_get(&format!("svf:w:{key}"))
            .unwrap()
            .as_deref(),
        Some(&[SVF_FRESH][..]),
        "the deduped echo must not flip svf stale"
    );
}

#[test]
fn vv_response_triggers_local_diff_update() {
    // Client sent VV_REQUEST earlier; the server's VV_RESPONSE must be
    // consumed (not a no-op) — the client computes and sends its diff.
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-04";
    client.ensure_window(key).unwrap();
    let client_window = client.window(key).unwrap();
    client_window
        .doc
        .get_map("entities")
        .insert("local", b"x".as_slice())
        .unwrap();
    client_window.doc.commit();

    let server_doc = server_window_doc();
    let msg = transport::encode_window_sync(
        key,
        window_sub_tags::VV_RESPONSE,
        &server_doc.oplog_vv().encode(),
    );
    let responses = client.handle_server_message(&msg).unwrap();
    assert_eq!(responses.len(), 1, "VV_RESPONSE → [UPDATE local diff]");

    let (k, sub, delta) = transport::decode_window_sync(&responses[0][1..]).unwrap();
    assert_eq!(k, key);
    assert_eq!(sub, window_sub_tags::UPDATE);
    server_doc.import(delta).unwrap();
    assert_eq!(
        client.window(key).unwrap().doc.get_deep_value(),
        server_doc.get_deep_value()
    );
}

/// ONE-1128 AC1 machinery: `window_converged` is the queue-clear gate, so
/// its truth table is pinned hard. `None` (no server witness) must be
/// treated as NOT converged by callers — fail-closed.
#[test]
fn window_converged_requires_server_witness_and_vv_equality() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    client.ensure_window(key).unwrap();

    // No server VV observed yet → None (caller must treat as NOT converged).
    assert_eq!(client.window_converged(key), None);
    // Unknown window → None.
    assert_eq!(client.window_converged("2026-04"), None);

    // Server is AHEAD: its VV_RESPONSE carries ops we lack → not converged.
    let server_doc = server_window_doc();
    server_doc
        .get_map("entities")
        .insert("server-op", b"s".as_slice())
        .unwrap();
    server_doc.commit();
    let resp = transport::encode_window_sync(
        key,
        window_sub_tags::VV_RESPONSE,
        &server_doc.oplog_vv().encode(),
    );
    client.handle_server_message(&resp).unwrap();
    assert_eq!(
        client.window_converged(key),
        Some(false),
        "server VV with ops we lack must NOT read as converged"
    );

    // Import the server's delta → VVs now match the recorded witness.
    let delta = export_updates_since(
        &server_doc,
        &client.window(key).unwrap().doc.oplog_vv().encode(),
    )
    .unwrap();
    let update = transport::encode_window_sync(key, window_sub_tags::UPDATE, &delta);
    client.handle_server_message(&update).unwrap();
    assert_eq!(client.window_converged(key), Some(true));

    // A NEW local write makes the witness stale → not converged again.
    // This is the lost-confirmation case: a server that never received
    // our ops can never produce a VV that includes them.
    let window = client.window(key).unwrap();
    window
        .doc
        .get_map("tombstones")
        .insert("deadbeef", b"t".as_slice())
        .unwrap();
    window.doc.commit();
    assert_eq!(
        client.window_converged(key),
        Some(false),
        "local ops missing from the server witness must block convergence"
    );

    // A server VV_REQUEST (SyncStep1) carrying a VV that includes our ops
    // refreshes the witness → converged.
    let our_delta = export_updates_since(
        &client.window(key).unwrap().doc,
        &server_doc.oplog_vv().encode(),
    )
    .unwrap();
    server_doc.import(&our_delta).unwrap();
    let req = transport::encode_window_sync(
        key,
        window_sub_tags::VV_REQUEST,
        &server_doc.oplog_vv().encode(),
    );
    client.handle_server_message(&req).unwrap();
    assert_eq!(client.window_converged(key), Some(true));
}

/// ONE-1128: queued offline updates must be importable into the local
/// doc (the VV-equality gate only vouches for ops the local doc holds);
/// garbage bytes fail closed with the typed transport error.
#[test]
fn import_queued_update_applies_ops_and_rejects_garbage() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";

    let writer = server_window_doc();
    writer
        .get_map("tombstones")
        .insert("victim", b"t".as_slice())
        .unwrap();
    writer.commit();
    let update = writer.export(ExportMode::all_updates()).unwrap();

    client.import_queued_update(key, &update).unwrap();
    assert_eq!(
        client.window(key).unwrap().doc.get_deep_value(),
        writer.get_deep_value(),
        "queued ops must land in the local doc before replay"
    );

    assert_matches!(
        client.import_queued_update(key, &[0xFF, 0xFE, 0xFD]),
        Err(TransportError::InvalidPayload(
            "queued update import failed"
        ))
    );
    assert_matches!(
        client.import_queued_update("2026-13", &update),
        Err(TransportError::InvalidWindowKey)
    );
}

#[test]
fn federated_import_seam_restamps_before_observed_import() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    put_policy_manifest_bytes(
        &vault,
        0x8A,
        &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]),
    );

    let id = test_entity_id(0x8B);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);
    client
        .import_federated_window_update(key, &update, FederationAdmissionRole::Member)
        .expect("federated member import should be admitted");

    let window = client.window(key).expect("federated import opens window");
    let doc_blob =
        crate::sync::loro_support::map_get_bytes(&window.doc.get_map("entities"), &id.to_hex())
            .expect("claim must be present in admitted window doc");
    let doc_body = crate::claim::decode_claim_body(&doc_blob[ENTITY_METADATA_HEADER_LEN..], false)
        .expect("decode doc claim");
    assert_eq!(doc_body.source, Some(ClaimSource::Imported));

    let raw = vault
        .get_raw(&id)
        .expect("read materialized claim")
        .expect("claim must materialize after admitted import");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode materialized claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::Imported));
}

#[test]
fn federated_generated_auto_claim_restamps_but_stays_non_consolidatable() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    put_policy_manifest_bytes(
        &vault,
        0x8C,
        &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]),
    );

    let id = test_entity_id(0x8D);
    let remote_body = source_trust_claim(ClaimSource::Generated);
    let update = federated_claim_update(&id, &remote_body);
    client
        .import_federated_window_update(key, &update, FederationAdmissionRole::Member)
        .expect("federated generated claim should be admitted under imported trust");

    let raw = vault
        .get_raw(&id)
        .expect("read materialized claim")
        .expect("claim must materialize after admitted import");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode materialized claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::Imported));
    assert!(
        crate::claim::claim_surfaceable(&materialized_body),
        "federated Auto/Generated-origin claims still surface after import"
    );
    assert!(
        !crate::claim::claim_consolidatable(&materialized_body),
        "federated Generated origin must survive restamp for read admission"
    );
}

#[test]
fn federated_selector_member_response_enters_admission_once() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    put_policy_manifest_bytes(
        &vault,
        0x93,
        &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]),
    );

    let selector = test_selector();
    let request = client
        .federated_selector_vv_request(key, &selector, &VersionVector::new().encode())
        .expect("selector request encodes");
    let (request_key, request_sub_tag, _) =
        transport::decode_window_sync(&request[1..]).expect("decode selector request frame");
    assert_eq!(request_key, key);
    assert_eq!(request_sub_tag, window_sub_tags::SELECTOR_VV_REQUEST);

    let id = test_entity_id(0x94);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);

    client
        .import_federated_selector_window_update(key, &update, FederationAdmissionRole::Member)
        .expect("selector member response should be admitted");

    let raw = vault
        .get_raw(&id)
        .expect("read admitted selector claim")
        .expect("admitted selector claim materializes");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode materialized selector claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::Imported));

    let ordinary_id = test_entity_id(0x9A);
    let ordinary_body = internal_source_trust_claim(ClaimSource::ToolOutput);
    let ordinary_update = federated_claim_update(&ordinary_id, &ordinary_body);
    let ordinary_response =
        transport::encode_window_sync(key, window_sub_tags::UPDATE, &ordinary_update)
            .into_result()
            .expect("ordinary full-window update encodes");

    client
        .handle_server_message(&ordinary_response)
        .expect("ordinary full-window update should remain trust-blind after selector import");

    let ordinary_raw = vault
        .get_raw(&ordinary_id)
        .expect("read ordinary post-selector claim")
        .expect("ordinary post-selector claim materializes");
    let ordinary_materialized_body =
        crate::claim::decode_claim_body(&ordinary_raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode ordinary post-selector claim");
    assert_eq!(
        ordinary_materialized_body.source,
        Some(ClaimSource::ToolOutput)
    );
}

#[test]
fn federated_selector_member_stale_claim_is_restamped_and_retained() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    put_policy_manifest_bytes(
        &vault,
        0x9B,
        &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]),
    );

    let id = test_entity_id(0x9C);
    let mut remote_body = source_trust_claim(ClaimSource::ToolOutput);
    remote_body.stale = true;
    let update = federated_claim_update(&id, &remote_body);

    client
        .import_federated_selector_window_update(key, &update, FederationAdmissionRole::Member)
        .expect("stale selector member response should be admitted and retained");

    let raw = vault
        .get_raw(&id)
        .expect("read stale selector claim")
        .expect("stale selector claim materializes");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode stale selector claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::Imported));
    assert!(
        materialized_body.stale,
        "F-STALE marker must be retained for read-path gating"
    );
    assert!(
        !crate::claim::claim_surfaceable(&materialized_body),
        "stale federated claims must remain hidden from surfaceable read paths"
    );
}

#[test]
fn federated_selector_guest_response_cannot_auto_approve_above_local_ceiling() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    put_policy_manifest_bytes(
        &vault,
        0x95,
        &encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]),
    );

    client
        .federated_selector_vv_request(key, &test_selector(), &VersionVector::new().encode())
        .expect("guest selector request encodes");
    let id = test_entity_id(0x96);
    let remote_body = internal_source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);

    let err = client
        .import_federated_selector_window_update(key, &update, FederationAdmissionRole::Guest)
        .expect_err("guest selector response above local ceiling must be denied");
    let TransportError::Storage(message) = err else {
        panic!("expected auditable admission storage error, got {err:?}");
    };
    assert!(
        message.contains("gate.pending.source_trust"),
        "denial reason must remain auditable, got {message}"
    );
    assert!(
        client.window(key).is_none(),
        "denied guest selector bytes must not open a live window"
    );
    assert!(
        vault
            .get_raw(&id)
            .expect("read denied guest selector claim")
            .is_none(),
        "denied guest selector claim must not materialize"
    );
}

#[test]
fn ordinary_full_window_update_remains_trust_blind_without_selector_marker() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let id = test_entity_id(0x97);
    let remote_body = internal_source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);
    let response = transport::encode_window_sync(key, window_sub_tags::UPDATE, &update)
        .into_result()
        .expect("full-window update encodes");

    client
        .handle_server_message(&response)
        .expect("ordinary full-window update should remain trust-blind");

    let raw = vault
        .get_raw(&id)
        .expect("read full-window claim")
        .expect("full-window claim materializes");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode full-window claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::ToolOutput));
}

#[test]
fn selector_request_builder_does_not_reclassify_next_update() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let _request = client
        .federated_selector_vv_request(key, &test_selector(), &VersionVector::new().encode())
        .expect("selector request encodes without recording a marker");

    let id = test_entity_id(0x98);
    let remote_body = internal_source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);
    let response = transport::encode_window_sync(key, window_sub_tags::UPDATE, &update)
        .into_result()
        .expect("full-window update encodes");

    client
        .handle_server_message(&response)
        .expect("selector request builder must not reclassify the update");

    let raw = vault
        .get_raw(&id)
        .expect("read full-window claim")
        .expect("full-window claim materializes");
    let materialized_body =
        crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)
            .expect("decode full-window claim");
    assert_eq!(materialized_body.source, Some(ClaimSource::ToolOutput));
}

#[test]
fn federated_import_seam_denies_before_window_import_with_reason() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let id = test_entity_id(0x8C);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&id, &remote_body);

    let err = client
        .import_federated_window_update(key, &update, FederationAdmissionRole::Guest)
        .expect_err("untrusted imported auto claim must be denied before import");
    let TransportError::Storage(message) = err else {
        panic!("expected auditable admission storage error, got {err:?}");
    };
    assert!(
        message.contains("gate.pending.source_trust"),
        "denial reason must remain auditable, got {message}"
    );
    assert!(
        client.window(key).is_none(),
        "denied federated bytes must not open or import a live window"
    );
    assert!(
        vault.get_raw(&id).expect("read denied claim").is_none(),
        "denied federated bytes must not materialize"
    );
}

#[test]
fn federated_import_seam_denies_preapproved_untrusted_claim() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let id = test_entity_id(0x92);
    let mut remote_body = source_trust_claim(ClaimSource::ToolOutput);
    remote_body.approval = ClaimApprovalStatus::Approved;
    let update = federated_claim_update(&id, &remote_body);

    let err = client
        .import_federated_window_update(key, &update, FederationAdmissionRole::Member)
        .expect_err("preapproved federated claim must still pass local source trust");
    let TransportError::Storage(message) = err else {
        panic!("expected auditable admission storage error, got {err:?}");
    };
    assert!(
        message.contains("gate.pending.source_trust"),
        "denial reason must remain auditable, got {message}"
    );
    assert!(
        client.window(key).is_none(),
        "denied preapproved federated bytes must not open or import a live window"
    );
    assert!(
        vault.get_raw(&id).expect("read denied claim").is_none(),
        "denied preapproved federated claim must not materialize"
    );
}

#[test]
fn federated_import_seam_denial_preserves_open_durable_window() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let window = client.ensure_window(key).expect("open window");
    let local_id = test_entity_id(0x8F);
    commit_local_entity(&window, &local_id, 1_772_400_000, &task_body());
    window.persist_state(&vault).expect("persist local state");

    let live_before = window.doc.get_deep_value();
    let updates_before = sync_state_values_with_prefix(&vault, &format!("u:w:{key}:"));
    let snapshot_before = vault.sync_state_get(&format!("d:w:{key}")).unwrap();
    let sv_before = vault.sync_state_get(&format!("sv:w:{key}")).unwrap();
    let svf_before = vault.sync_state_get(&format!("svf:w:{key}")).unwrap();

    let denied_id = test_entity_id(0x90);
    let remote_body = source_trust_claim(ClaimSource::ToolOutput);
    let update = federated_claim_update(&denied_id, &remote_body);
    let err = client
        .import_federated_window_update(key, &update, FederationAdmissionRole::Member)
        .expect_err("untrusted imported auto claim must be denied");
    let TransportError::Storage(message) = err else {
        panic!("expected auditable admission storage error, got {err:?}");
    };
    assert!(
        message.contains("gate.pending.source_trust"),
        "denial reason must remain auditable, got {message}"
    );

    assert_eq!(
        window.doc.get_deep_value(),
        live_before,
        "denied federated bytes must not mutate an already-open window"
    );
    assert!(
        vault
            .get_raw(&local_id)
            .expect("read local entity")
            .is_some(),
        "unrelated local state must survive the denied import"
    );
    assert!(
        vault
            .get_raw(&denied_id)
            .expect("read denied claim")
            .is_none(),
        "denied federated claim must not materialize"
    );
    assert_eq!(
        sync_state_values_with_prefix(&vault, &format!("u:w:{key}:")),
        updates_before,
        "denied federated bytes must not append durable update rows"
    );
    assert_eq!(
        vault.sync_state_get(&format!("d:w:{key}")).unwrap(),
        snapshot_before
    );
    assert_eq!(
        vault.sync_state_get(&format!("sv:w:{key}")).unwrap(),
        sv_before
    );
    assert_eq!(
        vault.sync_state_get(&format!("svf:w:{key}")).unwrap(),
        svf_before
    );
}

#[test]
fn federated_import_seam_rejects_tombstone_updates_until_delete_admission() {
    let manager = test_manager();
    let vault = Arc::clone(manager.vault());
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let tombstoned = test_entity_id(0x91);
    let update = federated_tombstone_update(&tombstoned);

    assert_matches!(
        client.import_federated_window_update(key, &update, FederationAdmissionRole::Member),
        Err(TransportError::InvalidPayload(
            "federated tombstone update rejected"
        ))
    );
    assert!(
        client.window(key).is_none(),
        "tombstone-only federated bytes must not open or import a live window"
    );
    assert!(
        vault
            .get_raw(&tombstoned)
            .expect("read tombstoned id")
            .is_none(),
        "rejected federated tombstone must not materialize delete effects"
    );
    assert!(
        sync_state_values_with_prefix(&vault, &format!("u:w:{key}:")).is_empty(),
        "rejected federated tombstone bytes must not be persisted"
    );
}

#[test]
fn federated_import_seam_rejects_oversized_update_before_window_open() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let update = vec![0u8; MAX_DECODED_PAYLOAD_BYTES + 1];

    assert_matches!(
        client.import_federated_window_update(key, &update, FederationAdmissionRole::Guest),
        Err(TransportError::FrameTooLarge { size, max })
            if size == MAX_DECODED_PAYLOAD_BYTES + 1 && max == MAX_DECODED_PAYLOAD_BYTES
    );
    assert!(
        client.window(key).is_none(),
        "oversized federated bytes must not open a live window"
    );
}

#[test]
fn federated_admission_error_mapping_preserves_local_storage_failures() {
    let err = map_federated_admission_err(crate::error::Error::MapFull);
    let TransportError::Storage(message) = err else {
        panic!("expected local storage failure to remain storage, got {err:?}");
    };
    assert!(
        message.contains("federated admission failed"),
        "storage mapping should keep admission context, got {message}"
    );
}

#[test]
fn federated_admission_error_mapping_keeps_remote_content_malformed() {
    assert_matches!(
        map_federated_admission_err(crate::error::Error::CorruptedIndex("entity metadata")),
        TransportError::InvalidPayload("federated update admission failed")
    );
}

/// ONE-1128 AC2: the re-bootstrap drops ALL in-memory docs and produces
/// Phase 1-2 frames WITHOUT the protocol hello (hello is per-connection,
/// ONE-1127). Fresh root VV must be EMPTY — that is what "drop Docs"
/// means on the wire.
#[test]
fn generate_re_bootstrap_sync_drops_docs_and_omits_hello() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);

    // Dirty state: a non-default window with local ops and a recorded
    // server witness. (The unsent debounce buffer lives in the
    // connection run loop since ONE-1126, not on the client.)
    let key = "2026-01";
    client.ensure_window(key).unwrap();
    let window = client.window(key).unwrap();
    window
        .doc
        .get_map("entities")
        .insert("local", b"x".as_slice())
        .unwrap();
    window.doc.commit();
    drop(window);
    let resp = transport::encode_window_sync(
        key,
        window_sub_tags::VV_RESPONSE,
        &loro::VersionVector::new().encode(),
    );
    client.handle_server_message(&resp).unwrap();

    let frames = client.generate_re_bootstrap_sync();

    // Docs dropped: the dirty window is gone, witnesses cleared.
    assert!(client.window(key).is_none(), "window docs must be dropped");
    assert_eq!(client.window_converged(key), None);

    // No hello frame anywhere — pinned wire literal [3, 1] (ONE-1127).
    assert!(
        frames.iter().all(|f| f != &vec![3u8, 1u8]),
        "re-bootstrap must NOT re-send the per-connection protocol hello"
    );

    // Frame 0: root VV — and it must decode to the EMPTY VV (fresh doc).
    assert_eq!(frames[0][0], TAG_VERSION_VECTOR);
    let root_vv = VersionVector::decode(&frames[0][1..]).unwrap();
    assert_eq!(
        root_vv,
        VersionVector::new(),
        "re-bootstrap root VV must be empty — the old root doc must not survive"
    );

    // Frames 1..: VV_REQUEST frames for the default windows (current + prev),
    // NOT for the dropped dirty window.
    assert_eq!(frames.len(), 3, "root VV + 2 default-window VV requests");
    for frame in &frames[1..] {
        assert_eq!(frame[0], TAG_WINDOW_SYNC);
        let (k, sub_tag, payload) = transport::decode_window_sync(&frame[1..]).unwrap();
        assert_ne!(k, key, "dropped window must not be re-requested");
        assert_eq!(sub_tag, window_sub_tags::VV_REQUEST);
        VersionVector::decode(payload).expect("window VV must be Loro binary encoding");
    }
}

#[test]
fn malformed_vv_payloads_fail_closed() {
    // The dead JSON encoding and arbitrary garbage must both be REJECTED
    // with the typed error — never silently treated as an empty VV (an
    // empty-VV fallback would ship the full history to a malformed peer).
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);

    let json_vv: &[u8] = b"{}";
    let garbage: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

    for (index, payload) in [json_vv, garbage].into_iter().enumerate() {
        let key = if index == 0 { "2026-03" } else { "2026-04" };
        let req = transport::encode_window_sync(key, window_sub_tags::VV_REQUEST, payload);
        assert!(
            matches!(
                client.handle_server_message(&req),
                Err(TransportError::VersionVectorDecode)
            ),
            "VV_REQUEST with malformed VV must fail closed"
        );
        assert!(
            client.window(key).is_none(),
            "malformed VV_REQUEST must not open a live window"
        );

        let resp = transport::encode_window_sync(key, window_sub_tags::VV_RESPONSE, payload);
        assert!(
            matches!(
                client.handle_server_message(&resp),
                Err(TransportError::VersionVectorDecode)
            ),
            "VV_RESPONSE with malformed VV must fail closed"
        );
        assert!(
            client.window(key).is_none(),
            "malformed VV_RESPONSE must not open a live window"
        );

        let mut root = vec![TAG_VERSION_VECTOR];
        root.extend_from_slice(payload);
        assert!(
            matches!(
                client.handle_server_message(&root),
                Err(TransportError::VersionVectorDecode)
            ),
            "root VV with malformed payload must fail closed"
        );
    }
}

#[test]
fn ephemeral_frame_applies_and_emits_event() {
    let manager = test_manager();
    let (client_a, mut rx_a) = test_client(&manager);
    let (mut client_b, mut rx_b) = test_client(&manager);

    let msg = client_a
        .set_ephemeral("presence:device-a", "online")
        .unwrap();
    let _ = rx_a.try_recv().expect("local set emits an event");

    let responses = client_b.handle_server_message(&msg).unwrap();
    assert!(
        responses.is_empty(),
        "ephemeral import must not echo an immediate response"
    );
    assert_eq!(
        client_b.ephemeral("presence:device-a"),
        Some("online".into())
    );
    let event = rx_b.try_recv().expect("remote import emits an event");
    assert_matches!(
        event,
        SyncEvent::EphemeralChanged {
            origin: EphemeralChangeOrigin::Remote,
            added,
            updated,
            removed,
        } if added == vec!["presence:device-a".to_string()]
            && updated.is_empty()
            && removed.is_empty()
    );
}

#[test]
fn ephemeral_delete_removes_remote_key() {
    let manager = test_manager();
    let (client_a, mut rx_a) = test_client(&manager);
    let (mut client_b, mut rx_b) = test_client(&manager);
    let key = "presence:device-a";

    let set = client_a.set_ephemeral(key, "online").unwrap();
    let _ = rx_a.try_recv().expect("local set emits an event");
    client_b.handle_server_message(&set).unwrap();
    let _ = rx_b.try_recv().expect("remote set emits an event");
    assert_eq!(client_b.ephemeral(key), Some("online".into()));

    std::thread::sleep(std::time::Duration::from_millis(2));
    let delete = client_a.delete_ephemeral(key).unwrap();
    let _ = rx_a.try_recv().expect("local delete emits an event");
    client_b.handle_server_message(&delete).unwrap();
    assert!(client_b.ephemeral(key).is_none());
    let event = rx_b.try_recv().expect("remote delete emits an event");
    assert_matches!(
        event,
        SyncEvent::EphemeralChanged {
            origin: EphemeralChangeOrigin::Remote,
            added,
            updated,
            removed,
        } if added.is_empty()
            && updated.is_empty()
            && removed == vec![key.to_string()]
    );
}

#[test]
fn client_rejects_non_positive_ephemeral_timeout() {
    let manager = test_manager();
    let result = SyncClient::new(
        manager,
        SyncClientConfig {
            ephemeral_timeout_ms: 0,
            ..Default::default()
        },
    );

    match result {
        Err(Error::SyncProtocolError {
            context:
                SyncProtocolValidation::InvalidConfig {
                    field: SyncConfigField::EphemeralTimeoutMs,
                },
        }) => {}
        Ok(_) => panic!("client construction must reject non-positive ephemeral timeout"),
        Err(err) => panic!("unexpected error: {err}"),
    }
}

#[test]
fn ephemeral_timeout_housekeeping_removes_key() {
    let manager = test_manager();
    let config = SyncClientConfig {
        ephemeral_timeout_ms: 5,
        ..Default::default()
    };
    let (client, mut rx) = SyncClient::new(manager, config).unwrap();
    let key = "presence:device-a";

    let _ = client.set_ephemeral(key, "online").unwrap();
    let _ = rx.try_recv().expect("local set emits an event");

    std::thread::sleep(std::time::Duration::from_millis(10));
    client.remove_outdated_ephemeral();

    assert!(client.ephemeral(key).is_none());
    let event = rx.try_recv().expect("timeout emits an event");
    assert_matches!(
        event,
        SyncEvent::EphemeralChanged {
            origin: EphemeralChangeOrigin::Timeout,
            added,
            updated,
            removed,
        } if added.is_empty()
            && updated.is_empty()
            && removed == vec![key.to_string()]
    );
}

#[test]
fn oversized_root_update_fails_closed() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&vec![0u8; MAX_DECODED_PAYLOAD_BYTES + 1]);

    assert_matches!(client.handle_server_message(&msg), Err(TransportError::FrameTooLarge { size, max })
                if size == MAX_DECODED_PAYLOAD_BYTES + 1 && max == MAX_DECODED_PAYLOAD_BYTES);
}

#[test]
fn oversized_window_update_fails_closed_before_window_open() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let key = "2026-03";
    let update = vec![0u8; MAX_DECODED_PAYLOAD_BYTES + 1];
    let mut msg = vec![TAG_WINDOW_SYNC, key.len() as u8];
    msg.extend_from_slice(key.as_bytes());
    msg.push(window_sub_tags::UPDATE);
    msg.extend_from_slice(&update);

    assert_matches!(
        client.handle_server_message(&msg),
        Err(TransportError::FrameTooLarge { size, max })
            if size == MAX_DECODED_PAYLOAD_BYTES + 1 && max == MAX_DECODED_PAYLOAD_BYTES
    );
    assert!(
        client.window(key).is_none(),
        "oversized ordinary window update must not open a live window"
    );
}

#[test]
fn sync_client_mints_client_id_once_and_keeps_it_stable() {
    let manager = test_manager();
    let (client, _rx) = test_client(&manager);

    let raw = manager
        .vault()
        .sync_state_get(KEY_CLIENT_ID)
        .unwrap()
        .expect("m:client_id must be minted on first client construction");
    assert_eq!(raw.len(), 8, "m:client_id must be u64 LE (8 bytes)");
    let persisted = u64::from_le_bytes(raw.try_into().unwrap());
    assert_ne!(persisted, 0);
    assert_eq!(client.client_id(), persisted);
    assert_eq!(
        client.root_doc().peer_id(),
        persisted,
        "stable client id must pin the root doc's CRDT peer id"
    );

    // Second client over the same vault: same identity, no re-mint.
    let (client2, _rx2) = test_client(&manager);
    assert_eq!(client2.client_id(), persisted);
    assert_eq!(
        manager
            .vault()
            .sync_state_get(KEY_CLIENT_ID)
            .unwrap()
            .unwrap(),
        persisted.to_le_bytes()
    );
}

#[test]
fn sync_client_fails_closed_on_malformed_client_id_row() {
    let manager = test_manager();
    manager
        .vault()
        .sync_state_put(KEY_CLIENT_ID, &[1, 2, 3])
        .unwrap();

    let result = SyncClient::new(Arc::clone(&manager), SyncClientConfig::default());
    assert!(
        matches!(result, Err(Error::CorruptedIndex("sync client_id row"))),
        "malformed m:client_id must not be silently re-minted"
    );
    // The corrupt row is left for diagnosis, not overwritten.
    assert_eq!(
        manager
            .vault()
            .sync_state_get(KEY_CLIENT_ID)
            .unwrap()
            .unwrap(),
        vec![1, 2, 3]
    );
}

#[test]
fn sync_client_fails_closed_on_zero_client_id_row() {
    let manager = test_manager();
    manager
        .vault()
        .sync_state_put(KEY_CLIENT_ID, &0u64.to_le_bytes())
        .unwrap();

    let result = SyncClient::new(Arc::clone(&manager), SyncClientConfig::default());
    assert!(
        matches!(result, Err(Error::CorruptedIndex("sync client_id zero"))),
        "stored zero m:client_id must fail closed, not be silently re-minted"
    );
    // The corrupt row is left for diagnosis, not overwritten.
    assert_eq!(
        manager
            .vault()
            .sync_state_get(KEY_CLIENT_ID)
            .unwrap()
            .unwrap(),
        0u64.to_le_bytes()
    );
}

#[test]
fn sync_client_mark_synced_writes_last_sync_row() {
    let manager = test_manager();
    let (client, _rx) = test_client(&manager);

    assert!(
        manager
            .vault()
            .sync_state_get(KEY_LAST_SYNC)
            .unwrap()
            .is_none()
    );
    client.mark_synced().unwrap();

    let raw = manager
        .vault()
        .sync_state_get(KEY_LAST_SYNC)
        .unwrap()
        .expect("m:last_sync must be written");
    assert_eq!(raw.len(), 8, "m:last_sync must be u64 LE (8 bytes)");
    let ts = u64::from_le_bytes(raw.try_into().unwrap());
    assert!(ts > 1_700_000_000, "timestamp should be wall-clock seconds");
}

#[test]
fn sync_client_filters_invalid_server_windows() {
    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let server_root = create_root_doc(
        "user-1",
        "vault-1",
        &[WindowKey::new("2026-03"), WindowKey::new("2026-04")],
    );
    let windows = root_windows_map(&server_root);
    windows.insert("1969-12", b"1".as_slice()).unwrap();
    windows.insert("2026-13", b"1".as_slice()).unwrap();
    windows.insert("garbage", b"1".as_slice()).unwrap();
    server_root.commit();

    let snapshot = export_snapshot(&server_root).unwrap();
    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&snapshot);
    client.handle_server_message(&msg).unwrap();

    let windows = client.server_windows();
    assert_eq!(windows, vec!["2026-03".to_string(), "2026-04".to_string()]);
}

#[test]
fn persist_root_state_reverts_in_memory_root_on_txn_failure() {
    use crate::sync::loro_support::export_snapshot;
    use crate::sync::schema::create_root_doc;

    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let frontiers_before = client.root_doc.state_frontiers();

    let server_root = create_root_doc("user-1", "vault-1", &[WindowKey::new("2026-03")]);
    let snapshot = export_snapshot(&server_root).unwrap();
    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&snapshot);

    crate::sync::lease::test_hooks::arm_mirror_failure();
    let err = client
        .handle_server_message(&msg)
        .expect_err("injected mirror failure must abort root persistence");
    let TransportError::Storage(message) = err else {
        panic!("expected storage error, got {err:?}");
    };
    assert!(
        message.contains("injected lease mirror failure"),
        "original txn error must surface, got {message}"
    );

    assert_eq!(
        client.root_doc.state_frontiers(),
        frontiers_before,
        "the in-memory root doc must roll back after root persist failure"
    );
    assert!(
        client.server_windows().is_empty(),
        "the imported root window list must not survive the failed persist"
    );
    assert!(
        manager
            .vault()
            .sync_state_get(KEY_ROOT_DOC)
            .unwrap()
            .is_none(),
        "the failed combined txn must not commit d:root"
    );
}

#[test]
fn server_windows_reads_schema_written_root_doc() {
    // Regression for ONE-637: server_windows() must decode meta.windows
    // via the same schema-owned path that create_root_doc uses.
    use crate::sync::loro_support::export_snapshot;
    use crate::sync::schema::create_root_doc;

    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);

    let server_root = create_root_doc(
        "user-1",
        "vault-1",
        &[WindowKey::new("2026-01"), WindowKey::new("2026-02")],
    );
    let snapshot = export_snapshot(&server_root).unwrap();

    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&snapshot);
    client.handle_server_message(&msg).unwrap();

    assert_eq!(
        client.server_windows(),
        vec!["2026-01".to_string(), "2026-02".to_string()],
    );
}

#[test]
fn server_windows_reads_legacy_encoded_root_doc() {
    use crate::sync::loro_support::export_snapshot;

    let manager = test_manager();
    let (mut client, _rx) = test_client(&manager);
    let server_root = LoroDoc::new();
    server_root
        .get_map("meta")
        .insert(
            crate::sync::schema::ROOT_WINDOWS_KEY,
            b"2026-02,2026-01,bad,2026-01".as_slice(),
        )
        .unwrap();
    server_root.commit();
    let snapshot = export_snapshot(&server_root).unwrap();

    let mut msg = vec![TAG_SYNC_UPDATE];
    msg.extend_from_slice(&snapshot);
    client.handle_server_message(&msg).unwrap();

    assert_eq!(
        client.server_windows(),
        vec!["2026-01".to_string(), "2026-02".to_string()],
    );
}

#[test]
fn backoff_calculation() {
    assert_eq!(next_backoff(1_000, 60_000), 2_000);
    assert_eq!(next_backoff(2_000, 60_000), 4_000);
    assert_eq!(next_backoff(32_000, 60_000), 60_000);
    assert_eq!(next_backoff(60_000, 60_000), 60_000);
}
