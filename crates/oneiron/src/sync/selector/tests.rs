use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::{CommitOptions, ExportMode, LoroDoc};

use super::*;
use crate::affect::Vad;
use crate::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, AuthorityAttestation, AuthorityKey, AuthorityLogEntry,
    AuthoritySignature, AuthoritySignatureSuite, AuthorityTier, DeviceAuthority, ROLE_ADMIN,
    ROLE_OWNER, authority_transcript, encode_authority_log_entry_body,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    decode_claim_body, encode_claim_body,
};
use crate::companion::{
    CompanionProvenance, CompanionRecord, CompanionScope, ENTITY_TYPE_COMPANION_REGISTER,
    encode_companion_record_body,
};
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body, encode_guest_share_envelope, encode_guest_share_envelope_body,
};
use crate::provenance::{
    EdgeProvenanceClaimBody, SupersessionStatus, encode_actor_class_evidence,
    encode_edge_provenance_value,
};
use crate::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_WORLD,
};
use crate::store::Store;
use crate::sync::bridge::{BRIDGE_ORIGIN, encode_edge_value_for_crdt};
use crate::sync::client::{SyncClient, SyncClientConfig};
use crate::sync::loro_support::map_get_bytes;
use crate::sync::manager::WindowManager;
use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
use crate::temporal::TimeRange;

fn entity_id(byte: u8) -> EntityId {
    crate::test_util::entity(byte)
}

fn local_world_id(byte: u8) -> LocalWorldId {
    LocalWorldId::from_entity_id(entity_id(byte)).unwrap()
}

fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
    crate::test_util::entity_record(entity_type, TimeRange { start: 1, end: 1 }, 1, body)
}

fn authority_genesis_entry(seed: u8) -> AuthorityLogEntry {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let op = AuthorityOp::Genesis {
        device: DeviceAuthority {
            key: key.clone(),
            transport_key_binding: [7; 32],
            attestation: AuthorityAttestation {
                kind: "SoftwareArgon2id".to_owned(),
                evidence: vec![1, 2, 3],
            },
            tier: AuthorityTier::Software,
            roles: ROLE_OWNER | ROLE_ADMIN,
        },
        genesis_nonce: [seed.wrapping_add(1); 32],
        tier_floor: AuthorityTier::Software,
        pending_widen_delay_secs: 86_400,
    };
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op,
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

fn claim_blob(world: Option<EntityId>) -> Vec<u8> {
    let mut claim = ClaimBody::new(
        "selector.test",
        ClaimSubject::Entity(entity_id(0x90)),
        Value::from("value"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    claim.world = world;
    entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap())
}

/// `claim_blob` with an explicit `sensitivity: public` (band 0) stamp, for
/// fixtures that cross FEDERATED ADMISSION rather than being handed straight
/// to the selector. The ONE-1645 provenance floor makes an UNSTAMPED claim read
/// band 2, which exceeds the `max_auto_sensitivity: 0` Imported row
/// `put_imported_source_trust` installs, so an unstamped claim would queue for
/// consent instead of admitting — a detour past the facet-scoping behavior
/// those fixtures exist to exercise.
fn public_claim_blob() -> Vec<u8> {
    let mut claim = ClaimBody::new(
        "selector.test",
        ClaimSubject::Entity(entity_id(0x90)),
        Value::from("value"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    claim.scope = Some(Value::Map(vec![(
        Value::from("sensitivity"),
        Value::from("public"),
    )]));
    entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap())
}

fn edge_provenance_claim_blob() -> Vec<u8> {
    let confidence = 0.75_f32;
    let record =
        EdgeProvenanceClaimBody::new(entity_id(0x5A), confidence, SupersessionStatus::Confirmed);
    let mut claim = ClaimBody::new(
        crate::provenance::PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::Edge {
            source: entity_id(0x5B),
            kind: EdgeKind::Mentions,
            target: entity_id(0xD6),
        },
        encode_edge_provenance_value(&record),
        confidence,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    claim.evidence = Some(encode_actor_class_evidence(EdgeActorClass::Human));
    claim.source = Some(ClaimSource::ToolOutput);
    // Explicit `sensitivity: public` (band 0). The ONE-1645 provenance floor
    // makes an UNSTAMPED claim read band 2, which exceeds the
    // `max_auto_sensitivity: 0` Imported row `put_imported_source_trust`
    // installs — the admission would queue for consent. The two fixtures using
    // this blob test RESERVED-PREDICATE ADMISSION and duplicate-frame byte
    // identity, not the sensitivity ceiling, so the stamp keeps them on the
    // path they exist to exercise.
    claim.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap())
}

fn companion_record_body(
    persona_ref: EntityId,
    export_classification: CompanionExportClassification,
) -> Vec<u8> {
    companion_record_body_in_scope(
        persona_ref,
        CompanionScope::neutral(),
        export_classification,
    )
}

fn companion_record_body_in_scope(
    persona_ref: EntityId,
    scope: CompanionScope,
    export_classification: CompanionExportClassification,
) -> Vec<u8> {
    companion_record_body_in_scope_with_lifecycle(
        persona_ref,
        scope,
        export_classification,
        ClaimLifecycleStatus::Active,
    )
}

fn companion_record_body_in_scope_with_lifecycle(
    persona_ref: EntityId,
    scope: CompanionScope,
    export_classification: CompanionExportClassification,
    lifecycle: ClaimLifecycleStatus,
) -> Vec<u8> {
    let mut record = CompanionRecord::persona(
        scope,
        persona_ref,
        Value::from("private companion tuning"),
        CompanionProvenance::new(
            entity_id(0xB8),
            EdgeActorClass::Agent,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            Value::from("private provenance"),
        ),
        export_classification,
    );
    record.lifecycle = lifecycle;
    match lifecycle {
        ClaimLifecycleStatus::Active => {
            record = record.created_at(1_772_400_000).unwrap();
        }
        ClaimLifecycleStatus::Superseded => {
            let ev = crate::companion::CompanionLifecycleEvent::superseded(1_772_400_000);
            record.lifecycle_events.push(ev);
        }
        ClaimLifecycleStatus::Retracted => {
            let ev = crate::companion::CompanionLifecycleEvent::retired(1_772_400_000);
            record.lifecycle_events.push(ev);
        }
    }
    encode_companion_record_body(&record).unwrap()
}

fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (Value::from("schema_version"), Value::from("1.1")),
        (Value::from("pack_id"), Value::from("selector-test")),
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
        (Value::from("rules"), Value::Array(vec![])),
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
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).unwrap();
    out
}

fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
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

fn put_imported_source_trust(vault: &Vault) {
    let body = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
    let id = entity_id(0xA7);
    let payload = entity_blob(ENTITY_TYPE_POLICY_MANIFEST, &body);
    vault
        .with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
        .unwrap();
}

fn insert_entity(doc: &LoroDoc, id: EntityId, entity_type: u8, body: &[u8]) {
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(entity_type, body),
    )
    .unwrap();
}

fn insert_blob(doc: &LoroDoc, id: EntityId, blob: &[u8]) {
    map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), blob).unwrap();
}

fn edge_key(src: EntityId, kind: EdgeKind, tgt: EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}

fn insert_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
    let value = encode_edge_value_for_crdt(kind, 0.7, 1, Some(Vad::NEUTRAL), None).unwrap();
    map_insert_bytes(&doc.get_map("edges"), &edge_key(src, kind, tgt), &value).unwrap();
}

fn insert_malformed_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
    doc.get_map("edges")
        .insert(edge_key(src, kind, tgt).as_str(), "not-binary")
        .unwrap();
}

fn insert_tombstone(doc: &LoroDoc, id: EntityId) {
    map_insert_bytes(&doc.get_map("tombstones"), &id.to_hex(), b"deleted").unwrap();
}

fn insert_uppercase_tombstone_alias(doc: &LoroDoc, id: EntityId) {
    map_insert_bytes(
        &doc.get_map("tombstones"),
        &id.to_hex().to_ascii_uppercase(),
        b"deleted",
    )
    .unwrap();
}

fn import_ids(update: &[u8]) -> Vec<EntityId> {
    let doc = create_window_doc("receiver", &WindowKey::new("2026-03"));
    doc.import(update).unwrap();
    let mut ids = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, value| {
        if value.is_some() {
            ids.push(EntityId::from_hex(key).unwrap());
        }
    });
    ids.sort_unstable();
    ids
}

fn imported_entity_type_count(update: &[u8], entity_type: u8) -> usize {
    let doc = create_window_doc("receiver", &WindowKey::new("2026-03"));
    doc.import(update).unwrap();
    let mut count = 0;
    map_for_each_value_bytes(&doc.get_map("entities"), |_, value| {
        let Some(blob) = value else {
            return;
        };
        if EntityMetadataHeader::parse(blob).is_some_and(|header| header.entity_type == entity_type)
        {
            count += 1;
        }
    });
    count
}

fn imported_tombstone_count(update: &[u8]) -> usize {
    let doc = create_window_doc("receiver", &WindowKey::new("2026-03"));
    doc.import(update).unwrap();
    let mut count = 0;
    map_for_each_tombstone_value(&doc.get_map("tombstones"), |_, _| {
        count += 1;
    });
    count
}

fn decode_msgpack_value(bytes: &[u8]) -> Value {
    let mut cursor = std::io::Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode MessagePack value");
    assert_eq!(cursor.position(), bytes.len() as u64);
    value
}

fn assert_no_forbidden_envelope_keys(value: &Value) {
    const FORBIDDEN: &[&str] = &[
        "membership",
        "memberships",
        "membership_count",
        "roster",
        "authority_roster",
        "roster_count",
        "topology",
        "topology_count",
        "count",
    ];

    match value {
        Value::Array(values) => {
            for value in values {
                assert_no_forbidden_envelope_keys(value);
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                if let Some(key) = key.as_str() {
                    assert!(
                        !FORBIDDEN.contains(&key),
                        "guest-share envelope leaked forbidden key `{key}`"
                    );
                }
                assert_no_forbidden_envelope_keys(value);
            }
        }
        _ => {}
    }
}

fn test_selector_scope() -> FederationGrantScope {
    FederationGrantScope::vault(7)
}

fn put_test_grant(vault: &Vault, member_ref: EntityId, scope: FederationGrantScope) -> EntityId {
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        scope,
        member_ref,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let body = encode_federation_grant_body(&grant).unwrap();
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .commit()
        .unwrap();
    grant_id
}

fn test_vault_with_grant_scope(
    member_ref: EntityId,
    scope: FederationGrantScope,
) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let grant_id = put_test_grant(&vault, member_ref, scope);
    (dir, vault, grant_id)
}

fn test_vault_with_grant(member_ref: EntityId) -> (tempfile::TempDir, Vault, EntityId) {
    test_vault_with_grant_scope(member_ref, test_selector_scope())
}

/// The PRODUCTION federation ingest stack: a real [`SyncClient`] over a real
/// [`WindowManager`], so an import lands through
/// `SyncClient::import_federated_window_update` into a LOADED window and
/// materializes through Observer B exactly as it does in the field.
fn test_client_with_grant(
    member_ref: EntityId,
    window: &str,
) -> (tempfile::TempDir, Arc<Vault>, EntityId, SyncClient) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), crate::VaultConfig::device()).unwrap());
    let grant_id = put_test_grant(&vault, member_ref, test_selector_scope());
    let manager = Arc::new(WindowManager::new(
        Arc::clone(&vault),
        Arc::new(crate::sync::bridge::Materializer::new()),
        "selector-test",
    ));
    let (client, _rx) = SyncClient::new(manager, SyncClientConfig::default()).unwrap();
    // LOADED, not cold: this is the arm a federated import materializes
    // through synchronously.
    client.ensure_window(window).unwrap();
    (dir, vault, grant_id, client)
}

/// Admits `doc` through the production federated entry for `role`.
fn import_federated(
    client: &mut SyncClient,
    window: &str,
    doc: &LoroDoc,
    role: FederationAdmissionRole,
) {
    let update = doc.export(ExportMode::all_updates()).unwrap();
    client
        .import_federated_window_update(window, &update, role)
        .unwrap_or_else(|e| panic!("{role:?}: federated import must not fail closed: {e:?}"));
}

#[test]
fn selector_codec_round_trips_strict_payload() {
    let selector = SyncSelector::new(
        entity_id(0x50),
        entity_id(0xB1),
        SyncSelectorWorld::World(local_world_id(0xC1)),
        vec![entity_id(0xD1), entity_id(0xD1)],
        vec![
            TypeByteBand::Core,
            TypeByteBand::Semantic,
            TypeByteBand::Core,
        ],
    );
    let payload = encode_selector_vv_request(&selector, b"vv").unwrap();
    let decoded = decode_selector_vv_request(&payload).unwrap();
    assert_eq!(decoded.selector, selector);
    assert_eq!(decoded.remote_vv, b"vv");

    let mut trailing = encode_sync_selector(&selector).unwrap();
    trailing.push(0);
    assert!(decode_sync_selector(&trailing).is_err());

    let unsupported_version = Value::Map(vec![
        (Value::from(KEY_SCHEMA_VERSION), Value::from(2_u64)),
        (
            Value::from(KEY_GRANT_ID),
            Value::from(selector.grant_id.to_hex()),
        ),
        (
            Value::from(KEY_MEMBER_REF),
            Value::from(selector.member_ref.to_hex()),
        ),
        (Value::from(KEY_WORLD), encode_world(selector.world)),
        (
            Value::from(KEY_FACETS),
            Value::Array(
                selector
                    .facets
                    .iter()
                    .map(|facet| Value::from(facet.to_hex()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_BANDS),
            Value::Array(
                selector
                    .bands
                    .iter()
                    .map(|band| Value::from(band_to_wire(*band)))
                    .collect(),
            ),
        ),
    ]);
    let mut unsupported = Vec::new();
    rmpv::encode::write_value(&mut unsupported, &unsupported_version).unwrap();
    assert!(decode_sync_selector(&unsupported).is_err());
}

#[test]
fn selector_decode_rejects_foreign_world_id_range() {
    let selector = SyncSelector::new(
        entity_id(0x50),
        entity_id(0xB1),
        SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let mut decoded =
        match rmpv::decode::read_value(&mut Cursor::new(encode_sync_selector(&selector).unwrap()))
            .unwrap()
        {
            Value::Map(entries) => entries,
            other => panic!("selector must encode as map, got {other:?}"),
        };
    for (key, value) in &mut decoded {
        if key.as_str() == Some(KEY_WORLD) {
            *value = Value::Map(vec![
                (Value::from(WORLD_KEYS[0]), Value::from(WORLD_KIND_WORLD)),
                (
                    Value::from(WORLD_KEYS[1]),
                    Value::from(entity_id(0xF1).to_hex()),
                ),
            ]);
        }
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(decoded)).unwrap();

    let err = decode_sync_selector(&bytes).expect_err("foreign world id must be rejected");

    assert!(matches!(
        err,
        Error::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: SelectorError::ForeignWorldId
            }
        }
    ));
}

#[test]
fn federated_admission_rejects_maintenance_band_non_claim_entities() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0x54));
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(
        &doc,
        entity_id(0x59),
        ENTITY_TYPE_POLICY_MANIFEST,
        b"remote-policy",
    );
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let err = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect_err("federated maintenance-band non-claims must fail closed");
    assert!(matches!(
        err,
        Error::MaintenanceKindNotWritable(ENTITY_TYPE_POLICY_MANIFEST)
    ));
}

#[test]
fn federated_admission_rejects_classification_routed_maintenance_kinds() {
    // ARCH-0055 / MS-01: IDENTITY_TOPOLOGY_EVENT (76) is
    // Maintenance-CLASSIFIED inside the Companion BAND, so the pre-fix
    // band-only check admitted a member/guest-authored type-76 blob —
    // single-writer ledger authority handed to a federated peer.
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0x54));
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(
        &doc,
        entity_id(0x59),
        crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT,
        b"guest-forged-topology-event",
    );
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let err = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect_err("classification-routed maintenance kinds must fail closed");
    assert!(matches!(
        err,
        Error::MaintenanceKindNotWritable(crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
    ));
}

#[test]
fn federated_admission_rejects_reserved_edge_kinds() {
    // The edges map was copied byte-for-byte pre-fix: a guest could inject
    // (X, merged_into, Y) and materialization would derive a real redirect
    // shell with no type-76 event behind it.
    for kind in [EdgeKind::MergedInto, EdgeKind::SplitInto] {
        let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0x54));
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("remote", &window_key);
        insert_edge(&doc, entity_id(0xB1), kind, entity_id(0xB2));
        doc.commit();
        let update = doc.export(ExportMode::all_updates()).unwrap();

        let err = admit_federated_window_update(
            &vault,
            &window_key,
            &update,
            FederationAdmissionRole::Guest,
        )
        .expect_err("reserved-kind federated edges must fail closed");
        assert!(matches!(err, Error::ReservedEdgeKind(_)));
    }
}

#[test]
fn federated_admission_rejects_foreign_authority_log() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xB2));
    let local = authority_genesis_entry(0x51);
    vault
        .put_authority_log_entry(&local, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();

    let foreign = authority_genesis_entry(0x52);
    let foreign_body = encode_authority_log_entry_body(&foreign).unwrap();
    // The row carries its own CORRECT content-derived id, so the store-key
    // bind passes and the FOREIGN-ROOT rejection is what is actually under
    // test (the key bind precedes the vault-id fold check, mirroring the
    // write door's ordering in `batch.rs`).
    let foreign_id = authority_log_entity_id(&foreign).unwrap();
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(&doc, foreign_id, ENTITY_TYPE_AUTHORITY_LOG, &foreign_body);
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let err = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect_err("foreign authority roots must not enter admitted federation updates");
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidAuthorityLogBody);
}

/// ONE-1604-D1 (fix-leg 4, admission door): admission validated the type-122
/// BODY and the vault root but never bound the CRDT row's KEY to the id
/// derived from that body. A wrong-key authority row therefore entered the
/// ADMITTED doc — the bytes the ordinary replay path imports — and only
/// failed later at materialize, after this door had already re-authored it
/// under a federation-admission origin. The bind is the same content-address
/// rule `check_authority_log_store_key` enforces at the write door.
#[test]
fn federated_admission_rejects_wrong_key_authority_row() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xB3));
    let local = authority_genesis_entry(0x55);
    vault
        .put_authority_log_entry(&local, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();

    // A row whose body is fully valid AND shares the local vault root, so
    // every other admission check passes: only the key is wrong.
    let body = encode_authority_log_entry_body(&local).unwrap();
    let derived = authority_log_entity_id(&local).unwrap();
    let wrong_key = entity_id(0xEE);
    assert_ne!(wrong_key, derived, "the fixture key must genuinely differ");

    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(&doc, wrong_key, ENTITY_TYPE_AUTHORITY_LOG, &body);
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let err = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect_err("a wrong-key authority row must not reach the admitted doc");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::AuthorityLogStoreKeyMismatch
    );
    // H2: the typed reason is a REMOTE rejection, so the replay sites
    // quarantine-and-continue instead of aborting the whole window.
    assert!(
        crate::sync::quarantine::remote_rejection_reason(&err).is_some(),
        "the bind must reject remotely, never as a local fail-closed error"
    );
}

/// The healing half of the bind: a CORRECT-key authority row sharing the
/// local vault root still admits and reaches the admitted doc byte-for-byte.
/// Without this, a bind that rejected everything would look identical to a
/// bind that works.
#[test]
fn federated_admission_admits_correct_key_authority_row() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xB4));
    let local = authority_genesis_entry(0x56);
    vault
        .put_authority_log_entry(&local, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();

    let body = encode_authority_log_entry_body(&local).unwrap();
    let derived = authority_log_entity_id(&local).unwrap();
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(&doc, derived, ENTITY_TYPE_AUTHORITY_LOG, &body);
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("a correct-key authority row must heal normally");

    let receiver = create_window_doc("receiver", &window_key);
    receiver.import(&admitted).unwrap();
    let blob = map_get_bytes(&receiver.get_map("entities"), &derived.to_hex())
        .expect("admitted authority row");
    assert_eq!(
        &blob[ENTITY_METADATA_HEADER_LEN..],
        body.as_slice(),
        "the admitted authority body must pass through unchanged"
    );
}

#[test]
fn federated_admission_allows_reserved_edge_provenance_claim_with_imported_trust() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xA8));
    put_imported_source_trust(&vault);
    let window_key = WindowKey::new("2026-03");
    let claim_id = entity_id(0xA9);
    let doc = create_window_doc("remote", &window_key);
    insert_blob(&doc, claim_id, &edge_provenance_claim_blob());
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("valid reserved provenance claim should admit under imported trust");

    let receiver = create_window_doc("receiver", &window_key);
    receiver.import(&admitted).unwrap();
    let blob = map_get_bytes(&receiver.get_map("entities"), &claim_id.to_hex())
        .expect("admitted provenance claim");
    let body = decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true).unwrap();
    assert_eq!(body.predicate, crate::provenance::PREDICATE_EDGE_PROVENANCE);
    assert_eq!(body.source, Some(ClaimSource::Imported));
}

#[test]
fn federated_admission_duplicate_frame_is_byte_identical() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xAA));
    put_imported_source_trust(&vault);
    let window_key = WindowKey::new("2026-03");
    let claim_id = entity_id(0xAB);
    let doc = create_window_doc("remote", &window_key);
    insert_blob(&doc, claim_id, &edge_provenance_claim_blob());
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();

    let first =
        admit_federated_window_update(&vault, &window_key, &update, FederationAdmissionRole::Guest)
            .expect("first admission");
    let second =
        admit_federated_window_update(&vault, &window_key, &update, FederationAdmissionRole::Guest)
            .expect("duplicate admission");
    assert_eq!(
        second, first,
        "same role/window/update must produce byte-identical admitted updates"
    );
}

#[test]
fn selected_window_omits_other_facets_and_keeps_closed_edges() {
    let member = entity_id(0x31);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);

    let facet_allowed = entity_id(0x50);
    let facet_denied = entity_id(0xB1);
    let claim_allowed = entity_id(0x60);
    let claim_denied = entity_id(0x12);
    let person = entity_id(0x21);
    let denied_only_person = entity_id(0x22);
    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, claim_allowed, &claim_blob(None));
    insert_blob(&doc, claim_denied, &claim_blob(None));
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(
        &doc,
        denied_only_person,
        ENTITY_TYPE_PERSON,
        b"denied-only-person",
    );
    insert_edge(&doc, claim_allowed, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, claim_denied, EdgeKind::FacetOf, facet_denied);
    insert_edge(&doc, claim_allowed, EdgeKind::Supports, person);
    insert_edge(&doc, claim_denied, EdgeKind::Supports, person);
    insert_edge(&doc, claim_denied, EdgeKind::Supports, denied_only_person);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let filtered =
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).unwrap();
    let update = filtered.export(ExportMode::all_updates()).unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&claim_allowed));
    assert!(ids.contains(&facet_allowed));
    assert!(ids.contains(&person));
    assert!(
        !ids.contains(&claim_denied),
        "unauthorized facet claim leaked"
    );
    assert!(
        !ids.contains(&facet_denied),
        "unreferenced denied facet entity leaked"
    );
    assert!(
        !ids.contains(&denied_only_person),
        "non-faceted neighbor reachable only from a denied facet leaked"
    );

    let receiver = create_window_doc("receiver", &window_key);
    receiver.import(&update).unwrap();
    let mut edge_count = 0;
    map_for_each_value_bytes(&receiver.get_map("edges"), |_, value| {
        if value.is_some() {
            edge_count += 1;
        }
    });
    assert_eq!(
        edge_count, 2,
        "only edges whose endpoints survived the selector should replicate"
    );
}

#[test]
fn envelope_strips_membership() {
    let member = entity_id(0x31);
    let other_member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);

    let person = entity_id(0x21);
    let membership = entity_id(0x41);
    let other_grant = FederationGrant::new(
        test_selector_scope(),
        other_member,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let grant_body = encode_federation_grant_body(&other_grant).unwrap();
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(&doc, membership, ENTITY_TYPE_FEDERATION_GRANT, &grant_body);
    insert_edge(&doc, person, EdgeKind::Supports, membership);
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let envelope = guest_share_envelope(
        &vault,
        &doc,
        &window_key,
        test_selector_scope(),
        &selector,
        |_| Ok(vec![0xA5]),
    )
    .unwrap();
    let ids = import_ids(&envelope.body.update);

    assert!(ids.contains(&person));
    assert!(
        !ids.contains(&membership),
        "guest-share envelope leaked a federation membership record"
    );

    let receiver = create_window_doc("receiver", &window_key);
    receiver.import(&envelope.body.update).unwrap();
    let mut leaked_membership_edge = false;
    map_for_each_value_bytes(&receiver.get_map("edges"), |key, value| {
        if value.is_some() && key.contains(&membership.to_hex()) {
            leaked_membership_edge = true;
        }
    });
    assert!(
        !leaked_membership_edge,
        "guest-share envelope leaked topology adjacent to a membership record"
    );
}

#[test]
fn no_topology_count_in_envelope() {
    let member = entity_id(0x33);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);

    let person = entity_id(0x22);
    let authority_id = entity_id(0x52);
    let authority_body = encode_authority_log_entry_body(&authority_genesis_entry(0x52))
        .expect("encode authority log");
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(
        &doc,
        authority_id,
        ENTITY_TYPE_AUTHORITY_LOG,
        &authority_body,
    );
    insert_edge(&doc, person, EdgeKind::Supports, authority_id);
    insert_tombstone(&doc, entity_id(0x62));
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let envelope = guest_share_envelope(
        &vault,
        &doc,
        &window_key,
        test_selector_scope(),
        &selector,
        |_| Ok(vec![0x5A]),
    )
    .unwrap();

    let encoded_envelope = encode_guest_share_envelope(&envelope).unwrap();
    let encoded_body = encode_guest_share_envelope_body(&envelope.body).unwrap();
    assert_no_forbidden_envelope_keys(&decode_msgpack_value(&encoded_envelope));
    assert_no_forbidden_envelope_keys(&decode_msgpack_value(&encoded_body));
    assert_eq!(
        imported_entity_type_count(&envelope.body.update, ENTITY_TYPE_AUTHORITY_LOG),
        0,
        "guest-share envelope leaked authority-roster/topology records"
    );
    assert_eq!(
        imported_tombstone_count(&envelope.body.update),
        0,
        "guest-share envelope leaked tombstone topology counts"
    );
}

#[test]
fn strip_happens_before_sign() {
    let member = entity_id(0x34);
    let other_member = entity_id(0x35);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);

    let person = entity_id(0x23);
    let membership = entity_id(0x43);
    let authority_id = entity_id(0x53);
    let other_grant = FederationGrant::new(
        test_selector_scope(),
        other_member,
        FederationGrantRole::Viewer,
        FederationGrantPreset::ReadOnly,
    );
    let grant_body = encode_federation_grant_body(&other_grant).unwrap();
    let authority_body = encode_authority_log_entry_body(&authority_genesis_entry(0x53))
        .expect("encode authority log");
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(&doc, membership, ENTITY_TYPE_FEDERATION_GRANT, &grant_body);
    insert_entity(
        &doc,
        authority_id,
        ENTITY_TYPE_AUTHORITY_LOG,
        &authority_body,
    );
    insert_edge(&doc, person, EdgeKind::Supports, membership);
    insert_edge(&doc, person, EdgeKind::Supports, authority_id);
    insert_tombstone(&doc, entity_id(0x63));
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let signed_transcript = std::cell::RefCell::new(Vec::new());
    let envelope = guest_share_envelope(
        &vault,
        &doc,
        &window_key,
        test_selector_scope(),
        &selector,
        |transcript| {
            signed_transcript.borrow_mut().extend_from_slice(transcript);
            Ok(blake3::hash(transcript).as_bytes().to_vec())
        },
    )
    .unwrap();

    let signed_transcript = signed_transcript.into_inner();
    let encoded_body = encode_guest_share_envelope_body(&envelope.body).unwrap();
    assert_eq!(
        signed_transcript, encoded_body,
        "signature transcript must be the stripped guest-share body"
    );
    assert_eq!(
        envelope.signature,
        blake3::hash(&encoded_body).as_bytes().to_vec()
    );
    assert_no_forbidden_envelope_keys(&decode_msgpack_value(&signed_transcript));

    let ids = import_ids(&envelope.body.update);
    assert!(ids.contains(&person));
    assert!(!ids.contains(&membership));
    assert!(!ids.contains(&authority_id));
    assert_eq!(imported_tombstone_count(&envelope.body.update), 0);
}

#[test]
fn companion_register_api_selector_suppresses_local_only_records() {
    let member = entity_id(0x39);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);

    let local_id = entity_id(0x3A);
    let portable_id = entity_id(0x3B);
    let shared_id = entity_id(0x3C);
    let other_shared_id = entity_id(0x3D);
    let retired_portable_id = entity_id(0x3E);
    insert_entity(
        &doc,
        local_id,
        ENTITY_TYPE_COMPANION_REGISTER,
        &companion_record_body(local_id, CompanionExportClassification::LocalOnly),
    );
    insert_entity(
        &doc,
        portable_id,
        ENTITY_TYPE_COMPANION_REGISTER,
        &companion_record_body(portable_id, CompanionExportClassification::Portable),
    );
    insert_entity(
        &doc,
        shared_id,
        ENTITY_TYPE_COMPANION_REGISTER,
        &companion_record_body_in_scope(
            shared_id,
            CompanionScope::shared_vault(7),
            CompanionExportClassification::SharedVault,
        ),
    );
    insert_entity(
        &doc,
        other_shared_id,
        ENTITY_TYPE_COMPANION_REGISTER,
        &companion_record_body_in_scope(
            other_shared_id,
            CompanionScope::shared_vault(8),
            CompanionExportClassification::SharedVault,
        ),
    );
    insert_entity(
        &doc,
        retired_portable_id,
        ENTITY_TYPE_COMPANION_REGISTER,
        &companion_record_body_in_scope_with_lifecycle(
            retired_portable_id,
            CompanionScope::neutral(),
            CompanionExportClassification::Portable,
            ClaimLifecycleStatus::Retracted,
        ),
    );
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![],
        vec![TypeByteBand::Companion],
    );
    let filtered =
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).unwrap();
    let entities = filtered.get_map("entities");
    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "selector export must not include local-only companion register records"
    );
    assert!(
        map_get_bytes(&entities, &portable_id.to_hex()).is_some(),
        "selector export should keep syncable companion register records"
    );
    assert!(
        map_get_bytes(&entities, &shared_id.to_hex()).is_some(),
        "selector export should keep companion records for the authorized shared vault"
    );
    assert!(
        map_get_bytes(&entities, &other_shared_id.to_hex()).is_none(),
        "selector export must not include another shared vault's companion register records"
    );
    assert!(
        map_get_bytes(&entities, &retired_portable_id.to_hex()).is_some(),
        "selector export should propagate portable companion retirement records"
    );
}

#[test]
fn selector_denies_entity_with_any_unselected_facet_of() {
    let member = entity_id(0x39);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-09");
    let doc = create_window_doc("source", &window_key);

    let facet_allowed = entity_id(0xA9);
    let facet_denied = entity_id(0xB9);
    let dual_facet_claim = entity_id(0x19);
    let person = entity_id(0x29);

    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, dual_facet_claim, &claim_blob(None));
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_edge(&doc, dual_facet_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, dual_facet_claim, EdgeKind::FacetOf, facet_denied);
    insert_edge(&doc, dual_facet_claim, EdgeKind::Supports, person);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&facet_allowed));
    assert!(
        !ids.contains(&dual_facet_claim),
        "an entity with any unselected FacetOf must fail closed"
    );
    assert!(
        !ids.contains(&facet_denied),
        "unselected facet entity leaked"
    );
    assert!(
        !ids.contains(&person),
        "neighbors of a denied dual-facet entity leaked"
    );
}

/// The federation door is disclosure-effective for EVERY `FacetOf` source
/// type, not just CLAIM. `facet_scope_by_source` builds a scope for every
/// `FacetOf` source with no source-type check, and `entity_selector_decision`
/// withholds an unselected-scoped entity of ANY type — so an EVENT stamped to
/// a facet this peer did not select is withheld, and the same EVENT restamped
/// to a selected facet replicates.
///
/// This is the behavior ONE-1646's exposure-consent gate keys on: the gate
/// covers `CLAIM | TURN | EVENT` precisely because each is effective on at
/// least one door, and EVENT's door is this one (it is inert on the local
/// query filter, which reads CLAIM adjacency only). If the selector ever grows
/// a source-type check for facet scoping — the design question deferred to
/// S-DISC2 — ONE-1646's gate table must be re-derived, and this test is the
/// tripwire that will fail first.
#[test]
fn selector_denies_event_scoped_to_unselected_facet() {
    let member = entity_id(0x3C);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-11");

    let facet_selected = entity_id(0xAC);
    let facet_unselected = entity_id(0xBC);
    let event = entity_id(0x1C);
    let claim_seed = entity_id(0x2C);

    // Arm 1: EVENT stamped to a facet the peer did NOT select. The EVENT is
    // adjacent to a CLAIM that IS scoped to the selected facet, so closure
    // WOULD pull it into the export — absence therefore proves the facet-scope
    // gate withheld it, not that it was merely unreachable. This is what makes
    // the test a tripwire: were `facet_scope_by_source` to skip EVENT sources,
    // the EVENT would become an unscoped candidate and leak through closure.
    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_unselected, ENTITY_TYPE_FACET, b"facet-b");
    insert_entity(&doc, event, ENTITY_TYPE_EVENT, b"event");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_selected);
    insert_edge(&doc, event, EdgeKind::FacetOf, facet_unselected);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, event);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&facet_selected));
    assert!(
        ids.contains(&claim_seed),
        "control: the selected-facet claim must seed closure, or the EVENT \
         assertion below would hold vacuously"
    );
    assert!(
        !ids.contains(&event),
        "an EVENT scoped only to an unselected facet must be withheld even when \
         a selected-facet seed is adjacent: EVENT-sourced FacetOf is \
         disclosure-effective on the federation door"
    );
    assert!(
        !ids.contains(&facet_unselected),
        "unselected facet entity leaked"
    );

    // Arm 2: the same EVENT restamped to the SELECTED facet replicates.
    let restamped = create_window_doc("source", &window_key);
    insert_entity(&restamped, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&restamped, facet_unselected, ENTITY_TYPE_FACET, b"facet-b");
    insert_entity(&restamped, event, ENTITY_TYPE_EVENT, b"event");
    insert_edge(&restamped, event, EdgeKind::FacetOf, facet_selected);
    restamped.commit();

    let update = filtered_window_doc(
        &vault,
        &restamped,
        &window_key,
        test_selector_scope(),
        &selector,
    )
    .unwrap()
    .export(ExportMode::all_updates())
    .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&event),
        "an EVENT scoped to the selected facet must replicate"
    );
    assert!(ids.contains(&facet_selected));
    assert!(
        !ids.contains(&facet_unselected),
        "unselected facet entity leaked on the restamped arm"
    );
}

/// ONE-1645 RESIDUE REGRESSION — the pin that proves the ADMISSION BOUNDARY,
/// not merely the replay gate.
///
/// The gate above (`window::forward_rematerialize`) stops an off-table stamp
/// from reaching LMDB. That is not the exposure. `facet_scope_by_source` reads
/// the RAW Loro edges map with no source-type check, so a forged
/// `PERSON -> <selected FACET>` row that merely SITS in the admitted / live
/// document still seeds facet scope — quarantined or not, LMDB never consulted.
/// Only dropping the row at the trust boundary closes it.
///
/// The exercise is end-to-end on purpose: forge into a peer window, run the
/// REAL admission door, forward-rematerialize, then filter THAT SAME document
/// for a facet-limited peer. The one-hop neighbor's ONLY adjacency is to the
/// forged seed, so its presence in the export would prove the seed still
/// scopes closure; the EVENT control is stamped to the same selected facet, so
/// its ABSENCE would prove the fix broke facet scoping instead of the forgery.
#[test]
fn forged_facet_seed_cannot_move_entities_across_the_disclosure_boundary() {
    let member = entity_id(0x3D);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");

    let facet_selected = entity_id(0xAD);
    let person = entity_id(0x1D);
    let neighbor = entity_id(0x2D);
    let event = entity_id(0x4D);

    // The hostile peer's window. Endpoint types are knowable from this update
    // itself — the bundled-endpoint delivery a forger would actually use.
    let remote = create_window_doc("federation-peer", &window_key);
    insert_entity(&remote, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&remote, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(&remote, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
    insert_entity(&remote, event, ENTITY_TYPE_EVENT, b"event");
    insert_edge(&remote, person, EdgeKind::FacetOf, facet_selected);
    // The neighbor is reachable EXCLUSIVELY through the forged seed.
    insert_edge(&remote, person, EdgeKind::Mentions, neighbor);
    insert_edge(&remote, event, EdgeKind::FacetOf, facet_selected);
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    // Full production ingest, so the filtered doc below is the one this vault
    // would really export.
    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("a forged facet stamp must not fail the admission door closed");
    let local = create_window_doc("local", &window_key);
    local.import(&admitted).unwrap();
    crate::sync::window::forward_rematerialize(
        &vault,
        &local,
        &crate::sync::bridge::Materializer::new(),
        &window_key,
    )
    .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let exported = filtered_window_doc(
        &vault,
        &local,
        &window_key,
        test_selector_scope(),
        &selector,
    )
    .unwrap()
    .export(ExportMode::all_updates())
    .unwrap();
    let ids = import_ids(&exported);

    assert!(
        !ids.contains(&person),
        "the forged PERSON must not be exported: its facet scope came from a \
         stamp the type table forbids, and only the admission boundary can \
         keep the RAW-map selector from reading it"
    );
    assert!(
        !ids.contains(&neighbor),
        "the one-hop neighbor is reachable ONLY through the forged seed — \
         exporting it would prove the seed still scopes closure"
    );
    assert!(
        ids.contains(&event),
        "control: the on-table EVENT stamped to the SAME selected facet must \
         still export — the fix removes the forged seed, not facet scoping"
    );
    assert!(
        ids.contains(&facet_selected),
        "control: the selected facet itself is always visible to its selector"
    );
}

/// The admission drop is TERMINAL, so it must schedule no retry work.
///
/// `rm:w:{window}:{entity_hex}` means "a forward rematerialization pass still
/// owes work on this entity", and forward remat discharges it by REPLAYING the
/// row out of the document. A row the admission door DROPPED is never in any
/// document, so no replay can reach it and the marker can never clear. Two
/// things break at once if the drop marks: the marker pends forever, and
/// because a pending `rm:` row is the engine's GDPR purge-may-have-failed
/// signal, the erasure SLA channel is permanently poisoned by a peer's forged
/// edge — a remote-controlled false alarm on the one channel that must stay
/// trustworthy.
///
/// The quarantine `x:` row is the WHOLE account of a terminal drop, and it is
/// complete on its own: typed reason, hashed key, hashed payload.
#[test]
fn admission_drop_leaves_no_pending_remat_work() {
    let member = entity_id(0x5B);
    let (_dir, vault, _grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-04");

    let facet = entity_id(0x5C);
    let person = entity_id(0x5D);

    // The forged stamp with BOTH endpoint types knowable from this frame:
    // PERSON is off the source half of the table, so the door DROPS it.
    let remote = create_window_doc("federation-peer", &window_key);
    insert_entity(&remote, facet, ENTITY_TYPE_FACET, b"facet");
    insert_entity(&remote, person, ENTITY_TYPE_PERSON, b"person");
    insert_edge(&remote, person, EdgeKind::FacetOf, facet);
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let admitted = admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("a forged stamp must not fail the admission closed");

    let local = create_window_doc("local", &window_key);
    local.import(&admitted).unwrap();
    assert!(
        map_get_bytes(
            &local.get_map("edges"),
            &edge_key(person, EdgeKind::FacetOf, facet)
        )
        .is_none(),
        "precondition — the forged row must actually be DROPPED, or this test \
         proves nothing about a drop's marker shape"
    );

    let records = quarantined_records(&vault).unwrap();
    assert!(
        records
            .iter()
            .any(|(_, record)| record.reason_code == "InvalidFacetOfEdge"
                && record.container == QuarantineContainer::Edges),
        "the drop must still leave typed durable evidence — silent drops are \
         the failure this whole surface exists to prevent"
    );

    assert!(
        crate::sync::quarantine::pending_remat_windows(&vault)
            .unwrap()
            .is_empty(),
        "an admission-DROPPED row can never be replayed out of a document it \
         never entered, so a needs-remat marker for it would pend forever and \
         permanently signal a GDPR purge failure that never happened"
    );

    // Draining is the operator's discharge path; it must find nothing to do.
    let report = crate::sync::quarantine::sync_doctor(&vault).unwrap();
    assert!(
        report.rm_pending_windows.is_empty(),
        "the doctor's erasure-SLA channel must stay clean after a peer's \
         forged edge is dropped"
    );
    assert_eq!(
        report.quarantine_count, 1,
        "exactly the one forged row is accounted"
    );
}

/// N forged rows in one admission cost a BOUNDED number of commits.
///
/// The peer chooses N. A `write_txn` + commit per rejected row therefore hands
/// it an amplification primitive: one admission, unbounded fsync traffic. The
/// rejections ride one batch that commits once for the whole pass.
///
/// The commit count is observed through LMDB's own committed-transaction id
/// (`Env::info().last_txn_id`), which is the property that actually matters —
/// asserting on a Rust-side counter would pass even if the batching were
/// removed.
#[test]
fn admission_drops_commit_in_one_bounded_batch() {
    let member = entity_id(0x6B);
    let (_dir, vault, _grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-05");

    let facet = entity_id(0x6C);
    // Enough rows that a per-row commit is unmistakable against a one-txn pass.
    let forged: Vec<EntityId> = (0x70_u8..0x90).map(entity_id).collect();

    let remote = create_window_doc("federation-peer", &window_key);
    insert_entity(&remote, facet, ENTITY_TYPE_FACET, b"facet");
    for id in &forged {
        insert_entity(&remote, *id, ENTITY_TYPE_PERSON, b"person");
        insert_edge(&remote, *id, EdgeKind::FacetOf, facet);
    }
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    let before = vault.store.env.info().last_txn_id;
    admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("forged rows must not fail the admission closed");
    let commits = vault.store.env.info().last_txn_id - before;

    assert_eq!(
        quarantined_records(&vault).unwrap().len(),
        forged.len(),
        "every rejected row is still accounted with its own typed evidence \
         row — bounding the COMMITS must not bound the ACCOUNTING"
    );
    assert!(
        commits < forged.len(),
        "{} forged rows cost {commits} commits — a peer-controlled row count \
         must not translate into a peer-controlled commit count",
        forged.len()
    );

    assert!(
        crate::sync::quarantine::pending_remat_windows(&vault)
            .unwrap()
            .is_empty(),
        "the batch keeps the terminal no-marker shape for every row"
    );
}

/// Past the per-pass evidence bound, rejections are accounted by COUNT.
///
/// The `x:` ring is SHARED and capped at 4096 rows, so an unbounded per-pass
/// mint would let one hostile frame flush every unrelated quarantine record the
/// vault holds — evidence destruction dressed as evidence keeping. The bound
/// caps what one pass mints; the remainder increments a doctor-visible counter,
/// so nothing is silently dropped. The reason code is uniform within a pass, so
/// the capped rows carry no information the kept rows do not.
///
/// H2 liveness is unaffected: the ADMISSION continues either way — this is only
/// about how the rejection is accounted.
#[test]
fn admission_drops_past_the_evidence_bound_are_counted_not_dropped() {
    use crate::sync::quarantine::MAX_QUARANTINE_ROWS_PER_PASS;

    let member = entity_id(0x7B);
    let (_dir, vault, _grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-06");

    let facet = entity_id(0x7C);
    let over_cap = 5_usize;
    let total = MAX_QUARANTINE_ROWS_PER_PASS + over_cap;

    let remote = create_window_doc("federation-peer", &window_key);
    insert_entity(&remote, facet, ENTITY_TYPE_FACET, b"facet");
    for index in 0..total {
        // 16-byte ids from a counter: the fixture needs more distinct forged
        // sources than the single-byte seed helper can mint without colliding
        // with the pinned-id list.
        let mut bytes = [0x11_u8; 16];
        bytes[0..8].copy_from_slice(&(index as u64 + 1).to_le_bytes());
        let id = EntityId::from_bytes(bytes).unwrap();
        insert_entity(&remote, id, ENTITY_TYPE_PERSON, b"person");
        insert_edge(&remote, id, EdgeKind::FacetOf, facet);
    }
    remote.commit();
    let update = remote.export(ExportMode::all_updates()).unwrap();

    admit_federated_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
    )
    .expect("an over-cap forged frame must not fail the admission closed");

    let report = crate::sync::quarantine::sync_doctor(&vault).unwrap();
    assert_eq!(
        report.quarantine_count, MAX_QUARANTINE_ROWS_PER_PASS,
        "one pass mints at most the per-pass bound, so a hostile frame cannot \
         flush the shared 4096-row evidence ring"
    );
    assert_eq!(
        report.batch_drop_count, over_cap as u64,
        "the rows past the bound are accounted by COUNT — a bounded evidence \
         budget must never become a silent drop"
    );
    assert!(
        report.rm_pending_windows.is_empty(),
        "over-cap rows keep the terminal no-marker shape too"
    );
}

/// OUT-OF-ORDER RESIDUE — the leg the admission drop alone cannot close, and
/// the reason the selector needs a read mirror of the write table.
///
/// The forger splits the delivery. Update 1 carries the stamp
/// `P -> <selected FACET>` with P absent everywhere: BOTH endpoint types are
/// genuinely unknowable, so the admission boundary passes it through — it must,
/// or every legitimate out-of-order first delivery burns permanently (H2).
/// Update 2 then delivers P as a PERSON. Nothing re-examines the stamp already
/// resident in the live doc, so a selector that honors raw `FacetOf` rows from
/// any source would read it as a facet seed and move P plus its one-hop
/// neighbor across the disclosure boundary.
///
/// Everything runs on the PRODUCTION stack: `SyncClient` over a real
/// `WindowManager`, both updates through
/// `SyncClient::import_federated_window_update` into a LOADED window, then the
/// real selector over that same live doc. The neighbor's only adjacency is to
/// P, so exporting it would prove the residue still scopes closure; the EVENT
/// control is stamped to the same selected facet, so its ABSENCE would prove
/// the mirror broke facet scoping instead of the forgery.
///
/// Both roles: a mirror that holds for members but not guests reads as
/// protection while being none.
#[test]
fn out_of_order_off_table_residue_cannot_scope_the_export_for_either_role() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0x60_u8),
        (FederationAdmissionRole::Guest, 0x70_u8),
    ] {
        let window = "2026-05";
        let member = entity_id(seed);
        let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);

        let facet_selected = entity_id(seed + 1);
        let person = entity_id(seed + 2);
        let neighbor = entity_id(seed + 3);
        let event = entity_id(seed + 4);

        // Update 1: the stamp lands while its SOURCE is unknowable everywhere
        // — the H2 defer the admission door must honor. The FACET target rides
        // along so the row names a facet this peer will select.
        let first = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&first, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
        insert_entity(&first, event, ENTITY_TYPE_EVENT, b"event");
        insert_edge(&first, person, EdgeKind::FacetOf, facet_selected);
        insert_edge(&first, event, EdgeKind::FacetOf, facet_selected);
        first.commit();
        import_federated(&mut client, window, &first, role);

        let live = client
            .window(window)
            .expect("federated import opens window");
        assert!(
            map_get_bytes(
                &live.doc.get_map("edges"),
                &edge_key(person, EdgeKind::FacetOf, facet_selected),
            )
            .is_some(),
            "{role:?}: precondition — the unknowable-source stamp must SURVIVE \
             admission, or this test proves nothing about the residue"
        );

        // Update 2: P arrives typed PERSON. The stamp from update 1 is already
        // resident and is never revisited.
        let second = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&second, person, ENTITY_TYPE_PERSON, b"person");
        insert_entity(&second, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
        insert_edge(&second, person, EdgeKind::Mentions, neighbor);
        second.commit();
        import_federated(&mut client, window, &second, role);

        let live = client.window(window).expect("window still loaded");
        assert!(
            map_get_bytes(&live.doc.get_map("entities"), &person.to_hex()).is_some(),
            "{role:?}: precondition — PERSON P must be present in the live doc, \
             or its absence from the export below would hold vacuously"
        );

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![],
        );
        let exported = filtered_window_doc(
            &vault,
            &live.doc,
            &WindowKey::new(window),
            test_selector_scope(),
            &selector,
        )
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
        let ids = import_ids(&exported);

        assert!(
            !ids.contains(&person),
            "{role:?}: an off-table source's FacetOf row carries NO facet scope \
             on the read side — the residue admission had to defer must not \
             become a seed once the source arrives typed PERSON"
        );
        assert!(
            !ids.contains(&neighbor),
            "{role:?}: the one-hop neighbor is reachable ONLY through P — \
             exporting it would prove the residue still scopes closure"
        );
        assert!(
            ids.contains(&event),
            "{role:?}: control — the on-table EVENT stamped to the SAME selected \
             facet must still export; the mirror removes forged scope, not \
             facet scoping"
        );
        assert!(
            ids.contains(&facet_selected),
            "{role:?}: control — the selected facet is always visible to its \
             selector"
        );
    }
}

/// The mirror must not punish HONEST out-of-order delivery. Same split
/// timeline as the regression above, but the late-arriving source is a CLAIM —
/// an admitted type — so its stamp scopes exactly as if it had arrived in one
/// frame: the CLAIM exports under its selected facet, and its one-hop neighbor
/// rides the seed's closure.
///
/// Without this pin the read mirror could be "fixed" by refusing every stamp
/// whose source was unknown at admission time, which would silently break
/// every legitimate two-frame delivery.
#[test]
fn out_of_order_on_table_source_still_scopes_after_the_mirror() {
    let window = "2026-06";
    let member = entity_id(0x80);
    let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
    // Admission restamps a federated claim to `Imported`, which requires an
    // explicit auto-permit row; without one the CLAIM queues for consent and
    // never reaches the doc, making the scoping assertions vacuous.
    put_imported_source_trust(&vault);

    let facet_selected = entity_id(0x81);
    let claim = entity_id(0x82);
    let neighbor = entity_id(0x83);

    let first = create_window_doc("federation-peer", &WindowKey::new(window));
    insert_entity(&first, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_edge(&first, claim, EdgeKind::FacetOf, facet_selected);
    first.commit();
    import_federated(&mut client, window, &first, FederationAdmissionRole::Member);

    let second = create_window_doc("federation-peer", &WindowKey::new(window));
    insert_blob(&second, claim, &public_claim_blob());
    insert_entity(&second, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
    insert_edge(&second, claim, EdgeKind::Supports, neighbor);
    second.commit();
    import_federated(
        &mut client,
        window,
        &second,
        FederationAdmissionRole::Member,
    );

    let live = client.window(window).expect("window still loaded");
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let exported = filtered_window_doc(
        &vault,
        &live.doc,
        &WindowKey::new(window),
        test_selector_scope(),
        &selector,
    )
    .unwrap()
    .export(ExportMode::all_updates())
    .unwrap();
    let ids = import_ids(&exported);

    assert!(
        ids.contains(&claim),
        "a CLAIM whose facet stamp arrived one frame ahead of it must still \
         scope to the selected facet — the mirror gates on the source's TYPE, \
         not on whether that type was knowable at admission time"
    );
    assert!(
        ids.contains(&neighbor),
        "the honest seed's one-hop neighbor must still ride its closure"
    );
    assert!(ids.contains(&facet_selected));
}

/// The mirror's WITHHOLD half. An off-table source stamped ONLY to an
/// UNSELECTED facet reads as Unfaceted — a NON-STATEMENT, not a withhold — so
/// the entity is judged on the selector's other rules exactly like any
/// unstamped entity, closure included.
///
/// The distinction is only observable through closure, which is what this
/// fixture builds: both the PERSON and the EVENT hang off a genuine
/// selected-facet CLAIM seed, so each would ride that seed's closure on its
/// own. The EVENT's stamp is ON the table and withholds it; the PERSON's is
/// not, so nothing withholds the PERSON and it exports.
///
/// This asymmetry is deliberate and worth pinning: making the mirror
/// "helpfully" fail closed on an unadmitted stamp would hand a hostile peer a
/// SUPPRESSION primitive — spray `<host's PERSON> -> <any facet>` rows into the
/// window and the host's own entities vanish from a legitimate grant. Refusing
/// to read an unwritable row is the fix; letting it deny is the same bug with
/// the sign flipped.
#[test]
fn selector_ignores_off_table_stamp_to_an_unselected_facet() {
    let member = entity_id(0x3E);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-12");

    let facet_selected = entity_id(0xAE);
    let facet_unselected = entity_id(0xBE);
    let claim_seed = entity_id(0x0E);
    let person = entity_id(0x1E);
    let event = entity_id(0x2E);

    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_unselected, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_entity(&doc, person, ENTITY_TYPE_PERSON, b"person");
    insert_entity(&doc, event, ENTITY_TYPE_EVENT, b"event");
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_selected);
    // Identical shape, differing only in SOURCE TYPE — the one variable.
    insert_edge(&doc, person, EdgeKind::FacetOf, facet_unselected);
    insert_edge(&doc, event, EdgeKind::FacetOf, facet_unselected);
    // Both hang off the seed, so each would export but for a withhold.
    insert_edge(&doc, claim_seed, EdgeKind::Supports, person);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, event);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&claim_seed),
        "control: the selected-facet claim must seed closure, or both \
         assertions below would hold vacuously"
    );
    assert!(
        ids.contains(&person),
        "an unadmitted source's FacetOf row is a NON-STATEMENT, not a withhold: \
         honoring it would hand a peer a suppression primitive against the \
         host's own entities on a legitimate grant"
    );
    assert!(
        !ids.contains(&event),
        "control: EVENT is ON the table, so the SAME stamp shape still \
         withholds — the mirror narrows by SOURCE TYPE, it does not give up"
    );
    assert!(
        !ids.contains(&facet_unselected),
        "unselected facet entity leaked"
    );
}

/// TARGET-SIDE MIRROR GAP — the half a source-only read mirror leaves open.
///
/// Membership in `selector.facets` is a list of ids the PEER NAMED. It is not
/// evidence that the id exists, still less that it is a FACET. So a stamp
/// `CLAIM -> <selected but ABSENT id>` has an on-table SOURCE and a target
/// that resolves to nothing — and a mirror that checks only the source half
/// reads it as a seed, moving the CLAIM and its one-hop neighbor across the
/// disclosure boundary on the strength of an id the document never typed.
///
/// Arm 1 then makes it worse in the way that matters: the target LATER arrives
/// as a PERSON. Nothing re-examines the resident stamp, so the forged seed
/// stays live forever under a source-only mirror. The correct behavior is
/// SCOPE-INERT — the row is neither a seed nor a withhold until a FACET blob
/// for that id exists.
///
/// Arm 2 is the healing control: the same split delivery with the target
/// arriving as a real FACET must scope normally. Without it the fix could be
/// "never honor a late target", which would break honest out-of-order
/// delivery — the H2 line this lane exists to respect.
///
/// Both arms run the PRODUCTION federated entry (`SyncClient` over a real
/// `WindowManager`) for BOTH roles: a mirror that holds for members but not
/// guests reads as protection while being none.
#[test]
fn selector_target_must_resolve_to_a_facet_before_any_scope_is_honored() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0x94_u8),
        (FederationAdmissionRole::Guest, 0x98_u8),
    ] {
        for target_arrives_as_facet in [false, true] {
            let window = "2026-09";
            let member = entity_id(seed);
            let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
            // The seed CLAIM is federated, so it needs the Imported auto-permit
            // row or it queues for consent and never reaches the doc.
            put_imported_source_trust(&vault);

            let named = entity_id(seed + 1);
            let claim = entity_id(seed + 2);
            let neighbor = entity_id(seed + 3);

            // Frame 1: the stamp names an id absent everywhere. BOTH the
            // admission door and the remat gate must defer (H2), so the row
            // lands resident in the live doc — the residue this mirror owns.
            let first = create_window_doc("federation-peer", &WindowKey::new(window));
            insert_blob(&first, claim, &public_claim_blob());
            insert_entity(&first, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
            insert_edge(&first, claim, EdgeKind::FacetOf, named);
            insert_edge(&first, claim, EdgeKind::Supports, neighbor);
            first.commit();
            import_federated(&mut client, window, &first, role);

            let live = client
                .window(window)
                .expect("federated import opens window");
            assert!(
                map_get_bytes(
                    &live.doc.get_map("edges"),
                    &edge_key(claim, EdgeKind::FacetOf, named),
                )
                .is_some(),
                "{role:?}/{target_arrives_as_facet}: precondition — the \
                 unknowable-TARGET stamp must SURVIVE admission, or this test \
                 proves nothing about the residue"
            );

            // Frame 2: the named id materializes — as a PERSON (the forgery)
            // or as a real FACET (the honest late delivery).
            let second = create_window_doc("federation-peer", &WindowKey::new(window));
            if target_arrives_as_facet {
                insert_entity(&second, named, ENTITY_TYPE_FACET, b"facet");
            } else {
                insert_entity(&second, named, ENTITY_TYPE_PERSON, b"person");
            }
            second.commit();
            import_federated(&mut client, window, &second, role);

            let live = client.window(window).expect("window still loaded");
            assert!(
                map_get_bytes(&live.doc.get_map("entities"), &named.to_hex()).is_some(),
                "{role:?}/{target_arrives_as_facet}: precondition — the named id \
                 must be present in the live doc"
            );

            let selector = SyncSelector::new(
                grant_id,
                member,
                SyncSelectorWorld::All,
                vec![named],
                vec![],
            );
            let exported = filtered_window_doc(
                &vault,
                &live.doc,
                &WindowKey::new(window),
                test_selector_scope(),
                &selector,
            )
            .unwrap()
            .export(ExportMode::all_updates())
            .unwrap();
            let ids = import_ids(&exported);

            if target_arrives_as_facet {
                assert!(
                    ids.contains(&claim),
                    "{role:?}: a stamp whose TARGET arrived one frame late as a \
                     real FACET must HEAL into ordinary scoping — the mirror \
                     gates on the target's TYPE, not on when it became knowable"
                );
                assert!(
                    ids.contains(&neighbor),
                    "{role:?}: the healed seed's one-hop neighbor must ride its \
                     closure"
                );
                assert!(
                    ids.contains(&named),
                    "{role:?}: the selected facet is visible to its own selector"
                );
            } else {
                assert!(
                    !ids.contains(&claim),
                    "{role:?}: a stamp aimed at a selected-but-NON-FACET id \
                     carries NO scope — being NAMED in the selector is not \
                     evidence the id is a FACET, and honoring it would seed \
                     closure from an id no write door would have accepted"
                );
                assert!(
                    !ids.contains(&neighbor),
                    "{role:?}: the one-hop neighbor is reachable ONLY through \
                     the CLAIM — exporting it would prove the inert row still \
                     scopes closure"
                );
                assert!(
                    !ids.contains(&named),
                    "{role:?}: a selected id that turned out to be a PERSON is \
                     not a facet and must not export as one"
                );
            }
        }
    }
}

/// SOURCE TRUTH IS NOT THE CRDT WINNER — the LWW forgery a document-blob-first
/// mirror hands a peer for free.
///
/// Entity type is IMMUTABLE per id (`Error::EntityTypeImmutable`). The write
/// door enforces it by QUARANTINING the re-type, which means LMDB keeps the
/// FIRST-writer type — but the Loro map is last-write-wins and keeps the
/// HIGHER-LAMPORT blob. The two therefore disagree by construction after a
/// rejected re-type, and the disagreement is entirely peer-controlled.
///
/// The three frames build exactly that state:
///
/// 1. the forged `S -> <selected FACET>` stamp, with S absent everywhere (the
///    H2 defer the admission door must honor);
/// 2. S materializes as a PERSON — off-table, so the row is inert;
/// 3. a CRDT-WINNING EVENT blob for the SAME id. The write door rejects it
///    (`EntityTypeImmutable` quarantine, LMDB stays PERSON) but the doc map now
///    types S as an admitted EVENT.
///
/// A mirror reading the document blob first sees EVENT and honors the stamp,
/// exporting the PERSON and its one-hop neighbor on the strength of a type the
/// engine REFUSED to write. Reading STORED-FIRST — the same order the
/// admission door uses, and permanent truth because the type is immutable —
/// closes it. The middle assertions are the load-bearing ones: they pin that
/// the quarantine really fired and LMDB really held PERSON, so the export
/// assertions are testing the mirror's ORDER rather than a doc that never
/// flipped.
///
/// Both roles: a mirror that holds for members but not guests reads as
/// protection while being none.
#[test]
fn selector_source_type_resolves_stored_first_against_a_winning_retype_blob() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0xC0_u8),
        (FederationAdmissionRole::Guest, 0xC8_u8),
    ] {
        let window = "2026-10";
        let member = entity_id(seed);
        let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);

        let facet_selected = entity_id(seed + 1);
        let source = entity_id(seed + 2);
        let neighbor = entity_id(seed + 3);
        let event = entity_id(seed + 4);

        // Frame 1: the forged stamp lands while its SOURCE is unknowable
        // everywhere. The FACET target rides along so the row names a facet
        // this peer will select, and the EVENT control is stamped to the same
        // facet so a broken mirror is distinguishable from a dead one.
        let first = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&first, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
        insert_entity(&first, event, ENTITY_TYPE_EVENT, b"event");
        insert_edge(&first, source, EdgeKind::FacetOf, facet_selected);
        insert_edge(&first, event, EdgeKind::FacetOf, facet_selected);
        first.commit();
        import_federated(&mut client, window, &first, role);

        // Frame 2: S materializes as PERSON. This is the write that reaches
        // LMDB, and immutability makes it permanent truth about this id.
        let second = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&second, source, ENTITY_TYPE_PERSON, b"person");
        insert_entity(&second, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
        insert_edge(&second, source, EdgeKind::Mentions, neighbor);
        second.commit();
        import_federated(&mut client, window, &second, role);

        assert_eq!(
            vault.get_raw(&source).unwrap().map(|blob| blob[0]),
            Some(ENTITY_TYPE_PERSON),
            "{role:?}: precondition — the first-writer type must be in LMDB"
        );

        // Frame 3: the re-type. Each admitted frame is authored in a FRESH doc
        // whose Lamport clock starts at zero, so "later frame" alone does not
        // mean "higher Lamport" — a lone re-type op ties frame 2's and the
        // winner falls to a peer-id tiebreak. The benign rows below are ids
        // that sort ahead of the source, so admission re-authors them first
        // and the re-type lands at a Lamport strictly above frame 2's. This is
        // what an ordinary multi-row window update looks like anyway; the
        // precondition assert right after is what keeps the test honest if
        // Loro's ordering ever shifts under it.
        let third = create_window_doc("federation-peer", &WindowKey::new(window));
        for pad in [0x02_u8, 0x03, 0x04, 0x05, 0x06] {
            insert_entity(&third, entity_id(pad), ENTITY_TYPE_PERSON, b"unrelated");
        }
        insert_entity(&third, source, ENTITY_TYPE_EVENT, b"forged-event");
        third.commit();
        import_federated(&mut client, window, &third, role);

        let live = client.window(window).expect("window still loaded");
        let doc_blob = map_get_bytes(&live.doc.get_map("entities"), &source.to_hex())
            .expect("the re-type blob is resident in the live doc");
        assert_eq!(
            EntityMetadataHeader::parse(&doc_blob).unwrap().entity_type,
            ENTITY_TYPE_EVENT,
            "{role:?}: precondition — the re-type must WIN the CRDT map, or a \
             blob-first mirror would pass this test vacuously"
        );
        assert_eq!(
            vault.get_raw(&source).unwrap().map(|blob| blob[0]),
            Some(ENTITY_TYPE_PERSON),
            "{role:?}: precondition — the immutability gate must keep LMDB at \
             the first-writer PERSON type"
        );
        assert!(
            quarantined_records(&vault)
                .unwrap()
                .iter()
                .any(|(_, record)| record.reason_code == "EntityTypeImmutable"
                    && record.container == QuarantineContainer::Entities),
            "{role:?}: precondition — the re-type must be QUARANTINED, which is \
             what makes the stored type permanent truth the mirror can rely on"
        );

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![],
        );
        let exported = filtered_window_doc(
            &vault,
            &live.doc,
            &WindowKey::new(window),
            test_selector_scope(),
            &selector,
        )
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
        let ids = import_ids(&exported);

        assert!(
            !ids.contains(&source),
            "{role:?}: the mirror must read the STORED PERSON type, not the \
             CRDT-winning EVENT blob the immutability gate refused to write — \
             otherwise a peer buys facet scope with a rejected re-type"
        );
        assert!(
            !ids.contains(&neighbor),
            "{role:?}: the one-hop neighbor is reachable ONLY through the \
             forged source — exporting it would prove the fake type still \
             scopes closure"
        );
        assert!(
            ids.contains(&event),
            "{role:?}: control — the honest EVENT stamped to the SAME selected \
             facet must still export; stored-first removes the fake, not facet \
             scoping"
        );
        assert!(
            ids.contains(&facet_selected),
            "{role:?}: control — the selected facet is always visible to its \
             selector"
        );
    }
}

/// A CONFLICTING document blob is NEVER CONSULTED — the stored type carries
/// the scope, in the WITHHOLD direction as much as the seed direction.
///
/// This pin previously asserted the opposite (conflict ⇒ no scope ⇒ the EVENT
/// exports), and the r7 finder proved that expectation was pinning the bug:
/// reading a source conflict as `None` makes the row inert, which ERASES a
/// withhold a valid stored EVENT + stored FACET pair had already established.
/// A peer that cannot otherwise touch this entity gets to publish it by
/// forging one rejected blob — non-monotone disclosure, peer-controlled. The
/// unified rule is that stored truth never loses to a rejected write in EITHER
/// role, so a conflicting blob can neither buy scope nor erase a withhold.
///
/// The suppression worry the old expectation answered is answered better by
/// the unified rule: the withholds that survive are exactly the ones the
/// STORED types already justified. A forged stamp aimed at a source stored as
/// a PERSON is off the table and stays inert — no new suppression primitive
/// appears (`selector_forged_facet_blob_cannot_retype_a_stored_person_target`
/// and the three-frame LWW pin hold that line).
///
/// The fixture puts the stamp on an UNSELECTED facet so the two readings
/// diverge: under a conflict-to-None source rule the EVENT rides the adjacent
/// seed's closure and exports; under stored-wins it stays WITHHELD.
///
/// (Renamed from `selector_conflicting_document_blob_carries_no_scope_in_
/// either_direction`, whose name stated the erasing rule the r7 ruling
/// removed.)
#[test]
fn selector_conflicting_document_blob_never_displaces_the_stored_type() {
    let member = entity_id(0x26);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-12");

    let facet_selected = entity_id(0x7F);
    let facet_unselected = entity_id(0x8F);
    let claim_seed = entity_id(0x9F);
    let conflicted = entity_id(0xAF);

    // Stored as an ADMITTED source type against a stored FACET target: BOTH
    // halves of this withhold are stored truth, which is exactly why a
    // rejected blob may not dissolve it.
    for (id, entity_type) in [
        (facet_selected, ENTITY_TYPE_FACET),
        (facet_unselected, ENTITY_TYPE_FACET),
        (conflicted, ENTITY_TYPE_EVENT),
    ] {
        vault
            .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, b"row")
            .unwrap();
    }

    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_unselected, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    // The CONFLICT: the doc types this id PERSON while LMDB holds EVENT.
    insert_entity(&doc, conflicted, ENTITY_TYPE_PERSON, b"rejected-retype");
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_selected);
    insert_edge(&doc, conflicted, EdgeKind::FacetOf, facet_unselected);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, conflicted);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&claim_seed),
        "control: the selected-facet claim must seed closure, or the assertion \
         below would hold vacuously"
    );
    assert!(
        !ids.contains(&conflicted),
        "the stored EVENT's stamp to a stored UNSELECTED facet is a withhold \
         BOTH endpoints' stored truth already justified, so it must survive a \
         conflicting blob: reading the source conflict as no-type would make \
         the row inert and let a peer PUBLISH this entity by forging one write \
         the immutability gate rejected (r7 — non-monotone disclosure)"
    );
    assert!(
        !ids.contains(&facet_unselected),
        "unselected facet entity leaked"
    );
}

/// POSITIVE CONTROL for the stored-first order: when the stored type and the
/// document blob AGREE, an admitted source scopes exactly as before. Without
/// this pin, "resolve stored-first" could be implemented as "ignore the
/// document entirely" or "treat any stored row as disqualifying", and both
/// would silently kill facet scoping for every normally-replicated entity.
///
/// The EVENT is stored AND present in the doc as an EVENT, stamped to a facet
/// the peer did NOT select, and hangs off a genuine selected-facet CLAIM seed
/// — so it would ride that seed's closure but for the withhold. Its absence is
/// therefore proof the agreeing stamp is still disclosure-effective.
#[test]
fn selector_honors_scope_when_stored_and_document_source_types_agree() {
    let member = entity_id(0x2B);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-11");

    let facet_selected = entity_id(0x3F);
    let facet_unselected = entity_id(0x4F);
    let claim_seed = entity_id(0x5F);
    let event = entity_id(0x6F);

    // The stored rows are the truth source the mirror consults first; the doc
    // blobs below agree with them, which is the ordinary replicated state.
    for (id, entity_type) in [
        (facet_selected, ENTITY_TYPE_FACET),
        (facet_unselected, ENTITY_TYPE_FACET),
        (event, ENTITY_TYPE_EVENT),
    ] {
        vault
            .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, b"row")
            .unwrap();
    }

    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, facet_selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_unselected, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_entity(&doc, event, ENTITY_TYPE_EVENT, b"event");
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_selected);
    insert_edge(&doc, event, EdgeKind::FacetOf, facet_unselected);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, event);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&claim_seed),
        "control: the selected-facet claim must seed closure, or the \
         assertion below would hold vacuously"
    );
    assert!(
        !ids.contains(&event),
        "an EVENT whose STORED and DOCUMENT types agree is on the table, so its \
         unselected-facet stamp must still withhold it — stored-first resolves \
         the type, it does not discard the scope"
    );
    assert!(ids.contains(&facet_selected));
    assert!(
        !ids.contains(&facet_unselected),
        "unselected facet entity leaked"
    );
}

/// A REJECTED RETYPE MUST NOT ERASE A VALID SCOPE — the TARGET-side arm of
/// the one conflict rule (stored truth never loses to a rejected write).
///
/// The target half decides whether a stamp CONTAINS its source, so resolving a
/// conflicted target to `None` makes the row inert and DELETES containment a
/// valid stored FACET had already established — a peer forges one PERSON blob
/// for a facet it does not own and an entity that was withheld from a
/// facet-limited peer starts exporting. (The SOURCE arm of the same erasure is
/// `selector_source_conflict_cannot_dissolve_a_multi_edge_withhold`; a
/// conflicting blob is a rejected write, so it is not consulted on either end,
/// and that single clause closes both.)
///
/// The fixture is the production repro: an EVENT scoped to a stored FACET T,
/// adjacent to a genuinely selected-facet CLAIM seed, so closure WOULD carry
/// it but for the withhold. Frame 2 lands a CRDT-winning PERSON blob for T.
/// The middle assertions are load-bearing: they pin that the retype really
/// won the map, that the immutability gate really quarantined it, and that
/// LMDB really still holds FACET — otherwise the withhold below would pass on
/// a document that never flipped.
///
/// Both roles through the production federated entry: a mirror that holds for
/// members but not guests reads as protection while being none.
#[test]
fn selector_target_conflict_keeps_the_stored_facet_scope() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0x60_u8),
        (FederationAdmissionRole::Guest, 0x68_u8),
    ] {
        let window = "2026-08";
        let member = entity_id(seed);
        let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
        put_imported_source_trust(&vault);

        let facet_t = entity_id(seed + 1);
        let event = entity_id(seed + 2);
        let facet_selected = entity_id(seed + 3);
        let claim_seed = entity_id(seed + 4);

        // Frame 1: the honest world. The EVENT is scoped to FACET T, which
        // this peer did NOT select, and hangs off a CLAIM that IS scoped to
        // the selected facet.
        let first = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&first, facet_t, ENTITY_TYPE_FACET, b"facet-t");
        insert_entity(&first, facet_selected, ENTITY_TYPE_FACET, b"facet-s");
        insert_entity(&first, event, ENTITY_TYPE_EVENT, b"event");
        insert_blob(&first, claim_seed, &public_claim_blob());
        insert_edge(&first, event, EdgeKind::FacetOf, facet_t);
        insert_edge(&first, claim_seed, EdgeKind::FacetOf, facet_selected);
        insert_edge(&first, claim_seed, EdgeKind::Supports, event);
        first.commit();
        import_federated(&mut client, window, &first, role);

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![],
        );
        let export_ids = |client: &mut SyncClient| {
            let live = client.window(window).expect("window still loaded");
            let update = filtered_window_doc(
                &vault,
                &live.doc,
                &WindowKey::new(window),
                test_selector_scope(),
                &selector,
            )
            .unwrap()
            .export(ExportMode::all_updates())
            .unwrap();
            import_ids(&update)
        };

        let ids = export_ids(&mut client);
        assert!(
            ids.contains(&claim_seed),
            "{role:?}: precondition — the selected-facet claim must seed closure"
        );
        assert!(
            !ids.contains(&event),
            "{role:?}: precondition — the EVENT's stamp to the UNSELECTED facet \
             T must withhold it, or the retype below erases nothing"
        );

        // Frame 2: the forged retype of T. The pad rows sort ahead of T, so
        // admission re-authors them first and the retype lands at a Lamport
        // strictly above frame 1's — a lone op would tie and fall to a peer-id
        // tiebreak. The precondition asserts below keep this honest if Loro's
        // ordering ever shifts.
        let second = create_window_doc("federation-peer", &WindowKey::new(window));
        for pad in [0x02_u8, 0x03, 0x04, 0x05, 0x06] {
            insert_entity(&second, entity_id(pad), ENTITY_TYPE_PERSON, b"unrelated");
        }
        insert_entity(&second, facet_t, ENTITY_TYPE_PERSON, b"forged-person");
        second.commit();
        import_federated(&mut client, window, &second, role);

        let live = client.window(window).expect("window still loaded");
        let doc_blob = map_get_bytes(&live.doc.get_map("entities"), &facet_t.to_hex())
            .expect("the retype blob is resident in the live doc");
        assert_eq!(
            EntityMetadataHeader::parse(&doc_blob).unwrap().entity_type,
            ENTITY_TYPE_PERSON,
            "{role:?}: precondition — the retype must WIN the CRDT map, or the \
             conflict this test is about never exists"
        );
        assert_eq!(
            vault.get_raw(&facet_t).unwrap().map(|blob| blob[0]),
            Some(ENTITY_TYPE_FACET),
            "{role:?}: precondition — the immutability gate must keep LMDB at \
             the first-writer FACET type"
        );
        assert!(
            quarantined_records(&vault)
                .unwrap()
                .iter()
                .any(|(_, record)| record.reason_code == "EntityTypeImmutable"
                    && record.container == QuarantineContainer::Entities),
            "{role:?}: precondition — the retype must be QUARANTINED, which is \
             what makes the stored FACET permanent truth the mirror relies on"
        );

        let ids = export_ids(&mut client);
        assert!(
            !ids.contains(&event),
            "{role:?}: the EVENT is scoped to a facet this peer did not select \
             and must STAY withheld — a REJECTED retype of the target may not \
             erase containment a valid stored FACET established"
        );
        assert!(
            ids.contains(&claim_seed),
            "{role:?}: control — the honest selected-facet seed must still \
             export; target-stored removes the erasure, not facet scoping"
        );
        assert!(
            ids.contains(&facet_selected),
            "{role:?}: control — the selected facet is visible to its selector"
        );
    }
}

/// THE MULTI-EDGE COMPOSITION (r7) — the shape that proved a SOURCE-side
/// conflict-to-None rule non-monotone, and the reason the conflict policy is
/// ONE rule rather than a role split.
///
/// Neither endpoint rule is wrong in isolation; the bug lives in how a single
/// source's SEVERAL stamps compose. `FacetScope` is an OR-fold per source: one
/// unselected-facet stamp withholds E outright. So the attacker does not need
/// to forge scope onto E — it only needs E's source half to go INERT, which
/// drops every stamp E carries, INCLUDING the withhold, and hands E back to
/// the adjacent honest seed's closure.
///
/// The fixture is that composition, production-reproduced:
///
/// * E is stored EVENT with TWO `FacetOf` stamps — one to a stored FACET the
///   peer did NOT select (the legitimate withhold), one to a doc-only FACET it
///   DID select (so E is not merely unreachable, and a source that stays
///   on-table still has a live selected stamp to weigh);
/// * an honest selected-facet CLAIM seed sits adjacent to E, so closure WOULD
///   carry E the moment the withhold dissolves;
/// * a higher-Lamport PERSON blob retypes E. The immutability gate quarantines
///   it and LMDB keeps EVENT — the conflict is entirely peer-controlled.
///
/// Under source-conflict-to-None, E's source half reads no type, BOTH stamps
/// go inert, the withhold vanishes and the seed exports E: a peer PUBLISHES an
/// entity by shipping a write the engine refused. Under stored-wins the source
/// still reads EVENT, the unselected stamp still withholds, and E stays in.
///
/// The middle assertions are load-bearing: they pin that the retype really won
/// the CRDT map, that it really quarantined, and that LMDB really still holds
/// EVENT — otherwise the withhold below would pass on a document that never
/// flipped. Both roles through the production federated entry: a mirror that
/// holds for members but not guests reads as protection while being none.
#[test]
fn selector_source_conflict_cannot_dissolve_a_multi_edge_withhold() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0x30_u8),
        (FederationAdmissionRole::Guest, 0x38_u8),
    ] {
        let window = "2026-07";
        let member = entity_id(seed);
        let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
        put_imported_source_trust(&vault);

        let facet_unselected = entity_id(seed + 1);
        let facet_selected = entity_id(seed + 2);
        let event = entity_id(seed + 3);
        let claim_seed = entity_id(seed + 4);

        // Frame 1: the honest world, admitted through the real door so the
        // EVENT and the UNSELECTED facet both materialize into LMDB. Those two
        // stored rows are what justify the withhold.
        let first = create_window_doc("federation-peer", &WindowKey::new(window));
        insert_entity(&first, facet_unselected, ENTITY_TYPE_FACET, b"facet-u");
        insert_entity(&first, event, ENTITY_TYPE_EVENT, b"event");
        insert_blob(&first, claim_seed, &public_claim_blob());
        insert_edge(&first, event, EdgeKind::FacetOf, facet_unselected);
        insert_edge(&first, claim_seed, EdgeKind::Supports, event);
        first.commit();
        import_federated(&mut client, window, &first, role);

        assert_eq!(
            vault.get_raw(&event).unwrap().map(|blob| blob[0]),
            Some(ENTITY_TYPE_EVENT),
            "{role:?}: precondition — the first-writer EVENT type must be in LMDB"
        );
        assert_eq!(
            vault
                .get_raw(&facet_unselected)
                .unwrap()
                .map(|blob| blob[0]),
            Some(ENTITY_TYPE_FACET),
            "{role:?}: precondition — the withheld-from facet must be STORED, so \
             both halves of this withhold are stored truth"
        );

        // The SELECTED facet and its seed stamp are DOC-ONLY: written straight
        // into the live doc under the bridge origin so Observer B leaves LMDB
        // alone. That is the second endpoint-resolution branch (no stored row
        // ⇒ the document blob), so this one fixture exercises the conflict
        // branch and the doc-only branch in the same closure computation.
        let live = client
            .window(window)
            .expect("federated import opens window");
        insert_entity(&live.doc, facet_selected, ENTITY_TYPE_FACET, b"facet-s");
        insert_edge(&live.doc, event, EdgeKind::FacetOf, facet_selected);
        insert_edge(&live.doc, claim_seed, EdgeKind::FacetOf, facet_selected);
        live.doc
            .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        assert!(
            vault.get_raw(&facet_selected).unwrap().is_none(),
            "{role:?}: precondition — the selected facet must stay DOC-ONLY, or \
             the doc-blob resolution branch is not exercised"
        );

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![],
        );
        let export_ids = |client: &mut SyncClient| {
            let live = client.window(window).expect("window still loaded");
            let update = filtered_window_doc(
                &vault,
                &live.doc,
                &WindowKey::new(window),
                test_selector_scope(),
                &selector,
            )
            .unwrap()
            .export(ExportMode::all_updates())
            .unwrap();
            import_ids(&update)
        };

        let ids = export_ids(&mut client);
        assert!(
            ids.contains(&claim_seed),
            "{role:?}: precondition — the selected-facet CLAIM must seed closure, \
             or E's absence below would hold vacuously"
        );
        assert!(
            !ids.contains(&event),
            "{role:?}: precondition — E's stamp to the UNSELECTED facet must \
             withhold it EVEN THOUGH it also carries a selected stamp and an \
             adjacent seed; the retype below erases nothing otherwise"
        );

        // Frame 2: the forged retype of E's OWN type. Pad rows sort ahead of E
        // so admission re-authors them first and the retype lands at a Lamport
        // strictly above frame 1's — a lone op would tie and fall to a peer-id
        // tiebreak. The precondition asserts below keep this honest if Loro's
        // ordering ever shifts.
        let second = create_window_doc("federation-peer", &WindowKey::new(window));
        for pad in [0x02_u8, 0x03, 0x04, 0x05, 0x06] {
            insert_entity(&second, entity_id(pad), ENTITY_TYPE_PERSON, b"unrelated");
        }
        insert_entity(&second, event, ENTITY_TYPE_PERSON, b"forged-person");
        second.commit();
        import_federated(&mut client, window, &second, role);

        let live = client.window(window).expect("window still loaded");
        let doc_blob = map_get_bytes(&live.doc.get_map("entities"), &event.to_hex())
            .expect("the retype blob is resident in the live doc");
        assert_eq!(
            EntityMetadataHeader::parse(&doc_blob).unwrap().entity_type,
            ENTITY_TYPE_PERSON,
            "{role:?}: precondition — the retype must WIN the CRDT map, or the \
             conflict this test is about never exists"
        );
        assert_eq!(
            vault.get_raw(&event).unwrap().map(|blob| blob[0]),
            Some(ENTITY_TYPE_EVENT),
            "{role:?}: precondition — the immutability gate must keep LMDB at \
             the first-writer EVENT type"
        );
        assert!(
            quarantined_records(&vault)
                .unwrap()
                .iter()
                .any(|(_, record)| record.reason_code == "EntityTypeImmutable"
                    && record.container == QuarantineContainer::Entities),
            "{role:?}: precondition — the retype must be QUARANTINED, which is \
             what makes the stored EVENT permanent truth the mirror relies on"
        );

        let ids = export_ids(&mut client);
        assert!(
            !ids.contains(&event),
            "{role:?}: E must STILL be withheld. A conflicting SOURCE blob read \
             as no-type drops EVERY stamp E carries — the unselected-facet \
             withhold included — and the adjacent seed's closure then exports \
             it: a peer publishes an entity it does not control by forging one \
             write the immutability gate rejected (r7). Stored truth never \
             loses to a rejected write"
        );
        assert!(
            ids.contains(&claim_seed),
            "{role:?}: control — the honest selected-facet seed must still \
             export; stored-wins removes the erasure, not facet scoping"
        );
        assert!(
            ids.contains(&facet_selected),
            "{role:?}: control — the doc-only selected facet is visible to its \
             own selector, so the doc-blob branch really did resolve"
        );
        assert!(
            !ids.contains(&facet_unselected),
            "{role:?}: unselected facet entity leaked"
        );
    }
}

/// THE INVERSE FORGERY: a fake retype must not CREATE a facet either.
///
/// Stored-wins is AUTHORITY, not a one-way bias toward withholding, and this
/// is the arm that proves it: the same clause that keeps a withhold standing
/// also refuses to manufacture a seed. The target is stored PERSON — off the
/// ONE-1645 table — while a forged FACET document blob wins the map, and the
/// peer names that very id in its selector, so a mirror reading the blob would
/// turn the stamp into a SEED and haul the source plus its one-hop neighbor
/// across the disclosure boundary.
///
/// The second source pins the other half of "inert": a stamp aimed at a
/// non-facet target is a NON-STATEMENT, not a withhold, so an entity carrying
/// one still rides an honest seed's closure like any unstamped entity. Letting
/// it deny would hand a peer a suppression primitive.
#[test]
fn selector_forged_facet_blob_cannot_retype_a_stored_person_target() {
    let member = entity_id(0x2E);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-08");

    let person_target = entity_id(0x7E);
    let facet_real = entity_id(0x8E);
    let forged_source = entity_id(0x9E);
    let neighbor = entity_id(0xAE);
    let claim_seed = entity_id(0xBE);
    let riding_source = entity_id(0xCE);

    // Stored truth: the target is a PERSON, permanently.
    for (id, entity_type) in [
        (person_target, ENTITY_TYPE_PERSON),
        (facet_real, ENTITY_TYPE_FACET),
        (forged_source, ENTITY_TYPE_EVENT),
        (riding_source, ENTITY_TYPE_EVENT),
    ] {
        vault
            .put_entity(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, b"row")
            .unwrap();
    }

    let doc = create_window_doc("source", &window_key);
    // The FORGERY: the doc types the stored PERSON as a FACET.
    insert_entity(&doc, person_target, ENTITY_TYPE_FACET, b"forged-facet");
    insert_entity(&doc, facet_real, ENTITY_TYPE_FACET, b"facet-real");
    insert_entity(&doc, forged_source, ENTITY_TYPE_EVENT, b"forged-source");
    insert_entity(&doc, riding_source, ENTITY_TYPE_EVENT, b"riding-source");
    insert_entity(&doc, neighbor, ENTITY_TYPE_PERSON, b"neighbor");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_edge(&doc, forged_source, EdgeKind::FacetOf, person_target);
    insert_edge(&doc, forged_source, EdgeKind::Mentions, neighbor);
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_real);
    insert_edge(&doc, riding_source, EdgeKind::FacetOf, person_target);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, riding_source);
    doc.commit();

    // The peer NAMES the forged id, which is the whole point: being selected
    // is not evidence of being a FACET.
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![person_target, facet_real],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&claim_seed),
        "control: the genuine selected-facet claim must seed closure, or the \
         assertions below hold vacuously"
    );
    assert!(
        !ids.contains(&forged_source),
        "a stamp whose TARGET is stored as a PERSON is off the table no matter \
         what the document blob claims — the stored row is authoritative in \
         BOTH directions, so a forged FACET blob cannot manufacture a seed"
    );
    assert!(
        !ids.contains(&neighbor),
        "the one-hop neighbor is reachable ONLY through the forged source — \
         exporting it would prove the fake facet still seeded closure"
    );
    assert!(
        ids.contains(&riding_source),
        "an off-table stamp is a NON-STATEMENT, not a withhold: an entity \
         carrying one still rides an honest seed's closure, or the mirror hands \
         a peer a suppression primitive"
    );
}

/// DOC-ONLY TARGET: with no stored row there is no conflict at all, so
/// resolution falls back to the document blob and the ONE-1645 table decides.
///
/// This is the branch fix-6's P1-1 pins reach through federated admission
/// (which materializes a stored row along the way); here it is exercised
/// directly, so a future "the stored row is always authoritative" reading
/// cannot quietly turn every not-yet-materialized facet into an inert one and
/// kill scoping for honest out-of-order delivery (the H2 line).
#[test]
fn selector_document_only_target_scopes_only_when_it_types_a_facet() {
    let member = entity_id(0x2F);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-08");

    let facet_doc_only = entity_id(0x7C);
    let person_doc_only = entity_id(0x8C);
    let claim_to_facet = entity_id(0x9C);
    let neighbor_of_facet_claim = entity_id(0xAC);
    let claim_to_person = entity_id(0xBC);
    let neighbor_of_person_claim = entity_id(0xCC);

    // No stored rows at all: every type below comes from the document.
    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, facet_doc_only, ENTITY_TYPE_FACET, b"facet");
    insert_entity(&doc, person_doc_only, ENTITY_TYPE_PERSON, b"person");
    insert_blob(&doc, claim_to_facet, &claim_blob(None));
    insert_blob(&doc, claim_to_person, &claim_blob(None));
    insert_entity(
        &doc,
        neighbor_of_facet_claim,
        ENTITY_TYPE_PERSON,
        b"neighbor-a",
    );
    insert_entity(
        &doc,
        neighbor_of_person_claim,
        ENTITY_TYPE_PERSON,
        b"neighbor-b",
    );
    insert_edge(&doc, claim_to_facet, EdgeKind::FacetOf, facet_doc_only);
    insert_edge(
        &doc,
        claim_to_facet,
        EdgeKind::Supports,
        neighbor_of_facet_claim,
    );
    insert_edge(&doc, claim_to_person, EdgeKind::FacetOf, person_doc_only);
    insert_edge(
        &doc,
        claim_to_person,
        EdgeKind::Supports,
        neighbor_of_person_claim,
    );
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_doc_only, person_doc_only],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(
        ids.contains(&claim_to_facet),
        "a document-only target that types a FACET scopes normally — absent a \
         stored row there is no conflict, and refusing the blob here would \
         break honest out-of-order delivery"
    );
    assert!(
        ids.contains(&neighbor_of_facet_claim),
        "the scoped seed's one-hop neighbor rides its closure"
    );
    assert!(
        !ids.contains(&claim_to_person),
        "a document-only target that types a PERSON is off the table, so the \
         stamp is inert and seeds nothing — being NAMED in the selector is not \
         evidence the id is a FACET"
    );
    assert!(
        !ids.contains(&neighbor_of_person_claim),
        "the inert stamp's neighbor is reachable only through it"
    );
}

#[test]
fn selector_facet_closure_does_not_expand_from_facet_entities() {
    let member = entity_id(0x3A);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-10");
    let doc = create_window_doc("source", &window_key);

    let facet_allowed = entity_id(0xAA);
    let claim_allowed = entity_id(0x1A);
    let selected_person = entity_id(0x2A);
    let facet_neighbor = entity_id(0x3B);

    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_blob(&doc, claim_allowed, &claim_blob(None));
    insert_entity(
        &doc,
        selected_person,
        ENTITY_TYPE_PERSON,
        b"selected-person",
    );
    insert_entity(&doc, facet_neighbor, ENTITY_TYPE_PERSON, b"facet-neighbor");
    insert_edge(&doc, claim_allowed, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, claim_allowed, EdgeKind::Supports, selected_person);
    insert_edge(&doc, facet_allowed, EdgeKind::Supports, facet_neighbor);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&facet_allowed));
    assert!(ids.contains(&claim_allowed));
    assert!(ids.contains(&selected_person));
    assert!(
        !ids.contains(&facet_neighbor),
        "selected facet entities must not seed arbitrary closure edges"
    );
}

#[test]
fn selector_applies_world_and_band_filters() {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-04");
    let doc = create_window_doc("source", &window_key);
    let world = local_world_id(0x5E);
    let other_world = entity_id(0xE2);
    let claim_world = entity_id(0x41);
    let claim_base = entity_id(0x61);
    let claim_other_world = entity_id(0x43);
    let world_entity = world.entity_id();
    let task_like = entity_id(0x45);

    insert_blob(&doc, claim_world, &claim_blob(Some(world.entity_id())));
    insert_blob(&doc, claim_base, &claim_blob(None));
    insert_blob(&doc, claim_other_world, &claim_blob(Some(other_world)));
    insert_entity(&doc, world_entity, ENTITY_TYPE_WORLD, b"world");
    insert_entity(&doc, task_like, 80, b"task-list");
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(world),
        vec![],
        vec![TypeByteBand::Semantic, TypeByteBand::Core],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&claim_world));
    assert!(
        ids.contains(&claim_base),
        "base claims belong to every world selector"
    );
    assert!(ids.contains(&world_entity));
    assert!(!ids.contains(&claim_other_world));
    assert!(!ids.contains(&task_like), "productivity band leaked");
}

#[test]
fn selector_requires_matching_federation_grant_member() {
    let member = entity_id(0x33);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-05");
    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, entity_id(0x55), ENTITY_TYPE_PERSON, b"person");
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        entity_id(0x34),
        SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    assert!(
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).is_err()
    );
}

#[test]
fn selector_requires_matching_federation_grant_scope() {
    let member = entity_id(0x35);
    let (_dir, vault, grant_id) =
        test_vault_with_grant_scope(member, FederationGrantScope::vault(8));
    let window_key = WindowKey::new("2026-05");
    let doc = create_window_doc("source", &window_key);
    insert_entity(&doc, entity_id(0x56), ENTITY_TYPE_PERSON, b"person");
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    assert!(
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).is_err()
    );
}

#[test]
fn selector_suppresses_tombstoned_live_map_residue() {
    let member = entity_id(0x36);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-06");
    let doc = create_window_doc("source", &window_key);
    let residue = entity_id(0x57);
    insert_entity(&doc, residue, ENTITY_TYPE_PERSON, b"stale-live-blob");
    insert_tombstone(&doc, residue);
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let filtered =
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).unwrap();
    let receiver = create_window_doc("receiver", &window_key);
    receiver
        .import(&filtered.export(ExportMode::all_updates()).unwrap())
        .unwrap();

    assert!(
        receiver
            .get_map("entities")
            .get(residue.to_hex().as_str())
            .is_none(),
        "tombstoned live-map residue must not replicate"
    );
    assert!(
        receiver
            .get_map("tombstones")
            .get(residue.to_hex().as_str())
            .is_some(),
        "unfiltered selector snapshots should retain tombstones"
    );
}

#[test]
fn selector_suppresses_tombstone_alias_live_map_residue() {
    let member = entity_id(0x38);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-08");
    let doc = create_window_doc("source", &window_key);
    let residue = entity_id(0x58);
    insert_entity(&doc, residue, ENTITY_TYPE_PERSON, b"stale-live-blob");
    insert_uppercase_tombstone_alias(&doc, residue);
    doc.commit();

    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let filtered =
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).unwrap();
    let receiver = create_window_doc("receiver", &window_key);
    receiver
        .import(&filtered.export(ExportMode::all_updates()).unwrap())
        .unwrap();

    assert!(
        receiver
            .get_map("entities")
            .get(residue.to_hex().as_str())
            .is_none(),
        "any parseable tombstone alias must suppress live-map residue"
    );
    assert!(
        receiver
            .get_map("tombstones")
            .get(residue.to_hex().to_ascii_uppercase().as_str())
            .is_some(),
        "selector snapshots should retain the alias tombstone"
    );
}

#[test]
fn selector_treats_malformed_facet_of_value_as_denied_scope() {
    let member = entity_id(0x37);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-07");
    let doc = create_window_doc("source", &window_key);
    let facet_allowed = entity_id(0xA7);
    let facet_denied = entity_id(0xB7);
    let malformed_claim = entity_id(0x17);

    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, malformed_claim, &claim_blob(None));
    insert_malformed_edge(&doc, malformed_claim, EdgeKind::FacetOf, facet_denied);
    insert_edge(&doc, facet_allowed, EdgeKind::Supports, malformed_claim);
    doc.commit();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&facet_allowed));
    assert!(
        !ids.contains(&malformed_claim),
        "malformed FacetOf value must fail closed, not behave as absent"
    );
}

// ---------------------------------------------------------------------------
// Pact activation gate (ONE-1408)
// ---------------------------------------------------------------------------

use crate::authority::{
    AuthorityEntryHash, AuthorityVaultId, FederationLifecycleAction, FederationLifecycleKind,
    authority_entry_hash, federation_scope_digest, sign_federation_pact_gesture,
};
use crate::federation::{
    FederationDirectionScope, FederationPactScope, FederationScopeBands, FederationScopeFacets,
    FederationScopeWorlds, encode_federation_pact_scope,
};

fn all_direction_scope() -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: FederationScopeWorlds::All,
        facets: FederationScopeFacets::All,
        bands: FederationScopeBands::All,
    }
}

fn selector_pact_scope(facets: FederationScopeFacets) -> FederationPactScope {
    let mut half = all_direction_scope();
    half.facets = facets;
    FederationPactScope {
        lo_to_hi: half.clone(),
        hi_to_lo: half,
    }
}

fn signed_lifecycle_entry(
    signing: &SigningKey,
    vault_id: AuthorityVaultId,
    seq: u64,
    parent: AuthorityEntryHash,
    action: FederationLifecycleAction,
) -> AuthorityLogEntry {
    let key = AuthorityKey::Ed25519(signing.verifying_key().to_bytes());
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![parent],
        op: AuthorityOp::FederationLifecycle(action),
        signer: AuthoritySignature {
            suite: AuthoritySignatureSuite::Ed25519,
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: 9,
    };
    let transcript = authority_transcript(&entry).unwrap();
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[derive(Clone, Copy)]
enum PactSeedStatus {
    Active,
    Suspended,
    Promoted,
    Disconnected,
    Dissolved,
}

/// Seeds a fold-derived pact binding `grant_id` with the requested status
/// through the ordinary type-122 write door.
fn seed_pact_for_grant(vault: &Vault, grant_id: EntityId, status: PactSeedStatus) {
    let owner = SigningKey::from_bytes(&[0x61; 32]);
    let genesis = authority_genesis_entry(0x61);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let peer = SigningKey::from_bytes(&[0x62; 32]);
    let peer_key = AuthorityKey::Ed25519(peer.verifying_key().to_bytes());
    let peer_vault_id = genesis_vault_id(&authority_genesis_entry(0x62)).unwrap();
    let pact_id = [0x63; 32];
    let nonce = [0x64; 16];
    let scope = selector_pact_scope(FederationScopeFacets::All);
    let digest = federation_scope_digest(&nonce, &encode_federation_pact_scope(&scope).unwrap());
    let connect_gesture = sign_federation_pact_gesture(
        FederationLifecycleKind::Connect,
        &pact_id,
        &vault_id,
        &peer_vault_id,
        1,
        &digest,
        None,
        &nonce,
        peer_key.clone(),
        |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
    )
    .unwrap();
    let connect = signed_lifecycle_entry(
        &owner,
        vault_id,
        1,
        authority_entry_hash(&genesis).unwrap(),
        FederationLifecycleAction {
            kind: FederationLifecycleKind::Connect,
            pact_id,
            grant_ref: grant_id,
            peer_vault_id,
            pact_epoch: 1,
            pact_scope: Some(scope),
            effective_scope: None,
            scope_digest: Some(digest),
            gesture: Some(connect_gesture),
            successor_vault_id: None,
            pact_nonce: nonce,
        },
    );
    let connect_hash = authority_entry_hash(&connect).unwrap();
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();
    vault
        .put_authority_log_entry(&connect, TimeRange { start: 2, end: 2 }, 2)
        .unwrap();

    let unilateral = |kind: FederationLifecycleKind, seq: u64| {
        signed_lifecycle_entry(
            &owner,
            vault_id,
            seq,
            connect_hash,
            FederationLifecycleAction {
                kind,
                pact_id,
                grant_ref: grant_id,
                peer_vault_id,
                pact_epoch: 1,
                pact_scope: None,
                effective_scope: None,
                scope_digest: None,
                gesture: None,
                successor_vault_id: None,
                pact_nonce: nonce,
            },
        )
    };
    let repact = |seq: u64, facet_byte: u8, nonce_byte: u8| {
        let scope = selector_pact_scope(FederationScopeFacets::Some(vec![entity_id(facet_byte)]));
        let nonce = [nonce_byte; 16];
        let digest =
            federation_scope_digest(&nonce, &encode_federation_pact_scope(&scope).unwrap());
        let gesture = sign_federation_pact_gesture(
            FederationLifecycleKind::Rescope,
            &pact_id,
            &vault_id,
            &peer_vault_id,
            2,
            &digest,
            None,
            &nonce,
            peer_key.clone(),
            |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
        )
        .unwrap();
        signed_lifecycle_entry(
            &owner,
            vault_id,
            seq,
            connect_hash,
            FederationLifecycleAction {
                kind: FederationLifecycleKind::Rescope,
                pact_id,
                grant_ref: grant_id,
                peer_vault_id,
                pact_epoch: 2,
                pact_scope: Some(scope),
                effective_scope: None,
                scope_digest: Some(digest),
                gesture: Some(gesture),
                successor_vault_id: None,
                pact_nonce: nonce,
            },
        )
    };

    let extras: Vec<AuthorityLogEntry> = match status {
        PactSeedStatus::Active => Vec::new(),
        PactSeedStatus::Disconnected => vec![unilateral(FederationLifecycleKind::Disconnect, 2)],
        PactSeedStatus::Dissolved => vec![unilateral(FederationLifecycleKind::Dissolve, 2)],
        PactSeedStatus::Promoted => {
            let successor = [0x65; 32];
            let gesture = sign_federation_pact_gesture(
                FederationLifecycleKind::Promote,
                &pact_id,
                &vault_id,
                &peer_vault_id,
                2,
                &digest,
                Some(&successor),
                &nonce,
                peer_key.clone(),
                |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
            )
            .unwrap();
            vec![signed_lifecycle_entry(
                &owner,
                vault_id,
                2,
                connect_hash,
                FederationLifecycleAction {
                    kind: FederationLifecycleKind::Promote,
                    pact_id,
                    grant_ref: grant_id,
                    peer_vault_id,
                    pact_epoch: 2,
                    pact_scope: None,
                    effective_scope: None,
                    scope_digest: Some(digest),
                    gesture: Some(gesture),
                    successor_vault_id: Some(successor),
                    pact_nonce: nonce,
                },
            )]
        }
        // Two concurrent equal-epoch repacts with divergent digests.
        PactSeedStatus::Suspended => vec![repact(2, 0x21, 0x66), repact(3, 0x22, 0x67)],
    };
    for entry in extras {
        vault
            .put_authority_log_entry(&entry, TimeRange { start: 3, end: 3 }, 3)
            .unwrap();
    }
}

#[test]
fn selector_authorization_gates_on_pact_activation() {
    let member = entity_id(0x34);

    // A grant with no lifecycle entries (Unpacted) authorizes exactly as
    // today: legacy-allow.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("unpacted grant keeps legacy-allow");

    // A pact-bound grant with status Active authorizes.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_pact_for_grant(&vault, grant_id, PactSeedStatus::Active);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("active pact-bound grant authorizes");

    // Suspended/Promoted/Disconnected/Dissolved pacts deny with GrantInactive.
    for (name, status) in [
        ("suspended", PactSeedStatus::Suspended),
        ("promoted", PactSeedStatus::Promoted),
        ("disconnected", PactSeedStatus::Disconnected),
        ("dissolved", PactSeedStatus::Dissolved),
    ] {
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        seed_pact_for_grant(&vault, grant_id, status);
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        let err = authorize_sync_selector(&vault, test_selector_scope(), &selector)
            .expect_err("non-active pact-bound grant must deny");
        assert!(
            matches!(
                err,
                Error::SyncProtocolError {
                    context: SyncProtocolValidation::Selector {
                        reason: SelectorError::GrantInactive
                    }
                }
            ),
            "{name}: wrong denial: {err:?}"
        );
    }
}

/// ONE-1604-D1 T10 (the 1632 seam floor): the keystone changes no
/// authorization outcome. A rejected divergent-overwrite attempt against an
/// admitted type-122 row leaves `authorize_sync_selector` deciding exactly as
/// it did before — 1631 hardens the store, it does not move the
/// authorization edge that 1632 will later split.
#[test]
fn rejected_divergent_authority_overwrite_does_not_change_authorization() {
    let member = entity_id(0x34);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_pact_for_grant(&vault, grant_id, PactSeedStatus::Active);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("precondition: the pact-bound grant authorizes");

    // Attempt a body-divergent write at an admitted authority row's key.
    let foreign = authority_genesis_entry(0x77);
    let foreign_body = encode_authority_log_entry_body(&foreign).unwrap();
    let occupied = vault
        .entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
        .into_iter()
        .next()
        .expect("an authority row must be seeded");
    let err = vault
        .batch()
        .put_replicated(
            &occupied,
            ENTITY_TYPE_AUTHORITY_LOG,
            TimeRange { start: 9, end: 9 },
            9,
            &foreign_body,
        )
        .commit()
        .expect_err("a divergent body at an occupied type-122 key must be rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::AuthorityLogStoreKeyMismatch
    );

    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("authorization must be byte-for-byte unchanged after the rejected overwrite");
}
