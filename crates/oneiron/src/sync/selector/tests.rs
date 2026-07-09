use ed25519_dalek::{Signer, SigningKey};
use loro::{ExportMode, LoroDoc};

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
    ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_WORLD,
};
use crate::store::Store;
use crate::sync::bridge::encode_edge_value_for_crdt;
use crate::sync::loro_support::map_get_bytes;
use crate::temporal::TimeRange;

fn entity_id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn local_world_id(byte: u8) -> LocalWorldId {
    LocalWorldId::from_entity_id(entity_id(byte)).unwrap()
}

fn entity_blob(entity_type: u8, body: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    blob.push(entity_type);
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(&1_u64.to_be_bytes());
    blob.extend_from_slice(body);
    blob
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

fn edge_provenance_claim_blob() -> Vec<u8> {
    let confidence = 0.75_f32;
    let record =
        EdgeProvenanceClaimBody::new(entity_id(0xA4), confidence, SupersessionStatus::Confirmed);
    let mut claim = ClaimBody::new(
        crate::provenance::PREDICATE_EDGE_PROVENANCE,
        ClaimSubject::Edge {
            source: entity_id(0xA5),
            kind: EdgeKind::Mentions,
            target: entity_id(0xA6),
        },
        encode_edge_provenance_value(&record),
        confidence,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    claim.evidence = Some(encode_actor_class_evidence(EdgeActorClass::Human));
    claim.source = Some(ClaimSource::ToolOutput);
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

fn insert_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
    let key = format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex());
    let value = encode_edge_value_for_crdt(kind, 0.7, 1, Some(Vad::NEUTRAL), None).unwrap();
    map_insert_bytes(&doc.get_map("edges"), &key, &value).unwrap();
}

fn insert_malformed_edge(doc: &LoroDoc, src: EntityId, kind: EdgeKind, tgt: EntityId) {
    let key = format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex());
    doc.get_map("edges")
        .insert(key.as_str(), "not-binary")
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

fn test_vault_with_grant_scope(
    member_ref: EntityId,
    scope: FederationGrantScope,
) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
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
    (dir, vault, grant_id)
}

fn test_vault_with_grant(member_ref: EntityId) -> (tempfile::TempDir, Vault, EntityId) {
    test_vault_with_grant_scope(member_ref, test_selector_scope())
}

#[test]
fn selector_codec_round_trips_strict_payload() {
    let selector = SyncSelector::new(
        entity_id(0xA1),
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
        entity_id(0xA1),
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
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xA2));
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(
        &doc,
        entity_id(0xA3),
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
fn federated_admission_rejects_foreign_authority_log() {
    let (_dir, vault, _grant_id) = test_vault_with_grant(entity_id(0xB2));
    let local = authority_genesis_entry(0x51);
    vault
        .put_authority_log_entry(&entity_id(0x51), &local, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();

    let foreign = authority_genesis_entry(0x52);
    let foreign_body = encode_authority_log_entry_body(&foreign).unwrap();
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("remote", &window_key);
    insert_entity(
        &doc,
        entity_id(0x52),
        ENTITY_TYPE_AUTHORITY_LOG,
        &foreign_body,
    );
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

    let facet_allowed = entity_id(0xA1);
    let facet_denied = entity_id(0xB1);
    let claim_allowed = entity_id(0x11);
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
    let world = local_world_id(0xE1);
    let other_world = entity_id(0xE2);
    let claim_world = entity_id(0x41);
    let claim_base = entity_id(0x42);
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
