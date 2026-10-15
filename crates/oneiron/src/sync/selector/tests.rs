use std::sync::Arc;

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
use crate::edge::EdgeActorClass;
use crate::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    encode_federation_grant_body, encode_guest_share_envelope_body,
};
use crate::provenance::{
    EdgeProvenanceClaimBody, SupersessionStatus, encode_actor_class_evidence,
    encode_edge_provenance_value,
};
use crate::registry::{
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_WORLD, TypeByteFamily,
};
use crate::store::Store;
use crate::sync::bridge::encode_edge_value_for_crdt;
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
        recovery: crate::authority::GenesisRecoveryStep::Saved([1; 32]),
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
    )
    .unwrap();
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
    )
    .unwrap();
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
    )
    .unwrap();
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

fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (
            Value::from("schema_version"),
            Value::from(crate::gate::POLICY_SCHEMA_VERSION),
        ),
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
            crate::gate::stamp_manifest_origin(&vault.store, wtxn, &id, &body, false)?;
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
    let selector = SyncSelector::new(grant_id, member_ref, SyncSelectorWorld::All, vec![], vec![]);
    let peer = crate::sync::federation_burst::FederationPeer::authorize(
        &vault,
        member_ref,
        test_selector_scope(),
        &selector,
    )
    .unwrap();
    let (client, _rx) = SyncClient::new(
        manager,
        SyncClientConfig {
            federation_peer: Some(peer),
            ..Default::default()
        },
    )
    .unwrap();
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
    client.replay_deferred_federation_update().unwrap();
}

/// Seeds mandatory record stamps for a manually built source doc.
///
/// The export filter withholds unstamped non-CLAIM rows, so every FACET /
/// PERSON / EVENT / WORLD doc row needs a matching local stamp (same bytes,
/// same digest) for the facet/band/world doors — not missing stamps — to
/// decide. CLAIM rows are intrinsic and skipped.
///
/// Same-type overwrites update the stamp to the doc bytes (type unchanged,
/// so scoping is unaffected); different-type conflicts are left alone
/// (`EntityTypeImmutable` ignored) so stored truth wins and the doc blob
/// stays unstamped-filtered, fail-closed.
fn seed_doc_stamps(vault: &Vault, doc: &LoroDoc) {
    use crate::sync::loro_support::map_for_each_value_bytes;
    let mut puts = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |raw_key, maybe_blob| {
        let Some(blob) = maybe_blob else {
            return;
        };
        let Ok(id) = EntityId::from_hex(raw_key) else {
            return;
        };
        if id.to_hex() != raw_key {
            return;
        };
        let Some(header) = EntityMetadataHeader::parse(blob) else {
            return;
        };
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            return;
        }
        puts.push((id, header.entity_type, blob.to_vec()));
    });
    for (id, entity_type, blob) in puts {
        let body = &blob[ENTITY_METADATA_HEADER_LEN..];
        let res = vault
            .batch()
            .put(&id, entity_type, TimeRange { start: 1, end: 1 }, 1, body)
            .commit();
        match res {
            Ok(()) => {}
            Err(Error::Registry(crate::error::RegistryError::EntityTypeImmutable { .. })) => {}
            Err(other) => panic!("seed_doc_stamps failed for {id:?}: {other:?}"),
        }
    }
}

/// Stamps ONLY the listed honest rows from a live (federated) doc.
///
/// Replicated opaque rows carry no record stamp (`stamp_put` refuses to invent
/// one for peer bytes), so the export filter withholds them until the owner
/// explicitly verifies the position with a local put. This helper is that
/// explicit verification for test fixtures: it reads the CURRENT live-doc
/// bytes for each id and puts them locally (same type, same bytes, digest
/// matches). CLAIM ids are skipped (intrinsic, no stamp needed).
///
/// The caller names ONLY honest controls — never forged sources, forged
/// targets, retype conflicts, or hostile neighbors. A conflicting doc blob
/// (rejected retype) fails with `EntityTypeImmutable` and is left unstamped,
/// fail-closed, exactly like `seed_doc_stamps`.
fn stamp_live_rows(vault: &Vault, doc: &LoroDoc, ids: &[EntityId]) {
    for id in ids {
        let Some(blob) = map_get_bytes(&doc.get_map("entities"), &id.to_hex()) else {
            panic!("stamp_live_rows: {id:?} not in live doc");
        };
        let Some(header) = EntityMetadataHeader::parse(&blob) else {
            panic!("stamp_live_rows: {id:?} header unparsable");
        };
        if header.entity_type == crate::registry::ENTITY_TYPE_CLAIM {
            continue;
        }
        let body = &blob[ENTITY_METADATA_HEADER_LEN..];
        match vault
            .batch()
            .put(
                id,
                header.entity_type,
                TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .commit()
        {
            Ok(()) => {}
            Err(Error::Registry(crate::error::RegistryError::EntityTypeImmutable { .. })) => {}
            Err(other) => panic!("stamp_live_rows failed for {id:?}: {other:?}"),
        }
    }
}

#[test]
fn selector_codec_round_trips_strict_payload() {
    let selector = SyncSelector::new(
        entity_id(0x50),
        entity_id(0xB1),
        SyncSelectorWorld::World(local_world_id(0xC1)),
        vec![entity_id(0xD1), entity_id(0xD1)],
        vec![
            SelectorRange::Core,
            SelectorRange::Semantic,
            SelectorRange::Core,
        ],
    );
    let payload = encode_selector_vv_request(&selector, b"vv").unwrap();
    let decoded = decode_selector_vv_request(&payload).unwrap();
    assert_eq!(decoded.selector, selector);
    assert_eq!(decoded.remote_vv, b"vv");

    let mut trailing = encode_sync_selector(&selector).unwrap();
    trailing.push(0);
    assert!(decode_sync_selector(&trailing).is_err());

    for bad_version in [3_u64, 99_u64] {
        let unsupported_version = Value::Map(vec![
            (Value::from(KEY_SCHEMA_VERSION), Value::from(bad_version)),
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
                        .named()
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
                        .named()
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
        Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: SelectorError::ForeignWorldId
            }
        })
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
        Error::Registry(RegistryError::MaintenanceKindNotWritable(
            crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
        ))
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
        assert!(matches!(
            err,
            Error::Registry(RegistryError::ReservedEdgeKind(_))
        ));
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

/// ONE-1604-D1 (fix-leg 4, admission door): admission validated the AUTHORITY_LOG
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
    // Mandatory record stamps for the non-CLAIM doc rows, including the
    // denied ones: facet withholding (not missing stamps) must decide.
    vault
        .batch()
        .put(
            &facet_allowed,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-a",
        )
        .put(
            &facet_denied,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-b",
        )
        .put(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .put(
            &denied_only_person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"denied-only-person",
        )
        .commit()
        .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    let mut edge_keys = Vec::new();
    map_for_each_value_bytes(&receiver.get_map("edges"), |key, value| {
        if value.is_some() {
            edge_keys.push(key.to_owned());
        }
    });
    assert!(edge_keys.contains(&edge_key(claim_allowed, EdgeKind::FacetOf, facet_allowed)));
    assert!(edge_keys.contains(&edge_key(claim_allowed, EdgeKind::Supports, person)));
    for withheld in [claim_denied, facet_denied, denied_only_person] {
        let source_prefix = format!("{}:", withheld.to_hex());
        let target_suffix = format!(":{}", withheld.to_hex());
        assert!(
            edge_keys
                .iter()
                .all(|key| !key.starts_with(&source_prefix) && !key.ends_with(&target_suffix)),
            "an edge incident to a withheld entity leaked"
        );
    }
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
    let facet_allowed = entity_id(0x51);
    let claim_seed = entity_id(0x61);
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
    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_edge(&doc, person, EdgeKind::Supports, membership);
    insert_edge(&doc, person, EdgeKind::Supports, authority_id);
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, person);
    insert_tombstone(&doc, entity_id(0x63));
    doc.commit();
    vault
        .batch()
        .put(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .put(
            &facet_allowed,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-a",
        )
        .commit()
        .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
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

/// R11133 on the federation door: a claim already resident in the window
/// leaves the selector's synthetic doc, with every edge naming it, once its
/// world turns device-only.
#[test]
fn selector_withholds_a_resident_claim_once_its_world_turns_device_only() {
    let member = entity_id(0x3B);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-03");
    let world = local_world_id(0x5B).entity_id();
    vault
        .put_entity(
            &world,
            ENTITY_TYPE_WORLD,
            TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    let doc = create_window_doc("source", &window_key);
    let kept_claim = entity_id(0x7B);
    let private_claim = entity_id(0x7C);
    let facet = entity_id(0x5C);
    insert_blob(&doc, kept_claim, &claim_blob(None));
    insert_blob(&doc, private_claim, &claim_blob(Some(world)));
    insert_entity(&doc, facet, ENTITY_TYPE_FACET, b"facet");
    insert_edge(&doc, kept_claim, EdgeKind::FacetOf, facet);
    insert_edge(&doc, private_claim, EdgeKind::FacetOf, facet);
    insert_edge(&doc, kept_claim, EdgeKind::Supports, private_claim);
    doc.commit();
    seed_doc_stamps(&vault, &doc);
    vault
        .keep_world_on_this_machine_for_test(world, true)
        .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let selected =
        filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector).unwrap();
    let ids = import_ids(&selected.export(ExportMode::all_updates()).unwrap());
    assert!(ids.contains(&kept_claim));
    assert!(!ids.contains(&private_claim));
    let mut edges = Vec::new();
    map_for_each_value_bytes(&selected.get_map("edges"), |key, _| {
        edges.push(key.to_owned());
    });
    assert!(edges.contains(&edge_key(kept_claim, EdgeKind::FacetOf, facet)));
    assert!(
        !edges
            .iter()
            .any(|key| key.contains(&private_claim.to_hex()))
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
    seed_doc_stamps(&vault, &doc);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    seed_doc_stamps(&vault, &doc);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    let local = create_window_doc("local", &window_key);
    let sender = (member, grant_id);
    import_from_peer(
        &vault,
        &local,
        &window_key,
        &update,
        sender,
        FederationAdmissionRole::Member,
    );
    // The local owner verifies these known fixture bodies, not the forged
    // FacetOf edge. With all four records stamped, missing Scope evidence
    // cannot mask a failure of the edge-disclosure boundary under test.
    stamp_live_rows(&vault, &local, &[facet_selected, event, person, neighbor]);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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

/// Astra on #1432 F2: a facet-narrowed reader reads a row in ANY of its
/// facets, so a stamp a peer adds to a row this vault already holds would put
/// the row in front of readers it was withheld from. The admission door drops
/// it with typed evidence for either role: a reader narrowed to the added
/// facet still does not read the row, while the stamp a row is born with in
/// the same frame still lands.
#[test]
fn a_peer_stamp_onto_a_stored_row_puts_it_in_no_new_facet() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0x6B_u8),
        (FederationAdmissionRole::Guest, 0x73_u8),
    ] {
        let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(seed));
        let window_key = WindowKey::new("2026-05");
        let [work, private, held, born] = [1, 2, 3, 4].map(|n| entity_id(seed + n));
        for (id, kind) in [
            (work, ENTITY_TYPE_FACET),
            (private, ENTITY_TYPE_FACET),
            (held, ENTITY_TYPE_EVENT),
        ] {
            vault
                .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"row")
                .unwrap();
        }
        vault
            .put_edge(&held, EdgeKind::FacetOf, &private, 1.0)
            .unwrap();

        let remote = create_window_doc("federation-peer", &window_key);
        insert_edge(&remote, held, EdgeKind::FacetOf, work);
        insert_entity(&remote, born, ENTITY_TYPE_EVENT, b"born");
        insert_edge(&remote, born, EdgeKind::FacetOf, work);
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();
        let local = create_window_doc("local", &window_key);
        let sender = (entity_id(seed), grant_id);
        import_from_peer(&vault, &local, &window_key, &update, sender, role);

        let only =
            |facet: EntityId| ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(facet)]));
        assert!(
            !vault.row_in_facets(&held, &only(work)).unwrap(),
            "{role:?}: a peer's stamp put a held row in front of a work reader"
        );
        assert!(vault.row_in_facets(&held, &only(private)).unwrap());
        assert!(
            vault.row_in_facets(&born, &only(work)).unwrap(),
            "{role:?}: the stamp a row is born with still lands"
        );
        assert!(
            quarantined_records(&vault)
                .unwrap()
                .iter()
                .any(|(_, record)| record.reason_code == "FacetStampImmutable"
                    && record.container == QuarantineContainer::Edges),
            "{role:?}: the dropped stamp leaves typed evidence"
        );
    }
}

fn facet_set(facet: EntityId) -> ScopeAxis<ScopeId> {
    ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(facet)]))
}

fn put_row(vault: &Vault, id: EntityId, kind: u8) {
    vault
        .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"row")
        .unwrap();
}

fn stamp_stored(vault: &Vault, src: EntityId, facet: EntityId) -> bool {
    let txn = vault.store.env.read_txn().unwrap();
    crate::ports::EdgeStoreRead::port_edge_get(&vault.store, &txn, &src, EdgeKind::FacetOf, &facet)
        .unwrap()
        .is_some()
}

fn rematerialize(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) {
    crate::sync::window::forward_rematerialize(
        vault,
        doc,
        &crate::sync::bridge::Materializer::new(),
        window_key,
    )
    .unwrap();
}

/// What the sync client does with an update `peer` sent under `grant`, on
/// `doc`: admit it, hold the stamps it sends ahead of their rows, import and
/// materialize it, then release the stamps whose rows it birthed.
fn import_from_peer(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    update: &[u8],
    (peer, grant): (EntityId, EntityId),
    role: FederationAdmissionRole,
) {
    let admitted = admit_peer_window_update(vault, window_key, update, role, peer).unwrap();
    admitted.hold_from_peer(vault, window_key, grant).unwrap();
    let born = crate::sync::ingest::watch_births(vault, admitted.births(), || {
        doc.import(admitted.bytes()).unwrap();
        rematerialize(vault, doc, window_key);
        Ok::<_, ()>(())
    })
    .unwrap();
    if let Some(released) = admitted.release(vault, window_key, &born).unwrap() {
        if let Some(update) = &released.update {
            doc.import(update).unwrap();
            rematerialize(vault, doc, window_key);
        }
        released.discard(vault).unwrap();
    }
}

/// The owner's other device: a vault that takes `doc`, this window as the
/// device holding it sent it, as its own.
fn synced_device(doc: &LoroDoc, window_key: &WindowKey, device: &Vault) -> LoroDoc {
    let synced = create_window_doc("device", window_key);
    synced
        .import(&doc.export(ExportMode::all_updates()).unwrap())
        .unwrap();
    rematerialize(device, &synced, window_key);
    synced
}

/// Sol R3 F1 under the Engine's rulings: a peer sends `row -FacetOf-> work`
/// before this vault has the row. A second writer then brings the row, born
/// in `private`: a local birth or another peer. The stamp never enters the
/// window, so neither this vault nor the owner's other device, which takes
/// the window as its own, puts the row in front of a work reader. The owner's
/// stamp of the same pair counts.
#[test]
fn a_stamp_ahead_of_its_row_stays_out_of_the_window_when_another_writer_brings_the_row() {
    let window_key = WindowKey::new("2026-05");
    for (leg, seed) in [("local birth", 0x90_u8), ("another peer", 0xB0_u8)] {
        let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(seed));
        let (_device_dir, device, _) = test_vault_with_grant(entity_id(seed));
        let [peer, other, work, private, row] = [1, 2, 3, 4, 5].map(|n| entity_id(seed + n));
        for facet in [work, private] {
            put_row(&vault, facet, ENTITY_TYPE_FACET);
            put_row(&device, facet, ENTITY_TYPE_FACET);
        }
        let live = create_window_doc("local", &window_key);
        let ahead = create_window_doc("federation-peer", &window_key);
        insert_edge(&ahead, row, EdgeKind::FacetOf, work);
        ahead.commit();
        let update = ahead.export(ExportMode::all_updates()).unwrap();
        let role = FederationAdmissionRole::Member;
        import_from_peer(&vault, &live, &window_key, &update, (peer, grant_id), role);

        if leg == "local birth" {
            for born in [&vault, &device] {
                put_row(born, row, ENTITY_TYPE_EVENT);
                born.put_edge(&row, EdgeKind::FacetOf, &private, 1.0)
                    .unwrap();
            }
        } else {
            let birth = create_window_doc("federation-peer", &window_key);
            insert_entity(&birth, row, ENTITY_TYPE_EVENT, b"row");
            insert_edge(&birth, row, EdgeKind::FacetOf, private);
            birth.commit();
            let update = birth.export(ExportMode::all_updates()).unwrap();
            import_from_peer(&vault, &live, &window_key, &update, (other, grant_id), role);
        }
        rematerialize(&vault, &live, &window_key);
        synced_device(&live, &window_key, &device);

        assert!(
            map_get_bytes(
                &live.get_map("edges"),
                &edge_key(row, EdgeKind::FacetOf, work)
            )
            .is_none(),
            "{leg}: a stamp whose sender never brought its row entered the window"
        );
        assert!(!stamp_stored(&vault, row, work), "{leg}");
        assert!(
            !vault.row_in_facets(&row, &facet_set(work)).unwrap(),
            "{leg}"
        );
        assert!(
            vault.row_in_facets(&row, &facet_set(private)).unwrap(),
            "{leg}"
        );
        assert!(
            !device.row_in_facets(&row, &facet_set(work)).unwrap(),
            "{leg}: the owner's other device put the row in front of a work reader"
        );
        assert!(
            device.row_in_facets(&row, &facet_set(private)).unwrap(),
            "{leg}"
        );
        vault.put_edge(&row, EdgeKind::FacetOf, &work, 1.0).unwrap();
        assert!(
            vault.row_in_facets(&row, &facet_set(work)).unwrap(),
            "{leg}: the owner's own stamp of the pair counts"
        );
    }
}

/// The positive control, on the production client: the same peer sends the
/// stamp first and the row second. The stamp enters the window once the
/// row's birth applies, so a reader narrowed to the stamped facet reads the
/// row, and the stamp seeds a facet-limited export, on this vault and on the
/// owner's other device alike (H2).
#[test]
fn a_peer_that_brings_its_row_after_the_stamp_puts_it_in_the_stamped_facet() {
    for (role, seed) in [
        (FederationAdmissionRole::Member, 0xB0_u8),
        (FederationAdmissionRole::Guest, 0xC0_u8),
    ] {
        let window = "2026-05";
        let window_key = WindowKey::new(window);
        let member = entity_id(seed);
        let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
        let (_device_dir, device, device_grant) = test_vault_with_grant(member);
        let [work, row] = [1, 2].map(|n| entity_id(seed + n));
        let ahead = create_window_doc("federation-peer", &window_key);
        insert_entity(&ahead, work, ENTITY_TYPE_FACET, b"work");
        insert_edge(&ahead, row, EdgeKind::FacetOf, work);
        ahead.commit();
        import_federated(&mut client, window, &ahead, role);
        let birth = create_window_doc("federation-peer", &window_key);
        insert_entity(&birth, row, ENTITY_TYPE_EVENT, b"row");
        birth.commit();
        import_federated(&mut client, window, &birth, role);
        let live = client.window(window).expect("window still loaded");
        rematerialize(&vault, &live.doc, &window_key);
        let synced = synced_device(&live.doc, &window_key, &device);

        for (name, holder, doc, grant) in [
            ("this vault", &*vault, &live.doc, grant_id),
            ("the other device", &device, &synced, device_grant),
        ] {
            assert!(stamp_stored(holder, row, work), "{role:?} {name}");
            assert!(
                holder.row_in_facets(&row, &facet_set(work)).unwrap(),
                "{role:?} {name}: the peer brought the row it stamped"
            );
            stamp_live_rows(holder, doc, &[work, row]);
            let selector = SyncSelector::new(
                grant,
                member,
                SyncSelectorWorld::All,
                vec![work],
                vec![SelectorRange::Semantic, SelectorRange::Core],
            );
            let exported =
                filtered_window_doc(holder, doc, &window_key, test_selector_scope(), &selector)
                    .unwrap()
                    .export(ExportMode::all_updates())
                    .unwrap();
            assert!(
                import_ids(&exported).contains(&row),
                "{role:?} {name}: the released stamp seeds the facet-limited export"
            );
        }
    }
}

/// Sol R3 F1's staged form: a foreign artifact holds only `row -FacetOf->
/// work`, staged while this vault lacks the row. The row is then born here in
/// `private`, and the operator confirms the artifact. The stamp never enters
/// the window, so a work reader does not read the row.
#[test]
fn a_staged_stamp_confirmed_after_its_row_arrived_stays_out_of_reads() {
    let window = "2026-05";
    let window_key = WindowKey::new(window);
    let (_dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(0xD0), window);
    let [work, private, row, actor] = [1, 2, 3, 4].map(|n| entity_id(0xD0 + n));
    for facet in [work, private] {
        put_row(&vault, facet, ENTITY_TYPE_FACET);
    }
    let artifact = create_window_doc("foreign", &window_key);
    insert_edge(&artifact, row, EdgeKind::FacetOf, work);
    artifact.commit();
    let classification = crate::batch::export::VaultImportReceipt {
        manifest_digest: [0xD0; 32],
        classification: crate::batch::export::VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    let staged = crate::batch::export::stage_foreign_vault_import(
        &vault,
        &classification,
        crate::batch::export::ForeignVaultImportSource::ForeignPlatform {
            platform: "elsewhere".into(),
        },
        &window_key,
        &artifact.export(ExportMode::all_updates()).unwrap(),
    )
    .unwrap();

    put_row(&vault, row, ENTITY_TYPE_EVENT);
    vault
        .put_edge(&row, EdgeKind::FacetOf, &private, 1.0)
        .unwrap();
    let confirmation = crate::batch::export::VaultImportConfirmation {
        receipt_id: staged.receipt.receipt_id,
        actor,
        confirmed_at_secs: 1,
    };
    client
        .confirm_staged_vault_import(staged, confirmation)
        .unwrap();
    let live = client.window(window).expect("confirm loads the window");
    rematerialize(&vault, &live.doc, &window_key);

    assert!(
        map_get_bytes(
            &live.doc.get_map("edges"),
            &edge_key(row, EdgeKind::FacetOf, work)
        )
        .is_none(),
        "an artifact that never brought the row put its stamp in the window"
    );
    assert!(!stamp_stored(&vault, row, work));
    assert!(!vault.row_in_facets(&row, &facet_set(work)).unwrap());
    assert!(vault.row_in_facets(&row, &facet_set(private)).unwrap());
}

/// Sol R5 F4 and Wonder R5 F1: a foreign artifact brings `row` and its
/// `row -FacetOf-> work` together, staged while this vault lacks the row. The
/// row is then born here in `private`, and the operator confirms: the
/// artifact no longer brings the row's birth, so its stamp is not released
/// and a work reader does not read the row.
#[test]
fn a_staged_birth_confirmed_after_another_writer_birthed_the_row_releases_no_stamp() {
    let window = "2026-05";
    let window_key = WindowKey::new(window);
    let (_dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(0xD8), window);
    let [work, private, row, actor] = [1, 2, 3, 4].map(|n| entity_id(0xD8 + n));
    for facet in [work, private] {
        put_row(&vault, facet, ENTITY_TYPE_FACET);
    }
    let artifact = create_window_doc("foreign", &window_key);
    insert_entity(&artifact, row, ENTITY_TYPE_EVENT, b"row");
    insert_edge(&artifact, row, EdgeKind::FacetOf, work);
    artifact.commit();
    let classification = crate::batch::export::VaultImportReceipt {
        manifest_digest: [0xD8; 32],
        classification: crate::batch::export::VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    let staged = crate::batch::export::stage_foreign_vault_import(
        &vault,
        &classification,
        crate::batch::export::ForeignVaultImportSource::ForeignPlatform {
            platform: "elsewhere".into(),
        },
        &window_key,
        &artifact.export(ExportMode::all_updates()).unwrap(),
    )
    .unwrap();

    put_row(&vault, row, ENTITY_TYPE_EVENT);
    vault
        .put_edge(&row, EdgeKind::FacetOf, &private, 1.0)
        .unwrap();
    let confirmation = crate::batch::export::VaultImportConfirmation {
        receipt_id: staged.receipt.receipt_id,
        actor,
        confirmed_at_secs: 1,
    };
    client
        .confirm_staged_vault_import(staged, confirmation)
        .unwrap();
    let live = client.window(window).expect("confirm loads the window");
    rematerialize(&vault, &live.doc, &window_key);
    assert!(
        map_get_bytes(
            &live.doc.get_map("edges"),
            &edge_key(row, EdgeKind::FacetOf, work)
        )
        .is_none(),
        "an artifact whose row another writer birthed released its stamp"
    );
    assert!(!stamp_stored(&vault, row, work));
    assert!(!vault.row_in_facets(&row, &facet_set(work)).unwrap());
    assert!(vault.row_in_facets(&row, &facet_set(private)).unwrap());
}

/// Stages `artifact` under a receipt as a foreign platform's export, while
/// this vault may lack its rows.
fn stage_artifact(
    vault: &Vault,
    window_key: &WindowKey,
    artifact: &LoroDoc,
    digest: u8,
) -> crate::batch::export::StagedVaultImport {
    let classification = crate::batch::export::VaultImportReceipt {
        manifest_digest: [digest; 32],
        classification: crate::batch::export::VaultImportClassification::ForeignAuthorityChain,
        mismatches: vec![],
        exported_vault_id: None,
        local_vault_id: None,
        exported_label: None,
        expected_label: None,
        byte_faithful: false,
    };
    crate::batch::export::stage_foreign_vault_import(
        vault,
        &classification,
        crate::batch::export::ForeignVaultImportSource::ForeignPlatform {
            platform: "elsewhere".into(),
        },
        window_key,
        &artifact.export(ExportMode::all_updates()).unwrap(),
    )
    .unwrap()
}

/// `actor` confirms `staged`; the confirmed window is materialized.
fn confirm_artifact(
    vault: &Vault,
    client: &mut SyncClient,
    window_key: &WindowKey,
    staged: crate::batch::export::StagedVaultImport,
    actor: EntityId,
) {
    let confirmation = crate::batch::export::VaultImportConfirmation {
        receipt_id: staged.receipt.receipt_id,
        actor,
        confirmed_at_secs: 1,
    };
    client
        .confirm_staged_vault_import(staged, confirmation)
        .unwrap();
    let live = client
        .window(window_key.as_str())
        .expect("confirm loads the window");
    rematerialize(vault, &live.doc, window_key);
}

/// The rows a lane holds.
fn held_under(vault: &Vault, lane: &str) -> u64 {
    let txn = vault.store.env.read_txn().unwrap();
    crate::federation::facet_read::held_rows_under(&vault.store, &txn, lane)
        .unwrap()
        .0
}

/// Rule 5 on #1432: a confirmed staged artifact is the owner's own work, so
/// no count drops its stamps. One that brings a row and stamps it into 17
/// facets, one past a peer's per-row cap, places all 17 at its confirmation.
#[test]
fn a_confirmed_staged_artifact_places_every_stamp_of_its_row() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(0x84), "2026-05");
    let facets: Vec<EntityId> = (0x85..=0x95).map(entity_id).collect();
    let [row, actor] = [0x96, 0x97].map(entity_id);
    let artifact = create_window_doc("foreign", &window_key);
    insert_entity(&artifact, row, ENTITY_TYPE_EVENT, b"row");
    for &facet in &facets {
        put_row(&vault, facet, ENTITY_TYPE_FACET);
        insert_edge(&artifact, row, EdgeKind::FacetOf, facet);
    }
    artifact.commit();
    let staged = stage_artifact(&vault, &window_key, &artifact, 0x84);
    confirm_artifact(&vault, &mut client, &window_key, staged, actor);

    assert_eq!(
        facets.len(),
        crate::federation::facet_read::MAX_HELD_PER_ROW + 1
    );
    for &facet in &facets {
        assert!(
            stamp_stored(&vault, row, facet),
            "a confirmed artifact's stamp into {} was dropped by count",
            facet.to_hex()
        );
        assert!(vault.row_in_facets(&row, &facet_set(facet)).unwrap());
    }
}

/// Astra-c F1 on #1432: an owner's staged stamps stay held while the
/// receipt is Pending, whatever their age, and the one on the row the
/// artifact brings lands at its confirmation; a peer's stamp as old retires.
/// Once the receipt is confirmed, the stamp it held on a row it never
/// brought leaves with it.
#[test]
fn a_pending_staged_stamp_outlives_the_age_a_peer_stamp_retires_at() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, grant_id, mut client) = test_client_with_grant(entity_id(0x98), "2026-05");
    let [work, row, stray, peer, peer_row, actor] = [1, 2, 3, 4, 5, 6].map(|n| entity_id(0x98 + n));
    put_row(&vault, work, ENTITY_TYPE_FACET);
    let artifact = create_window_doc("foreign", &window_key);
    insert_entity(&artifact, row, ENTITY_TYPE_EVENT, b"row");
    insert_edge(&artifact, row, EdgeKind::FacetOf, work);
    insert_edge(&artifact, stray, EdgeKind::FacetOf, work);
    artifact.commit();
    let staged = stage_artifact(&vault, &window_key, &artifact, 0x98);
    let ahead = create_window_doc("federation-peer", &window_key);
    insert_edge(&ahead, peer_row, EdgeKind::FacetOf, work);
    ahead.commit();
    import_from_peer(
        &vault,
        &create_window_doc("local", &window_key),
        &window_key,
        &ahead.export(ExportMode::all_updates()).unwrap(),
        (peer, grant_id),
        FederationAdmissionRole::Member,
    );
    let peer_lane = crate::federation::facet_read::HeldLane::Peer(peer).key();
    let staged_lane =
        crate::federation::facet_read::HeldLane::Staged(staged.receipt.receipt_id).key();
    assert_eq!(
        (
            held_under(&vault, &peer_lane),
            held_under(&vault, &staged_lane)
        ),
        (1, 2),
        "precondition: both lanes hold their stamps"
    );

    let aged =
        vault.store.clock.now_recorded_at() + crate::federation::facet_read::HELD_STAMP_TTL_SECS;
    let retire = |now| {
        crate::federation::facet_read::retire_held_stamps(&vault, now, |_, grants| {
            Ok(grants.clone())
        })
        .unwrap()
    };
    assert_eq!(retire(aged), 1, "only the peer's stamp ages out");
    assert_eq!(held_under(&vault, &peer_lane), 0);
    assert_eq!(held_under(&vault, &staged_lane), 2);
    confirm_artifact(&vault, &mut client, &window_key, staged, actor);
    assert!(
        stamp_stored(&vault, row, work),
        "the owner's staged stamp lands"
    );
    assert!(vault.row_in_facets(&row, &facet_set(work)).unwrap());
    assert_eq!(
        retire(vault.store.clock.now_recorded_at()),
        1,
        "the stamp on a row the confirmed artifact never brought leaves with it"
    );
    assert_eq!(held_under(&vault, &staged_lane), 0);
}

/// A staged artifact that brings `row` and stamps it into `work`, its record
/// of that stamp rewritten by `edit` (bound to the receipt when `bind`) and
/// staged again, then confirmed, which it refuses.
fn confirm_edited_record(
    seed: u8,
    edit: impl FnOnce(&mut Vec<u8>, EntityId),
    bind: bool,
) -> (tempfile::TempDir, Arc<Vault>, [EntityId; 3]) {
    let window_key = WindowKey::new("2026-05");
    let (dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(seed), "2026-05");
    let [work, home, row, actor] = [1, 2, 3, 4].map(|n| entity_id(seed + n));
    for facet in [work, home] {
        put_row(&vault, facet, ENTITY_TYPE_FACET);
    }
    let artifact = create_window_doc("foreign", &window_key);
    insert_entity(&artifact, row, ENTITY_TYPE_EVENT, b"row");
    insert_edge(&artifact, row, EdgeKind::FacetOf, work);
    artifact.commit();
    let id = stage_artifact(&vault, &window_key, &artifact, seed)
        .receipt
        .receipt_id;
    let mut record = crate::batch::export::vault_import_staged_stamps(&vault, &id)
        .unwrap()
        .expect("the receipt keeps its record");
    edit(&mut record, home);
    crate::batch::export::rewrite_staged_stamps_for_test(&vault, &id, &record, bind).unwrap();
    let staged = stage_artifact(&vault, &window_key, &artifact, seed);
    let confirmation = crate::batch::export::VaultImportConfirmation {
        receipt_id: id,
        actor,
        confirmed_at_secs: 1,
    };
    client
        .confirm_staged_vault_import(staged, confirmation)
        .expect_err("an edited record refuses the confirmation");
    assert_eq!(
        crate::batch::export::vault_import_stage_receipt(&vault, &id)
            .unwrap()
            .unwrap()
            .status,
        crate::batch::export::VaultImportStageStatus::Pending,
        "the refused confirmation leaves the receipt Pending"
    );
    (dir, vault, [work, home, row])
}

/// Astra-d F1 on #1432: the receipt binds its record of staged stamps by
/// digest, so a record whose stamp was moved on disk to another stored facet
/// refuses the confirmation, and nothing lands.
#[test]
fn a_staged_record_moved_to_another_facet_on_disk_refuses_the_confirmation() {
    let (_dir, vault, [work, home, row]) = confirm_edited_record(
        0xB3,
        |record, home| record[16..32].copy_from_slice(home.as_bytes()),
        false,
    );
    assert!(!stamp_stored(&vault, row, home));
    assert!(!stamp_stored(&vault, row, work));
    assert!(!vault.row_in_facets(&row, &facet_set(home)).unwrap());
}

/// Astra-d F1 on #1432: a recorded stamp is decoded at the confirmation as
/// admission decoded it, so a record whose digest matches but whose weight is
/// NaN refuses the confirmation, and nothing lands.
#[test]
fn a_staged_record_with_a_nan_weight_refuses_the_confirmation() {
    let (_dir, vault, [work, _, row]) = confirm_edited_record(
        0xB8,
        |record, _| record[40..44].copy_from_slice(&f32::NAN.to_le_bytes()),
        true,
    );
    assert!(!stamp_stored(&vault, row, work));
}

/// Astra-c F1 on #1432, the guard: the held table restores live while the
/// receipt restores with its content, so a Pending receipt can outlive its
/// holds. The receipt's own record holds every staged stamp again at the
/// confirmation, and the stamp lands.
#[test]
fn a_staged_stamp_whose_hold_is_gone_lands_from_its_receipt() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(0x9F), "2026-05");
    let [work, row, actor] = [0xB0, 0xB1, 0xB2].map(entity_id);
    put_row(&vault, work, ENTITY_TYPE_FACET);
    let artifact = create_window_doc("foreign", &window_key);
    insert_entity(&artifact, row, ENTITY_TYPE_EVENT, b"row");
    insert_edge(&artifact, row, EdgeKind::FacetOf, work);
    artifact.commit();
    let staged = stage_artifact(&vault, &window_key, &artifact, 0x9F);
    let lane = crate::federation::facet_read::HeldLane::Staged(staged.receipt.receipt_id).key();
    vault
        .with_write_txn_grouped(|wtxn| {
            crate::federation::facet_read::unpark_released(&vault.store, wtxn, (row, work), &lane)
        })
        .unwrap();
    assert_eq!(
        held_under(&vault, &lane),
        0,
        "precondition: the hold is gone"
    );

    confirm_artifact(&vault, &mut client, &window_key, staged, actor);
    assert!(
        stamp_stored(&vault, row, work),
        "a staged stamp whose hold was lost never landed"
    );
    assert!(vault.row_in_facets(&row, &facet_set(work)).unwrap());
}

/// Sol R5 F3: a peer's early stamps reach the owner's two devices apart, `row
/// -FacetOf-> work` on one and `row -FacetOf-> private` on the other. The same
/// row update then releases a different stamp on each. Each device authors
/// its release under its own operation ids, so own-device sync carries both
/// and the devices converge.
#[test]
fn one_row_update_releasing_different_stamps_on_two_devices_converges() {
    let window_key = WindowKey::new("2026-05");
    let (_one_dir, one, one_grant) = test_vault_with_grant(entity_id(0xC0));
    let (_two_dir, two, two_grant) = test_vault_with_grant(entity_id(0xC0));
    let [peer, work, private, row] = [1, 2, 3, 4].map(|n| entity_id(0xC0 + n));
    let role = FederationAdmissionRole::Member;
    let birth = create_window_doc("federation-peer", &window_key);
    insert_entity(&birth, row, ENTITY_TYPE_EVENT, b"row");
    birth.commit();
    let birth = birth.export(ExportMode::all_updates()).unwrap();
    let mut docs = Vec::new();
    for (device, grant, facet) in [(&one, one_grant, work), (&two, two_grant, private)] {
        put_row(device, work, ENTITY_TYPE_FACET);
        put_row(device, private, ENTITY_TYPE_FACET);
        let doc = create_window_doc("local", &window_key);
        let ahead = create_window_doc("federation-peer", &window_key);
        insert_edge(&ahead, row, EdgeKind::FacetOf, facet);
        ahead.commit();
        let ahead = ahead.export(ExportMode::all_updates()).unwrap();
        import_from_peer(device, &doc, &window_key, &ahead, (peer, grant), role);
        import_from_peer(device, &doc, &window_key, &birth, (peer, grant), role);
        docs.push(doc);
    }
    docs[0]
        .import(&docs[1].export(ExportMode::all_updates()).unwrap())
        .unwrap();
    docs[1]
        .import(&docs[0].export(ExportMode::all_updates()).unwrap())
        .unwrap();

    for (device, doc) in [(&one, &docs[0]), (&two, &docs[1])] {
        rematerialize(device, doc, &window_key);
        for facet in [work, private] {
            assert!(
                stamp_stored(device, row, facet),
                "own-device sync dropped a released stamp"
            );
        }
    }
}

/// Astra R5 F3 on #1432: an edge value that is not bytes refuses the frame
/// whether the row it names is stored or not, so the refusal tells the peer
/// nothing about the row.
#[test]
fn an_edge_value_that_is_not_bytes_is_refused_whether_or_not_its_row_is_stored() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(0xD0));
    let [peer, stored, absent, facet] = [1, 2, 3, 4].map(|n| entity_id(0xD0 + n));
    let role = FederationAdmissionRole::Member;
    put_row(&vault, stored, ENTITY_TYPE_EVENT);
    for kind in [EdgeKind::FacetOf, EdgeKind::AddressedTo] {
        for (name, src) in [("stored", stored), ("absent", absent)] {
            let probe = create_window_doc("federation-peer", &window_key);
            insert_malformed_edge(&probe, src, kind, facet);
            probe.commit();
            let update = probe.export(ExportMode::all_updates()).unwrap();
            let admitted =
                admit_peer_window_update(&vault, &window_key, &update, role, peer).map(drop);
            assert!(
                matches!(admitted, Err(Error::InvalidKey)),
                "{kind:?} onto the {name} row: {admitted:?}"
            );
        }
    }
    // Nor does a stamp the peer holds stand in for the value (Astra R7 F1).
    for (name, src) in [("stored", stored), ("absent", absent)] {
        let ahead = create_window_doc("federation-peer", &window_key);
        insert_edge(&ahead, src, EdgeKind::FacetOf, facet);
        ahead.commit();
        let ahead = ahead.export(ExportMode::all_updates()).unwrap();
        admit_peer_window_update(&vault, &window_key, &ahead, role, peer)
            .unwrap()
            .hold_from_peer(&vault, &window_key, grant_id)
            .unwrap();
        let birth = create_window_doc("federation-peer", &window_key);
        insert_entity(&birth, src, ENTITY_TYPE_EVENT, b"row");
        insert_malformed_edge(&birth, src, EdgeKind::FacetOf, facet);
        birth.commit();
        let birth = birth.export(ExportMode::all_updates()).unwrap();
        let admitted = admit_peer_window_update(&vault, &window_key, &birth, role, peer).map(drop);
        assert!(
            matches!(admitted, Err(Error::InvalidKey)),
            "a held stamp onto the {name} row: {admitted:?}"
        );
    }
}

/// Astra R8 F1 on #1432: a peer's stamp onto a stored row goes no further
/// than admission whether the row holds it or not, so no later check of the
/// frame tells the peer which.
#[test]
fn a_stamp_onto_a_stored_row_leaves_admission_alike_whether_the_row_holds_it() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x30));
    let [peer, stamped, unstamped, facet] = [1, 2, 3, 4].map(|n| entity_id(0x30 + n));
    put_row(&vault, facet, ENTITY_TYPE_FACET);
    for row in [stamped, unstamped] {
        put_row(&vault, row, ENTITY_TYPE_EVENT);
    }
    vault
        .put_edge(&stamped, EdgeKind::FacetOf, &facet, 1.0)
        .unwrap();
    for (name, row) in [("holds", stamped), ("lacks", unstamped)] {
        let probe = create_window_doc("federation-peer", &window_key);
        insert_edge(&probe, row, EdgeKind::FacetOf, facet);
        probe.commit();
        let probe = probe.export(ExportMode::all_updates()).unwrap();
        let role = FederationAdmissionRole::Member;
        let admitted = create_window_doc("local", &window_key);
        let update = admit_peer_window_update(&vault, &window_key, &probe, role, peer).unwrap();
        admitted.import(update.bytes()).unwrap();
        assert_eq!(
            admitted.get_map("edges").len(),
            0,
            "the stamp left admission when the row {name} it"
        );
    }
}

/// Astra R7 F2 on #1432: release looks up the rows an update brings without
/// copying a stored one, however many spellings of its key the update carries.
#[test]
fn release_copies_no_stored_row_for_the_keys_an_update_names() {
    const BODY: &[u8] = b"Qx7-release-fixture-body";
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x50));
    let [peer, row] = [entity_id(0x51), entity_id(0xBC)];
    vault
        .put_entity(
            &row,
            ENTITY_TYPE_EVENT,
            TimeRange { start: 1, end: 1 },
            1,
            BODY,
        )
        .unwrap();
    let update = create_window_doc("federation-peer", &window_key);
    let hex = row.to_hex();
    for upper in 0..hex.len() {
        let mut alias = hex.clone();
        alias.replace_range(upper..=upper, &hex[upper..=upper].to_uppercase());
        map_insert_bytes(&update.get_map("entities"), &alias, b"").unwrap();
    }
    update.commit();
    let update = update.export(ExportMode::all_updates()).unwrap();

    crate::ports::row_copies::watch(BODY);
    let admitted = admit_peer_window_update(
        &vault,
        &window_key,
        &update,
        FederationAdmissionRole::Member,
        peer,
    );
    assert!(admitted.is_err(), "a key in another spelling is refused");
    assert_eq!(
        crate::ports::row_copies::sites(),
        Vec::<String>::new(),
        "the readers that copied the stored row"
    );
    assert_eq!(
        crate::ports::row_copies::wiped_sites(),
        Vec::<String>::new(),
        "the readers that copied the stored row into a wiped buffer"
    );
}

/// Astra R5 F2 on #1432: the birth of a row releases every stamp its sender
/// holds on the row, so a sender holds only a bounded number there.
#[test]
fn a_sender_holds_a_bounded_number_of_stamps_on_one_row() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(0x60));
    let [peer, row] = [1, 2].map(|n| entity_id(0x60 + n));
    let role = FederationAdmissionRole::Member;
    let local = create_window_doc("local", &window_key);
    let ahead = create_window_doc("federation-peer", &window_key);
    for n in 0..40_u8 {
        insert_edge(&ahead, row, EdgeKind::FacetOf, entity_id(0x70 + n));
    }
    ahead.commit();
    let ahead = ahead.export(ExportMode::all_updates()).unwrap();
    import_from_peer(&vault, &local, &window_key, &ahead, (peer, grant_id), role);
    let birth = create_window_doc("federation-peer", &window_key);
    insert_entity(&birth, row, ENTITY_TYPE_EVENT, b"row");
    birth.commit();
    let birth = birth.export(ExportMode::all_updates()).unwrap();

    import_from_peer(&vault, &local, &window_key, &birth, (peer, grant_id), role);
    let mut released = 0;
    map_for_each_value_bytes(&local.get_map("edges"), |key, _| {
        if key.starts_with(&row.to_hex()) {
            released += 1;
        }
    });
    assert_eq!(
        released,
        crate::federation::facet_read::MAX_HELD_PER_ROW,
        "the row's birth released every stamp its sender sent ahead"
    );
}

/// The window as a reload loads it: its persisted snapshot with its pending
/// updates, or the pending updates on a fresh document.
fn reloaded_window(vault: &Vault, window_key: &WindowKey) -> LoroDoc {
    crate::sync::window::load_window_from_state(vault, "local", window_key).unwrap_or_else(|_| {
        let doc = create_window_doc("local", window_key);
        crate::sync::window::apply_pending_window_updates(vault, &doc, window_key).unwrap();
        doc
    })
}

/// Astra-b F1 on #1432: a peer's stamp counts only once that peer's birth of
/// its row has applied here, never on the row's presence in an update. The
/// peer stamps `row` into `work`, and sends an EVENT at `row` that the write
/// door refuses (it ends before it starts): after the stamp, or with it. The
/// owner then writes `row` in `private` only. A reader narrowed to `work`
/// does not read it, and neither replaying the window nor reloading it
/// writes the stamp.
#[test]
fn a_stamp_whose_row_the_write_door_refused_never_places_a_later_row() {
    for (leg, seed) in [("stamp ahead", 0x30_u8), ("same frame", 0x38_u8)] {
        let window = "2026-05";
        let window_key = WindowKey::new(window);
        let (_dir, vault, _grant_id, mut client) = test_client_with_grant(entity_id(seed), window);
        let [work, private, row] = [1, 2, 3].map(|n| entity_id(seed + n));
        for facet in [work, private] {
            put_row(&vault, facet, ENTITY_TYPE_FACET);
        }
        let role = FederationAdmissionRole::Member;
        let refused = crate::test_util::entity_record(
            ENTITY_TYPE_EVENT,
            TimeRange { start: 2, end: 1 },
            1,
            b"refused",
        );
        let frame = create_window_doc("federation-peer", &window_key);
        insert_edge(&frame, row, EdgeKind::FacetOf, work);
        if leg == "stamp ahead" {
            frame.commit();
            import_federated(&mut client, window, &frame, role);
            let birth = create_window_doc("federation-peer", &window_key);
            insert_blob(&birth, row, &refused);
            birth.commit();
            import_federated(&mut client, window, &birth, role);
        } else {
            insert_blob(&frame, row, &refused);
            frame.commit();
            import_federated(&mut client, window, &frame, role);
        }
        assert!(
            !vault.entity_exists(&row).unwrap(),
            "{leg}: precondition, the write door refused the peer's row"
        );

        put_row(&vault, row, ENTITY_TYPE_EVENT);
        vault
            .put_edge(&row, EdgeKind::FacetOf, &private, 1.0)
            .unwrap();
        let live = client.window(window).expect("window still loaded");
        rematerialize(&vault, &live.doc, &window_key);
        rematerialize(&vault, &reloaded_window(&vault, &window_key), &window_key);

        assert!(
            map_get_bytes(
                &live.doc.get_map("edges"),
                &edge_key(row, EdgeKind::FacetOf, work)
            )
            .is_none(),
            "{leg}: the stamp of a refused row entered the window"
        );
        assert!(!stamp_stored(&vault, row, work), "{leg}");
        assert!(
            !vault.row_in_facets(&row, &facet_set(work)).unwrap(),
            "{leg}: a work reader reads the owner's row"
        );
        assert!(
            vault.row_in_facets(&row, &facet_set(private)).unwrap(),
            "{leg}"
        );
    }
}

/// Sol R10 F2 on #1432: between a peer update's admission and its import,
/// another writer stores the peer's row first, with the very bytes the peer
/// brings (here the owner's other device relays it), and the owner stamps it
/// `private`. The peer's copy is then an idempotent skip, not its birth, so
/// it releases no stamp: not one sent with the row, nor one held from before.
/// A reader narrowed to `work` does not read the row.
#[test]
fn a_peer_copy_of_a_row_another_writer_stored_first_releases_no_stamp() {
    let window_key = WindowKey::new("2026-05");
    for (leg, seed) in [("with the row", 0x60_u8), ("held", 0x68_u8)] {
        let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(seed));
        let [peer, work, private, row] = [1, 2, 3, 4].map(|n| entity_id(seed + n));
        for facet in [work, private] {
            put_row(&vault, facet, ENTITY_TYPE_FACET);
        }
        let live = create_window_doc("local", &window_key);
        let role = FederationAdmissionRole::Member;
        let blob = entity_blob(ENTITY_TYPE_EVENT, b"row");
        let frame = create_window_doc("federation-peer", &window_key);
        insert_edge(&frame, row, EdgeKind::FacetOf, work);
        let birth = if leg == "held" {
            frame.commit();
            let update = frame.export(ExportMode::all_updates()).unwrap();
            import_from_peer(&vault, &live, &window_key, &update, (peer, grant_id), role);
            create_window_doc("federation-peer", &window_key)
        } else {
            frame
        };
        insert_blob(&birth, row, &blob);
        birth.commit();
        let update = birth.export(ExportMode::all_updates()).unwrap();
        let admitted = admit_peer_window_update(&vault, &window_key, &update, role, peer).unwrap();
        admitted
            .hold_from_peer(&vault, &window_key, grant_id)
            .unwrap();

        let relay = create_window_doc("device", &window_key);
        insert_blob(&relay, row, &blob);
        relay.commit();
        rematerialize(&vault, &relay, &window_key);
        vault
            .put_edge(&row, EdgeKind::FacetOf, &private, 1.0)
            .unwrap();
        let born = crate::sync::ingest::watch_births(&vault, admitted.births(), || {
            live.import(admitted.bytes()).unwrap();
            rematerialize(&vault, &live, &window_key);
            Ok::<_, ()>(())
        })
        .unwrap();
        assert!(
            born.is_empty(),
            "{leg}: the peer's copy counted as its birth"
        );
        if let Some(released) = admitted.release(&vault, &window_key, &born).unwrap() {
            if let Some(update) = &released.update {
                live.import(update).unwrap();
                rematerialize(&vault, &live, &window_key);
            }
            released.discard(&vault).unwrap();
        }

        assert!(
            map_get_bytes(
                &live.get_map("edges"),
                &edge_key(row, EdgeKind::FacetOf, work)
            )
            .is_none(),
            "{leg}: the peer's copy of a stored row released its stamp"
        );
        assert!(!stamp_stored(&vault, row, work), "{leg}");
        assert!(
            !vault.row_in_facets(&row, &facet_set(work)).unwrap(),
            "{leg}: a work reader reads the row"
        );
        assert!(
            vault.row_in_facets(&row, &facet_set(private)).unwrap(),
            "{leg}"
        );
    }
}

/// Astra-b F2 on #1432: a peer sends ten times the cap of stamps onto rows it
/// never brings, one stamp per row. Each update is charged for the stamps it
/// holds, so it is deferred, and a deferred update holds nothing. Replayed,
/// they hold exactly the cap, and the rest are refused with a typed reason.
/// Revoking the peer's grant retires every one at the next maintain.
#[test]
fn a_peer_holds_a_charged_capped_number_of_stamps_until_its_grant_goes() {
    let window = "2026-05";
    let window_key = WindowKey::new(window);
    let member = entity_id(0x26);
    let (_dir, vault, grant_id, mut client) = test_client_with_grant(member, window);
    let vault = &*vault;
    let facet = entity_id(0x27);
    put_row(vault, facet, ENTITY_TYPE_FACET);
    let lane = format!("p{}", member.to_hex());
    let held = |vault: &Vault| {
        let txn = vault.store.env.read_txn().unwrap();
        let stored =
            crate::federation::facet_read::held_rows_under(&vault.store, &txn, &lane).unwrap();
        let counted = crate::federation::facet_read::held_by(&vault.store, &txn, &lane).unwrap();
        assert_eq!(
            counted, stored,
            "the lane's usage row counts its rows and their stored bytes"
        );
        stored.0
    };
    let cap = crate::federation::facet_read::MAX_HELD_PER_SENDER;
    for frame in 0..10_u32 {
        let stamps = create_window_doc("federation-peer", &window_key);
        for n in 0..cap as u32 {
            let mut row = [0x5A; 16];
            row[8..12].copy_from_slice(&frame.to_be_bytes());
            row[12..].copy_from_slice(&n.to_be_bytes());
            insert_edge(
                &stamps,
                EntityId::from_bytes(row).unwrap(),
                EdgeKind::FacetOf,
                facet,
            );
        }
        stamps.commit();
        let update = stamps.export(ExportMode::all_updates()).unwrap();
        client
            .import_federated_window_update(window, &update, FederationAdmissionRole::Member)
            .unwrap();
        if frame == 0 {
            assert!(
                !vault.federation_burst_review_bundles().unwrap().is_empty(),
                "an update of held stamps alone is charged for them, so it is deferred"
            );
            assert_eq!(held(vault), 0, "a deferred update holds nothing");
        }
    }
    while client.replay_deferred_federation_update().unwrap() {}

    assert_eq!(held(vault), cap, "a peer holds exactly the cap");
    assert!(
        quarantined_records(vault)
            .unwrap()
            .iter()
            .any(|(_, record)| record.reason_code == "HeldFacetStampsFull"),
        "a stamp past the cap is refused with its typed reason"
    );
    vault
        .delete_entity_with_options(
            &grant_id,
            crate::deletion::DeleteEntityOptions { purge: true },
        )
        .unwrap();
    let report = vault.maintain().run().unwrap();
    assert_eq!(report.held_facet_stamps_retired, cap);
    assert_eq!(held(vault), 0, "a revoked grant's stamps are retired");
}

/// Sol R10 F3 on #1432: maintain scans a held stamp while its grant does not
/// confer, and the grant confers again before the stamp is removed (a pact
/// healed, the peer holding the stamp again). The removal judges the grant
/// again in its own transaction, so the live hold stays.
#[test]
fn a_hold_whose_grant_confers_again_before_its_removal_stays() {
    let window_key = WindowKey::new("2026-05");
    let (_dir, vault, grant_id) = test_vault_with_grant(entity_id(0x50));
    let [peer, facet, row] = [1, 2, 3].map(|n| entity_id(0x50 + n));
    put_row(&vault, facet, ENTITY_TYPE_FACET);
    let live = create_window_doc("local", &window_key);
    let ahead = create_window_doc("federation-peer", &window_key);
    insert_edge(&ahead, row, EdgeKind::FacetOf, facet);
    ahead.commit();
    let update = ahead.export(ExportMode::all_updates()).unwrap();
    let role = FederationAdmissionRole::Member;
    import_from_peer(&vault, &live, &window_key, &update, (peer, grant_id), role);
    let lane = format!("p{}", peer.to_hex());
    let held = || {
        let txn = vault.store.env.read_txn().unwrap();
        crate::federation::facet_read::held_rows_under(&vault.store, &txn, &lane)
            .unwrap()
            .0
    };
    assert_eq!(held(), 1, "precondition: the stamp is held");

    let judged = std::cell::Cell::new(0);
    let now = vault.store.clock.now_recorded_at();
    let retired = crate::federation::facet_read::retire_held_stamps(&vault, now, |_, grants| {
        judged.set(judged.get() + 1);
        Ok(if judged.get() == 1 {
            std::collections::BTreeSet::new()
        } else {
            grants.clone()
        })
    })
    .unwrap();
    assert_eq!(retired, 0, "a hold whose grant confers again was retired");
    assert_eq!(held(), 1);
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
        // — the H2 defer the admission door must honor, now by holding the
        // stamp out of the window until its sender brings the source. The
        // FACET target rides along so the row names a facet this peer will
        // select.
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
            .is_none(),
            "{role:?}: precondition — the unknowable-source stamp is held out \
             of the window until its sender brings the source"
        );

        // Update 2: the same sender brings P typed PERSON. Its held stamp is
        // judged at the release, off-table.
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
        assert!(
            map_get_bytes(
                &live.doc.get_map("edges"),
                &edge_key(person, EdgeKind::FacetOf, facet_selected),
            )
            .is_none()
                && quarantined_records(&vault)
                    .unwrap()
                    .iter()
                    .any(|(_, record)| record.reason_code == "InvalidFacetOfEdge"),
            "{role:?}: the released off-table stamp is dropped with typed evidence"
        );
        // Owner-verified bodies do not endorse the hostile FacetOf residue.
        // Stamp all known fixture records so the negative observes the facet
        // boundary rather than an unrelated absence of record evidence.
        stamp_live_rows(
            &vault,
            &live.doc,
            &[facet_selected, event, person, neighbor],
        );

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![SelectorRange::Semantic, SelectorRange::Core],
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
    // Explicit verified positions for the honest opaque rows (the CLAIM is
    // intrinsic and needs no stamp): the facet and the one-hop neighbor ride
    // replicated bytes, which carry no stamp until verified here.
    stamp_live_rows(&vault, &live.doc, &[facet_selected, neighbor]);
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    seed_doc_stamps(&vault, &doc);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_selected],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
            // Explicit verified positions: the neighbor is honest in both arms
            // (the CLAIM is intrinsic). The named id is verified ONLY when it
            // arrived as a real FACET — a PERSON forgery gets no stamp.
            if target_arrives_as_facet {
                stamp_live_rows(&vault, &live.doc, &[named, neighbor]);
            } else {
                stamp_live_rows(&vault, &live.doc, &[neighbor]);
            }

            let selector = SyncSelector::new(
                grant_id,
                member,
                SyncSelectorWorld::All,
                vec![named],
                vec![SelectorRange::Semantic, SelectorRange::Core],
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

#[test]
fn valid_claim_retype_cannot_erase_stored_event_facet_withhold() {
    let member = entity_id(0x26);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let key = WindowKey::new("2026-12");
    let selected = entity_id(0x7F);
    let unselected = entity_id(0x8F);
    let seed = entity_id(0x9F);
    let conflicted = entity_id(0xAF);
    for (id, kind) in [
        (selected, ENTITY_TYPE_FACET),
        (unselected, ENTITY_TYPE_FACET),
        (conflicted, ENTITY_TYPE_EVENT),
    ] {
        vault
            .put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"row")
            .unwrap();
    }
    let doc = create_window_doc("source", &key);
    insert_entity(&doc, selected, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, unselected, ENTITY_TYPE_FACET, b"facet-b");
    let claim = ClaimBody::new(
        "selector.test",
        ClaimSubject::Entity(selected),
        Value::from("valid claim"),
        0.8,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    let blob = entity_blob(ENTITY_TYPE_CLAIM, &encode_claim_body(&claim).unwrap());
    insert_blob(&doc, seed, &blob);
    insert_blob(&doc, conflicted, &blob);
    insert_edge(&doc, seed, EdgeKind::FacetOf, selected);
    insert_edge(&doc, conflicted, EdgeKind::FacetOf, unselected);
    insert_edge(&doc, seed, EdgeKind::Supports, conflicted);
    doc.commit();
    seed_doc_stamps(&vault, &doc);
    let broad = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let broad_bytes = filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &broad)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    assert!(
        import_ids(&broad_bytes).contains(&conflicted),
        "valid conflicting claim must not be masked by another export gate"
    );
    let limited = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![selected],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let bytes = filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &limited)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&bytes);
    assert!(ids.contains(&seed));
    assert!(!ids.contains(&conflicted));
    assert!(!ids.contains(&unselected));
}

/// A REJECTED RETYPE MUST NOT ERASE A VALID SCOPE — the TARGET-side arm of
/// the one conflict rule (stored truth never loses to a rejected write).
///
/// The target half decides whether a stamp CONTAINS its source, so resolving a
/// conflicted target to `None` makes the row inert and DELETES containment a
/// valid stored FACET had already established — a peer forges one PERSON blob
/// for a facet it does not own and an entity that was withheld from a
/// facet-limited peer starts exporting. (The same erasure has a SOURCE arm; a
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
        // Explicit verified positions for the honest opaque rows (the CLAIM
        // seed is intrinsic). The forged retype below targets facet_t, whose
        // stamp then mismatches the conflicting doc blob — fail-closed — while
        // the EVENT and selected-facet stamps persist across both exports.
        {
            let live = client.window(window).expect("window still loaded");
            stamp_live_rows(&vault, &live.doc, &[facet_t, facet_selected, event]);
        }

        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet_selected],
            vec![SelectorRange::Semantic, SelectorRange::Core],
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
    seed_doc_stamps(&vault, &doc);

    // The peer NAMES the forged id, which is the whole point: being selected
    // is not evidence of being a FACET.
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![person_target, facet_real],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    // H2 doc-only premise preserved: the two TARGETS stay unstamped (no
    // stored rows, types resolve from the document alone). Only the
    // one-hop neighbors are stamped so closure — not missing stamps —
    // decides their verdicts.
    vault
        .batch()
        .put(
            &neighbor_of_facet_claim,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"neighbor-a",
        )
        .put(
            &neighbor_of_person_claim,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"neighbor-b",
        )
        .commit()
        .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_doc_only, person_doc_only],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
    seed_doc_stamps(&vault, &doc);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
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
fn selector_suppresses_tombstoned_live_map_residue() {
    let member = entity_id(0x36);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-06");
    let doc = create_window_doc("source", &window_key);
    let residue = entity_id(0x57);
    let facet_allowed = entity_id(0x58);
    let claim_seed = entity_id(0x59);
    insert_entity(&doc, residue, ENTITY_TYPE_PERSON, b"stale-live-blob");
    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_blob(&doc, claim_seed, &claim_blob(None));
    insert_edge(&doc, claim_seed, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, claim_seed, EdgeKind::Supports, residue);
    insert_tombstone(&doc, residue);
    doc.commit();
    vault
        .batch()
        .put(
            &residue,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"stale-live-blob",
        )
        .put(
            &facet_allowed,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-a",
        )
        .commit()
        .unwrap();

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
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
fn selector_treats_malformed_facet_of_value_as_denied_scope() {
    let member = entity_id(0x37);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let window_key = WindowKey::new("2026-07");
    let doc = create_window_doc("source", &window_key);
    let facet_allowed = entity_id(0xA7);
    let facet_denied = entity_id(0xB7);
    let malformed_claim = entity_id(0x17);
    let authorized_claim = entity_id(0x18);
    let unstamped_claim = entity_id(0x19);

    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_entity(&doc, facet_denied, ENTITY_TYPE_FACET, b"facet-b");
    insert_blob(&doc, malformed_claim, &claim_blob(None));
    insert_malformed_edge(&doc, malformed_claim, EdgeKind::FacetOf, facet_denied);
    insert_edge(&doc, facet_allowed, EdgeKind::Supports, malformed_claim);
    insert_blob(&doc, authorized_claim, &claim_blob(None));
    insert_blob(&doc, unstamped_claim, &claim_blob(None));
    insert_edge(&doc, authorized_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, authorized_claim, EdgeKind::Supports, malformed_claim);
    insert_edge(&doc, authorized_claim, EdgeKind::Supports, unstamped_claim);
    doc.commit();
    seed_doc_stamps(&vault, &doc);

    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);

    assert!(ids.contains(&facet_allowed));
    assert!(ids.contains(&authorized_claim));
    assert!(
        ids.contains(&unstamped_claim),
        "an unstamped claim reachable from the authorized claim must travel"
    );
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
use crate::error::{RegistryError, SyncError};
use crate::federation::{
    FederationDirectionScope, FederationPactScope, ScopeAxis, ScopeId, encode_federation_pact_scope,
};

fn all_direction_scope() -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }
}

fn selector_pact_scope(facets: ScopeAxis<ScopeId>) -> FederationPactScope {
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
/// through the ordinary AUTHORITY_LOG write door.
fn seed_pact_for_grant(vault: &Vault, grant_id: EntityId, status: PactSeedStatus) {
    let owner = SigningKey::from_bytes(&[0x61; 32]);
    let genesis = authority_genesis_entry(0x61);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let peer = SigningKey::from_bytes(&[0x62; 32]);
    let peer_key = AuthorityKey::Ed25519(peer.verifying_key().to_bytes());
    let peer_vault_id = genesis_vault_id(&authority_genesis_entry(0x62)).unwrap();
    let pact_id = [0x63; 32];
    let nonce = [0x64; 16];
    let scope = selector_pact_scope(ScopeAxis::All);
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
        let scope = selector_pact_scope(ScopeAxis::from_iter([entity_id(facet_byte)].map(ScopeId)));
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

/// Review repro (access deletion fences): a FederationGrant whose delete was
/// accepted but not applied keeps its body. It authorizes no selector.
#[test]
fn a_grant_deleted_here_authorizes_no_selector() {
    let member = entity_id(0x35);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("a live grant authorizes");
    vault
        .with_write_txn(|txn| vault.fence_unapplied_delete_in_txn(txn, &grant_id, &[1; 25]))
        .unwrap();
    assert!(vault.get_raw(&grant_id).unwrap().is_some());
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect_err("a grant deleted here authorizes nothing");
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
                Error::Sync(SyncError::SyncProtocolError {
                    context: SyncProtocolValidation::Selector {
                        reason: SelectorError::GrantInactive
                    }
                })
            ),
            "{name}: wrong denial: {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Pact scope ceiling (ONE-1591)
// ---------------------------------------------------------------------------

/// Seeds one Active fold-derived pact per entry in `scopes`, every one bound to
/// `grant_id`, through the ordinary AUTHORITY_LOG write door.
///
/// Each Connect parents the genesis entry directly, so more than one entry
/// models the divergent-branch concurrent-Connect case: the fold merges sibling
/// branches into several live pact states naming a single grant. Both halves of
/// every pact scope carry the same direction scope, so the fold's lo/hi
/// outbound selection is irrelevant and each `effective_scope` is exactly its
/// entry.
fn seed_scoped_pacts_for_grant(
    vault: &Vault,
    grant_id: EntityId,
    scopes: &[FederationDirectionScope],
) {
    let owner = SigningKey::from_bytes(&[0x61; 32]);
    let genesis = authority_genesis_entry(0x61);
    let vault_id = genesis_vault_id(&genesis).unwrap();
    let genesis_hash = authority_entry_hash(&genesis).unwrap();
    vault
        .put_authority_log_entry(&genesis, TimeRange { start: 1, end: 1 }, 1)
        .unwrap();

    for (index, scope) in scopes.iter().enumerate() {
        let offset = u8::try_from(index).unwrap();
        let peer_seed = 0x71 + offset;
        let peer = SigningKey::from_bytes(&[peer_seed; 32]);
        let peer_key = AuthorityKey::Ed25519(peer.verifying_key().to_bytes());
        let peer_vault_id = genesis_vault_id(&authority_genesis_entry(peer_seed)).unwrap();
        let pact_id = [0x81 + offset; 32];
        let nonce = [0x91 + offset; 16];
        let pact_scope = FederationPactScope {
            lo_to_hi: scope.clone(),
            hi_to_lo: scope.clone(),
        };
        let digest =
            federation_scope_digest(&nonce, &encode_federation_pact_scope(&pact_scope).unwrap());
        let gesture = sign_federation_pact_gesture(
            FederationLifecycleKind::Connect,
            &pact_id,
            &vault_id,
            &peer_vault_id,
            1,
            &digest,
            None,
            &nonce,
            peer_key,
            |transcript| Ok(peer.sign(transcript).to_bytes().to_vec()),
        )
        .unwrap();
        let connect = signed_lifecycle_entry(
            &owner,
            vault_id,
            1 + u64::from(offset),
            genesis_hash,
            FederationLifecycleAction {
                kind: FederationLifecycleKind::Connect,
                pact_id,
                grant_ref: grant_id,
                peer_vault_id,
                pact_epoch: 1,
                pact_scope: Some(pact_scope),
                effective_scope: None,
                scope_digest: Some(digest),
                gesture: Some(gesture),
                successor_vault_id: None,
                pact_nonce: nonce,
            },
        );
        vault
            .put_authority_log_entry(&connect, TimeRange { start: 2, end: 2 }, 2)
            .unwrap();
    }
}

fn assert_grant_scope_mismatch(err: &Error, label: &str) {
    assert!(
        matches!(
            err,
            Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::Selector {
                    reason: SelectorError::GrantScopeMismatch
                }
            })
        ),
        "{label}: expected a ceiling refusal, got {err:?}"
    );
}

/// Empty wire axes request no narrowing, and a ⊥ ceiling axis still exports
/// nothing to them; named worlds retain their export boundary, and wire round
/// trips preserve independently expected sets.
#[test]
fn selector_request_decodes_wire_semantics() {
    let member = entity_id(0x34);
    let grant = entity_id(0x35);
    let world = local_world_id(0x51);
    let (_dir, vault, _) = test_vault_with_grant(member);
    put_selector_test_federation_grant(
        &vault,
        &grant,
        &FederationGrant::new(
            test_selector_scope(),
            member,
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        ),
        1,
    )
    .unwrap();

    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);
    let base_claim = entity_id(0x71);
    let named_claim = entity_id(0x72);
    let other_claim = entity_id(0x73);
    let facet_allowed = entity_id(0x54);
    insert_blob(&doc, base_claim, &claim_blob(None));
    insert_blob(&doc, named_claim, &claim_blob(Some(world.entity_id())));
    insert_blob(
        &doc,
        other_claim,
        &claim_blob(Some(local_world_id(0x52).entity_id())),
    );
    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    insert_edge(&doc, base_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, named_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, other_claim, EdgeKind::FacetOf, facet_allowed);
    doc.commit();
    vault
        .batch()
        .put(
            &facet_allowed,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-a",
        )
        .commit()
        .unwrap();

    let silent = SyncSelector::new(grant, member, SyncSelectorWorld::All, vec![], vec![]);
    for (world_axis, include_named, include_other) in [
        (SyncSelectorWorld::All, true, true),
        (SyncSelectorWorld::Base, false, false),
        (SyncSelectorWorld::World(world), true, false),
    ] {
        let selector = SyncSelector::new(
            grant,
            member,
            world_axis,
            vec![facet_allowed],
            vec![SelectorRange::Semantic, SelectorRange::Core],
        );
        let selector = decode_sync_selector(&encode_sync_selector(&selector).unwrap()).unwrap();
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap()
                .export(ExportMode::all_updates())
                .unwrap();
        let ids = import_ids(&update);
        assert!(ids.contains(&base_claim));
        assert_eq!(ids.contains(&named_claim), include_named);
        assert_eq!(ids.contains(&other_claim), include_other);
    }

    // Independently pin the normalized wire sets, not a private lattice value.
    let filtered = SyncSelector::new(
        grant,
        member,
        SyncSelectorWorld::All,
        vec![entity_id(0x62), entity_id(0x61), entity_id(0x62)],
        vec![SelectorRange::Core, SelectorRange::Semantic],
    );
    let decoded = decode_sync_selector(&encode_sync_selector(&filtered).unwrap()).unwrap();
    assert_eq!(
        decoded.facets,
        RequestedAxis::Named(vec![entity_id(0x61), entity_id(0x62)])
    );
    assert_eq!(
        decoded.bands,
        RequestedAxis::Named(vec![SelectorRange::Semantic, SelectorRange::Core]),
    );

    // Test each empty axis independently: the other axis remains populated.
    for scope in [
        FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::Bottom,
            bands: ScopeAxis::All,
        },
        FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::All,
            bands: ScopeAxis::Bottom,
        },
    ] {
        let (_scope_dir, scope_vault, _) = test_vault_with_grant(member);
        put_selector_test_federation_grant(
            &scope_vault,
            &grant,
            &FederationGrant::new(
                test_selector_scope(),
                member,
                FederationGrantRole::Viewer,
                FederationGrantPreset::ReadOnly,
            ),
            1,
        )
        .unwrap();
        let empty_facets = matches!(&scope.facets, ScopeAxis::Bottom);
        seed_scoped_pacts_for_grant(&scope_vault, grant, &[scope]);
        authorize_sync_selector(&scope_vault, test_selector_scope(), &silent).unwrap();
        let selector = SyncSelector::new(
            grant,
            member,
            SyncSelectorWorld::All,
            if empty_facets {
                vec![]
            } else {
                vec![entity_id(0x61)]
            },
            if empty_facets {
                vec![SelectorRange::Semantic, SelectorRange::Core]
            } else {
                vec![]
            },
        );
        let scoped_doc = create_window_doc("scope-source", &window_key);
        insert_entity(&scoped_doc, entity_id(0x61), ENTITY_TYPE_FACET, b"facet");
        insert_blob(&scoped_doc, base_claim, &claim_blob(None));
        insert_edge(&scoped_doc, base_claim, EdgeKind::FacetOf, entity_id(0x61));
        scoped_doc.commit();
        for request in [&silent, &selector] {
            authorize_sync_selector(&scope_vault, test_selector_scope(), request).unwrap();
            let update = filtered_window_doc(
                &scope_vault,
                &scoped_doc,
                &window_key,
                test_selector_scope(),
                request,
            )
            .unwrap()
            .export(ExportMode::all_updates())
            .unwrap();
            assert!(import_ids(&update).is_empty());
        }
        let err =
            authorize_sync_selector(&scope_vault, test_selector_scope(), &filtered).unwrap_err();
        assert_grant_scope_mismatch(&err, "non-empty request exceeds the bottom axis");
    }
}

/// Done-means 1 and 2: a selector equal to the effective scope authorizes, and
/// so does one narrower on any axis.
#[test]
fn selector_within_pact_ceiling_authorizes() {
    let member = entity_id(0x34);
    let world_a = local_world_id(0x51);
    let world_b = local_world_id(0x52);
    let facet_a = entity_id(0x61);
    let facet_b = entity_id(0x62);

    // Equal on every axis.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[FederationDirectionScope {
            worlds: ScopeAxis::from_iter([world_a.entity_id()].map(ScopeId)),
            facets: ScopeAxis::from_iter([facet_a, facet_b].map(ScopeId)),
            bands: ScopeAxis::from_iter([SelectorRange::Semantic, SelectorRange::Core]),
        }],
    );
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(world_a),
        vec![facet_a, facet_b],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("a selector equal to the effective scope authorizes");

    // Narrower on the facet, band, and world axes under an All-worlds ceiling.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::from_iter([facet_a, facet_b].map(ScopeId)),
            bands: ScopeAxis::from_iter([SelectorRange::Semantic, SelectorRange::Core]),
        }],
    );
    for (name, world, facets, bands) in [
        (
            "base under all worlds",
            SyncSelectorWorld::Base,
            vec![facet_a, facet_b],
            vec![SelectorRange::Semantic, SelectorRange::Core],
        ),
        (
            "named world under all worlds",
            SyncSelectorWorld::World(world_a),
            vec![facet_a, facet_b],
            vec![SelectorRange::Semantic, SelectorRange::Core],
        ),
        (
            "facet subset",
            SyncSelectorWorld::All,
            vec![facet_b],
            vec![SelectorRange::Semantic, SelectorRange::Core],
        ),
        (
            "band subset",
            SyncSelectorWorld::All,
            vec![facet_a, facet_b],
            vec![SelectorRange::Core],
        ),
    ] {
        let selector = SyncSelector::new(grant_id, member, world, facets, bands);
        authorize_sync_selector(&vault, test_selector_scope(), &selector)
            .unwrap_or_else(|err| panic!("{name}: a narrower selector must authorize: {err:?}"));
    }

    // A subset of a NAMED worlds set, which the All-worlds ceiling cannot show.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[FederationDirectionScope {
            worlds: ScopeAxis::from_iter([world_a.entity_id(), world_b.entity_id()].map(ScopeId)),
            facets: ScopeAxis::All,
            bands: ScopeAxis::All,
        }],
    );
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(world_b),
        vec![facet_a],
        vec![SelectorRange::Semantic],
    );
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("one of the ceiling's named worlds is a narrowing");
}

/// Done-means 3: a widen on any single axis is refused even when the other two
/// axes are strictly narrower.
#[test]
fn selector_wider_than_pact_ceiling_on_any_axis_denies() {
    let member = entity_id(0x34);
    let world_a = local_world_id(0x51);
    let world_b = local_world_id(0x52);
    let facet_a = entity_id(0x61);
    let facet_b = entity_id(0x62);
    let unnamed_facet = entity_id(0x63);

    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[FederationDirectionScope {
            worlds: ScopeAxis::from_iter([world_a.entity_id(), world_b.entity_id()].map(ScopeId)),
            facets: ScopeAxis::from_iter([facet_a, facet_b].map(ScopeId)),
            bands: ScopeAxis::from_iter([SelectorRange::Semantic, SelectorRange::Core]),
        }],
    );
    for (name, world, facets, bands) in [
        (
            "worlds widen",
            SyncSelectorWorld::All,
            vec![facet_a],
            vec![SelectorRange::Semantic],
        ),
        (
            "facet widen",
            SyncSelectorWorld::World(world_a),
            vec![unnamed_facet],
            vec![SelectorRange::Semantic],
        ),
        (
            "band widen",
            SyncSelectorWorld::World(world_a),
            vec![facet_a],
            vec![SelectorRange::Family(
                crate::registry::TypeByteFamily::Companion,
            )],
        ),
    ] {
        let selector = SyncSelector::new(grant_id, member, world, facets, bands);
        let err = authorize_sync_selector(&vault, test_selector_scope(), &selector)
            .expect_err("a selector exceeding the pact ceiling must be refused");
        assert_grant_scope_mismatch(&err, name);
    }
}

/// Done-means 4: the masking regression. Concurrent disjoint facet narrows and
/// concurrent disjoint band narrows meet at ⊥, and ⊥ denies every
/// content-carrying selector — a disjoint meet must never decode as an
/// accidental widen. The unnarrowed selector's pass, which resolves to that
/// ⊥, is asserted alongside it.
#[test]
fn disjoint_concurrent_narrows_meet_at_bottom_and_deny_content() {
    let member = entity_id(0x34);
    let facet_a = entity_id(0x61);
    let facet_b = entity_id(0x62);

    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[
            FederationDirectionScope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::from_iter([facet_a].map(ScopeId)),
                bands: ScopeAxis::from_iter([SelectorRange::Semantic]),
            },
            FederationDirectionScope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::from_iter([facet_b].map(ScopeId)),
                bands: ScopeAxis::from_iter([SelectorRange::Core]),
            },
        ],
    );

    let fold = vault.authority_fold().unwrap();
    let ceiling =
        effective_scope_for_grant(&fold, &grant_id).expect("a pact-bound grant has a ceiling");
    assert_eq!(
        ceiling.as_scope().facets,
        ScopeAxis::Bottom,
        "disjoint facet narrows must meet at ⊥, not widen"
    );
    assert_eq!(
        ceiling.as_scope().bands,
        ScopeAxis::Bottom,
        "disjoint band narrows must meet at ⊥, not widen"
    );

    for (name, facets, bands) in [
        ("both axes", vec![facet_a], vec![SelectorRange::Semantic]),
        ("facet only", vec![facet_a], Vec::new()),
        ("band only", Vec::new(), vec![SelectorRange::Core]),
    ] {
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, facets, bands);
        let err = authorize_sync_selector(&vault, test_selector_scope(), &selector)
            .expect_err("a ⊥ ceiling denies every content-carrying selector");
        assert_grant_scope_mismatch(&err, name);
    }

    // The empty-vector selector requests no narrowing, so it sits within even a
    // ⊥ ceiling and resolves to that ⊥.
    let silent = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    assert_eq!(
        resolve_selector_position(&silent, &ceiling)
            .unwrap()
            .as_scope()
            .facets,
        ScopeAxis::Bottom
    );
    authorize_sync_selector(&vault, test_selector_scope(), &silent)
        .expect("an unnarrowed request sits within every ceiling");
}

/// The source window the pact-ceiling export tests share. CLAIM is band
/// Semantic, PERSON and FACET are band Core, and only `facet_named` (0x64) is
/// inside the ceiling — so every leak is content the ceiling names as out of
/// scope, not merely extra rows. The non-CLAIM rows are stamped so filtering,
/// not a missing stamp, decides every verdict.
fn pact_ceiling_source_doc(vault: &Vault, window_key: &WindowKey) -> LoroDoc {
    let facet_named = entity_id(0x64);
    let facet_unnamed = entity_id(0x65);
    let claim_named = entity_id(0x66);
    let claim_unnamed = entity_id(0x67);
    let doc = create_window_doc("source", window_key);
    insert_entity(&doc, facet_named, ENTITY_TYPE_FACET, b"facet-in");
    insert_entity(&doc, facet_unnamed, ENTITY_TYPE_FACET, b"facet-out");
    insert_blob(&doc, claim_named, &claim_blob(None));
    insert_blob(&doc, claim_unnamed, &claim_blob(None));
    insert_entity(&doc, entity_id(0x68), ENTITY_TYPE_PERSON, b"person");
    insert_edge(&doc, claim_named, EdgeKind::FacetOf, facet_named);
    insert_edge(&doc, claim_unnamed, EdgeKind::FacetOf, facet_unnamed);
    insert_tombstone(&doc, entity_id(0x69));
    doc.commit();
    seed_doc_stamps(vault, &doc);
    doc
}

/// Done-means 4, export half (OF-453 L3): the ceiling binds the export, not
/// only the door. A request that leaves an axis unnarrowed resolves to the
/// ceiling's axis, so it exports what the ceiling allows and none of the
/// Core-band or unnamed-facet content the ceiling exists to withhold.
#[test]
fn pact_ceiling_binds_the_export_not_only_the_door() {
    let member = entity_id(0x3D);
    let facet_named = entity_id(0x64);
    let claim_named = entity_id(0x66);
    let window_key = WindowKey::new("2026-12");
    let ceiling = FederationDirectionScope {
        worlds: ScopeAxis::All,
        facets: ScopeAxis::from_iter([facet_named].map(ScopeId)),
        bands: ScopeAxis::from_iter([SelectorRange::Semantic]),
    };
    for (name, facets, bands) in [
        ("both axes unnarrowed", Vec::new(), Vec::new()),
        ("band axis unnarrowed", vec![facet_named], Vec::new()),
        (
            "facet axis unnarrowed",
            Vec::new(),
            vec![SelectorRange::Semantic],
        ),
    ] {
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        seed_scoped_pacts_for_grant(&vault, grant_id, std::slice::from_ref(&ceiling));
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, facets, bands);
        let doc = pact_ceiling_source_doc(&vault, &window_key);
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap_or_else(|err| panic!("{name}: the request authorizes: {err:?}"))
                .export(ExportMode::all_updates())
                .unwrap();

        assert_eq!(import_ids(&update), vec![claim_named], "{name}");
    }
}

/// Done-means 5: several Active pacts on one grant intersect into a single
/// ceiling; a selector permitted by only one of them is denied.
#[test]
fn multiple_active_pacts_intersect_into_one_ceiling() {
    let member = entity_id(0x34);
    let facet_a = entity_id(0x61);
    let facet_b = entity_id(0x62);
    let facet_c = entity_id(0x63);

    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[
            FederationDirectionScope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::from_iter([facet_a, facet_b].map(ScopeId)),
                bands: ScopeAxis::All,
            },
            FederationDirectionScope {
                worlds: ScopeAxis::All,
                facets: ScopeAxis::from_iter([facet_b, facet_c].map(ScopeId)),
                bands: ScopeAxis::All,
            },
        ],
    );

    let fold = vault.authority_fold().unwrap();
    let ceiling =
        effective_scope_for_grant(&fold, &grant_id).expect("a pact-bound grant has a ceiling");
    assert_eq!(
        ceiling.as_scope().facets,
        ScopeAxis::from_iter([facet_b].map(ScopeId)),
        "the ceiling is the meet of every bound pact, not one arbitrary pact"
    );

    let shared = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_b],
        vec![SelectorRange::Semantic],
    );
    authorize_sync_selector(&vault, test_selector_scope(), &shared)
        .expect("the facet both pacts name authorizes");

    let one_pact_only = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet_a],
        vec![SelectorRange::Semantic],
    );
    let err = authorize_sync_selector(&vault, test_selector_scope(), &one_pact_only)
        .expect_err("a facet only one pact names exceeds the intersected ceiling");
    assert_grant_scope_mismatch(&err, "single-pact facet");
}

/// Done-means 6: no re-federation widening. `SyncSelectorWorld::World` can only
/// be built from a [`LocalWorldId`], which refuses the received-foreign range,
/// and exporting a local world includes base claims but no other world.
#[test]
fn foreign_world_ids_cannot_enter_a_selector_scope() {
    // Constructed directly rather than through `entity_id`: this fixture needs
    // an id INSIDE the pinned foreign-world range, which is the one property
    // the generic seed helper cannot express.
    let foreign = EntityId::from_bytes([0xF1; 16]).unwrap();
    assert!(
        LocalWorldId::from_entity_id(foreign).is_err(),
        "a foreign-range world id must never reach a selector world axis"
    );

    let local = local_world_id(0x51);
    let facet_allowed = entity_id(0x53);
    let selector = SyncSelector::new(
        entity_id(0x35),
        entity_id(0x34),
        SyncSelectorWorld::World(local),
        vec![facet_allowed],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x34));
    put_selector_test_federation_grant(
        &vault,
        &selector.grant_id,
        &FederationGrant::new(
            test_selector_scope(),
            entity_id(0x34),
            FederationGrantRole::Viewer,
            FederationGrantPreset::ReadOnly,
        ),
        1,
    )
    .unwrap();
    let window_key = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window_key);
    let base_claim = entity_id(0x71);
    let local_claim = entity_id(0x72);
    let other_claim = entity_id(0x73);
    let foreign_claim = entity_id(0x74);
    insert_blob(&doc, base_claim, &claim_blob(None));
    insert_blob(&doc, local_claim, &claim_blob(Some(local.entity_id())));
    insert_blob(
        &doc,
        other_claim,
        &claim_blob(Some(local_world_id(0x52).entity_id())),
    );
    insert_blob(&doc, foreign_claim, &claim_blob(Some(foreign)));
    insert_entity(&doc, facet_allowed, ENTITY_TYPE_FACET, b"facet-a");
    // All four seed the selected facet so the world axis (not facet
    // withholding) decides each verdict.
    insert_edge(&doc, base_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, local_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, other_claim, EdgeKind::FacetOf, facet_allowed);
    insert_edge(&doc, foreign_claim, EdgeKind::FacetOf, facet_allowed);
    doc.commit();
    vault
        .batch()
        .put(
            &facet_allowed,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet-a",
        )
        .commit()
        .unwrap();

    let update = filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);
    assert!(ids.contains(&base_claim));
    assert!(ids.contains(&local_claim));
    assert!(!ids.contains(&other_claim));
    assert!(!ids.contains(&foreign_claim));
}

/// Done-means 8: the flat `grant.scope == grant_scope` check is untouched and
/// is not satisfied by a selector that merely fits under the pact ceiling.
#[test]
fn flat_grant_scope_check_survives_the_ceiling() {
    let member = entity_id(0x34);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    seed_scoped_pacts_for_grant(&vault, grant_id, &[all_direction_scope()]);
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![entity_id(0x61)],
        vec![SelectorRange::Semantic],
    );

    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("precondition: the selector fits under an All ceiling");

    let err = authorize_sync_selector(&vault, FederationGrantScope::vault(9), &selector)
        .expect_err("a mismatched flat grant scope still denies");
    assert_grant_scope_mismatch(&err, "flat grant scope");
}

// ---------------------------------------------------------------------------
// Delegate expiry gate (ONE-1409)
// ---------------------------------------------------------------------------

/// Fixed mint clock for delegate fixtures — the `_at` seam exists so nothing
/// here has to race the real clock to the expiry second.
const DELEGATE_NOW: u64 = 1_700_000_000;
const DELEGATE_EXPIRES_AT: u64 = DELEGATE_NOW + 3_600;

/// Stores an attenuated delegate grant minted from an admin parent.
fn put_delegate_grant(
    vault: &Vault,
    member_ref: EntityId,
    now_secs: u64,
    expires_at_secs: u64,
) -> EntityId {
    let parent = FederationGrant::new(
        test_selector_scope(),
        entity_id(0x37),
        FederationGrantRole::Admin,
        FederationGrantPreset::Admin,
    );
    let mut delegate =
        FederationGrant::attenuated_delegate(&parent, member_ref, now_secs, expires_at_secs)
            .expect("an admin parent mints a delegate");
    // Clock/selector fixture: select an explicit read capability. The bare
    // constructor is inert; production mints from vault-resident policy.
    delegate.authority_scope = parent
        .authority_scope
        .meet(&crate::federation::scope_codec::read_preset());
    let grant_id = EntityId::now();
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&delegate).unwrap(),
        )
        .commit()
        .unwrap();
    grant_id
}

fn test_vault_with_delegate(
    member_ref: EntityId,
    now_secs: u64,
    expires_at_secs: u64,
) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let grant_id = put_delegate_grant(&vault, member_ref, now_secs, expires_at_secs);
    (dir, vault, grant_id)
}

fn assert_grant_expired(err: &Error, label: &str) {
    assert!(
        matches!(
            err,
            Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::Selector {
                    reason: SelectorError::GrantExpired
                }
            })
        ),
        "{label}: expected an expiry refusal, got {err:?}"
    );
}

/// Done-means 2: a delegate authorizes strictly before its expiry and denies
/// from the expiry second onward; a non-delegate grant authorizes at any age.
#[test]
fn delegate_selector_denies_from_the_expiry_second() {
    let member = entity_id(0x36);
    let (_dir, vault, grant_id) =
        test_vault_with_delegate(member, DELEGATE_NOW, DELEGATE_EXPIRES_AT);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);

    for now in [0, DELEGATE_NOW, DELEGATE_EXPIRES_AT - 1] {
        authorize_sync_selector_at(&vault, test_selector_scope(), &selector, now)
            .unwrap_or_else(|e| panic!("a live delegate must authorize at {now}: {e:?}"));
    }
    for now in [DELEGATE_EXPIRES_AT, DELEGATE_EXPIRES_AT + 1, u64::MAX] {
        let err =
            authorize_sync_selector_at(&vault, test_selector_scope(), &selector, now).unwrap_err();
        assert_grant_expired(&err, &format!("delegate at {now}"));
    }

    // A non-delegate grant carries no expiry and is untouched by the new arm.
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    for now in [0, DELEGATE_EXPIRES_AT, u64::MAX] {
        authorize_sync_selector_at(&vault, test_selector_scope(), &selector, now)
            .unwrap_or_else(|e| panic!("a non-delegate grant must authorize at {now}: {e:?}"));
    }
}

/// The public wrapper reads the WALL CLOCK, not a caller-chosen instant: the
/// `_at` seam is a test affordance, never a way to pick a favourable now.
#[test]
fn public_authorize_reads_the_wall_clock() {
    let member = entity_id(0x36);
    let now = crate::unix_seconds_now();

    let (_dir, vault, grant_id) = test_vault_with_delegate(member, now - 7_200, now - 3_600);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let err = authorize_sync_selector(&vault, test_selector_scope(), &selector).unwrap_err();
    assert_grant_expired(&err, "delegate that lapsed an hour ago");

    let (_dir, vault, grant_id) =
        test_vault_with_delegate(member, now, now + crate::federation::MAX_DELEGATE_TTL_SECS);
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    authorize_sync_selector(&vault, test_selector_scope(), &selector)
        .expect("a delegate with 90 days left authorizes");
}

// ---------------------------------------------------------------------------
// Cross-vault coreference export filter (FED-07, ONE-1414)
// ---------------------------------------------------------------------------

/// The pact `seed_pact_for_grant` binds. `COREFERENCE_PACT_Q` is any OTHER
/// pact — the peer on the far side of P is not party to it.
const COREFERENCE_PACT_P: [u8; 32] = [0x63; 32];
const COREFERENCE_PACT_Q: [u8; 32] = [0x64; 32];

const COREFERENCE_MEMBER_SEED: u8 = 0x6E;
const COREFERENCE_FACET_SEED: u8 = 0x6A;
const COREFERENCE_PERSON_A_SEED: u8 = 0x6B;
const COREFERENCE_PERSON_B_SEED: u8 = 0x6C;
const COREFERENCE_CONTROL_CLAIM_SEED: u8 = 0x6F;

struct CoreferenceExport {
    _dir: tempfile::TempDir,
    vault: Vault,
    grant_id: EntityId,
    member: EntityId,
    facet: EntityId,
    person_a: EntityId,
    person_b: EntityId,
    /// Ordinary non-coreference claim: the CONTROL. Without it an empty export
    /// would "pass" every withholding assertion for the wrong reason.
    control_claim: EntityId,
    status_claim: EntityId,
}

/// A vault holding a viewer grant (optionally pact-bound and Active), the two
/// people, and a Confirmed `same_as` link between them.
fn coreference_export(pacted: bool) -> CoreferenceExport {
    let (dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let member = entity_id(COREFERENCE_MEMBER_SEED);
    let grant_id = put_test_grant(&vault, member, test_selector_scope());
    if pacted {
        seed_pact_for_grant(&vault, grant_id, PactSeedStatus::Active);
    }

    let person_a = entity_id(COREFERENCE_PERSON_A_SEED);
    let person_b = entity_id(COREFERENCE_PERSON_B_SEED);
    for id in [person_a, person_b] {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
    }

    let control_claim = entity_id(COREFERENCE_CONTROL_CLAIM_SEED);
    vault
        .put_claim(
            &control_claim,
            &ClaimBody::new(
                "selector.test",
                ClaimSubject::Entity(person_a),
                Value::from("control"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .unwrap(),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();

    let status_claim = crate::federation::put_coreference_link(
        &vault,
        &crate::write_envelope::WriteActor::new(person_a, EdgeActorClass::Human),
        person_a,
        person_b,
        crate::federation::CoreferenceStatus::Confirmed,
        TimeRange { start: 1, end: 1 },
        1,
    )
    .unwrap();

    CoreferenceExport {
        _dir: dir,
        vault,
        grant_id,
        member,
        facet: entity_id(COREFERENCE_FACET_SEED),
        person_a,
        person_b,
        control_claim,
        status_claim,
    }
}

impl CoreferenceExport {
    fn consent(&self, pact_id: &[u8; 32]) -> EntityId {
        crate::federation::coreference_share_consent(
            &self.vault,
            &crate::write_envelope::WriteActor::new(self.person_a, EdgeActorClass::Human),
            self.person_a,
            self.person_b,
            pact_id,
            TimeRange { start: 2, end: 2 },
            2,
        )
        .expect("write share consent")
    }

    /// The window as the peer would see it: both people, the link, the
    /// control claim, and every claim in `claims` — each facet-stamped so the
    /// pact-bound ⊥ facet reading (ONE-1591) does not withhold everything for
    /// an unrelated reason.
    fn window(&self, claims: &[EntityId]) -> LoroDoc {
        let doc = create_window_doc("source", &WindowKey::new("2026-03"));
        insert_entity(&doc, self.facet, ENTITY_TYPE_FACET, b"facet");
        // Bodies match the vault rows (`b"person"`) so the mandatory record
        // stamps (same digest) let the coreference door — not missing stamps
        // — decide. The facet has no vault row yet; it is seeded below.
        insert_entity(&doc, self.person_a, ENTITY_TYPE_PERSON, b"person");
        insert_entity(&doc, self.person_b, ENTITY_TYPE_PERSON, b"person");
        for claim in std::iter::once(&self.control_claim).chain(claims) {
            let raw = self.vault.get_raw(claim).unwrap().expect("stored claim");
            insert_blob(&doc, *claim, &raw);
            insert_edge(&doc, *claim, EdgeKind::FacetOf, self.facet);
            insert_structural_edge(&doc, *claim, EdgeKind::ClaimOf, self.person_a, 1.0);
        }
        // Both people reach `kept` through ORDINARY material (the control
        // claim's own edges), never through the link. Otherwise "the link did
        // not cross" would be ambiguous between the coreference rule and an
        // endpoint that was never exportable in the first place.
        insert_edge(&doc, self.control_claim, EdgeKind::Mentions, self.person_b);
        insert_structural_edge(&doc, self.person_a, EdgeKind::SameAs, self.person_b, 0.0);
        doc.commit();
        // Seed the selected facet's stamp (same bytes); persons and claims
        // already match vault rows (CLAIMs are intrinsic).
        self.vault
            .batch()
            .put(
                &self.facet,
                ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                b"facet",
            )
            .commit()
            .unwrap();
        doc
    }

    fn filtered(&self, claims: &[EntityId]) -> (Vec<EntityId>, bool) {
        self.filtered_doc(&self.window(claims))
    }

    fn filtered_doc(&self, doc: &LoroDoc) -> (Vec<EntityId>, bool) {
        let window_key = WindowKey::new("2026-03");
        let selector = SyncSelector::new(
            self.grant_id,
            self.member,
            SyncSelectorWorld::All,
            vec![self.facet],
            vec![SelectorRange::Semantic, SelectorRange::Core],
        );
        let filtered = filtered_window_doc(
            &self.vault,
            doc,
            &window_key,
            test_selector_scope(),
            &selector,
        )
        .expect("filter the window");
        let update = filtered.export(ExportMode::all_updates()).unwrap();
        let receiver = create_window_doc("receiver", &window_key);
        receiver.import(&update).unwrap();
        let mut linked = false;
        map_for_each_value_bytes(&receiver.get_map("edges"), |key, value| {
            if value.is_some() && matches!(parse_edge_key(key), Some((_, EdgeKind::SameAs, _))) {
                linked = true;
            }
        });
        (import_ids(&update), linked)
    }
}

fn insert_structural_edge(
    doc: &LoroDoc,
    src: EntityId,
    kind: EdgeKind,
    tgt: EntityId,
    weight: f32,
) {
    let value = encode_edge_value_for_crdt(kind, weight, 1, None, None).unwrap();
    map_insert_bytes(&doc.get_map("edges"), &edge_key(src, kind, tgt), &value).unwrap();
}

/// ONE-1414 done-means 3 (default half) — coreference is LOCAL BY DEFAULT.
///
/// An Active pact-bound grant exports no `same_as` edge and no
/// `core.coreference.*` claim until the owner consents. The control claim
/// crossing in the same export is what makes the absence meaningful.
#[test]
fn pact_bound_export_withholds_coreference_material_by_default() {
    let fixture = coreference_export(true);
    let (ids, linked) = fixture.filtered(&[fixture.status_claim]);

    assert!(
        ids.contains(&fixture.control_claim),
        "the control claim must cross, else this proves nothing"
    );
    assert!(ids.contains(&fixture.person_a));
    assert!(!linked, "an unconsented same_as link leaked");
    assert!(
        !ids.contains(&fixture.status_claim),
        "an unconsented coreference status claim leaked"
    );
}

/// ONE-1414 done-means 3 (consented half) — after Approved consent for pact P,
/// the SAME export carries the link, its status, and P's own consent claim,
/// while a consent claim naming pact Q stays home.
#[test]
fn approved_consent_exports_the_link_its_status_and_only_that_pacts_consent() {
    let fixture = coreference_export(true);
    let consent_p = fixture.consent(&COREFERENCE_PACT_P);
    let consent_q = fixture.consent(&COREFERENCE_PACT_Q);

    let (ids, linked) = fixture.filtered(&[fixture.status_claim, consent_p, consent_q]);

    assert!(linked, "the consented same_as link must cross");
    assert!(ids.contains(&fixture.status_claim));
    assert!(ids.contains(&consent_p));
    assert!(ids.contains(&fixture.person_a));
    assert!(ids.contains(&fixture.person_b));
    assert!(
        !ids.contains(&consent_q),
        "another pact's consent claim leaked under this pact"
    );
}

/// ONE-1414 done-means 3 (cross half) — consent for one pact exports NOTHING
/// under another. The link is consented into Q only, and the export runs under
/// P, so the link, its status, and Q's consent claim are all withheld.
#[test]
fn consent_for_another_pact_exports_nothing_under_this_one() {
    let fixture = coreference_export(true);
    let consent_q = fixture.consent(&COREFERENCE_PACT_Q);

    let (ids, linked) = fixture.filtered(&[fixture.status_claim, consent_q]);

    assert!(ids.contains(&fixture.control_claim));
    assert!(!linked, "a link consented only into another pact leaked");
    assert!(!ids.contains(&fixture.status_claim));
    assert!(!ids.contains(&consent_q));
}

/// ONE-1414 done-means 4 — an UNPACTED grant exports no coreference material
/// even when a consent-shaped claim exists.
///
/// With no pact there is nothing a consent claim could name, so a
/// consent-shaped row is not consent to anything. Unpacted grants keep their
/// legacy-allow reading everywhere else in this filter; coreference is the
/// exception because its whole disclosure rule is per-pact.
#[test]
fn unpacted_grant_exports_no_coreference_material() {
    let fixture = coreference_export(false);
    let consent_p = fixture.consent(&COREFERENCE_PACT_P);

    let (ids, linked) = fixture.filtered(&[fixture.status_claim, consent_p]);

    assert!(
        ids.contains(&fixture.control_claim),
        "the unpacted grant still exports ordinary material"
    );
    assert!(!linked, "an unpacted grant leaked a same_as link");
    assert!(!ids.contains(&fixture.status_claim));
    assert!(!ids.contains(&consent_p));
}

/// VERDICT-FIX (P1 `coreference-export-fail-open`) — an UNDECODABLE claim row
/// cannot buy its way past the coreference filter.
///
/// `filtered_window_doc` filters a caller-supplied doc, and in production that
/// doc is the live window holding peer-pushed rows: quarantine RECORDS a
/// rejected row but never removes it from the CRDT. The filter used to pass any
/// claim it could not decode, and
/// [`CoreferenceExportContext::claim_travels`] is the ONLY place the allowed
/// link and the exact export pact are checked — so a row that was
/// coreference-shaped but undecodable skipped the pact boundary entirely.
///
/// The planted blob is the pact-Q consent claim's OWN BYTES plus one trailing
/// byte. Well-formed, it is withheld under pact P by the pact rule; malformed,
/// it must be withheld too. One byte must not be the difference between
/// withholding a foreign pact id and shipping it.
#[test]
fn an_undecodable_coreference_claim_is_withheld_not_passed_through() {
    let fixture = coreference_export(true);
    let consent_q = fixture.consent(&COREFERENCE_PACT_Q);
    let planted = entity_id(0x6D);

    let mut blob = fixture
        .vault
        .get_raw(&consent_q)
        .unwrap()
        .expect("the stored pact-Q consent claim");
    blob.push(0xC1); // never a valid MessagePack byte: trailing-bytes decode error
    assert!(
        decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], true).is_err(),
        "the fixture must actually be undecodable, else this proves nothing"
    );

    let doc = fixture.window(&[consent_q]);
    insert_blob(&doc, planted, &blob);
    insert_edge(&doc, planted, EdgeKind::FacetOf, fixture.facet);
    insert_structural_edge(&doc, planted, EdgeKind::ClaimOf, fixture.person_a, 1.0);
    doc.commit();

    let (ids, linked) = fixture.filtered_doc(&doc);

    assert!(
        ids.contains(&fixture.control_claim),
        "the control claim must cross, else this proves nothing"
    );
    assert!(!linked);
    assert!(
        !ids.contains(&consent_q),
        "the well-formed twin is withheld by the pact rule"
    );
    assert!(
        !ids.contains(&planted),
        "an undecodable coreference-shaped claim leaked a foreign pact id"
    );
}

#[test]
fn selector_export_verifies_machine_origin_against_actual_crdt_id_and_body() {
    use crate::write_envelope::{
        ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
    };
    let member = entity_id(0xB8);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let machine = entity_id(0xB9);
    let facet = entity_id(0xBA);
    let signed_id = entity_id(0xBB);
    let changed_id = entity_id(0xBC);
    let stamp = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(
            &machine,
            crate::registry::ENTITY_TYPE_MACHINE,
            stamp,
            1,
            b"machine",
        )
        .unwrap();
    vault
        .put_entity(&facet, ENTITY_TYPE_FACET, stamp, 1, b"facet")
        .unwrap();
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"selector machine root").unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    let signing = SigningKey::from_bytes(&[0xB9; 32]);
    vault
        .enroll_machine_identity(
            &issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [8; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .unwrap();
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "selector.machine",
        ClaimSubject::Entity(machine),
        Value::from("safe"),
        1.0,
    );
    let transcript = vault
        .machine_claim_transcript(&signed_id, &candidate, &envelope)
        .unwrap();
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&signed_id, candidate.clone(), &signed, stamp, 1)
        .commit()
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let body = candidate
        .into_claim_body(
            &signed,
            crate::claim::default_facet_in(&vault.store, &txn).unwrap(),
        )
        .unwrap();
    drop(txn);
    let window = WindowKey::new("2026-03");
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![SelectorRange::Semantic, SelectorRange::Core],
    );
    let selected = |id: EntityId, claim: &ClaimBody| {
        let doc = create_window_doc("source", &window);
        insert_entity(&doc, facet, ENTITY_TYPE_FACET, b"facet");
        insert_blob(
            &doc,
            id,
            &entity_blob(
                crate::registry::ENTITY_TYPE_CLAIM,
                &encode_claim_body(claim).unwrap(),
            ),
        );
        insert_edge(&doc, id, EdgeKind::FacetOf, facet);
        let history = crate::claim::history_store::machine_history_ids_for_target(
            &vault.store,
            &vault.store.env.read_txn().unwrap(),
            signed_id,
        )
        .unwrap();
        for control_id in history {
            let raw = vault.get_raw(&control_id).unwrap().unwrap();
            insert_blob(&doc, control_id, &raw);
            insert_edge(&doc, control_id, EdgeKind::FacetOf, facet);
        }
        doc.commit();
        let filtered =
            filtered_window_doc(&vault, &doc, &window, test_selector_scope(), &selector).unwrap();
        let selected =
            import_ids(&filtered.export(ExportMode::all_updates()).unwrap()).contains(&id);
        let guest =
            guest_share_envelope_body(&vault, &doc, &window, test_selector_scope(), &selector)
                .unwrap();
        let guest_selected = import_ids(&guest.update).contains(&id);
        (selected, guest_selected)
    };
    assert_eq!(
        selected(signed_id, &body),
        (true, true),
        "valid signed row must cross both selector and guest share"
    );
    assert!(
        selected(changed_id, &body) == (false, false),
        "transplanted id must be withheld"
    );
    let mut tampered = body.clone();
    tampered.value = Value::from("attacker");
    assert!(
        selected(signed_id, &tampered) == (false, false),
        "changed payload must be withheld"
    );
    let mut bogus = body.clone();
    if let Some(Value::Map(entries)) = &mut bogus.evidence {
        for (key, value) in entries {
            if key.as_str() == Some("machine_signature") {
                *value = Value::Array(vec![
                    Value::Binary(signing.verifying_key().to_bytes().to_vec()),
                    Value::Binary(vec![0; 64]),
                ]);
            }
        }
    }
    assert!(
        selected(signed_id, &bogus) == (false, false),
        "bogus enrolled-key proof must be withheld"
    );
    vault.retract_claim(&signed_id, 20).unwrap();
    let current = vault.get_claim(&signed_id).unwrap().unwrap();
    assert_eq!(current.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        selected(signed_id, &current),
        (true, true),
        "the full scoped handoff chain must travel after retraction"
    );
    assert_eq!(
        selected(signed_id, &body),
        (false, false),
        "the old signed birth cannot be exported as current state"
    );
}

#[test]
fn explicit_crm_pack_registration_exports_by_family_after_reopen() {
    use crate::registry::{
        TYPE_BYTE_ZONE_COMPILED_PRODUCT_END, TYPE_BYTE_ZONE_COMPILED_PRODUCT_START, TypeByteFamily,
        TypeByteZone, entity_type_registry_entry,
    };
    let member = entity_id(0xD1);
    let (dir, vault, grant_id) = test_vault_with_grant(member);
    let slots: Vec<_> = (TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
        ..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
        .filter(|byte| {
            entity_type_registry_entry(*byte).is_none()
                && vault.structural_kind_registration(*byte).is_none()
        })
        .take(3)
        .collect();
    let pack = crate::campaign::register_crm_pack(
        &vault,
        slots[0],
        slots[1],
        crate::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    // Whole-pack retry preserves the same declared family and assigned slots.
    assert_eq!(
        crate::campaign::register_crm_pack(
            &vault,
            slots[0],
            slots[1],
            crate::registry::TypeByteFamily::Productivity
        )
        .unwrap(),
        pack
    );
    vault
        .register_structural_kind(slots[2], "qx", TypeByteZone::CompiledProduct, "local-only")
        .unwrap();
    let ids = [entity_id(0xD2), entity_id(0xD3), entity_id(0xD4)];
    for (id, kind) in ids.iter().zip(&slots) {
        vault
            .put_entity(id, *kind, TimeRange { start: 1, end: 1 }, 1, b"record")
            .unwrap();
    }
    drop(vault);
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let window = WindowKey::new("2026-03");
    let doc = create_window_doc("source", &window);
    let facet = entity_id(0xD5);
    let seed = entity_id(0xD6);
    insert_entity(&doc, facet, ENTITY_TYPE_FACET, b"pack facet");
    insert_blob(&doc, seed, &claim_blob(None));
    insert_edge(&doc, seed, EdgeKind::FacetOf, facet);
    seed_doc_stamps(&vault, &doc);
    for id in &ids {
        insert_blob(&doc, *id, &vault.get_raw(id).unwrap().unwrap());
        insert_edge(&doc, seed, EdgeKind::Supports, *id);
    }
    doc.commit();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![
            SelectorRange::Semantic,
            SelectorRange::Family(TypeByteFamily::Productivity),
        ],
    );
    let filtered =
        filtered_window_doc(&vault, &doc, &window, test_selector_scope(), &selector).unwrap();
    let exported = import_ids(&filtered.export(ExportMode::all_updates()).unwrap());
    assert!(exported.contains(&ids[0]));
    assert!(exported.contains(&ids[1]));
    assert!(!exported.contains(&ids[2]));
    let other_family = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![
            SelectorRange::Semantic,
            SelectorRange::Family(TypeByteFamily::Documents),
        ],
    );
    let filtered =
        filtered_window_doc(&vault, &doc, &window, test_selector_scope(), &other_family).unwrap();
    let exported = import_ids(&filtered.export(ExportMode::all_updates()).unwrap());
    assert!(
        exported.contains(&seed),
        "the facet seed must cross, else this proves nothing"
    );
    assert!(ids.iter().all(|id| !exported.contains(id)));
}

#[test]
fn peer_document_write_requires_stored_grant_scope_even_inside_selector() {
    let member = entity_id(0x34);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let mut grant = FederationGrant::new(
        test_selector_scope(),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let id = entity_id(0x41);
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            b"turn",
        )
        .unwrap();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![],
        vec![crate::federation::selector_range_of(crate::registry::ENTITY_TYPE_TURN).unwrap()],
    );
    {
        let txn = vault.store.env.read_txn().unwrap();
        super::document_admission::admit_document_write_in_txn(
            &vault,
            &txn,
            id,
            test_selector_scope(),
            &selector,
        )
        .unwrap();
    }
    // The same selector and stamped TURN must be refused once the stored
    // grant permits only reads. A matching selector cannot supply the verb.
    grant.authority_scope = crate::federation::scope_codec::read_preset();
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            2,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let err = super::document_admission::admit_document_write_in_txn(
        &vault,
        &txn,
        id,
        test_selector_scope(),
        &selector,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::DocumentAdmissionDenied,
        })
    ));
}

#[test]
fn document_peer_import_rechecks_pact_activation_ceiling_and_expiry_in_txn() {
    use crate::sync::transport::document_sub_tags;
    for active in [true, false] {
        let member = entity_id(0x34);
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        let grant = FederationGrant::new(
            test_selector_scope(),
            member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        vault
            .batch()
            .put_replicated(
                &grant_id,
                ENTITY_TYPE_FEDERATION_GRANT,
                TimeRange { start: 1, end: 1 },
                1,
                &encode_federation_grant_body(&grant).unwrap(),
            )
            .commit()
            .unwrap();
        let id = entity_id(0x41);
        let facet = entity_id(0x44);
        vault
            .put_entity(
                &id,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                b"turn",
            )
            .unwrap();
        vault
            .put_entity(
                &facet,
                ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                b"facet",
            )
            .unwrap();
        vault.put_edge(&id, EdgeKind::FacetOf, &facet, 1.0).unwrap();
        if active {
            let mut ceiling = all_direction_scope();
            ceiling.facets = ScopeAxis::from_iter([facet].map(ScopeId));
            seed_scoped_pacts_for_grant(&vault, grant_id, &[ceiling]);
        } else {
            seed_pact_for_grant(&vault, grant_id, PactSeedStatus::Disconnected);
        }
        let vault = Arc::new(vault);
        let manager = Arc::new(WindowManager::new(
            vault.clone(),
            Arc::new(crate::sync::bridge::Materializer::new()),
            "document pact",
        ));
        let doc = manager.documents().open(id).unwrap();
        let remote = LoroDoc::new();
        remote.get_text("body").insert(0, "admitted").unwrap();
        remote.commit();
        let update = remote.export(ExportMode::all_updates()).unwrap();
        let selector = SyncSelector::new(
            grant_id,
            member,
            SyncSelectorWorld::All,
            vec![facet],
            vec![
                crate::federation::selector_range_of(crate::registry::ENTITY_TYPE_TURN)
                    .expect("TURN has a registered selector identity"),
            ],
        );
        let result = doc.import_from_peer(
            document_sub_tags::UPDATE,
            &update,
            test_selector_scope(),
            &selector,
        );
        if active {
            result.unwrap();
            assert_eq!(doc.text().unwrap(), "admitted");
            let mut wider = selector.clone();
            wider.facets = RequestedAxis::Named(vec![facet, entity_id(0x43)]);
            let error = doc
                .import_from_peer(
                    document_sub_tags::UPDATE,
                    &update,
                    test_selector_scope(),
                    &wider,
                )
                .unwrap_err();
            assert_grant_scope_mismatch(&error, "peer document writer");
        } else {
            assert!(matches!(
                result.unwrap_err(),
                Error::Sync(SyncError::SyncProtocolError {
                    context: SyncProtocolValidation::Selector {
                        reason: SelectorError::GrantInactive
                    },
                })
            ));
            assert_eq!(doc.text().unwrap(), "");
        }
    }
    // Expiry shares the exact txn-bound grant door with NOTE reads. Delegate
    // roles never write, even before expiry; expired reads must also refuse.
    let member = entity_id(0x34);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let grant = FederationGrant {
        authority_scope: crate::federation::scope_codec::read_preset(),
        scope: test_selector_scope(),
        member_ref: member,
        role: FederationGrantRole::Delegate,
        preset: FederationGrantPreset::Delegate,
        expires_at: Some(1),
        delegated_by: Some(entity_id(0x35)),
        guest: None,
    };
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let error = vault
        .with_write_txn(|txn| {
            super::document_admission::authorize_in_txn(
                &vault,
                txn,
                test_selector_scope(),
                &selector,
                None,
            )
            .map(|_| ())
        })
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::Selector {
                reason: SelectorError::GrantExpired
            },
        })
    ));
}

#[test]
fn replay_tier_fork_scales_federated_confidence_once_and_audits_remote_value() {
    use crate::sync::client::ImportTier;
    let key = WindowKey::new("2026-03");
    let (_own_dir, own, _, mut own_client) = test_client_with_grant(entity_id(0xB1), key.as_str());
    let (_fed_dir, fed, _, mut fed_client) = test_client_with_grant(entity_id(0xB2), key.as_str());
    let id = entity_id(0xB3);
    let remote = create_window_doc("remote", &key);
    insert_blob(&remote, id, &edge_provenance_claim_blob());
    remote.commit();
    let bytes = remote.export(ExportMode::all_updates()).unwrap();
    own_client
        .import_window_update(key.as_str(), &bytes, ImportTier::OwnDevice)
        .unwrap();
    let own_body = own.get_claim(&id).unwrap().unwrap();
    assert_eq!(own_body.confidence, 0.75);
    assert_eq!(
        crate::provenance::decode_edge_provenance_body(&own_body.value)
            .unwrap()
            .confidence,
        0.75
    );
    assert_eq!(own_body.source, Some(ClaimSource::ToolOutput));
    assert!(matches!(
        fed_client.import_window_update(
            key.as_str(),
            &bytes,
            ImportTier::Federated(FederationAdmissionRole::Member)
        ),
        Err(crate::sync::TransportError::AdmissionDenied(_))
    ));
    assert!(fed.get_claim(&id).unwrap().is_none());
    put_imported_source_trust(&fed);
    fed_client
        .import_window_update(
            key.as_str(),
            &bytes,
            ImportTier::Federated(FederationAdmissionRole::Member),
        )
        .unwrap();
    assert!(
        quarantined_records(&fed).unwrap().is_empty(),
        "admitted claim must materialize: {:?}",
        quarantined_records(&fed).unwrap()
    );
    let body = fed.get_claim(&id).unwrap().unwrap();
    assert_eq!(body.confidence, 0.375);
    assert_eq!(
        crate::provenance::decode_edge_provenance_body(&body.value)
            .unwrap()
            .confidence,
        0.375
    );
    assert_eq!(body.source, Some(ClaimSource::Imported));
    let Some(Value::Map(scope)) = body.scope else {
        panic!("missing audit scope")
    };
    assert!(scope.iter().any(
        |(key, value)| key.as_str() == Some("federated_original_confidence")
            && value.as_f64() == Some(0.75)
    ));
    fed_client
        .import_window_update(
            key.as_str(),
            &bytes,
            ImportTier::Federated(FederationAdmissionRole::Member),
        )
        .unwrap();
    assert_eq!(fed.get_claim(&id).unwrap().unwrap().confidence, 0.375);
    // Direct replicated puts take the identical tier fork, inside their write transaction.
    for (tag, tier, confidence) in [
        (0xB4, ImportTier::OwnDevice, 0.75),
        (
            0xB5,
            ImportTier::Federated(FederationAdmissionRole::Guest),
            0.375,
        ),
    ] {
        let id = entity_id(tag);
        let blob = edge_provenance_claim_blob();
        crate::sync::replay::replay_entity(
            &fed,
            crate::sync::replay::ReplicatedEntity {
                id,
                entity_type: ENTITY_TYPE_CLAIM,
                occurred: crate::TimeRange { start: 1, end: 1 },
                learned_at: 1,
                body: &blob[ENTITY_METADATA_HEADER_LEN..],
            },
            tier,
        )
        .unwrap();
        let body = fed.get_claim(&id).unwrap().unwrap();
        assert_eq!(body.confidence, confidence);
        assert_eq!(
            crate::provenance::decode_edge_provenance_body(&body.value)
                .unwrap()
                .confidence,
            confidence
        );
    }
}

#[test]
fn selector_custody_locality_uses_the_export_read_snapshot() {
    use crate::secret_custody::{
        CustodyClass, SECRET_CUSTODY_SCHEMA_VERSION, SecretCustodyFloor, SecretCustodyRecord,
        SecretCustodyStatus,
    };

    let member = entity_id(0xB6);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let key = WindowKey::new("2026-03");
    let doc = create_window_doc("custody-selector", &key);
    let facet = entity_id(0xB7);
    let seed = entity_id(0xB8);
    insert_entity(&doc, facet, ENTITY_TYPE_FACET, b"custody facet");
    insert_blob(&doc, seed, &claim_blob(None));
    insert_edge(&doc, seed, EdgeKind::FacetOf, facet);
    seed_doc_stamps(&vault, &doc);
    let mut secrets = Vec::new();
    for device_only in [false, true] {
        let id = vault
            .register_secret(SecretCustodyRecord {
                schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
                name: format!("selector-custody-{device_only}"),
                class: CustodyClass::CustodyPortable,
                device_only,
                value_bytes: b"selector-custody-canary".to_vec(),
                status: SecretCustodyStatus::Active,
                registered_at: 1,
                rotated_at: None,
                rotation_generation: 0,
                bindings: Vec::new(),
                manifest_ref: "secrets.toml".into(),
                declared_paths: Vec::new(),
                policy_floor_snapshot: SecretCustodyFloor::default(),
            })
            .unwrap();
        let raw = vault.get_raw_unsealed(&id).unwrap().unwrap();
        insert_blob(&doc, id, &raw);
        insert_edge(&doc, seed, EdgeKind::Supports, id);
        secrets.push((id, device_only));
    }
    doc.commit();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![
            SelectorRange::Semantic,
            SelectorRange::Core,
            SelectorRange::Family(TypeByteFamily::AuthorityPolicyCustody),
        ],
    );
    let update = filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap();
    let ids = import_ids(&update);
    assert!(ids.contains(&seed));
    for (id, device_only) in secrets {
        assert_eq!(ids.contains(&id), !device_only);
    }
}

fn member_grant_vault(member: EntityId) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let grant_id = EntityId::now();
    put_selector_test_federation_grant(
        &vault,
        &grant_id,
        &FederationGrant::new(
            test_selector_scope(),
            member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
        1,
    )
    .unwrap();
    (dir, vault, grant_id)
}

fn note_window_export(vault: &Vault, note: EntityId, selector: &SyncSelector) -> Vec<u8> {
    let raw = vault.get_raw(&note).unwrap().unwrap();
    let key = WindowKey::from_timestamp(EntityMetadataHeader::parse(&raw).unwrap().learned_at);
    let doc = create_window_doc("source", &key);
    crate::sync::window::reverse_rematerialize(vault, &doc, &key).unwrap();
    filtered_window_doc(vault, &doc, &key, test_selector_scope(), selector)
        .unwrap()
        .export(ExportMode::all_updates())
        .unwrap()
}

#[test]
fn a_replica_serves_a_replicated_note_that_carries_its_stamp() {
    let origin_dir = tempfile::tempdir().unwrap();
    let origin = Vault::open(origin_dir.path(), crate::VaultConfig::device()).unwrap();
    let owner = origin.ensure_embedded_owner_actor().unwrap();
    let note = origin
        .create_note(
            "research",
            "replicated birth",
            crate::WriteActor::new(owner, EdgeActorClass::Human),
        )
        .unwrap();
    let raw = origin.get_raw(&note).unwrap().unwrap();
    let header = EntityMetadataHeader::parse(&raw).unwrap();
    let stamp = origin
        .edges_out(&note)
        .unwrap()
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::FacetOf)
        .unwrap();
    let member = entity_id(0x3E);
    let (_dir, host, grant_id) = member_grant_vault(member);
    host.batch()
        .put_replicated(
            &note,
            crate::registry::ENTITY_TYPE_NOTE,
            TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            &raw[ENTITY_METADATA_HEADER_LEN..],
        )
        .edge_with_value_fields(
            &note,
            EdgeKind::FacetOf,
            &stamp.target,
            crate::batch::EdgeValueFields {
                weight: stamp.weight,
                created_at: stamp.created_at,
                vad: Vad::NEUTRAL,
                provenance: None,
            },
        )
        .commit()
        .unwrap();
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);

    assert!(import_ids(&note_window_export(&host, note, &selector)).contains(&note));
}

#[test]
fn a_named_facet_request_selects_a_note_born_under_that_facet() {
    let member = entity_id(0x3F);
    let (_dir, vault, grant_id) = member_grant_vault(member);
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let facet = entity_id(0x6A);
    vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"facet",
        )
        .unwrap();
    let receipt = vault
        .memory(owner, EdgeActorClass::Human)
        .author_note(&crate::note::NoteWriteEnvelope {
            kind: crate::note::NoteKind::OpinionTake,
            scope: crate::note::NoteScope::About(crate::note::TakeTarget::Subject(owner)),
            markdown: "masked take".to_owned(),
            source_revision_ref: [0x6B; 16],
            mask: Some(facet),
        })
        .unwrap();
    let note = EntityId::from_hex(&receipt.id_hex).unwrap();
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        vec![facet],
        vec![],
    );

    assert!(import_ids(&note_window_export(&vault, note, &selector)).contains(&note));
}

#[test]
fn federation_addressing_copy_requires_stamped_source_and_exact_edge_bytes() {
    let (_dir, source, conv, actor) = crate::conversation_dag::fixtures::fixture();
    let recipient = EntityId::now();
    let forged = EntityId::now();
    for id in [recipient, forged] {
        source
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                &crate::conversation_dag::fixtures::body("person"),
            )
            .unwrap();
    }
    let mut input = crate::conversation_dag::fixtures::input(conv, None, true, actor);
    input.address = crate::conversation_dag::AddressMode::Direct;
    input.recipients = vec![recipient];
    let record = source.append_dag_record(&input).unwrap().id;
    let key = WindowKey::from_timestamp(input.learned_at);
    let source_doc = create_window_doc("source", &key);
    crate::sync::window::reverse_rematerialize(&source, &source_doc, &key).unwrap();
    let valid = crate::sync::bridge::format_edge_key(&record, EdgeKind::AddressedTo, &recipient);
    let invalid = crate::sync::bridge::format_edge_key(&record, EdgeKind::AddressedTo, &forged);
    map_insert_bytes(
        &source_doc.get_map("edges"),
        &invalid,
        &encode_edge_value_for_crdt(EdgeKind::AddressedTo, 1.0, input.learned_at, None, None)
            .unwrap(),
    )
    .unwrap();
    let target = create_window_doc("target", &key);
    let peer_dir = tempfile::tempdir().unwrap();
    let peer = Vault::open(peer_dir.path(), crate::VaultConfig::device()).unwrap();
    edge::copy_admitted_edges(
        &peer,
        &key,
        &source_doc.get_map("entities"),
        &source_doc.get_map("entities"),
        &source_doc.get_map("edges"),
        &target.get_map("edges"),
    )
    .unwrap();
    assert!(crate::sync::loro_support::map_contains_binary(
        &target.get_map("edges"),
        &valid
    ));
    assert!(!crate::sync::loro_support::map_contains_binary(
        &target.get_map("edges"),
        &invalid
    ));
    assert!(
        quarantined_records(&peer)
            .unwrap()
            .iter()
            .any(|(_, row)| row.container == QuarantineContainer::Edges
                && row.reason_code == "ReservedEdgeKind")
    );
}

#[test]
fn ask_guest_grant_cannot_authorize_sync_selector() {
    let member = entity_id(0x70);
    let group = entity_id(0x71);
    let guest = FederationGrant::ask_guest(
        group,
        member,
        entity_id(0x72),
        entity_id(0x73),
        std::collections::BTreeSet::from([entity_id(0x74)]),
    )
    .expect("valid guest grant");
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let grant_id = EntityId::now();
    let body = encode_federation_grant_body(&guest).unwrap();
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
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);

    assert!(authorize_sync_selector(&vault, FederationGrantScope::ask(group), &selector).is_err());
    assert!(authorize_sync_selector(&vault, FederationGrantScope::vault(7), &selector).is_err());
}

#[test]
fn world_selector_keeps_authorized_claim_to_shared_base_edge_across_windows() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let world = local_world_id(0x5e);
    let person = entity_id(0x62);
    let claim = entity_id(0x63);
    let base_key = WindowKey::new("2026-03");
    let at = base_key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(
        &world.entity_id(),
        ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, at, b"person")?;
    let mut body = ClaimBody::new(
        "selector.shared_subject",
        ClaimSubject::Entity(person),
        Value::from("world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world.entity_id());
    vault.put_claim(&claim, &body, occurred, at)?;
    vault
        .batch()
        .edge(&claim, EdgeKind::About, &person, 1.0)
        .commit()?;
    let world_key = WindowKey::for_month_world(&base_key, world.entity_id());
    let base_doc = create_window_doc("source", &base_key);
    let world_doc = create_window_doc("source", &world_key);
    crate::sync::window::reverse_rematerialize(&vault, &base_doc, &base_key)?;
    crate::sync::window::reverse_rematerialize(&vault, &world_doc, &world_key)?;
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::World(world),
        vec![],
        vec![],
    );
    let base = filtered_window_doc(
        &vault,
        &base_doc,
        &base_key,
        test_selector_scope(),
        &selector,
    )?;
    let scoped = filtered_window_doc(
        &vault,
        &world_doc,
        &world_key,
        test_selector_scope(),
        &selector,
    )?;
    let edge = crate::sync::bridge::format_edge_key(&claim, EdgeKind::About, &person);
    assert!(base.get_map("entities").get(&person.to_hex()).is_some());
    assert!(scoped.get_map("entities").get(&claim.to_hex()).is_some());
    assert!(scoped.get_map("entities").get(&person.to_hex()).is_none());
    assert!(scoped.get_map("edges").get(&edge).is_some());
    let peer_dir = tempfile::tempdir()?;
    let peer = Vault::open(peer_dir.path(), crate::VaultConfig::device())?;
    let materializer = crate::sync::bridge::Materializer::new();
    crate::sync::window::forward_rematerialize(&peer, &base, &materializer, &base_key)?;
    crate::sync::window::forward_rematerialize(&peer, &scoped, &materializer, &world_key)?;
    assert!(
        peer.edges_out(&claim)?
            .iter()
            .any(|row| row.kind == EdgeKind::About && row.target == person)
    );
    Ok(())
}

/// Astra #1384 P1-2: an epoch summary leaves only with every record it was
/// written from. A run read a CLAIM in private world W and summarized it: a
/// peer whose grant takes base-world SUMMARY rows but not W gets neither the
/// summary nor its words, and no source is sent along. A summary of base
/// records still leaves beside them. A source only another window carries
/// cannot be proven from this export (Sol round 10 on #1384), so even a peer
/// that takes W gets the CLAIM and not its summary. The scoped record export
/// door judges the same way.
#[test]
fn an_epoch_summary_leaves_only_with_every_record_it_was_written_from() -> crate::Result<()> {
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochSummaryBody,
        encode_epoch_summary_body,
    };
    use crate::federation::{Scope, ScopeAxis, ScopeId};
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let world = local_world_id(0x5e);
    let person = entity_id(0x62);
    let (claim, private, plain) = (entity_id(0x63), entity_id(0x64), entity_id(0x65));
    let base_key = WindowKey::new("2026-03");
    let at = base_key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(
        &world.entity_id(),
        ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, at, b"person")?;
    let mut body = ClaimBody::new(
        "selector.private_fact",
        ClaimSubject::Entity(person),
        Value::from("the private world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world.entity_id());
    vault.put_claim(&claim, &body, occurred, at)?;
    let epoch = |epoch: u64, text: &str| {
        encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: entity_id(0x66).to_hex(),
            epoch,
            turn_start: epoch * 3,
            turn_end: epoch * 3 + 2,
            level: EPOCH_SUMMARY_LEVEL,
            text: text.into(),
            actor: entity_id(0x67).to_hex(),
        })
    };
    vault
        .batch()
        .put(
            &private,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch(1, "the run learned the private world fact")?,
        )
        .edge(&private, EdgeKind::DerivedFrom, &claim, 1.0)
        .put(
            &plain,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch(2, "the run met the person")?,
        )
        .edge(&plain, EdgeKind::DerivedFrom, &person, 1.0)
        .commit()?;
    let base_doc = create_window_doc("source", &base_key);
    crate::sync::window::reverse_rematerialize(&vault, &base_doc, &base_key)?;
    let sent = |world_axis| -> crate::Result<Vec<EntityId>> {
        let selector = SyncSelector::new(grant_id, member, world_axis, vec![], vec![]);
        let filtered = filtered_window_doc(
            &vault,
            &base_doc,
            &base_key,
            test_selector_scope(),
            &selector,
        )?;
        Ok(import_ids(
            &filtered.export(ExportMode::all_updates()).unwrap(),
        ))
    };
    let base = sent(SyncSelectorWorld::Base)?;
    assert!(base.contains(&person) && base.contains(&plain));
    assert!(!base.contains(&private), "the summary stays with its CLAIM");
    assert!(!base.contains(&claim), "no source is sent along");
    let all = sent(SyncSelectorWorld::All)?;
    assert!(
        all.contains(&plain) && !all.contains(&private),
        "a summary leaves only beside its sources, and the CLAIM travels in W's window"
    );

    let mut base_only = Scope::top();
    base_only.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(
        crate::claim::base_world_id(),
    )]));
    let top = Scope::top();
    let exported = vault
        .export_records_in_scope(&base_only, &top, &top)?
        .into_iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    assert!(exported.contains(&plain));
    assert!(!exported.contains(&private) && !exported.contains(&claim));
    let read = vault
        .records_in_scope(
            &base_only,
            &top,
            &top,
            crate::federation::record_scope::ScopeView::Normal,
        )?
        .into_iter()
        .map(|record| record.id)
        .collect::<Vec<_>>();
    assert!(read.contains(&plain) && !read.contains(&private));
    Ok(())
}

/// Sol round 5 on #1384: an epoch summary stays where its world or a source
/// stays. A summary a run settled in world W is not base-world disclosure,
/// and a world flagged device-only keeps both the summary born in it and
/// every summary written from its rows on this device.
#[test]
fn an_epoch_summary_stays_where_its_world_or_a_source_stays() -> crate::Result<()> {
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochPlacement, EpochSummaryBody,
        encode_epoch_summary_body,
    };
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let world = local_world_id(0x5f);
    let person = entity_id(0x68);
    let (claim, kept, placed) = (entity_id(0x69), entity_id(0x6a), entity_id(0x6b));
    let base_key = WindowKey::new("2026-03");
    let at = base_key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(
        &world.entity_id(),
        ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, at, b"person")?;
    let mut body = ClaimBody::new(
        "selector.device_fact",
        ClaimSubject::Entity(person),
        Value::from("the device-only world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world.entity_id());
    vault.put_claim(&claim, &body, occurred, at)?;
    let epoch = |epoch: u64, text: &str| {
        encode_epoch_summary_body(&EpochSummaryBody {
            v: EPOCH_SUMMARY_BODY_VERSION,
            session: entity_id(0x6c).to_hex(),
            epoch,
            turn_start: epoch * 3,
            turn_end: epoch * 3 + 2,
            level: EPOCH_SUMMARY_LEVEL,
            text: text.into(),
            actor: entity_id(0x6d).to_hex(),
        })
    };
    vault
        .batch()
        .put(
            &kept,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch(1, "the run learned the device-only world fact")?,
        )
        .edge(&kept, EdgeKind::DerivedFrom, &claim, 1.0)
        .put(
            &placed,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch(2, "the run met the person in its world")?,
        )
        .edge(&placed, EdgeKind::DerivedFrom, &person, 1.0)
        .commit()?;
    let placement = EpochPlacement {
        world: Some(world.entity_id()),
        facet: None,
    };
    vault.with_write_txn_grouped(|txn| placement.settle_in(&vault.store, txn, placed))?;
    let packed = || -> crate::Result<LoroDoc> {
        let doc = create_window_doc("source", &base_key);
        crate::sync::window::reverse_rematerialize(&vault, &doc, &base_key)?;
        Ok(doc)
    };
    let sent = |doc: &LoroDoc, world_axis| -> crate::Result<Vec<EntityId>> {
        let selector = SyncSelector::new(grant_id, member, world_axis, vec![], vec![]);
        let filtered =
            filtered_window_doc(&vault, doc, &base_key, test_selector_scope(), &selector)?;
        Ok(import_ids(
            &filtered.export(ExportMode::all_updates()).unwrap(),
        ))
    };
    let before = packed()?;
    let base = sent(&before, SyncSelectorWorld::Base)?;
    assert!(base.contains(&person));
    assert!(
        !base.contains(&placed),
        "a summary born in W is not base-world disclosure"
    );
    let all = sent(&before, SyncSelectorWorld::All)?;
    assert!(all.contains(&placed), "a summary born in W leaves with W");
    assert!(
        !all.contains(&kept),
        "a summary of W's CLAIM stays home: the CLAIM travels in W's window"
    );

    vault.keep_world_on_this_machine_for_test(world.entity_id(), true)?;
    let all = sent(&before, SyncSelectorWorld::All)?;
    assert!(
        !all.contains(&kept),
        "a device-only source keeps its summary home"
    );
    assert!(
        !all.contains(&placed),
        "a summary born in a device-only world stays home, even out of an older window"
    );
    assert!(all.contains(&person) && !all.contains(&claim));
    let after = sent(&packed()?, SyncSelectorWorld::All)?;
    assert!(
        !after.contains(&placed),
        "a summary born in a device-only world is never packed"
    );
    assert!(after.contains(&person) && !after.contains(&kept));
    Ok(())
}

/// #1384 beside #1402 (R11133): a world turned device-only keeps the epoch
/// summaries packed while it was portable, at every export door, until the
/// flag clears. `placed` was born in W; `told` was born in base reality from
/// W's CLAIM and carries its words; `lost` was written from a row this device
/// no longer holds, so the world it sat in is unknown (a raw row delete: every
/// deletion path takes the edge to the row with it, so this models a store
/// left inconsistent). The window door withholds each one's base window, the
/// selector drops `placed` and every edge naming it, and the scoped record
/// export drops both. A promotion stands: the flag withholds bytes, not the
/// grant's authority (Sol round 17 on #1384).
#[test]
fn a_device_only_world_keeps_epoch_summaries_packed_while_it_was_portable() -> crate::Result<()> {
    use crate::compaction::EpochPlacement;
    use crate::federation::Scope;
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let world = local_world_id(0x58).entity_id();
    let (person, placed) = (entity_id(0x59), entity_id(0x5a));
    let (fact, told) = (entity_id(0x60), entity_id(0x61));
    let (gone, lost) = (entity_id(0x62), entity_id(0x63));
    let (march, april, may) = (
        WindowKey::new("2026-03"),
        WindowKey::new("2026-04"),
        WindowKey::new("2026-05"),
    );
    let at = |key: &WindowKey| {
        let at = key.start_timestamp().unwrap() + 60;
        (TimeRange { start: at, end: at }, at)
    };
    // The WORLD row sits in February's window, so only a summary can make
    // March's or April's window one the flag keeps.
    let (occurred, learned) = at(&WindowKey::new("2026-02"));
    vault.put_entity(&world, ENTITY_TYPE_WORLD, occurred, learned, b"world")?;
    let (in_march, march_at) = at(&march);
    let (in_april, april_at) = at(&april);
    let (in_may, may_at) = at(&may);
    vault.put_entity(&person, ENTITY_TYPE_PERSON, in_march, march_at, b"person")?;
    vault.put_entity(&gone, ENTITY_TYPE_PERSON, in_may, may_at, b"gone")?;
    let mut body = ClaimBody::new(
        "selector.world_fact",
        ClaimSubject::Entity(person),
        Value::from("the world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    vault.put_claim(&fact, &body, in_april, april_at)?;
    vault
        .batch()
        .put(
            &placed,
            crate::registry::ENTITY_TYPE_SUMMARY,
            in_march,
            march_at,
            &epoch_summary_bytes(1, "the run met the person in its world")?,
        )
        .edge(&placed, EdgeKind::DerivedFrom, &person, 1.0)
        .put(
            &told,
            crate::registry::ENTITY_TYPE_SUMMARY,
            in_april,
            april_at,
            &epoch_summary_bytes(2, "the run learned the world fact")?,
        )
        .edge(&told, EdgeKind::DerivedFrom, &fact, 1.0)
        .put(
            &lost,
            crate::registry::ENTITY_TYPE_SUMMARY,
            in_may,
            may_at,
            &epoch_summary_bytes(3, "the run met someone")?,
        )
        .edge(&lost, EdgeKind::DerivedFrom, &gone, 1.0)
        .commit()?;
    let in_world = EpochPlacement {
        world: Some(world),
        facet: None,
    };
    vault.with_write_txn_grouped(|txn| in_world.settle_in(&vault.store, txn, placed))?;
    vault.with_write_txn_grouped(|txn| {
        for base in [told, lost] {
            EpochPlacement::default().settle_in(&vault.store, txn, base)?;
        }
        Ok(())
    })?;
    let packed = |key: &WindowKey| -> crate::Result<LoroDoc> {
        let doc = create_window_doc("source", key);
        crate::sync::window::reverse_rematerialize(&vault, &doc, key)?;
        Ok(doc)
    };
    let (march_doc, april_doc, may_doc) = (packed(&march)?, packed(&april)?, packed(&may)?);
    vault.with_write_txn(|txn| {
        vault.store.entities.delete(txn, gone.as_bytes())?;
        Ok(())
    })?;
    let top = Scope::top();
    let ships = |shipped: bool| -> crate::Result<()> {
        let window = |key: &WindowKey, doc: &LoroDoc| -> crate::Result<bool> {
            Ok(!crate::sync::window::export_withheld(
                &vault,
                key,
                doc,
                &loro::VersionVector::default(),
            )?)
        };
        assert_eq!(
            window(&march, &march_doc)?,
            shipped,
            "the window door, March"
        );
        assert_eq!(
            window(&april, &april_doc)?,
            shipped,
            "the window door, April"
        );
        assert_eq!(window(&may, &may_doc)?, shipped, "the window door, May");
        let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
        let selected =
            filtered_window_doc(&vault, &march_doc, &march, test_selector_scope(), &selector)?;
        let ids = import_ids(&selected.export(ExportMode::all_updates()).unwrap());
        let mut edges = Vec::new();
        map_for_each_value_bytes(&selected.get_map("edges"), |key, _| {
            edges.push(key.to_owned());
        });
        assert!(ids.contains(&person));
        assert_eq!(ids.contains(&placed), shipped, "the selector, the summary");
        let promoted = crate::sync::residence::promotion_covers_full_window(
            &vault,
            &march_doc,
            &march,
            test_selector_scope(),
            &selector,
            |_| Ok(true),
        )?;
        assert!(promoted, "the promotion stands");
        assert_eq!(
            edges.iter().any(|key| key.contains(&placed.to_hex())),
            shipped,
            "the selector, an edge naming the summary"
        );
        let exported = vault
            .export_records_in_scope(&top, &top, &top)?
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();
        assert_eq!(
            exported.contains(&placed),
            shipped,
            "the scoped export, born in W"
        );
        assert_eq!(
            exported.contains(&told),
            shipped,
            "the scoped export, W's words"
        );
        Ok(())
    };
    ships(true)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    ships(false)?;
    vault.keep_world_on_this_machine_for_test(world, false)?;
    ships(true)
}

/// #1384 beside #1402: a deletion that withdraws an epoch summary records
/// where the words it took sat, read before that source, its stamp and its
/// edges go, so the summary keeps them home while a world is device-only.
/// `told` was written from W's CLAIM and `plain` from a base CLAIM, both
/// purged with their edges; `outer` from `inner`, a summary born in W that a
/// user delete leaves as a shell with no stamp. `erased`, written from W's
/// CLAIM, is itself erased first: its words stay in May's packed window.
#[test]
fn a_deletion_records_the_worlds_it_withdrew_an_epoch_summary_for() -> crate::Result<()> {
    use crate::compaction::EpochPlacement;
    use crate::deletion::DeleteEntityOptions;
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x32));
    let world = local_world_id(0x58).entity_id();
    let person = entity_id(0x59);
    let (fact, told) = (entity_id(0x60), entity_id(0x61));
    let (base_fact, plain) = (entity_id(0x64), entity_id(0x65));
    let (inner, outer, erased) = (entity_id(0x66), entity_id(0x67), entity_id(0x68));
    let (may, june, july, august) = (
        WindowKey::new("2026-05"),
        WindowKey::new("2026-06"),
        WindowKey::new("2026-07"),
        WindowKey::new("2026-08"),
    );
    let at = |key: &WindowKey| {
        let at = key.start_timestamp().unwrap() + 60;
        (TimeRange { start: at, end: at }, at)
    };
    // The sources sit in September, apart from the windows checked.
    let (sources, sources_at) = at(&WindowKey::new("2026-09"));
    vault.put_entity(&world, ENTITY_TYPE_WORLD, sources, sources_at, b"world")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, sources, sources_at, b"person")?;
    let claim = |world: Option<EntityId>| {
        let mut body = ClaimBody::new(
            "selector.fact",
            ClaimSubject::Entity(person),
            Value::from("the fact"),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = world;
        body
    };
    vault.put_claim(&fact, &claim(Some(world)), sources, sources_at)?;
    vault.put_claim(&base_fact, &claim(None), sources, sources_at)?;
    let summary = crate::registry::ENTITY_TYPE_SUMMARY;
    let ((in_june, june_at), (in_july, july_at)) = (at(&june), at(&july));
    let ((in_may, may_at), (in_august, august_at)) = (at(&may), at(&august));
    vault
        .batch()
        .put(
            &erased,
            summary,
            in_may,
            may_at,
            &epoch_summary_bytes(5, "the world fact")?,
        )
        .edge(&erased, EdgeKind::DerivedFrom, &fact, 1.0)
        .put(
            &told,
            summary,
            in_june,
            june_at,
            &epoch_summary_bytes(1, "the world fact")?,
        )
        .edge(&told, EdgeKind::DerivedFrom, &fact, 1.0)
        .put(
            &plain,
            summary,
            in_july,
            july_at,
            &epoch_summary_bytes(2, "the fact")?,
        )
        .edge(&plain, EdgeKind::DerivedFrom, &base_fact, 1.0)
        .put(
            &inner,
            summary,
            sources,
            sources_at,
            &epoch_summary_bytes(3, "the person")?,
        )
        .edge(&inner, EdgeKind::DerivedFrom, &person, 1.0)
        .put(
            &outer,
            summary,
            in_august,
            august_at,
            &epoch_summary_bytes(4, "again")?,
        )
        .edge(&outer, EdgeKind::DerivedFrom, &inner, 1.0)
        .commit()?;
    let in_world = EpochPlacement {
        world: Some(world),
        facet: None,
    };
    vault.with_write_txn_grouped(|txn| {
        in_world.settle_in(&vault.store, txn, inner)?;
        for base in [told, plain, outer, erased] {
            EpochPlacement::default().settle_in(&vault.store, txn, base)?;
        }
        Ok(())
    })?;
    let packed = |key: &WindowKey| -> crate::Result<LoroDoc> {
        let doc = create_window_doc("source", key);
        crate::sync::window::reverse_rematerialize(&vault, &doc, key)?;
        Ok(doc)
    };
    let (may_doc, june_doc) = (packed(&may)?, packed(&june)?);
    let (july_doc, august_doc) = (packed(&july)?, packed(&august)?);
    // A soft erase leaves the words in May's packed window and in history,
    // so the shell keeps W (Sol round 21).
    vault.delete_entity(&erased)?;
    let purge = DeleteEntityOptions { purge: true };
    vault.delete_entity_with_options(&fact, purge)?;
    vault.delete_entity_with_options(&base_fact, purge)?;
    vault.delete_entity(&inner)?;
    // A peer that had not seen the purge sends its soft delete late: the
    // words are gone already, so the summary's record does not change (Sol
    // round 18).
    let late = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 5,
        request_id: [7; 16],
    };
    vault.apply_replayed_tombstone(&base_fact, &late.encode())?;
    // `inner`'s shell no longer says where it sat; a summary minted from it
    // now would copy its words (Sol round 18).
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        crate::settings::minted_worlds_in(&vault.store, &rtxn, &inner)?.unknown,
        "a deleted summary's shell is unknown to a mint"
    );
    drop(rtxn);

    let ships = |portable: bool| -> crate::Result<()> {
        let window = |key: &WindowKey, doc: &LoroDoc| -> crate::Result<bool> {
            Ok(!crate::sync::window::export_withheld(
                &vault,
                key,
                doc,
                &loro::VersionVector::default(),
            )?)
        };
        assert_eq!(
            window(&may, &may_doc)?,
            portable,
            "May, an erased summary of W's CLAIM"
        );
        assert_eq!(
            window(&june, &june_doc)?,
            portable,
            "June, W's purged CLAIM"
        );
        assert!(window(&july, &july_doc)?, "July, a purged base CLAIM");
        assert_eq!(
            window(&august, &august_doc)?,
            portable,
            "August, a deleted W summary"
        );
        Ok(())
    };
    ships(true)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    ships(false)?;
    vault.keep_world_on_this_machine_for_test(world, false)?;
    ships(true)?;

    // A restore over this vault brings the summary back with them.
    let backups = crate::test_support::restore_tempdir();
    let image = backups.path().join("image");
    vault.snapshot_checkpoint(&image, 100)?;
    let (restored, _) = Vault::restore_checkpoint_keeping_authority(
        &image,
        &backups.path().join("restored"),
        vault.config.clone(),
        &vault,
        101,
    )?;
    let rtxn = restored.store.env.read_txn()?;
    assert!(restored.get_raw_in(&rtxn, &told)?.is_some());
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&restored.store, &rtxn, &told)?
            .map(|withdrawn| withdrawn.worlds),
        Some(std::collections::BTreeSet::from([world])),
        "a restored summary keeps what it was withdrawn for"
    );
    Ok(())
}

/// Sol round 17 on #1384, and the Engine ruling after it. A NOTE an export
/// drops is judged in the selection's own snapshot, before the epoch pass, so
/// a summary written from it never leaves without it, even when a flag lands
/// as the export closes its snapshot. A device-only flag is policy, not
/// authority: the view a promotion is judged by keeps a NOTE of the flagged
/// world (this corrects #1402's authority-mode NOTE drop, which revoked the
/// promotion), while the export withholds the NOTE and the summary of it.
#[test]
fn a_summary_never_leaves_without_a_note_the_export_drops() -> crate::Result<()> {
    let member = entity_id(0x3F);
    let (_dir, vault, grant_id) = member_grant_vault(member);
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let note = vault
        .create_note(
            "research",
            "the private research",
            crate::WriteActor::new(owner, EdgeActorClass::Human),
        )
        .unwrap();
    let world = local_world_id(0x58).entity_id();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(&world, ENTITY_TYPE_WORLD, at, 1, b"world")?;
    vault
        .put_edge(&note, EdgeKind::InWorld, &world, 1.0)
        .unwrap();
    let learned = EntityMetadataHeader::parse(&vault.get_raw(&note)?.unwrap())
        .unwrap()
        .learned_at;
    let key = WindowKey::from_timestamp(learned);
    let summary = entity_id(0x6B);
    vault
        .batch()
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: learned,
                end: learned,
            },
            learned,
            &epoch_summary_bytes(1, "the run read the private research")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &note, 1.0)
        .commit()?;
    vault.with_write_txn_grouped(|txn| {
        crate::compaction::EpochPlacement::default().settle_in(&vault.store, txn, summary)
    })?;
    let doc = create_window_doc("source", &key);
    crate::sync::window::reverse_rematerialize(&vault, &doc, &key)?;
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    // The window also holds the grant's own rows, which no selector ships,
    // so the check reads the granted view a promotion compares with it.
    let granted = || -> crate::Result<Vec<EntityId>> {
        let granted = granted_window_doc(&vault, &doc, &key, test_selector_scope(), &selector)?;
        Ok(import_ids(
            &granted.export(ExportMode::all_updates()).unwrap(),
        ))
    };
    let exported = || -> crate::Result<Vec<EntityId>> {
        let filtered = filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &selector)?;
        Ok(import_ids(
            &filtered.export(ExportMode::all_updates()).unwrap(),
        ))
    };
    let portable = granted()?;
    assert!(portable.contains(&note) && portable.contains(&summary));
    crate::sync::window::test_hooks::arm_device_only_flag_race(world);
    let raced = exported()?;
    assert!(
        vault.world_is_device_only(world)?,
        "the flag landed mid-export"
    );
    assert_eq!(
        raced.contains(&summary),
        raced.contains(&note),
        "a summary never leaves without its source"
    );
    let promoted = granted()?;
    assert!(
        promoted.contains(&note) && promoted.contains(&summary),
        "the promotion's view keeps a NOTE of a device-only world"
    );
    let flagged = exported()?;
    assert!(!flagged.contains(&note) && !flagged.contains(&summary));
    Ok(())
}

/// Astra #1384d F1: an epoch summary that cannot prove where it was born is
/// unknown, never base, so it stays home while any world is device-only. A
/// replica reaches device B through a base window without the stamp and the
/// record that placed it on A, and without its edge to W's CLAIM, which lives
/// in W's window. A summary written from an unstamped replica stays home with
/// it, and deleting the replica records the unknown world on that summary. A
/// stamped base epoch of base records still leaves by every door.
#[test]
fn an_unplaced_epoch_summary_stays_home_while_a_world_is_device_only() -> crate::Result<()> {
    use crate::compaction::EpochPlacement;
    use crate::deletion::DeleteEntityOptions;
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let b_dir = tempfile::tempdir()?;
    let device_b = Vault::open(b_dir.path(), crate::VaultConfig::device())?;
    let world = local_world_id(0x58).entity_id();
    let (person, fact) = (entity_id(0x59), entity_id(0x60));
    let (replica, inner) = (entity_id(0x68), entity_id(0x69));
    let (outer, settled) = (entity_id(0x6a), entity_id(0x6c));
    let at = |month: &str| {
        let key = WindowKey::new(month);
        let at = key.start_timestamp().unwrap() + 60;
        (key, TimeRange { start: at, end: at }, at)
    };
    // W's rows and `inner` sit in September, apart from the windows checked.
    let (_, sources, sources_at) = at("2026-09");
    let (october, in_october, october_at) = at("2026-10");
    let (november, in_november, november_at) = at("2026-11");
    let (december, in_december, december_at) = at("2026-12");
    for device in [&vault, &device_b] {
        device.put_entity(&world, ENTITY_TYPE_WORLD, sources, sources_at, b"world")?;
    }
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        in_december,
        december_at,
        b"person",
    )?;
    let mut body = ClaimBody::new(
        "selector.world_fact",
        ClaimSubject::Entity(person),
        Value::from("the world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    vault.put_claim(&fact, &body, sources, sources_at)?;
    let summary = crate::registry::ENTITY_TYPE_SUMMARY;
    vault
        .batch()
        .put(
            &replica,
            summary,
            in_october,
            october_at,
            &epoch_summary_bytes(1, "the world fact")?,
        )
        .edge(&replica, EdgeKind::DerivedFrom, &fact, 1.0)
        // `inner` arrived through sync ingest's door, unstamped like any
        // replica; a local write is stamped as it lands.
        .put_replicated(
            &inner,
            summary,
            sources,
            sources_at,
            &epoch_summary_bytes(2, "the person")?,
        )
        .edge(&inner, EdgeKind::DerivedFrom, &person, 1.0)
        .put(
            &outer,
            summary,
            in_november,
            november_at,
            &epoch_summary_bytes(3, "the person again")?,
        )
        .edge(&outer, EdgeKind::DerivedFrom, &inner, 1.0)
        .put(
            &settled,
            summary,
            in_december,
            december_at,
            &epoch_summary_bytes(4, "the person, settled")?,
        )
        .edge(&settled, EdgeKind::DerivedFrom, &person, 1.0)
        .commit()?;
    // The local summaries are settled in base.
    vault.with_write_txn_grouped(|txn| {
        for base in [replica, outer, settled] {
            EpochPlacement::default().settle_in(&vault.store, txn, base)?;
        }
        Ok(())
    })?;

    let sent = packed_window(&vault, &october)?;
    crate::sync::window::forward_rematerialize(
        &device_b,
        &sent,
        &crate::sync::bridge::Materializer::new(),
        &october,
    )?;
    assert!(device_b.get_raw(&replica)?.is_some(), "B holds the replica");
    let on_b = packed_window(&device_b, &october)?;
    assert!(owner_window_ships(&device_b, &october, &on_b)?);
    device_b.keep_world_on_this_machine_for_test(world, true)?;
    assert!(
        !owner_window_ships(&device_b, &october, &on_b)?,
        "B's window door, a replica"
    );

    let (november_doc, december_doc) = (
        packed_window(&vault, &november)?,
        packed_window(&vault, &december)?,
    );
    assert!(owner_window_ships(&vault, &november, &november_doc)?);
    vault.keep_world_on_this_machine_for_test(world, true)?;
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, a summary of an unplaced epoch"
    );
    assert!(
        owner_window_ships(&vault, &december, &december_doc)?,
        "the window door, a stamped base epoch of base records"
    );
    let (selected, scoped) =
        selected_and_scoped(&vault, grant_id, member, &december, &december_doc)?;
    assert!(
        selected.contains(&settled) && scoped.contains(&settled),
        "a stamped base epoch of base records leaves"
    );
    vault.delete_entity_with_options(&inner, DeleteEntityOptions { purge: true })?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &outer)?,
        Some(crate::settings::CarriedWorlds {
            worlds: std::collections::BTreeSet::new(),
            unknown: true,
        }),
        "the deletion of an unplaced epoch"
    );
    drop(rtxn);
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, withdrawn by an unplaced epoch"
    );
    vault.keep_world_on_this_machine_for_test(world, false)?;
    assert!(owner_window_ships(&vault, &november, &november_doc)?);
    Ok(())
}

/// Astra #1384d F2: removing an epoch summary's `DerivedFrom` edge withdraws
/// it as deleting the source would, at the batch door, at the sync bridge's
/// edge-map removal and in a purge's edge sweep alike. W's CLAIM stays live
/// in W while the summary's body keeps its words: the summary is stale, its
/// record holds W, and with W flagged no door ships it.
#[test]
fn a_lost_source_edge_withdraws_an_epoch_summary() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let vault = Arc::new(vault);
    let (batched, bridged) = (entity_id(0x6d), entity_id(0x6e));
    let (october, november) = (WindowKey::new("2026-10"), WindowKey::new("2026-11"));
    let (world, fact) =
        summaries_of_a_world_fact(&vault, &[(batched, &october), (bridged, &november)])?;
    let (october_doc, november_doc) = (
        packed_window(&vault, &october)?,
        packed_window(&vault, &november)?,
    );
    // A purge's lexical-hint cascade deletes a hint CLAIM with no
    // invalidation of its own; the sweep of its edges withdraws a summary
    // written from it.
    let (person, hinted, claim) = (entity_id(0x59), entity_id(0x71), entity_id(0x72));
    let before = vault.entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?;
    vault
        .batch()
        .claim_candidate_with_lexical_hints(
            &claim,
            crate::write_envelope::ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(person),
                Value::from("sencha"),
                0.9,
            ),
            &crate::write_envelope::WriteEnvelope::new(
                crate::write_envelope::WriteActor::new(person, EdgeActorClass::Human),
                crate::claim::ClaimSource::UserStated,
                crate::write_envelope::WriteProvenance::new(Value::from("fixture"))?,
                ClaimApprovalStatus::Approved,
            ),
            TimeRange { start: 10, end: 10 },
            11,
            &["hintedwords"],
        )
        .commit()?;
    let hint = vault
        .entities_by_type(crate::registry::ENTITY_TYPE_CLAIM)?
        .into_iter()
        .find(|id| *id != claim && !before.contains(id))
        .expect("the hint CLAIM");
    let (during, learned) = {
        let at = WindowKey::new("2026-12").start_timestamp().unwrap() + 60;
        (TimeRange { start: at, end: at }, at)
    };
    vault
        .batch()
        .put(
            &hinted,
            crate::registry::ENTITY_TYPE_SUMMARY,
            during,
            learned,
            &epoch_summary_bytes(9, "sencha")?,
        )
        .edge(&hinted, EdgeKind::DerivedFrom, &hint, 1.0)
        .commit()?;
    vault.with_write_txn_grouped(|txn| {
        crate::compaction::EpochPlacement::default().settle_in(&vault.store, txn, hinted)
    })?;
    vault
        .delete_entity_with_options(&claim, crate::deletion::DeleteEntityOptions { purge: true })?;
    assert!(vault.get_raw(&hint)?.is_none(), "the cascade took the hint");
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        crate::ports::stale_in_txn(&vault.store, &rtxn, &hinted)?,
        "the purge's edge sweep: the summary is withdrawn"
    );
    drop(rtxn);
    vault
        .batch()
        .delete_edge(&batched, EdgeKind::DerivedFrom, &fact)
        .commit()?;
    // A base summary's edge to W's CLAIM lives in W's window; a peer's
    // removal there reaches this vault through the bridge.
    let learned = EntityMetadataHeader::parse(&vault.get_raw(&fact)?.unwrap())
        .unwrap()
        .learned_at;
    let in_world = WindowKey::for_world(learned, world);
    let world_doc = packed_window(&vault, &in_world)?;
    let edge = crate::sync::bridge::format_edge_key(&bridged, EdgeKind::DerivedFrom, &fact);
    assert!(map_get_bytes(&world_doc.get_map("edges"), &edge).is_some());
    let materializer = Arc::new(crate::sync::bridge::Materializer::new());
    let _observer = crate::sync::bridge::register_observer_b(
        &world_doc,
        &vault,
        &materializer,
        in_world.as_str(),
    );
    crate::sync::loro_support::map_delete(&world_doc.get_map("edges"), &edge)?;
    world_doc.commit();
    assert!(
        !vault.edge_exists(&bridged, EdgeKind::DerivedFrom, &fact)?,
        "the bridge applied the peer's removal"
    );
    let rtxn = vault.store.env.read_txn()?;
    for (summary, door) in [(batched, "the batch door"), (bridged, "the sync bridge")] {
        assert!(
            crate::ports::stale_in_txn(&vault.store, &rtxn, &summary)?,
            "{door}: the summary is withdrawn"
        );
        assert_eq!(
            crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &summary)?
                .map(|withdrawn| withdrawn.worlds),
            Some(std::collections::BTreeSet::from([world])),
            "{door}: its record holds W"
        );
    }
    drop(rtxn);
    // A regeneration from W's CLAIM completes only once the summary's edges
    // name it again: export doors read those (Sol round 19).
    let regenerate = |summary: EntityId, source: EntityId, at: u64| -> crate::Result<bool> {
        let source_at = EntityMetadataHeader::parse(&vault.get_raw(&source)?.unwrap())
            .unwrap()
            .learned_at;
        vault
            .batch()
            .put(
                &summary,
                crate::registry::ENTITY_TYPE_SUMMARY,
                TimeRange { start: at, end: at },
                at,
                &epoch_summary_bytes(1, "the fact, again")?,
            )
            .commit()?;
        vault.with_write_txn(|txn| {
            crate::ports::DependencyIndex::port_dependency_complete_regeneration(
                &*vault,
                txn,
                &summary,
                at,
                &[crate::ports::SourceSpan {
                    document: source,
                    frontier: source_at,
                }],
            )
        })
    };
    let rewritten = october.start_timestamp().unwrap() + 120;
    assert!(
        !regenerate(batched, fact, rewritten)?,
        "a regeneration the graph does not name ends nothing"
    );
    // An edge the regeneration does not declare would lose the dependency
    // row that withdraws the summary when that source is erased (Sol round
    // 20); it goes through the batch door first.
    vault
        .batch()
        .edge(&batched, EdgeKind::DerivedFrom, &fact, 1.0)
        .edge(&batched, EdgeKind::DerivedFrom, &person, 1.0)
        .commit()?;
    assert!(
        !regenerate(batched, fact, rewritten + 60)?,
        "a regeneration that leaves a named source undeclared ends nothing"
    );
    vault
        .batch()
        .delete_edge(&batched, EdgeKind::DerivedFrom, &person)
        .commit()?;
    assert!(regenerate(batched, fact, rewritten + 120)?);
    // A regeneration from a base PERSON alone still keeps W: the summary's
    // old words sit in the November snapshot packed before any of this,
    // which a door judges by the current row (Sol round 20).
    vault
        .batch()
        .edge(&bridged, EdgeKind::DerivedFrom, &person, 1.0)
        .commit()?;
    assert!(regenerate(
        bridged,
        person,
        november.start_timestamp().unwrap() + 120
    )?);
    let rtxn = vault.store.env.read_txn()?;
    assert!(!crate::ports::stale_in_txn(&vault.store, &rtxn, &bridged)?);
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &bridged)?
            .map(|withdrawn| withdrawn.worlds),
        Some(std::collections::BTreeSet::from([world])),
        "a regeneration keeps what the summary was withdrawn for"
    );
    drop(rtxn);
    let ships = |shipped: bool| -> crate::Result<()> {
        assert_eq!(
            owner_window_ships(&vault, &october, &october_doc)?,
            shipped,
            "the window door, the batch removal"
        );
        assert_eq!(
            owner_window_ships(&vault, &november, &november_doc)?,
            shipped,
            "the window door, the bridge removal"
        );
        Ok(())
    };
    ships(true)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    ships(false)?;
    let (selected, scoped) = selected_and_scoped(&vault, grant_id, member, &october, &october_doc)?;
    assert!(!selected.contains(&batched), "the selector");
    assert!(
        !scoped.contains(&batched) && !scoped.contains(&bridged),
        "the scoped export"
    );
    // A soft erase leaves the regenerated summary's old words in November's
    // packed window; its shell keeps W (Sol round 21).
    vault.delete_entity(&bridged)?;
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "a soft erase keeps a regenerated summary's old words home"
    );
    Ok(())
}

/// Sol round 21: an epoch summary rewritten in place into a SUMMARY body that
/// is no epoch stops every walk at it, while a summary written from it still
/// holds W's words. The rewrite records the worlds the old body carried, so
/// the nested summary stays home while W is flagged.
#[test]
fn a_summary_of_a_summary_rewritten_as_no_epoch_keeps_its_world() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let (source, nested) = (entity_id(0x73), entity_id(0x74));
    let (october, november) = (WindowKey::new("2026-10"), WindowKey::new("2026-11"));
    let world = summary_of_a_summary(&vault, source, &october, nested, &november)?;
    let november_doc = packed_window(&vault, &november)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    assert!(!owner_window_ships(&vault, &november, &november_doc)?);
    let rewritten = october.start_timestamp().unwrap() + 120;
    vault
        .batch()
        .put(
            &source,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: rewritten,
                end: rewritten,
            },
            rewritten,
            b"a summary written by hand",
        )
        .commit()?;
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, a summary of a summary rewritten as no epoch"
    );
    let (selected, scoped) =
        selected_and_scoped(&vault, grant_id, member, &november, &november_doc)?;
    assert!(
        !selected.contains(&nested) && !scoped.contains(&nested),
        "the selector and the scoped export"
    );
    Ok(())
}

/// Wonder P2-1: an epoch summary rewritten in place into a SUMMARY body that
/// is no epoch no longer says what a summary written from it copied. That
/// summary is withdrawn, so a base-only read, the scoped export and a Base
/// selector take it no more than they took it before the rewrite.
#[test]
fn a_summary_of_a_summary_rewritten_as_no_epoch_is_withdrawn() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let (source, nested) = (entity_id(0x7b), entity_id(0x7c));
    let (october, november) = (WindowKey::new("2026-10"), WindowKey::new("2026-11"));
    summary_of_a_summary(&vault, source, &october, nested, &november)?;
    let rewritten = october.start_timestamp().unwrap() + 120;
    vault
        .batch()
        .put(
            &source,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: rewritten,
                end: rewritten,
            },
            rewritten,
            b"a summary written by hand",
        )
        .commit()?;
    let mut base_only = crate::federation::Scope::top();
    base_only.worlds = ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(
        crate::claim::base_world_id(),
    )]));
    let top = crate::federation::Scope::top();
    let exported = vault.export_records_in_scope(&base_only, &top, &top)?;
    assert!(
        !exported.iter().any(|record| record.id == nested),
        "the scoped export, a summary of a summary rewritten as no epoch"
    );
    let read = vault.records_in_scope(
        &base_only,
        &top,
        &top,
        crate::federation::record_scope::ScopeView::Normal,
    )?;
    assert!(
        !read.iter().any(|record| record.id == nested),
        "a base-only read, a summary of a summary rewritten as no epoch"
    );
    let november_doc = packed_window(&vault, &november)?;
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::Base, vec![], vec![]);
    let selected = filtered_window_doc(
        &vault,
        &november_doc,
        &november,
        test_selector_scope(),
        &selector,
    )?;
    assert!(
        !import_ids(&selected.export(ExportMode::all_updates()).unwrap()).contains(&nested),
        "a Base selector, a summary of a summary rewritten as no epoch"
    );
    Ok(())
}

/// Sol round 23: an owner's move of an epoch summary's text to the document
/// plane leaves a pointer body. The summary is still an epoch to every reader
/// (Astra 1384e), and the move records the worlds the old body carried, so a
/// summary written from it stays home while W is flagged. Without that record
/// (a move made before it existed) its sources still hold it.
#[test]
fn a_summary_of_a_summary_moved_to_the_text_plane_keeps_its_world() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), crate::VaultConfig::device())?;
    let (source, nested) = (entity_id(0x75), entity_id(0x76));
    let (october, november) = (WindowKey::new("2026-10"), WindowKey::new("2026-11"));
    let world = summary_of_a_summary(&vault, source, &october, nested, &november)?;
    let november_doc = packed_window(&vault, &november)?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    assert!(!owner_window_ships(&vault, &november, &november_doc)?);
    move_text_to_document_plane(&vault, &source)?;
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, a summary of a summary moved to the text plane"
    );
    vault
        .with_write_txn(|txn| crate::ports::retire_withdrawn_in_txn(&vault.store, txn, &source))?;
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, the sources of a summary on the text plane"
    );
    Ok(())
}

/// Astra 1384e: an epoch summary whose text moved to the document plane
/// reaches a vault that never held it through canonical recovery, as a
/// pointer with no birth stamp and no record of what it carried. A summary
/// minted there from it ships while no world is flagged. Once W is, the
/// window door holds it in a window packed before, packing leaves it out,
/// and the door still holds it once no head stands for the pointer.
#[test]
fn a_summary_of_a_recovered_summary_on_the_text_plane_stays_home() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let source = entity_id(0x77);
    let (restored, world, _) = recovered_summary_on_the_text_plane(dir.path(), source)?;
    let (nested, november) = (entity_id(0x78), WindowKey::new("2026-11"));
    nested_summary(&restored, source, nested, &november)?;
    let november_doc = packed_window(&restored, &november)?;
    assert!(
        owner_window_ships(&restored, &november, &november_doc)?,
        "no world flagged: a summary of a recovered summary ships"
    );
    restored.keep_world_on_this_machine_for_test(world, true)?;
    assert!(
        !owner_window_ships(&restored, &november, &november_doc)?,
        "the window door, a summary of a recovered summary on the text plane"
    );
    let fresh = packed_window(&restored, &november)?;
    assert!(
        map_get_bytes(&fresh.get_map("entities"), &nested.to_hex()).is_none(),
        "packing, a summary of a recovered summary on the text plane"
    );
    restored
        .with_write_txn(|txn| crate::entity_doc::erase_in_txn(&restored.store, txn, &source))?;
    assert!(
        !owner_window_ships(&restored, &november, &november_doc)?,
        "the window door, a summary of a pointer no head stands for"
    );
    Ok(())
}

/// Astra 1384f: a pointer row decides an epoch's shape and its head only
/// completes it. A second recovery that names another field for the
/// recovered summary's document leaves the row as it was, and a summary
/// minted from it afterwards still stays home while W is flagged.
#[test]
fn a_recovered_summary_stays_an_epoch_whatever_field_its_head_names() -> crate::Result<()> {
    let dir = tempfile::tempdir()?;
    let source = entity_id(0x79);
    let (restored, world, snapshot) = recovered_summary_on_the_text_plane(dir.path(), source)?;
    let mut retitled = snapshot;
    retitled
        .entity_documents
        .iter_mut()
        .find(|document| document.entity_id == *source.as_bytes())
        .expect("the summary's document")
        .field = Some("title".into());
    crate::recovery::recover_vault_window(
        &restored,
        &crate::sync::bridge::Materializer::new(),
        dir.path().join("manifest-retitled"),
        &retitled,
        crate::recovery::RecoveryBudget::default(),
    )?;
    let (nested, november) = (entity_id(0x7a), WindowKey::new("2026-11"));
    nested_summary(&restored, source, nested, &november)?;
    let november_doc = packed_window(&restored, &november)?;
    restored.keep_world_on_this_machine_for_test(world, true)?;
    assert!(
        !owner_window_ships(&restored, &november, &november_doc)?,
        "the window door, a summary of a recovered summary its head names as titled"
    );
    let fresh = packed_window(&restored, &november)?;
    assert!(
        map_get_bytes(&fresh.get_map("entities"), &nested.to_hex()).is_none(),
        "packing, a summary of a recovered summary its head names as titled"
    );
    Ok(())
}

/// A vault at `dir` that never held epoch summary `source` of W's CLAIM,
/// holding W's WORLD row and `source` recovered from a canonical October
/// window captured after its text moved to the document plane. Returns it,
/// W and that snapshot.
fn recovered_summary_on_the_text_plane(
    dir: &std::path::Path,
    source: EntityId,
) -> crate::Result<(Vault, EntityId, crate::recovery::CanonicalSnapshot)> {
    let origin_dir = tempfile::tempdir()?;
    let origin = Vault::open_owned(origin_dir.path(), crate::VaultConfig::device())?;
    let october = WindowKey::new("2026-10");
    let (world, _) = summaries_of_a_world_fact(&origin, &[(source, &october)])?;
    move_text_to_document_plane(&origin, &source)?;
    let snapshot = crate::recovery::capture_canonical_window(
        &origin,
        "2026-10",
        &packed_window(&origin, &october)?,
    )?;
    let restored = Vault::open_owned(dir, crate::VaultConfig::device())?;
    let at = WindowKey::new("2026-09").start_timestamp().unwrap() + 60;
    let during = TimeRange { start: at, end: at };
    restored.put_entity(&world, ENTITY_TYPE_WORLD, during, at, b"world")?;
    crate::recovery::recover_vault_window(
        &restored,
        &crate::sync::bridge::Materializer::new(),
        dir.join("manifest"),
        &snapshot,
        crate::recovery::RecoveryBudget::default(),
    )?;
    assert_eq!(restored.entity_text(&source)?, "the world fact");
    Ok((restored, world, snapshot))
}

/// The owner moves the text of `id` to the document plane.
fn move_text_to_document_plane(vault: &Vault, id: &EntityId) -> crate::Result<()> {
    use crate::entity_doc::{DocAuthorization, TextField};
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let authority = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.migrate_entity_text(
        id,
        &TextField::MapField("text".into()),
        crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human),
        &DocAuthorization::Owner(&authority),
    )
}

/// An epoch summary `source` of W's CLAIM settled in base in `at`, and an
/// epoch summary `nested` written from it settled in base in `nested_at`;
/// returns W.
fn summary_of_a_summary(
    vault: &Vault,
    source: EntityId,
    at: &WindowKey,
    nested: EntityId,
    nested_at: &WindowKey,
) -> crate::Result<EntityId> {
    let (world, _) = summaries_of_a_world_fact(vault, &[(source, at)])?;
    nested_summary(vault, source, nested, nested_at)?;
    Ok(world)
}

/// An epoch summary `nested` written from `source`, settled in base in `at`.
fn nested_summary(
    vault: &Vault,
    source: EntityId,
    nested: EntityId,
    at: &WindowKey,
) -> crate::Result<()> {
    let learned = at.start_timestamp().unwrap() + 60;
    vault
        .batch()
        .put(
            &nested,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange {
                start: learned,
                end: learned,
            },
            learned,
            &epoch_summary_bytes(2, "the world fact, again")?,
        )
        .edge(&nested, EdgeKind::DerivedFrom, &source, 1.0)
        .commit()?;
    vault.with_write_txn_grouped(|txn| {
        crate::compaction::EpochPlacement::default().settle_in(&vault.store, txn, nested)
    })
}

/// Astra #1384d F3: what an epoch summary was withdrawn for lives as long as
/// its words. A standalone tombstone invalidates the summary and keeps the
/// body, so the record stays and the summary stays home while W is flagged.
/// A purge leaves the words in window history, so the record stays until the
/// historical sweep has rewritten it (Sol round 21).
#[test]
fn a_tombstone_that_keeps_a_summary_body_keeps_its_withdrawal_record() -> crate::Result<()> {
    use crate::deletion::DeleteEntityOptions;
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x32));
    let (kept, purged) = (entity_id(0x6f), entity_id(0x70));
    let (october, november) = (WindowKey::new("2026-10"), WindowKey::new("2026-11"));
    let (world, fact) =
        summaries_of_a_world_fact(&vault, &[(kept, &october), (purged, &november)])?;
    let (october_doc, november_doc) = (
        packed_window(&vault, &october)?,
        packed_window(&vault, &november)?,
    );
    let purge = DeleteEntityOptions { purge: true };
    vault.delete_entity_with_options(&fact, purge)?;
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserDelete,
        deleted_at: 5,
        request_id: [7; 16],
    };
    vault.with_write_txn(|txn| {
        crate::ports::TombstoneStore::port_tombstone_create(&vault, txn, &kept, tombstone)
    })?;
    vault.delete_entity_with_options(&purged, purge)?;
    let rtxn = vault.store.env.read_txn()?;
    assert!(vault.get_raw_in(&rtxn, &kept)?.is_some());
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &kept)?
            .map(|withdrawn| withdrawn.worlds),
        Some(std::collections::BTreeSet::from([world])),
        "a tombstone that keeps the body keeps the record"
    );
    assert!(vault.get_raw_in(&rtxn, &purged)?.is_none());
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &purged)?
            .map(|withdrawn| withdrawn.worlds),
        Some(std::collections::BTreeSet::from([world])),
        "a purge keeps the record while its words sit in window history"
    );
    drop(rtxn);
    assert!(owner_window_ships(&vault, &october, &october_doc)?);
    assert!(owner_window_ships(&vault, &november, &november_doc)?);
    vault.keep_world_on_this_machine_for_test(world, true)?;
    assert!(
        !owner_window_ships(&vault, &october, &october_doc)?,
        "the window door, a tombstoned summary"
    );
    assert!(
        !owner_window_ships(&vault, &november, &november_doc)?,
        "the window door, a purged summary's words in history"
    );
    crate::sweep::run_hard_erase_sweep(&vault)?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &purged)?,
        None,
        "the historical sweep retires the record with the words"
    );
    Ok(())
}

/// Sol round 19: a first deletion reads where a row's words sat whatever its
/// body holds, since its marker is written before the purge. A WORLD with an
/// empty body still carries its own world: purging it records that world on
/// a summary written from it, and a window packed after the purge, which no
/// longer names the WORLD, never ships the summary while it is flagged.
#[test]
fn a_first_purge_of_an_empty_world_records_it_on_its_summary() -> crate::Result<()> {
    use crate::deletion::DeleteEntityOptions;
    let (_dir, vault, _) = test_vault_with_grant(entity_id(0x32));
    let world = local_world_id(0x5b).entity_id();
    let summary = entity_id(0x73);
    let at = |key: &WindowKey| {
        let at = key.start_timestamp().unwrap() + 60;
        (TimeRange { start: at, end: at }, at)
    };
    let october = WindowKey::new("2026-10");
    let (sources, sources_at) = at(&WindowKey::new("2026-09"));
    let (during, learned) = at(&october);
    vault.put_entity(&world, ENTITY_TYPE_WORLD, sources, sources_at, b"")?;
    vault
        .batch()
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            during,
            learned,
            &epoch_summary_bytes(1, "the world")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &world, 1.0)
        .commit()?;
    vault.with_write_txn_grouped(|txn| {
        crate::compaction::EpochPlacement::default().settle_in(&vault.store, txn, summary)
    })?;
    vault.keep_world_on_this_machine_for_test(world, true)?;
    vault.delete_entity_with_options(&world, DeleteEntityOptions { purge: true })?;
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        crate::ports::withdrawn_worlds_in(&vault.store, &rtxn, &summary)?
            .map(|withdrawn| withdrawn.worlds),
        Some(std::collections::BTreeSet::from([world])),
        "a first purge of an empty WORLD"
    );
    drop(rtxn);
    // Packing leaves out what a flag keeps, so a window packed now never
    // ships the summary, carried or not.
    let fresh = packed_window(&vault, &october)?;
    let carried = map_get_bytes(&fresh.get_map("entities"), &summary.to_hex()).is_some();
    assert!(
        !carried || !owner_window_ships(&vault, &october, &fresh)?,
        "a window packed after the purge never ships the summary"
    );
    Ok(())
}

/// W's CLAIM about a PERSON, beside the WORLD row in September, apart from
/// the windows checked, and one epoch summary of it settled in base in each
/// given window. Returns W and the CLAIM.
fn summaries_of_a_world_fact(
    vault: &Vault,
    summaries: &[(EntityId, &WindowKey)],
) -> crate::Result<(EntityId, EntityId)> {
    let world = local_world_id(0x58).entity_id();
    let (person, fact) = (entity_id(0x59), entity_id(0x60));
    let at = |key: &WindowKey| {
        let at = key.start_timestamp().unwrap() + 60;
        (TimeRange { start: at, end: at }, at)
    };
    let (sources, sources_at) = at(&WindowKey::new("2026-09"));
    vault.put_entity(&world, ENTITY_TYPE_WORLD, sources, sources_at, b"world")?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, sources, sources_at, b"person")?;
    let mut body = ClaimBody::new(
        "selector.world_fact",
        ClaimSubject::Entity(person),
        Value::from("the world fact"),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    body.world = Some(world);
    vault.put_claim(&fact, &body, sources, sources_at)?;
    for (epoch, &(summary, key)) in (1..).zip(summaries) {
        let (during, learned) = at(key);
        vault
            .batch()
            .put(
                &summary,
                crate::registry::ENTITY_TYPE_SUMMARY,
                during,
                learned,
                &epoch_summary_bytes(epoch, "the world fact")?,
            )
            .edge(&summary, EdgeKind::DerivedFrom, &fact, 1.0)
            .commit()?;
        vault.with_write_txn_grouped(|txn| {
            crate::compaction::EpochPlacement::default().settle_in(&vault.store, txn, summary)
        })?;
    }
    Ok((world, fact))
}

fn packed_window(vault: &Vault, key: &WindowKey) -> crate::Result<LoroDoc> {
    let doc = create_window_doc("source", key);
    crate::sync::window::reverse_rematerialize(vault, &doc, key)?;
    Ok(doc)
}

fn owner_window_ships(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> crate::Result<bool> {
    Ok(!crate::sync::window::export_withheld(
        vault,
        key,
        doc,
        &loro::VersionVector::default(),
    )?)
}

/// The ids an all-world selector ships from `doc`, and the ids the scoped
/// record export ships.
fn selected_and_scoped(
    vault: &Vault,
    grant: EntityId,
    member: EntityId,
    key: &WindowKey,
    doc: &LoroDoc,
) -> crate::Result<(Vec<EntityId>, Vec<EntityId>)> {
    let selector = SyncSelector::new(grant, member, SyncSelectorWorld::All, vec![], vec![]);
    let selected = filtered_window_doc(vault, doc, key, test_selector_scope(), &selector)?;
    let top = crate::federation::Scope::top();
    Ok((
        import_ids(&selected.export(ExportMode::all_updates()).unwrap()),
        vault
            .export_records_in_scope(&top, &top, &top)?
            .into_iter()
            .map(|record| record.id)
            .collect(),
    ))
}

fn epoch_summary_bytes(epoch: u64, text: &str) -> crate::Result<Vec<u8>> {
    use crate::compaction::{
        EPOCH_SUMMARY_BODY_VERSION, EPOCH_SUMMARY_LEVEL, EpochSummaryBody,
        encode_epoch_summary_body,
    };
    encode_epoch_summary_body(&EpochSummaryBody {
        v: EPOCH_SUMMARY_BODY_VERSION,
        session: entity_id(0x7e).to_hex(),
        epoch,
        turn_start: epoch * 3,
        turn_end: epoch * 3 + 2,
        level: EPOCH_SUMMARY_LEVEL,
        text: text.into(),
        actor: entity_id(0x7f).to_hex(),
    })
}

/// Astra #1384b P2-1: a summary's settled facet binds the export. A
/// vault-wide run summarized a step faceted F; the summary is born under
/// the vault's default facet. A peer whose pact ceiling is F gets the step,
/// never the summary riding its `DerivedFrom` edge to it.
#[test]
fn an_epoch_summary_leaves_only_where_its_settled_facet_is_selected() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let shared = entity_id(0x76);
    let (step, summary) = (entity_id(0x77), entity_id(0x78));
    let key = WindowKey::new("2026-03");
    let at = key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(&shared, ENTITY_TYPE_FACET, occurred, at, b"shared")?;
    vault
        .batch()
        .put(&step, ENTITY_TYPE_EVENT, occurred, at, b"the shared step")
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(1, "the run took the shared step")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &step, 1.0)
        .commit()?;
    vault
        .batch()
        .edge(&step, EdgeKind::FacetOf, &shared, 1.0)
        .commit()?;
    // A vault-wide run's summary: base reality, the vault's default facet.
    let placement = crate::compaction::EpochPlacement::default();
    vault.with_write_txn_grouped(|txn| placement.settle_in(&vault.store, txn, summary))?;
    assert_ne!(vault.default_facet()?, shared);
    seed_scoped_pacts_for_grant(
        &vault,
        grant_id,
        &[FederationDirectionScope {
            worlds: ScopeAxis::All,
            facets: ScopeAxis::from_iter([ScopeId(shared)]),
            bands: ScopeAxis::All,
        }],
    );
    let doc = create_window_doc("source", &key);
    crate::sync::window::reverse_rematerialize(&vault, &doc, &key)?;
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::Base, vec![], vec![]);
    let sent = import_ids(
        &filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &selector)?
            .export(ExportMode::all_updates())
            .unwrap(),
    );
    assert!(sent.contains(&step), "the faceted step is selected");
    assert!(
        !sent.contains(&summary),
        "a summary born under another facet stays out of the pact ceiling"
    );
    Ok(())
}

/// Astra #1384b P2-2: the fence judges a source by the export that carries
/// it. Person R, learned in January, is selected only through February's
/// faceted event, which January's window does not hold, so no window
/// exports R. The February summary written from R stays home with it.
#[test]
fn an_epoch_summary_stays_home_when_no_window_exports_its_source() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let facet = entity_id(0x79);
    let (person, event, summary) = (entity_id(0x7a), entity_id(0x7b), entity_id(0x7c));
    let (january, february) = (WindowKey::new("2026-01"), WindowKey::new("2026-02"));
    let jan = january.start_timestamp().unwrap() + 60;
    let feb = february.start_timestamp().unwrap() + 60;
    let at = |second| TimeRange {
        start: second,
        end: second,
    };
    vault.put_entity(&facet, ENTITY_TYPE_FACET, at(jan), jan, b"facet")?;
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        at(jan),
        jan,
        b"the private sentence",
    )?;
    vault
        .batch()
        .put(
            &event,
            ENTITY_TYPE_EVENT,
            at(feb),
            feb,
            b"the faceted event",
        )
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            at(feb),
            feb,
            &epoch_summary_bytes(1, "the run read the private sentence")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &person, 1.0)
        .edge(&summary, EdgeKind::DerivedFrom, &event, 1.0)
        .commit()?;
    vault
        .batch()
        .edge(&event, EdgeKind::FacetOf, &facet, 1.0)
        .edge(&person, EdgeKind::Mentions, &event, 1.0)
        .commit()?;
    // Born under the requested facet: its own position is selected.
    let placement = crate::compaction::EpochPlacement {
        world: None,
        facet: Some(facet),
    };
    vault.with_write_txn_grouped(|txn| placement.settle_in(&vault.store, txn, summary))?;
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::Base,
        vec![facet],
        vec![],
    );
    let mut sent = Vec::new();
    for key in [&january, &february] {
        let doc = create_window_doc("source", key);
        crate::sync::window::reverse_rematerialize(&vault, &doc, key)?;
        sent.extend(import_ids(
            &filtered_window_doc(&vault, &doc, key, test_selector_scope(), &selector)?
                .export(ExportMode::all_updates())
                .unwrap(),
        ));
    }
    assert!(sent.contains(&event), "the faceted event is selected");
    assert!(!sent.contains(&person), "no window exports the person");
    assert!(
        !sent.contains(&summary),
        "the summary stays home with a source no window exports"
    );
    Ok(())
}

/// Sol round 8 on #1384: a machine CLAIM leaves only with its whole signed
/// history in its own window. A claim learned in January and retracted in
/// February has history rows in both months, so neither window exports it,
/// and the February summary written from it stays home too.
#[test]
fn an_epoch_summary_stays_home_when_its_source_history_spans_windows() -> crate::Result<()> {
    use crate::write_envelope::{
        ClaimCandidate, MachineWriteSignature, WriteActor, WriteEnvelope, WriteProvenance,
    };
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let (machine, claim, summary) = (entity_id(0xc1), entity_id(0xc2), entity_id(0xc3));
    let person = entity_id(0xc4);
    let (january, february) = (WindowKey::new("2026-01"), WindowKey::new("2026-02"));
    let jan = january.start_timestamp().unwrap() + 60;
    let feb = february.start_timestamp().unwrap() + 60;
    let at = |second| TimeRange {
        start: second,
        end: second,
    };
    vault.put_entity(
        &machine,
        crate::registry::ENTITY_TYPE_MACHINE,
        at(jan),
        jan,
        b"machine",
    )?;
    let issuer = crate::authority::HostSlipIssuer::from_secret(b"selector machine root").unwrap();
    vault.ensure_host_root_slip(&issuer)?;
    let signing = SigningKey::from_bytes(&[0xc1; 32]);
    vault.enroll_machine_identity(
        &issuer,
        machine,
        signing.verifying_key().to_bytes(),
        [8; 32],
        |transcript| Ok(signing.sign(transcript).to_bytes()),
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(Value::from("machine")).unwrap(),
        ClaimApprovalStatus::Proposed,
    );
    let candidate = ClaimCandidate::new(
        "selector.machine",
        ClaimSubject::Entity(machine),
        Value::from("the machine's private fact"),
        1.0,
    );
    let transcript = vault.machine_claim_transcript(&claim, &candidate, &envelope)?;
    let signed = envelope.with_machine_signature(MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    });
    vault
        .batch()
        .claim_candidate(&claim, candidate, &signed, at(jan), jan)
        .commit()?;
    vault
        .batch()
        .put(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            at(feb),
            feb,
            &epoch_summary_bytes(1, "the run read the machine's private fact")?,
        )
        .edge(&summary, EdgeKind::DerivedFrom, &claim, 1.0)
        .commit()?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, at(feb), feb, b"person")?;
    // The retraction's signed transition and handoff are February's rows.
    vault.retract_claim(&claim, feb)?;
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::Base, vec![], vec![]);
    let mut sent = Vec::new();
    for key in [&january, &february] {
        let doc = create_window_doc("source", key);
        crate::sync::window::reverse_rematerialize(&vault, &doc, key)?;
        sent.extend(import_ids(
            &filtered_window_doc(&vault, &doc, key, test_selector_scope(), &selector)?
                .export(ExportMode::all_updates())
                .unwrap(),
        ));
    }
    assert!(sent.contains(&person), "the selector exports");
    assert!(
        !sent.contains(&claim),
        "no window carries the claim's history whole"
    );
    assert!(
        !sent.contains(&summary),
        "the summary stays home with a source whose history no window carries"
    );
    Ok(())
}

/// Sol rounds 10 to 12 on #1384: a summary leaves only beside the records
/// it was written from, not beside what a peer put at their ids. In one base
/// window a peer's CLAIM wins the carrier of a nested epoch whose source is a
/// CLAIM in private world W, of a nested epoch born in W, and of a CLAIM in W
/// itself, and a peer's garbled copy wins the carrier of a summary of a CLAIM
/// in W. The vault refused each write, so the stored records stand, and no
/// summary written from them leaves through a Base export.
#[test]
fn an_epoch_summary_stays_home_when_a_peer_rewrote_a_source_carrier() -> crate::Result<()> {
    let member = entity_id(0x32);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let world = local_world_id(0x5d);
    let (person, claim, moved) = (entity_id(0xd1), entity_id(0xd2), entity_id(0xd9));
    let (nested, outer) = (entity_id(0xd3), entity_id(0xd4));
    let (born_in_w, over) = (entity_id(0xd5), entity_id(0xd6));
    let (from_moved, garbled) = (entity_id(0xd8), entity_id(0xda));
    let key = WindowKey::new("2026-03");
    let at = key.start_timestamp().unwrap() + 60;
    let occurred = TimeRange { start: at, end: at };
    vault.put_entity(
        &world.entity_id(),
        ENTITY_TYPE_WORLD,
        occurred,
        at,
        b"world",
    )?;
    vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, at, b"person")?;
    for (id, fact) in [
        (claim, "the private world fact"),
        (moved, "the other private world fact"),
    ] {
        let mut body = ClaimBody::new(
            "selector.private_fact",
            ClaimSubject::Entity(person),
            Value::from(fact),
            1.0,
            ClaimApprovalStatus::Proposed,
            ClaimLifecycleStatus::Active,
        )
        .unwrap();
        body.world = Some(world.entity_id());
        vault.put_claim(&id, &body, occurred, at)?;
    }
    vault
        .batch()
        .put(
            &nested,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(1, "the run learned the private world fact")?,
        )
        .edge(&nested, EdgeKind::DerivedFrom, &claim, 1.0)
        .put(
            &outer,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(2, "the run repeated what it learned")?,
        )
        .edge(&outer, EdgeKind::DerivedFrom, &nested, 1.0)
        .put(
            &born_in_w,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(3, "the run met the person in its world")?,
        )
        .edge(&born_in_w, EdgeKind::DerivedFrom, &person, 1.0)
        .put(
            &over,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(4, "the run recalled its world")?,
        )
        .edge(&over, EdgeKind::DerivedFrom, &born_in_w, 1.0)
        .put(
            &from_moved,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(5, "the run learned the other private world fact")?,
        )
        .edge(&from_moved, EdgeKind::DerivedFrom, &moved, 1.0)
        .put(
            &garbled,
            crate::registry::ENTITY_TYPE_SUMMARY,
            occurred,
            at,
            &epoch_summary_bytes(6, "the run repeated the private world fact")?,
        )
        .edge(&garbled, EdgeKind::DerivedFrom, &claim, 1.0)
        .commit()?;
    let placement = crate::compaction::EpochPlacement {
        world: Some(world.entity_id()),
        facet: None,
    };
    vault.with_write_txn_grouped(|txn| placement.settle_in(&vault.store, txn, born_in_w))?;
    let doc = create_window_doc("source", &key);
    crate::sync::window::reverse_rematerialize(&vault, &doc, &key)?;
    for id in [nested, born_in_w, moved] {
        insert_blob(&doc, id, &claim_blob(None));
    }
    // The summary's own bytes with one trailing byte: no longer an epoch body,
    // still its words.
    let mut copy = vault.get_raw_unsealed(&garbled)?.expect("a stored summary");
    copy.push(0xc0);
    insert_blob(&doc, garbled, &copy);
    doc.commit();
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::Base, vec![], vec![]);
    let sent = import_ids(
        &filtered_window_doc(&vault, &doc, &key, test_selector_scope(), &selector)?
            .export(ExportMode::all_updates())
            .unwrap(),
    );
    assert!(sent.contains(&person), "the selector exports");
    let left = [
        (outer, "outer"),
        (over, "over"),
        (from_moved, "from_moved"),
        (garbled, "garbled"),
    ]
    .into_iter()
    .filter(|(id, _)| sent.contains(id))
    .map(|(_, name)| name)
    .collect::<Vec<_>>();
    assert!(
        left.is_empty(),
        "summaries left beside a peer's carrier, not their sources: {left:?}"
    );
    Ok(())
}

/// A TASK a writer creates through the host-bound `Memory` door, born in
/// `world` when one is bound.
fn mint_board_task(vault: &Vault, world: Option<EntityId>) -> EntityId {
    let writer = EntityId::now();
    vault
        .put_entity(
            &writer,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"writer",
        )
        .unwrap();
    vault
        .memory(writer, EdgeActorClass::Human)
        .with_birth_position(crate::federation::record_scope::BirthPosition { world, facet: None })
        .tasks_create(&crate::task_verb::TaskCreateSpec::new(
            Value::from("board work"),
            None,
            None,
            Some(100),
        ))
        .unwrap()
        .task_ref
        .unwrap()
}

/// ARCH-0067 §5: a TASK a world-narrowed writer creates is born in that world,
/// and a world row travels only where a CLAIM in that world would — under its
/// own world or `All`, and its authority facts with it. A grant that would
/// carry every world does not lift a base-only pact or selector, nor carry the
/// row to another world's peer. A base TASK travels under every selector.
#[test]
fn a_world_born_task_travels_only_under_its_own_world() {
    let member = entity_id(0x3E);
    let world = local_world_id(0x53);
    let other_world = local_world_id(0x54);
    let window_key = WindowKey::new("2026-12");
    for (name, selector_world, pact_worlds, born_travels) in [
        ("base selector", SyncSelectorWorld::Base, None, false),
        (
            "base-only pact",
            SyncSelectorWorld::Base,
            Some(crate::federation::base_world_axis()),
            false,
        ),
        (
            "another world",
            SyncSelectorWorld::World(other_world),
            None,
            false,
        ),
        ("its own world", SyncSelectorWorld::World(world), None, true),
        ("every world", SyncSelectorWorld::All, None, true),
    ] {
        let (_dir, vault, grant_id) = test_vault_with_grant(member);
        if let Some(worlds) = pact_worlds {
            seed_scoped_pacts_for_grant(
                &vault,
                grant_id,
                &[FederationDirectionScope {
                    worlds,
                    facets: ScopeAxis::All,
                    bands: ScopeAxis::All,
                }],
            );
        }
        let born = mint_board_task(&vault, Some(world.entity_id()));
        let base = mint_board_task(&vault, None);
        // Each TASK with the authority facts it was minted with.
        let rows = |task: EntityId| {
            let mut rows = vec![task];
            rows.extend(
                vault
                    .edges_in(&task)
                    .unwrap()
                    .into_iter()
                    .filter(|row| row.kind == EdgeKind::ScopedTo)
                    .map(|row| row.target),
            );
            assert!(
                rows.len() > 1,
                "{name}: a minted TASK carries its Owner fact"
            );
            rows
        };
        let (born_rows, base_rows) = (rows(born), rows(base));
        let doc = create_window_doc("source", &window_key);
        for row in born_rows.iter().chain(&base_rows) {
            insert_blob(&doc, *row, &vault.get_raw(row).unwrap().unwrap());
        }
        doc.commit();
        let selector = SyncSelector::new(grant_id, member, selector_world, vec![], vec![]);
        let update =
            filtered_window_doc(&vault, &doc, &window_key, test_selector_scope(), &selector)
                .unwrap_or_else(|err| panic!("{name}: the request authorizes: {err:?}"))
                .export(ExportMode::all_updates())
                .unwrap();

        let exported = import_ids(&update);
        for row in &base_rows {
            assert!(exported.contains(row), "{name}: a base TASK row travels");
        }
        for row in &born_rows {
            assert_eq!(
                exported.contains(row),
                born_travels,
                "{name}: a world-born TASK row"
            );
        }
    }
}

/// The stored-selection door a peer's edit passes reads the same world rule:
/// a world-born TASK is reachable through its own world's selector or `All`,
/// never through a base-only one.
#[test]
fn a_peer_edit_reaches_a_world_born_task_only_through_its_own_world() {
    let member = entity_id(0x3F);
    let world = local_world_id(0x55);
    let (_dir, vault, grant_id) = test_vault_with_grant(member);
    let grant = FederationGrant::new(
        test_selector_scope(),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    vault
        .batch()
        .put_replicated(
            &grant_id,
            ENTITY_TYPE_FEDERATION_GRANT,
            TimeRange { start: 1, end: 1 },
            1,
            &encode_federation_grant_body(&grant).unwrap(),
        )
        .commit()
        .unwrap();
    let born = mint_board_task(&vault, Some(world.entity_id()));
    let base = mint_board_task(&vault, None);
    for (name, selector_world, born_admitted) in [
        ("base selector", SyncSelectorWorld::Base, false),
        ("its own world", SyncSelectorWorld::World(world), true),
        ("every world", SyncSelectorWorld::All, true),
    ] {
        let selector = SyncSelector::new(grant_id, member, selector_world, vec![], vec![]);
        let txn = vault.store.env.read_txn().unwrap();
        for (task, admitted) in [(base, true), (born, born_admitted)] {
            let result = super::document_admission::admit_document_write_in_txn(
                &vault,
                &txn,
                task,
                test_selector_scope(),
                &selector,
            );
            assert_eq!(result.is_ok(), admitted, "{name}: {result:?}");
        }
    }
}
