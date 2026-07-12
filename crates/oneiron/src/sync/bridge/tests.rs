use super::*;
use crate::Vault;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::companion::{
    CompanionExportClassification, CompanionProvenance, CompanionRecord, CompanionScope,
    ENTITY_TYPE_COMPANION_REGISTER, encode_companion_record_body,
};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_TASK;
use crate::sync::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_since, import_doc,
    map_contains_binary, map_insert_bytes,
};
use crate::temporal::TimeRange;
use core::assert_matches;
use ed25519_dalek::{Signer, SigningKey};
use rmpv::Value;
use std::sync::Arc;

fn test_vault() -> Arc<Vault> {
    let dir = tempfile::tempdir().unwrap();
    Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap())
}

#[test]
fn decode_observer_u_seq_accepts_le_u32() {
    assert_eq!(decode_observer_u_seq(&42u32.to_le_bytes()).unwrap(), 42);
}

#[test]
fn decode_observer_u_seq_rejects_bad_lengths_without_panic() {
    for raw in [&[][..], &[1, 2, 3][..], &[1, 2, 3, 4, 5][..]] {
        let err = decode_observer_u_seq(raw).expect_err("malformed u_seq row must be rejected");
        assert_matches!(err, Error::CorruptedIndex(ERR_OBSERVER_A_U_SEQ_ROW));
    }
}

fn task_body() -> Vec<u8> {
    crate::habit::task_body_for_test(crate::habit::TaskRole::Task)
}

/// Minimal WARN-level event capture: collects `message` fields so tests
/// can assert a specific warn fired without a subscriber dependency.
#[derive(Clone, Default)]
struct WarnCapture {
    messages: Arc<Mutex<Vec<String>>>,
}

impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        struct MessageVisitor(Option<String>);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = Some(format!("{value:?}"));
                }
            }
        }
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        if let Some(message) = visitor.0 {
            self.messages.lock().unwrap().push(message);
        }
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn read_dt_marker(vault: &Vault, id: &EntityId) -> Option<Vec<u8>> {
    let rtxn = vault.store.env.read_txn().unwrap();
    vault
        .store
        .sync_state
        .get(&rtxn, &crate::deletion::local_hard_delete_key(id))
        .unwrap()
        .map(<[u8]>::to_vec)
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

fn companion_record(
    persona_ref: EntityId,
    export_classification: CompanionExportClassification,
) -> CompanionRecord {
    CompanionRecord::persona(
        CompanionScope::neutral(),
        persona_ref,
        Value::from("private companion tuning"),
        CompanionProvenance::new(
            EntityId::from_bytes_unchecked([0xB8; 16]),
            EdgeActorClass::Agent,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            Value::from("private provenance"),
        ),
        export_classification,
    )
}

#[cfg(feature = "sync")]
fn authority_test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

#[cfg(feature = "sync")]
fn authority_key_from_signing(signing: &SigningKey) -> crate::authority::AuthorityKey {
    crate::authority::AuthorityKey::Ed25519(signing.verifying_key().to_bytes())
}

#[cfg(feature = "sync")]
fn authority_test_device(key: crate::authority::AuthorityKey) -> crate::authority::DeviceAuthority {
    crate::authority::DeviceAuthority {
        key,
        transport_key_binding: [0; 32],
        attestation: crate::authority::AuthorityAttestation {
            kind: "SoftwareArgon2id".to_owned(),
            evidence: vec![1, 2, 3],
        },
        tier: crate::authority::AuthorityTier::Software,
        roles: crate::authority::ROLE_OWNER,
    }
}

#[cfg(feature = "sync")]
fn authority_genesis_fixture(seed: u8) -> crate::authority::AuthorityLogEntry {
    let signing = authority_test_key(seed);
    let key = authority_key_from_signing(&signing);
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: None,
        seq: 0,
        parent_hashes: Vec::new(),
        op: crate::authority::AuthorityOp::Genesis {
            device: authority_test_device(key.clone()),
            genesis_nonce: [seed.wrapping_add(1); 32],
            tier_floor: crate::authority::AuthorityTier::Software,
            pending_widen_delay_secs: 86_400,
        },
        signer: crate::authority::AuthoritySignature {
            suite: key.suite(),
            public_key: key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signing.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_enroll_fixture(
    vault_id: crate::authority::AuthorityVaultId,
    parent: &crate::authority::AuthorityLogEntry,
    signer: &SigningKey,
    new_seed: u8,
    seq: u64,
) -> crate::authority::AuthorityLogEntry {
    let signer_key = authority_key_from_signing(signer);
    let new_key = authority_key_from_signing(&authority_test_key(new_seed));
    let mut entry = crate::authority::AuthorityLogEntry {
        schema_version: crate::authority::AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(vault_id),
        seq,
        parent_hashes: vec![crate::authority::authority_entry_hash(parent).expect("parent hash")],
        op: crate::authority::AuthorityOp::EnrollDevice {
            device: authority_test_device(new_key),
        },
        signer: crate::authority::AuthoritySignature {
            suite: signer_key.suite(),
            public_key: signer_key,
            signature: vec![0; 64],
        },
        cosigns: Vec::new(),
        ts: u64::from(new_seed),
    };
    let transcript = crate::authority::authority_transcript(&entry).expect("transcript");
    entry.signer.signature = signer.sign(&transcript).to_bytes().to_vec();
    entry
}

#[cfg(feature = "sync")]
fn authority_log_entity_blob(
    entry: &crate::authority::AuthorityLogEntry,
    learned_at: u64,
) -> Result<Vec<u8>> {
    let body = crate::authority::encode_authority_log_entry_body(entry)?;
    Ok(entity_blob(
        ENTITY_TYPE_AUTHORITY_LOG,
        TimeRange {
            start: learned_at,
            end: learned_at,
        },
        learned_at,
        &body,
    ))
}

#[cfg(feature = "sync")]
#[test]
fn over_quota_peer_rejected() -> Result<()> {
    let vault = test_vault();
    quota::set_maintenance_ingest_quota_config(
        &vault,
        quota::MaintenanceIngestQuotaConfig {
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
        },
    )?;
    let owner = authority_test_key(31);
    let genesis = authority_genesis_fixture(31);
    let vault_id = crate::authority::genesis_vault_id(&genesis)?;
    vault.put_authority_log_entry(
        &EntityId::now(),
        &genesis,
        TimeRange { start: 1, end: 1 },
        1,
    )?;

    let first = authority_enroll_fixture(vault_id, &genesis, &owner, 32, 1);
    let second = authority_enroll_fixture(vault_id, &genesis, &owner, 33, 2);
    let first_blob = authority_log_entity_blob(&first, 2)?;
    let second_blob = authority_log_entity_blob(&second, 3)?;
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");

    vault.with_write_txn(|wtxn| {
        let wrote = materialize_entity_blob_in_txn(
            &vault,
            wtxn,
            &tombstones,
            &EntityId::now().to_hex(),
            &first_blob,
            crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        )?;
        assert!(
            wrote,
            "first authority replay-door write should materialize"
        );
        Ok(())
    })?;

    let second_id = EntityId::now();
    let err = vault
        .with_write_txn(|wtxn| {
            materialize_entity_blob_in_txn(
                &vault,
                wtxn,
                &tombstones,
                &second_id.to_hex(),
                &second_blob,
                crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
            )
            .map(|_| ())
        })
        .expect_err("same authority signer must be capped by production replay-door quota");

    assert!(matches!(
        err,
        Error::MaintenanceIngestQuotaExceeded {
            accepted_count: 1,
            max_ops_per_peer_window: 1,
            quota_window_secs: 3_600,
            ..
        }
    ));
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .entities
            .get(&rtxn, second_id.as_bytes())?
            .is_none(),
        "over-quota authority replay-door blob must not be stored"
    );
    Ok(())
}

/// Index-aligned metas for direct `apply_materialized_edge_ops` calls.
fn test_metas_for_ops(ops: &[BatchOp]) -> Vec<EdgeOpMeta> {
    ops.iter()
        .map(|op| {
            let (src, kind, tgt) = match op {
                BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
                | BatchOp::Edge { src, kind, tgt, .. }
                | BatchOp::DeleteEdge { src, kind, tgt } => (src, *kind, tgt),
                _ => unreachable!("edge ops only"),
            };
            EdgeOpMeta::for_key(&format_edge_key(src, kind, tgt), &[])
        })
        .collect()
}

#[test]
fn parse_edge_key_valid() {
    let src = EntityId::from_bytes_unchecked([0x11; 16]);
    let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
    let key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
    let (s, k, t) = parse_edge_key(&key).unwrap();
    assert_eq!(s, src);
    assert_eq!(k, EdgeKind::Mentions);
    assert_eq!(t, tgt);
}

#[test]
fn parse_edge_key_invalid_length() {
    assert!(parse_edge_key("too-short").is_none());
}

#[test]
fn edge_value_round_trip() {
    let vad = Vad {
        valence: 0.5,
        arousal: 0.3,
        dominance: 0.7,
    };
    let buf = encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 12345, Some(vad), None).unwrap();
    let decoded = parse_edge_value(&buf).unwrap();
    assert!((decoded.weight - 0.8).abs() < f32::EPSILON);
    assert_eq!(decoded.created_at, 12345);
    let v = decoded.vad.unwrap();
    assert!((v.valence - 0.5).abs() < f32::EPSILON);
    assert!((v.arousal - 0.3).abs() < f32::EPSILON);
    assert!((v.dominance - 0.7).abs() < f32::EPSILON);
}

#[test]
fn apply_materialized_edge_ops_keeps_other_edges_after_child_of_failure() {
    let vault = test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &c,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::EdgeWithCreatedAt {
                    src: a,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: c,
                    kind: EdgeKind::Mentions,
                    tgt: a,
                    weight: 0.8,
                    created_at: 11,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
    assert!(vault.edge_exists(&c, EdgeKind::Mentions, &a).unwrap());
}

#[test]
fn apply_materialized_edge_ops_keeps_valid_child_of_delete_when_add_fails() {
    let vault = test_vault();
    let a = EntityId::now();
    let b = EntityId::now();
    let c = EntityId::now();

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &c,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .edge(&c, EdgeKind::ChildOf, &b, 1.0)
        .edge(&b, EdgeKind::ChildOf, &a, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::DeleteEdge {
                    src: c,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: a,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(!vault.edge_exists(&c, EdgeKind::ChildOf, &b).unwrap());
    assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
}

#[test]
fn apply_materialized_edge_ops_child_of_subset_is_deterministic() {
    let vault = test_vault();
    let a = EntityId::from_bytes_unchecked([1; 16]);
    let x = EntityId::from_bytes_unchecked([2; 16]);
    let b = EntityId::from_bytes_unchecked([3; 16]);
    let y = EntityId::from_bytes_unchecked([4; 16]);

    vault
        .batch()
        .put(
            &a,
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        )
        .put(
            &x,
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        )
        .put(
            &b,
            ENTITY_TYPE_TASK,
            TimeRange { start: 5, end: 5 },
            6,
            &task_body(),
        )
        .put(
            &y,
            ENTITY_TYPE_TASK,
            TimeRange { start: 7, end: 7 },
            8,
            &task_body(),
        )
        .edge(&a, EdgeKind::ChildOf, &x, 1.0)
        .edge(&b, EdgeKind::ChildOf, &y, 1.0)
        .commit()
        .unwrap();

    vault
        .with_write_txn(|wtxn| {
            let ops = vec![
                BatchOp::EdgeWithCreatedAt {
                    src: y,
                    kind: EdgeKind::ChildOf,
                    tgt: a,
                    weight: 1.0,
                    created_at: 10,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
                BatchOp::EdgeWithCreatedAt {
                    src: x,
                    kind: EdgeKind::ChildOf,
                    tgt: b,
                    weight: 1.0,
                    created_at: 11,
                    vad: Vad::NEUTRAL,
                    provenance: None,
                },
            ];
            let metas = test_metas_for_ops(&ops);
            apply_materialized_edge_ops(&vault, wtxn, ops, &metas, "2026-03")?;
            Ok(())
        })
        .unwrap();

    assert!(vault.edge_exists(&x, EdgeKind::ChildOf, &b).unwrap());
    assert!(!vault.edge_exists(&y, EdgeKind::ChildOf, &a).unwrap());
}

#[test]
fn observer_b_hydrates_edge_endpoints_from_current_crdt_state() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let a = EntityId::now();
    let b = EntityId::now();

    map_insert_bytes(
        &entities,
        &a.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &b.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get(&a).unwrap().is_some());
    assert!(vault.get(&b).unwrap().is_some());
    assert!(vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap());
}

#[test]
fn observer_b_does_not_rehydrate_tombstoned_edge_endpoint() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let tombstones = doc.get_map("tombstones");
    let deleted = EntityId::now();
    let live = EntityId::now();

    map_insert_bytes(
        &entities,
        &deleted.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &live.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    tombstones.insert(&deleted.to_hex(), b"1").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&deleted, EdgeKind::Mentions, &live),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get(&deleted).unwrap().is_none());
    assert!(
        !vault
            .edge_exists(&deleted, EdgeKind::Mentions, &live)
            .unwrap()
    );
}

/// The endpoint-ready check must run the tombstone gate BEFORE the
/// LMDB-row shortcut: a tombstoned endpoint whose stale local row
/// survives (crash window between the tombstone CRDT commit and the
/// purge txn, or a failed purge) must never count as "ready". Pre-fix
/// code returned true on ANY existing row and materialized the edge.
/// Covers binary AND non-binary tombstone values (fail closed).
#[test]
fn observer_b_does_not_materialize_edge_to_tombstoned_endpoint_with_stale_row() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let edges = doc.get_map("edges");
    let tombstones = doc.get_map("tombstones");
    let live = EntityId::now();
    let del_bin = EntityId::now(); // binary (legacy hard) tombstone
    let del_str = EntityId::now(); // non-binary tombstone — must gate too

    // All three rows exist locally — the deleted ones are the stale
    // survivors of an interrupted purge.
    for id in [&live, &del_bin, &del_str] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }
    tombstones.insert(&del_bin.to_hex(), b"1").unwrap();
    tombstones.insert(&del_str.to_hex(), "corrupt").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    for (src, tgt) in [(&live, &del_bin), (&live, &del_str), (&del_bin, &live)] {
        map_insert_bytes(
            &edges,
            &format_edge_key(src, EdgeKind::Mentions, tgt),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
    }
    doc.commit();

    assert!(
        !vault
            .edge_exists(&live, EdgeKind::Mentions, &del_bin)
            .unwrap(),
        "edge to tombstoned target with stale row must not materialize"
    );
    assert!(
        !vault
            .edge_exists(&live, EdgeKind::Mentions, &del_str)
            .unwrap(),
        "non-binary tombstone must gate the target too (fail closed)"
    );
    assert!(
        !vault
            .edge_exists(&del_bin, EdgeKind::Mentions, &live)
            .unwrap(),
        "edge FROM a tombstoned source with stale row must not materialize"
    );
}

#[test]
fn observer_b_quarantines_fenced_edge_before_apply_and_keeps_ordinary_control() {
    let vault = test_vault();
    let source = EntityId::now();
    let fenced_target = EntityId::now();
    let ordinary_target = EntityId::now();
    for id in [&source, &fenced_target, &ordinary_target] {
        vault
            .put_entity(
                id,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                &task_body(),
            )
            .unwrap();
    }
    vault
        .enter_off_record_session(
            "sess-observer-edge-fence",
            crate::off_record::OffRecordBackendClass::Local,
        )
        .unwrap();
    vault
        .tag_turn_off_record("sess-observer-edge-fence", &fenced_target)
        .unwrap();

    let doc = LoroDoc::new();
    let edges = doc.get_map("edges");
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    for target in [&fenced_target, &ordinary_target] {
        map_insert_bytes(
            &edges,
            &format_edge_key(&source, EdgeKind::Mentions, target),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
    }
    doc.commit();

    assert!(
        !vault
            .edge_exists(&source, EdgeKind::Mentions, &fenced_target)
            .unwrap(),
        "edge touching a fenced endpoint must be rejected before LMDB apply"
    );
    assert!(
        vault
            .edge_exists(&source, EdgeKind::Mentions, &ordinary_target)
            .unwrap(),
        "unrelated ordinary edge in the same Observer-B batch must survive"
    );
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .iter()
            .any(|(_, record)| {
                record.reason_code == "OffRecordFencedTurnWriteRejected"
                    && record.container == crate::sync::quarantine::QuarantineContainer::Edges
            }),
        "rejected fenced edge must retain hashed quarantine evidence"
    );
}

/// ONE-1122 AC2 — ARCH-0023b: "If tombstoned in CRDT → never resurrect";
/// contracts.ts `user_hard_delete`: "Tombstone-first prevents sync
/// resurrection". Hard delete writes the CRDT tombstone and (ONE-1132)
/// removes the live `entities[id]` map copy in the SAME CRDT commit, so
/// a later remote commit re-touching the entity key must NOT
/// rematerialize the purged body into LMDB.
#[test]
fn observer_b_never_resurrects_hard_deleted_entity_on_entity_key_retouch() {
    let vault = test_vault();
    let materializer = Arc::new(Materializer::new());

    let id = EntityId::now();
    let learned_at = 1_772_400_000u64; // 2026-03 window
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // Mirror LMDB → CRDT, then persist, so `write_crdt_tombstone` (which
    // loads the persisted window doc) operates on a doc holding the blob.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let window =
        crate::sync::window::LoadedWindow::new("local", window_key.clone(), &vault, &materializer);
    let mirrored =
        crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);
    window.persist_state(&vault).unwrap();
    drop(window);

    // Hard delete: CRDT tombstone FIRST, then active-store purge.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(vault.get(&id).unwrap().is_none());

    let doc = crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    let hex_id = id.to_hex();
    assert!(
        map_get_bytes(&doc.get_map("entities"), &hex_id).is_none(),
        "precondition: hard delete removes the live entities-map copy in the same CRDT commit (ONE-1132)"
    );
    assert!(
        map_contains_binary(&doc.get_map("tombstones"), &hex_id),
        "precondition: hard delete writes the CRDT tombstone"
    );

    // Remote commit re-touches the entity key after Observer B attaches.
    let window =
        crate::sync::window::LoadedWindow::from_doc(doc, window_key, &vault, &materializer);
    let entities = window.doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &hex_id,
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    window.doc.commit();

    assert!(
        vault.get(&id).unwrap().is_none(),
        "tombstoned entity must never resurrect into LMDB"
    );
}

/// ONE-1122 AC3 — SoftErased-shell variant: a 25 B envelope shell in
/// LMDB + the full blob arriving via an entities-map delta + the
/// tombstone present in the doc → the body is NOT restored. The gate
/// fires BEFORE the put; nothing heals after.
#[test]
fn observer_b_does_not_restore_soft_erased_body_when_tombstoned() {
    let vault = test_vault();
    let id = EntityId::now();
    let learned_at = 1_772_400_000u64;
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // SoftErase (`user_delete`): scrubs the body, keeps the 25 B shell.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(outcome.existed);
    assert_eq!(
        vault.get_raw(&id).unwrap().expect("shell row").len(),
        ENTITY_METADATA_HEADER_LEN,
        "SoftErase must leave the bare 25 B envelope shell"
    );

    // Doc already tombstoned BEFORE observers attach; then the full blob
    // arrives via a delta re-touching the entity key.
    let doc = LoroDoc::new();
    let tombstones = doc.get_map("tombstones");
    tombstones.insert(&id.to_hex(), b"1").unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let entities = doc.get_map("entities");
    map_insert_bytes(
        &entities,
        &id.to_hex(),
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    doc.commit();

    let raw = vault.get_raw(&id).unwrap().expect("shell must remain");
    assert_eq!(
        raw.len(),
        ENTITY_METADATA_HEADER_LEN,
        "tombstoned entity body must NOT be restored over the SoftErase shell"
    );
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(&[][..]),
        "entity body must stay empty after the gated delta"
    );
}

/// ONE-1115 AC7 — sync replay (observer-b edge materialization →
/// `apply_edge_with_created_at`) routes through the same contract \[0, 1\]
/// weight gate as local batch writes: an in-range replayed edge lands in
/// `edges_out` with its weight and `created_at` intact.
#[test]
fn observer_b_replays_in_range_edge_weight_through_write_gate() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let a = EntityId::now();
    let b = EntityId::now();

    map_insert_bytes(
        &entities,
        &a.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    map_insert_bytes(
        &entities,
        &b.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 3, end: 3 },
            4,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(
        &edges,
        &format_edge_key(&a, EdgeKind::Mentions, &b),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    let out = vault.edges_out(&a).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, EdgeKind::Mentions);
    assert_eq!(out[0].target, b);
    assert_eq!(
        out[0].weight.to_bits(),
        0.6_f32.to_bits(),
        "replayed in-range weight must survive the write gate verbatim"
    );
    assert_eq!(out[0].created_at, 10);
}

/// ONE-1122 resurrection regression (handoff §8c.5): a crafted update
/// that REMOVES the CRDT tombstone and re-puts the entity key must NOT
/// rematerialize the hard-deleted body. The CRDT map is mutable remote
/// input; the `dt:` marker written in the origin purge txn is the local
/// truth the gate falls back to, and the removal is quarantined (x:
/// row, ONE-1124) as a protocol violation.
#[test]
fn observer_b_refuses_resurrection_after_crafted_tombstone_removal() {
    let vault = test_vault();
    let materializer = Arc::new(Materializer::new());

    let id = EntityId::now();
    let learned_at = 1_772_400_000u64; // 2026-03 window
    let occurred = TimeRange { start: 1, end: 1 };
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();

    // Mirror LMDB → CRDT and persist so the hard delete operates on a
    // window doc holding the blob.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let window =
        crate::sync::window::LoadedWindow::new("local", window_key.clone(), &vault, &materializer);
    let mirrored =
        crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
    assert_eq!(mirrored, 1);
    window.persist_state(&vault).unwrap();
    drop(window);

    // Hard delete: CRDT tombstone + dt: marker + active-store purge.
    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(outcome.existed);
    assert!(vault.get(&id).unwrap().is_none());
    assert!(
        read_dt_marker(&vault, &id).is_some(),
        "precondition: hard delete writes the dt: marker"
    );

    let hex_id = id.to_hex();
    let local_doc =
        crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    assert!(
        map_contains_binary(&local_doc.get_map("tombstones"), &hex_id),
        "precondition: hard delete writes the CRDT tombstone"
    );

    // Crafted attacker update: fork the local doc state, REMOVE the
    // tombstone, re-put the entity key, export the delta.
    let fork = doc_from_snapshot(&export_snapshot(&local_doc).unwrap()).unwrap();
    fork.get_map("tombstones").delete(&hex_id).unwrap();
    map_insert_bytes(
        &fork.get_map("entities"),
        &hex_id,
        &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
    )
    .unwrap();
    fork.commit();
    let crafted = export_updates_since(&fork, &doc_version_vector(&local_doc)).unwrap();

    // Apply the crafted update with observers attached, capturing warns.
    let window =
        crate::sync::window::LoadedWindow::from_doc(local_doc, window_key, &vault, &materializer);
    let warns = WarnCapture::default();
    tracing::subscriber::with_default(warns.clone(), || {
        import_doc(&window.doc, &crafted).unwrap();
    });

    // The removal landed in the CRDT map (no tombstone left to re-fire)…
    assert!(
        !map_contains_binary(&window.doc.get_map("tombstones"), &hex_id),
        "crafted removal must actually clear the CRDT tombstone"
    );
    // …but the dt: marker gate refused the re-put.
    assert!(
        vault.get(&id).unwrap().is_none(),
        "hard-deleted entity must not rematerialize after crafted tombstone removal"
    );
    let messages = warns.messages.lock().unwrap();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("rejected by write gate")),
        "protocol-violation quarantine warn must fire, got: {messages:?}"
    );
    assert!(
        messages.iter().any(|m| m.contains("dt: marker")),
        "dt: gate refusal warn must fire, got: {messages:?}"
    );
    // The removal is quarantined (x: row, ONE-1124) — never a bare log.
    let records = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert!(
        records
            .iter()
            .any(|(_, r)| r.container == QuarantineContainer::Tombstones),
        "crafted tombstone removal must persist a Tombstones x: row"
    );
}

/// ONE-1122 `dt:` marker shape: written in the purge txn on HARD
/// outcomes (pinned `[reason:1][deleted_at:8 LE][request_id:16]`
/// layout), absent on SoftErase, and pure LMDB truth — independent of
/// any CRDT map state.
#[test]
fn hard_delete_writes_dt_marker_soft_delete_does_not() {
    let vault = test_vault();
    let occurred = TimeRange { start: 1, end: 1 };
    let learned_at = 1_772_400_000u64;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let hard = EntityId::now();
    vault
        .put_entity(&hard, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&hard, crate::DeleteReason::UserHardDelete)
        .unwrap();

    let marker = read_dt_marker(&vault, &hard).expect("dt: row written on hard delete");
    assert_eq!(
        marker.len(),
        25,
        "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
    );
    assert_eq!(marker[0], 2, "user_hard_delete reason byte");
    let deleted_at = u64::from_le_bytes(marker[1..9].try_into().unwrap());
    assert!(
        deleted_at >= before && deleted_at <= before + 60,
        "deleted_at must be the request time"
    );
    assert_ne!(&marker[9..25], &[0u8; 16][..], "request id present");

    // GDPR delete is also HARD — marker with reason byte 3.
    let gdpr = EntityId::now();
    vault
        .put_entity(&gdpr, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&gdpr, crate::DeleteReason::GdprDelete)
        .unwrap();
    let marker = read_dt_marker(&vault, &gdpr).expect("dt: row written on gdpr delete");
    assert_eq!(marker[0], 3, "gdpr_delete reason byte");

    // SoftErase writes NO marker.
    let soft = EntityId::now();
    vault
        .put_entity(&soft, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    vault
        .delete_entity_with_reason(&soft, crate::DeleteReason::UserDelete)
        .unwrap();
    assert!(
        read_dt_marker(&vault, &soft).is_none(),
        "soft delete must not write a dt: marker"
    );

    // The marker is LMDB truth: dropping the tombstone from the loaded
    // window doc leaves the dt: row untouched.
    let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
    let doc = crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
    doc.get_map("tombstones").delete(&hard.to_hex()).unwrap();
    doc.commit();
    assert!(
        read_dt_marker(&vault, &hard).is_some(),
        "dt: marker survives independently of the CRDT tombstone map"
    );
}

/// ONE-1122 `dt:` marker, headerless leg: a hard delete that routes
/// through `delete_entity_without_header` (active residue, entity row /
/// 25 B header missing) writes NO CRDT tombstone — the `dt:` marker
/// written in the purge txn is the only local delete truth for that id.
/// It must exist after the delete, and the Observer-B gate must refuse
/// a crafted re-put on its strength alone.
#[test]
fn headerless_hard_delete_writes_dt_marker_and_gate_refuses_reput() {
    let vault = test_vault();
    let occurred = TimeRange { start: 1, end: 1 };
    let learned_at = 1_772_400_000u64;

    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, &task_body())
        .unwrap();
    // Strip ONLY the entity row, leaving index residue (short-id
    // reverse row) — the exact shape `delete_entity_without_header`
    // exists for: active data present, no parseable header.
    {
        let mut wtxn = vault.store.env.write_txn().unwrap();
        assert!(
            vault
                .store
                .entities
                .delete(&mut wtxn, id.as_bytes())
                .unwrap()
        );
        wtxn.commit().unwrap();
    }

    let outcome = vault
        .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
        .unwrap();
    assert!(
        outcome.receipt_id.is_some(),
        "headerless residue purge must write a receipt (not the missing no-op)"
    );
    let marker = read_dt_marker(&vault, &id)
        .expect("headerless hard delete must write the dt: marker in the purge txn");
    assert_eq!(
        marker.len(),
        25,
        "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
    );
    assert_eq!(marker[0], 2, "user_hard_delete reason byte");

    // Crafted re-put through Observer B: no CRDT tombstone exists for a
    // headerless delete, so ONLY the dt: leg of the OR-gate can refuse.
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");
    let warns = WarnCapture::default();
    tracing::subscriber::with_default(warns.clone(), || {
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, &task_body()),
        )
        .unwrap();
        doc.commit();
    });

    assert!(
        vault.get(&id).unwrap().is_none(),
        "dt: gate must refuse rematerialization of a headerless hard delete"
    );
    let messages = warns.messages.lock().unwrap();
    assert!(
        messages.iter().any(|m| m.contains("dt: marker")),
        "dt: gate refusal warn must fire, got: {messages:?}"
    );
}

/// Negative: an entity that was never deleted materializes through the
/// unchanged honest path — the dt: OR-gate adds no false refusals.
#[test]
fn observer_b_materializes_never_deleted_entity_normally() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::now();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange { start: 1, end: 1 },
            2,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let expected = task_body();
    assert_eq!(
        vault.get(&id).unwrap().as_deref(),
        Some(expected.as_slice()),
        "never-deleted entity must materialize normally"
    );
}

#[test]
fn companion_register_api_observer_b_materializes_portable_on_fresh_vault() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::from_bytes_unchecked([0x41; 16]);
    let learned_at = 1_772_400_000u64;
    let record = companion_record(id, CompanionExportClassification::Portable);
    let body = encode_companion_record_body(&record.created_at(learned_at).unwrap()).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(
        vault.get_companion_record(&id).unwrap().is_some(),
        "live sync replay should register the companion kind and materialize portable records"
    );
}

#[test]
fn companion_register_api_observer_b_suppresses_local_only_records() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let id = EntityId::from_bytes_unchecked([0x42; 16]);
    let learned_at = 1_772_400_000u64;
    let record = companion_record(id, CompanionExportClassification::LocalOnly);
    let body = encode_companion_record_body(&record.created_at(learned_at).unwrap()).unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(
        vault.get_companion_record(&id).unwrap().is_none(),
        "live sync replay must not materialize local-only companion register records"
    );
}

#[test]
fn companion_register_api_observer_b_scrubs_local_only_rows_and_edges_from_crdt() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let local_id = EntityId::from_bytes_unchecked([0x43; 16]);
    let portable_id = EntityId::from_bytes_unchecked([0x44; 16]);
    let learned_at = 1_772_400_001u64;
    let local_record = companion_record(local_id, CompanionExportClassification::LocalOnly);
    let portable_record = companion_record(portable_id, CompanionExportClassification::Portable);
    let local_body =
        encode_companion_record_body(&local_record.created_at(learned_at).unwrap()).unwrap();
    let portable_body =
        encode_companion_record_body(&portable_record.created_at(learned_at).unwrap()).unwrap();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let edge_key = format_edge_key(&local_id, EdgeKind::Mentions, &portable_id);

    map_insert_bytes(
        &entities,
        &portable_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &portable_body,
        ),
    )
    .unwrap();
    map_insert_bytes(
        &edges,
        &edge_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, learned_at, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();

    map_insert_bytes(
        &entities,
        &local_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_COMPANION_REGISTER,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &local_body,
        ),
    )
    .unwrap();
    doc.commit();

    assert!(vault.get_companion_record(&local_id).unwrap().is_none());
    assert!(
        map_get_bytes(&entities, &local_id.to_hex()).is_none(),
        "live observer must scrub local-only companion rows from the CRDT window"
    );
    assert!(
        map_get_bytes(&edges, &edge_key).is_none(),
        "live observer must scrub edges touching local-only companion rows"
    );
    assert!(
        vault.get_companion_record(&portable_id).unwrap().is_some(),
        "syncable companion rows should still materialize"
    );
}

#[test]
fn companion_register_api_observer_b_rejects_edges_touching_existing_local_only_endpoint() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    let local_id = EntityId::from_bytes_unchecked([0x45; 16]);
    let task_id = EntityId::from_bytes_unchecked([0x46; 16]);
    let learned_at = 1_772_400_002u64;
    let local_record = companion_record(local_id, CompanionExportClassification::LocalOnly);
    vault
        .create_companion_record(&local_id, &local_record, learned_at)
        .unwrap();
    map_insert_bytes(
        &doc.get_map("entities"),
        &task_id.to_hex(),
        &entity_blob(
            ENTITY_TYPE_TASK,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &task_body(),
        ),
    )
    .unwrap();
    doc.commit();

    let edge_key = format_edge_key(&task_id, EdgeKind::Mentions, &local_id);
    map_insert_bytes(
        &doc.get_map("edges"),
        &edge_key,
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.7, learned_at, None, None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(
        !vault
            .edge_exists(&task_id, EdgeKind::Mentions, &local_id)
            .unwrap(),
        "edges touching existing local-only companion endpoints must not materialize"
    );
    assert!(
        map_get_bytes(&doc.get_map("edges"), &edge_key).is_none(),
        "live observer must scrub the rejected local-only edge carrier"
    );
}

/// ONE-1123: Observer B materializes a remote reserved-predicate
/// `edge.provenance` Claim — the truth behind the 26 B edge flag cache
/// (contracts.ts edgeProvenanceClaim: "the edge flags are a DERIVED
/// CACHE of that Claim, and the Claim is truth") — byte-identical,
/// instead of warn-skipping it at the public reserved-namespace gate.
///
/// FAILS against pre-fix code: `materialize_entity_blob_in_txn` routed
/// the type-0 Claim through the pre-rename replay door
/// (`allow_reserved_predicate: false`), `validate_claim_body_bytes`
/// rejected it with ReservedPredicate, and the observer warn-skipped it
/// — the Claim never reached the replica's LMDB.
///
/// Since ONE-1159 the door also validates provenance STRUCTURE, so the
/// forged Claim carries a real value record + actor-class evidence
/// (the original junk-string `val` pinned the pre-1159 hole) — this is
/// now also the door's positive control: a fully-valid edge.provenance
/// Claim replicates with zero quarantine rows.
#[test]
fn observer_b_materializes_remote_edge_provenance_claim() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");

    let src = EntityId::now();
    let tgt = EntityId::now();
    let actor = EntityId::now();
    let claim_id = EntityId::now();

    let record = crate::provenance::EdgeProvenanceClaimBody::new(
        actor,
        0.9,
        crate::provenance::SupersessionStatus::Confirmed,
    );
    let mut body = crate::claim::ClaimBody::new(
        "edge.provenance",
        crate::claim::ClaimSubject::Edge {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        },
        crate::provenance::encode_edge_provenance_value(&record),
        0.9,
        crate::claim::ClaimApprovalStatus::Auto,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    body.evidence = Some(crate::provenance::encode_actor_class_evidence(
        crate::edge::EdgeActorClass::Human,
    ));
    let body_bytes = crate::claim::encode_claim_body(&body).unwrap();
    let claim_blob = entity_blob(
        crate::registry::ENTITY_TYPE_CLAIM,
        TimeRange { start: 5, end: 5 },
        6,
        &body_bytes,
    );

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    map_insert_bytes(&entities, &claim_id.to_hex(), &claim_blob).unwrap();
    doc.commit();

    assert_eq!(
        vault.get_raw(&claim_id).unwrap().as_deref(),
        Some(claim_blob.as_slice()),
        "remote edge.provenance Claim must materialize byte-identical via Observer B"
    );
    let read = vault
        .get_claim(&claim_id)
        .unwrap()
        .expect("materialized Claim must read back through get_claim");
    assert_eq!(read.predicate, "edge.provenance");
    assert!(
        crate::sync::quarantine::quarantined_records(&vault)
            .unwrap()
            .is_empty(),
        "a fully-valid edge.provenance Claim must not trip the ONE-1159 door check"
    );
}

/// ONE-1124 fix wave 2 (fail-closed split) — when the src endpoint
/// fails with a REMOTE-rejectable error and the tgt endpoint fails with
/// a LOCAL error, the LOCAL error wins: the edge transaction aborts and
/// NO x: row is written. Pre-fix, `(Err(e), _) | (_, Err(e))` bound the
/// remote src error, quarantined the edge, and silently swallowed the
/// local failure.
#[test]
fn local_endpoint_error_aborts_batch_before_remote_quarantine() {
    let vault = test_vault();
    let doc = LoroDoc::new();
    let entities = doc.get_map("entities");
    let edges = doc.get_map("edges");
    let src = EntityId::now();
    let tgt = EntityId::now();

    // src endpoint blob: parses structurally but fails the entity write
    // gate with InvalidEntityType (unknown type byte) — a
    // remote-rejectable endpoint error. Inserted BEFORE the observer is
    // registered so only the edge delta fires.
    map_insert_bytes(
        &entities,
        &src.to_hex(),
        &entity_blob(200, TimeRange { start: 1, end: 1 }, 2, b"s"),
    )
    .unwrap();
    doc.commit();

    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, "2026-03");

    // tgt endpoint: injected LOCAL read failure (the engine's own read
    // erroring — not classifiable as a remote rejection).
    INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.set(Some(tgt)));
    map_insert_bytes(
        &edges,
        &format_edge_key(&src, EdgeKind::Mentions, &tgt),
        &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.5, 10, Some(Vad::NEUTRAL), None).unwrap(),
    )
    .unwrap();
    doc.commit();

    assert!(
        INJECT_LOCAL_ENDPOINT_FAILURE.with(|cell| cell.get().is_none()),
        "precondition: the local tgt failure was actually hit"
    );
    let records = crate::sync::quarantine::quarantined_records(&vault).unwrap();
    assert!(
        records.is_empty(),
        "local endpoint error must abort the txn — no x: row may pretend the edge was handled"
    );
    assert!(
        !vault.edge_exists(&src, EdgeKind::Mentions, &tgt).unwrap(),
        "aborted txn must not materialize the edge"
    );
    assert!(
        vault.get(&src).unwrap().is_none(),
        "aborted txn must not materialize the src endpoint"
    );
}
