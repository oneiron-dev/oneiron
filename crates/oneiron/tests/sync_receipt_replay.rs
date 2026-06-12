//! ONE-1134 — REDACTION_AUDIT (type 120) replay validation + immutability +
//! audit-divergence quarantine at both sync replay doors (Observer B entity
//! path + `forward_rematerialize`).
//!
//! Contract sources:
//! * contracts.ts `redactionAuditReceipt`: "Immutable maintenance/audit
//!   record"; minimization "Opaque identifiers + timestamps only"; pinned
//!   field set request_id, scope, reason (user_hard_delete | gdpr_delete |
//!   policy_delete), requested_at, soft_complete_at, hard_purge_complete_at,
//!   sweep_queued_at?, sweep_complete_at?, affected_revision_ids,
//!   verification (GDPR Art. 5(2) accountability metadata).
//! * ARCH-0023b stream-class split: audit/guardrail state is fail-closed —
//!   "QUARANTINE divergent same-identity payloads … never silent LWW".
//!
//! OWNER-DECISION (M4 unit 07, option [a]): validate-and-accept-new +
//! immutability + quarantine-divergent. The maintenance door stays open for
//! legitimate own-receipt round-trips (byte-identical re-delivery is an
//! idempotent accept). Residual accepted: a well-formed FORGED NEW receipt
//! from a hostile peer remains admissible — see
//! `forged_well_formed_new_receipt_is_accepted_residual_documented`.
//!
//! Lives in its own integration binary (fresh process): the lib test binary
//! sits near a per-process LMDB env-open budget on macOS, and these tests
//! open one vault per scenario.

#![cfg(feature = "sync")]

use std::sync::Arc;

use loro::LoroDoc;
use oneiron::sync::bridge::{Materializer, register_observer_b};
use oneiron::sync::quarantine::{QuarantineContainer, QuarantineRecord, quarantined_records};
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::types::WindowKey;
use oneiron::sync::window::forward_rematerialize;
use oneiron::types::{ENTITY_TYPE_REDACTION_AUDIT, TimeRange};
use oneiron::{DeleteReason, EntityId, Error, Vault, VaultConfig};
use rmpv::Value;
use xxhash_rust::xxh3::xxh3_64;

/// `learned_at` inside the 2026-03 window used for forged receipts.
const LEARNED_AT: u64 = 1_772_400_000;
const WINDOW: &str = "2026-03";

/// A syntactically valid (any-version) UUID literal for forged request_ids.
const FORGED_REQUEST_ID: &str = "018f3a2b-7c4d-7e5f-8a9b-0c1d2e3f4a5b";

fn test_config() -> VaultConfig {
    let mut cfg = VaultConfig::device();
    cfg.map_size = 16 * 1024 * 1024;
    cfg.dimensions = 4;
    cfg.embedding_model = None;
    cfg.max_readers = 16;
    cfg
}

fn test_vault_with_dir() -> (tempfile::TempDir, Arc<Vault>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), test_config()).unwrap());
    (dir, vault)
}

/// 25-byte pinned envelope: type u8 + occurred_start/end + learned_at u64 BE.
/// Receipts are point events (`occurred_start == occurred_end == learned_at`,
/// matching the engine's direct receipt writer).
fn receipt_envelope(learned_at: u64, body: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(25 + body.len());
    blob.push(ENTITY_TYPE_REDACTION_AUDIT);
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(&learned_at.to_be_bytes());
    blob.extend_from_slice(body);
    blob
}

/// Hand-built receipt body entries carrying EXACTLY the pinned contracts.ts
/// `redactionAuditReceipt` field set, encoded independently of the engine's
/// own serializer (no round-tripping engine output as the expectation).
fn receipt_body_entries(scope_entity_hex: &str) -> Vec<(Value, Value)> {
    vec![
        ("request_id".into(), FORGED_REQUEST_ID.into()),
        (
            "scope".into(),
            Value::Map(vec![
                (
                    "entity_ids".into(),
                    Value::Array(vec![scope_entity_hex.into()]),
                ),
                ("revision_ids".into(), Value::Array(vec![])),
            ]),
        ),
        ("reason".into(), "gdpr_delete".into()),
        ("requested_at".into(), 100u64.into()),
        ("soft_complete_at".into(), 101u64.into()),
        ("hard_purge_complete_at".into(), 102u64.into()),
        ("sweep_queued_at".into(), Value::Nil),
        ("sweep_complete_at".into(), Value::Nil),
        ("affected_revision_ids".into(), Value::Array(vec![])),
        ("verification".into(), Value::Map(vec![])),
    ]
}

fn encode_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).unwrap();
    out
}

fn insert_bytes(map: &loro::LoroMap, key: &str, value: &[u8]) {
    map.insert(key, value).unwrap();
}

fn record_for_key<'a>(
    records: &'a [(u64, QuarantineRecord)],
    crdt_key: &str,
) -> Option<&'a QuarantineRecord> {
    let key_hash = xxh3_64(crdt_key.as_bytes());
    let key_len = u32::try_from(crdt_key.len()).unwrap();
    records
        .iter()
        .rev()
        .map(|(_, rec)| rec)
        .find(|rec| rec.crdt_key_hash == key_hash && rec.crdt_key_len == key_len)
}

/// Authors a REAL receipt through the engine's own delete path and returns
/// (receipt_id, raw envelope bytes, derived window key).
fn author_receipt(vault: &Vault) -> (EntityId, Vec<u8>, WindowKey) {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            1, // TURN
            TimeRange {
                start: 301,
                end: 301,
            },
            301,
            b"forget-me",
        )
        .unwrap();
    let outcome = vault
        .delete_entity_with_reason(&subject, DeleteReason::UserHardDelete)
        .unwrap();
    let receipt_id = outcome
        .receipt_id
        .expect("user hard delete must author a REDACTION_AUDIT receipt");
    let raw = vault
        .get_raw(&receipt_id)
        .unwrap()
        .expect("receipt must exist locally");
    assert_eq!(raw[0], ENTITY_TYPE_REDACTION_AUDIT);
    let learned_at = vault.get_learned_at(&receipt_id).unwrap();
    (receipt_id, raw, WindowKey::from_timestamp(learned_at))
}

// ─── AC5 (a) — malformed type-120 blobs via delta ────────────────────────────

/// AC1/AC5(a) — a type-120 blob failing the pinned receipt-body validation
/// at the Observer B entity door is QUARANTINED (x: record, typed reason,
/// payload hash) and never written to LMDB. The table covers each
/// fail-closed rule of the validator, asserting contract literals: a
/// plausible-wrong implementation that admits any MessagePack map (or skips
/// body validation entirely, today's pre-fix behavior) fails here.
#[test]
fn malformed_type_120_blob_via_delta_is_quarantined_not_written() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let entities = doc.get_map("entities");
    let scope_hex = EntityId::now().to_hex();

    let cases: Vec<(&'static str, Vec<u8>)> = vec![
        ("not_messagepack", b"definitely-not-msgpack".to_vec()),
        ("missing_required_field", {
            // request_id dropped — required by the pinned field set.
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .filter(|(key, _)| key.as_str() != Some("request_id"))
                .collect();
            encode_map(entries)
        }),
        ("unknown_extra_field", {
            // A field outside the pinned set violates minimization
            // ("opaque identifiers + timestamps only").
            let mut entries = receipt_body_entries(&scope_hex);
            entries.push(("erased_content".into(), "the deleted text".into()));
            encode_map(entries)
        }),
        ("non_receipt_reason", {
            // user_delete writes NO receipt (DeleteReason::writes_receipt),
            // so it can never legitimately appear in one.
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(key, value)| {
                    if key.as_str() == Some("reason") {
                        (key, "user_delete".into())
                    } else {
                        (key, value)
                    }
                })
                .collect();
            encode_map(entries)
        }),
        ("free_text_in_scope_ids", {
            // Names/content in scope ids would smuggle personal data into an
            // immutable replicated audit record (GDPR Art. 5(2) minimization).
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(key, value)| {
                    if key.as_str() == Some("scope") {
                        (
                            key,
                            Value::Map(vec![
                                (
                                    "entity_ids".into(),
                                    Value::Array(vec!["Alice Smith — call her back".into()]),
                                ),
                                ("revision_ids".into(), Value::Array(vec![])),
                            ]),
                        )
                    } else {
                        (key, value)
                    }
                })
                .collect();
            encode_map(entries)
        }),
        ("free_text_in_verification", {
            // verification is pinned EMPTY until the audit-chain proof
            // schema exists: a populated map is an unvalidated content
            // channel into the immutable record — the same deleted text the
            // top-level rejection above catches must not pass when nested
            // here (the divergence gate would then PROTECT the forged
            // bytes).
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(key, value)| {
                    if key.as_str() == Some("verification") {
                        (
                            key,
                            Value::Map(vec![("proof".into(), "the deleted text".into())]),
                        )
                    } else {
                        (key, value)
                    }
                })
                .collect();
            encode_map(entries)
        }),
        ("scope_missing_revision_ids", {
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(key, value)| {
                    if key.as_str() == Some("scope") {
                        (
                            key,
                            Value::Map(vec![(
                                "entity_ids".into(),
                                Value::Array(vec![scope_hex.as_str().into()]),
                            )]),
                        )
                    } else {
                        (key, value)
                    }
                })
                .collect();
            encode_map(entries)
        }),
        ("nil_request_id", {
            let entries = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(key, value)| {
                    if key.as_str() == Some("request_id") {
                        (key, Value::Nil)
                    } else {
                        (key, value)
                    }
                })
                .collect();
            encode_map(entries)
        }),
        ("positional_array_encoding", {
            // The wire shape is a string-keyed map (the engine's
            // to_vec_named encoding); a positional array of the same ten
            // values is NOT the pinned shape.
            let values = receipt_body_entries(&scope_hex)
                .into_iter()
                .map(|(_, value)| value)
                .collect();
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &Value::Array(values)).unwrap();
            out
        }),
    ];

    let case_count = cases.len();
    for (name, body) in cases {
        let id = EntityId::now();
        let blob = receipt_envelope(LEARNED_AT, &body);
        insert_bytes(&entities, &id.to_hex(), &blob);
        doc.commit();

        assert!(
            vault.get_raw(&id).unwrap().is_none(),
            "{name}: malformed receipt must never be written to LMDB"
        );
        let records = quarantined_records(&vault).unwrap();
        let rec = record_for_key(&records, &id.to_hex())
            .unwrap_or_else(|| panic!("{name}: rejection must be quarantined, never silent"));
        assert_eq!(
            rec.reason_code, "InvalidRedactionReceiptBody",
            "{name}: typed reason"
        );
        assert_eq!(rec.container, QuarantineContainer::Entities, "{name}");
        assert_eq!(rec.window_key, WINDOW, "{name}");
        assert_eq!(
            rec.payload_hash,
            xxh3_64(&blob),
            "{name}: record carries the hash of the rejected envelope"
        );
    }
    assert_eq!(
        quarantined_records(&vault).unwrap().len(),
        case_count,
        "exactly one quarantine record per malformed blob"
    );
}

// ─── AC2 + AC5 (b) — divergent bytes for an existing receipt id ──────────────

/// AC2/AC5(b) — divergent remote bytes for an EXISTING receipt id are
/// quarantined at BOTH replay doors and the LOCAL bytes survive untouched
/// (immutable audit record — never silent LWW, never overwrite). Also pins
/// that a type-swap overwrite attempt (non-120 blob at the receipt id) is
/// rejected and quarantined, so receipts cannot be destroyed by re-typing.
#[test]
fn divergent_remote_receipt_bytes_quarantined_local_bytes_survive() {
    let (_dir, vault) = test_vault_with_dir();
    let (receipt_id, receipt_raw, window_key) = author_receipt(&vault);
    let receipt_hex = receipt_id.to_hex();
    let learned_at = vault.get_learned_at(&receipt_id).unwrap();

    // Door 1 — Observer B entity delta. The remote payload is WELL-FORMED
    // (passes the pinned receipt-body validation) but byte-divergent, so the
    // rejection below is the immutability gate, not the validator.
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, window_key.as_str());
    let divergent_body = encode_map(receipt_body_entries(&EntityId::now().to_hex()));
    let divergent_blob = receipt_envelope(learned_at, &divergent_body);
    assert_ne!(divergent_blob, receipt_raw, "precondition: bytes diverge");
    insert_bytes(&doc.get_map("entities"), &receipt_hex, &divergent_blob);
    doc.commit();

    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice()),
        "delta door: local receipt bytes must survive a divergent remote payload"
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let rec = record_for_key(&records, &receipt_hex).unwrap();
    assert_eq!(rec.reason_code, "RedactionReceiptDivergence");
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.payload_hash, xxh3_64(&divergent_blob));

    // Door 1, type-swap variant: a non-120 blob at the receipt id must not
    // re-type the record away (EntityTypeImmutable → quarantined).
    let mut impostor = Vec::new();
    impostor.push(1u8); // TURN
    impostor.extend_from_slice(&learned_at.to_be_bytes());
    impostor.extend_from_slice(&learned_at.to_be_bytes());
    impostor.extend_from_slice(&learned_at.to_be_bytes());
    impostor.extend_from_slice(b"impostor");
    insert_bytes(&doc.get_map("entities"), &receipt_hex, &impostor);
    doc.commit();

    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice()),
        "type-swap: local receipt bytes must survive"
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(
        record_for_key(&records, &receipt_hex).unwrap().reason_code,
        "EntityTypeImmutable"
    );

    // Door 2 — forward_rematerialize. Header-divergent variant: the SAME
    // body bytes under a shifted learned_at still diverge at the envelope
    // level and must quarantine, not overwrite (an implementation comparing
    // only bodies fails here).
    let header_divergent = receipt_envelope(learned_at + 1, &receipt_raw[25..]);
    assert_ne!(header_divergent, receipt_raw);
    let doc2 = create_window_doc("node-x", &window_key);
    insert_bytes(&doc2.get_map("entities"), &receipt_hex, &header_divergent);
    doc2.commit();
    let materializer2 = Materializer::new();
    forward_rematerialize(&vault, &doc2, &materializer2, &window_key).unwrap();

    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice()),
        "forward door: local receipt bytes must survive a divergent remote payload"
    );
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 3);
    let rec = record_for_key(&records, &receipt_hex).unwrap();
    assert_eq!(rec.reason_code, "RedactionReceiptDivergence");
    assert_eq!(rec.payload_hash, xxh3_64(&header_divergent));
}

/// AC1/AC5(a) forward door — a malformed type-120 blob arriving via
/// `forward_rematerialize` (startup CRDT→LMDB pass) is quarantined and
/// never written, mirroring the Observer B door.
#[test]
fn malformed_type_120_blob_via_forward_remat_is_quarantined_not_written() {
    let (_dir, vault) = test_vault_with_dir();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("node-x", &window_key);
    let id = EntityId::now();
    let blob = receipt_envelope(LEARNED_AT, b"not-a-receipt-body");
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    let materializer = Materializer::new();
    let count = forward_rematerialize(&vault, &doc, &materializer, &window_key).unwrap();
    assert_eq!(count, 0, "nothing materializes");
    assert!(vault.get_raw(&id).unwrap().is_none());

    let records = quarantined_records(&vault).unwrap();
    assert_eq!(records.len(), 1);
    let rec = record_for_key(&records, &id.to_hex()).unwrap();
    assert_eq!(rec.reason_code, "InvalidRedactionReceiptBody");
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.payload_hash, xxh3_64(&blob));
}

// ─── AC3 + AC5 (c) — byte-identical re-delivery is an idempotent no-op ───────

/// AC3/AC5(c) — byte-identical re-delivery of an existing receipt (the
/// own-receipt round-trip: a node's receipt mirrored to CRDT and echoed
/// back) is an idempotent accept at BOTH doors: no overwrite, no quarantine
/// record. This is the maintenance door the OWNER-DECISION keeps open —
/// `redaction_audit_receipt_survives_crdt_sync_round_trip` (sync_bridge)
/// stays green on top of it.
#[test]
fn byte_identical_receipt_redelivery_is_noop_without_quarantine() {
    let (_dir, vault) = test_vault_with_dir();
    let (receipt_id, receipt_raw, window_key) = author_receipt(&vault);
    let receipt_hex = receipt_id.to_hex();

    // Door 1 — Observer B entity delta with the exact local envelope bytes.
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, window_key.as_str());
    insert_bytes(&doc.get_map("entities"), &receipt_hex, &receipt_raw);
    doc.commit();

    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice())
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "delta door: byte-identical re-delivery must not quarantine"
    );

    // Door 2 — forward_rematerialize over a doc carrying the same bytes.
    let doc2 = create_window_doc("node-x", &window_key);
    insert_bytes(&doc2.get_map("entities"), &receipt_hex, &receipt_raw);
    doc2.commit();
    let materializer2 = Materializer::new();
    forward_rematerialize(&vault, &doc2, &materializer2, &window_key).unwrap();

    assert_eq!(
        vault.get_raw(&receipt_id).unwrap().as_deref(),
        Some(receipt_raw.as_slice())
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "forward door: byte-identical re-delivery must not quarantine"
    );
}

// ─── AC5 (d) — the accepted residual: forged-but-well-formed NEW receipts ────

/// AC5(d) — RESIDUAL RISK, ACCEPTED BY OWNER-DECISION (M4 unit 07, option
/// [a] "validate-and-accept-new"): a FORGED, well-formed NEW receipt from a
/// hostile peer IS admitted. Entity blobs carry no authorship at the Loro
/// layer (EntityMetadataHeader has no author field; Observer B filters only
/// origin == "bridge"), so a node's own-receipt round-trip and a remote
/// forgery are indistinguishable here — rejecting NEW receipts outright
/// would break legitimate cross-node receipt sync
/// (`redaction_audit_receipt_survives_crdt_sync_round_trip`).
///
/// Eliminating this residual requires origin attestation / a single-writer
/// lease on the audit stream (`ls:` keys per ARCH-0023b — "fail-closed ·
/// single-writer-leased"), which is M5-shaped machinery: ticketed as the M5
/// lease follow-up (option [b] of the A1-9 fork), deliberately NOT built in
/// M4. If this test starts failing because NEW receipts are rejected,
/// either the lease landed (update this test to forge a lease-signed
/// receipt) or someone closed the maintenance door and broke receipt sync —
/// check the round-trip test before "fixing" anything.
#[test]
fn forged_well_formed_new_receipt_is_accepted_residual_documented() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    // Forged: this vault never authored any receipt; the body is hand-built.
    let id = EntityId::now();
    let body = encode_map(receipt_body_entries(&EntityId::now().to_hex()));
    let blob = receipt_envelope(LEARNED_AT, &body);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    assert_eq!(
        vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice()),
        "well-formed NEW receipt must be accepted byte-identical (option [a])"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&id),
        "accepted receipt lands in the maintenance type index"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "acceptance is not a rejection — no quarantine record"
    );
}

// ─── AC4 — public write gate unchanged ───────────────────────────────────────

/// AC4 — the replay-door work must not loosen the PUBLIC write gate: a user
/// write of the maintenance band (type byte 120) still fails with
/// `MaintenanceKindNotWritable`, and nothing is written.
#[test]
fn public_write_gate_still_rejects_maintenance_band() {
    let (_dir, vault) = test_vault_with_dir();
    let id = EntityId::now();
    let err = vault
        .put_entity(
            &id,
            ENTITY_TYPE_REDACTION_AUDIT,
            TimeRange { start: 1, end: 1 },
            1,
            b"user-authored-receipt",
        )
        .unwrap_err();
    assert!(
        matches!(err, Error::MaintenanceKindNotWritable(120)),
        "public gate must still reject type 120, got: {err:?}"
    );
    assert!(vault.get_raw(&id).unwrap().is_none());
}
