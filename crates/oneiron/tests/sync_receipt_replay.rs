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
//! idempotent accept). The M4 residual — a well-formed FORGED NEW receipt
//! was admissible — is CLOSED by ONE-1140 (option [b]): a NEW receipt must
//! carry a valid Ed25519 origin attestation (OD-6) bound to a registered
//! device lease (`ls:` rows, OD-3/OD-4/OD-7) — see
//! `forged_new_receipt_without_valid_lease_attestation_is_quarantined`.
//!
//! Lives in its own integration binary (fresh process): the lib test binary
//! sits near a per-process LMDB env-open budget on macOS, and these tests
//! open one vault per scenario.

#![cfg(feature = "sync")]

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use loro::LoroDoc;
use oneiron::sync::bridge::{Materializer, register_observer_b};
use oneiron::sync::lease;
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

const TEST_LEASE_VAULT_ID: u64 = 0;
const OTHER_TEST_LEASE_VAULT_ID: u64 = 0x1110_0f0e_0d0c_0b0a;

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

// ─── ONE-1140 attestation forging kit (independent of the engine signer) ─────

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replaces the trailing empty `verification` entry with a hand-built
/// 4-entry att_ map (OD-6 literals, sorted key order).
fn with_att_entries(
    mut entries: Vec<(Value, Value)>,
    client_id: u64,
    pubkey_hex: &str,
    sig_hex: &str,
) -> Vec<(Value, Value)> {
    let last = entries.last_mut().expect("body entries non-empty");
    assert_eq!(last.0.as_str(), Some("verification"));
    last.1 = Value::Map(vec![
        ("att_client".into(), format!("{client_id:016x}").into()),
        ("att_pk".into(), pubkey_hex.into()),
        ("att_sig".into(), sig_hex.into()),
        ("att_v".into(), "1".into()),
    ]);
    entries
}

/// Forges a fully-signed receipt envelope per the OD-6 transcript, entirely
/// in the test (the contract, not the engine's signer): sign
/// `b"oneiron/receipt-att/v1" || receipt_id || header(25) || body-with-
/// verification-empty`, then splice the four att_ entries in.
fn signed_receipt_blob(
    signing_key: &SigningKey,
    client_id: u64,
    receipt_id: &EntityId,
    learned_at: u64,
    scope_hex: &str,
) -> Vec<u8> {
    let body_unsigned = encode_map(receipt_body_entries(scope_hex));
    let header = {
        let mut h = Vec::with_capacity(25);
        h.push(ENTITY_TYPE_REDACTION_AUDIT);
        h.extend_from_slice(&learned_at.to_be_bytes());
        h.extend_from_slice(&learned_at.to_be_bytes());
        h.extend_from_slice(&learned_at.to_be_bytes());
        h
    };
    let mut msg = Vec::new();
    msg.extend_from_slice(b"oneiron/receipt-att/v1");
    msg.extend_from_slice(receipt_id.as_bytes());
    msg.extend_from_slice(&header);
    msg.extend_from_slice(&body_unsigned);
    let sig = signing_key.sign(&msg);

    let body = encode_map(with_att_entries(
        receipt_body_entries(scope_hex),
        client_id,
        &hex_lower(&signing_key.verifying_key().to_bytes()),
        &hex_lower(&sig.to_bytes()),
    ));
    receipt_envelope(learned_at, &body)
}

/// Writes a hand-built `ls:` lease-registry row (the pinned 66 B OD-4
/// layout, assembled byte-by-byte in the test): `[ver 0x02][status]
/// [pubkey:32][granted:8 LE][renewed:8 LE][expires:8 LE][vault_id:8 BE]`.
fn register_lease_row(vault: &Vault, vault_id: u64, client_id: u64, pubkey: &[u8; 32], status: u8) {
    let mut record = Vec::with_capacity(66);
    record.push(0x02);
    record.push(status);
    record.extend_from_slice(pubkey);
    record.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    record.extend_from_slice(&1_700_000_000u64.to_le_bytes());
    record.extend_from_slice(&(1_700_000_000u64 + 7_776_000).to_le_bytes());
    record.extend_from_slice(&vault_id.to_be_bytes());
    assert_eq!(record.len(), 66, "OD-4 record length literal");
    vault
        .sync_state_put(&lease::lease_key(vault_id, client_id), &record)
        .unwrap();
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
    // (passes the pinned receipt-body validation, including the ONE-1140 v2
    // att_ grammar — the att values are grammar-valid garbage, which is
    // enough: the immutability gate runs BEFORE any crypto, so divergence
    // is the rejection below, not the validator and not the signature).
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, window_key.as_str());
    let divergent_body = encode_map(with_att_entries(
        receipt_body_entries(&EntityId::now().to_hex()),
        0xdead_beef_dead_beef,
        &"ab".repeat(32),
        &"cd".repeat(64),
    ));
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

// ─── ONE-1140 — the M4 residual is CLOSED: forged NEW receipts quarantine ────

/// ONE-1140 (closes the M4-07 option-[a] residual; delete-safety adjacent,
/// cap-exempt). A FORGED NEW receipt — well-formed, from a hostile peer —
/// is REJECTED at the Observer B door and quarantined (x: row, GDPR-inert
/// hash+len), never accepted, never silently dropped. Matrix per the old
/// escape hatch's own doc-comment ("update this test to forge a
/// lease-signed receipt"), reason-code literals per the OD-6/OD-7 door
/// order:
///
/// (i)   empty `verification` (the pre-1140 forgery) →
///       `InvalidRedactionReceiptBody` (validator v2);
/// (ii)  self-minted key, VALID signature, but no `ls:` row →
///       `ReceiptLeaseUnknown`;
/// (iii) registered client id claimed, garbage signature →
///       `ReceiptAttestationInvalid`;
/// (iv)  valid signed receipt TRANSPLANTED under a different entity id →
///       `ReceiptAttestationInvalid` (the transcript binds the id);
/// (v)   valid signature under key K2 claiming a client whose registry
///       binding is K1 → `ReceiptAttestationInvalid` (registry pubkey
///       wins).
///
/// Each case: nothing in LMDB, no type-index row, exactly one x: record
/// carrying the typed reason literal.
#[test]
fn forged_new_receipt_without_valid_lease_attestation_is_quarantined() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let scope_hex = EntityId::now().to_hex();

    let hostile_key = SigningKey::from_bytes(&[42u8; 32]);
    let hostile_client = 0x4242_4242_4242_4242u64;

    // (iii)/(v) need a REGISTERED binding to claim: client `bound_client`
    // is leased to `bound_key` (status active).
    let bound_key = SigningKey::from_bytes(&[9u8; 32]);
    let bound_client = 0x0909_0909_0909_0909u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        bound_client,
        &bound_key.verifying_key().to_bytes(),
        0x01,
    );

    // (case_name, target_id, blob, expected_reason)
    let mut cases: Vec<(&'static str, EntityId, Vec<u8>, &'static str)> = Vec::new();

    let id_i = EntityId::now();
    cases.push((
        "empty_verification_pre_1140_forgery",
        id_i,
        receipt_envelope(LEARNED_AT, &encode_map(receipt_body_entries(&scope_hex))),
        "InvalidRedactionReceiptBody",
    ));

    let id_ii = EntityId::now();
    cases.push((
        "valid_signature_unleased_client",
        id_ii,
        signed_receipt_blob(&hostile_key, hostile_client, &id_ii, LEARNED_AT, &scope_hex),
        "ReceiptLeaseUnknown",
    ));

    let id_iii = EntityId::now();
    cases.push((
        "registered_client_garbage_signature",
        id_iii,
        receipt_envelope(
            LEARNED_AT,
            &encode_map(with_att_entries(
                receipt_body_entries(&scope_hex),
                bound_client,
                &hex_lower(&bound_key.verifying_key().to_bytes()),
                &"cd".repeat(64),
            )),
        ),
        "ReceiptAttestationInvalid",
    ));

    // (iv): a receipt VALIDLY signed by the leased device for id A,
    // re-inserted under id B — the transcript binds the entity id.
    let id_a = EntityId::now();
    let id_iv = EntityId::now();
    let transplanted = signed_receipt_blob(&bound_key, bound_client, &id_a, LEARNED_AT, &scope_hex);
    cases.push((
        "valid_receipt_transplanted_under_other_id",
        id_iv,
        transplanted,
        "ReceiptAttestationInvalid",
    ));

    let id_v = EntityId::now();
    cases.push((
        "valid_signature_key_disagrees_with_registry_binding",
        id_v,
        signed_receipt_blob(&hostile_key, bound_client, &id_v, LEARNED_AT, &scope_hex),
        "ReceiptAttestationInvalid",
    ));

    let case_count = cases.len();
    for (name, id, blob, expected_reason) in cases {
        insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
        doc.commit();

        assert!(
            vault.get_raw(&id).unwrap().is_none(),
            "{name}: forged receipt must never be written to LMDB"
        );
        assert!(
            !vault
                .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
                .unwrap()
                .contains(&id),
            "{name}: forged receipt must not enter the maintenance type index"
        );
        let records = quarantined_records(&vault).unwrap();
        let rec = record_for_key(&records, &id.to_hex())
            .unwrap_or_else(|| panic!("{name}: rejection must be quarantined, never silent"));
        assert_eq!(rec.reason_code, expected_reason, "{name}: typed reason");
        assert_eq!(rec.container, QuarantineContainer::Entities, "{name}");
        assert_eq!(rec.window_key, WINDOW, "{name}");
        assert_eq!(rec.payload_hash, xxh3_64(&blob), "{name}: payload hash");
    }
    assert_eq!(
        quarantined_records(&vault).unwrap().len(),
        case_count,
        "exactly one quarantine record per forged receipt"
    );
}

/// ONE-1140 (OD-7; delete-safety adjacent, cap-exempt): the door enforces
/// lease STATUS only — `expired` (0x02) still accepts (devices have no
/// trustworthy shared clock; backdating defeats time bounds, residual R2),
/// `revoked` (0x03) rejects with `ReceiptLeaseRevoked` and quarantines.
///
/// Also pins the RULING C pubkey-floor NEGATIVE CONTROL: a receipt from a
/// DISTINCT active pubkey is accepted even with a revoked binding already in
/// the registry — the floor matches on PUBKEY equality, never on "any
/// revoked row present" nor on client_id (no over-reach).
#[test]
fn door_accepts_expired_rejects_revoked() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let scope_hex = EntityId::now().to_hex();

    // Expired binding (status byte 0x02) → accepted.
    let expired_key = SigningKey::from_bytes(&[11u8; 32]);
    let expired_client = 0x1111_1111_1111_1111u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        expired_client,
        &expired_key.verifying_key().to_bytes(),
        0x02,
    );
    let id_expired = EntityId::now();
    let blob_expired = signed_receipt_blob(
        &expired_key,
        expired_client,
        &id_expired,
        LEARNED_AT,
        &scope_hex,
    );
    insert_bytes(
        &doc.get_map("entities"),
        &id_expired.to_hex(),
        &blob_expired,
    );
    doc.commit();
    assert_eq!(
        vault.get_raw(&id_expired).unwrap().as_deref(),
        Some(blob_expired.as_slice()),
        "an EXPIRED lease still verifies at the door (OD-7: status only, no clock checks)"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "expired-lease acceptance is not a rejection"
    );

    // Revoked binding (status byte 0x03) → quarantined, terminal.
    let revoked_key = SigningKey::from_bytes(&[13u8; 32]);
    let revoked_client = 0x1313_1313_1313_1313u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        revoked_client,
        &revoked_key.verifying_key().to_bytes(),
        0x03,
    );
    let id_revoked = EntityId::now();
    let blob_revoked = signed_receipt_blob(
        &revoked_key,
        revoked_client,
        &id_revoked,
        LEARNED_AT,
        &scope_hex,
    );
    insert_bytes(
        &doc.get_map("entities"),
        &id_revoked.to_hex(),
        &blob_revoked,
    );
    doc.commit();
    assert!(
        vault.get_raw(&id_revoked).unwrap().is_none(),
        "a REVOKED lease must never admit new receipts"
    );
    let records = quarantined_records(&vault).unwrap();
    let rec = record_for_key(&records, &id_revoked.to_hex()).expect("quarantined, never silent");
    assert_eq!(rec.reason_code, "ReceiptLeaseRevoked");
    assert_eq!(rec.payload_hash, xxh3_64(&blob_revoked));

    // Negative control (RULING C — `door_floor_does_not_reject_distinct_
    // active_pubkey`): the pubkey floor matches on PUBKEY equality, NOT on
    // "any revoked row present" nor on client_id. A DISTINCT active pubkey is
    // accepted even though `revoked_key` above sits revoked in the registry.
    let distinct_key = SigningKey::from_bytes(&[17u8; 32]);
    let distinct_client = 0x1717_1717_1717_1717u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        distinct_client,
        &distinct_key.verifying_key().to_bytes(),
        0x01,
    );
    let q_before = quarantined_records(&vault).unwrap().len();
    let id_distinct = EntityId::now();
    let blob_distinct = signed_receipt_blob(
        &distinct_key,
        distinct_client,
        &id_distinct,
        LEARNED_AT,
        &scope_hex,
    );
    insert_bytes(
        &doc.get_map("entities"),
        &id_distinct.to_hex(),
        &blob_distinct,
    );
    doc.commit();
    assert_eq!(
        vault.get_raw(&id_distinct).unwrap().as_deref(),
        Some(blob_distinct.as_slice()),
        "a distinct active pubkey must not be rejected by the revoked-pubkey floor"
    );
    assert_eq!(
        quarantined_records(&vault).unwrap().len(),
        q_before,
        "accepting a distinct active pubkey adds no quarantine record"
    );
}

/// ONE-1190: the pubkey revocation floor is scoped to the claimed lease's
/// vault dimension. A revoked binding for the SAME pubkey in another vault
/// must not poison an independently leased active/expired row.
#[test]
fn revoked_pubkey_in_other_vault_does_not_reject_receipt() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let scope_hex = EntityId::now().to_hex();

    let key_p = SigningKey::from_bytes(&[29u8; 32]);
    let pubkey_p = key_p.verifying_key().to_bytes();
    let claimed_client = 0x2929_2929_2929_2929u64;
    let other_vault_client = 0x2929_2929_2929_0001u64;

    register_lease_row(&vault, TEST_LEASE_VAULT_ID, claimed_client, &pubkey_p, 0x02);
    register_lease_row(
        &vault,
        OTHER_TEST_LEASE_VAULT_ID,
        other_vault_client,
        &pubkey_p,
        0x03,
    );

    let id = EntityId::now();
    let blob = signed_receipt_blob(&key_p, claimed_client, &id, LEARNED_AT, &scope_hex);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    assert_eq!(
        vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice()),
        "a different-vault revoked binding for the same pubkey must not reject this receipt"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "accepted cross-vault non-match must not quarantine"
    );
}

/// ONE-1190 same-vault terminal regression: a revoked sibling for the same
/// pubkey still kills a fresh active client_id in that vault.
#[test]
fn revoked_pubkey_same_vault_still_terminal() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let scope_hex = EntityId::now().to_hex();

    let key_p = SigningKey::from_bytes(&[30u8; 32]);
    let pubkey_p = key_p.verifying_key().to_bytes();
    let revoked_client = 0x3030_3030_3030_0001u64;
    let claimed_client = 0x3030_3030_3030_0002u64;

    register_lease_row(&vault, TEST_LEASE_VAULT_ID, revoked_client, &pubkey_p, 0x03);
    register_lease_row(&vault, TEST_LEASE_VAULT_ID, claimed_client, &pubkey_p, 0x01);

    let id = EntityId::now();
    let blob = signed_receipt_blob(&key_p, claimed_client, &id, LEARNED_AT, &scope_hex);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "same-vault revoked pubkey must remain terminal"
    );
    let records = quarantined_records(&vault).unwrap();
    let rec = record_for_key(&records, &id.to_hex()).expect("quarantined, never silent");
    assert_eq!(rec.reason_code, "ReceiptLeaseRevoked");
    assert_eq!(rec.payload_hash, xxh3_64(&blob));
}

/// ONE-1140 RULING C (OD-8 amended, pubkey-bound; delete-safety adjacent,
/// cap-exempt): revocation binds to the Ed25519 PUBKEY, not the mintable
/// att_client. A receipt VALIDLY signed by a revoked pubkey is rejected at
/// the door even when the att_client it claims points at a FRESH, ACTIVE
/// `ls:` row — the rebind-under-a-new-client_id bypass that the
/// client_id-keyed kill switch missed. The floor scans the claimed vault's
/// `ls:` rows and rejects on pubkey equality with any same-vault revoked
/// binding. A plausible-wrong impl that only checks the claimed
/// `ls:{vault}:{B}` row (active) ACCEPTS and FAILS this test.
#[test]
fn revoked_pubkey_rebound_under_fresh_client_id_is_rejected_at_door() {
    let (_dir, vault) = test_vault_with_dir();
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    let scope_hex = EntityId::now().to_hex();

    // Pubkey P is revoked under the ORIGINAL client A …
    let key_p = SigningKey::from_bytes(&[31u8; 32]);
    let pubkey_p = key_p.verifying_key().to_bytes();
    let client_a = 0x3131_3131_3131_3131u64;
    register_lease_row(&vault, TEST_LEASE_VAULT_ID, client_a, &pubkey_p, 0x03);

    // … but the attacker re-registers the SAME key under a FRESH, never-seen
    // client B with an ACTIVE row (the bypass the client_id kill switch let
    // through).
    let client_b = 0x6262_6262_6262_6262u64;
    register_lease_row(&vault, TEST_LEASE_VAULT_ID, client_b, &pubkey_p, 0x01);

    let id = EntityId::now();
    let blob = signed_receipt_blob(&key_p, client_b, &id, LEARNED_AT, &scope_hex);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "a revoked pubkey must not admit a receipt by rebinding under a fresh client_id"
    );
    assert!(
        !vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&id),
        "the rejected receipt must not enter the maintenance type index"
    );
    let records = quarantined_records(&vault).unwrap();
    let rec = record_for_key(&records, &id.to_hex()).expect("quarantined, never silent");
    assert_eq!(rec.reason_code, "ReceiptLeaseRevoked");
    assert_eq!(rec.container, QuarantineContainer::Entities);
    assert_eq!(rec.window_key, WINDOW);
    assert_eq!(rec.payload_hash, xxh3_64(&blob));
}

/// ONE-1140/ONE-1190 fail-closed rider (delete-safety adjacent, cap-exempt):
/// the pubkey-revocation floor scans the claimed vault's `ls:` rows, so a
/// malformed same-vault sibling row (OUR mirror corruption, not remote bytes)
/// propagates fail-closed for the vault — never a best-effort skip. The error
/// is the LOCAL `CorruptedIndex`, which is NOT a remote rejection, so the
/// receipt is neither written nor quarantined.
#[test]
fn corrupt_sibling_ls_row_fails_door_closed() {
    let (_dir, vault) = test_vault_with_dir();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("node-x", &window_key);
    let scope_hex = EntityId::now().to_hex();

    // A VALID active binding for the receipt's author …
    let author_key = SigningKey::from_bytes(&[41u8; 32]);
    let author_client = 0x4141_4141_4141_4141u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        author_client,
        &author_key.verifying_key().to_bytes(),
        0x01,
    );
    // … plus a CORRUPT same-vault sibling `ls:` row (truncated below the
    // pinned 66 B).
    vault
        .sync_state_put(
            &lease::lease_key(TEST_LEASE_VAULT_ID, 0xdead_beef_dead_beefu64),
            b"too-short",
        )
        .unwrap();

    let id = EntityId::now();
    let blob = signed_receipt_blob(&author_key, author_client, &id, LEARNED_AT, &scope_hex);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    let materializer = Materializer::new();
    let err = forward_rematerialize(&vault, &doc, &materializer, &window_key)
        .expect_err("a corrupt sibling ls: row must fail the door closed, not skip");
    assert!(
        matches!(err, Error::CorruptedIndex(_)),
        "local mirror corruption propagates fail-closed, got: {err:?}"
    );
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "fail-closed: the receipt is not written"
    );
    assert!(
        record_for_key(&quarantined_records(&vault).unwrap(), &id.to_hex()).is_none(),
        "CorruptedIndex is LOCAL, never a remote quarantine"
    );
}

/// FED-005: hosted receipt replay must verify against the same nonzero
/// lease-vault scope that root grants mirror into `ls:{tenant}:{client}`.
/// This drives both production replay doors: live Observer B and startup
/// `forward_rematerialize`.
#[test]
fn nonzero_lease_vault_receipt_replay_doors_use_materializer_scope() {
    let (_dir, vault) = test_vault_with_dir();
    let tenant_vault = OTHER_TEST_LEASE_VAULT_ID;
    let author_key = SigningKey::from_bytes(&[61u8; 32]);
    let author_client = 0x6161_6161_6161_6161u64;
    register_lease_row(
        &vault,
        tenant_vault,
        author_client,
        &author_key.verifying_key().to_bytes(),
        0x01,
    );

    let observer_id = EntityId::now();
    let observer_blob = signed_receipt_blob(
        &author_key,
        author_client,
        &observer_id,
        LEARNED_AT,
        &EntityId::now().to_hex(),
    );
    let doc = LoroDoc::new();
    let materializer = Arc::new(Materializer::with_lease_vault_id(tenant_vault));
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);
    insert_bytes(
        &doc.get_map("entities"),
        &observer_id.to_hex(),
        &observer_blob,
    );
    doc.commit();

    assert_eq!(
        vault.get_raw(&observer_id).unwrap().as_deref(),
        Some(observer_blob.as_slice()),
        "Observer B must read the tenant-scoped lease row, not default vault 0"
    );

    let window_key = WindowKey::new(WINDOW);
    let remat_id = EntityId::now();
    let remat_blob = signed_receipt_blob(
        &author_key,
        author_client,
        &remat_id,
        LEARNED_AT,
        &EntityId::now().to_hex(),
    );
    let remat_doc = create_window_doc("node-x", &window_key);
    insert_bytes(
        &remat_doc.get_map("entities"),
        &remat_id.to_hex(),
        &remat_blob,
    );
    remat_doc.commit();

    let remat_materializer = Materializer::with_lease_vault_id(tenant_vault);
    let count = forward_rematerialize(&vault, &remat_doc, &remat_materializer, &window_key)
        .expect("forward remat must verify with the tenant-scoped lease row");
    assert_eq!(count, 1);
    assert_eq!(
        vault.get_raw(&remat_id).unwrap().as_deref(),
        Some(remat_blob.as_slice()),
        "forward remat must read the tenant-scoped lease row, not default vault 0"
    );
    assert!(
        quarantined_records(&vault).unwrap().is_empty(),
        "valid scoped receipts must not be quarantined as ReceiptLeaseUnknown"
    );
}

/// Claimed-row status has precedence over the pubkey floor: if the claimed
/// lease is revoked, the door returns the remote `ReceiptLeaseRevoked`
/// result before decoding any malformed sibling row in the scoped scan.
#[test]
fn revoked_claimed_row_precedes_scoped_floor_scan() {
    let (_dir, vault) = test_vault_with_dir();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("node-x", &window_key);
    let scope_hex = EntityId::now().to_hex();

    let author_key = SigningKey::from_bytes(&[45u8; 32]);
    let author_client = 0x4545_4545_4545_4545u64;
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        author_client,
        &author_key.verifying_key().to_bytes(),
        0x03,
    );
    vault
        .sync_state_put(
            &lease::lease_key(TEST_LEASE_VAULT_ID, 0x4545_4545_4545_0001u64),
            b"too-short",
        )
        .unwrap();

    let id = EntityId::now();
    let blob = signed_receipt_blob(&author_key, author_client, &id, LEARNED_AT, &scope_hex);
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();

    let materializer = Materializer::new();
    forward_rematerialize(&vault, &doc, &materializer, &window_key)
        .expect("claimed-row revoked path must return before the corrupt sibling scan");
    assert!(
        vault.get_raw(&id).unwrap().is_none(),
        "revoked claimed row rejects the receipt"
    );
    let records = quarantined_records(&vault).unwrap();
    let rec = record_for_key(&records, &id.to_hex()).expect("quarantined, never silent");
    assert_eq!(rec.reason_code, "ReceiptLeaseRevoked");
    assert_eq!(rec.payload_hash, xxh3_64(&blob));
}

/// ONE-1140 (OD-10; delete-safety adjacent, cap-exempt): lease-quarantined
/// receipts re-admit LAZILY — the rejected bytes stay in the CRDT map, and
/// the next `forward_rematerialize` re-runs the door after the `ls:` mirror
/// catches up. No new scheduling machinery; transient ordering races
/// (window update beats root update) self-heal.
#[test]
fn quarantined_receipt_readmitted_after_lease_lands() {
    let (_dir, vault) = test_vault_with_dir();
    let window_key = WindowKey::new(WINDOW);
    let doc = create_window_doc("node-x", &window_key);
    let materializer = Arc::new(Materializer::new());
    let _subs = register_observer_b(&doc, &vault, &materializer, WINDOW);

    let author_key = SigningKey::from_bytes(&[21u8; 32]);
    let author_client = 0x2121_2121_2121_2121u64;
    let id = EntityId::now();
    let blob = signed_receipt_blob(
        &author_key,
        author_client,
        &id,
        LEARNED_AT,
        &EntityId::now().to_hex(),
    );

    // Window update arrives BEFORE the lease registry row (the OD-10 race):
    // quarantined as ReceiptLeaseUnknown, bytes stay in the doc.
    insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob);
    doc.commit();
    assert!(vault.get_raw(&id).unwrap().is_none());
    let records = quarantined_records(&vault).unwrap();
    assert_eq!(
        record_for_key(&records, &id.to_hex()).unwrap().reason_code,
        "ReceiptLeaseUnknown"
    );

    // The lease mirror catches up…
    register_lease_row(
        &vault,
        TEST_LEASE_VAULT_ID,
        author_client,
        &author_key.verifying_key().to_bytes(),
        0x01,
    );

    // …and the next forward rematerialization re-admits byte-identically.
    let materializer2 = Materializer::new();
    let count = forward_rematerialize(&vault, &doc, &materializer2, &window_key).unwrap();
    assert!(count >= 1, "the re-run door must now admit the receipt");
    assert_eq!(
        vault.get_raw(&id).unwrap().as_deref(),
        Some(blob.as_slice()),
        "lazy re-admission must materialize the exact quarantined bytes (OD-10)"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_REDACTION_AUDIT)
            .unwrap()
            .contains(&id),
        "re-admitted receipt lands in the maintenance type index"
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
