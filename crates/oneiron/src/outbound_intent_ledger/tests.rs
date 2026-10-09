use std::collections::HashSet;

use crate::config::VaultConfig;

use super::*;

const AUTHORIZATION: OutboundAuthorizationBinding = OutboundAuthorizationBinding::new([0xA5; 32]);

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn attempt(byte: u8) -> AttemptId {
    AttemptId::from_bytes(&[byte; 16]).expect("attempt id")
}

fn descriptor(
    read_only_hint: Option<bool>,
    idempotency_supported_hint: Option<bool>,
) -> OutboundToolDescriptor {
    OutboundToolDescriptor {
        read_only_hint,
        idempotency_supported_hint,
    }
}

fn request(
    attempt_id: AttemptId,
    call_seq: u64,
    payload: &[u8],
    now_ms: u64,
) -> OutboundCallRequest {
    OutboundCallRequest::new(
        attempt_id,
        call_seq,
        "test-server",
        "test-tool",
        payload.to_vec(),
        now_ms,
    )
    .with_authorization_binding(AUTHORIZATION)
}

fn persist_pending(
    vault: &Vault,
    attempt_id: AttemptId,
    call_seq: u64,
    payload: &[u8],
    now_ms: u64,
    idempotency_supported: bool,
) -> IntentLedgerRecord {
    let request = request(attempt_id, call_seq, payload, now_ms);
    let authorization_binding = request
        .authorization_binding
        .expect("test request authorization binding");
    let payload_hash = hash_frozen_payload(&request.payload);
    let intent_id = derive_intent_id(
        request.attempt_id,
        request.call_seq,
        &request.server,
        &request.tool,
        &payload_hash,
    )
    .expect("intent id");
    let call =
        FrozenOutboundCall::effectful(request, payload_hash, intent_id, idempotency_supported);
    let pending = IntentLedgerRecord {
        id: call.intent_id.expect("intent id"),
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload_hash: call.payload_hash,
        payload: call.payload.to_vec(),
        idempotency_key: call.idempotency_key.expect("idempotency key"),
        idempotency_supported,
        authorization_binding: Some(authorization_binding),
        admitted_approval: None,
        binding_version: OUTBOUND_BINDING_VERSION,
        resolved_endpoint: None,
        capability_provenance: None,
        budget_accounting: BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: now_ms,
        },
        recorded_outcome: None,
        delivery_uncertain: false,
        state: IntentState::Pending,
        created_ms: now_ms,
        updated_ms: now_ms,
    };
    let (record, replayed) = insert_pending_or_read(vault, &pending).expect("persist pending");
    assert!(!replayed);
    record
}

#[derive(Default)]
struct CountingSender {
    calls: usize,
    outcome: Option<OutboundSendOutcome>,
}

impl OutboundSender for CountingSender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.calls += 1;
        self.outcome.unwrap_or(OutboundSendOutcome::Acked)
    }
}

#[test]
fn deterministic_identity_changes_with_every_identity_input() {
    // Each stable identity input must change the digest, while identical
    // canonical inputs must produce exactly the same replay key.
    let attempt_id = attempt(8);
    let payload_hash = hash_frozen_payload(b"payload");
    let base = derive_intent_id(attempt_id, 3, "server", "tool", &payload_hash).expect("id");
    assert_eq!(
        base,
        derive_intent_id(attempt_id, 3, "server", "tool", &payload_hash).expect("same id")
    );

    let changed_payload_hash = hash_frozen_payload(b"changed");
    for changed in [
        derive_intent_id(attempt(9), 3, "server", "tool", &payload_hash).expect("attempt"),
        derive_intent_id(attempt_id, 4, "server", "tool", &payload_hash).expect("sequence"),
        derive_intent_id(attempt_id, 3, "other", "tool", &payload_hash).expect("server"),
        derive_intent_id(attempt_id, 3, "server", "other", &payload_hash).expect("tool"),
        derive_intent_id(attempt_id, 3, "server", "tool", &changed_payload_hash).expect("payload"),
    ] {
        assert_ne!(base, changed);
    }
}

#[test]
fn greenfield_row_rejects_every_missing_chokepoint_field() {
    let (_dir, vault) = open_vault();
    let pending = persist_pending(&vault, attempt(28), 0, b"strict greenfield", 100, true);
    let key = intent_ledger_key(&pending.id);
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let original = vault
        .store
        .vault_meta
        .get(&rtxn, &key)
        .expect("read canonical row")
        .expect("canonical row")
        .to_vec();
    drop(rtxn);

    for required_key in [
        KEY_BINDING_VERSION,
        KEY_RESOLVED_ENDPOINT,
        KEY_CAPABILITY_PROVENANCE,
        KEY_BUDGET_ACCOUNTING,
        KEY_RECORDED_OUTCOME,
        KEY_DELIVERY_UNCERTAIN,
    ] {
        let Value::Map(mut entries) =
            rmpv::decode::read_value(&mut std::io::Cursor::new(&original))
                .expect("decode canonical row")
        else {
            panic!("canonical row must be a map");
        };
        let original_len = entries.len();
        entries.retain(|(candidate, _)| candidate.as_str() != Some(required_key));
        assert_eq!(entries.len() + 1, original_len);
        let mut encoded = Vec::new();
        rmpv::encode::write_value(&mut encoded, &Value::Map(entries))
            .expect("encode missing-field row");
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .vault_meta
            .put(&mut wtxn, &key, &encoded)
            .expect("replace row");
        wtxn.commit().expect("commit missing-field row");
        // The audit listing is per row: the damaged row is reported as corrupt
        // with its exact key and typed error, and is never returned as valid.
        let listing = intent_ledger_records(&vault).expect("listing survives the damaged row");
        assert!(listing.is_empty(), "a damaged row is never listed as valid");
        assert_eq!(listing.corrupt.len(), 1);
        assert_eq!(&*listing.corrupt[0].key, key.as_slice());
        assert!(matches!(
            listing.corrupt[0].error,
            IntentLedgerError::InvalidRecord(_)
        ));
    }
}

#[test]
fn terminal_state_cannot_be_resurrected() {
    let (_dir, vault) = open_vault();
    let mut sender = CountingSender {
        calls: 0,
        outcome: Some(OutboundSendOutcome::Ambiguous),
    };
    let result = execute_outbound_call(
        &vault,
        descriptor(None, Some(false)),
        request(attempt(11), 0, b"effect", 100),
        &mut sender,
    )
    .expect("dispatch");
    let id = result.intent_id.expect("intent id");
    assert!(matches!(
        transition_record(&vault, id, IntentState::Done, 101),
        Err(IntentLedgerError::InvalidTransition {
            from: IntentState::Abandoned,
            to: IntentState::Done,
        })
    ));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].state, IntentState::Abandoned);

    sender.outcome = Some(OutboundSendOutcome::Acked);
    let done = execute_outbound_call(
        &vault,
        descriptor(None, Some(true)),
        request(attempt(11), 1, b"other effect", 102),
        &mut sender,
    )
    .expect("done dispatch");
    let done_id = done.intent_id.expect("done intent id");
    assert!(matches!(
        transition_record(&vault, done_id, IntentState::Pending, 103),
        Err(IntentLedgerError::InvalidTransition {
            from: IntentState::Done,
            to: IntentState::Pending,
        })
    ));
    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.state == IntentState::Done)
            .count(),
        1
    );
}

#[test]
fn debug_redacts_raw_payload_from_receipt_and_request() {
    let (_dir, vault) = open_vault();
    let secret: &[u8] = b"SECRET-charge-4242-body";
    let payload_debug = format!("{:?}", secret.to_vec());
    let mut sender = CountingSender::default();
    execute_outbound_call(
        &vault,
        descriptor(Some(false), Some(true)),
        request(attempt(19), 0, secret, 100),
        &mut sender,
    )
    .expect("dispatch");

    let records = intent_ledger_records(&vault).expect("records");
    assert_eq!(records.records.len(), 1);
    let record_debug = format!("{:?}", records.records[0]);
    assert!(!record_debug.contains("SECRET-charge-4242-body"));
    assert!(!record_debug.contains(&payload_debug));

    let request_debug = format!("{:?}", request(attempt(19), 0, secret, 100));
    assert!(!request_debug.contains("SECRET-charge-4242-body"));
    assert!(!request_debug.contains(&payload_debug));
}

// --- ONE-1885 typed capability provenance serialization ----------------------

fn capability_fixture() -> ScopedCapabilityProvenance {
    ScopedCapabilityProvenance::mint(
        "files",
        &EntityId::from_bytes([0x4D; 16]).expect("grant id"),
    )
    .expect("safe canonical scoped server")
}

fn capability_record(capability: ScopedCapabilityProvenance) -> IntentLedgerRecord {
    let mut request = request(attempt(31), 0, b"capability payload", 100);
    request.server = capability.server().to_owned();
    IntentLedgerRecord::pending(
        request
            .with_resolved_endpoint("https://files.example.test/mcp")
            .with_capability_provenance(capability),
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 100,
        },
    )
    .expect("pending record")
}

#[test]
fn capability_row_without_resolved_endpoint_is_rejected_before_recovery_send() {
    let (_dir, vault) = open_vault();
    let mut record = capability_record(capability_fixture());
    // Encode a reconstructed v3 row with a self-consistent digest, but with
    // the endpoint that the scoped writer always freezes removed. This bypasses
    // insertion validation so recovery must treat the row as corrupt rather
    // than allowing it to reach a sender.
    record.resolved_endpoint = None;
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode malformed capability row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("insert reconstructed row");
    wtxn.commit().expect("commit reconstructed row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0, "invalid capability row must never be sent");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.completed, 0);
    assert_eq!(recovery.pending, 0);
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some(record.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }]
    );
}

#[test]
fn endpoint_bound_row_without_capability_provenance_is_rejected_before_recovery_send() {
    let (_dir, vault) = open_vault();
    let mut record = capability_record(capability_fixture());
    // A reconstructed scoped row may retain its endpoint and binding while the
    // typed discriminator is missing. Encode a self-consistent row directly so
    // recovery must reject it before it can downgrade the call to ordinary.
    record.capability_provenance = None;
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode malformed capability row");
    let mut wtxn = vault.store.env.write_txn().expect("write transaction");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, &key, &encoded)
        .expect("insert reconstructed row");
    wtxn.commit().expect("commit reconstructed row");

    let mut sender = CountingSender::default();
    let recovery = recover_outbound_intents(&vault, &mut sender, 101).expect("recovery");
    assert_eq!(sender.calls, 0, "untyped scoped row must never be sent");
    assert_eq!(recovery.scanned, 1);
    assert_eq!(recovery.resent, 0);
    assert_eq!(recovery.completed, 0);
    assert_eq!(recovery.pending, 0);
    assert_eq!(
        recovery.escalations,
        vec![IntentEscalation {
            intent_id: Some(record.id),
            reason: IntentEscalationReason::CorruptLedgerRow,
        }]
    );
}

fn row_with_capability_value(encoded: &[u8], value: Value) -> Vec<u8> {
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).expect("decode canonical row")
    else {
        panic!("canonical row must be a map");
    };
    for (candidate, slot) in &mut entries {
        if candidate.as_str() == Some(KEY_CAPABILITY_PROVENANCE) {
            *slot = value.clone();
        }
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode tampered row");
    out
}

#[test]
fn capability_provenance_round_trips_and_fails_closed_when_forged() {
    let capability = capability_fixture();
    let record = capability_record(capability.clone());
    let key = intent_ledger_key(&record.id);
    let encoded = encode_record(&record).expect("encode capability row");
    let decoded = decode_record(&key, &encoded).expect("decode capability row");
    assert_eq!(decoded, record);
    assert_eq!(decoded.capability_provenance(), Some(&capability));

    // The typed server is part of the durable call identity. A valid capability
    // minted for another server cannot be transplanted onto this row.
    let mut mismatched_server = record;
    mismatched_server.capability_provenance = Some(
        ScopedCapabilityProvenance::mint("other", &capability.grant_id())
            .expect("safe canonical scoped server"),
    );
    let mismatched_encoded = encode_record(&mismatched_server).expect("encode mismatched row");
    assert!(matches!(
        decode_record(&key, &mismatched_encoded),
        Err(IntentLedgerError::InvalidRecord(_))
    ));

    // An ordinary row stays representable with no capability provenance at all.
    let (_dir, vault) = open_vault();
    let ordinary = persist_pending(&vault, attempt(32), 0, b"ordinary", 100, true);
    assert!(ordinary.capability_provenance().is_none());
    let ordinary_encoded = encode_record(&ordinary).expect("encode ordinary row");
    assert_eq!(
        decode_record(&intent_ledger_key(&ordinary.id), &ordinary_encoded).expect("decode"),
        ordinary
    );

    // The digest binds the typed field: stripping it to Nil is a different row.
    assert!(matches!(
        decode_record(&key, &row_with_capability_value(&encoded, Value::Nil)),
        Err(IntentLedgerError::InvalidRecord(_))
    ));

    // Malformed and unknown provenance forms fail closed, and so does any
    // internally inconsistent identity — a connector that is not EXACTLY what
    // (server, grant) mints can never be read back as a capability.
    let grant_id = capability.grant_id();
    let grant_value = || Value::Binary(grant_id.as_bytes().to_vec());
    for forged in [
        Value::from("mcp:files:grant:0"),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
            (Value::from("extra"), Value::Nil),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("Files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
        ]),
        Value::Map(vec![
            (Value::from(CAPABILITY_PROVENANCE_KEYS[0]), grant_value()),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from("mcp:other:grant:00112233445566778899aabbccddeeff"),
            ),
        ]),
        Value::Map(vec![
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[0]),
                Value::Binary(vec![0x4D; 8]),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[1]),
                Value::from("files"),
            ),
            (
                Value::from(CAPABILITY_PROVENANCE_KEYS[2]),
                Value::from(capability.connector()),
            ),
        ]),
    ] {
        assert!(
            matches!(
                decode_record(&key, &row_with_capability_value(&encoded, forged.clone())),
                Err(IntentLedgerError::InvalidRecord(_))
            ),
            "forged capability provenance {forged:?} must fail closed"
        );
    }
}

// --- ONE-1769 digest preimage, storage ABI, and tolerant listing -------------

/// Writes one raw `vault_meta` row, bypassing every encoder, so a former-format
/// or damaged row can be observed exactly as a crashed device would leave it.
fn put_raw_row(vault: &Vault, key: &[u8], row: &[u8]) {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .vault_meta
        .put(&mut wtxn, key, row)
        .expect("put raw row");
    wtxn.commit().expect("commit raw row");
}

fn raw_row(vault: &Vault, key: &[u8]) -> Vec<u8> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let raw = vault
        .store
        .vault_meta
        .get(&rtxn, key)
        .expect("read raw row")
        .expect("raw row exists")
        .to_vec();
    drop(rtxn);
    raw
}

fn row_entries(encoded: &[u8]) -> Vec<(Value, Value)> {
    let Value::Map(entries) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(encoded)).expect("decode row")
    else {
        panic!("an intent row must be a map");
    };
    entries
}

fn encode_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &Value::Map(entries)).expect("encode row");
    encoded
}

fn row_with_content_digest(encoded: &[u8], digest: [u8; 32]) -> Vec<u8> {
    let mut entries = row_entries(encoded);
    for (candidate, slot) in &mut entries {
        if candidate.as_str() == Some(KEY_CONTENT_DIGEST) {
            *slot = Value::Binary(digest.to_vec());
        }
    }
    encode_entries(entries)
}

#[test]
fn greenfield_row_rejects_non_boolean_delivery_uncertainty() {
    let (_dir, vault) = open_vault();
    let record = persist_pending(&vault, attempt(40), 0, b"uncertainty shape", 100, true);
    let key = intent_ledger_key(&record.id);
    let mut entries = row_entries(&raw_row(&vault, &key));
    let (_, value) = entries
        .iter_mut()
        .find(|(candidate, _)| candidate.as_str() == Some(KEY_DELIVERY_UNCERTAIN))
        .expect("pinned uncertainty key");
    *value = Value::from("true");
    let error = decode_record(&key, &encode_entries(entries))
        .expect_err("only a typed boolean can carry uncertainty");
    assert!(matches!(error, IntentLedgerError::InvalidRecord(_)));
}

#[test]
fn content_digest_is_hash_of_msgpack_minus_digest_key() {
    // The preimage IS the stored body minus one key. Rebuilding it here from
    // the persisted bytes — without calling the production digest — is what
    // catches a future second body representation.
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"digest preimage payload";
    let record = persist_pending(&vault, attempt(41), 0, payload, 100, true);
    let raw = raw_row(&vault, &intent_ledger_key(&record.id));

    let mut entries = row_entries(&raw);
    let stored_keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("row keys are strings"))
        .collect();
    assert_eq!(stored_keys, INTENT_LEDGER_VALUE_KEYS);

    let (digest_key, digest_value) = entries.pop().expect("the row carries a final entry");
    assert_eq!(digest_key.as_str(), Some(KEY_CONTENT_DIGEST));
    let Value::Binary(stored_digest) = digest_value else {
        panic!("the stored content digest must be binary");
    };
    assert_eq!(stored_digest.len(), 32);
    assert_eq!(entries.len(), 21);

    let preimage = encode_entries(entries);
    // A 21-entry map is `map16`: the map header itself is inside the preimage.
    assert_eq!(preimage[..3], [0xde, 0x00, 0x15]);
    let width = payload.len();
    assert!(
        preimage.windows(width).any(|window| window == payload),
        "the raw payload rides the preimage"
    );
    assert_eq!(blake3::hash(&preimage).as_bytes()[..], stored_digest[..]);
    assert_eq!(
        encode_record_digest_preimage(&record).expect("preimage"),
        preimage
    );
    assert_eq!(
        record_content_digest(&record).expect("digest")[..],
        stored_digest[..]
    );
}

/// Hand-typed storage ABI of one persisted intent row. These literals are
/// deliberately NOT read from `INTENT_LEDGER_VALUE_KEYS` or recomputed from the
/// encoder: producer and expectation must be able to disagree, or a co-drifting
/// change would rewrite both sides at once. Pre-launch, a deliberate ABI change
/// re-pins them with a stated rationale.
const GOLDEN_ROW_KEYS: [&str; 22] = [
    "schema_version",
    "id",
    "attempt_id",
    "call_seq",
    "server",
    "tool",
    "payload_hash",
    "payload",
    "idempotency_key",
    "idempotency_supported",
    "authorization_binding",
    "binding_version",
    "resolved_endpoint",
    "capability_provenance",
    "budget_accounting",
    "recorded_outcome",
    "delivery_uncertain",
    "state",
    "created_ms",
    "updated_ms",
    "admitted_approval",
    "content_digest",
];
const GOLDEN_ATTEMPT_BYTE: u8 = 0x2B;
const GOLDEN_CALL_SEQ: u64 = 7;
const GOLDEN_PAYLOAD: &[u8] = b"golden fixture payload";
const GOLDEN_NOW_MS: u64 = 1_700_000_000_000;
/// The identity this fixture's attempt, sequence, server, tool, and payload
/// hash derive, in lowercase hex.
const GOLDEN_INTENT_ID_HEX: &str =
    "311135d83a39aeef442248566c71583daf41968a7e78ca7688da8119259086d3";
/// BLAKE3 of the 21-entry MessagePack body of that row at schema version 3.
const GOLDEN_CONTENT_DIGEST_HEX: &str =
    "dbb70caa8e247714991d3bd22b2357677ecd472c9370bbedc603b4b4569e3d74";

#[test]
fn storage_abi_golden_fixture() {
    let (_dir, vault) = open_vault();
    let record = persist_pending(
        &vault,
        attempt(GOLDEN_ATTEMPT_BYTE),
        GOLDEN_CALL_SEQ,
        GOLDEN_PAYLOAD,
        GOLDEN_NOW_MS,
        true,
    );
    // Identity is pinned beside the row: the keyspace and the id it addresses
    // rows by cannot drift apart unnoticed.
    assert_eq!(
        derive_intent_id(
            attempt(GOLDEN_ATTEMPT_BYTE),
            GOLDEN_CALL_SEQ,
            "test-server",
            "test-tool",
            &hash_frozen_payload(GOLDEN_PAYLOAD),
        )
        .expect("golden identity"),
        record.id
    );
    assert_eq!(bytes_to_hex_lower(&record.id), GOLDEN_INTENT_ID_HEX);

    let entries = row_entries(&raw_row(&vault, &intent_ledger_key(&record.id)));
    let stored_keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("row keys are strings"))
        .collect();
    assert_eq!(stored_keys, GOLDEN_ROW_KEYS);
    let Some((_, Value::Binary(stored_digest))) = entries.last() else {
        panic!("the final entry is the binary content digest");
    };
    assert_eq!(bytes_to_hex_lower(stored_digest), GOLDEN_CONTENT_DIGEST_HEX);
}

#[test]
fn content_digest_is_stable_for_one_logical_record() {
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"stable digest payload";
    let persisted = persist_pending(&vault, attempt(42), 3, payload, 500, true);
    // Built through a different constructor, never read back from storage.
    let rebuilt = IntentLedgerRecord::pending(
        request(attempt(42), 3, payload, 500),
        true,
        BudgetChargeMarker {
            key_ref: None,
            budget_class: BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: 500,
        },
    )
    .expect("independently built record");
    assert_eq!(persisted, rebuilt);
    assert_eq!(
        encode_record_digest_preimage(&persisted).expect("persisted preimage"),
        encode_record_digest_preimage(&rebuilt).expect("rebuilt preimage")
    );
    assert_eq!(
        record_content_digest(&persisted).expect("persisted digest"),
        record_content_digest(&rebuilt).expect("rebuilt digest")
    );

    // Entry order in a raw row is not the canonical order: a reordered but
    // otherwise equivalent map decodes to the same record and re-encodes to the
    // same canonical bytes and digest.
    let key = intent_ledger_key(&persisted.id);
    let canonical = encode_record(&persisted).expect("encode canonical row");
    let mut entries = row_entries(&canonical);
    entries.reverse();
    let reordered = encode_entries(entries);
    assert_ne!(reordered, canonical);
    let decoded = decode_record(&key, &reordered).expect("a reordered row still decodes");
    assert_eq!(decoded, persisted);
    assert_eq!(encode_record(&decoded).expect("re-encode"), canonical);
    assert_eq!(
        record_content_digest(&decoded).expect("reordered digest"),
        record_content_digest(&persisted).expect("canonical digest")
    );
}

const OTHER_BINDING: OutboundAuthorizationBinding = OutboundAuthorizationBinding::new([0x5A; 32]);

/// Applies one mutation and re-establishes the identity fields it moves, so
/// every mutated fixture is still a row this engine could have written. A field
/// is digest-bound only if a row the engine ACCEPTS still gets another digest.
fn mutated(
    base: &IntentLedgerRecord,
    change: impl FnOnce(&mut IntentLedgerRecord),
) -> IntentLedgerRecord {
    let mut record = base.clone();
    change(&mut record);
    record.payload_hash = hash_frozen_payload(record.payload());
    record.id = derive_intent_id(
        record.attempt_id,
        record.call_seq,
        &record.server,
        &record.tool,
        &record.payload_hash,
    )
    .expect("mutated identity");
    record.idempotency_key = bytes_to_hex_lower(&record.id);
    record
}

#[test]
fn every_body_field_is_digest_bound() {
    let (_dir, vault) = open_vault();
    let base = persist_pending(&vault, attempt(50), 11, b"digest binding", 1_000, true);
    let capability = capability_fixture();
    let scoped = capability_record(capability.clone());
    let other_grant = EntityId::from_bytes([0x5E; 16]).expect("other grant id");
    let mail_base = mutated(&base, |record| {
        record.server = "email".into();
        record.tool = "send".into();
        record.payload = serde_json::to_vec(&serde_json::json!({
            "native_mail_recipient": true,
            "native_mail_logical_ref": "intent:golden-mail",
            "channel": "email", "verb": "send",
            "actor_ref": "11111111111111111111111111111111",
            "actor_entity_ref": "11111111111111111111111111111111",
            "channel_identity_ref": "22222222222222222222222222222222",
            "target": "new@example.test", "counterparty_ref": "new@example.test",
            "content_ref": "draft:golden", "job_ref": "brief:golden",
        }))
        .expect("canonical frozen mail payload");
    });

    // Fields coupled by validation move together; the case names the body keys
    // it moves so the table can prove it covers every one of them.
    let cases: Vec<(&str, Vec<&str>, IntentLedgerRecord, IntentLedgerRecord)> = vec![
        (
            "typed admitted approval",
            vec![KEY_ADMITTED_APPROVAL],
            mail_base.clone(),
            mutated(&mail_base, |record| {
                record.admitted_approval = Some(AdmittedApproval::from_gate(
                    record.id,
                    crate::channel_identity_provider::native_mail::approval_digest_from_frozen_payload(
                        record.payload(),
                    ).expect("canonical mail digest"),
                ));
            }),
        ),
        (
            "attempt_id",
            vec![KEY_ID, KEY_ATTEMPT_ID, KEY_IDEMPOTENCY_KEY],
            base.clone(),
            mutated(&base, |record| record.attempt_id = attempt(51)),
        ),
        (
            "call_seq",
            vec![KEY_CALL_SEQ],
            base.clone(),
            mutated(&base, |record| record.call_seq = 12),
        ),
        (
            "server",
            vec![KEY_SERVER],
            base.clone(),
            mutated(&base, |record| record.server = "other".to_owned()),
        ),
        (
            "tool",
            vec![KEY_TOOL],
            base.clone(),
            mutated(&base, |record| record.tool = "other".to_owned()),
        ),
        (
            "payload",
            vec![KEY_PAYLOAD, KEY_PAYLOAD_HASH],
            base.clone(),
            mutated(&base, |record| record.payload = b"other body".to_vec()),
        ),
        (
            "idempotency_supported",
            vec![KEY_IDEMPOTENCY_SUPPORTED],
            base.clone(),
            mutated(&base, |record| record.idempotency_supported = false),
        ),
        (
            "authorization_binding",
            vec![KEY_AUTHORIZATION_BINDING],
            base.clone(),
            mutated(&base, |record| {
                record.authorization_binding = Some(OTHER_BINDING);
            }),
        ),
        (
            "budget key_ref, matched_rows, and sends_debit",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.key_ref =
                    Some(EntityId::from_bytes([0x77; 16]).expect("budget key ref"));
                record.budget_accounting.matched_rows = vec![1, 2];
                record.budget_accounting.sends_debit = 1;
            }),
        ),
        (
            "budget_class",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.budget_class = BudgetClass::Operation;
            }),
        ),
        (
            "budget accounted_at_ms",
            vec![KEY_BUDGET_ACCOUNTING],
            base.clone(),
            mutated(&base, |record| {
                record.budget_accounting.accounted_at_ms = 2_000;
            }),
        ),
        (
            "delivery_uncertain",
            vec![KEY_DELIVERY_UNCERTAIN],
            base.clone(),
            mutated(&base, |record| record.delivery_uncertain = true),
        ),
        (
            "state and recorded_outcome",
            vec![KEY_STATE, KEY_RECORDED_OUTCOME],
            base.clone(),
            mutated(&base, |record| {
                record.state = IntentState::Done;
                record.recorded_outcome = Some(RecordedOutboundOutcome::Acked);
            }),
        ),
        (
            "created_ms",
            vec![KEY_CREATED_MS],
            base.clone(),
            mutated(&base, |record| record.created_ms = 900),
        ),
        (
            "updated_ms",
            vec![KEY_UPDATED_MS],
            base.clone(),
            mutated(&base, |record| record.updated_ms = 1_100),
        ),
        (
            "capability provenance stripped with its endpoint",
            vec![KEY_RESOLVED_ENDPOINT, KEY_CAPABILITY_PROVENANCE],
            scoped.clone(),
            mutated(&scoped, |record| {
                record.resolved_endpoint = None;
                record.capability_provenance = None;
            }),
        ),
        (
            "capability provenance swapped for another grant",
            vec![KEY_CAPABILITY_PROVENANCE],
            scoped.clone(),
            mutated(&scoped, |record| {
                record.capability_provenance = Some(
                    ScopedCapabilityProvenance::mint(capability.server(), &other_grant)
                        .expect("safe canonical scoped server"),
                );
            }),
        ),
    ];

    let mut covered: HashSet<&str> = HashSet::new();
    for (label, keys, case_base, case_mutated) in cases {
        for key in keys {
            assert!(
                INTENT_LEDGER_VALUE_KEYS[..21].contains(&key),
                "{label} names a key outside the digest preimage"
            );
            covered.insert(key);
        }
        let base_digest = record_content_digest(&case_base).expect("base digest");
        let moved_digest = record_content_digest(&case_mutated).expect("mutated digest");
        assert_ne!(base_digest, moved_digest, "{label} must move the digest");
        assert_ne!(
            encode_record_digest_preimage(&case_base).expect("base preimage"),
            encode_record_digest_preimage(&case_mutated).expect("moved preimage"),
            "{label} must move the digest preimage"
        );
        let key = intent_ledger_key(&case_mutated.id);
        let encoded = encode_record(&case_mutated).expect("encode mutated row");
        assert_eq!(
            decode_record(&key, &encoded).expect("the mutated row is itself valid"),
            case_mutated,
            "{label} must stay a row this engine could write"
        );
        let spliced = row_with_content_digest(&encoded, base_digest);
        assert!(
            matches!(
                decode_record(&key, &spliced),
                Err(IntentLedgerError::InvalidRecord(_))
            ),
            "{label} must fail decode once the unmutated digest is spliced in"
        );
    }

    // Keys 0 and 11 are digest-bound STRUCTURALLY, not mutationally: no valid
    // row can carry another schema_version or binding_version, so the fixture
    // pins their byte-exact preimage entries instead of mutating them.
    assert_eq!(INTENT_LEDGER_SCHEMA_VERSION, 3);
    assert_eq!(OUTBOUND_BINDING_VERSION, 2);
    let preimage = encode_record_digest_preimage(&base).expect("base preimage");
    for (key, value) in [("schema_version", 3_u64), ("binding_version", 2_u64)] {
        let mut entry = Vec::new();
        rmpv::encode::write_value(&mut entry, &Value::from(key)).expect("encode pinned key");
        rmpv::encode::write_value(&mut entry, &Value::from(value)).expect("encode pinned value");
        assert!(
            preimage
                .windows(entry.len())
                .any(|window| window == entry.as_slice()),
            "the preimage must carry a byte-exact ({key}, {value}) entry"
        );
    }

    let expected: HashSet<&str> = INTENT_LEDGER_VALUE_KEYS[..21]
        .iter()
        .copied()
        .filter(|key| *key != KEY_SCHEMA_VERSION && *key != KEY_BINDING_VERSION)
        .collect();
    assert_eq!(covered, expected, "every body key needs a mutation case");
    assert_eq!(covered.len(), 19, "21 body keys minus 2 structural ones");
}

#[test]
fn listing_storage_errors_stay_top_level_by_construction() {
    // Tolerance is for row damage, never for an unavailable substrate. The
    // guard is structural because the byte-identical iteration line also lives
    // in the recovery walks, so a whole-file `contains` would prove nothing —
    // and no LMDB fault-injection harness exists or is wanted.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/outbound_intent_ledger/dispatch.rs");
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("reading {} must succeed: {err}", path.display()));
    let iteration = "let (key, value) = row?;";
    assert!(
        src.matches(iteration).count() >= 2,
        "the recovery walks share this line, which is why the scan slices"
    );
    let start = src
        .find("\npub fn intent_ledger_records(")
        .expect("the listing must be findable by its signature")
        + 1;
    let end = start
        + src[start..]
            .find("\n}\n")
            .expect("the listing must terminate")
        + "\n}\n".len();
    let body = &src[start..end];
    assert!(
        body.contains("read_txn().map_err(Error::from)?"),
        "opening the read transaction stays a top-level error"
    );
    assert!(
        body.contains("ledger_rows(vault, &rtxn)?"),
        "creating the prefix iterator stays a top-level error"
    );
    let iteration_at = body
        .find(iteration)
        .expect("advancing a failed iterator stays a top-level error");
    let tolerance_at = body
        .find("match decode_record_in_txn(vault, &rtxn, &key, &value)")
        .expect("per-row tolerance must include attempt binding validation");
    assert!(
        body.contains("Err(error) => return Err(error)"),
        "index read failures stay top-level errors"
    );
    assert!(
        iteration_at < tolerance_at,
        "the storage error propagates BEFORE any per-row tolerance"
    );
}

#[test]
fn audit_and_authorized_recovery_isolate_broken_attempt_backlinks() {
    use crate::outbound_consent::{
        OutboundBindingAuthority, OutboundResultSender, OutboundTransportResult, RawOutboundResult,
        recover_authorized_outbound_intents,
    };

    #[derive(Default)]
    struct RecoverySender {
        calls: Vec<FrozenOutboundCall>,
    }

    impl OutboundResultSender for RecoverySender {
        fn send(&mut self, call: &FrozenOutboundCall) -> OutboundTransportResult {
            self.calls.push(call.clone());
            OutboundTransportResult {
                outcome: OutboundSendOutcome::Acked,
                raw_result: RawOutboundResult::new(None, None, None, None),
            }
        }
    }

    for missing in [true, false] {
        let (_dir, vault) = open_vault();
        // Use the ledger's bound Pending fixtures, not unbound connector rows
        // that the authorized sweep intentionally skips before Resume.
        let mut rows = [
            persist_pending(&vault, attempt(130), 0, b"index first", 100, true),
            persist_pending(&vault, attempt(131), 0, b"index second", 100, true),
        ];
        rows.sort_by_key(|record| record.id);
        let [bad, healthy] = rows;
        assert!(bad.authorization_binding.is_some());
        assert!(bad.id < healthy.id, "the bad row must precede the good row");
        let bad_key = intent_ledger_key(&bad.id);
        let original_bytes = raw_row(&vault, &bad_key);
        let index_key = intent_attempt_key(bad.attempt_id, bad.call_seq);
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        if missing {
            assert!(
                vault
                    .store
                    .vault_meta
                    .delete(&mut wtxn, &index_key)
                    .unwrap()
            );
        } else {
            // A correctly-sized pointer to ANOTHER valid row is still damage.
            vault
                .store
                .vault_meta
                .put(&mut wtxn, &index_key, &healthy.id)
                .unwrap();
        }
        wtxn.commit().expect("damage only the backlink");
        let decoded = decode_record(&bad_key, &original_bytes).unwrap();
        assert_eq!(decoded.id, bad.id);
        assert_eq!(decoded.payload(), bad.payload());
        assert!(matches!(decoded.state, IntentState::Pending));
        assert!(matches!(
            read_intent_record(&vault, &bad.id),
            Err(IntentLedgerError::InvalidRecord(_))
        ));
        let readable = read_intent_record(&vault, &healthy.id)
            .unwrap()
            .expect("healthy row remains readable");
        assert_eq!(readable.id, healthy.id);
        assert!(matches!(readable.state, IntentState::Pending));

        let listing = intent_ledger_records(&vault).expect("row-isolated audit");
        assert_eq!(listing.records.len(), 1);
        assert_eq!(listing.records[0].id, healthy.id);
        assert_eq!(listing.corrupt.len(), 1);
        assert_eq!(&*listing.corrupt[0].key, bad_key.as_slice());
        assert!(matches!(
            &listing.corrupt[0].error,
            IntentLedgerError::InvalidRecord(_)
        ));
        let entries = intent_recovery_entries(&vault).expect("row-isolated recovery entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|entry| matches!(
            entry,
            IntentRecoveryEntry::Corrupt(Some(id)) if *id == bad.id
        )));
        assert!(entries.iter().any(|entry| matches!(
            entry,
            IntentRecoveryEntry::Valid(record) if record.id == healthy.id
        )));

        let authority = OutboundBindingAuthority::for_vault(&vault).expect("authority");
        let mut sender = RecoverySender::default();
        let report =
            recover_authorized_outbound_intents(&vault, &authority, &mut sender, 200, 30_000)
                .expect("a corrupt first row must not abort the authorized sweep");
        assert_eq!(report.ledger.scanned, 2);
        assert_eq!(report.ledger.resent, 1);
        assert_eq!(report.ledger.completed, 1);
        assert_eq!(report.ledger.pending, 0);
        assert_eq!(report.effectful_sends, 1);
        assert_eq!(report.authorization_rejections, 0);
        assert!(report.ledger.failures.is_empty());
        assert_eq!(report.ledger.escalations.len(), 1);
        assert_eq!(report.ledger.escalations[0].intent_id, Some(bad.id));
        assert!(matches!(
            report.ledger.escalations[0].reason,
            IntentEscalationReason::CorruptLedgerRow
        ));
        assert_eq!(sender.calls.len(), 1);
        let call = &sender.calls[0];
        assert_eq!(call.intent_id(), Some(&healthy.id));
        assert_eq!(call.server(), healthy.server.as_str());
        assert_eq!(call.tool(), healthy.tool.as_str());
        assert_eq!(call.payload(), healthy.payload());
        assert_eq!(call.payload_hash(), &healthy.payload_hash);
        assert_eq!(
            call.idempotency_key(),
            Some(healthy.idempotency_key.as_str())
        );
        assert!(call.idempotency_supported());
        assert_eq!(call.authorization_binding(), Some(&AUTHORIZATION));
        assert_eq!(call.binding_version(), OUTBOUND_BINDING_VERSION);
        assert!(call.resolved_endpoint().is_none());
        assert!(call.capability_provenance().is_none());
        let after = intent_ledger_records(&vault).expect("audit after recovery");
        assert_eq!(after.records.len(), 1);
        assert_eq!(after.records[0].id, healthy.id);
        assert_eq!(after.records[0].state, IntentState::Done);
        assert_eq!(after.corrupt.len(), 1);
        assert_eq!(&*after.corrupt[0].key, bad_key.as_slice());
        assert!(matches!(
            &after.corrupt[0].error,
            IntentLedgerError::InvalidRecord(_)
        ));
        assert_eq!(raw_row(&vault, &bad_key), original_bytes);
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let index = vault.store.vault_meta.get(&rtxn, &index_key).unwrap();
        assert_eq!(
            index.as_deref(),
            (!missing).then_some(healthy.id.as_slice())
        );
    }
}

#[test]
fn strict_targeted_reads_remain_strict() {
    let (_dir, vault) = open_vault();
    let payload: &[u8] = b"strict target payload";
    let target = persist_pending(&vault, attempt(80), 0, payload, 100, true);
    let neighbour = persist_pending(&vault, attempt(81), 0, b"neighbour", 100, true);
    let key = intent_ledger_key(&target.id);
    let damaged = row_with_content_digest(&raw_row(&vault, &key), [0xEE; 32]);
    put_raw_row(&vault, &key, &damaged);

    assert!(matches!(
        read_intent_record(&vault, &target.id),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    assert!(matches!(
        transition_record(&vault, target.id, IntentState::Done, 101),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    // Replay re-reads the targeted row and refuses: listing tolerance is
    // observation, never execution authority.
    let mut sender = CountingSender::default();
    assert!(matches!(
        execute_outbound_call(
            &vault,
            descriptor(None, Some(true)),
            request(attempt(80), 0, payload, 102),
            &mut sender,
        ),
        Err(IntentLedgerError::InvalidRecord(_))
    ));
    assert_eq!(sender.calls, 0);

    let listing = intent_ledger_records(&vault).expect("listing");
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].id, neighbour.id);
    assert_eq!(listing.corrupt.len(), 1);
    assert_eq!(&*listing.corrupt[0].key, key.as_slice());
}
