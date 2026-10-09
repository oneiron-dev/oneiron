use std::collections::BTreeMap;

#[path = "admission_tests.rs"]
mod admission_tests;
#[path = "canonical_tests.rs"]
mod canonical_tests;
#[path = "repair/tests.rs"]
mod repair_tests;

use super::*;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::{ErrorKind, RegistryError};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::open_test_vault_with;

// ── fixtures ────────────────────────────────────────────────────────────────

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::default())
}

fn at(seconds: u64) -> TimeRange {
    TimeRange {
        start: seconds,
        end: seconds,
    }
}

fn seed_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("seeded id is not a reserved pattern")
}

fn observation(seed: u8, observed_at: u64) -> DiagnosticObservation {
    DiagnosticObservation {
        source_ref: seed_id(seed),
        kind: "receipt",
        payload_digest: [seed; 32],
        observed_at,
    }
}

/// The draft every fixture detector emits, so "same ordered input" is a
/// property of the OBSERVATION rather than of the detector's mood.
fn event_for(scope_ref: &str, observation: &DiagnosticObservation) -> DiagnosticEvent {
    DiagnosticEvent {
        detector_id: "test.stub_detector".to_owned(),
        event_class: DiagnosticEventClass::TestFailure,
        actor_class: "system".to_owned(),
        actor_ref: Some(observation.source_ref),
        source: DiagnosticSourceKind::Receipt,
        criticality: DiagnosticCriticality::Normal,
        expected: Value::from("green"),
        actual: Value::from("red"),
        delta: Value::Integer(Integer::from(1_u64)),
        replay: DiagnosticReplayCoordinate {
            content_hash: observation.payload_digest,
            run_ref: Some(scope_ref.to_owned()),
            checkpoint_ref: None,
        },
        evidence_refs: vec![observation.source_ref],
        untrusted_detail: Some("stderr said\tno".to_owned()),
        valid_from: observation.observed_at,
        valid_to: Some(observation.observed_at + 60),
    }
}

fn sample_event() -> DiagnosticEvent {
    event_for("scope.gate14", &observation(2, 1_000))
}

struct StubDetector;

impl DeterministicDetector for StubDetector {
    fn detector_id(&self) -> &'static str {
        "test.stub_detector"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        let mut drafts = Vec::new();
        for observation in input.observations {
            drafts.push(event_for(input.scope_ref, observation));
        }
        drafts
    }
}

/// Emits the SAME draft twice, so deduplication has something to do.
struct DoubleDetector;

impl DeterministicDetector for DoubleDetector {
    fn detector_id(&self) -> &'static str {
        "test.double_detector"
    }

    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent> {
        let Some(first) = input.observations.first() else {
            return Vec::new();
        };
        let mut draft = event_for(input.scope_ref, first);
        draft.detector_id = self.detector_id().to_owned();
        vec![draft.clone(), draft]
    }
}

fn stored_body(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let raw = vault.get_raw(id)?.expect("diagnostic entity is stored");
    let header = EntityMetadataHeader::parse(&raw).expect("entity header parses");
    assert_eq!(header.entity_type, ENTITY_TYPE_DIAGNOSTIC);
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}

fn type_census(vault: &Vault) -> Result<BTreeMap<u8, usize>> {
    let mut census = BTreeMap::new();
    for byte in 0..=u8::MAX {
        let count = vault.entities_by_type(byte)?.len();
        if count > 0 {
            census.insert(byte, count);
        }
    }
    Ok(census)
}

fn body_entries(bytes: &[u8]) -> Vec<(Value, Value)> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor).expect("fixture body decodes");
    match value {
        Value::Map(entries) => entries,
        other => panic!("fixture body must be a map, got {other:?}"),
    }
}

fn encode_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("fixture map encodes");
    out
}

fn set_key(entries: &mut [(Value, Value)], key: &str, value: Value) {
    for (entry_key, entry_value) in entries.iter_mut() {
        if entry_key.as_str() == Some(key) {
            *entry_value = value;
            return;
        }
    }
    panic!("key {key} is not a DIAGNOSTIC body key");
}

fn assert_rejected(bytes: &[u8], what: &str) {
    match decode_diagnostic_event_body(bytes) {
        Ok(_) => panic!("{what} must be rejected by DIAGNOSTIC decode"),
        Err(err) => assert_eq!(err.kind(), ErrorKind::InvalidDiagnosticBody, "{what}"),
    }
}

// ── 2. determinism ──────────────────────────────────────────────────────────

/// Done-means 2: the same scoped ordered working set and detector set produce
/// byte-identical canonical bodies, identical event ids, identical ordering,
/// and identical deduplication — across two independent vaults, so nothing
/// ambient (clock, insertion order, id minting) can be smuggled in.
#[test]
fn deterministic_detection() -> Result<()> {
    let observations = [observation(2, 1_000), observation(3, 2_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.gate14",
        observations: &observations,
    };
    let stub = StubDetector;
    let double = DoubleDetector;
    let detectors: [&dyn DeterministicDetector; 2] = [&stub, &double];

    let (_dir_a, vault_a) = open_vault();
    let first = run_deterministic_detectors(&vault_a, &input, &detectors)?;
    let (_dir_b, vault_b) = open_vault();
    let second = run_deterministic_detectors(&vault_b, &input, &detectors)?;

    assert_eq!(first, second, "ids and their order must be identical");
    // Stub emits one event per observation (2); Double emits the SAME draft
    // twice and must collapse to one. Four drafts, three persisted events.
    assert_eq!(first.len(), 3, "identical drafts must deduplicate");
    let ascending = first.windows(2).all(|pair| pair[0] < pair[1]);
    assert!(ascending, "ids must be returned sorted");

    for id in &first {
        let left = stored_body(&vault_a, id)?;
        let right = stored_body(&vault_b, id)?;
        assert_eq!(left, right, "canonical bodies must be byte-identical");

        // The id is a function of `(detector_id, canonical body)` and nothing
        // else, so it re-derives from the stored bytes alone. Folding the
        // detector id in is what keeps two detectors that observe the same
        // fact from overwriting each other's finding.
        let event = decode_diagnostic_event_body(&left)?;
        assert_eq!(*id, diagnostic_event_id(&event.detector_id, &left));
        assert_ne!(
            *id,
            diagnostic_event_id("another.detector", &left),
            "detector identity separates ids"
        );
    }
    Ok(())
}

// ── 4. only the engine-authored door writes byte 69 ─────────────────────────

/// Done-means 4: generic and public puts of byte 69 fail with
/// `MaintenanceKindNotWritable` on BOTH builder doors, write nothing, and are
/// not conflated with `InvalidEntityType`. The engine-authored door writes the
/// very same validated body.
#[test]
fn public_byte_69_put_rejected() -> Result<()> {
    let (_dir, vault) = open_vault();
    let event = sample_event();
    let body = encode_diagnostic_event_body(&event)?;
    let id = diagnostic_event_id(&event.detector_id, &body);

    let err = vault
        .put_entity(&id, ENTITY_TYPE_DIAGNOSTIC, at(1_000), 1_001, &body)
        .expect_err("a public put of byte 69 must fail");
    let expected = ENTITY_TYPE_DIAGNOSTIC;
    assert!(
        matches!(err, Error::Registry(RegistryError::MaintenanceKindNotWritable(b)) if b == expected)
    );
    assert_eq!(err.kind(), ErrorKind::MaintenanceKindNotWritable);
    assert_ne!(err.kind(), ErrorKind::InvalidEntityType);
    assert!(vault.get(&id)?.is_none(), "nothing was written");

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .put(&id, ENTITY_TYPE_DIAGNOSTIC, at(1_000), 1_001, &body)
                .apply(wtxn)
        })
        .expect_err("a txn-batch put of byte 69 must fail");
    assert!(
        matches!(err, Error::Registry(RegistryError::MaintenanceKindNotWritable(b)) if b == expected)
    );
    assert!(vault.get(&id)?.is_none(), "nothing was written");
    assert!(vault.entities_by_type(ENTITY_TYPE_DIAGNOSTIC)?.is_empty());

    // The one engine-authored door accepts the identical body.
    vault.emit_diagnostic_event(&id, &sample_event())?;
    assert_eq!(stored_body(&vault, &id)?, body);
    Ok(())
}

/// The maintenance band is a DOOR, not a hole: the write path validates the
/// pinned body grammar even when `allow_maintenance` is already open, so a
/// malformed byte-69 body cannot be staged by any caller inside the engine.
#[test]
fn maintenance_door_validates_the_body() {
    let (_dir, vault) = open_vault();

    // The door's own encode gate refuses a draft outside the vocabulary.
    let mut broken = sample_event();
    broken.actor_class = "root".to_owned();
    let err = vault
        .emit_diagnostic_event(&seed_id(5), &broken)
        .expect_err("an out-of-vocabulary actor_class must be refused");
    assert_eq!(err.kind(), ErrorKind::InvalidDiagnosticBody);

    // The apply-time arm refuses a malformed body even on the maintenance
    // band, which is the seam a future writer would otherwise slip through.
    let err = vault
        .with_write_txn(|wtxn| {
            apply_ops(
                &vault.store,
                &vault.config,
                &vault.analyzer,
                wtxn,
                vec![BatchOp::Put {
                    id: seed_id(6),
                    entity_type: ENTITY_TYPE_DIAGNOSTIC,
                    occurred: at(1_000),
                    learned_at: 1_001,
                    data: b"not-messagepack".to_vec(),
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                false,
                false,
                true,
            )
        })
        .expect_err("a malformed body must be refused at the apply door");
    assert_eq!(err.kind(), ErrorKind::InvalidDiagnosticBody);
    assert!(vault.get(&seed_id(6)).expect("read").is_none());
}

// ── 5. decode fails closed ──────────────────────────────────────────────────

/// Done-means 5/6: decode rejects unknown, missing and duplicate body keys,
/// trailing bytes, invalid enum strings, malformed refs and hashes,
/// non-monotonic validity, non-canonical invariant values and evidence order,
/// and control data hidden in the untrusted leaf.
#[test]
fn diagnostic_body_decode_fail_closed() {
    let canonical = encode_diagnostic_event_body(&sample_event()).expect("sample encodes");
    decode_diagnostic_event_body(&canonical).expect("the canonical body decodes");

    let mut entries = body_entries(&canonical);
    entries.push((Value::from("extra"), Value::from(1_u64)));
    assert_rejected(&encode_entries(entries), "an unknown body key");

    let mut entries = body_entries(&canonical);
    entries.retain(|(key, _)| key.as_str() != Some("delta"));
    assert_rejected(&encode_entries(entries), "a missing body key");

    let mut entries = body_entries(&canonical);
    let duplicate = entries[0].clone();
    entries.push(duplicate);
    assert_rejected(&encode_entries(entries), "a duplicate body key");

    let mut trailing = canonical.clone();
    trailing.push(0xC0);
    assert_rejected(&trailing, "trailing bytes after the body map");

    for (key, bad) in [
        ("event_class", "not_a_class"),
        ("source", "not_a_source"),
        ("criticality", "loud"),
        ("actor_class", "root"),
    ] {
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, key, Value::from(bad));
        assert_rejected(&encode_entries(entries), key);
    }

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "actor_ref", Value::from("nope"));
    assert_rejected(&encode_entries(entries), "a malformed actor ref");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "replay_content_hash", Value::from("ab"));
    assert_rejected(&encode_entries(entries), "a short content hash");

    let mut entries = body_entries(&canonical);
    let uppercase = Value::from("F".repeat(64));
    set_key(&mut entries, "replay_content_hash", uppercase);
    assert_rejected(&encode_entries(entries), "an uppercase content hash");

    let mut entries = body_entries(&canonical);
    let bad_ref = Value::Array(vec![Value::from("zz")]);
    set_key(&mut entries, "evidence_refs", bad_ref);
    assert_rejected(&encode_entries(entries), "a malformed evidence ref");

    let mut entries = body_entries(&canonical);
    let descending = Value::Array(vec![
        Value::from(seed_id(3).to_hex()),
        Value::from(seed_id(2).to_hex()),
    ]);
    set_key(&mut entries, "evidence_refs", descending);
    assert_rejected(&encode_entries(entries), "descending evidence refs");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "valid_to", Value::from(1_u64));
    assert_rejected(&encode_entries(entries), "non-monotonic validity");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "schema_version", Value::from(99_u64));
    assert_rejected(&encode_entries(entries), "an unsupported schema version");

    for hidden in [
        "bell \u{0007} rings",
        "override \u{202E} reversed",
        "zero \u{200B} width",
        "line \u{2028} separator",
        "raw \\ backslash",
    ] {
        let mut entries = body_entries(&canonical);
        set_key(&mut entries, "untrusted_detail", Value::from(hidden));
        assert_rejected(&encode_entries(entries), "control data in untrusted_detail");
    }

    let mut entries = body_entries(&canonical);
    let unsorted = Value::Map(vec![
        (Value::from("b"), Value::from(1_u64)),
        (Value::from("a"), Value::from(2_u64)),
    ]);
    set_key(&mut entries, "expected", unsorted);
    assert_rejected(&encode_entries(entries), "an unsorted invariant map");

    let mut entries = body_entries(&canonical);
    let raw_bytes = Value::Binary(vec![1, 2, 3]);
    set_key(&mut entries, "actual", raw_bytes);
    assert_rejected(&encode_entries(entries), "a binary invariant leaf");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "delta", Value::F64(f64::NAN));
    assert_rejected(&encode_entries(entries), "a non-finite invariant float");

    assert_rejected(b"", "an empty body");
    assert_rejected(&[0xC0], "a nil body");
}

/// Drafts are CANONICALIZED, so two detectors that mean the same thing produce
/// the same bytes: evidence refs are sorted and deduplicated, and an equivalent
/// invariant map spelled in a different key order collapses to one body.
#[test]
fn drafts_are_canonicalized_before_addressing() {
    let mut sorted = sample_event();
    sorted.evidence_refs = vec![seed_id(2), seed_id(3)];
    sorted.expected = Value::Map(vec![
        (Value::from("a"), Value::from(1_u64)),
        (Value::from("b"), Value::from(2_u64)),
    ]);

    let mut scrambled = sorted.clone();
    scrambled.evidence_refs = vec![seed_id(3), seed_id(2), seed_id(3)];
    scrambled.expected = Value::Map(vec![
        (Value::from("b"), Value::from(2_u64)),
        (Value::from("a"), Value::from(1_u64)),
    ]);

    let left = encode_diagnostic_event_body(&sorted).expect("sorted encodes");
    let right = encode_diagnostic_event_body(&scrambled).expect("scrambled encodes");
    assert_eq!(left, right, "canonicalization must erase draft spelling");
    let id = "test.stub_detector";
    let left_id = diagnostic_event_id(id, &left);
    let right_id = diagnostic_event_id(id, &right);
    assert_eq!(left_id, right_id, "one canonical body, one event id");
}
