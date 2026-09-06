use std::collections::BTreeMap;

use super::*;

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::registry::{
    ENTITY_TYPE_PERSON, ENTITY_TYPE_REGISTRY, EntityClassification, TypeByteZone,
    entity_type_registry_entry,
};
use crate::store::Store;
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
        let draft = event_for(input.scope_ref, first);
        vec![draft.clone(), draft]
    }
}

fn stored_body(vault: &Vault, id: &EntityId) -> Result<Vec<u8>> {
    let raw = vault.get_raw(id)?.expect("diagnostic entity is stored");
    let header = EntityMetadataHeader::parse(&raw).expect("entity header parses");
    assert_eq!(header.entity_type, ENTITY_TYPE_DIAGNOSTIC);
    Ok(raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
}

fn stored_header(vault: &Vault, id: &EntityId) -> Result<EntityMetadataHeader> {
    let raw = vault.get_raw(id)?.expect("diagnostic entity is stored");
    let header = EntityMetadataHeader::parse(&raw).expect("entity header parses");
    assert_eq!(header.entity_type, ENTITY_TYPE_DIAGNOSTIC);
    Ok(header)
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

// ── 1. every emitted event is fully typed ───────────────────────────────────

/// Done-means 1: an emitted event carries a closed class plus actor, source,
/// criticality, expected/actual/delta, replay coordinate, evidence refs, and
/// bitemporal validity — read back off disk, not off the draft.
#[test]
fn detector_emits_typed_event() -> Result<()> {
    let (_dir, vault) = open_vault();
    let observations = [observation(2, 1_000), observation(3, 2_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.gate14",
        observations: &observations,
    };
    let detector = StubDetector;
    let detectors: [&dyn DeterministicDetector; 1] = [&detector];

    let ids = run_deterministic_detectors(&vault, &input, &detectors)?;
    assert_eq!(ids.len(), 2, "one event per observation");

    for id in &ids {
        let event = decode_diagnostic_event_body(&stored_body(&vault, id)?)?;
        assert_eq!(event.event_class, DiagnosticEventClass::TestFailure);
        assert_eq!(event.actor_class, "system");
        assert!(event.actor_ref.is_some(), "actor is addressable");
        assert_eq!(event.source, DiagnosticSourceKind::Receipt);
        assert_eq!(event.criticality, DiagnosticCriticality::Normal);
        assert_eq!(event.expected, Value::from("green"));
        assert_eq!(event.actual, Value::from("red"));
        assert_eq!(event.delta, Value::Integer(Integer::from(1_u64)));
        assert_ne!(event.replay.content_hash, [0_u8; 32], "replay is addressed");
        assert_eq!(event.replay.run_ref.as_deref(), Some("scope.gate14"));
        assert_eq!(event.evidence_refs.len(), 1, "evidence is cited");
        assert!(event.valid_to.is_some_and(|end| end > event.valid_from));

        // The untrusted leaf arrived ESCAPED: the raw tab never reached disk.
        let detail = event.untrusted_detail.expect("untrusted detail survives");
        assert!(!detail.contains('\t'), "raw control data must not persist");
        assert!(detail.contains("\\u{0009}"), "control data is escaped");
    }
    Ok(())
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
        let stub_id = diagnostic_event_id("test.stub_detector", &left);
        let double_id = diagnostic_event_id("test.double_detector", &left);
        assert_ne!(stub_id, double_id, "detector identity separates ids");
        assert!(*id == stub_id || *id == double_id, "id derives from body");
    }
    Ok(())
}

/// The working-set order is CHECKED, never imposed: a caller that hands over an
/// unsorted slice gets a rejection instead of a deterministic-looking result
/// built on a non-deterministic read.
#[test]
fn working_set_order_is_checked_not_imposed() {
    let (_dir, vault) = open_vault();
    let descending = [observation(3, 2_000), observation(2, 1_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.gate14",
        observations: &descending,
    };
    let detector = StubDetector;
    let detectors: [&dyn DeterministicDetector; 1] = [&detector];

    let err = run_deterministic_detectors(&vault, &input, &detectors)
        .expect_err("an unsorted working set must be rejected");
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);

    // A duplicated observation is not ascending either: the pinned key is
    // strict, so the same fact cannot appear twice and double-count.
    let duplicated = [observation(2, 1_000), observation(2, 1_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.gate14",
        observations: &duplicated,
    };
    assert!(run_deterministic_detectors(&vault, &input, &detectors).is_err());
}

// ── 3. detection has no repair path ─────────────────────────────────────────

/// Done-means 3: a detector run writes DIAGNOSTIC entities and NOTHING else.
/// It does not propose, authorize or apply a repair — there is no repair type
/// to write — and it does not mutate the records it observed.
#[test]
fn no_repair_side_effect() -> Result<()> {
    let (_dir, vault) = open_vault();

    let observed = seed_id(2);
    vault.put_entity(&observed, ENTITY_TYPE_PERSON, at(1_000), 1_001, b"observed")?;
    let before_bytes = vault.get(&observed)?.expect("observed record exists");
    let before = type_census(&vault)?;

    let observations = [observation(2, 1_000), observation(3, 2_000)];
    let input = DiagnosticWorkingSet {
        scope_ref: "scope.gate14",
        observations: &observations,
    };
    let detector = StubDetector;
    let detectors: [&dyn DeterministicDetector; 1] = [&detector];
    let ids = run_deterministic_detectors(&vault, &input, &detectors)?;

    let after = type_census(&vault)?;
    let observed_now = vault.get(&observed)?.expect("observed record survives");
    assert_eq!(observed_now, before_bytes, "observed record not mutated");

    let mut bytes: Vec<u8> = before.keys().copied().collect();
    bytes.extend(after.keys().copied());
    bytes.sort_unstable();
    bytes.dedup();
    for byte in bytes {
        let was = before.get(&byte).copied().unwrap_or(0);
        let now = after.get(&byte).copied().unwrap_or(0);
        if byte == ENTITY_TYPE_DIAGNOSTIC {
            assert_eq!(now, was + ids.len(), "only diagnostics were added");
        } else {
            assert_eq!(now, was, "byte {byte} population must not change");
        }
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
    let id = seed_id(4);
    let body = encode_diagnostic_event_body(&sample_event())?;

    let err = vault
        .put_entity(&id, ENTITY_TYPE_DIAGNOSTIC, at(1_000), 1_001, &body)
        .expect_err("a public put of byte 69 must fail");
    let expected = ENTITY_TYPE_DIAGNOSTIC;
    assert!(matches!(err, Error::MaintenanceKindNotWritable(b) if b == expected));
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
    assert!(matches!(err, Error::MaintenanceKindNotWritable(b) if b == expected));
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

/// An event that is STILL valid is written as an open interval, not as an
/// instant. `valid_to = None` means "has not ended", so it indexes to the
/// repo's open-ended `u64::MAX`; collapsing it to `[valid_from, valid_from]`
/// made every still-open failure invisible to a temporal read anchored after
/// the moment it was noticed, which is every read of it. A closed event keeps
/// its declared end.
#[test]
fn open_validity_indexes_as_an_open_interval() -> Result<()> {
    let (_dir, vault) = open_vault();

    let mut open = sample_event();
    open.valid_to = None;
    let open_id = seed_id(7);
    vault.emit_diagnostic_event(&open_id, &open)?;

    let closed = sample_event();
    let closed_end = closed.valid_to.expect("the sample event is closed");
    let closed_id = seed_id(8);
    vault.emit_diagnostic_event(&closed_id, &closed)?;

    let open_header = stored_header(&vault, &open_id)?;
    assert_eq!(open_header.occurred_start, open.valid_from);
    assert_eq!(
        open_header.occurred_end,
        u64::MAX,
        "an absent valid_to means still valid, not valid for an instant"
    );

    let closed_header = stored_header(&vault, &closed_id)?;
    assert_eq!(closed_header.occurred_start, closed.valid_from);
    assert_eq!(
        closed_header.occurred_end, closed_end,
        "a closed event is unchanged"
    );

    // `pipeline::channels` picks up a spanning interval when the row's end is
    // beyond the query window and its start is before it. Take a window that
    // opens a day AFTER valid_from: the open event satisfies both halves and
    // is found, which is precisely the read the point spelling missed.
    let window_start = open.valid_from + 86_400;
    let window_end = window_start + 86_400;
    let open_end = open_header.occurred_end;
    assert!(
        open_header.occurred_start < window_start && open_end > window_end,
        "an open event must span a window that opens after valid_from"
    );

    let rtxn = vault.store.env.read_txn()?;
    let open_key = Store::encode_temporal_key(open_end, &open_id);
    assert_eq!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &open_key)?
            .as_deref(),
        Some(&open.valid_from.to_be_bytes()[..]),
        "the open event must be indexed as a spanning interval"
    );

    let closed_key = Store::encode_temporal_key(closed_end, &closed_id);
    assert!(
        vault
            .store
            .temporal_long_intervals
            .get(&rtxn, &closed_key)?
            .is_none(),
        "a 60-second closed event is not a spanning interval"
    );
    Ok(())
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

/// The untrusted leaf is escaped ONCE, at the raw author door, and is TERMINAL
/// once stored: decode hands it back escaped and the stored door re-encodes it
/// without touching it, so a stored diagnostic keeps its content address
/// across a read/write round trip.
#[test]
fn stored_untrusted_leaf_is_terminal() {
    let mut event = sample_event();
    event.untrusted_detail = Some("tab\there and a \\ slash".to_owned());
    let once = encode_diagnostic_event_body(&event).expect("first encode");
    let decoded = decode_diagnostic_event_body(&once).expect("first decode");
    let twice = encode_stored_diagnostic_event_body(&decoded).expect("stored re-encode");
    assert_eq!(once, twice, "the canonical body is a fixed point");
    validate_diagnostic_event_body_bytes(&once).expect("the canonical body is accepted");

    let detail = decoded.untrusted_detail.expect("detail survives");
    assert!(!detail.contains('\t'), "the raw tab is gone");
    assert!(detail.contains("\\u{0009}"), "the tab is visibly escaped");
    assert!(detail.contains("\\\\"), "the literal backslash is escaped");
}

/// Escaping is TOTAL, so it is injective: a RAW control scalar and the literal
/// text of its escape are two different findings and must not be able to
/// collide on one stored body and one content-addressed id. A passthrough for
/// already-escaped-looking input is exactly how they would collide, so there
/// is none.
#[test]
fn raw_control_and_literal_escape_text_do_not_collide() {
    let detector = "test.stub_detector";

    let mut raw_tab = sample_event();
    raw_tab.untrusted_detail = Some("a\tb".to_owned());
    let mut escape_text = sample_event();
    // The eight literal characters `\u{0009}`, not a tab.
    escape_text.untrusted_detail = Some("a\\u{0009}b".to_owned());

    let tab_body = encode_diagnostic_event_body(&raw_tab).expect("raw tab encodes");
    let text_body = encode_diagnostic_event_body(&escape_text).expect("escape text encodes");
    assert_ne!(tab_body, text_body, "distinct inputs, distinct bodies");
    assert_ne!(
        diagnostic_event_id(detector, &tab_body),
        diagnostic_event_id(detector, &text_body),
        "distinct bodies, distinct event ids"
    );

    // Both are canonical, and each round-trips back to the leaf it names: the
    // tab is escaped, and the input that already looked escaped has its
    // backslash escaped instead of being waved through.
    for (body, expected) in [(&tab_body, "a\\u{0009}b"), (&text_body, "a\\\\u{0009}b")] {
        validate_diagnostic_event_body_bytes(body).expect("canonical body is accepted");
        let decoded = decode_diagnostic_event_body(body).expect("body decodes");
        assert_eq!(decoded.untrusted_detail.as_deref(), Some(expected));
        assert_eq!(
            encode_stored_diagnostic_event_body(&decoded).expect("stored re-encode"),
            *body,
            "the stored leaf is terminal"
        );
    }
}

/// A content address has to pin BYTES, not just values: the write door
/// re-encodes what it decoded and demands byte equality, so a body that means
/// the right thing in the wrong spelling — re-ordered keys, a wider
/// MessagePack marker than the value needs, an uppercase ref — is refused
/// instead of being stored as a second byte string for one event.
#[test]
fn non_canonical_spellings_are_refused() {
    let canonical = encode_diagnostic_event_body(&sample_event()).expect("sample encodes");
    validate_diagnostic_event_body_bytes(&canonical).expect("the canonical body is accepted");

    // 1. Re-ordered keys: the same 16 pairs, spelled in a different order.
    let mut entries = body_entries(&canonical);
    entries.swap(0, 1);
    let reordered = encode_entries(entries);
    assert_ne!(reordered, canonical, "the fixture really is re-ordered");
    assert_rejected(&reordered, "re-ordered body keys");
    assert_eq!(
        validate_diagnostic_event_body_bytes(&reordered)
            .expect_err("re-ordered keys must be refused")
            .kind(),
        ErrorKind::InvalidDiagnosticBody
    );

    // 2. An alternate wire marker: `schema_version`'s 1 written as a uint8
    // (0xCC 0x01) instead of the positive fixint it canonically is. This
    // decodes to the same value, so only the byte-equality gate catches it.
    let mut key_bytes = Vec::new();
    rmpv::encode::write_value(&mut key_bytes, &Value::from("schema_version")).expect("key encodes");
    let at = canonical
        .windows(key_bytes.len())
        .position(|window| window == key_bytes)
        .expect("the schema_version key is present")
        + key_bytes.len();
    assert_eq!(canonical[at], 0x01, "1 is canonically a positive fixint");
    let mut wide_marker = canonical[..at].to_vec();
    wide_marker.extend_from_slice(&[0xCC, 0x01]);
    wide_marker.extend_from_slice(&canonical[at + 1..]);
    assert_ne!(wide_marker, canonical, "the fixture really is re-marked");
    decode_diagnostic_event_body(&wide_marker).expect("a marker alias still decodes");
    assert_eq!(
        validate_diagnostic_event_body_bytes(&wide_marker)
            .expect_err("an alternate wire marker must be refused")
            .kind(),
        ErrorKind::InvalidDiagnosticBody
    );

    // 3. Uppercase refs: `EntityId::from_hex` is case-insensitive, so decode
    // pins the lowercase spelling itself rather than leaning on the gate.
    // Seed 0xAB, so the hex actually carries letters to upcase.
    let lettered = seed_id(0xAB).to_hex();
    let shouted = lettered.to_uppercase();
    assert_ne!(lettered, shouted, "the fixture ref really has letters");

    let mut entries = body_entries(&canonical);
    set_key(&mut entries, "actor_ref", Value::from(shouted.clone()));
    assert_rejected(&encode_entries(entries), "an uppercase actor ref");

    let mut entries = body_entries(&canonical);
    set_key(
        &mut entries,
        "evidence_refs",
        Value::Array(vec![Value::from(shouted)]),
    );
    assert_rejected(&encode_entries(entries), "an uppercase evidence ref");
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

// ── 6. the byte is registered exactly once ──────────────────────────────────

/// Done-means 6: `ENTITY_TYPE_DIAGNOSTIC = 69` is registered exactly once as a
/// Maintenance/System kind with no short-id prefix, and no other byte is
/// allocated or renumbered. 72 stays a canon reserve because a suspicious wake
/// is an event CLASS here, and 126/127 stay unregistered.
#[test]
fn registry_registers_diagnostic_once() {
    assert_eq!(ENTITY_TYPE_DIAGNOSTIC, 69, "canon byte-space v3 says 69");

    let mut rows = Vec::new();
    for entry in ENTITY_TYPE_REGISTRY {
        if entry.type_byte == ENTITY_TYPE_DIAGNOSTIC {
            rows.push(entry);
        }
    }
    assert_eq!(rows.len(), 1, "DIAGNOSTIC is registered exactly once");

    let entry = rows[0];
    assert_eq!(entry.kind, "DIAGNOSTIC");
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
    assert_eq!(entry.short_id_prefix, None, "no short-id prefix");
    assert!(entry.legacy_short_id_prefixes.is_empty());

    for reserved in [72_u8, 74, 75, 126, 127] {
        assert!(
            entity_type_registry_entry(reserved).is_none(),
            "byte {reserved} must stay unregistered by this feature"
        );
    }
    assert!(DiagnosticEventClass::all().contains(&DiagnosticEventClass::SuspiciousWake));
}

// ── vocabulary pins ─────────────────────────────────────────────────────────

/// The `actor_class` vocabulary IS the Gate's, not a second one invented here.
#[test]
fn actor_class_vocabulary_tracks_the_gate() {
    let gate = [
        EdgeActorClass::Human,
        EdgeActorClass::Agent,
        EdgeActorClass::System,
    ];
    for class in gate {
        let spelling = class.gate_actor_class();
        assert!(
            DIAGNOSTIC_ACTOR_CLASSES.contains(&spelling),
            "gate actor class {spelling} is missing from the diagnostic set"
        );
    }
    assert_eq!(DIAGNOSTIC_ACTOR_CLASSES.len(), gate.len());
}

/// Every wire spelling round-trips, and the key set stays the pinned 16.
#[test]
fn closed_vocabularies_round_trip() {
    for class in DiagnosticEventClass::all() {
        let parsed = DiagnosticEventClass::from_wire(class.as_str());
        assert_eq!(parsed, Some(class));
    }
    assert!(DiagnosticEventClass::from_wire("test_failure ").is_none());
    assert!(DiagnosticEventClass::from_wire("").is_none());

    for source in [
        DiagnosticSourceKind::Receipt,
        DiagnosticSourceKind::RetrievalTelemetry,
        DiagnosticSourceKind::DreamerEventDag,
        DiagnosticSourceKind::SelfReport,
    ] {
        let parsed = DiagnosticSourceKind::from_wire(source.as_str());
        assert_eq!(parsed, Some(source));
    }
    for level in [
        DiagnosticCriticality::Normal,
        DiagnosticCriticality::Critical,
    ] {
        let parsed = DiagnosticCriticality::from_wire(level.as_str());
        assert_eq!(parsed, Some(level));
    }

    assert_eq!(DIAGNOSTIC_BODY_KEYS.len(), 16);
    let mut unique: Vec<&str> = DIAGNOSTIC_BODY_KEYS.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), DIAGNOSTIC_BODY_KEYS.len(), "keys distinct");
    assert_eq!(DIAGNOSTIC_SCHEMA_VERSION, 1);
}
