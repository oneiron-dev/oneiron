//! NOTE body ABI: the pinned four keys, the closed kind, and the negative
//! set the decoder must fail closed on.

use rmpv::Value;

use super::*;

fn actor(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("actor id")
}

fn take(markdown: &str) -> NoteBody {
    NoteBody {
        kind: NoteKind::OpinionTake,
        author_ref: actor(0x7a),
        markdown: markdown.to_owned(),
        source_revision_ref: [0x42; 16],
    }
}

/// Encodes an arbitrary map so the negative cases can express bodies the
/// public encoder refuses to produce.
fn encode_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode map");
    out
}

#[test]
fn opinion_kind_round_trip() {
    // The wire literal IS the ABI — pinned here, not derived.
    assert_eq!(NoteKind::OpinionTake.as_str(), "opinion/take");
    assert_eq!(NoteKind::parse("opinion/take"), Some(NoteKind::OpinionTake));
    assert_eq!(
        NOTE_BODY_KEYS,
        ["kind", "author_ref", "markdown", "source_revision_ref"]
    );
    assert_eq!(NoteKind::parse("diary"), Some(NoteKind::Diary));

    let body = take("Disagree: the source predates the merger.");
    let decoded = decode_note_body(&encode_note_body(&body).expect("encode")).expect("decode");
    assert_eq!(decoded, body);

    // Unknown kinds fail closed — the remaining ARCH-0032 kinds are not
    // implemented, so they must not decode as anything.
    for unknown in [
        "scratchpad",
        "observation",
        "handoff",
        "research",
        "reflection",
        "plugin/",
        "OPINION/TAKE",
        "",
    ] {
        assert_eq!(NoteKind::parse(unknown), None, "kind {unknown:?}");
    }
}

#[test]
fn decode_rejects_every_abi_deviation() {
    let author = actor(0x7a);

    // Trailing bytes after an otherwise valid map.
    let mut trailing = encode_note_body(&take("solid")).expect("encode");
    trailing.push(0xC0);
    assert!(decode_note_body(&trailing).is_err(), "trailing bytes");

    // Not MessagePack at all, and MessagePack that is not a map.
    assert!(decode_note_body(&[0xFF, 0xFF, 0xFF]).is_err(), "garbage");
    let mut not_a_map = Vec::new();
    rmpv::encode::write_value(&mut not_a_map, &Value::from("opinion/take")).expect("encode");
    assert!(decode_note_body(&not_a_map).is_err(), "non-map body");

    // Unknown key alongside the pinned four.
    let unknown_key = encode_map(vec![
        (Value::from("kind"), Value::from("opinion/take")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
        (Value::from("author_display"), Value::from("Ada")),
    ]);
    assert!(decode_note_body(&unknown_key).is_err(), "unknown key");

    // Duplicate key — last-write-wins would let a writer smuggle a second
    // author past a reader that stops at the first.
    let duplicate = encode_map(vec![
        (Value::from("kind"), Value::from("opinion/take")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("author_ref"), Value::from(actor(0x7b).to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
    ]);
    assert!(decode_note_body(&duplicate).is_err(), "duplicate key");

    // Non-string key.
    let int_key = encode_map(vec![(Value::from(1), Value::from("opinion/take"))]);
    assert!(decode_note_body(&int_key).is_err(), "non-string key");

    // Unknown kind on the wire.
    let unknown_kind = encode_map(vec![
        (Value::from("kind"), Value::from("scratchpad")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("markdown"), Value::from("solid")),
        (
            Value::from("source_revision_ref"),
            Value::Binary(vec![0x42; 16]),
        ),
    ]);
    assert!(decode_note_body(&unknown_kind).is_err(), "unknown kind");

    // Invalid actor bytes: wrong length, non-hex, and wrong MessagePack type.
    for bad_actor in [
        Value::from("deadbeef"),
        Value::from("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
        Value::Binary(author.as_bytes().to_vec()),
    ] {
        let body = encode_map(vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), bad_actor.clone()),
            (Value::from("markdown"), Value::from("solid")),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]);
        assert!(decode_note_body(&body).is_err(), "actor {bad_actor:?}");
    }

    // Blank markdown, on both the decode and the encode side.
    for blank in ["", "   ", "\n\t "] {
        let body = encode_map(vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from(blank)),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]);
        assert!(decode_note_body(&body).is_err(), "blank {blank:?} decode");
        assert!(
            encode_note_body(&take(blank)).is_err(),
            "blank {blank:?} encode"
        );
    }

    // Every missing-key subset of the pinned four.
    for omit in NOTE_BODY_KEYS {
        let entries = vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from("solid")),
            (
                Value::from("source_revision_ref"),
                Value::Binary(vec![0x42; 16]),
            ),
        ]
        .into_iter()
        .filter(|(key, _)| key.as_str() != Some(omit))
        .collect();
        assert!(
            decode_note_body(&encode_map(entries)).is_err(),
            "missing {omit}"
        );
    }
}

#[test]
fn live_note_projection_validates_birth_abi_in_every_feature_mode() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let txn = vault.store.env.read_txn().unwrap();
    let id = actor(0x6a);
    let valid = encode_note_body(&take("valid birth")).unwrap();
    assert_eq!(
        live_body_in_txn(
            &vault.store,
            &txn,
            &id,
            crate::registry::ENTITY_TYPE_NOTE,
            &valid
        )
        .unwrap()
        .as_ref(),
        valid.as_slice(),
    );
    assert!(matches!(
        live_body_in_txn(
            &vault.store,
            &txn,
            &id,
            crate::registry::ENTITY_TYPE_NOTE,
            &[0xff]
        ),
        Err(Error::Record(RecordError::InvalidNoteBody(_)))
    ));
    assert_eq!(
        live_body_in_txn(
            &vault.store,
            &txn,
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            &[0xff]
        )
        .unwrap()
        .as_ref(),
        &[0xff],
    );
}

#[test]
fn brief_kind_round_trip_is_person_stamped_and_fail_closed() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::device());
    let actor = actor(0x61);
    vault
        .put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .unwrap();
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let contract = memory.bless_brief_kind().unwrap();
    assert_eq!(contract.person(), actor);
    assert_eq!(contract.extraction, NoteExtractionDefault::Disabled);
    assert_eq!(contract.context, NoteContextDefault::RelationshipScoped);
    assert_eq!(contract.retention, NoteRetentionDefault::Durable);
    assert_eq!(vault.brief_kind_contract().unwrap(), Some(contract.clone()));
    assert_eq!(
        BriefKindContract::decode(&contract.encode().unwrap()).unwrap(),
        contract
    );
    let value: serde_json::Value = serde_json::from_slice(&contract.encode().unwrap()).unwrap();
    for (field, invalid) in [
        ("version", serde_json::json!(2)),
        ("person", serde_json::json!("not-an-entity-id")),
        ("extraction", serde_json::json!("allowed")),
        ("context", serde_json::json!("global")),
        ("retention", serde_json::json!("ephemeral")),
        ("grant", serde_json::json!("owner")),
    ] {
        let mut malformed = value.clone();
        malformed[field] = invalid;
        assert!(matches!(
            BriefKindContract::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
    }
    for field in ["version", "person", "extraction", "context", "retention"] {
        let mut malformed = value.clone();
        malformed.as_object_mut().unwrap().remove(field);
        assert!(matches!(
            BriefKindContract::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
    }
    for tag in ["brief", "unknown.pack"] {
        let body = NoteBody {
            kind: NoteKind::Plugin(tag.into()),
            author_ref: actor,
            markdown: "authored".into(),
            source_revision_ref: [0x42; 16],
        };
        assert_eq!(
            decode_note_body(&encode_note_body(&body).unwrap()).unwrap(),
            body
        );
    }
    assert_eq!(
        NOTE_BODY_KEYS,
        ["kind", "author_ref", "markdown", "source_revision_ref"]
    );
}

#[test]
fn diary_round_trip_and_revision_are_required() {
    let mut diary = take("private journal");
    diary.kind = NoteKind::Diary;
    let bytes = encode_note_body(&diary).expect("encode diary");
    assert_eq!(decode_note_body(&bytes).expect("decode diary"), diary);
    assert!(!note_body_readable(&bytes, None));
    assert!(!note_body_readable(&bytes, Some(&actor(0x7b))));
    assert!(note_body_readable(&bytes, Some(&diary.author_ref)));
    for revision in [
        Value::Nil,
        Value::Binary(vec![1; 15]),
        Value::Binary(vec![1; 17]),
        Value::from("opaque"),
    ] {
        let bytes = encode_map(vec![
            (Value::from("kind"), Value::from("diary")),
            (
                Value::from("author_ref"),
                Value::from(diary.author_ref.to_hex()),
            ),
            (Value::from("markdown"), Value::from("private")),
            (Value::from("source_revision_ref"), revision),
        ]);
        assert!(matches!(
            decode_note_body(&bytes),
            Err(Error::Record(RecordError::InvalidNoteBody(_)))
        ));
        assert!(!note_body_readable(&bytes, Some(&diary.author_ref)));
    }
}
