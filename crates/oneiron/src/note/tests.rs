//! NOTE body ABI: the pinned four keys, the closed kind, and the negative
//! set the decoder must fail closed on.

use rmpv::Value;

use super::*;

fn actor(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("actor id")
}

fn take(markdown: &str) -> NoteBody {
    NoteBody {
        document_head: None,
        kind: NoteKind::parse("opinion/take").expect("shipped kind"),
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
    assert_eq!(
        NoteKind::parse("opinion/take")
            .expect("shipped kind")
            .as_str(),
        "opinion/take"
    );
    assert_eq!(
        NoteKind::parse("opinion/take"),
        Some(NoteKind::parse("opinion/take").expect("shipped kind"))
    );
    assert_eq!(
        NOTE_BODY_KEYS,
        [
            "kind",
            "author_ref",
            "markdown",
            "document_head",
            "source_revision_ref"
        ]
    );

    let body = take("Disagree: the source predates the merger.");
    let decoded = decode_note_body(&encode_note_body(&body).expect("encode")).expect("decode");
    assert_eq!(decoded, body);

    for unknown in ["plugin/custom", "OPINION/TAKE", ""] {
        assert_eq!(NoteKind::parse(unknown), None);
    }
    for kind in [
        "scratchpad",
        "observation",
        "handoff",
        "research",
        "reflection",
        "diary",
    ] {
        let body = NoteBody {
            kind: NoteKind::parse(kind).unwrap(),
            ..take("birth")
        };
        assert_eq!(
            decode_note_body(&encode_note_body(&body).unwrap()).unwrap(),
            body
        );
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
        (Value::from("kind"), Value::from("not_registered")),
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

    // Missing keys in an inline core are rejected.
    for omit in ["kind", "author_ref", "markdown", "source_revision_ref"] {
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
fn diary_round_trip_and_revision_are_required() {
    let dir = tempfile::tempdir().unwrap();
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
    let txn = vault.store.env.read_txn().unwrap();
    let readable = |bytes: &[u8], actor: Option<&EntityId>| {
        note_body_readable(&vault.store, &txn, bytes, actor).unwrap()
    };
    let mut diary = take("private journal");
    diary.kind = NoteKind::parse("diary").expect("shipped kind");
    let bytes = encode_note_body(&diary).expect("encode diary");
    assert_eq!(decode_note_body(&bytes).expect("decode diary"), diary);
    assert!(!readable(&bytes, None));
    assert!(!readable(&bytes, Some(&actor(0x7b))));
    assert!(readable(&bytes, Some(&diary.author_ref)));
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
        assert!(!readable(&bytes, Some(&diary.author_ref)));
    }
}

#[test]
fn document_core_retains_revision_and_refuses_inline_text() {
    let mut body = take("");
    body.document_head = Some(actor(0x43));
    let bytes = encode_note_body(&body).unwrap();
    assert_eq!(decode_note_body(&bytes).unwrap(), body);
    let mut value = rmpv::decode::read_value(&mut bytes.as_slice()).unwrap();
    let Value::Map(fields) = &mut value else {
        panic!("NOTE map")
    };
    fields.push(("markdown".into(), "cannot retain both".into()));
    assert!(decode_note_body(&encode_map(fields.clone())).is_err());
    body.markdown = "cannot retain both".into();
    assert!(encode_note_body(&body).is_err());
}
