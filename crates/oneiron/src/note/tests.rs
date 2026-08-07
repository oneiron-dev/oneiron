//! NOTE body ABI: the pinned three keys, the closed kind, and the negative
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
    assert_eq!(NOTE_BODY_KEYS, ["kind", "author_ref", "markdown"]);

    let body = take("Disagree: the source predates the merger.");
    let decoded = decode_note_body(&encode_note_body(&body).expect("encode")).expect("decode");
    assert_eq!(decoded, body);

    // Unknown kinds fail closed — the other six ARCH-0032 kinds are not
    // implemented, so they must not decode as anything.
    for unknown in [
        "scratchpad",
        "observation",
        "handoff",
        "research",
        "reflection",
        "diary",
        "plugin/custom",
        "OPINION/TAKE",
        "",
    ] {
        assert_eq!(NoteKind::parse(unknown), None, "kind {unknown:?}");
    }
}

#[test]
fn decode_rejects_every_abi_deviation() {
    let author = actor(0x7a);
    let good = encode_note_body(&take("solid")).expect("encode");

    // Trailing bytes after an otherwise valid map.
    let mut trailing = good.clone();
    trailing.push(0xC0);
    assert!(decode_note_body(&trailing).is_err(), "trailing bytes");

    // Not MessagePack at all, and MessagePack that is not a map.
    assert!(decode_note_body(&[0xFF, 0xFF, 0xFF]).is_err(), "garbage");
    let mut not_a_map = Vec::new();
    rmpv::encode::write_value(&mut not_a_map, &Value::from("opinion/take")).expect("encode");
    assert!(decode_note_body(&not_a_map).is_err(), "non-map body");

    // Unknown key alongside the pinned three.
    let unknown_key = encode_map(vec![
        (Value::from("kind"), Value::from("opinion/take")),
        (Value::from("author_ref"), Value::from(author.to_hex())),
        (Value::from("markdown"), Value::from("solid")),
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
        ]);
        assert!(decode_note_body(&body).is_err(), "actor {bad_actor:?}");
    }

    // Blank markdown, on both the decode and the encode side.
    for blank in ["", "   ", "\n\t "] {
        let body = encode_map(vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from(blank)),
        ]);
        assert!(decode_note_body(&body).is_err(), "blank {blank:?} decode");
        assert!(encode_note_body(&take(blank)).is_err(), "blank {blank:?} encode");
    }

    // Every missing-key subset of the pinned three.
    for omit in NOTE_BODY_KEYS {
        let entries = vec![
            (Value::from("kind"), Value::from("opinion/take")),
            (Value::from("author_ref"), Value::from(author.to_hex())),
            (Value::from("markdown"), Value::from("solid")),
        ]
        .into_iter()
        .filter(|(key, _)| key.as_str() != Some(omit))
        .collect();
        assert!(decode_note_body(&encode_map(entries)).is_err(), "missing {omit}");
    }
}
