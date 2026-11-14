use std::path::PathBuf;

use oneiron_ruler::pack::{PackError, Record, RecordKind, Slice, load_slice, write_slice};

fn fixture_dir() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/retrieval_pack_tiny"
    ))
}

#[test]
fn pack_digest_is_stable() {
    let loaded = load_slice(&fixture_dir(), Slice::Search).unwrap();
    let digest = loaded.slice.pack_digest().unwrap();
    assert_eq!(digest, loaded.pack_digest);
    assert_eq!(
        digest, "59450de974bf80597a2fb50f433b64632176af6dfa8345a8824b80ea6800408e",
        "pack digest drifted; computed {digest}"
    );
}

#[test]
fn pack_round_trips_through_write_and_load() {
    let loaded = load_slice(&fixture_dir(), Slice::Search).unwrap();
    let temp = tempfile::tempdir().unwrap();
    let digest = write_slice(temp.path(), &loaded.slice, loaded.vectors.as_ref()).unwrap();
    let again = load_slice(temp.path(), Slice::Search).unwrap();
    assert_eq!(again.slice, loaded.slice);
    assert_eq!(again.vectors, loaded.vectors);
    assert_eq!(digest, loaded.pack_digest);
    assert_eq!(again.pack_digest, loaded.pack_digest);
}

#[test]
fn pack_refuses_unknown_record_in_qrels() {
    let mut pack = load_slice(&fixture_dir(), Slice::Search).unwrap().slice;
    let query = pack
        .queries
        .iter_mut()
        .find(|query| query.query_id == "tiny-q1")
        .unwrap();
    query.qrels.insert("tiny-r99".to_owned(), 1);
    assert!(matches!(
        pack.validate(),
        Err(PackError::UnknownRecordInQrels { .. })
    ));
}

#[test]
fn pack_refuses_query_of_another_slice() {
    let mut pack = load_slice(&fixture_dir(), Slice::Search).unwrap().slice;
    let query = pack
        .queries
        .iter_mut()
        .find(|query| query.query_id == "tiny-q2")
        .unwrap();
    query.slice = Slice::HeldOut;
    assert!(matches!(
        pack.validate(),
        Err(PackError::QueryOfAnotherSlice { .. })
    ));
}

#[test]
fn pack_refuses_vector_digest_mismatch() {
    let dir = fixture_dir();
    let temp = tempfile::tempdir().unwrap();
    std::fs::copy(dir.join("search.json"), temp.path().join("search.json")).unwrap();
    let mut bytes = std::fs::read(dir.join("search.vectors.f32")).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(temp.path().join("search.vectors.f32"), bytes).unwrap();
    assert!(matches!(
        load_slice(temp.path(), Slice::Search),
        Err(PackError::VectorDigestMismatch { .. })
    ));
}

#[test]
fn pack_refuses_orphan_record() {
    let mut pack = load_slice(&fixture_dir(), Slice::Search).unwrap().slice;
    pack.records.push(Record {
        record_id: "tiny-r99".to_owned(),
        kind: RecordKind::Turn,
        speaker: "user".to_owned(),
        text: "Owen waved at Yuki across the platform.".to_owned(),
        source_ref: "tiny-s9#0".to_owned(),
    });
    assert!(matches!(
        pack.validate(),
        Err(PackError::OrphanRecord { .. })
    ));
}
