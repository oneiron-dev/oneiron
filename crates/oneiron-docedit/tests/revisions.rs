use std::io::Read;

use oneiron_docedit::{
    ArchiveLimits, DoceditError, Document, preflight_with_limits, revise, validate_blocking,
    validate_blocking_with_limits, validate_revision_transaction,
};

const INPUT: &[u8] = include_bytes!("../vendor/stemma-engine/testdata/simple-text/before.docx");

#[test]
fn tracked_replace_is_a_clean_word_revision() {
    let doc = Document::parse(INPUT).unwrap();
    let first = &doc.read().blocks[0];
    let transaction = serde_json::json!({
        "ops": [{ "op": "replace", "target": first.id, "guard": first.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "A tracked replacement."}
            ]}
        }],
        "revision": {"author": "Editor"}
    })
    .to_string();
    let output = revise(INPUT, &transaction).unwrap();
    validate_blocking(&output).unwrap();
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&output)).unwrap();
    let mut document = String::new();
    archive
        .by_name("word/document.xml")
        .unwrap()
        .read_to_string(&mut document)
        .unwrap();
    assert!(document.contains("<w:ins"));
    assert!(document.contains("<w:del"));
    let result = Document::parse(&output).unwrap();
    assert!(
        result
            .read_accepted()
            .unwrap()
            .to_text()
            .contains("A tracked replacement.")
    );
    assert!(
        !result
            .read_rejected()
            .unwrap()
            .to_text()
            .contains("A tracked replacement.")
    );
}

#[test]
fn stale_guard_is_not_exported() {
    let doc = Document::parse(INPUT).unwrap();
    let transaction = serde_json::json!({
        "ops": [{ "op": "replace", "target": doc.read().blocks[0].id,
            "guard": "stale", "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Cannot apply."}
            ]}}],
        "revision": {"author": "Editor"}
    })
    .to_string();
    assert!(revise(INPUT, &transaction).is_err());
}

#[test]
fn direct_mode_is_refused_even_over_another_authors_pending_revision() {
    // First create a real pending redline from another author. Direct mode
    // otherwise resolves it as a side effect and loses the rejectable base.
    let original = Document::parse(INPUT).unwrap();
    let first = &original.read().blocks[0];
    let tracked = serde_json::json!({
        "ops": [{"op": "replace", "target": first.id, "guard": first.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Earlier author's pending edit."}
            ]}}],
        "revision": {"author": "Earlier Author"}
    })
    .to_string();
    let pending = revise(INPUT, &tracked).unwrap();
    let document = Document::parse(&pending).unwrap();
    assert!(
        document
            .read_rejected()
            .unwrap()
            .to_text()
            .contains("This is a test")
    );
    let block = &document.read().blocks[0];
    let direct = serde_json::json!({
        "ops": [{"op": "replace", "target": block.id, "guard": block.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Untracked overwrite."}
            ]}}],
        "materialization_mode": "direct",
        "revision": {"author": "New Editor"}
    })
    .to_string();
    assert!(matches!(
        validate_revision_transaction(&direct),
        Err(DoceditError::InvalidTransaction(_))
    ));
    assert!(matches!(
        revise(&pending, &direct),
        Err(DoceditError::InvalidTransaction(_))
    ));
    let direct_from_base = serde_json::json!({
        "ops": [{"op": "replace", "target": first.id, "guard": first.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "Untracked overwrite."}
            ]}}],
        "materialization_mode": "direct",
        "revision": {"author": "New Editor"}
    })
    .to_string();
    assert!(matches!(
        revise(INPUT, &direct_from_base),
        Err(DoceditError::InvalidTransaction(_))
    ));
    // Refusal leaves the caller-owned pending bytes and old rejectable text intact.
    assert!(
        Document::parse(&pending)
            .unwrap()
            .read_rejected()
            .unwrap()
            .to_text()
            .contains("This is a test")
    );
}

#[test]
fn archive_preflight_refuses_entry_part_and_cumulative_inflation() {
    use std::io::Write;
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for name in ["word/document.xml", "word/styles.xml"] {
        zip.start_file(name, zip::write::FileOptions::default())
            .unwrap();
        zip.write_all(&[b'x'; 64]).unwrap();
    }
    let bytes = zip.finish().unwrap().into_inner();
    let generous = ArchiveLimits {
        max_entries: 2,
        max_part_bytes: 80,
        max_total_bytes: 160,
    };
    assert!(preflight_with_limits(&bytes, generous).is_ok());
    assert!(
        preflight_with_limits(
            &bytes,
            ArchiveLimits {
                max_entries: ArchiveLimits::DEFAULT.max_entries + 1,
                ..ArchiveLimits::DEFAULT
            }
        )
        .is_err()
    );
    for limits in [
        ArchiveLimits {
            max_entries: 1,
            ..generous
        },
        ArchiveLimits {
            max_part_bytes: 32,
            ..generous
        },
        ArchiveLimits {
            max_total_bytes: 100,
            ..generous
        },
    ] {
        assert!(preflight_with_limits(&bytes, limits).is_err());
        assert!(validate_blocking_with_limits(&bytes, limits).is_err());
    }
}
