use std::io::Read;

use oneiron_docedit::{Document, revise, validate_blocking};

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
