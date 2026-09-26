//! Produce one deterministic tracked-change sample for the external Word oracle.
use oneiron_docedit::{Document, revise};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input = include_bytes!("../vendor/stemma-engine/testdata/simple-text/before.docx");
    let doc = Document::parse(input)?;
    let block = &doc.read().blocks[0];
    let transaction = serde_json::json!({
        "ops": [{"op": "replace", "target": block.id, "guard": block.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "A tracked replacement."}
            ]}}],
        "revision": {"author": "Editor"}
    })
    .to_string();
    let output = revise(input, &transaction)?;
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: emit_revision <output.docx>")?;
    std::fs::write(&path, output)?;
    Ok(())
}
