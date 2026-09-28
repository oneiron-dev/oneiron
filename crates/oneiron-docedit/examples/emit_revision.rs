//! Produce one deterministic tracked-change sample for the external Word oracle.
use oneiron_docedit::{Document, revise};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or("usage: emit_revision <output.docx> [input.docx]")?;
    let input = match args.next() {
        Some(source) => std::fs::read(source)?,
        None => include_bytes!("../vendor/stemma-engine/testdata/simple-text/before.docx").to_vec(),
    };
    let doc = Document::parse(&input)?;
    let block = &doc.read().blocks[0];
    let transaction = serde_json::json!({
        "ops": [{"op": "replace", "target": block.id, "guard": block.guard,
            "content": {"type": "paragraph", "content": [
                {"type": "text", "text": "A tracked replacement."}
            ]}}],
        "revision": {"author": "Editor"}
    })
    .to_string();
    let output = revise(&input, &transaction)?;
    std::fs::write(&path, output)?;
    Ok(())
}
