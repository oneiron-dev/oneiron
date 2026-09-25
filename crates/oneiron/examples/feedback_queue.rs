//! Seed a real receiving-vault queue and export its evidence for a host triage agent.
//! No triage prompt or prioritization policy is embedded in the engine.
use oneiron::feedback::intake::FeedbackDedup;
use oneiron::feedback::{
    FeedbackBundle, FeedbackCategory, FeedbackPlatform, decode_feedback_bundle,
    encode_feedback_bundle,
};
use oneiron::{Vault, VaultConfig};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .ok_or("expected a new output JSON path")?;
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.dimensions = 2;
    config.fast_dims = None;
    config.embedding_model = Some("fixture/feedback@v1".into());
    let vault = Vault::open(dir.path(), config)?;
    let dial = FeedbackDedup::new(0.9)?;
    let first = FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current())
        .with_user_note("Recall omitted the recent note after an edit.");
    let variant = FeedbackBundle::new(FeedbackCategory::Bug, "1.0", FeedbackPlatform::current())
        .with_user_note("After editing a note, recall still shows its older content.");
    let distinct = FeedbackBundle::new(
        FeedbackCategory::Confusion,
        "1.0",
        FeedbackPlatform::current(),
    )
    .with_user_note(
        "The documentation does not explain when indexed reads catch up with live reads.",
    );
    let bytes = encode_feedback_bundle(&first)?;
    vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 10)?;
    vault.ingest_feedback(&bytes, &[1.0, 0.0], dial, 11)?;
    vault.ingest_feedback(&encode_feedback_bundle(&variant)?, &[0.99, 0.01], dial, 12)?;
    vault.ingest_feedback(&encode_feedback_bundle(&distinct)?, &[0.0, 1.0], dial, 13)?;
    let queue = vault.feedback_digest()?;
    assert_eq!(queue.len(), 2);
    assert_eq!(queue[0].bundles.len(), 2);
    let mut rows = Vec::new();
    for item in queue {
        let mut sources = Vec::new();
        for id in item.bundles {
            let bytes = vault.get(&id)?.ok_or("missing source bundle")?;
            let bundle = decode_feedback_bundle(&bytes)?;
            sources.push(serde_json::json!({
                "id": id.to_hex(), "user_note": bundle.user_note,
                "bytes_blake3": blake3::hash(&bytes).to_hex().to_string()
            }));
        }
        rows.push(serde_json::json!({
            "id": item.id.to_hex(), "category": item.category, "open": item.open,
            "received_at": item.received_at, "sources": sources
        }));
    }
    let evidence = serde_json::json!({
        "fixture": "feedback-intake-chat-v1", "submitted": 4,
        "distinct_bundles": 3, "open_items": rows
    });
    let bytes = serde_json::to_vec_pretty(&evidence)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?
        .write_all(&bytes)?;
    Ok(())
}
