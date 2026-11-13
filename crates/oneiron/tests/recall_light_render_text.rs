//! E2E MUSE-RECALL-08: light recall must return witnessed message text in both
//! structured items and every explicit text format (TOON, Markdown, JSON, YAML,
//! plaintext). Reopening the vault must preserve the rendered text.

use oneiron::memory::{
    Effort, Memory, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

const SENTINEL: &str = "recalllighttextsentinel7q9z";
const FORMATS: [&str; 5] = ["toon", "md", "json", "yaml", "txt"];

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn witness_sentinel(memory: &Memory<'_>) -> TestResult {
    memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: format!("The recalled message contains {SENTINEL}."),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: 900,
        assertions: WitnessAssertions::default(),
    })?;
    Ok(())
}

fn assert_light_render_text(memory: &Memory<'_>, format: &str) -> TestResult {
    let pack = memory.recall(
        SENTINEL,
        Effort::Light,
        &RecallScope::default(),
        10,
        Some(format),
        None,
    )?;
    assert!(
        pack.items
            .iter()
            .any(|item| item.kind == "TURN" && item.value_text.contains(SENTINEL)),
        "{format}: structured TURN items must contain {SENTINEL}"
    );
    let rendered = pack
        .rendered
        .as_deref()
        .expect("an explicit recall format produces a rendered pack");
    assert!(
        rendered.contains(SENTINEL),
        "{format}: rendered pack must contain {SENTINEL}, got: {rendered}"
    );
    Ok(())
}

#[test]
fn light_recall_renders_message_text_in_every_format() -> TestResult {
    let directory = tempfile::tempdir()?;
    {
        let vault = Vault::open(directory.path(), VaultConfig::device())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let memory = vault.memory(owner, EdgeActorClass::Human);
        witness_sentinel(&memory)?;
        for format in FORMATS {
            assert_light_render_text(&memory, format)?;
        }
    }
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    assert_light_render_text(&memory, "json")?;
    Ok(())
}
