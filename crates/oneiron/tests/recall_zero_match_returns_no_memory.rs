//! E2E MUSE-RECALL-04: recall without query evidence returns no memory and
//! records an empty serving run, including after a vault restart. Lexical
//! matches and explicit temporal queries still return witnessed messages.

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::memory::{
    Effort, Memory, RecallScope, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn capture_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    config
}

fn witness_sentinels(memory: &Memory<'_>) -> Result<[String; 3], Box<dyn std::error::Error>> {
    let occurred_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sentinels = ["witnessalpha", "witnessbeta", "witnessgamma"]
        .map(|prefix| format!("{prefix}{}", EntityId::now().to_hex()));
    for sentinel in &sentinels {
        memory.witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: sentinel.clone(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at,
            assertions: WitnessAssertions::default(),
        })?;
    }
    Ok(sentinels)
}

fn assert_zero_match(vault: &Vault, memory: &Memory<'_>, query: &str) -> TestResult {
    let pack = memory.recall(
        query,
        Effort::Light,
        &RecallScope::default(),
        10,
        None,
        None,
    )?;
    assert!(
        pack.items.is_empty(),
        "a query with no evidence returned {} items",
        pack.items.len()
    );
    assert_eq!(pack.retrieval_meta.claims_returned, 0);
    let run_id = pack
        .retrieval_run_id
        .expect("capture-enabled recall publishes a serving run id");
    let run = vault
        .retrieval_run(run_id)?
        .expect("the serving retrieval run is publicly readable");
    assert!(run.result_ids.is_empty());
    assert!(run.score_breakdown.is_empty());
    Ok(())
}

fn assert_matching_turn(memory: &Memory<'_>, sentinel: &str) -> TestResult {
    let pack = memory.recall(
        sentinel,
        Effort::Light,
        &RecallScope::default(),
        10,
        None,
        None,
    )?;
    assert!(pack.items.iter().any(|item| {
        matches!(item.kind.as_str(), "TURN" | "MESSAGE") && item.value_text.contains(sentinel)
    }));
    Ok(())
}

#[test]
fn zero_match_recall_returns_no_memory() -> TestResult {
    let directory = tempfile::tempdir()?;
    let query = format!("unmatched{}", EntityId::now().to_hex());
    {
        let vault = Vault::open(directory.path(), capture_config())?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let memory = vault.memory(owner, EdgeActorClass::Human);
        let sentinels = witness_sentinels(&memory)?;
        assert_zero_match(&vault, &memory, &query)?;
        assert_matching_turn(&memory, &sentinels[0])?;
    }
    let vault = Vault::open(directory.path(), capture_config())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    assert_zero_match(&vault, &memory, &query)?;
    Ok(())
}

#[test]
fn matching_recall_still_returns_the_turn() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), capture_config())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let sentinels = witness_sentinels(&memory)?;
    assert_matching_turn(&memory, &sentinels[0])?;
    Ok(())
}

#[test]
fn explicit_time_anchor_still_counts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), capture_config())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let sentinels = witness_sentinels(&memory)?;
    let scope = RecallScope {
        kinds: Some(vec!["TURN".to_owned(), "MESSAGE".to_owned()]),
        ..RecallScope::default()
    };
    let pack = memory.recall("recent", Effort::Light, &scope, 10, None, None)?;
    for sentinel in &sentinels {
        assert!(pack.items.iter().any(|item| {
            matches!(item.kind.as_str(), "TURN" | "MESSAGE") && item.value_text.contains(sentinel)
        }));
    }
    Ok(())
}
