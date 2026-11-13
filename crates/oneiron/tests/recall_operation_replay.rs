//! L1-13 p5 (RESEARCH-0363 p5; Engine RULING L1-13-P5-NOW, 14 Nov, design
//! (i)): `vault.recall` under a caller's operation id. The first recall
//! under an id keeps its items by identity; the same request under it again
//! answers those items, rebuilt at the revisions it served under the caller's
//! current read, and refuses once one of them no longer reads. Without an id,
//! recall tracks the vault as before.
//!
//! The requests are built from JSON, as the wire sends them, so this file
//! compiles where `operation_id` is not a field: there the id is ignored and
//! every replay answers afresh.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test recall_operation_replay`

use oneiron::deletion::DeleteReason;
use oneiron::memory::{
    Memory, MemoryPack, MemoryResult, RecallRequest, WitnessAssertions, WitnessAuthor,
    WitnessMessage, WitnessTurn,
};
use oneiron::task_verb::sdk::{RecallDoor, recall_at_door};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};

/// The word every witnessed message holds, so one query recalls each.
const TOPIC: &str = "lanternwickreplay";

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    (directory, vault)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

/// Witnesses one turn of one user message holding `content`.
fn witness(memory: &Memory<'_>, content: &str) {
    memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: content.to_owned(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })
        .expect("witness one turn");
}

/// A light `vault.recall` request for [`TOPIC`], spelled as the wire spells
/// it, with `extra` fields merged in.
fn request(extra: serde_json::Value) -> RecallRequest {
    let mut value = serde_json::json!({ "query": TOPIC, "effort": "light", "limit": 10 });
    if let (Some(fields), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        fields.extend(extra.clone());
    }
    serde_json::from_value(value).expect("a vault.recall request")
}

fn recall(memory: &Memory<'_>, extra: serde_json::Value) -> MemoryResult<MemoryPack> {
    recall_at_door(memory, request(extra), |_| None, &RecallDoor::now())
}

fn items_json(pack: &MemoryPack) -> String {
    serde_json::to_string(&pack.items).expect("items as JSON")
}

fn holds(pack: &MemoryPack, word: &str) -> bool {
    pack.items.iter().any(|item| item.value_text.contains(word))
}

#[test]
fn a_replayed_operation_answers_its_first_items() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the first {TOPIC} note says alpha"));
    let operation = serde_json::json!({ "operation_id": "session-1:step-4:recall:0" });
    let first = recall(&memory, operation.clone()).expect("the first recall");
    assert!(
        holds(&first, "alpha"),
        "FIXTURE: the first recall finds the witnessed turn"
    );

    witness(
        &memory,
        &format!("{TOPIC} {TOPIC} {TOPIC}: the second note says beta"),
    );
    let fresh = recall(&memory, serde_json::json!({})).expect("a recall without an id");
    assert!(
        holds(&fresh, "beta"),
        "FIXTURE: a recall without an operation id finds the new turn"
    );

    let replay = recall(&memory, operation).expect("the replay");
    assert!(
        !holds(&replay, "beta"),
        "a replay answers the first answer's items, never a record written after it"
    );
    assert_eq!(
        items_json(&replay),
        items_json(&first),
        "a replay answers the first answer's items byte for byte"
    );
}

#[test]
fn a_replay_after_a_delete_is_refused() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the {TOPIC} note says gamma"));
    let operation = serde_json::json!({ "operation_id": "session-2:step-1:recall:0" });
    let first = recall(&memory, operation.clone()).expect("the first recall");
    let record = first
        .items
        .iter()
        .find(|item| item.value_text.contains("gamma"))
        .and_then(|item| item.record.as_ref())
        .expect("FIXTURE: the first recall serves the turn with its record");
    let served = EntityId::from_hex(&record.id).expect("a record id");
    assert!(
        vault
            .delete_entity_with_reason(&served, DeleteReason::UserDelete)
            .expect("delete the served record")
            .existed,
        "FIXTURE: the delete removes the served record"
    );
    let fresh = recall(&memory, serde_json::json!({})).expect("a recall without an id");
    assert!(
        !holds(&fresh, "gamma"),
        "FIXTURE: a recall without an operation id no longer serves the deleted record"
    );

    let refusal = recall(&memory, operation).expect_err("a replay of a deleted record refuses");
    assert_eq!(refusal.code, oneiron::memory::MEMORY_CODE_INVALID_STATE);
    assert!(
        !refusal.message.contains("gamma"),
        "the refusal carries none of the deleted text"
    );
}

#[test]
fn a_used_operation_id_refuses_another_request() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the {TOPIC} note says delta"));
    recall(&memory, serde_json::json!({ "operation_id": "session-3" })).expect("the first recall");
    let refusal = recall(
        &memory,
        serde_json::json!({ "operation_id": "session-3", "limit": 3 }),
    )
    .expect_err("another request under a used operation id refuses");
    assert_eq!(refusal.code, oneiron::memory::MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn an_operation_recall_takes_no_format() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the {TOPIC} note says epsilon"));
    let refusal = recall(
        &memory,
        serde_json::json!({ "operation_id": "session-4", "format": "json" }),
    )
    .expect_err("an operation id recall refuses a format");
    assert_eq!(refusal.code, oneiron::memory::MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn control_a_recall_without_an_operation_id_tracks_the_vault() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the {TOPIC} note says zeta"));
    let first = recall(&memory, serde_json::json!({})).expect("the first recall");
    assert!(holds(&first, "zeta"), "the first recall finds the turn");
    witness(&memory, &format!("{TOPIC} {TOPIC}: the next note says eta"));
    let second = recall(&memory, serde_json::json!({})).expect("the second recall");
    assert!(
        holds(&second, "eta"),
        "a recall without an id finds the new turn"
    );
    assert!(holds(&second, "zeta"), "and still finds the first");
}
