//! L1-13 p5 (RESEARCH-0363 p5; Engine RULING L1-13-P5-NOW, 14 Nov, design
//! (i)): `vault.recall` under a caller's operation id. The first recall
//! under an id keeps its items by identity; the same request under it again
//! answers those items, rebuilt at the revisions it served under the caller's
//! current read, and refuses once one of them, or a world its census named,
//! no longer reads. Two first calls that race both answer the one kept
//! first. Without an id, recall tracks the vault as before.
//!
//! The requests are built from JSON, as the wire sends them, so this file
//! compiles where `operation_id` is not a field: there the id is ignored and
//! every replay answers afresh.
//!
//! Fleet: `cargo test --locked -p oneiron --all-features --test recall_operation_replay`

use std::sync::Arc;

use oneiron::deletion::DeleteReason;
use oneiron::memory::{
    ClaimInput, Memory, MemoryPack, MemoryResult, ReadFilterInput, RecallRequest,
    WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
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
    let turn = first
        .items
        .iter()
        .find(|item| item.value_text.contains("gamma"))
        .expect("FIXTURE: the first recall serves the turn");
    // The message the turn reads its text from, then the turn: the order a
    // room's own delete takes them in.
    let mut served = Vec::new();
    for message in &turn.cited_messages {
        let record = message
            .record
            .as_ref()
            .expect("FIXTURE: the cited message carries its record");
        served.push(EntityId::from_hex(&record.id).expect("a message id"));
    }
    assert!(
        !served.is_empty(),
        "FIXTURE: the turn cites the message it reads"
    );
    let record = turn
        .record
        .as_ref()
        .expect("FIXTURE: the turn carries its record");
    served.push(EntityId::from_hex(&record.id).expect("a turn id"));
    // The subject is the replay after a delete, not who may delete: a
    // witnessed TURN and its MESSAGE are room records, which a plain delete
    // refuses without the room's authority (ConversationDenied), so the
    // test-support seam deletes them. Every delete signs as this install.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    for id in &served {
        let outcome = vault
            .delete_room_record_unchecked_for_test(id, DeleteReason::UserDelete)
            .unwrap_or_else(|error| panic!("FIXTURE: delete the served record {id:?}: {error:?}"));
        assert!(
            outcome.existed,
            "FIXTURE: the delete removes the served record"
        );
    }
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

#[test]
fn a_first_call_that_keeps_second_answers_the_first_kept_answer() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the first {TOPIC} note says theta"));
    let operation = serde_json::json!({ "operation_id": "session-6:step-2:recall:0" });
    // Two first calls of one operation race. This one misses the kept row
    // and, while its query embeds, the other runs to its end and keeps its
    // answer; then a new turn lands, which this call's retrieval reads.
    let racing = operation.clone();
    let mut kept_first = None;
    let kept_second = recall_at_door(
        &memory,
        request(operation.clone()),
        |_| {
            kept_first = Some(recall(&memory, racing).expect("the call that keeps first"));
            witness(
                &memory,
                &format!("{TOPIC} {TOPIC} {TOPIC}: the later note says iota"),
            );
            None
        },
        &RecallDoor::now(),
    )
    .expect("the call that keeps second");
    let kept_first = kept_first.expect("FIXTURE: the racing call ran while the query embedded");
    assert!(
        holds(&kept_first, "theta") && !holds(&kept_first, "iota"),
        "FIXTURE: the call that keeps first answers before the later turn"
    );
    let fresh = recall(&memory, serde_json::json!({})).expect("a recall without an id");
    assert!(
        holds(&fresh, "iota"),
        "FIXTURE: a recall without an operation id finds the later turn"
    );

    assert_eq!(
        items_json(&kept_second),
        items_json(&kept_first),
        "the call that keeps second answers the operation's first kept answer"
    );
    let replay = recall(&memory, operation).expect("a later replay");
    assert_eq!(
        items_json(&replay),
        items_json(&kept_first),
        "a later replay answers the first kept answer, never one kept over it"
    );
}

#[test]
fn a_replay_names_no_world_the_current_read_does_not_read() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    witness(&memory, &format!("the {TOPIC} note says kappa"));
    // Control first: an operation whose census names no world.
    let control = serde_json::json!({ "operation_id": "session-7:step-1:recall:0" });
    let control_first = recall(&memory, control.clone()).expect("the control's first recall");
    assert!(
        control_first.scope_honesty.out_of_scope_worlds.is_empty(),
        "FIXTURE: with no claim in another world the census names none"
    );

    // A surfaceable claim in a world the default scope does not read.
    let world = EntityId::now();
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    memory
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "profile.city".to_owned(),
            subject_ref: owner.to_hex(),
            value: serde_json::json!("a city in another world"),
            confidence: 1.0,
            confidence_details: None,
            source: "user_stated".to_owned(),
            world_ref: Some(world.to_hex()),
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(100),
            learned_at: Some(100),
            salience: None,
        })
        .expect("FIXTURE: the owner writes a claim in another world");
    let operation = serde_json::json!({ "operation_id": "session-7:step-2:recall:0" });
    let first = recall(&memory, operation.clone()).expect("the first recall");
    assert_eq!(
        first.scope_honesty.out_of_scope_worlds,
        vec![world.to_hex()],
        "FIXTURE: the first answer's census names the claim's world"
    );

    // The same caller, its read narrowed to turns and messages: it still
    // reads the turn, and no claim, so no world.
    let narrowed: ReadFilterInput =
        serde_json::from_value(serde_json::json!({ "entity_types": ["TURN", "MESSAGE"] }))
            .expect("a read filter");
    let narrowed = memory.with_read_filter(Some(&narrowed));
    let fresh = recall(&narrowed, serde_json::json!({})).expect("a narrowed recall");
    assert!(
        holds(&fresh, "kappa") && fresh.scope_honesty.out_of_scope_worlds.is_empty(),
        "FIXTURE: the narrowed read reads the turn and names no world"
    );
    let control_replay = recall(&narrowed, control).expect("the control's narrowed replay");
    assert_eq!(
        items_json(&control_replay),
        items_json(&control_first),
        "FIXTURE: the narrowed read replays the turn items unchanged"
    );

    let refusal = recall(&narrowed, operation)
        .expect_err("a replay whose census names a world the read no longer reads refuses");
    assert_eq!(refusal.code, oneiron::memory::MEMORY_CODE_INVALID_STATE);
    assert!(
        !refusal.message.contains(&world.to_hex()),
        "the refusal names no world"
    );
}
