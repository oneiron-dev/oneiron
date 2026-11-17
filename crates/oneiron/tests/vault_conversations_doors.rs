//! The `vault.conversations.*` doors keep the conversation DAG promises
//! (ruling L4-23 = A: each test proves a promise at its public door). Every
//! write enters through `oneiron_testkit::door::invoke`, the generated verb
//! dispatch every transport shares; the DAG is read back through the public
//! `Vault::head`, `Vault::main_line` and `Vault::move_head`, since no verb
//! pages the main line.
//!
//! - P1 `canon oneiron/backend/oneiron-arch-0006a-conversations-api-core.md:70`
//!   "the edge — not array position — defines the thread": a record appended
//!   last but off the line is not on it.
//! - P2 the same file `:86` "A fork is sibling messages off one parent": two
//!   children of one record are two TURNs with one parent; the fork moves no
//!   HEAD, and selecting it shares the parent, never a copy.
//! - P3 `:80` "The old reply stays": `vault.conversations.turn.retry` names
//!   the reply it answers again and leaves that reply and the line as they
//!   were.
//! - P4 the `vault.conversations.turn.continue` row: an interrupted reply
//!   resumes "from exactly its saved text".
//! - Refusals, one table: a HEAD advance off the line, a second root, a
//!   parent from another conversation, continuing a complete reply, and a
//!   rebind with no live slip.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_conversations_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::conversation::{TurnAction, TurnActionAttempt, TurnActionAuthority};
use oneiron::conversation_dag::DagPageRequest;
use oneiron::memory::Memory;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// A private copy of the empty fixture. The `TestVault` holds the directory
/// and must outlive the `Vault`.
fn fixture() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("an open");
    (copy, vault)
}

fn id_of(receipt: &Value) -> String {
    receipt["id"]
        .as_str()
        .expect("the receipt names its record")
        .to_owned()
}

fn hex(id: &str) -> EntityId {
    EntityId::from_hex(id).expect("a 32-hex id")
}

fn create(owner: &Memory<'_>, body: Value) -> String {
    id_of(
        &door::invoke(owner, "vault.conversations.create", json!({"body": body}))
            .expect("the owner creates a conversation"),
    )
}

fn append(owner: &Memory<'_>, input: Value) -> Value {
    door::invoke(owner, "vault.conversations.records.append", input)
        .expect("the owner appends a record")
}

fn main_line(vault: &Vault, conversation: &str) -> Vec<String> {
    vault
        .main_line(
            &hex(conversation),
            DagPageRequest {
                after: None,
                limit: 100,
            },
        )
        .expect("the main line")
        .main_line
        .iter()
        .map(EntityId::to_hex)
        .collect()
}

fn head(vault: &Vault, conversation: &str) -> Option<String> {
    vault
        .head(&hex(conversation))
        .expect("the HEAD")
        .map(|id| id.to_hex())
}

/// A root `a`, its child `b` that advances HEAD, then its child `c`,
/// appended last, that does not.
fn fork(owner: &Memory<'_>) -> (String, Value, Value, Value) {
    let conversation = create(owner, json!({"kind": "group", "title": "a fork"}));
    let a = append(
        owner,
        json!({"conversation": conversation, "advance": true, "body": {"txt": "a"}}),
    );
    let b = append(
        owner,
        json!({"conversation": conversation, "parent": id_of(&a), "advance": true, "body": {"txt": "b"}}),
    );
    let c = append(
        owner,
        json!({"conversation": conversation, "parent": id_of(&a), "advance": false, "body": {"txt": "c"}}),
    );
    (conversation, a, b, c)
}

/// P1 (ARCH-0006a:70). `c` is the newest record, yet the line is the
/// Parent edges from HEAD: `[a, b]`.
/// Seeded fault: `crates/oneiron/src/conversation_dag/graph.rs:373`, `cursor
/// = parent(store, txn, &id)?;` in `chain` made `cursor = None;`, so the
/// line stops following edges.
#[test]
fn the_edge_not_the_append_order_defines_the_line() {
    let (_dir, vault) = fixture();
    let owner = door::owner(&vault).expect("the owner");
    let (conversation, a, b, c) = fork(&owner);
    let (a, b, c) = (id_of(&a), id_of(&b), id_of(&c));

    assert_eq!(head(&vault, &conversation).as_deref(), Some(b.as_str()));
    let line = main_line(&vault, &conversation);
    assert_eq!(line, vec![a, b], "the line follows the Parent edges");
    assert!(
        !line.contains(&c),
        "the last append is off the line: {line:?}"
    );
}

/// P2 (ARCH-0006a:86). `b` and `c` are two TURNs whose receipts name one
/// parent; `c` leaves HEAD on `b`; moving HEAD to `c` gives the line `[a, c]`,
/// with `a` once.
/// Seeded fault: `crates/oneiron/src/conversation_dag/writes.rs:589`, `if
/// input.advance {` made `if true {`, so a fork takes HEAD.
#[test]
fn a_fork_is_two_siblings_off_one_parent() {
    let (_dir, vault) = fixture();
    let owner = door::owner(&vault).expect("the owner");
    let (conversation, a, b, c) = fork(&owner);
    assert_eq!(b["parent"], c["parent"], "one parent: {b} {c}");
    let (a, b, c) = (id_of(&a), id_of(&b), id_of(&c));
    assert_ne!(b, c, "two records, not one");
    for sibling in [&b, &c] {
        assert_eq!(
            vault.get_entity_type(&hex(sibling)).expect("a type"),
            Some(ENTITY_TYPE_TURN),
            "{sibling} is a TURN"
        );
    }
    assert_eq!(
        head(&vault, &conversation).as_deref(),
        Some(b.as_str()),
        "a fork that does not advance leaves HEAD"
    );

    vault
        .move_head(&hex(&conversation), &hex(&c))
        .expect("the owner selects the fork");
    assert_eq!(
        main_line(&vault, &conversation),
        vec![a, c],
        "the fork shares its parent"
    );
}

/// A user TURN and its MESSAGE, then a streamed companion reply to it,
/// finished or interrupted: (conversation, user turn, reply turn, reply
/// message).
fn exchange(owner: &Memory<'_>, vault: &Vault, interrupt: bool) -> [String; 4] {
    let conversation = create(
        owner,
        json!({"kind": "group", "member_ids": [owner.actor().to_hex()]}),
    );
    let user_turn = id_of(&append(
        owner,
        json!({"conversation": conversation, "advance": true, "body": {"txt": "the owner asks"}}),
    ));
    append(
        owner,
        json!({
            "conversation": conversation,
            "containing_turn": user_turn,
            "advance": false,
            "body": {"author": "user", "type": "text", "content": "the owner asks", "is_visible": true, "order": 0},
        }),
    );
    let reply_turn = EntityId::now().to_hex();
    let reply_message = EntityId::now().to_hex();
    let handle = door::invoke(
        owner,
        "vault.begin_message_stream",
        json!({
            "message_id": reply_message,
            "birth": {
                "conversation_ref": conversation,
                "turn_ref": reply_turn,
                "author": "companion",
                "message_type": "text",
                "is_visible": true,
                "order": 0,
                "occurred_at": vault.now_recorded_at(),
            },
        }),
    )
    .expect("the reply stream begins");
    door::invoke(
        owner,
        "vault.append_to_stream",
        json!({"handle": handle, "delta": "a partial answer"}),
    )
    .expect("the reply takes text");
    if interrupt {
        door::invoke(
            owner,
            "vault.cancel_stream",
            json!({"handle": handle, "reason": "user_interrupted"}),
        )
        .expect("the reply is interrupted");
    } else {
        door::invoke(owner, "vault.finalize_stream", json!({"handle": handle}))
            .expect("the reply finishes");
    }
    [conversation, user_turn, reply_turn, reply_message]
}

fn body(owner: &Memory<'_>, record: &str) -> Value {
    owner
        .get_entity(record)
        .expect("a read")
        .value
        .expect("the record")
        .body
        .expect("its body")
}

/// P3 (ARCH-0006a:80). The retry receipt names the reply it answers again;
/// the reply's body and the line are unchanged.
/// Seeded fault: `crates/oneiron/src/conversation/turn_actions.rs:494`,
/// `message: resolved.message,` made `message: resolved.user_turn,`, so the
/// retry no longer answers for the old reply.
#[test]
fn a_retry_keeps_the_old_reply() {
    let (_dir, vault) = fixture();
    let owner = door::owner(&vault).expect("the owner");
    let [conversation, _, reply_turn, reply_message] = exchange(&owner, &vault, false);
    let before = body(&owner, &reply_message);
    let line = main_line(&vault, &conversation);

    let receipt = door::invoke(
        &owner,
        "vault.conversations.turn.retry",
        json!({"turn_id": reply_turn}),
    )
    .expect("the owner retries the reply");
    assert_eq!(receipt["action"], "retry");
    assert_eq!(receipt["turn_id"].as_str(), Some(reply_turn.as_str()));
    assert_eq!(
        receipt["message_id"].as_str(),
        Some(reply_message.as_str()),
        "the retry answers for the old reply: {receipt}"
    );
    assert_eq!(body(&owner, &reply_message), before, "the old reply stays");
    assert_eq!(main_line(&vault, &conversation), line, "the line stays");
}

/// P4 (the `turn.continue` row). The continue receipt names the interrupted
/// reply, and the action resumes from exactly its saved text.
/// Seeded fault: `crates/oneiron/src/conversation/turn_actions.rs:669`,
/// `saved: reply.text.clone(),` made `saved: String::new(),`.
#[test]
fn a_continue_resumes_from_the_saved_text() {
    let (_dir, vault) = fixture();
    let owner = door::owner(&vault).expect("the owner");
    let [conversation, user_turn, reply_turn, reply_message] = exchange(&owner, &vault, true);

    let receipt = door::invoke(
        &owner,
        "vault.conversations.turn.continue",
        json!({"turn_id": reply_turn}),
    )
    .expect("the owner continues the reply");
    assert_eq!(receipt["action"], "continue");
    assert_eq!(receipt["message_id"].as_str(), Some(reply_message.as_str()));

    let attempt = TurnActionAttempt {
        action: TurnAction::Continue,
        conversation: hex(&conversation),
        user_turn: hex(&user_turn),
        assistant_turn: hex(&reply_turn),
        message: hex(&reply_message),
        actor: owner.actor(),
        actor_class: EdgeActorClass::Human as u8,
        authority: TurnActionAuthority::Native,
        off_device: false,
        rebound_from: Vec::new(),
    };
    let context = owner
        .turn_action_context(&attempt, 0)
        .expect("the action's context");
    assert_eq!(context.saved, "a partial answer", "exactly the saved text");
    assert_eq!(context.user_text, "the owner asks");
}

/// Refusals, one row each.
/// Seeded fault: `crates/oneiron/src/conversation_dag/writes.rs:278`, `if
/// input.advance && input.parent != old_head {` given `&& false`, so HEAD
/// advances off the line.
#[test]
fn a_malformed_conversation_act_is_refused() {
    let (_dir, vault) = fixture();
    let owner = door::owner(&vault).expect("the owner");
    let (conversation, a, _, _) = fork(&owner);
    let other = create(&owner, json!({"kind": "group"}));
    let [_, _, complete, _] = exchange(&owner, &vault, false);
    let a = id_of(&a);

    let rows = [
        (
            "a HEAD advance off the line",
            "vault.conversations.records.append",
            json!({"conversation": conversation, "parent": a, "advance": true, "body": {"txt": "x"}}),
            "INVALID_STATE",
        ),
        (
            "a second root",
            "vault.conversations.records.append",
            json!({"conversation": conversation, "advance": false, "body": {"txt": "x"}}),
            "BAD_REQUEST",
        ),
        (
            "a parent from another conversation",
            "vault.conversations.records.append",
            json!({"conversation": other, "parent": a, "advance": false, "body": {"txt": "x"}}),
            "INVALID_STATE",
        ),
        (
            "continuing a complete reply",
            "vault.conversations.turn.continue",
            json!({"turn_id": complete}),
            "INVALID_STATE",
        ),
        (
            "a rebind with no live slip",
            "vault.conversations.turn.rebind",
            json!({"attempt_id": "0".repeat(32)}),
            "FORBIDDEN",
        ),
    ];
    for (name, verb, input, code) in rows {
        let refused = door::invoke(&owner, verb, input).expect_err(name);
        assert_eq!(refused.code, code, "{name}: {refused:?}");
    }
    assert_eq!(
        main_line(&vault, &conversation).len(),
        2,
        "no refused append moved the line"
    );
}
