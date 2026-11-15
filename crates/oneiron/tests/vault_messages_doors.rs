//! The `vault.messages.*` doors keep the reaction and message-lifecycle
//! promises. Every write and read enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares. No verb pages reactions, so they are read back through
//! the public `Vault::reaction_pills` and `Vault::reaction_history`.
//!
//! - `a_reaction_is_one_live_claim_per_person_and_glyph` (canon
//!   `oneiron/backend/oneiron-arch-0006a-conversations-api-core.md:12`, OF-372
//!   "Channel reactions (send/receive as first-class signals)"; chain law
//!   `crates/oneiron/src/reaction/mod.rs:13-16`): a repeat put answers the live
//!   claim, a remove retracts it, a re-add is a new claim, and the chain reads
//!   back in order.
//! - `a_reaction_is_read_and_made_only_by_the_rooms_readers` (arch-0006a:394
//!   "A reaction is read under the reader's credential too."): the room's
//!   members read the reaction; a PERSON outside the room reads no pill and
//!   cannot react.
//! - `a_message_no_stream_wrote_reads_as_complete` (canon
//!   `oneiron/core/oneiron-arch-0002-structural-entities.md:865-867`, an
//!   interrupted reply stays one message marked incomplete; the row reads its
//!   completion): a witnessed MESSAGE is complete with no receipt, and a TURN
//!   or unknown id reads as null.
//! - `a_malformed_or_foreign_message_act_is_refused`: one refusal table.
//!
//! Not in this file: provider ingress (`external`) is the served door's; the
//! in-process door refuses it (table row). An agent speaks only when
//! addressed or tasked (arch-0006a:243): no `vault.messages` row consults
//! that. A records-narrowed credential's durability read is the generic read
//! lane's (`key_value_credential_read.rs` pins that lane).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test vault_messages_doors`.
#![cfg(oneiron_test_support)]

use oneiron::memory::Memory;
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::{
    EdgeActorClass, EntityId, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN,
    MEMORY_CODE_NOT_FOUND, TimeRange, Vault,
};
use oneiron_testkit::{FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

const THUMBS_UP: &str = "\u{1F44D}";

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

/// A bare PERSON row; no verb mints one.
fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            name.as_bytes(),
        )
        .expect("a seeded person");
    id
}

fn hex(id: &str) -> EntityId {
    EntityId::from_hex(id).expect("a 32-hex id")
}

fn id_of(receipt: &Value) -> String {
    receipt["id"]
        .as_str()
        .expect("the receipt names its record")
        .to_owned()
}

/// A group conversation of the owner and bob (carol stays outside), its
/// first TURN, and one MESSAGE in that TURN, all written by the owner.
struct Room {
    turn: String,
    message: String,
    owner: EntityId,
    bob: EntityId,
    carol: EntityId,
}

fn seed(vault: &Vault) -> Room {
    let owner_door = door::owner(vault).expect("the owner");
    let owner = owner_door.actor();
    let bob = person(vault, "Bob");
    let carol = person(vault, "Carol");
    let conversation = id_of(
        &door::invoke(
            &owner_door,
            "vault.conversations.create",
            json!({"body": {"kind": "group", "title": "reactions",
                            "member_ids": [owner.to_hex(), bob.to_hex()]}}),
        )
        .expect("the owner creates a room with bob"),
    );
    let turn = id_of(
        &door::invoke(
            &owner_door,
            "vault.conversations.records.append",
            json!({"conversation": conversation, "advance": true,
                   "body": {"txt": "the question"}}),
        )
        .expect("the first TURN"),
    );
    let message = door::invoke(
        &owner_door,
        "vault.conversations.records.append",
        json!({"conversation": conversation, "containing_turn": turn, "advance": false,
               "body": {"author": "user", "type": "text", "content": "the question",
                        "is_visible": true, "order": 0}}),
    )
    .expect("the MESSAGE");
    assert_eq!(
        message["entity_type"].as_u64(),
        Some(u64::from(ENTITY_TYPE_MESSAGE)),
        "{message}"
    );
    Room {
        turn,
        message: id_of(&message),
        owner,
        bob,
        carol,
    }
}

fn react(caller: &Memory<'_>, message: &str, by: EntityId, occurred_at: u64) -> Value {
    door::invoke(
        caller,
        "vault.messages.react",
        json!({"message": message, "by": by.to_hex(), "glyph": THUMBS_UP,
               "occurred_at": occurred_at}),
    )
    .expect("the react lands")
}

fn unreact(caller: &Memory<'_>, message: &str, by: EntityId) -> Value {
    door::invoke(
        caller,
        "vault.messages.react",
        json!({"message": message, "by": by.to_hex(), "glyph": THUMBS_UP, "remove": true}),
    )
    .expect("the remove lands")
}

#[test]
fn a_reaction_is_one_live_claim_per_person_and_glyph() {
    let (_dir, vault) = fixture();
    let room = seed(&vault);
    let bob = vault.memory(room.bob, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let message = hex(&room.message);

    let put = react(&bob, &room.message, room.bob, now);
    assert_eq!(put["event"], "reaction.put", "{put}");
    let first = id_of(&put);
    let again = react(&bob, &room.message, room.bob, now);
    assert_eq!(
        (id_of(&again), again["event"].clone()),
        (first.clone(), json!("reaction.replayed")),
        "a repeat put answers the live claim"
    );
    let pills = vault
        .reaction_pills(&[message], room.owner)
        .expect("the owner's pills");
    assert_eq!(pills[&message].len(), 1, "{pills:?}");
    let pill = &pills[&message][0];
    assert_eq!(
        (pill.glyph.as_str(), pill.count, pill.mine),
        (THUMBS_UP, 1, false)
    );
    assert_eq!(pill.by, vec![room.bob]);

    let removed = unreact(&bob, &room.message, room.bob);
    assert_eq!(
        (id_of(&removed), removed["event"].clone()),
        (first.clone(), json!("reaction.revoked"))
    );
    let removed_again = unreact(&bob, &room.message, room.bob);
    assert_eq!(
        (id_of(&removed_again), removed_again["event"].clone()),
        (first.clone(), json!("reaction.replayed")),
        "removing nothing answers the last claim"
    );
    assert!(
        vault
            .reaction_pills(&[message], room.owner)
            .expect("the owner's pills")[&message]
            .is_empty()
    );

    let readded = react(&bob, &room.message, room.bob, vault.now_recorded_at());
    assert_eq!(readded["event"], "reaction.put", "{readded}");
    let second = id_of(&readded);
    assert_ne!(second, first, "a re-add is a new claim");
    let history = vault
        .reaction_history(message, room.bob, THUMBS_UP)
        .expect("the chain");
    assert_eq!(
        history.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![hex(&first), hex(&second)],
        "the chain reads back in order"
    );
    assert!(history[0].removed_at.is_some());
    assert_eq!(history[1].removed_at, None);
}

#[test]
fn a_reaction_is_read_and_made_only_by_the_rooms_readers() {
    let (_dir, vault) = fixture();
    let room = seed(&vault);
    let bob = vault.memory(room.bob, EdgeActorClass::Human);
    let carol = vault.memory(room.carol, EdgeActorClass::Human);
    let message = hex(&room.message);

    react(&bob, &room.message, room.bob, vault.now_recorded_at());
    let mine = vault
        .reaction_pills(&[message], room.bob)
        .expect("bob's pills");
    assert_eq!(mine[&message].len(), 1, "{mine:?}");
    assert!(mine[&message][0].mine);
    let owners = vault
        .reaction_pills(&[message], room.owner)
        .expect("the owner's pills");
    assert_eq!(owners[&message].len(), 1, "{owners:?}");
    assert!(!owners[&message][0].mine);
    let outside = vault
        .reaction_pills(&[message], room.carol)
        .expect("carol's pills");
    assert!(
        !outside.contains_key(&message),
        "a PERSON outside the room reads no pill: {outside:?}"
    );

    let refused = door::invoke(
        &carol,
        "vault.messages.react",
        json!({"message": room.message, "by": room.carol.to_hex(), "glyph": THUMBS_UP,
               "occurred_at": vault.now_recorded_at()}),
    )
    .expect_err("a PERSON outside the room cannot react");
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{refused:?}");
    assert!(
        vault
            .reaction_history(message, room.carol, THUMBS_UP)
            .expect("carol's chain")
            .is_empty(),
        "the refused react wrote no claim"
    );
}

#[test]
fn a_message_no_stream_wrote_reads_as_complete() {
    let (_dir, vault) = fixture();
    let room = seed(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let bob = vault.memory(room.bob, EdgeActorClass::Human);

    for caller in [&owner, &bob] {
        let read = door::invoke(
            caller,
            "vault.messages.durability",
            json!({"message_id": room.message}),
        )
        .expect("the durability read");
        let value = &read["value"];
        assert_eq!(value["message_id"], room.message.as_str(), "{read}");
        assert_eq!(
            value["completion"],
            json!({"incomplete": false, "generating": false, "finish_reason": null}),
            "a MESSAGE no stream wrote is complete: {read}"
        );
        assert!(value["latest_receipt"].is_null(), "{read}");
        assert_eq!(value["receipts"], json!([]), "{read}");
        assert!(read["narrowing"].is_object(), "{read}");
    }

    for id in [room.turn.clone(), EntityId::now().to_hex()] {
        let read = door::invoke(
            &owner,
            "vault.messages.durability",
            json!({"message_id": id}),
        )
        .expect("the durability read");
        assert!(
            read["value"].is_null(),
            "a TURN or unknown id is no MESSAGE: {read}"
        );
    }
}

#[test]
fn a_malformed_or_foreign_message_act_is_refused() {
    let (_dir, vault) = fixture();
    let room = seed(&vault);
    let owner = door::owner(&vault).expect("the owner");
    let bob = vault.memory(room.bob, EdgeActorClass::Human);
    let ghost_id = EntityId::now();
    let ghost = vault.memory(ghost_id, EdgeActorClass::Human);
    let now = vault.now_recorded_at();
    let message = room.message.as_str();
    let by = room.bob.to_hex();
    let unknown = EntityId::now().to_hex();
    let react = "vault.messages.react";
    let durability = "vault.messages.durability";
    let rows: Vec<(&str, &Memory<'_>, &str, Value, &str)> = vec![
        (
            "a reaction by another person",
            &bob,
            react,
            json!({"message": message, "by": room.owner.to_hex(), "glyph": THUMBS_UP, "occurred_at": now}),
            MEMORY_CODE_FORBIDDEN,
        ),
        (
            "provider ingress in-process",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": THUMBS_UP, "occurred_at": now,
                   "external": {"connector": "imessage", "id": "gen-1"}}),
            MEMORY_CODE_FORBIDDEN,
        ),
        (
            "an add without occurred_at",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": THUMBS_UP}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "an unknown message",
            &bob,
            react,
            json!({"message": unknown, "by": by, "glyph": THUMBS_UP, "occurred_at": now}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a bad message id",
            &bob,
            react,
            json!({"message": "not-hex", "by": by, "glyph": THUMBS_UP, "occurred_at": now}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "an empty glyph",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": "", "occurred_at": now}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a 65-scalar glyph",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": "x".repeat(65), "occurred_at": now}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a control character glyph",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": "a\u{0}b", "occurred_at": now}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "an occurrence an hour ahead",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": THUMBS_UP, "occurred_at": now + 3600}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "an occurrence an hour back",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": THUMBS_UP,
                   "occurred_at": now.saturating_sub(3600)}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a remove with no reaction",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": "\u{1F389}", "remove": true}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a caller the vault does not hold",
            &ghost,
            react,
            json!({"message": message, "by": ghost_id.to_hex(), "glyph": THUMBS_UP, "occurred_at": now}),
            MEMORY_CODE_NOT_FOUND,
        ),
        (
            "an unknown react field",
            &bob,
            react,
            json!({"message": message, "by": by, "glyph": THUMBS_UP, "occurred_at": now,
                   "weight": 1}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a bad durability id",
            &owner,
            durability,
            json!({"message_id": "not-hex"}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "a bad after_generation",
            &owner,
            durability,
            json!({"message_id": message, "after_generation": "zz"}),
            MEMORY_CODE_BAD_REQUEST,
        ),
        (
            "an unknown durability field",
            &owner,
            durability,
            json!({"message_id": message, "since": 1}),
            MEMORY_CODE_BAD_REQUEST,
        ),
    ];
    for (name, caller, verb, input, code) in rows {
        let Err(refused) = door::invoke(caller, verb, input) else {
            panic!("{name} was not refused");
        };
        assert_eq!(refused.code, code, "{name}: {refused:?}");
    }
    let message = hex(message);
    assert!(
        vault
            .reaction_pills(&[message], room.owner)
            .expect("the owner's pills")[&message]
            .is_empty(),
        "no refused react wrote"
    );
    assert!(
        vault
            .reaction_history(message, room.bob, THUMBS_UP)
            .expect("bob's chain")
            .is_empty()
    );
}
