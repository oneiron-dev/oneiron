//! The change feed verbs (untangle slice 6.8d) through the generated verb dispatch
//! (`oneiron::task_verb::sdk::invoke`), as a client calls them: JSON in, JSON out, on the
//! caller's own `Memory`. Run with `cargo test -p oneiron --all-features --test feed_verbs`.

use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Memory, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

fn open() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    (dir, vault)
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb}: {error:?}"))
}

fn put_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("person");
    id
}

/// Subscribe, read, ack, list, resync and unsubscribe, each through its verb: the page shows the
/// PERSON written after subscribing, the ack moves the cursor so the next page is empty, the
/// resync stands it at the head, and the subscription is the caller's until it ends.
#[test]
fn the_feed_verbs_follow_one_subscription_from_subscribe_to_unsubscribe() {
    let (_dir, vault) = open();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let subscribed = call(
        &memory,
        "vault.feeds.subscribe",
        json!({"selector": {"sources": ["changes"]}, "start": "head"}),
    );
    let subscription = subscribed["subscription"].clone();
    assert!(subscription.is_string(), "{subscribed}");
    assert_eq!(subscribed["actor"], json!(owner.to_hex()), "{subscribed}");

    let person = put_person(&vault);
    let page = call(
        &memory,
        "vault.feeds.read",
        json!({"subscription": subscription}),
    );
    assert_eq!(page["status"], "page", "{page}");
    let entries = page["entries"].as_array().expect("entries");
    assert!(
        entries
            .iter()
            .any(|entry| entry["entity"] == json!(person.to_hex()) && entry["kind"] == "edit"),
        "{page}"
    );
    let through = page["through"].clone();
    assert_eq!(through.as_array().map(Vec::len), Some(1), "{page}");

    let acked = call(
        &memory,
        "vault.feeds.ack",
        json!({"subscription": subscription, "through": through}),
    );
    assert_eq!(
        acked["cursors"].as_array().map(Vec::len),
        Some(1),
        "one sealed cursor per source: {acked}"
    );
    let next = call(
        &memory,
        "vault.feeds.read",
        json!({"subscription": subscription}),
    );
    assert_eq!(next["entries"], json!([]), "{next}");

    let listed = call(&memory, "vault.feeds.list", json!({}));
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "{listed}");
    let resynced = call(
        &memory,
        "vault.feeds.resync",
        json!({"subscription": subscription}),
    );
    assert_eq!(resynced["subscription"], subscription, "{resynced}");
    assert_eq!(
        call(
            &memory,
            "vault.feeds.read",
            json!({"subscription": subscription}),
        )["entries"],
        json!([]),
        "the resync stands at the head"
    );
    assert_eq!(
        call(
            &memory,
            "vault.feeds.unsubscribe",
            json!({"subscription": subscription}),
        ),
        json!(true)
    );
    assert_eq!(call(&memory, "vault.feeds.list", json!({})), json!([]));
    assert!(
        invoke(
            &memory,
            "vault.feeds.read",
            json!({"subscription": subscription}),
        )
        .is_err(),
        "an ended subscription reads nothing"
    );
}

/// A subscription is its actor's own: another actor's verbs neither read nor end it.
#[test]
fn another_actors_feed_verbs_do_not_reach_a_subscription() {
    let (_dir, vault) = open();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let subscription = call(
        &memory,
        "vault.feeds.subscribe",
        json!({"selector": {"sources": ["changes", "settlements"]}}),
    )["subscription"]
        .clone();

    let other = put_person(&vault);
    let stranger = vault.memory(other, EdgeActorClass::Human);
    assert!(
        invoke(
            &stranger,
            "vault.feeds.read",
            json!({"subscription": subscription}),
        )
        .is_err()
    );
    if let Ok(ended) = invoke(
        &stranger,
        "vault.feeds.unsubscribe",
        json!({"subscription": subscription}),
    ) {
        assert_eq!(ended, json!(false));
    }
    assert_eq!(
        call(&memory, "vault.feeds.list", json!({}))
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}
