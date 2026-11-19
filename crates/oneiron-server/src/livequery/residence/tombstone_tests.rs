//! The home's followed-world tombstone answer, `residence.tombstones`
//! (FOLLOWED-WORLD-TIER1-TOMBSTONE-IDS; canon ARCH-0023b :500: "Tier 1 ...
//! also carries the tombstone id set for every followed world. So a device
//! writes the delete marker even for a window it never held."). A device
//! whose followed window the home refuses to it still learns each delete it
//! may read, page by page. Before, the home answered no such call.
//!
//! Which ids leave is the selector export's own tombstone rule, proved
//! row by row in `crates/oneiron/tests/residence_tombstone_answer.rs`.

use super::*;
use crate::livequery::{production_tests, test_wire};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::sync::{SyncSelectorWorld, encode_sync_selector};
use oneiron::temporal::TimeRange;

fn reply(server: &SyncServer, auth: &CoreAuth, params: Value) -> Value {
    // An unproved peer keeps the device's unknown-destination set (OF-534 G6).
    let answer = run(
        server,
        auth,
        PeerMachine::Unknown,
        RpcRequest {
            request_id: 7,
            method: "residence.tombstones".into(),
            params,
        },
        &mut None,
        &mut None,
        &mut None,
    )
    .unwrap()
    .0;
    test_wire::reply(&answer.queued(0))
}

/// The ids of one answer page, in order, and its cursor.
fn page(answer: &Value) -> (Vec<String>, Option<String>) {
    let items = answer["result"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a tombstone page: {answer:#}"));
    let ids = items
        .iter()
        .map(|item| item["entityId"].as_str().expect("an id").to_owned())
        .collect();
    let cursor = answer["result"]["nextCursor"].as_str().map(str::to_owned);
    (ids, cursor)
}

/// A window of three PERSON rows, the first two hard-deleted, and the
/// actor's credential and encoded selector under a member grant on it: the
/// deleted ids in ascending order, and the live one.
async fn window_with_deletes(
    server: &SyncServer,
) -> (CoreAuth, WindowKey, String, [EntityId; 2], EntityId) {
    let actor = EntityId::from_hex(production_tests::ACTOR).unwrap();
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        crate::handler::selector_grant_scope(),
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(
        &server.vault,
        &grant_id,
        &grant,
        production_tests::AT,
    )
    .unwrap();
    let body = rmp_serde::to_vec_named(&json!({"title":"A row", "content":"words"})).unwrap();
    let mut deleted = [EntityId::now(), EntityId::now()];
    deleted.sort_unstable_by_key(EntityId::to_hex);
    let live = EntityId::now();
    for id in deleted.iter().chain([&live]) {
        server
            .vault
            .put_entity(
                id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: production_tests::AT,
                    end: production_tests::AT,
                },
                production_tests::AT,
                &body,
            )
            .unwrap();
    }
    for id in &deleted {
        assert!(
            server
                .vault
                .delete_entity_with_reason(id, oneiron::DeleteReason::UserHardDelete)
                .unwrap()
                .existed,
            "FIXTURE: the deleted row existed"
        );
    }
    let window = WindowKey::from_timestamp(production_tests::AT);
    server.get_or_create_window(&window).await.unwrap();
    let doc = server.reassert_manager.open_window(&window).unwrap();
    for id in &deleted {
        assert!(
            doc.doc.get_map("tombstones").get(&id.to_hex()).is_some(),
            "FIXTURE: the home's window holds the tombstone of {}",
            id.to_hex()
        );
    }
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let auth = crate::test_credentials::authenticate(server, &production_tests::token("human"));
    (auth, window, encoded, deleted, live)
}

/// The home answers a window's hard-deleted ids with their raw tombstone
/// values, one page at a time by an id cursor, and never a live row's id.
#[tokio::test]
async fn a_window_answers_the_ids_of_its_hard_deleted_rows() {
    let (_dir, server) = production_tests::server();
    let (auth, window, encoded, [first, second], live) = window_with_deletes(&server).await;

    let one = reply(
        &server,
        &auth,
        json!({"window": window.as_str(), "selector": encoded, "limit": 1}),
    );
    let (ids, cursor) = page(&one);
    assert_eq!(ids, vec![first.to_hex()], "the first page: {one:#}");
    assert_eq!(cursor.as_deref(), Some(first.to_hex().as_str()));
    let value = base64::engine::general_purpose::STANDARD
        .decode(one["result"]["items"][0]["value"].as_str().unwrap())
        .unwrap();
    assert_eq!(value.first(), Some(&2), "the hard delete's reason byte");
    assert_eq!(value.len(), 25, "the whole tombstone value");

    let two = reply(
        &server,
        &auth,
        json!({"window": window.as_str(), "selector": encoded, "after": cursor, "limit": 1}),
    );
    let (ids, cursor) = page(&two);
    assert_eq!(ids, vec![second.to_hex()], "the second page: {two:#}");
    let three = reply(
        &server,
        &auth,
        json!({"window": window.as_str(), "selector": encoded, "after": cursor, "limit": 1}),
    );
    let (ids, cursor) = page(&three);
    assert!(ids.is_empty() && cursor.is_none(), "the end: {three:#}");

    let whole = reply(
        &server,
        &auth,
        json!({"window": window.as_str(), "selector": encoded, "limit": 256}),
    );
    let (ids, cursor) = page(&whole);
    assert_eq!(ids, vec![first.to_hex(), second.to_hex()]);
    assert!(cursor.is_none());
    assert!(
        !whole.to_string().contains(&live.to_hex()),
        "a live row's id never rides the answer"
    );
}

/// A selector whose member is not the credential's principal looks missing,
/// as every residence read does: no id leaves.
#[tokio::test]
async fn another_members_selector_gets_no_ids() {
    let (_dir, server) = production_tests::server();
    let (auth, window, _encoded, [first, _], _) = window_with_deletes(&server).await;
    let stranger = SyncSelector::new(
        EntityId::now(),
        EntityId::now(),
        SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&stranger).unwrap());
    let answer = reply(
        &server,
        &auth,
        json!({"window": window.as_str(), "selector": encoded, "limit": 256}),
    );
    assert_eq!(answer["error"]["code"], "NOT_FOUND", "{answer:#}");
    assert!(!answer.to_string().contains(&first.to_hex()));
}
