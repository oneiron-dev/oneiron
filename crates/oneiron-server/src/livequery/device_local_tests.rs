#![allow(clippy::unwrap_used)]
//! Sol on the device-local reads (F6): a live view keeps the pushes it
//! derived while its world was portable, for a resume or a redelivery. Once
//! the world turns device-local none of them leaves again: the client gets a
//! gap and a fresh snapshot.
use super::production_tests::{ACTOR, AT, server, token};
use super::source::BoundSource;
use super::*;
use oneiron::memory::ClaimInput;
use oneiron::sync::bridge::LiveQueryTee;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

#[tokio::test]
async fn a_view_pushed_while_its_world_was_portable_resends_none_of_it_once_device_local() {
    let (_dir, server) = server();
    let window_key = oneiron::sync::WindowKey::from_timestamp(AT);
    let window = server.get_or_create_window(&window_key).await.unwrap();
    let world = EntityId::from_hex("77777777777777777777777777777777").unwrap();
    server
        .vault()
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::temporal::TimeRange { start: AT, end: AT },
            AT,
            b"world",
        )
        .unwrap();
    // A caller off this device, as every test credential is.
    let auth = crate::test_credentials::authenticate(&server, &token("human"));
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth,
        "device-local-history".into(),
    ));
    let queries = Arc::new(subscriptions::LiveQueries::new(1, source.clone()));
    let tee: Arc<dyn LiveQueryTee> = queries.clone();
    server
        .reassert_manager
        .materializer()
        .attach_live_query_tee(&tee);
    let view = ScopedView {
        query: Some("orchidneedle".into()),
        world_ref: Some(world.to_hex()),
        ..Default::default()
    };
    // Two views of the world, open while it is empty: the client holds the
    // first one's snapshot cursor.
    let held = queries
        .open(1, view.clone(), Channel::View, None, None)
        .unwrap()[0]
        .cursor
        .clone();
    queries
        .open(2, view.clone(), Channel::View, None, None)
        .unwrap();

    // A claim joins the world while it is portable; both views push it.
    let claim = EntityId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let receipt = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(claim.to_hex()),
            predicate: "profile.orchid".into(),
            subject_ref: ACTOR.into(),
            value: json!("kept"),
            confidence: 1.0,
            source: "user_stated".into(),
            world_ref: Some(world.to_hex()),
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(AT),
            learned_at: Some(AT),
            salience: None,
        })
        .unwrap();
    server
        .vault()
        .batch()
        .text(&claim, &[("body", "orchidneedle kept")])
        .commit()
        .unwrap();
    oneiron::sync::window::reverse_rematerialize(server.vault(), &window, &window_key).unwrap();
    queries.refresh().unwrap();
    let names = |pushes: &[subscriptions::Push]| {
        serde_json::to_string(pushes)
            .unwrap()
            .contains(&receipt.claim_short_id)
    };
    for id in [1, 2] {
        assert!(names(&queries.pending(id).unwrap()), "view {id} pushed it");
    }

    server.vault().set_world_device_only(world, true).unwrap();
    // A resume from the held cursor replays nothing pushed before the flag.
    let resumed = queries
        .open(1, view.clone(), Channel::View, Some(&held), None)
        .unwrap();
    assert!(!names(&resumed), "{resumed:?}");
    assert_eq!(
        resumed.iter().map(|push| push.kind).collect::<Vec<_>>(),
        ["gap", "snapshot", "eose"]
    );
    // Nor does a redelivery of the other view's ring.
    let redelivered = queries.buffered().unwrap();
    assert!(!names(&redelivered), "{redelivered:?}");
    assert!(
        redelivered
            .iter()
            .any(|push| push.subscription_id == 2 && push.kind == "gap"),
        "{redelivered:?}"
    );
}
