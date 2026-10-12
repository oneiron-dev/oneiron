#![allow(clippy::unwrap_used)]
//! Sol on the device-local reads (F6, R2 F1 and F8): a live view keeps the
//! pushes it derived for a resume or a redelivery. Off this device none of
//! them leaves again once a row it serves turns device-local, whether its
//! world is flagged later or the row moves into a flagged world: the client
//! gets a gap and a fresh snapshot.
use super::production_tests::{ACTOR, AT, server, token};
use super::source::BoundSource;
use super::*;
use crate::server::SyncServer;
use oneiron::memory::ClaimInput;
use oneiron::sync::bridge::LiveQueryTee;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

const CLAIM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Two views of `view` for a caller off this device (as every test
/// credential is), opened while nothing matches them, and the snapshot
/// cursor the client holds for the first.
struct Views {
    queries: Arc<subscriptions::LiveQueries>,
    view: ScopedView,
    held: Cursor,
}

fn put_world(server: &SyncServer, hex: &str) -> EntityId {
    let world = EntityId::from_hex(hex).unwrap();
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
    world
}

impl Views {
    fn open(server: &Arc<SyncServer>, view: ScopedView) -> Self {
        let auth = crate::test_credentials::authenticate(server, &token("human"));
        let source = Arc::new(BoundSource::new(
            Arc::downgrade(server),
            auth,
            "device-local-history".into(),
        ));
        let queries = Arc::new(subscriptions::LiveQueries::new(1, source));
        let tee: Arc<dyn LiveQueryTee> = queries.clone();
        server
            .reassert_manager
            .materializer()
            .attach_live_query_tee(&tee);
        let held = queries
            .open(1, view.clone(), Channel::View, None, None)
            .unwrap()[0]
            .cursor
            .clone();
        queries
            .open(2, view.clone(), Channel::View, None, None)
            .unwrap();
        Self {
            queries,
            view,
            held,
        }
    }

    /// Both views pushed the claim: its short id is in each one's ring.
    fn pushed(&self, short_id: &str) {
        for id in [1, 2] {
            assert!(
                names(&self.queries.pending(id).unwrap(), short_id),
                "view {id} pushed it"
            );
        }
    }

    /// A resume from the held cursor, and a redelivery of the second view's
    /// ring, send nothing pushed while the claim could leave.
    fn resend_nothing_of(&self, short_id: &str) {
        let resumed = self
            .queries
            .open(1, self.view.clone(), Channel::View, Some(&self.held), None)
            .unwrap();
        assert!(!names(&resumed, short_id), "{resumed:?}");
        assert_eq!(
            resumed.iter().map(|push| push.kind).collect::<Vec<_>>(),
            ["gap", "snapshot", "eose"]
        );
        let redelivered = self.queries.buffered().unwrap();
        assert!(!names(&redelivered, short_id), "{redelivered:?}");
        assert!(
            redelivered
                .iter()
                .any(|push| push.subscription_id == 2 && push.kind == "gap"),
            "{redelivered:?}"
        );
    }
}

fn names(pushes: &[subscriptions::Push], short_id: &str) -> bool {
    serde_json::to_string(pushes).unwrap().contains(short_id)
}

/// The claim, in `world`, matching the views; its short id once both views
/// pushed it.
async fn push_claim(server: &SyncServer, views: &Views, world: EntityId) -> String {
    let window_key = oneiron::sync::WindowKey::from_timestamp(AT);
    let window = server.get_or_create_window(&window_key).await.unwrap();
    let claim = EntityId::from_hex(CLAIM).unwrap();
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
    views.queries.refresh().unwrap();
    views.pushed(&receipt.claim_short_id);
    receipt.claim_short_id
}

#[tokio::test]
async fn a_view_pushed_while_its_world_was_portable_resends_none_of_it_once_device_local() {
    let (_dir, server) = server();
    let world = put_world(&server, "77777777777777777777777777777777");
    let views = Views::open(
        &server,
        ScopedView {
            query: Some("orchidneedle".into()),
            world_ref: Some(world.to_hex()),
            ..Default::default()
        },
    );
    let short_id = push_claim(&server, &views, world).await;

    server.vault().set_world_device_only(world, true).unwrap();
    views.resend_nothing_of(&short_id);
}

#[tokio::test]
async fn a_view_resends_nothing_of_a_claim_moved_into_a_device_local_world() {
    let (_dir, server) = server();
    let kept = put_world(&server, "77777777777777777777777777777777");
    let open = put_world(&server, "88888888888888888888888888888888");
    server.vault().set_world_device_only(kept, true).unwrap();
    let views = Views::open(
        &server,
        ScopedView {
            query: Some("orchidneedle".into()),
            ..Default::default()
        },
    );
    let short_id = push_claim(&server, &views, open).await;

    // The claim moves into the flagged world: no flag changes.
    let claim = EntityId::from_hex(CLAIM).unwrap();
    let mut body = server.vault().get_claim(&claim).unwrap().unwrap();
    body.world = Some(kept);
    server
        .vault()
        .put_claim(
            &claim,
            &body,
            oneiron::temporal::TimeRange { start: AT, end: AT },
            AT,
        )
        .unwrap();
    views.resend_nothing_of(&short_id);
}
