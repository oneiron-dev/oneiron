#![allow(clippy::unwrap_used)]
//! Sol on the device-local reads (F6, R2 F1 and F8, R3 F1): a live
//! subscription keeps the pushes it derived, for a resume, a redelivery and
//! a frame already queued for its socket. Each is judged again when it is
//! released: off this device none naming a row a device-local world keeps
//! now leaves again, and the client gets a gap and a fresh snapshot. On this
//! device they all still go out.
use super::production_tests::{ACTOR, AT, server, token};
use super::source::BoundSource;
use super::*;
use crate::server::SyncServer;
use oneiron::claim::CallerLocality;
use oneiron::memory::ClaimInput;
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

const CLAIM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn put_world(server: &SyncServer) -> EntityId {
    let world = EntityId::now();
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

/// A claim by the test actor in `world`: its gate receipt is a row of the
/// actor's receipts subscription, naming the claim.
fn put_claim(server: &SyncServer, world: EntityId) -> String {
    server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: Some(CLAIM.into()),
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
    CLAIM.to_owned()
}

/// The test actor's subscriptions read from `locality`, and their source.
fn subscriptions(
    server: &Arc<SyncServer>,
    locality: CallerLocality,
) -> (subscriptions::LiveQueries, Arc<BoundSource>) {
    let auth = crate::test_credentials::authenticate(server, &token("human")).at(locality);
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(server),
        auth,
        "device-local".into(),
    ));
    (subscriptions::LiveQueries::new(1, source.clone()), source)
}

fn names(pushes: &[subscriptions::Push], id: &str) -> bool {
    serde_json::to_string(pushes).unwrap().contains(id)
}

/// Whether an encoded frame spells the claim's id.
fn spells(frame: &[u8]) -> bool {
    frame.windows(CLAIM.len()).any(|w| w == CLAIM.as_bytes())
}

fn kinds(pushes: &[subscriptions::Push]) -> Vec<&'static str> {
    pushes.iter().map(|push| push.kind).collect()
}

/// A resume replays the pushes its source journaled after the client's
/// cursor. Off this device it replays none naming a claim whose world turned
/// device-local since: the client gets a gap and a fresh snapshot.
#[tokio::test]
async fn a_resume_off_this_device_replays_no_push_naming_a_device_local_row() {
    let (_dir, server) = server();
    let world = put_world(&server);
    let claim = put_claim(&server, world);
    let view = ScopedView {
        query: Some("unmatched".into()),
        ..Default::default()
    };
    for locality in [CallerLocality::OnDevice, CallerLocality::OffDevice] {
        server.vault().set_world_device_only(world, false).unwrap();
        let (queries, source) = subscriptions(&server, locality);
        let anchor = queries
            .open(7, view.clone(), Channel::Receipts, None, None)
            .unwrap()[0]
            .cursor
            .clone();
        // A push the journal kept, naming the claim while its world was
        // portable.
        let mut next = anchor.clone();
        next.batch = anchor.batch + 1;
        source
            .record(
                &view,
                Channel::Receipts,
                &[subscriptions::Push {
                    subscription_id: 7,
                    cursor: next,
                    kind: "data",
                    result: Some(json!([{ "claim_ref": claim }])),
                }],
            )
            .unwrap();
        queries.close(7).unwrap();
        let resumed = queries
            .open(7, view.clone(), Channel::Receipts, Some(&anchor), None)
            .unwrap();
        assert!(names(&resumed, &claim), "{locality:?}: {resumed:?}");
        queries.close(7).unwrap();

        server.vault().set_world_device_only(world, true).unwrap();
        let resumed = queries
            .open(7, view.clone(), Channel::Receipts, Some(&anchor), None)
            .unwrap();
        if locality == CallerLocality::OnDevice {
            assert!(names(&resumed, &claim), "{resumed:?}");
        } else {
            assert!(!names(&resumed, &claim), "{resumed:?}");
            assert_eq!(kinds(&resumed), ["gap", "snapshot", "eose"]);
        }
    }
}

/// A subscription's ring holds what it has not had acknowledged, and a
/// socket may hold a frame of it queued. Once the claim they name is
/// device-local, off this device the queued body is not released and the
/// redelivery is a gap. On this device both still go out.
#[tokio::test]
async fn a_body_queued_off_this_device_is_not_released_once_its_row_is_device_local() {
    let (_dir, server) = server();
    let world = put_world(&server);
    let claim = put_claim(&server, world);
    let (here, _) = subscriptions(&server, CallerLocality::OnDevice);
    let opened = here
        .open(3, ScopedView::default(), Channel::Receipts, None, None)
        .unwrap();
    assert!(names(&opened, &claim), "{opened:?}");
    // Off this device, as every test credential is: the frames a socket
    // was sent, queued again as a broadcast copy.
    let hub = connection::Hub::for_server(&server);
    let mut socket = connection::Connection::new(hub, 9);
    let auth = crate::test_credentials::authenticate(&server, &token("human"));
    let queued: Vec<_> = socket
        .control(
            &auth,
            SubRequest::Open {
                subscription_id: 3,
                scoped_view: ScopedView::default(),
                channel: Channel::Receipts,
                cursor: None,
                origin: None,
            },
        )
        .unwrap()
        .into_iter()
        .map(|frame| routing::wrap(9, 3, frame))
        .collect();
    assert!(queued.iter().any(|frame| spells(frame.as_slice())));
    assert!(
        queued
            .iter()
            .all(|frame| socket.receive_broadcast(frame).is_some())
    );

    server.vault().set_world_device_only(world, true).unwrap();
    assert!(here.releases(3).unwrap());
    assert!(names(&here.buffered().unwrap(), &claim));
    let released: Vec<_> = queued
        .iter()
        .filter_map(|frame| socket.receive_broadcast(frame))
        .collect();
    assert!(!released.iter().any(|frame| spells(frame.as_slice())));
    let redelivered = socket.delivery().unwrap();
    assert_eq!(redelivered.len(), 1);
    assert!(!spells(&redelivered[0]));
}
