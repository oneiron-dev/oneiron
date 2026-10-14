#![allow(clippy::unwrap_used)]
//! Sol on the device-local reads (F6, R2 F1 and F8, R3 F1): a live
//! subscription keeps the pushes it derived, for a resume, a redelivery and
//! a frame already queued for its socket. Each is judged again when it is
//! released: off this device none naming a row a device-local world keeps
//! now leaves again, and the client gets a gap and a fresh snapshot. On this
//! device they all still go out.
use super::production_tests::{ACTOR, AT, server, token};
use super::source::BoundSource;
use super::subscriptions::LiveQuerySource as _;
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
/// cursor. Off this device it replays none derived from a claim whose world
/// turned device-local since, even one whose body names the claim only by a
/// short ref: the client gets a gap and a fresh snapshot.
#[tokio::test]
async fn a_resume_off_this_device_replays_no_push_naming_a_device_local_row() {
    let (_dir, server) = server();
    let world = put_world(&server);
    let claim = put_claim(&server, world);
    let view = ScopedView::default();
    for locality in [CallerLocality::OnDevice, CallerLocality::OffDevice] {
        server
            .vault()
            .keep_world_on_this_machine_under_for_test(
                &crate::test_credentials::host_issuer(&server),
                world,
                false,
            )
            .unwrap();
        let (queries, source) = subscriptions(&server, locality);
        let anchor = queries
            .open(7, view.clone(), Channel::Receipts, None, None)
            .unwrap()[0]
            .cursor
            .clone();
        // A push the journal kept, derived from the claim while its world
        // was portable.
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
                    result: Some(json!([{ "claim": &claim[..8] }])),
                    rows: vec![EntityId::from_hex(&claim).unwrap()],
                }],
            )
            .unwrap();
        queries.close(7).unwrap();
        let resumed = queries
            .open(7, view.clone(), Channel::Receipts, Some(&anchor), None)
            .unwrap();
        assert!(names(&resumed, &claim[..8]), "{locality:?}: {resumed:?}");
        queries.close(7).unwrap();

        server
            .vault()
            .keep_world_on_this_machine_under_for_test(
                &crate::test_credentials::host_issuer(&server),
                world,
                true,
            )
            .unwrap();
        let resumed = queries
            .open(7, view.clone(), Channel::Receipts, Some(&anchor), None)
            .unwrap();
        if locality == CallerLocality::OnDevice {
            assert!(names(&resumed, &claim[..8]), "{resumed:?}");
        } else {
            assert!(!names(&resumed, &claim[..8]), "{resumed:?}");
            assert_eq!(kinds(&resumed), ["gap", "snapshot", "eose"]);
        }
    }
}

/// A socket's reply queue holds the frames a subscription's open derived,
/// each with the rows it was derived from (Sol R4 F2). Once the claim they
/// name is device-local, off this device the queued body is not released at
/// the socket's send door, nothing more of the subscription leaves before
/// its gap, and the gap is what goes out. On this device they all still go
/// out.
#[tokio::test]
async fn a_body_queued_off_this_device_is_not_released_once_its_row_is_device_local() {
    let (_dir, server) = server();
    let world = put_world(&server);
    let claim = put_claim(&server, world);
    // The receipts of the claims in W.
    let view = ScopedView {
        world_ref: Some(world.to_hex()),
        ..ScopedView::default()
    };
    let (here, _) = subscriptions(&server, CallerLocality::OnDevice);
    let opened = here
        .open(3, view.clone(), Channel::Receipts, None, None)
        .unwrap();
    assert!(names(&opened, &claim), "{opened:?}");
    // Off this device, as every test credential is: the frames the open
    // queued for the socket.
    let (mut socket, queued) = open_socket(&server, 3, &view);
    assert!(queued.iter().any(|frame| spells(frame)));
    let off = CallerLocality::OffDevice;
    assert!(
        queued
            .iter()
            .all(|frame| socket.release(off, frame).is_some())
    );

    server
        .vault()
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    assert!(names(&here.buffered().unwrap(), &claim));
    let on = CallerLocality::OnDevice;
    assert!(
        queued
            .iter()
            .all(|frame| socket.release(on, frame).is_some())
    );
    let released: Vec<_> = queued
        .iter()
        .filter_map(|frame| socket.release(off, frame))
        .collect();
    assert!(released.is_empty(), "{released:?}");
    let redelivered = socket.delivery().unwrap();
    assert_eq!(redelivered.len(), 1);
    assert!(!spells(&redelivered[0]));
    let gap = socket.release(off, &redelivered[0]).unwrap();
    assert_eq!(test_wire::reply(&[gap])["kind"], "gap");
}

/// Sol R4 F5: a frame queued for a subscription is released only to the
/// incarnation it was derived for. Once the caller closes the subscription
/// and opens the same id again, a frame of the earlier one is dropped, never
/// judged against the new one, and the reopened subscription gets its own
/// snapshot.
#[tokio::test]
async fn a_frame_queued_for_a_closed_subscription_reaches_no_reopened_one() {
    let (_dir, server) = server();
    let world = put_world(&server);
    put_claim(&server, world);
    let view = ScopedView {
        world_ref: Some(world.to_hex()),
        ..ScopedView::default()
    };
    let (mut socket, queued) = open_socket(&server, 3, &view);
    assert!(queued.iter().any(|frame| spells(frame)));

    server
        .vault()
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    let auth = crate::test_credentials::authenticate(&server, &token("human"));
    socket
        .control(&auth, SubRequest::Close { subscription_id: 3 })
        .unwrap();
    let reopened = socket
        .control(&auth, open(3, &ScopedView::default()))
        .unwrap();
    assert!(!reopened.iter().any(|frame| spells(frame)));
    let off = CallerLocality::OffDevice;
    let released: Vec<_> = queued
        .iter()
        .filter_map(|frame| socket.release(off, frame))
        .collect();
    assert!(released.is_empty(), "{released:?}");
    assert!(
        reopened
            .iter()
            .all(|frame| socket.release(off, frame).is_some())
    );
}

fn open(id: u64, view: &ScopedView) -> SubRequest {
    SubRequest::Open {
        subscription_id: id,
        scoped_view: view.clone(),
        channel: Channel::Receipts,
        cursor: None,
        origin: None,
    }
}

/// A socket off this device with subscription `id` open on `view`, and the
/// frames the open queued for it.
fn open_socket(
    server: &Arc<SyncServer>,
    id: u64,
    view: &ScopedView,
) -> (connection::Connection, Vec<Vec<u8>>) {
    let hub = connection::Hub::for_server(server);
    let mut socket = connection::Connection::new(hub, 9);
    let auth = crate::test_credentials::authenticate(server, &token("human"));
    let queued = socket.control(&auth, open(id, view)).unwrap();
    (socket, queued)
}

/// Sol R4 F2: an open's snapshot waits in its socket's reply queue with the
/// rows it was derived from. Once one of them is device-local, off this
/// device the snapshot is not sent at the queue's send door: the subscriber
/// gets a gap.
#[tokio::test]
async fn a_queued_snapshot_off_this_device_names_no_row_turned_device_local() {
    let f = production_socket_tests::fixture().await;
    let world = put_world(&f.server);
    put_claim(&f.server, world);
    let mut socket = production_socket_tests::connect(&f, "human").await;
    release_hook::arm(world);
    production_socket_tests::send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":3,
        "scopedView":{"worldRef":world.to_hex()},"channel":"receipts"}),
    )
    .await;
    let first = production_socket_tests::app(&mut socket, TAG_SUB).await;
    assert_eq!(first["kind"], "gap", "{first}");
}

/// Sol R4 F2: a read's result waits in its socket's reply queue with the
/// rows it carries, though it names a row by short ref alone and the read
/// named none. Once one of them is device-local, the result is refused at
/// the send door: off this device the caller reads only that the result
/// changed, and the read repeated finds nothing.
#[tokio::test]
async fn a_queued_read_result_off_this_device_names_no_row_turned_device_local() {
    let f = production_socket_tests::fixture().await;
    let world = put_world(&f.server);
    let claim = put_claim(&f.server, world);
    f.server
        .vault()
        .batch()
        .text(
            &EntityId::from_hex(&claim).unwrap(),
            &[("body", "orchid kept")],
        )
        .commit()
        .unwrap();
    let mut socket = production_socket_tests::connect(&f, "human").await;
    let search = json!({"requestId":8,"method":"queryBm25",
        "params":{"query":"orchid","limit":10}});
    let mut read = async || {
        production_socket_tests::send(&mut socket, TAG_RPC, search.clone()).await;
        production_socket_tests::app(&mut socket, TAG_RPC).await
    };
    let portable = read().await;
    assert_eq!(
        portable["result"]["value"].as_array().map(Vec::len),
        Some(1),
        "{portable}"
    );
    assert!(!portable.to_string().contains(&claim), "{portable}");

    release_hook::arm(world);
    let refused = read().await;
    assert_eq!(refused["error"]["code"], "RESULT_CHANGED", "{refused}");
    assert!(refused.get("result").is_none(), "{refused}");
    let fresh = read().await;
    assert_eq!(fresh["result"]["value"], json!([]), "{fresh}");
}
