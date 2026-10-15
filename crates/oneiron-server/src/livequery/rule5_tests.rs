#![allow(clippy::unwrap_used)]
//! Rule five at the live-query rows (census rows 20 to 24): past a row the
//! next session or subscription waits its turn and is served, or meets its
//! deadline as a typed timeout; retained state is charged to the
//! retained-memory line, where one piece larger than the whole line runs
//! alone and only a full line, the memory floor, refuses; a crossing asks.
use super::subscriptions::{DerivedView, LiveQueries, LiveQuerySource};
use super::*;
use crate::admission::Crossing;
use crate::byte_line::ByteLine;
use crate::config::LimitsConfig;
use crate::server::SyncServer;
use crate::wire_telemetry::{LimitQuestions, LimitRow};
use oneiron::sync::bridge::{MaterializedDiffSummary, OriginMark};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

const MIB: usize = 1024 * 1024;

fn open(id: u64) -> SubRequest {
    SubRequest::Open {
        subscription_id: id,
        scoped_view: ScopedView::default(),
        channel: Channel::Receipts,
        cursor: None,
        origin: None,
    }
}

fn auth(server: &SyncServer) -> CoreAuth {
    crate::test_credentials::authenticate(server, &production_tests::token("human"))
}

/// Opens subscription `id` on `socket` as the socket loop does: its turns
/// first, then the request. `None` when it is served, else the refusal's code.
async fn subscribe(
    socket: &mut connection::Connection,
    auth: &CoreAuth,
    id: u64,
) -> Option<String> {
    let payload = test_wire::request(
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":id,"scopedView":{},"channel":"receipts"}),
    );
    socket.admit(Some(auth), &payload[1..]).await;
    let frames = socket.control(auth, open(id)).unwrap();
    (!socket.opened(id)).then(|| {
        test_wire::reply(&frames)["error"]["code"]
            .as_str()
            .unwrap()
            .to_owned()
    })
}

async fn settle(mut done: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the line never settled");
}

/// How many times `row` was crossed, as its question counts them.
fn crossings(server: &SyncServer, row: LimitRow) -> u64 {
    server
        .wire_telemetry
        .limit_questions()
        .latest(row)
        .map_or(0, |question| question.crossings)
}

/// Crosses `limits.live_sessions` set to one: a socket holds the only
/// session, `callers` more wait their turn behind it, and each is served once
/// the socket before it goes.
pub(crate) async fn cross_the_sessions(callers: usize) -> Crossing {
    let (_dir, server) = production_tests::server_with_limits(LimitsConfig {
        live_sessions: 1,
        ..LimitsConfig::default()
    });
    let (refused, _) = queue_behind_one(&server, callers, |_| async {}).await;
    Crossing {
        refused,
        asked: crossings(&server, LimitRow::LiveSessions) > 0,
    }
}

/// Crosses `limits.live_subscriptions` set to one: a socket holds the only
/// subscription, `callers` more wait their turn behind it, and each is
/// served once the one before it closes.
pub(crate) async fn cross_the_subscriptions(callers: usize) -> Crossing {
    let (_dir, server) = production_tests::server_with_limits(LimitsConfig {
        live_subscriptions: 1,
        ..LimitsConfig::default()
    });
    let (refused, _) = queue_behind_one(&server, callers, close).await;
    Crossing {
        refused,
        asked: crossings(&server, LimitRow::LiveSubscriptions) > 0,
    }
}

/// Closes a served socket's subscription, so its turn passes on.
async fn close((mut socket, auth): (connection::Connection, CoreAuth)) {
    socket
        .control(&auth, SubRequest::Close { subscription_id: 1 })
        .unwrap();
}

/// One socket subscribes, `callers` more queue behind it on one credential,
/// then the first lets go. Each caller hands its socket to `done` once it is
/// served. Returns how many were refused, and the line's waiters before the
/// first let go.
async fn queue_behind_one<F, D>(
    server: &Arc<SyncServer>,
    callers: usize,
    done: D,
) -> (usize, (usize, usize))
where
    D: Fn((connection::Connection, CoreAuth)) -> F + Clone + Send + 'static,
    F: std::future::Future<Output = ()> + Send,
{
    let hub = connection::Hub::for_server(server);
    let auth = auth(server);
    let mut first = connection::Connection::new(Arc::clone(&hub), 1);
    let mut refused = usize::from(subscribe(&mut first, &auth, 1).await.is_some());
    let waiters: Vec<_> = (0..callers)
        .map(|n| {
            let (hub, auth, done) = (Arc::clone(&hub), auth.clone(), done.clone());
            tokio::spawn(async move {
                let mut socket = connection::Connection::new(hub, 2 + n as u32);
                let refusal = subscribe(&mut socket, &auth, 1).await;
                if refusal.is_none() {
                    done((socket, auth)).await;
                }
                refusal
            })
        })
        .collect();
    settle(|| {
        let (sessions, subscriptions) = hub.waiting();
        sessions + subscriptions == callers
    })
    .await;
    let waiting = hub.waiting();
    first
        .control(&auth, SubRequest::Close { subscription_id: 1 })
        .unwrap();
    drop(first);
    for waiter in waiters {
        if let Some(code) = waiter.await.unwrap() {
            eprintln!("a waiter was refused: {code}");
            refused += 1;
        }
    }
    (refused, waiting)
}

/// Bug repro (rule 5, rows 21 and 24): the hub refused a 65th live-query
/// session, and a session its 129th subscription. Done-means: both are
/// served on one credential.
#[tokio::test]
async fn sessions_and_subscriptions_past_the_old_counts_are_served() {
    let (_dir, server) = production_tests::server();
    let hub = connection::Hub::for_server(&server);
    let auth = auth(&server);
    let sockets: Vec<_> = (1..=65)
        .map(|conn| {
            let mut socket = connection::Connection::new(Arc::clone(&hub), conn);
            socket.control(&auth, open(1)).unwrap();
            assert!(socket.has_active_subscriptions(), "session {conn} refused");
            socket
        })
        .collect();
    drop(sockets);
    let mut socket = connection::Connection::new(Arc::clone(&hub), 100);
    for id in 1..=129 {
        let frames = socket.control(&auth, open(id)).unwrap();
        assert!(
            routing::addressed(&frames[0], 100).is_some(),
            "subscription {id} refused"
        );
    }
}

/// Done-means (rule 5, row 21): past the session row the next sessions wait
/// their turn and are served, on one credential, and the row asks once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_session_row_sessions_wait_their_turn_and_are_served() {
    let (_dir, server) = production_tests::server_with_limits(LimitsConfig {
        live_sessions: 1,
        ..LimitsConfig::default()
    });
    let (refused, waiting) = queue_behind_one(&server, 4, |_| async {}).await;
    assert_eq!(waiting, (4, 0), "past the row the sessions wait");
    assert_eq!(refused, 0);
    assert_eq!(crossings(&server, LimitRow::LiveSessions), 1);
}

/// Done-means (rule 5, row 24): past the subscription row the next
/// subscriptions wait their turn and are served, and the row asks once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn past_the_subscription_row_subscriptions_wait_their_turn_and_are_served() {
    let (_dir, server) = production_tests::server_with_limits(LimitsConfig {
        live_subscriptions: 1,
        ..LimitsConfig::default()
    });
    let (refused, waiting) = queue_behind_one(&server, 4, close).await;
    assert_eq!(waiting, (0, 4), "past the row the subscriptions wait");
    assert_eq!(refused, 0);
    assert_eq!(crossings(&server, LimitRow::LiveSubscriptions), 1);
}

/// Done-means (rule 5): a wait past its deadline ends in a typed timeout,
/// never a refusal for the count, and the request after it is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wait_past_its_deadline_is_a_typed_timeout() {
    let (_dir, server) = production_tests::server_with_limits(LimitsConfig {
        live_subscriptions: 1,
        queue_wait_timeout_ms: 50,
        ..LimitsConfig::default()
    });
    let hub = connection::Hub::for_server(&server);
    let auth = auth(&server);
    let mut first = connection::Connection::new(Arc::clone(&hub), 1);
    assert_eq!(subscribe(&mut first, &auth, 1).await, None);
    let mut second = connection::Connection::new(Arc::clone(&hub), 2);
    assert_eq!(
        subscribe(&mut second, &auth, 1).await.as_deref(),
        Some("WAITED_OUT")
    );
    first
        .control(&auth, SubRequest::Close { subscription_id: 1 })
        .unwrap();
    assert_eq!(subscribe(&mut second, &auth, 1).await, None);
}

struct Source(Value);
impl LiveQuerySource for Source {
    fn derive(&self, _: &ScopedView, _: Channel) -> Result<DerivedView, AppError> {
        Ok(DerivedView {
            value: self.0.clone(),
            cursor: Cursor {
                document: "fixture".into(),
                version_vector: Vec::new(),
                batch: 0,
            },
            dependencies: BTreeSet::new(),
            followed: BTreeSet::new(),
        })
    }
    fn can_resume(&self, _: &Cursor) -> Result<bool, AppError> {
        Ok(true)
    }
    fn ready(&self, _: &MaterializedDiffSummary, _: &OriginMark) -> Result<bool, AppError> {
        Ok(true)
    }
}

fn retaining(bytes: usize) -> Arc<dyn LiveQuerySource> {
    Arc::new(Source(json!("x".repeat(bytes))))
}

/// Bug repro (rule 5, row 20): a session's retained views were refused past
/// 8 MiB. Done-means: the session keeps them all.
#[test]
fn a_session_retains_past_the_old_share() {
    let queries = LiveQueries::new(1, retaining(3 * MIB));
    for id in 1..=4 {
        queries
            .open(id, ScopedView::default(), Channel::Receipts, None, None)
            .unwrap_or_else(|error| panic!("view {id} refused: {error:?}"));
    }
}

/// A line of `total` bytes and where its crossings ask.
fn line(total: usize) -> (Arc<budget::Budget>, Arc<LimitQuestions>) {
    let questions = Arc::new(LimitQuestions::default());
    let line = Arc::new(ByteLine::new(LimitRow::RetainedMemoryBytes, total));
    (budget::Budget::new(line, Arc::clone(&questions)), questions)
}

/// Opens one view of `bytes` on `line`; the refusal's code if refused.
fn retain(line: &Arc<budget::Budget>, bytes: usize) -> (LiveQueries, Option<String>) {
    let queries = LiveQueries::with_budget(1, retaining(bytes), Arc::clone(line));
    let refusal = queries
        .open(1, ScopedView::default(), Channel::Receipts, None, None)
        .err()
        .map(|error| serde_json::to_value(error).unwrap()["code"].to_string());
    (queries, refusal)
}

/// Crosses `limits.retained_memory_bytes`: `callers` views, each larger than
/// the whole line, one after another. Each runs alone and is served.
pub(crate) fn cross_the_retained_bytes(callers: usize) -> Crossing {
    let (line, questions) = line(MIB);
    let refused = (0..callers)
        .filter(|_| retain(&line, 2 * MIB).1.is_some())
        .count();
    Crossing {
        refused,
        asked: questions.latest(LimitRow::RetainedMemoryBytes).is_some(),
    }
}

/// Done-means (rule 5, rows 19, 20 and 22): state larger than the whole
/// retained line runs alone; beside it, only the full line, the memory
/// floor, refuses; once it goes, the next is served.
#[test]
fn a_view_past_the_whole_line_runs_alone_and_only_the_floor_refuses() {
    let (line, questions) = line(MIB);
    let (alone, refusal) = retain(&line, 2 * MIB);
    assert_eq!(refusal, None, "a view past the whole line runs alone");
    assert!(questions.latest(LimitRow::RetainedMemoryBytes).is_some());
    let (_, refusal) = retain(&line, 1024);
    assert_eq!(refusal.as_deref(), Some("\"MEMORY_FLOOR\""));
    drop(alone);
    let (_, refusal) = retain(&line, 1024);
    assert_eq!(refusal, None, "the line gives its bytes back");
}

/// Crosses a residence index row on a socket's own projection.
pub(crate) async fn cross_the_index(row: LimitRow, callers: usize) -> Crossing {
    super::residence::tests::cross_the_index(row, callers).await
}
