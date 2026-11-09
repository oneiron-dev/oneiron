//! The queue law every permit site shares (ARCH-0044 C5, SEC rule 5): past
//! the bound, work waits and is served round-robin across keys, in arrival
//! order within one key, with the host's own work last; a wait ends at its
//! deadline with nothing taken; and a crossing asks its row's question once.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{Admission, WaitTimedOut};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

const LONG: Duration = Duration::from_secs(60);

fn pool(bound: usize, wait: Duration) -> (Arc<Admission<&'static str>>, Arc<LimitQuestions>) {
    let questions = Arc::new(LimitQuestions::default());
    let pool = Admission::new(LimitRow::GitExchanges, Arc::clone(&questions), bound, wait);
    (Arc::new(pool), questions)
}

/// Lines up `key`'s next waiter behind the ones already queued, and records
/// its name when its turn comes; it holds the permit until the next turn.
async fn line_up(
    pool: &Arc<Admission<&'static str>>,
    served: &Arc<Mutex<Vec<&'static str>>>,
    key: &'static str,
    name: &'static str,
) {
    let before = pool.waiting();
    let (pool_, served_) = (Arc::clone(pool), Arc::clone(served));
    tokio::spawn(async move {
        let permit = pool_.admit(key).await.expect("a turn within the deadline");
        served_.lock().unwrap().push(name);
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(permit);
    });
    while pool.waiting() == before {
        tokio::task::yield_now().await;
    }
}

async fn handle_queued(pool: &Arc<Admission<&'static str>>, before: usize) {
    while pool.waiting() == before {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_ends_at_its_deadline_and_its_place_goes_on() {
    let (pool, _) = pool(1, Duration::from_millis(300));
    let held = pool.admit("a").await.unwrap();

    let started = Instant::now();
    assert_eq!(pool.admit("b").await.err(), Some(WaitTimedOut));
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "a waiter is never turned away before its deadline"
    );
    assert_eq!(pool.waiting(), 0, "a wait that ended leaves the line");

    // A caller who hangs up mid-wait leaves the line too, and the permit
    // goes to whoever is still there.
    let gone = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.admit("gone").await.map(drop) }
    });
    handle_queued(&pool, 0).await;
    let next = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.admit("next").await.map(drop) }
    });
    handle_queued(&pool, 1).await;
    gone.abort();
    drop(held);
    assert_eq!(next.await.unwrap(), Ok(()));
    assert!(pool.is_idle());
}
