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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turns_go_round_the_keys_and_in_order_within_one_key() {
    let (pool, _) = pool(1, LONG);
    let served = Arc::new(Mutex::new(Vec::new()));
    let held = pool.admit("fleet").await.unwrap();

    // One credential's burst arrives first, then two other callers.
    for name in ["fleet-1", "fleet-2", "fleet-3"] {
        line_up(&pool, &served, "fleet", name).await;
    }
    line_up(&pool, &served, "alice", "alice-1").await;
    line_up(&pool, &served, "bob", "bob-1").await;
    // The host's own work waits behind every caller, whenever it arrived.
    let background = {
        let (waiting, served) = (Arc::clone(&pool), Arc::clone(&served));
        let before = pool.waiting();
        let handle = tokio::task::spawn_blocking(move || {
            let _permit = waiting.admit_background_blocking().expect("a turn at last");
            served.lock().unwrap().push("maintenance");
        });
        handle_queued(&pool, before).await;
        handle
    };
    line_up(&pool, &served, "fleet", "fleet-4").await;

    drop(held);
    background.await.unwrap();
    assert_eq!(
        *served.lock().unwrap(),
        [
            "fleet-1",
            "alice-1",
            "bob-1",
            "fleet-2",
            "fleet-3",
            "fleet-4",
            "maintenance"
        ],
        "one turn per key per round, a key's own work in arrival order, the host's last"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crossing_asks_its_row_once_and_refuses_nothing() {
    let (pool, questions) = pool(2, LONG);
    let first = pool.admit("fleet").await.unwrap();
    let second = pool.admit("fleet").await.unwrap();
    assert!(
        questions.latest(LimitRow::GitExchanges).is_none(),
        "work inside the row asks nothing"
    );

    let waiters: Vec<_> = (0..5)
        .map(|_| {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.admit("fleet").await.map(drop) })
        })
        .collect();
    while pool.waiting() < 5 {
        tokio::task::yield_now().await;
    }
    let question = questions
        .latest(LimitRow::GitExchanges)
        .expect("the first wait past the row asks");
    assert_eq!(question.row, "limits.git_exchanges");
    assert_eq!(question.bound, 2);
    assert_eq!(question.observed, 3, "held plus the one that had to wait");

    drop((first, second));
    for waiter in waiters {
        assert_eq!(waiter.await.unwrap(), Ok(()), "every waiter gets its turn");
    }
}

/// Review r2 (Astra and Sol, P1): a pool asked again only once a permit came
/// back to it, so a wait that began after the last waiter took its turn
/// asked nothing; and the row's question took only the first crossing of its
/// minute. A wait that begins when nobody waits is a new crossing, and each
/// one counts in the row's question.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_crossing_counts_in_its_rows_question() {
    // One window holds every crossing below.
    let into_minute = oneiron_vault_contract::now_ts() % 60;
    if into_minute > 50 {
        tokio::time::sleep(Duration::from_secs(61 - into_minute)).await;
    }
    let (pool, questions) = pool(1, LONG);
    let crossings = || {
        questions
            .latest(LimitRow::GitExchanges)
            .map_or(0, |question| question.crossings)
    };
    let queue = |key: &'static str| {
        let pool = Arc::clone(&pool);
        tokio::spawn(async move { pool.admit(key).await })
    };
    // A wait is in line before its crossing asks, which it does outside the
    // queue's lock, on another worker: give it until a deadline.
    let until_one_waits_and = |crossed: u64| {
        let pool = Arc::clone(&pool);
        let questions = Arc::clone(&questions);
        async move {
            let deadline = Instant::now() + Duration::from_secs(10);
            while (pool.waiting() == 0
                || questions
                    .latest(LimitRow::GitExchanges)
                    .map_or(0, |question| question.crossings)
                    < crossed)
                && Instant::now() < deadline
            {
                tokio::task::yield_now().await;
            }
        }
    };

    let first = pool.admit("first").await.unwrap();
    let second = queue("second");
    until_one_waits_and(1).await;
    assert_eq!(crossings(), 1);

    // The permit passes to the one waiter, and the line is empty: the next
    // wait crosses the row again.
    drop(first);
    let second = second.await.unwrap().unwrap();
    let third = queue("third");
    until_one_waits_and(2).await;
    assert_eq!(crossings(), 2, "a wait after the line ran empty crosses");

    // Everything ends and the pool is idle; a burst in the same minute
    // crosses once more.
    drop(second);
    drop(third.await.unwrap().unwrap());
    assert!(pool.is_idle());
    let fourth = pool.admit("fourth").await.unwrap();
    let fifth = queue("fifth");
    until_one_waits_and(3).await;
    assert_eq!(crossings(), 3, "a crossing in the same minute still counts");
    drop(fourth);
    assert!(fifth.await.unwrap().is_ok(), "nobody is refused");
}
