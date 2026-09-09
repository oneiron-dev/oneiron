//! Tick push and hybrid tests: coalescing, lane fairness, drain order, hint order and overflow, exhaustion races.

use std::pin::pin;
use std::time::Duration;

use oneiron::WakeTrigger;

use super::super::push::SESSION_HINT_QUEUE_CAP;
use super::super::*;
use super::*;
use crate::session::SessionHint;

#[test]
fn push_coalesces_same_lane_wakes() {
    let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    for _ in 0..3 {
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
    }
    assert_eq!(
        receiver.take_pending(),
        Some(Tick::Wake(WakeSignal {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
        }))
    );
    assert_eq!(receiver.take_pending(), None, "burst coalesced to one");
}

#[test]
fn distinct_lane_wakes_never_collapse() {
    let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::Timer, DreamerConsolidationScope::Macro)
        .expect("open channel");
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    let first = receiver.take_pending().expect("first wake");
    let second = receiver.take_pending().expect("second wake");
    assert!(matches!(
        first,
        Tick::Wake(WakeSignal {
            scope: DreamerConsolidationScope::Micro,
            ..
        })
    ));
    assert!(matches!(
        second,
        Tick::Wake(WakeSignal {
            scope: DreamerConsolidationScope::Macro,
            ..
        })
    ));
    assert_eq!(receiver.take_pending(), None);
}

#[test]
fn wake_drains_before_hint() {
    let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    hint.push_hint().expect("open channel");
    hint.push_hint().expect("open channel");
    wake.push_wake(WakeTrigger::SessionEnd, DreamerConsolidationScope::Meso)
        .expect("open channel");
    assert!(matches!(
        receiver.take_pending(),
        Some(Tick::Wake(WakeSignal {
            scope: DreamerConsolidationScope::Meso,
            ..
        }))
    ));
    assert_eq!(
        receiver.take_pending(),
        Some(Tick::Hint(HintSignal::default())),
        "hint burst coalesced to one, delivered after the wake"
    );
    assert_eq!(receiver.take_pending(), None);
}

#[test]
fn session_hints_preserve_arrival_order_and_coalesce_only_adjacent_same_kind() {
    let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // Arrival sequence: open, a typing burst (adjacent → ONE bump),
    // end, REOPEN, plain advisory. The second AppOpen is same-kind but
    // NOT adjacent to the first — collapsing them would erase a whole
    // sitting (the C4/G1 causality bug).
    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    for _ in 0..3 {
        hint.push_session_hint(SessionHint::Activity, None)
            .expect("open channel");
    }
    hint.push_session_hint(SessionHint::ExplicitEnd, None)
        .expect("open channel");
    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    hint.push_hint().expect("open channel");

    let mut drained = Vec::new();
    while let Some(tick) = receiver.take_pending() {
        let Tick::Hint(signal) = tick else {
            panic!("only hints were pushed, got {tick:?}");
        };
        drained.push(signal.session);
    }
    assert_eq!(
        drained,
        vec![
            Some(SessionHint::AppOpen),
            Some(SessionHint::Activity),
            Some(SessionHint::ExplicitEnd),
            Some(SessionHint::AppOpen),
            None,
        ],
        "arrival order preserved; only the adjacent typing burst coalesced"
    );
}

#[test]
fn adjacent_session_hint_coalescing_retains_the_activity_period() {
    const COALESCE_FLOOR_MS: u64 = 100;

    let now = Arc::new(AtomicU64::new(10));
    let clock_now = Arc::clone(&now);
    let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
    let (mut receiver, _wake, hint) = PushTick::channel_with_clock(clock, COALESCE_FLOOR_MS);

    hint.push_session_hint(SessionHint::Activity, None)
        .expect("open channel");
    now.store(20, Ordering::Release);
    hint.push_session_hint(SessionHint::Activity, None)
        .expect("coalesced activity");
    hint.push_session_hint(SessionHint::ExplicitEnd, None)
        .expect("distinct hint");

    let activity = receiver
        .take_buffered_session_hint_carrier()
        .expect("activity period");
    assert_eq!(activity.hint, SessionHint::Activity);
    assert_eq!(activity.first.claimed_ms, None);
    assert_eq!(activity.first.arrival_ms, 10);
    assert_eq!(activity.last.claimed_ms, None);
    assert_eq!(activity.last.arrival_ms, 20);
    assert_eq!(activity.count, 2);
    assert_eq!(
        receiver.take_buffered_session_hint(),
        Some((SessionHint::ExplicitEnd, None, 20))
    );
    assert_eq!(receiver.take_buffered_session_hint(), None);
}

#[test]
fn adjacent_activity_hints_across_the_idle_floor_remain_two_carriers() {
    const COALESCE_FLOOR_MS: u64 = 100;
    const FIRST_ARRIVAL_MS: u64 = 10;
    const WITHIN_FLOOR_ARRIVAL_MS: u64 = FIRST_ARRIVAL_MS + COALESCE_FLOOR_MS - 1;
    const ACROSS_FLOOR_ARRIVAL_MS: u64 = WITHIN_FLOOR_ARRIVAL_MS + COALESCE_FLOOR_MS + 25;

    let now = Arc::new(AtomicU64::new(FIRST_ARRIVAL_MS));
    let clock_now = Arc::clone(&now);
    let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
    let (mut receiver, _wake, hint) = PushTick::channel_with_clock(clock, COALESCE_FLOOR_MS);

    hint.push_session_hint(SessionHint::Activity, Some(1))
        .expect("first activity");
    now.store(WITHIN_FLOOR_ARRIVAL_MS, Ordering::Release);
    hint.push_session_hint(SessionHint::Activity, Some(2))
        .expect("within-floor activity");
    now.store(ACROSS_FLOOR_ARRIVAL_MS, Ordering::Release);
    hint.push_session_hint(SessionHint::Activity, Some(3))
        .expect("across-floor activity");

    let first = receiver
        .take_buffered_session_hint_carrier()
        .expect("first carrier");
    let second = receiver
        .take_buffered_session_hint_carrier()
        .expect("second carrier");
    assert_eq!(first.hint, SessionHint::Activity);
    assert_eq!(first.first.claimed_ms, Some(1));
    assert_eq!(first.first.arrival_ms, FIRST_ARRIVAL_MS);
    assert_eq!(first.last.claimed_ms, Some(2));
    assert_eq!(first.last.arrival_ms, WITHIN_FLOOR_ARRIVAL_MS);
    assert_eq!(first.count, 2);
    assert_eq!(second.hint, SessionHint::Activity);
    assert_eq!(second.first, second.last);
    assert_eq!(second.first.claimed_ms, Some(3));
    assert_eq!(second.first.arrival_ms, ACROSS_FLOOR_ARRIVAL_MS);
    assert_eq!(second.count, 1);
    assert_eq!(receiver.take_buffered_session_hint_carrier(), None);
}

#[test]
fn session_hint_queue_overflow_preserves_boundaries_and_evicts_only_activity() {
    let (mut receiver, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // A full all-boundary queue rejects another boundary for producer
    // retry; all eight durable points remain present and ordered.
    for index in 0..SESSION_HINT_QUEUE_CAP {
        let kind = if index % 2 == 0 {
            SessionHint::AppOpen
        } else {
            SessionHint::ExplicitEnd
        };
        hint.push_session_hint(kind, None).expect("open channel");
    }
    assert_eq!(
        hint.push_session_hint(SessionHint::AppOpen, None),
        Err(TickPushError::QueueFull)
    );

    let mut drained = Vec::new();
    while let Some(tick) = receiver.take_pending() {
        let Tick::Hint(signal) = tick else {
            panic!("only hints were pushed, got {tick:?}");
        };
        drained.push(signal.session.expect("session hints only"));
    }
    assert_eq!(drained.len(), SESSION_HINT_QUEUE_CAP);
    let expected: Vec<SessionHint> = (0..SESSION_HINT_QUEUE_CAP)
        .map(|index| {
            if index % 2 == 0 {
                SessionHint::AppOpen
            } else {
                SessionHint::ExplicitEnd
            }
        })
        .collect();
    assert_eq!(drained, expected, "QueueFull lost no boundary point");

    // With a mixed full queue, accepting a new boundary removes the
    // oldest Activity period and no boundary.
    let (mut mixed, _wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    let initial = [
        SessionHint::AppOpen,
        SessionHint::Activity,
        SessionHint::ExplicitEnd,
        SessionHint::Activity,
        SessionHint::AppOpen,
        SessionHint::ExplicitEnd,
        SessionHint::AppOpen,
        SessionHint::ExplicitEnd,
    ];
    for (index, kind) in initial.into_iter().enumerate() {
        hint.push_session_hint(kind, Some(index as u64))
            .expect("fill mixed queue");
    }
    hint.push_session_hint(SessionHint::ExplicitEnd, Some(8))
        .expect("boundary evicts activity");

    let mut mixed_drained = Vec::new();
    while let Some(carrier) = mixed.take_buffered_session_hint_carrier() {
        mixed_drained.push(carrier);
    }
    assert_eq!(mixed_drained.len(), SESSION_HINT_QUEUE_CAP);
    assert_eq!(
        mixed_drained
            .iter()
            .filter(|carrier| carrier.hint == SessionHint::Activity)
            .count(),
        1,
        "exactly the later Activity period survives"
    );
    assert_eq!(
        mixed_drained
            .iter()
            .filter(|carrier| carrier.first.claimed_ms == Some(1))
            .count(),
        0,
        "the oldest Activity period was the sole eviction"
    );
    assert_eq!(
        mixed_drained
            .iter()
            .filter(|carrier| carrier.hint != SessionHint::Activity)
            .count(),
        7,
        "all six original boundaries plus the incoming boundary survive"
    );
}

#[test]
fn wake_lane_round_robin_does_not_starve_buffered_macro_under_micro_refill() {
    // P2 (codex r4): fixed micro→meso→macro scan always drained a
    // refilled micro slot first, so a buffered macro/meso wake never
    // returned under continuous micro push. Rotating scan start after
    // each returned wake drains every occupied lane within N=3 takes.
    let (mut receiver, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    wake.push_wake(WakeTrigger::Timer, DreamerConsolidationScope::Macro)
        .expect("open channel");

    let mut scopes = Vec::new();
    for _ in 0..3 {
        let Some(Tick::Wake(signal)) = receiver.take_pending() else {
            panic!("expected a wake within the 3-take fairness window");
        };
        scopes.push(signal.scope);
        // Refill micro after every take — the starvation pattern under
        // a fixed scan that always preferred lane 0.
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
    }

    assert_eq!(
        scopes,
        [
            DreamerConsolidationScope::Micro,
            DreamerConsolidationScope::Macro,
            DreamerConsolidationScope::Micro,
        ],
        "cursor advances past drained lane: micro, then macro (skip empty meso), then micro"
    );
    assert_eq!(
        receiver.wake_scan_start, 1,
        "after micro→macro→micro drains, next scan starts at meso (1)"
    );
}

#[tokio::test]
async fn push_recv_ends_when_producers_drop() {
    let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
        .expect("open channel");
    drop(wake);
    drop(hint);
    assert!(matches!(receiver.recv().await, Some(Tick::Wake(_))));
    assert_eq!(receiver.recv().await, None, "drained + no producers");
}

#[tokio::test]
async fn push_recv_delivers_final_wake_when_producer_drops_immediately() {
    // P2 (codex r6 / 3585850157): between empty take_pending and the
    // pushers==0 check a producer can push then Drop. Without a final
    // take_pending re-check, recv returns None while a wake is buffered.
    // Producer order: store under mutex, notify_one, Drop decrements
    // pushers (store-before-decrement). The re-check closes the window
    // either way. Concurrent push+drop while recv is waiting (and the
    // sequential push-then-drop case) both deliver exactly one signal.
    let (mut receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    // Drop the unused hint first so the last producer can race alone.
    drop(hint);

    let producer = tokio::spawn(async move {
        // Let recv park on notified() after an empty take_pending.
        tokio::task::yield_now().await;
        wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
            .expect("open channel");
        drop(wake);
    });

    let first = receiver.recv().await;
    producer.await.expect("producer task");
    assert!(
        matches!(
            first,
            Some(Tick::Wake(WakeSignal {
                trigger: WakeTrigger::Compaction,
                scope: DreamerConsolidationScope::Micro,
            }))
        ),
        "exactly one buffered wake must be delivered, got {first:?}"
    );
    assert_eq!(
        receiver.recv().await,
        None,
        "second recv must exhaust (count: exactly 1 signal)"
    );
}

#[test]
fn push_after_receiver_drop_is_rejected() {
    let (receiver, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    drop(receiver);
    assert_eq!(
        wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro),
        Err(TickPushError::Closed)
    );
    assert_eq!(hint.push_hint(), Err(TickPushError::Closed));
}

#[tokio::test(start_paused = true)]
async fn hybrid_timer_lane_fires_at_the_read_deadline_then_goes_quiet() {
    let deadline = CommitmentDeadline {
        due_at_ms: 5_000,
        scope: DreamerConsolidationScope::Micro,
    };
    let timer = TimerTick::with_clock(
        ScriptedDeadlines::new(vec![Some(deadline), None]),
        frozen_clock(0),
    );
    let (push, wake, hint) = PushTick::channel(COALESCE_FLOOR_MS);
    drop(wake);
    drop(hint);
    let mut hybrid = HybridTick::new(timer, push);
    assert_eq!(hybrid.next_tick().await, Some(Tick::Deadline(deadline)));
    // Quiet timer lane AND no producers left: the one true exhaustion.
    assert_eq!(hybrid.next_tick().await, None);
}

#[tokio::test(start_paused = true)]
async fn hybrid_with_no_timed_work_waits_for_push_instead_of_exhausting() {
    // A quiet timer lane (no upcoming deadline) is NOT tick-source
    // exhaustion while push producers remain: the supervisor must keep
    // waiting for a push, not stop permanently. Bare TimerTick is no
    // longer a TickSource precisely because it cannot express this.
    let timer = TimerTick::with_clock(ScriptedDeadlines::new(vec![None]), frozen_clock(0));
    let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    let mut hybrid = HybridTick::new(timer, push);

    let mut next = pin!(hybrid.next_tick());
    assert!(
        tokio::time::timeout(Duration::from_secs(3_600), next.as_mut())
            .await
            .is_err(),
        "no timed work + live producers must idle, not exhaust"
    );
    wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
        .expect("open channel");
    assert!(matches!(next.await, Some(Tick::Wake(_))));
}

#[tokio::test(start_paused = true)]
async fn hybrid_due_deadline_beats_pending_push() {
    let deadline = CommitmentDeadline {
        due_at_ms: 1_000,
        scope: DreamerConsolidationScope::Meso,
    };
    let timer = TimerTick::with_clock(
        ScriptedDeadlines::new(vec![Some(deadline)]),
        frozen_clock(1_000),
    );
    let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    let mut hybrid = HybridTick::new(timer, push);
    assert_eq!(
        hybrid.next_tick().await,
        Some(Tick::Deadline(deadline)),
        "an already-due deadline wins over a ready push"
    );
    // The push was NOT consumed by the deadline win: it surfaces next.
    assert!(matches!(hybrid.next_tick().await, Some(Tick::Wake(_))));
}

#[tokio::test(start_paused = true)]
async fn hybrid_push_wakes_while_deadline_is_far() {
    let deadline = CommitmentDeadline {
        due_at_ms: 60_000,
        scope: DreamerConsolidationScope::Micro,
    };
    let timer = TimerTick::with_clock(
        ScriptedDeadlines::new(vec![Some(deadline), Some(deadline)]),
        frozen_clock(0),
    );
    let (push, wake, _hint) = PushTick::channel(COALESCE_FLOOR_MS);
    wake.push_wake(WakeTrigger::SessionEnd, DreamerConsolidationScope::Meso)
        .expect("open channel");
    let mut hybrid = HybridTick::new(timer, push);
    assert!(
        matches!(hybrid.next_tick().await, Some(Tick::Wake(_))),
        "a ready push beats a far deadline"
    );
    // The far deadline was not dropped: the next cycle re-reads and
    // waits it out (paused time auto-advances).
    assert_eq!(hybrid.next_tick().await, Some(Tick::Deadline(deadline)));
}
