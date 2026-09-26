//! One-shot wake-policy timer: quiet expiry, inbound cancellation, and durable queue.
use super::*;
use oneiron::dreamer_wake::WakeIdleState;
use oneiron::registry::ENTITY_TYPE_TURN;
use rmpv::Value;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

fn seed_user_turn(vault: &Vault) {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(vec![("spkr".into(), "user".into())]))
        .unwrap();
    vault
        .put_entity(
            &EntityId::now(),
            ENTITY_TYPE_TURN,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .unwrap();
}
fn sample(last: Arc<AtomicU64>) -> IdleSample {
    Arc::new(move || WakeIdleState {
        running_turns: false,
        live_background_work: false,
        last_inbound_at: last.load(Ordering::SeqCst),
    })
}

#[tokio::test(start_paused = true)]
async fn policy_timer_cancels_on_inbound_and_fires_at_new_quiet_deadline() {
    let (_dir, vault) = open_vault();
    seed_user_turn(&vault);
    let node_id = vault_client_node_id(&vault);
    let started = tokio::time::Instant::now();
    let now_ms: NowMillis = Arc::new(move || {
        3_500_000 + u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    });
    let last = Arc::new(AtomicU64::new(1));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&now_ms), COALESCE_FLOOR_MS);
    let timer = TimerTick::with_clock(
        AttemptQueueDeadlines::new(&vault, node_id),
        Arc::clone(&now_ms),
    );
    let mut ticks = WakePolicyTicks::new(
        HybridTick::new(timer, push),
        &vault,
        sample(Arc::clone(&last)),
        Arc::clone(&now_ms),
    );
    let (tick, ()) = tokio::join!(ticks.next_tick(), async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        last.store(now_ms() / 1_000, Ordering::SeqCst);
        hint.push_hint().unwrap();
    });
    assert!(matches!(tick, Some(Tick::Hint(_))));
    assert!(AttemptQueue::new(&vault).list().unwrap().is_empty());
    // The former 3,601s deadline is cancelled; no old timer can enqueue.
    let expired = tokio::time::timeout(Duration::from_secs(101), ticks.next_tick()).await;
    assert!(expired.is_err());
    assert!(AttemptQueue::new(&vault).list().unwrap().is_empty());
    // The injected clock follows paused Tokio time exactly, so the one new
    // quiet deadline fires at 7,110s, not at the cancelled 3,601s deadline.
    let (tick, ()) = tokio::join!(ticks.next_tick(), async {
        tokio::time::sleep(Duration::from_secs(3_499)).await;
    });
    assert!(matches!(tick, Some(Tick::Deadline(_))));
    assert_eq!(AttemptQueue::new(&vault).list().unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn empty_vault_has_no_policy_timer_or_queued_wake() {
    let (_dir, vault) = open_vault();
    let started = tokio::time::Instant::now();
    let now_ms: NowMillis =
        Arc::new(move || u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    let node_id = vault_client_node_id(&vault);
    let (push, _wake, _hint) = PushTick::channel_with_clock(Arc::clone(&now_ms), COALESCE_FLOOR_MS);
    let timer = TimerTick::with_clock(
        AttemptQueueDeadlines::new(&vault, node_id),
        Arc::clone(&now_ms),
    );
    let mut ticks = WakePolicyTicks::new(
        HybridTick::new(timer, push),
        &vault,
        sample(Arc::new(AtomicU64::new(0))),
        now_ms,
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(172_800), ticks.next_tick())
            .await
            .is_err()
    );
    assert!(AttemptQueue::new(&vault).list().unwrap().is_empty());
}
