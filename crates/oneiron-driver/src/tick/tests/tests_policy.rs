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
fn configure_quiet_window(vault: &Vault) {
    let owner = EntityId::now();
    vault
        .put_entity(
            &owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"owner",
        )
        .unwrap();
    let proof = vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let mut policy = vault.dreamer_wake_policy().unwrap();
    policy.wake_grain_turns = 100;
    policy.new_records = 100;
    policy.idle_secs = 60;
    policy.quiet_weave_secs = 3_600;
    vault.set_dreamer_wake_policy(&proof, policy).unwrap();
}

fn sample(last: Arc<AtomicU64>) -> IdleSample {
    Arc::new(move || WakeIdleState {
        running_turns: false,
        live_background_work: false,
        compute_available: true,
        last_inbound_at: last.load(Ordering::SeqCst),
    })
}

#[tokio::test(start_paused = true)]
async fn policy_timer_cancels_on_inbound_and_fires_at_new_quiet_deadline() {
    let (_dir, vault) = open_vault();
    seed_user_turn(&vault);
    configure_quiet_window(&vault);
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
    )
    .expect("one timer per vault");
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
    )
    .expect("one timer per vault");
    assert!(
        tokio::time::timeout(Duration::from_secs(172_800), ticks.next_tick())
            .await
            .is_err()
    );
    assert!(AttemptQueue::new(&vault).list().unwrap().is_empty());
}

#[test]
fn only_one_idle_timer_can_own_an_open_vault() {
    let (_dir, vault) = open_vault();
    let clock = frozen_clock(0);
    let idle = sample(Arc::new(AtomicU64::new(0)));
    let (one, _wake_one, _hint_one) = PushTick::channel(0);
    let first = WakePolicyTicks::new(one, &vault, Arc::clone(&idle), Arc::clone(&clock))
        .expect("first timer owns vault");
    let (two, _wake_two, _hint_two) = PushTick::channel(0);
    assert!(matches!(
        WakePolicyTicks::new(two, &vault, Arc::clone(&idle), Arc::clone(&clock)),
        Err(oneiron::Error::InvalidConfig(_))
    ));
    drop(first);
    let (three, _wake_three, _hint_three) = PushTick::channel(0);
    assert!(WakePolicyTicks::new(three, &vault, idle, clock).is_ok());
}

#[tokio::test(start_paused = true)]
async fn zero_compute_has_no_due_policy_timer_or_attempt() {
    let (_dir, vault) = open_vault();
    seed_user_turn(&vault);
    let started = tokio::time::Instant::now();
    let now_ms: NowMillis = Arc::new(move || {
        4_000_000 + u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
    });
    let idle: IdleSample = Arc::new(|| WakeIdleState {
        running_turns: false,
        live_background_work: false,
        compute_available: false,
        last_inbound_at: 0,
    });
    let node_id = vault_client_node_id(&vault);
    let (push, _wake, _hint) = PushTick::channel_with_clock(Arc::clone(&now_ms), COALESCE_FLOOR_MS);
    let timer = TimerTick::with_clock(
        AttemptQueueDeadlines::new(&vault, node_id),
        Arc::clone(&now_ms),
    );
    let mut ticks = WakePolicyTicks::new(HybridTick::new(timer, push), &vault, idle, now_ms)
        .expect("one timer per vault");
    assert!(
        tokio::time::timeout(Duration::from_secs(7_200), ticks.next_tick())
            .await
            .is_err()
    );
    assert!(AttemptQueue::new(&vault).list().unwrap().is_empty());
}
