use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::attempt_queue::{
    AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use oneiron::{
    DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND, DreamerAttemptPayload, DreamerRunnerStore, EdgeKind,
    SessionEndReason, TimeRange, VaultConfig, WakeTrigger, decode_partition_payload, request_wake,
};

use super::*;
use crate::tick::{AttemptQueueDeadlines, CommitmentDeadline, HybridTick, PushTick, TimerTick};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

/// Manually-advanced millisecond clock for the sync policy tests.
fn manual_clock(start_ms: u64) -> (Arc<AtomicU64>, NowMillis) {
    let now = Arc::new(AtomicU64::new(start_ms));
    let clock_now = Arc::clone(&now);
    let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
    (now, clock)
}

/// COUNT of meso consolidation attempts ever created (any state) — never `any()`.
fn meso_attempt_count(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .count()
}

fn seed_conversation(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            b"conversation",
        )
        .expect("seed conversation");
    id
}

/// One admissible dirty turn (a TURN entity with an extraction-admissible
/// speaker and the structural ChildOf conversation edge) — what the
/// SessionEnd close's production planning round consolidates.
fn seed_dirty_turn(vault: &Vault, conversation: &EntityId, learned_at: u64) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from("sitting turn")),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    turn
}

/// Dirty TURN without its structural ChildOf edge, as can happen when the
/// entity arrives before the corresponding conversation edge during sync.
fn seed_dirty_turn_without_edge(vault: &Vault, learned_at: u64) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from("user")),
            (rmpv::Value::from("txt"), rmpv::Value::from("orphan turn")),
        ]),
    )
    .expect("turn body encode");
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            &body,
        )
        .expect("seed turn without edge");
    turn
}

fn complete_one_meso_attempt(vault: &Vault, owner: &str, now: u64) {
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(record) = queue
        .claim_kind(
            DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: owner.to_owned(),
                now,
            },
        )
        .expect("claim meso attempt")
    else {
        panic!("expected one claimable meso attempt");
    };
    queue
        .complete(CompleteAttempt {
            id: record.id,
            lease_owner: owner.to_owned(),
            attempt_count: record.attempt_count,
            now: now + 1,
        })
        .expect("complete meso attempt");
}

/// The production planning trio, exactly as the driver's close runs it —
/// used to hand stale closers a REAL non-empty wake plan.
fn meso_wake(vault: &Vault) -> SessionEndWake {
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(vault, scope).expect("watermark");
    let dirty = scan_dirty_turns(vault, scope, &watermark, usize::MAX).expect("scan");
    let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
    let plans = plan_partitions(vault, scope, &dirty, &watermark).expect("plan");
    SessionEndWake {
        plans,
        planned_watermark: watermark.last_learned_at,
        advance_watermark_to,
    }
}

fn driver(
    vault: &Vault,
    config: SessionLifecycleConfig,
    clock: NowMillis,
) -> SessionLifecycleDriver<'_> {
    SessionLifecycleDriver::new(vault, config, clock).expect("valid session config")
}

const FLOOR: u64 = DEFAULT_SESSION_IDLE_FLOOR_SECS; // 1_200 s
const CEILING: u64 = 8 * 60 * 60; // 8 h test ceiling

#[test]
fn config_rejects_a_ceiling_at_or_below_the_idle_floor() {
    assert!(SessionLifecycleConfig::new(0, CEILING).validate().is_err());
    assert!(
        SessionLifecycleConfig::new(FLOOR, FLOOR)
            .validate()
            .is_err()
    );
    assert!(
        SessionLifecycleConfig::new(FLOOR, FLOOR - 1)
            .validate()
            .is_err()
    );
    assert!(
        SessionLifecycleConfig::with_idle_floor_default(CEILING)
            .validate()
            .is_ok()
    );
}

#[test]
fn default_constructor_pins_the_ticket_twenty_minute_idle_floor() {
    // ONE-1685 pins the default: 20 minutes. The literal is the oracle —
    // a drive-by edit of the constant must fail here.
    let config = SessionLifecycleConfig::with_idle_floor_default(CEILING);
    assert_eq!(config.idle_floor_secs, 1_200);
    assert_eq!(config.lifetime_ceiling_secs, CEILING);
    assert_eq!(DEFAULT_SESSION_IDLE_FLOOR_SECS, 1_200);
}

#[test]
fn app_open_mints_a_zero_turn_session() {
    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);

    let effect = driver.apply_hint(SessionHint::AppOpen).expect("app open");
    let SessionHintEffect::Minted(id) = effect else {
        panic!("expected a fresh mint, got {effect:?}");
    };
    // Presence is signal: no turn was ever witnessed.
    let open = vault.open_session().expect("read").expect("open");
    assert_eq!(open.session, id);
    assert_eq!(open.started_at, 1_000);
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "minting fires no consolidation"
    );
}

#[test]
fn app_open_on_an_open_session_bumps_instead_of_splitting_the_sitting() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);

    let SessionHintEffect::Minted(first) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_300_000, Ordering::Release);
    let effect = driver.apply_hint(SessionHint::AppOpen).expect("re-open");
    assert_eq!(effect, SessionHintEffect::Bumped(first));
    let open = vault.open_session().expect("read").expect("open");
    assert_eq!(open.session, first, "same sitting");
    assert_eq!(open.last_activity, 1_300, "re-open counted as activity");
}

#[test]
fn activity_hint_never_mints_a_session_fail_closed() {
    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);

    assert_eq!(
        driver.apply_hint(SessionHint::Activity).expect("activity"),
        SessionHintEffect::NoOp
    );
    assert_eq!(vault.open_session().expect("read"), None);
    assert_eq!(
        driver.apply_hint(SessionHint::ExplicitEnd).expect("end"),
        SessionHintEffect::NoOp,
        "ending nothing is a no-op, not an error"
    );
}

#[test]
fn explicit_end_fires_exactly_one_durable_meso_wake() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x41);
    let turn = seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(ended) = driver.apply_hint(SessionHint::ExplicitEnd).expect("end")
    else {
        panic!("expected an ended session");
    };
    assert_eq!(ended.session, id);
    assert_eq!(ended.reason, SessionEndReason::Explicit);
    assert_eq!(ended.ended_at, 1_060);

    // Exactly one meso attempt — and it decodes on the PRODUCTION executor
    // path (attempt payload → partition payload). The old bare-string payload
    // fails exactly here.
    let attempts: Vec<_> = AttemptQueue::new(&vault)
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .collect();
    assert_eq!(attempts.len(), 1, "exactly one SessionEnd meso attempt");
    let payload =
        decode_dreamer_attempt_payload(&attempts[0].payload).expect("attempt payload decodes");
    let (partition, turn_ids, watermark) =
        decode_partition_payload(&payload.input).expect("production partition decode");
    assert_eq!(partition.conversation_ref, conversation);
    assert_eq!(turn_ids, vec![turn]);
    assert_eq!(watermark, 0, "planned against the bootstrap watermark");
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("watermark")
            .last_learned_at,
        999,
        "the watermark settled in the same commit as the enqueue"
    );

    // Idempotent: a second end is a no-op and never doubles the wake.
    assert_eq!(
        driver.apply_hint(SessionHint::ExplicitEnd).expect("re-end"),
        SessionHintEffect::NoOp
    );
    assert_eq!(meso_attempt_count(&vault), 1);
}

#[test]
fn idle_floor_closes_at_exactly_the_boundary_and_not_before() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x42);
    seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_300_000, Ordering::Release);
    driver.apply_hint(SessionHint::Activity).expect("bump");

    // One second before the floor: still open (discriminating boundary).
    now.store((1_300 + FLOOR - 1) * 1_000, Ordering::Release);
    assert_eq!(driver.close_due_session().expect("not yet due"), None);
    let open = vault.open_session().expect("read").expect("still open");
    assert_eq!(open.session, id);
    assert_eq!(open.last_activity, 1_300);
    assert_eq!(meso_attempt_count(&vault), 0, "no close ⇒ no wake attempt");

    // At the floor: closed, reason IdleFloor, one durable meso wake.
    now.store((1_300 + FLOOR) * 1_000, Ordering::Release);
    let ended = driver
        .close_due_session()
        .expect("close")
        .expect("idle session ended");
    assert_eq!(ended.session, id);
    assert_eq!(ended.reason, SessionEndReason::IdleFloor);
    assert_eq!(ended.last_activity, 1_300, "floor measured from the bump");
    assert_eq!(meso_attempt_count(&vault), 1);
}

#[test]
fn forged_activity_hints_cannot_outlive_the_lifetime_ceiling() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x43);
    seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };

    // A lying app streams activity hints forever: bump every 10 minutes so
    // the idle floor NEVER fires. H-S4: the floor is a backstop, not a cap.
    let started = 1_000_u64;
    let mut bumps = 0_u64;
    let mut t = started;
    while t + 600 < started + CEILING {
        t += 600;
        now.store(t * 1_000, Ordering::Release);
        assert_eq!(
            driver.apply_hint(SessionHint::Activity).expect("bump"),
            SessionHintEffect::Bumped(id)
        );
        bumps += 1;
        assert_eq!(
            driver.close_due_session().expect("check"),
            None,
            "inside the ceiling a fresh activity clock keeps the session open"
        );
    }
    assert_eq!(bumps, CEILING / 600 - 1, "the forgery really ran");

    // At the ceiling the session closes DESPITE fresh activity ~10 min ago.
    now.store((started + CEILING) * 1_000, Ordering::Release);
    let ended = driver
        .close_due_session()
        .expect("close")
        .expect("ceiling ended the session");
    assert_eq!(ended.reason, SessionEndReason::LifetimeCeiling);
    assert_eq!(
        meso_attempt_count(&vault),
        1,
        "exactly one SessionEnd meso attempt"
    );
    assert_eq!(vault.open_session().expect("read"), None);
}

#[test]
fn crash_between_wake_enqueue_and_end_replays_into_the_same_dedupe_key() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };

    // A LEGACY (pre-atomic-close) crash artifact: an orphaned wake attempt that
    // landed without its session end. Under the atomic close protocol this
    // window no longer exists — the test pins that recovery still tolerates
    // an old vault carrying one.
    let dedupe_key = format!("session_end:{}", id.to_hex());
    request_wake(
        &DreamerRunnerStore::new(&vault),
        WakeTrigger::SessionEnd,
        DreamerConsolidationScope::Meso,
        DreamerAttemptPayload {
            attempt_type: oneiron::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND.to_owned(),
            input: rmpv::Value::from(dedupe_key.as_str()),
            parent_attempt: None,
        },
        Some(dedupe_key),
        None,
        1_030,
    )
    .expect("crashed attempt's enqueue");
    assert_eq!(meso_attempt_count(&vault), 1);
    let open = vault
        .open_session()
        .expect("read")
        .expect("crash left the session open");
    assert_eq!(open.session, id);

    // Recovery: the close re-runs and ends the session; with nothing dirty
    // to plan it enqueues nothing, so the wake never doubles.
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(ended) = driver.apply_hint(SessionHint::ExplicitEnd).expect("end")
    else {
        panic!("expected an ended session");
    };
    assert_eq!(ended.session, id);
    assert_eq!(
        meso_attempt_count(&vault),
        1,
        "the legacy attempt stands alone; the recovery close adds nothing"
    );
    assert_eq!(vault.open_session().expect("read"), None);
}

#[test]
fn a_completed_wake_attempt_is_never_recreated_by_a_later_close_attempt() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x61);
    seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(_) = driver.apply_hint(SessionHint::ExplicitEnd).expect("end")
    else {
        panic!("expected an ended session");
    };
    assert_eq!(meso_attempt_count(&vault), 1);

    // COMPLETE the attempt. Completion deletes the pending-only dedupe row —
    // the exact G2 driver: under the old ordering a later close attempt
    // could re-enqueue the same key and double the wake.
    let queue = AttemptQueue::new(&vault);
    let ClaimOutcome::Claimed(record) = queue
        .claim_kind(
            DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "g2-test".to_owned(),
                now: 1_070,
            },
        )
        .expect("claim")
    else {
        panic!("expected a claimable meso attempt");
    };
    queue
        .complete(CompleteAttempt {
            id: record.id,
            lease_owner: "g2-test".to_owned(),
            attempt_count: record.attempt_count,
            now: 1_080,
        })
        .expect("complete");

    // Re-close attempts: the driver hint AND a stale engine-level replay
    // (still holding the ended session's id) both no-op structurally —
    // re-ending an ended session cannot re-enqueue, dedupe or no dedupe.
    now.store(1_090_000, Ordering::Release);
    assert_eq!(
        driver.apply_hint(SessionHint::ExplicitEnd).expect("re-end"),
        SessionHintEffect::NoOp
    );
    assert_eq!(
        vault
            .end_session_with_wake(
                &id,
                SessionClosePredicate::Explicit,
                1_095,
                &meso_wake(&vault),
            )
            .expect("stale replay"),
        None
    );

    // Total meso attempts EVER created for that session: exactly one, completed.
    let attempts: Vec<_> = queue
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(|attempt| attempt.kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .collect();
    assert_eq!(attempts.len(), 1, "no re-enqueue after completion — ever");
    assert_eq!(attempts[0].state, AttemptState::Completed);
}

#[test]
fn closing_a_sitting_with_no_dirty_turns_plans_no_consolidation() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);

    let SessionHintEffect::Minted(id) = driver.apply_hint(SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(ended) = driver.apply_hint(SessionHint::ExplicitEnd).expect("end")
    else {
        panic!("expected an ended session");
    };
    assert_eq!(ended.session, id);
    assert_eq!(vault.open_session().expect("read"), None);
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "a zero-turn sitting has nothing to dream about: no dirty turns, no attempt"
    );
}

#[test]
fn session_close_watermark_stops_at_the_first_unplanned_turn() {
    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(1_000_000_000);
    let lifecycle = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x71);
    seed_dirty_turn(&vault, &conversation, 999_990);
    let orphan = seed_dirty_turn_without_edge(&vault, 999_995);
    seed_dirty_turn(&vault, &conversation, 999_999);

    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::ExplicitEnd),
        Ok(SessionHintEffect::Ended(_))
    ));
    assert_eq!(meso_attempt_count(&vault), 1);
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("first watermark")
            .last_learned_at,
        999_990
    );

    vault
        .batch()
        .edge(&orphan, EdgeKind::ChildOf, &conversation, 1.0)
        .commit()
        .expect("late ChildOf edge");
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::ExplicitEnd),
        Ok(SessionHintEffect::Ended(_))
    ));
    assert_eq!(meso_attempt_count(&vault), 2);
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Meso)
            .expect("second watermark")
            .last_learned_at,
        999_999
    );
}

/// Millisecond clock that tracks tokio's (paused) time.
fn tokio_clock(base_ms: u64) -> NowMillis {
    let start = tokio::time::Instant::now();
    Arc::new(move || base_ms + u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX))
}

#[tokio::test(start_paused = true)]
async fn session_ticks_close_the_idle_session_and_surface_the_meso_deadline() {
    let (_dir, vault) = open_vault();
    let base_ms = 1_000_000_000; // 1_000_000 s
    let clock = tokio_clock(base_ms);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x44);
    seed_dirty_turn(&vault, &conversation, 999_999);

    // The app-open hint surfaces unchanged (least-privileged pass shape is
    // the supervisor's mapping) AND mints the session on the way through.
    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    let first = ticks.next_tick().await.expect("hint tick");
    assert_eq!(
        first,
        Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        })
    );
    let open = vault.open_session().expect("read").expect("session open");
    assert_eq!(open.started_at, 1_000_000);

    // No further pushes: paused time auto-advances to the idle floor. The
    // decorator closes the session, enqueues the DURABLE meso attempt, and the
    // inner deadline lane surfaces it — no synthetic wake authority.
    let second = ticks.next_tick().await.expect("deadline tick");
    assert!(
        matches!(
            second,
            Tick::Deadline(CommitmentDeadline {
                scope: DreamerConsolidationScope::Meso,
                ..
            })
        ),
        "expected the SessionEnd meso deadline, got {second:?}"
    );
    assert_eq!(vault.open_session().expect("read"), None);
    let record = vault
        .session_lifecycle_record(&open.session)
        .expect("read")
        .expect("record retained");
    assert_eq!(record.end_reason, Some(SessionEndReason::IdleFloor));
    assert_eq!(record.ended_at, Some(1_000_000 + FLOOR));
    assert_eq!(meso_attempt_count(&vault), 1);
}

#[tokio::test(start_paused = true)]
async fn session_ticks_explicit_end_reaches_the_meso_deadline_without_a_micro_pass() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x45);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    assert!(matches!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        }))
    ));

    // Explicit end: the hint is consumed by the close (the wakeup it earns
    // is the meso deadline, not a least-privileged micro pass).
    hint.push_session_hint(SessionHint::ExplicitEnd)
        .expect("open channel");
    let tick = ticks.next_tick().await.expect("deadline tick");
    assert!(
        matches!(
            tick,
            Tick::Deadline(CommitmentDeadline {
                scope: DreamerConsolidationScope::Meso,
                ..
            })
        ),
        "expected the SessionEnd meso deadline, got {tick:?}"
    );
    assert_eq!(meso_attempt_count(&vault), 1);
    assert_eq!(vault.open_session().expect("read"), None);
}

#[tokio::test(start_paused = true)]
async fn end_then_open_burst_ends_the_sitting_and_mints_its_replacement() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x62);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let a = vault.open_session().expect("read").expect("A open").session;

    // ExplicitEnd then AppOpen, buffered together: arrival order is
    // lifecycle causality — A ends, then a NEW sitting B mints. The old
    // per-kind slots drained open-first, so the reopen never minted.
    hint.push_session_hint(SessionHint::ExplicitEnd)
        .expect("open channel");
    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    let deadline = ticks.next_tick().await.expect("deadline");
    assert!(
        matches!(
            deadline,
            Tick::Deadline(CommitmentDeadline {
                scope: DreamerConsolidationScope::Meso,
                ..
            })
        ),
        "A's ready meso deadline keeps inner priority, got {deadline:?}"
    );
    complete_one_meso_attempt(&vault, "end-reopen", 1_000_001);

    let tick = ticks.next_tick().await.expect("reopen hint");
    assert_eq!(
        tick,
        Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        }),
        "the reopen follows the deadline; the end was consumed by its close"
    );

    let b = vault.open_session().expect("read").expect("B open").session;
    assert_ne!(a, b, "two sittings, not one");
    assert_eq!(
        vault
            .session_lifecycle_record(&a)
            .expect("read")
            .expect("A record")
            .end_reason,
        Some(SessionEndReason::Explicit)
    );
    assert_eq!(
        vault
            .session_lifecycle_record(&b)
            .expect("read")
            .expect("B record")
            .ended_at,
        None
    );
    assert_eq!(
        meso_attempt_count(&vault),
        1,
        "exactly one meso attempt — A's close planned the dirty turn"
    );
}

#[tokio::test(start_paused = true)]
async fn open_end_open_burst_from_closed_state_makes_two_distinct_sittings() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);

    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    hint.push_session_hint(SessionHint::ExplicitEnd)
        .expect("open channel");
    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");

    // Exactly TWO mint hints surface — one per sitting. The old fixed
    // slots collapsed both opens into one slot, so the burst produced ONE
    // sitting and left nothing open.
    let first = ticks.next_tick().await.expect("first hint");
    let second = ticks.next_tick().await.expect("second hint");
    let open_hint = Tick::Hint(crate::tick::HintSignal {
        session: Some(SessionHint::AppOpen),
    });
    assert_eq!(first, open_hint);
    assert_eq!(second, open_hint);

    let open = vault
        .open_session()
        .expect("read")
        .expect("the second sitting is open");
    assert_eq!(open.started_at, 1_000_000);
    assert_eq!(
        vault
            .session_lifecycle_record(&open.session)
            .expect("read")
            .expect("record")
            .ended_at,
        None
    );
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "the zero-turn first sitting had nothing to consolidate"
    );
}

#[tokio::test(start_paused = true)]
async fn buffered_activity_at_the_deadline_beats_the_idle_expiry() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x63);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open channel");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let open = vault.open_session().expect("read").expect("open");
    assert_eq!(open.started_at, 1_000_000);

    // The activity hint is buffered, then the idle deadline passes before
    // the driver runs again: the buffered bump must be applied BEFORE the
    // close decision reads the durable clock it bumps (C11).
    hint.push_session_hint(SessionHint::Activity)
        .expect("open channel");
    tokio::time::advance(std::time::Duration::from_secs(FLOOR)).await;

    let tick = ticks.next_tick().await.expect("tick");
    assert_eq!(
        tick,
        Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::Activity),
        }),
        "the buffered bump surfaces; no close happened"
    );
    let open = vault
        .open_session()
        .expect("read")
        .expect("session still open — the bump beat the expiry");
    assert_eq!(open.last_activity, 1_000_000 + FLOOR);
    assert_eq!(meso_attempt_count(&vault), 0, "no close ⇒ no wake attempt");
}

#[tokio::test]
async fn retry_slot_applies_before_newer_buffered_hints() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let SessionHintEffect::Minted(a) = lifecycle.apply_hint(SessionHint::AppOpen).expect("open A")
    else {
        panic!("expected A to mint");
    };
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    now.store(1_001_000, Ordering::Release);
    hint.push_session_hint(SessionHint::AppOpen)
        .expect("buffer newer reopen");
    let mut ticks =
        SessionTicks::new(push, lifecycle).with_retry_hint(SessionHint::ExplicitEnd, 1_000_000);

    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        }))
    );
    let b = vault.open_session().expect("read").expect("B open").session;
    assert_ne!(a, b, "the retained end applies before the newer reopen");
    assert_eq!(
        vault
            .session_lifecycle_record(&a)
            .expect("read A")
            .expect("A record")
            .end_reason,
        Some(SessionEndReason::Explicit)
    );
    assert_eq!(meso_attempt_count(&vault), 0);
}

#[tokio::test(start_paused = true)]
async fn ready_meso_deadline_beats_an_applied_pending_hint() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    let conversation = seed_conversation(&vault, 0x72);
    seed_dirty_turn(&vault, &conversation, 999_999);
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);

    hint.push_session_hint(SessionHint::Activity)
        .expect("pending activity");
    hint.push_session_hint(SessionHint::ExplicitEnd)
        .expect("end sitting");
    let first = ticks.next_tick().await.expect("first tick");
    assert!(
        matches!(
            first,
            Tick::Deadline(CommitmentDeadline {
                scope: DreamerConsolidationScope::Meso,
                ..
            })
        ),
        "the ready meso deadline must beat the applied activity, got {first:?}"
    );
    assert_eq!(meso_attempt_count(&vault), 1);

    complete_one_meso_attempt(&vault, "deadline-priority", 1_000_001);
    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::Activity),
        }))
    );
}

#[tokio::test]
async fn ready_wake_beats_an_applied_pending_hint() {
    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(1_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    let (push, wake, hint) = PushTick::channel_with_clock(clock);
    let mut ticks = SessionTicks::new(push, lifecycle);

    hint.push_session_hint(SessionHint::Activity)
        .expect("pending activity");
    wake.push_wake(WakeTrigger::Event, DreamerConsolidationScope::Micro)
        .expect("pending wake");
    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Wake(crate::tick::WakeSignal {
            trigger: WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
        }))
    );
    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::Activity),
        }))
    );
}

#[tokio::test(start_paused = true)]
async fn sustained_session_hints_cannot_starve_a_due_meso_deadline() {
    const CYCLES: usize = 4;

    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let conversation = seed_conversation(&vault, 0x73);
    seed_dirty_turn(&vault, &conversation, 999_999);
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::ExplicitEnd),
        Ok(SessionHintEffect::Ended(_))
    ));
    assert!(matches!(
        lifecycle.apply_hint(SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert_eq!(meso_attempt_count(&vault), 1);

    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let mut observed = Vec::new();
    for _ in 0..CYCLES {
        hint.push_session_hint(SessionHint::Activity)
            .expect("sustained activity");
        observed.push(ticks.next_tick().await.expect("tick"));
    }

    assert!(matches!(
        observed[0],
        Tick::Deadline(CommitmentDeadline {
            scope: DreamerConsolidationScope::Meso,
            ..
        })
    ));
    assert_eq!(
        observed
            .iter()
            .filter(|tick| matches!(tick, Tick::Deadline(_)))
            .count(),
        CYCLES,
        "the still-due deadline wins every cycle despite hint refill"
    );
}

#[tokio::test(start_paused = true)]
async fn app_open_arriving_past_the_idle_floor_mints_a_replacement_sitting() {
    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock));
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x74);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen)
        .expect("open old sitting");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let old = vault.open_session().expect("read").expect("old open");

    tokio::time::advance(std::time::Duration::from_secs(FLOOR + 1)).await;
    hint.push_session_hint(SessionHint::AppOpen)
        .expect("resume app open");
    let first = ticks.next_tick().await.expect("post-resume tick");
    assert!(
        matches!(
            first,
            Tick::Deadline(CommitmentDeadline {
                scope: DreamerConsolidationScope::Meso,
                ..
            })
        ),
        "old sitting's close deadline wins before reopen surfacing, got {first:?}"
    );
    assert_eq!(meso_attempt_count(&vault), 1);

    complete_one_meso_attempt(&vault, "resume-past-floor", 1_001_202);
    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        }))
    );
    let new = vault
        .open_session()
        .expect("read")
        .expect("replacement open");
    assert_ne!(old.session, new.session);
    assert_eq!(new.started_at, 1_000_000 + FLOOR + 1);
    assert_eq!(
        vault
            .session_lifecycle_record(&old.session)
            .expect("read old")
            .expect("old record")
            .end_reason,
        Some(SessionEndReason::IdleFloor)
    );
}
