use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::{
    DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND, DreamerConsolidationScope, EdgeKind, SessionEndWake,
    SessionMintOutcome, TimeRange, VaultConfig, dreamer_consolidation::decode_partition_payload,
    session_lifecycle::SessionEndReason,
};

use super::*;
use crate::tick::{AttemptQueueDeadlines, CommitmentDeadline, HybridTick, PushTick, TimerTick};

fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    (dir, vault)
}

// The driver and vault use the same clock, in their respective ms/sec units.
struct RecordedDriverClock(NowMillis);
impl oneiron::store::ports::Clock for RecordedDriverClock {
    fn now_recorded_at(&self) -> u64 {
        (self.0)() / 1_000
    }
}
fn open_vault_with_clock(clock: NowMillis) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = VaultConfig::device();
    config.store_clock = oneiron::store::ports::StoreClock::new(
        Arc::new(RecordedDriverClock(clock)),
        oneiron::store::ports::ManualClock::new(0),
    );
    let vault = Vault::open(dir.path(), config).expect("vault");
    (dir, vault)
}

/// Manually-advanced millisecond clock for the sync policy tests.
fn manual_clock(start_ms: u64) -> (Arc<AtomicU64>, NowMillis) {
    let now = Arc::new(AtomicU64::new(start_ms));
    let clock_now = Arc::clone(&now);
    let clock: NowMillis = Arc::new(move || clock_now.load(Ordering::Acquire));
    (now, clock)
}

/// True when the attempt is a SessionEnd consolidation PARTITION on the Meso
/// scope — positively identified by payload, mirroring the production
/// executor's dispatch. Kind alone is not enough: the Meso kind carries
/// payload-discriminated passengers (ED-04's mine today; the reflection gap
/// scan rides the same pattern), and a row that fails to decode is nobody's
/// partition.
fn is_meso_partition(attempt: &AttemptRecord) -> bool {
    attempt.kind == DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND
        && decode_dreamer_attempt_payload(&attempt.payload)
            .is_ok_and(|payload| payload.attempt_type == DreamerConsolidationScope::Meso.as_str())
}

/// Counts the SessionEnd PARTITION attempts on the Meso queue — the "did this
/// close plan consolidation work" signal. Positive payload identification:
/// passengers (count the mine with [`mine_attempt_count`]) and undecodable
/// rows never count. Counts rows ever created, any state — never `any()`.
fn meso_attempt_count(vault: &Vault) -> usize {
    AttemptQueue::new(vault)
        .list()
        .expect("attempt list")
        .iter()
        .filter(|attempt| is_meso_partition(attempt))
        .count()
}

fn seed_conversation(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    let body = oneiron::conversation::ConversationBody::default()
        .to_bytes()
        .expect("conversation body encode");
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
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

/// Claims and completes every claimable Meso row: the one pending SessionEnd
/// partition attempt (asserted) plus any ED-04 mine passenger, leaving the
/// Meso deadline surface exactly as it was before ONE-1760 made every close
/// carry a passenger row.
fn complete_one_meso_attempt(vault: &Vault, owner: &str, now: u64) {
    let queue = AttemptQueue::new(vault);
    let mut partitions = 0;
    while let ClaimOutcome::Claimed(record) = queue
        .claim_kind(
            DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: owner.to_owned(),
                now,
            },
        )
        .expect("claim meso attempt")
    {
        if is_meso_partition(&record) {
            partitions += 1;
        }
        queue
            .complete(CompleteAttempt {
                id: record.id,
                lease_owner: owner.to_owned(),
                attempt_count: record.attempt_count,
                now: now + 1,
            })
            .expect("complete meso attempt");
    }
    assert_eq!(
        partitions, 1,
        "expected exactly one claimable partition attempt"
    );
}

/// The production planning round, exactly as the driver's close runs it
/// (`Vault::plan_session_end_wake` for the sitting) — used to hand stale
/// closers a REAL wake plan.
fn meso_wake(vault: &Vault, session: &EntityId) -> SessionEndWake {
    vault.plan_session_end_wake(session).expect("plan session end wake")
}

/// The one actor these tests open sittings for, on this install's machine
/// (`Vault::local_session_key`, the on-device caller's binding).
fn sitting_key(vault: &Vault) -> SessionKey {
    let actor = EntityId::from_bytes([0x5e; 16]).expect("actor id");
    vault.local_session_key(actor).expect("local session key")
}

fn driver(
    vault: &Vault,
    config: SessionLifecycleConfig,
    clock: NowMillis,
) -> SessionLifecycleDriver<'_> {
    SessionLifecycleDriver::new(vault, config, clock).expect("valid session config")
}

/// Mechanical adapter for pre-existing policy tests: sample their manual
/// scheduling clock outside the mutation, then pass the stamp explicitly.
fn apply_now(driver: &SessionLifecycleDriver<'_>, hint: SessionHint) -> Result<SessionHintEffect> {
    let arrival_ms = (driver.clock())();
    driver.apply_hint(sitting_key(driver.vault), hint, None, arrival_ms)
}

const FLOOR: u64 = crate::TEST_SESSION_IDLE_FLOOR_SECS; // 1_200 s
const CEILING: u64 = 8 * 60 * 60; // 8 h test ceiling

#[test]
fn a_completed_wake_attempt_is_never_recreated_by_a_later_close_attempt() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(Some(FLOOR), Some(CEILING)), clock);
    let conversation = seed_conversation(&vault, 0x61);
    seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = apply_now(&driver, SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(_) = apply_now(&driver, SessionHint::ExplicitEnd).expect("end")
    else {
        panic!("expected an ended session");
    };
    assert_eq!(meso_attempt_count(&vault), 1);

    // COMPLETE the attempt. Completion deletes the pending-only dedupe row —
    // the exact G2 driver: under the old ordering a later close attempt
    // could re-enqueue the same key and double the wake.
    let queue = AttemptQueue::new(&vault);
    let record = loop {
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
            panic!("expected a claimable partition attempt");
        };
        if is_meso_partition(&record) {
            break record;
        }
        // A payload-discriminated passenger (ED-04's mine, ONE-1760): complete
        // it out of the way — the G2 scenario is about the WAKE attempt's
        // dedupe row.
        queue
            .complete(CompleteAttempt {
                id: record.id,
                lease_owner: "g2-test".to_owned(),
                attempt_count: record.attempt_count,
                now: 1_075,
            })
            .expect("complete mine passenger");
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
        apply_now(&driver, SessionHint::ExplicitEnd).expect("re-end"),
        SessionHintEffect::NoOp
    );
    assert_eq!(
        vault
            .end_session_with_wake(
                &id,
                SessionClosePredicate::Explicit,
                1_095,
                &meso_wake(&vault, &id),
            )
            .expect("stale replay"),
        None
    );

    // Total PARTITION attempts EVER created for that session: exactly one,
    // completed (the ED-04 mine passenger is payload-discriminated out).
    let attempts: Vec<_> = queue
        .list()
        .expect("attempt list")
        .into_iter()
        .filter(is_meso_partition)
        .collect();
    assert_eq!(attempts.len(), 1, "no re-enqueue after completion — ever");
    assert_eq!(attempts[0].state, AttemptState::Completed);
}

/// Millisecond clock that tracks tokio's (paused) time on EVERY thread. The
/// vault samples its store clock off the runtime too (the authority-fold
/// cache probes on a scoped thread), where `tokio::time::Instant` falls back
/// to the real clock; one such sample would raise the vault's recorded-at
/// floor past paused time and stamp attempts in the test's future.
fn tokio_clock(base_ms: u64) -> NowMillis {
    let runtime = tokio::runtime::Handle::current();
    let start = tokio::time::Instant::now();
    Arc::new(move || {
        let _paused_clock = runtime.enter();
        base_ms + u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

#[tokio::test(start_paused = true)]
async fn end_then_open_burst_ends_the_sitting_and_mints_its_replacement() {
    let clock = tokio_clock(1_000_000_000);
    let (_dir, vault) = open_vault_with_clock(Arc::clone(&clock));
    let key = sitting_key(&vault);
    // The session-end miner runs as the Dreamer, a MACHINE writer: the host
    // roots the vault and holds its key.
    crate::provision_test_engine_machines(&vault);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(Some(FLOOR), Some(CEILING)),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock), FLOOR * 1_000);
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x62);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(key, SessionHint::AppOpen, None)
        .expect("open channel");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let a = vault.open_session(key).expect("read").expect("A open").session;

    // ExplicitEnd then AppOpen, buffered together: arrival order is
    // lifecycle causality — A ends, then a NEW sitting B mints. The old
    // per-kind slots drained open-first, so the reopen never minted.
    hint.push_session_hint(key, SessionHint::ExplicitEnd, None)
        .expect("open channel");
    hint.push_session_hint(key, SessionHint::AppOpen, None)
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

    let b = vault.open_session(key).expect("read").expect("B open").session;
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
async fn ready_meso_deadline_beats_an_applied_pending_hint() {
    let clock = tokio_clock(1_000_000_000);
    let (_dir, vault) = open_vault_with_clock(Arc::clone(&clock));
    let key = sitting_key(&vault);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(Some(FLOOR), Some(CEILING)),
        Arc::clone(&clock),
    );
    assert!(matches!(
        apply_now(&lifecycle, SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    let conversation = seed_conversation(&vault, 0x72);
    seed_dirty_turn(&vault, &conversation, 999_999);
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock), FLOOR * 1_000);
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);

    hint.push_session_hint(key, SessionHint::Activity, None)
        .expect("pending activity");
    hint.push_session_hint(key, SessionHint::ExplicitEnd, None)
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
