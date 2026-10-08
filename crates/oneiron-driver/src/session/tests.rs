use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{
    AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use oneiron::dreamer_runner::decode_dreamer_attempt_payload;
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::{
    DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND, EdgeKind, SessionMintOutcome, TimeRange, VaultConfig,
    dreamer_consolidation::decode_partition_payload, session_lifecycle::SessionEndReason,
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

/// The production planning trio, exactly as the driver's close runs it —
/// used to hand stale closers a REAL non-empty wake plan.
fn meso_wake(vault: &Vault) -> SessionEndWake {
    let scope = DreamerConsolidationScope::Meso;
    let watermark = read_watermark(vault, scope).expect("watermark");
    let dirty = scan_dirty_turns(vault, scope, &watermark, usize::MAX).expect("scan");
    let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
    let planned_turn_ids = dirty.iter().map(|turn| turn.turn_id).collect();
    let plans = plan_partitions(vault, scope, &dirty, &watermark).expect("plan");
    SessionEndWake {
        plans,
        planned_watermark: watermark.last_learned_at,
        planned_turn_ids,
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

/// Mechanical adapter for pre-existing policy tests: sample their manual
/// scheduling clock outside the mutation, then pass the stamp explicitly.
fn apply_now(driver: &SessionLifecycleDriver<'_>, hint: SessionHint) -> Result<SessionHintEffect> {
    let arrival_ms = (driver.clock())();
    driver.apply_hint(hint, None, arrival_ms)
}

const FLOOR: u64 = DEFAULT_SESSION_IDLE_FLOOR_SECS; // 1_200 s
const CEILING: u64 = 8 * 60 * 60; // 8 h test ceiling

#[test]
fn claimed_time_is_decisional_only_when_sane_and_raw_claims_are_retained() {
    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(1_000_000);
    let lifecycle = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let SessionHintEffect::Minted(id) = lifecycle
        .apply_hint(SessionHint::AppOpen, None, 1_000_000)
        .expect("mint")
    else {
        panic!("expected mint");
    };

    let sane_claim_ms = 1_005_250;
    let sane_arrival_ms = 1_010_500;
    assert_eq!(
        lifecycle
            .apply_hint(SessionHint::Activity, Some(sane_claim_ms), sane_arrival_ms,)
            .expect("sane claimed activity"),
        SessionHintEffect::Bumped(id)
    );
    let insane_arrival_ms = 1_020_750;
    let insane_claim_ms = insane_arrival_ms + 1;
    assert_eq!(
        lifecycle
            .apply_hint(
                SessionHint::Activity,
                Some(insane_claim_ms),
                insane_arrival_ms,
            )
            .expect("future-claimed activity"),
        SessionHintEffect::Bumped(id)
    );

    let record = vault
        .session_lifecycle_record(&id)
        .expect("record read")
        .expect("record exists");
    assert_eq!(record.app_open_hints.len(), 1);
    assert_eq!(record.activity_periods.len(), 2);
    assert_eq!(
        record
            .activity_periods
            .iter()
            .map(|period| period.count)
            .sum::<u64>(),
        2
    );
    let sane = record.activity_periods[0];
    assert_eq!(sane.first.claimed_ms, Some(sane_claim_ms));
    assert_eq!(sane.first.arrival_ms, sane_arrival_ms);
    assert_eq!(sane.first.effective_ms, sane_claim_ms);
    assert_eq!(sane.last, sane.first);
    let insane = record.activity_periods[1];
    assert_eq!(insane.first.claimed_ms, Some(insane_claim_ms));
    assert_eq!(insane.first.arrival_ms, insane_arrival_ms);
    assert_eq!(insane.first.effective_ms, insane_arrival_ms);
    assert_eq!(insane.last, insane.first);
    assert_eq!(record.last_activity, insane_arrival_ms / 1_000);
    assert_eq!(record.last_effective_ms, insane_arrival_ms);
}

#[test]
fn delayed_pre_expiry_claim_reopens_after_arrival_closes_the_stale_sitting() {
    const START_MS: u64 = 1_000_000;
    const DEADLINE_MS: u64 = START_MS + 10_000;
    const CLAIMED_MS: u64 = DEADLINE_MS - 1_000;
    const ARRIVAL_MS: u64 = DEADLINE_MS + 2_000;

    let (_dir, vault) = open_vault();
    let (_now, clock) = manual_clock(START_MS);
    let lifecycle = driver(&vault, SessionLifecycleConfig::new(10, 100), clock);
    let SessionHintEffect::Minted(old_id) = lifecycle
        .apply_hint(SessionHint::AppOpen, None, START_MS)
        .expect("mint old sitting")
    else {
        panic!("expected old sitting to mint");
    };

    let SessionHintEffect::Minted(new_id) = lifecycle
        .apply_hint(SessionHint::AppOpen, Some(CLAIMED_MS), ARRIVAL_MS)
        .expect("delayed reopen")
    else {
        panic!("arrival after expiry must mint a replacement");
    };
    assert_ne!(old_id, new_id);
    assert_eq!(
        vault
            .entities_by_type(ENTITY_TYPE_SESSION)
            .expect("session entities")
            .len(),
        2
    );
    let old = vault
        .session_lifecycle_record(&old_id)
        .expect("old record read")
        .expect("old record exists");
    assert_eq!(old.end_reason, Some(SessionEndReason::IdleFloor));
    assert_eq!(old.ended_at, Some(DEADLINE_MS / 1_000));
    let new = vault
        .session_lifecycle_record(&new_id)
        .expect("new record read")
        .expect("new record exists");
    assert_eq!(new.started_at, CLAIMED_MS / 1_000);
    assert_eq!(new.started_effective_ms, CLAIMED_MS);
    assert_eq!(new.ended_at, None);
    assert_eq!(meso_attempt_count(&vault), 0);
}

#[test]
fn explicit_end_fires_exactly_one_durable_meso_wake() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
    let conversation = seed_conversation(&vault, 0x41);
    let turn = seed_dirty_turn(&vault, &conversation, 999);

    let SessionHintEffect::Minted(id) = apply_now(&driver, SessionHint::AppOpen).expect("open")
    else {
        panic!("expected mint");
    };
    now.store(1_060_000, Ordering::Release);
    let SessionHintEffect::Ended(ended) =
        apply_now(&driver, SessionHint::ExplicitEnd).expect("end")
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
        .filter(is_meso_partition)
        .collect();
    assert_eq!(
        attempts.len(),
        1,
        "exactly one SessionEnd partition attempt"
    );
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
        apply_now(&driver, SessionHint::ExplicitEnd).expect("re-end"),
        SessionHintEffect::NoOp
    );
    assert_eq!(meso_attempt_count(&vault), 1);
}

#[test]
fn a_completed_wake_attempt_is_never_recreated_by_a_later_close_attempt() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let driver = driver(&vault, SessionLifecycleConfig::new(FLOOR, CEILING), clock);
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
                &meso_wake(&vault),
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
        apply_now(&lifecycle, SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert!(matches!(
        apply_now(&lifecycle, SessionHint::ExplicitEnd),
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
        apply_now(&lifecycle, SessionHint::AppOpen),
        Ok(SessionHintEffect::Minted(_))
    ));
    assert!(matches!(
        apply_now(&lifecycle, SessionHint::ExplicitEnd),
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

#[tokio::test]
async fn session_expiry_wins_an_exact_poll_tie_with_an_inner_tick() {
    const STARTED_AT_SECS: u64 = 1_000_000;
    const DUE_AT_MS: u64 = (STARTED_AT_SECS + FLOOR) * 1_000;

    let (_dir, vault) = open_vault();
    let SessionMintOutcome::Minted(id) = vault.mint_session(STARTED_AT_SECS).expect("mint") else {
        panic!("expected a fresh mint");
    };
    let clock_reads = Arc::new(AtomicUsize::new(0));
    let clock_read_count = Arc::clone(&clock_reads);
    let clock: NowMillis = Arc::new(move || {
        if clock_read_count.fetch_add(1, Ordering::AcqRel) == 0 {
            DUE_AT_MS - 1
        } else {
            DUE_AT_MS
        }
    });
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let (push, _wake, hint) = PushTick::channel_with_clock(clock, FLOOR * 1_000);
    hint.push_hint().expect("ready inner hint");
    let mut ticks = SessionTicks::new(push, lifecycle);

    assert!(
        matches!(
            ticks.next_tick().await,
            Some(Tick::Hint(crate::tick::HintSignal { session: None }))
        ),
        "the level-ready inner hint survives the expiry-first tie",
    );
    assert!(vault.open_session().expect("open session read").is_none());
    let record = vault
        .session_lifecycle_record(&id)
        .expect("record read")
        .expect("record retained");
    assert_eq!(record.end_reason, Some(SessionEndReason::IdleFloor));
    assert_eq!(record.ended_at, Some(STARTED_AT_SECS + FLOOR));
    assert_eq!(
        meso_attempt_count(&vault),
        0,
        "zero dirty turns enqueue none"
    );
}

#[tokio::test(start_paused = true)]
async fn end_then_open_burst_ends_the_sitting_and_mints_its_replacement() {
    let clock = tokio_clock(1_000_000_000);
    let (_dir, vault) = open_vault_with_clock(Arc::clone(&clock));
    // The session-end miner runs as the Dreamer, a MACHINE writer: the host
    // roots the vault and holds its key.
    crate::provision_test_engine_machines(&vault);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock), FLOOR * 1_000);
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x62);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let a = vault.open_session().expect("read").expect("A open").session;

    // ExplicitEnd then AppOpen, buffered together: arrival order is
    // lifecycle causality — A ends, then a NEW sitting B mints. The old
    // per-kind slots drained open-first, so the reopen never minted.
    hint.push_session_hint(SessionHint::ExplicitEnd, None)
        .expect("open channel");
    hint.push_session_hint(SessionHint::AppOpen, None)
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

#[tokio::test]
async fn adjacent_app_opens_straddling_the_floor_both_survive_and_reopen() {
    let (_dir, vault) = open_vault();
    let (now, clock) = manual_clock(1_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let (push, _wake, hint) = PushTick::channel_with_clock(clock, FLOOR * 1_000);
    let mut ticks = SessionTicks::new(push, lifecycle);

    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("first open");
    now.store((1_000 + FLOOR + 1) * 1_000, Ordering::Release);
    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("post-floor reopen");

    let expected = Tick::Hint(crate::tick::HintSignal {
        session: Some(SessionHint::AppOpen),
    });
    assert_eq!(ticks.next_tick().await, Some(expected));
    assert_eq!(ticks.next_tick().await, Some(expected));

    let sessions = vault
        .entities_by_type(ENTITY_TYPE_SESSION)
        .expect("session entities");
    assert_eq!(sessions.len(), 2, "neither boundary AppOpen was coalesced");
    let open = vault
        .open_session()
        .expect("open read")
        .expect("replacement open");
    let ended: Vec<_> = sessions
        .iter()
        .copied()
        .filter(|session| *session != open.session)
        .collect();
    assert_eq!(ended.len(), 1);
    assert_ne!(ended[0], open.session);
    let old_record = vault
        .session_lifecycle_record(&ended[0])
        .expect("old record read")
        .expect("old record retained");
    assert_eq!(old_record.app_open_hints.len(), 1);
    assert_eq!(old_record.ended_at, Some(1_000 + FLOOR));
    assert_eq!(old_record.end_reason, Some(SessionEndReason::IdleFloor));
    let replacement = vault
        .session_lifecycle_record(&open.session)
        .expect("replacement record read")
        .expect("replacement record exists");
    assert_eq!(replacement.app_open_hints.len(), 1);
    assert_eq!(replacement.started_at, 1_000 + FLOOR + 1);
    assert_eq!(replacement.ended_at, None);
    assert_eq!(meso_attempt_count(&vault), 0);
}

#[tokio::test(start_paused = true)]
async fn buffered_activity_at_the_deadline_beats_the_idle_expiry() {
    const K_SECS: u64 = 5;

    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let timer = TimerTick::with_clock(AttemptQueueDeadlines::new(&vault, 1), Arc::clone(&clock));
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock), FLOOR * 1_000);
    let mut ticks = SessionTicks::new(HybridTick::new(timer, push), lifecycle);
    let conversation = seed_conversation(&vault, 0x63);
    seed_dirty_turn(&vault, &conversation, 999_999);

    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open channel");
    assert!(matches!(ticks.next_tick().await, Some(Tick::Hint(_))));
    let open = vault.open_session().expect("read").expect("open");
    assert_eq!(open.started_at, 1_000_000);

    // C11 survives the effective-time ruling: a genuinely recent activity
    // arrives K seconds before the original floor, then processing resumes
    // after that floor. It must beat expiry, but its bump is the ARRIVAL
    // second rather than the later processing second.
    tokio::time::advance(std::time::Duration::from_secs(FLOOR - K_SECS)).await;
    hint.push_session_hint(SessionHint::Activity, None)
        .expect("open channel");
    let activity_arrival_secs = 1_000_000 + FLOOR - K_SECS;
    tokio::time::advance(std::time::Duration::from_secs(K_SECS + 2)).await;

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
    assert_eq!(open.last_activity, activity_arrival_secs);
    assert_eq!(meso_attempt_count(&vault), 0, "no close ⇒ no wake attempt");
}

#[tokio::test(start_paused = true)]
async fn awaited_session_hint_keeps_its_pre_expiry_arrival_stamp_after_suspend() {
    const K_SECS: u64 = 5;

    let (_dir, vault) = open_vault();
    let clock = tokio_clock(1_000_000_000);
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
        Arc::clone(&clock),
    );
    let (push, _wake, hint) = PushTick::channel_with_clock(clock, FLOOR * 1_000);
    let mut ticks = SessionTicks::new(push, lifecycle);

    hint.push_session_hint(SessionHint::AppOpen, None)
        .expect("open");
    assert_eq!(
        ticks.next_tick().await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::AppOpen),
        }))
    );
    let id = vault.open_session().expect("read").expect("open").session;

    let awaited = ticks.next_tick();
    tokio::pin!(awaited);
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(awaited.as_mut().poll(&mut context), Poll::Pending);
    tokio::time::advance(std::time::Duration::from_secs(FLOOR - K_SECS)).await;
    hint.push_session_hint(SessionHint::Activity, None)
        .expect("awaited activity");
    let activity_arrival_secs = 1_000_000 + FLOOR - K_SECS;
    tokio::time::advance(std::time::Duration::from_secs(K_SECS + 2)).await;

    assert_eq!(
        awaited.await,
        Some(Tick::Hint(crate::tick::HintSignal {
            session: Some(SessionHint::Activity),
        }))
    );
    let open = vault.open_session().expect("read").expect("still open");
    assert_eq!(open.session, id);
    assert_eq!(open.last_activity, activity_arrival_secs);
    assert_eq!(meso_attempt_count(&vault), 0);
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
    let SessionHintEffect::Minted(a) = apply_now(&lifecycle, SessionHint::AppOpen).expect("open A")
    else {
        panic!("expected A to mint");
    };
    let (push, _wake, hint) = PushTick::channel_with_clock(Arc::clone(&clock), FLOOR * 1_000);
    now.store(1_001_000, Ordering::Release);
    hint.push_session_hint(SessionHint::AppOpen, None)
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
    let clock = tokio_clock(1_000_000_000);
    let (_dir, vault) = open_vault_with_clock(Arc::clone(&clock));
    let lifecycle = driver(
        &vault,
        SessionLifecycleConfig::new(FLOOR, CEILING),
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

    hint.push_session_hint(SessionHint::Activity, None)
        .expect("pending activity");
    hint.push_session_hint(SessionHint::ExplicitEnd, None)
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
