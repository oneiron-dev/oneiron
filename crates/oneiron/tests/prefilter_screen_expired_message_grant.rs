//! An expired MESSAGE grant lends the prefilter screen no words.
//!
//! At a threshold above zero a TURN whose sole MESSAGE the Dreamer may read
//! only through a grant with an end time is scored while the grant is live
//! and passes unscored once the clock is past its end, even when nothing
//! judged a grant in between: the committed plan and the enqueue writer
//! judge at a persisted grant clock.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test prefilter_screen_expired_message_grant`.
#![cfg(oneiron_test_support)]

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::dreamer_consolidation::{
    ConsolidationWatermark, WorkingSetTurn, enqueue_partition_attempts,
};
use oneiron::dreamer_prefilter::{
    PREFILTER_DECISION_SKIP, PREFILTER_OUTCOME_SCREENED, PrefilterConfig,
};
use oneiron::dreamer_wake::WakeTurnSubject;
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::test_doors::extraction_inputs::set_extraction_prefilter;
use oneiron::test_doors::seat_park_model_step::open_partition_vault;
use oneiron::{
    AttemptId, AttemptQueue, DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope,
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, plan_partitions, read_watermark,
    scan_dirty_turns,
};
use oneiron_authority::federation::scope_codec::read_preset;
use oneiron_store::ports::manual_clock::ManualClock;
use oneiron_store::store_clock::{Clock, StoreClock};
use serde_json::json;
use std::sync::{Arc, Mutex};

/// Returns a fixture or assertion error without hiding its source.
type ExpiredGrantTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The vault clock at setup, far from zero so grant times never meet it.
const T0: u64 = 4_000_000_000;

/// How long the Dreamer MESSAGE grant stays live after `T0`, in seconds.
const GRANT_LIVE_SECS: u64 = 3_600;

/// How far past `T0` the after phase moves the clock, in seconds.
const AFTER_SECS: u64 = 7_200;

/// How many vault-clock reads the turn wake's sieve pass makes before the
/// wake's own read runs: its grant-clock observation and its writer's clock
/// floor, each exactly one read.
const SIEVE_CLOCK_READS: u64 = 2;

/// The thin chat TURN words: one filler word, so it scores below 1.0.
const THIN_WORDS: &str = "ok";

/// The threshold the tests screen under: any scored TURN is skipped.
const PERFECT_THRESHOLD: f32 = 1.0;

/// What the screen ruled on the receipt row: `skip`, or `screened` on a rollup.
const DECISION: &str = "decision";

/// The screened TURN, lower hex; skip receipts only.
const TURN: &str = "turn";

/// Opens the Dreamer fixture vault on a clock the test moves at `now`.
fn open_clock_vault(
    dir: &tempfile::TempDir,
    now: u64,
) -> ExpiredGrantTestResult<(Vault, Arc<ManualClock>)> {
    let clock = ManualClock::new(now);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = open_partition_vault(dir.path(), config, "owen")?;
    Ok((vault, clock))
}

/// Scans the Micro dirty set the way the consolidation door does, and returns
/// the scan with the watermark it was read under.
fn scan_micro_turns(
    vault: &Vault,
) -> ExpiredGrantTestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
    let watermark = read_watermark(vault, DreamerConsolidationScope::Micro)?;
    let scan = scan_dirty_turns(vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    Ok((watermark, scan))
}

/// Returns the TURN ids the committed-state preview keeps, in plan order.
fn planned_turn_ids(
    vault: &Vault,
    dirty: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> ExpiredGrantTestResult<Vec<EntityId>> {
    let plans = plan_partitions(vault, DreamerConsolidationScope::Micro, dirty, watermark)?;
    Ok(plans
        .iter()
        .flat_map(|plan| plan.turns.iter().map(|turn| turn.turn_id))
        .collect())
}

/// Returns the prefilter Extraction receipts split into skips and rounds, by decision.
fn prefilter_receipts(
    vault: &Vault,
) -> ExpiredGrantTestResult<(Vec<ReceiptRecord>, Vec<ReceiptRecord>)> {
    let mut skips = Vec::new();
    let mut rounds = Vec::new();
    for receipt in vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))? {
        match receipt.fields.get(DECISION).map(String::as_str) {
            Some(PREFILTER_DECISION_SKIP) => skips.push(receipt),
            Some(PREFILTER_OUTCOME_SCREENED) => rounds.push(receipt),
            other => panic!("a prefilter receipt decides skip or screened, found {other:?}"),
        }
    }
    Ok((skips, rounds))
}

/// Puts one live RELATIONSHIP row the MESSAGE metadata names, and returns it.
fn witness_relationship_space(vault: &Vault) -> ExpiredGrantTestResult<EntityId> {
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )?;
    Ok(relationship)
}

/// Witnesses `THIN_WORDS` as one visible MESSAGE limited to `relationship`
/// into a fresh TURN, and returns that TURN.
fn witness_thin_relationship_turn(
    vault: &Vault,
    relationship: &EntityId,
) -> ExpiredGrantTestResult<EntityId> {
    let speaker = EntityId::now();
    vault.put_entity(
        &speaker,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"witness",
    )?;
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let related = relationship.to_hex();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: THIN_WORDS.to_owned(),
                parts: None,
                metadata: Some(json!({"rel": related})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })?;
    Ok(turn)
}

/// Grants the Dreamer `MessagesRead` on `space` until `until`, and returns
/// the grant id.
fn grant_dreamer_messages_until(
    vault: &Vault,
    space: &EntityId,
    until: u64,
) -> ExpiredGrantTestResult<EntityId> {
    let actor = vault.dreamer_authority()?.entity_ref();
    let grant = EntityId::now();
    vault.create_access_grant(
        &grant,
        &AccessGrant {
            principal_ref: actor,
            scope: AccessGrantScope::Messages { space_ref: *space },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: 1,
            revoked_at: None,
            expires_at: Some(until),
            authority_scope: read_preset(),
            companion_bounds: None,
        },
    )?;
    Ok(grant)
}

/// A vault-clock source that answers `T0` until it is armed past a read
/// count, and `T0 + AFTER_SECS` after, so one wake call observes the sieve
/// pass's clock with the grant live and the wake's read with it ended.
struct FlipClock {
    /// How many reads the source has answered so far.
    calls: Mutex<u64>,
    /// The count past which reads answer the after time, when armed.
    armed_past: Mutex<Option<u64>>,
}

impl FlipClock {
    /// A flip clock answering `T0` until it is armed.
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(0),
            armed_past: Mutex::new(None),
        })
    }

    /// How many vault-clock reads the source has answered so far.
    fn calls(&self) -> u64 {
        *self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Arms the flip: reads past `past` answer `T0 + AFTER_SECS`.
    fn flip_after(&self, past: u64) {
        *self
            .armed_past
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(past);
    }
}

impl Clock for FlipClock {
    /// Answers `T0` until armed past this read, then `T0 + AFTER_SECS`.
    fn now_recorded_at(&self) -> u64 {
        let mut calls = self
            .calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *calls = calls.saturating_add(1);
        let armed = *self
            .armed_past
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match armed {
            Some(past) if *calls > past => T0 + AFTER_SECS,
            _ => T0,
        }
    }
}

/// Opens the Dreamer fixture vault on a flip clock answering `T0`, with a
/// `ManualClock` id source the flip never moves.
fn open_flip_vault(dir: &tempfile::TempDir) -> ExpiredGrantTestResult<(Vault, Arc<FlipClock>)> {
    let clock = FlipClock::new();
    let mut config = VaultConfig::device();
    config.store_clock = StoreClock::new(clock.clone(), ManualClock::new(T0));
    let vault = open_partition_vault(dir.path(), config, "owen")?;
    Ok((vault, clock))
}

/// A wake fixture's thin TURN and the learned second the scan read it at.
struct WakeFixture {
    /// The witnessed thin TURN.
    turn: EntityId,
    /// The scan row's learned second, where the settled watermark stops.
    learned_at: u64,
}

/// Witnesses the thin relationship TURN, grants the Dreamer its MESSAGE
/// until `T0 + GRANT_LIVE_SECS`, screens at the perfect threshold, judges
/// once at `T0` so the vault holds a grant-clock lease over it, and sieves
/// to quiescence, so the turn wake's own sieve pass reads no new turn.
fn prepare_wake_fixture(vault: &Vault) -> ExpiredGrantTestResult<WakeFixture> {
    let relationship = witness_relationship_space(vault)?;
    let turn = witness_thin_relationship_turn(vault, &relationship)?;
    let _grant = grant_dreamer_messages_until(vault, &relationship, T0 + GRANT_LIVE_SECS)?;
    screen_at_perfect_threshold(vault)?;
    let judged = vault.authorization_time()?;
    assert_eq!(judged, T0, "the forced decision judges at the setup clock");
    while vault.sieve_pass(T0)?.more {}
    let (_, scan) = scan_micro_turns(vault)?;
    assert_eq!(scan.len(), 1, "the scan holds the thin TURN");
    assert_eq!(scan[0].turn_id, turn, "the scan holds the thin TURN");
    Ok(WakeFixture {
        turn,
        learned_at: scan[0].learned_at,
    })
}

/// The queued Micro consolidation attempts' ids, in queue order.
fn micro_attempt_ids(vault: &Vault) -> ExpiredGrantTestResult<Vec<AttemptId>> {
    Ok(AttemptQueue::new(vault)
        .list()?
        .into_iter()
        .filter(|row| row.kind == DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND)
        .map(|row| row.id)
        .collect())
}

/// Screens under `PERFECT_THRESHOLD`, and checks the door stored it.
fn screen_at_perfect_threshold(vault: &Vault) -> ExpiredGrantTestResult<()> {
    set_extraction_prefilter(
        vault,
        &PrefilterConfig {
            threshold: PERFECT_THRESHOLD,
            ..PrefilterConfig::default()
        },
    )?;
    let policy = vault.prefilter_config()?;
    assert_eq!(
        policy.threshold, PERFECT_THRESHOLD,
        "the door stores the perfect threshold"
    );
    assert!(policy.enabled, "the door leaves the screen enabled");
    Ok(())
}

/// A live MESSAGE grant lets the screen score and skip the thin TURN: the
/// preview plans nothing and the enqueue writes one skip receipt naming it;
/// green at both heads, the control that proves the fixture grant lends the
/// words, failing when the grant lends none, as without it the TURN passes
/// unscored and no receipt exists.
#[test]
fn a_live_message_grant_lets_the_screen_score_and_skip_the_thin_turn() -> ExpiredGrantTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let (vault, _clock) = open_clock_vault(&dir, T0)?;
    let relationship = witness_relationship_space(&vault)?;
    let turn = witness_thin_relationship_turn(&vault, &relationship)?;
    let _grant = grant_dreamer_messages_until(&vault, &relationship, T0 + GRANT_LIVE_SECS)?;
    screen_at_perfect_threshold(&vault)?;
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 1, "the scan holds the thin TURN");
    assert!(
        planned_turn_ids(&vault, &scan, &watermark)?.is_empty(),
        "the preview skips the thin TURN while the grant is live"
    );
    let outcomes = enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    assert!(outcomes.is_empty(), "the skipped TURN enqueues no attempt");
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert_eq!(skips.len(), 1, "one TURN is skipped");
    assert_eq!(rounds.len(), 1, "one round is rolled up");
    assert_eq!(
        skips[0].fields.get(TURN),
        Some(&turn.to_hex()),
        "the skip receipt names the thin TURN"
    );
    Ok(())
}

/// An ended MESSAGE grant passes the TURN unscored in the committed plan: the
/// preview plans exactly the TURN once the clock is past its end, with no
/// grant judged in between; red at `c5bcf23acee3`, where the snapshot judges
/// at the last decision and the grant still lends its words, so the plan is
/// empty.
#[test]
fn an_ended_message_grant_passes_the_turn_unscored_in_the_committed_plan()
-> ExpiredGrantTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, clock) = open_clock_vault(&dir, T0)?;
    let relationship = witness_relationship_space(&vault)?;
    let turn = witness_thin_relationship_turn(&vault, &relationship)?;
    let _grant = grant_dreamer_messages_until(&vault, &relationship, T0 + GRANT_LIVE_SECS)?;
    screen_at_perfect_threshold(&vault)?;
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 1, "the scan holds the thin TURN");
    let judged = vault.authorization_time()?;
    assert_eq!(judged, T0, "the forced decision judges at the setup clock");
    assert!(
        planned_turn_ids(&vault, &scan, &watermark)?.is_empty(),
        "the preview skips the thin TURN while the grant is live"
    );
    clock.set(T0 + AFTER_SECS);
    assert_eq!(
        planned_turn_ids(&vault, &scan, &watermark)?,
        vec![turn],
        "the preview plans the TURN once its grant has ended"
    );
    Ok(())
}

/// An ended MESSAGE grant passes the TURN unscored at the enqueue: the writer
/// enqueues one attempt for the TURN and writes no prefilter receipt once the
/// clock is past its end, with no grant judged in between; red at
/// `c5bcf23acee3`, where the writer judges at the last decision and the grant
/// still lends its words, so no attempt is enqueued and the receipts exist.
#[test]
fn an_ended_message_grant_passes_the_turn_unscored_at_the_enqueue() -> ExpiredGrantTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, clock) = open_clock_vault(&dir, T0)?;
    let relationship = witness_relationship_space(&vault)?;
    let turn = witness_thin_relationship_turn(&vault, &relationship)?;
    let _grant = grant_dreamer_messages_until(&vault, &relationship, T0 + GRANT_LIVE_SECS)?;
    screen_at_perfect_threshold(&vault)?;
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 1, "the scan holds one TURN");
    assert_eq!(scan[0].turn_id, turn, "the scan holds the thin TURN");
    let judged = vault.authorization_time()?;
    assert_eq!(judged, T0, "the forced decision judges at the setup clock");
    assert!(
        planned_turn_ids(&vault, &scan, &watermark)?.is_empty(),
        "the preview skips the thin TURN while the grant is live"
    );
    clock.set(T0 + AFTER_SECS);
    let outcomes = enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    assert_eq!(outcomes.len(), 1, "the unscored TURN enqueues one attempt");
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert!(skips.is_empty(), "the unscored TURN writes no skip receipt");
    assert!(rounds.is_empty(), "nothing skipped writes no round receipt");
    Ok(())
}

/// An ended MESSAGE grant passes the TURN unscored in the turn wake: armed
/// past the sieve pass's two clock reads, the flip moves the grant clock
/// past the grant's end before the wake's own read observes, so the due wake
/// queues one attempt for the TURN, settles the watermark past it, and writes
/// no prefilter receipt; red at `b29bae1470fc`, where the wake's read judges
/// at the sieve pass's observation with the grant still live, so the TURN is
/// scored thin and skipped: no attempt is queued and both receipts exist.
#[test]
fn an_ended_message_grant_passes_the_turn_unscored_in_the_turn_wake() -> ExpiredGrantTestResult<()>
{
    let dir = tempfile::tempdir()?;
    let (vault, clock) = open_flip_vault(&dir)?;
    let fixture = prepare_wake_fixture(&vault)?;
    clock.flip_after(clock.calls() + SIEVE_CLOCK_READS);
    assert!(
        vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, T0)?,
        "the due wake queues the unscored TURN"
    );
    assert_eq!(
        micro_attempt_ids(&vault)?.len(),
        1,
        "the unscored TURN enqueues one attempt"
    );
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Micro)?.last_learned_at,
        fixture.learned_at,
        "the watermark settles past the TURN"
    );
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert!(skips.is_empty(), "the unscored TURN writes no skip receipt");
    assert!(rounds.is_empty(), "nothing skipped writes no round receipt");
    Ok(())
}

/// The same wake with the clock never armed skips the thin TURN and writes
/// its skip receipt: the grant stays live through the wake's own read at both
/// commits, so the TURN is scored, skipped with no attempt queued, and still
/// consumed; green at `b29bae1470fc` and at this head, proving the main
/// test's wake runs due and its fixture grant lends the words.
#[test]
fn an_unarmed_wake_scores_and_skips_the_thin_turn() -> ExpiredGrantTestResult<()> {
    let dir = tempfile::tempdir()?;
    let (vault, _clock) = open_flip_vault(&dir)?;
    let fixture = prepare_wake_fixture(&vault)?;
    assert!(
        !vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, T0)?,
        "the skipping wake queues nothing"
    );
    assert!(
        micro_attempt_ids(&vault)?.is_empty(),
        "the skipped TURN enqueues no attempt"
    );
    assert_eq!(
        read_watermark(&vault, DreamerConsolidationScope::Micro)?.last_learned_at,
        fixture.learned_at,
        "the watermark settles past the skipped TURN"
    );
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert_eq!(skips.len(), 1, "one TURN is skipped");
    assert_eq!(rounds.len(), 1, "one round is rolled up");
    assert_eq!(
        skips[0].fields.get(TURN),
        Some(&fixture.turn.to_hex()),
        "the skip receipt names the thin TURN"
    );
    Ok(())
}
