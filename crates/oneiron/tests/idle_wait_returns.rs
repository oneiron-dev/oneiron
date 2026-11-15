//! L2-37 PR-1 (ARCH-0067 #idle-fold-policy): every parked canonical wait records its session
//! kind, its wait class and its wall-clock park and return, and the Coach's weekly pass builds
//! the E+ return cells by session kind, wait class, four-hour band and weekend from them.
//!
//! Each wait parks as a canonical run does: the run parks on its wait, its trap opens and waits,
//! and the try's park binds the trap through the public `park_and_bind_wait_trap`; a reply comes
//! through the public `WaitDeliveries::deliver`. The rows, the pass and the cells read through
//! `oneiron::test_doors::idle_fold`, built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, CallerOrigin,
    DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::code_run::{WaitDeliveries, WaitKey, park_and_bind_wait_trap};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, ParkDreamerAttempt,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::settings::CallerLocality;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::idle_fold as doors;
use oneiron::{DreamerParkCause, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "idle-wait-returns";
/// Tue 14 Nov 2023 22:13:20 UTC: band 5 on a weekday.
const TUESDAY_LATE_SECS: u64 = 1_700_000_000;
/// Tue 14 Nov 2023 09:00 UTC: band 2 on a weekday.
const TUESDAY_MORNING_SECS: u64 = 1_699_952_400;
/// Sat 18 Nov 2023 21:00 UTC: band 5 on a weekend.
const SATURDAY_EVENING_SECS: u64 = 1_700_341_200;
const DAY_SECS: u64 = 86_400;

/// A temporary device vault with a process-memory device keystore and its embedded owner, as
/// the crate's test opener opens one.
fn open_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor()?;
    Ok((dir, vault))
}

/// One leased try: a micro consolidation attempt, which carries no dispatch input, enqueued
/// under `tag` and claimed under the fixture's lease owner.
fn leased_try(vault: &Vault, tag: &str) -> TestResult<AttemptRecord> {
    let store = DreamerRunnerStore::new(vault);
    let status = match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now: 20,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        other => panic!("unexpected enqueue outcome {other:?}"),
    };
    let ClaimOutcome::Claimed(row) = AttemptQueue::new(vault).claim_kind(
        DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: u64::MAX,
        },
    )?
    else {
        panic!("the enqueued try is ready to claim");
    };
    assert_eq!(
        row.id, status.attempt.id,
        "the claim takes the try just enqueued"
    );
    Ok(row)
}

/// A wait key with a fresh run and wait id from `seed`, at generation 0.
fn wait_key(seed: u8) -> TestResult<WaitKey> {
    Ok(WaitKey {
        run: EntityId::from_bytes([seed; 16])?,
        wait_id: EntityId::from_bytes([seed.wrapping_add(0x20); 16])?,
        generation: 0,
    })
}

/// Parks `row`'s run on `key` under a trap of `kind` at `now_ms`, as a canonical host does: the
/// run parks on its wait, its trap opens and waits, and the try's park binds the trap.
fn park(
    vault: &Vault,
    row: &AttemptRecord,
    key: &WaitKey,
    kind: llm::DreamerTrapKind,
    now_ms: u64,
) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    assert!(
        !WaitDeliveries::canonical(vault).park(key)?,
        "the run parks before any reply"
    );
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms,
        spend_scope: None,
        wake_pass_bound: false,
    };
    // One step per wait: its run and wait ids.
    let mut step = [0_u8; 32];
    step[..16].copy_from_slice(key.run.as_bytes());
    step[16..].copy_from_slice(key.wait_id.as_bytes());
    let trap = llm::open_trap(vault, &ctx, kind, step, "code-run wait")?;
    assert_eq!(
        llm::register_wait(vault, &trap, now_ms)?,
        llm::DreamerTrapState::Waiting,
        "the trap waits for its signal"
    );
    let woke = park_and_bind_wait_trap(
        vault,
        ParkDreamerAttempt {
            attempt_id: row.id,
            reason: "idle wait park".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap.trap_claim_id),
            carried_spend: None,
            now: now_ms / 1_000,
        },
        key,
        &trap,
        now_ms,
    )?;
    assert!(!woke, "the park binds with no reply delivered");
    Ok(())
}

/// Parks a fresh try on a fresh human wait at `parked_secs` and delivers its answer
/// `gap_secs` later.
fn human_wait_returned(vault: &Vault, seed: u8, parked_secs: u64, gap_secs: u64) -> TestResult {
    let row = leased_try(vault, &format!("idle-wait-{seed}"))?;
    let key = wait_key(seed)?;
    park(
        vault,
        &row,
        &key,
        llm::DreamerTrapKind::HumanResponse,
        parked_secs * 1_000,
    )?;
    let delivered = WaitDeliveries::canonical(vault).deliver(
        key.wait_id,
        &serde_json::json!({"answer": "done"}),
        (parked_secs + gap_secs) * 1_000,
    )?;
    assert_eq!(delivered, 1, "the answer delivers to its one waiter");
    Ok(())
}

/// A parked human wait records its session kind, its class and its wall-clock park, and its
/// delivered answer closes it at the delivery's time.
#[test]
fn a_parked_human_wait_records_its_wall_clock_return() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let parked_at_ms = TUESDAY_LATE_SECS * 1_000;
    human_wait_returned(&vault, 0x61, TUESDAY_LATE_SECS, 95)?;

    let waits = doors::waits(&vault)?;
    assert_eq!(
        waits,
        vec![doors::IdleWaitView {
            key: wait_key(0x61)?,
            // A consolidation try has no dispatch input.
            session_kind: "unknown",
            wait_class: "user",
            parked_at_ms,
            returned_at_ms: Some(parked_at_ms + 95_000),
            never: false,
        }],
        "the one parked wait is recorded, closed at its answer's time"
    );
    Ok(())
}

/// A peer wait records as a tool wait and a consent wait as a user wait; both stay open with
/// no reply.
#[test]
fn a_peer_wait_records_as_a_tool_wait() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let peer_row = leased_try(&vault, "idle-wait-peer")?;
    let peer_key = wait_key(0x62)?;
    park(
        &vault,
        &peer_row,
        &peer_key,
        llm::DreamerTrapKind::PeerResult,
        TUESDAY_LATE_SECS * 1_000,
    )?;
    let consent_row = leased_try(&vault, "idle-wait-consent")?;
    let consent_key = wait_key(0x63)?;
    park(
        &vault,
        &consent_row,
        &consent_key,
        llm::DreamerTrapKind::Consent,
        TUESDAY_LATE_SECS * 1_000 + 1,
    )?;

    let waits = doors::waits(&vault)?;
    let class_of = |key: WaitKey| {
        waits
            .iter()
            .find(|wait| wait.key == key)
            .map(|wait| (wait.wait_class, wait.returned_at_ms, wait.never))
    };
    assert_eq!(waits.len(), 2, "both parked waits are recorded");
    assert_eq!(
        class_of(peer_key),
        Some(("tool", None, false)),
        "a peer wait is a tool wait, open"
    );
    assert_eq!(
        class_of(consent_key),
        Some(("user", None, false)),
        "a consent wait is a user wait, open"
    );
    Ok(())
}

/// A wait still open a day after it parked counts as never: the pass marks its row, and its
/// cell holds no gap and one never.
#[test]
fn a_wait_left_open_past_a_day_counts_as_never() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let row = leased_try(&vault, "idle-wait-open")?;
    let key = wait_key(0x64)?;
    park(
        &vault,
        &row,
        &key,
        llm::DreamerTrapKind::HumanResponse,
        TUESDAY_LATE_SECS * 1_000,
    )?;
    let now = TUESDAY_LATE_SECS + 25 * 3_600;

    assert!(doors::rebuild(&vault, now)?, "the first pass rebuilds");
    let waits = doors::waits(&vault)?;
    assert_eq!(waits.len(), 1, "the open wait is still recorded");
    assert!(waits[0].never, "the pass marks a day-old open wait never");
    assert_eq!(waits[0].returned_at_ms, None, "it never returned");
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 5, false)?,
        Some(doors::IdleReturnCellView {
            returned_after_secs: Vec::new(),
            never: 1,
        }),
        "its cell holds no gap and one never"
    );
    Ok(())
}

/// The weekly pass builds one cell per session kind, wait class, band and weekend, rebuilds
/// only once its last build is a week old, and drops waits older than its eight-week window.
#[test]
fn the_weekly_pass_builds_return_cells_by_kind_band_and_weekend() -> TestResult {
    let (_dir, vault) = open_vault()?;
    human_wait_returned(&vault, 0x65, TUESDAY_MORNING_SECS, 40)?;
    human_wait_returned(&vault, 0x66, TUESDAY_MORNING_SECS + 60, 600)?;
    human_wait_returned(&vault, 0x67, TUESDAY_MORNING_SECS + 120, 95)?;
    human_wait_returned(&vault, 0x68, SATURDAY_EVENING_SECS, 30)?;
    let now = SATURDAY_EVENING_SECS + 3_600;

    assert!(doors::rebuild(&vault, now)?, "the first pass rebuilds");
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 2, false)?,
        Some(doors::IdleReturnCellView {
            returned_after_secs: vec![40, 95, 600],
            never: 0,
        }),
        "the weekday band-2 cell holds its three gaps, sorted"
    );
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 5, true)?,
        Some(doors::IdleReturnCellView {
            returned_after_secs: vec![30],
            never: 0,
        }),
        "the Saturday band-5 cell holds its one gap"
    );
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 5, false)?,
        None,
        "no wait parked in the weekday band 5"
    );

    assert!(
        !doors::rebuild(&vault, now + DAY_SECS)?,
        "a pass a day after the build rebuilds nothing"
    );
    assert!(
        doors::rebuild(&vault, now + 7 * DAY_SECS)?,
        "a pass a week after the build rebuilds"
    );
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 2, false)?.map(|cell| cell.returned_after_secs),
        Some(vec![40, 95, 600]),
        "the rebuilt cell reads the same waits"
    );

    assert!(
        doors::rebuild(&vault, now + 63 * DAY_SECS)?,
        "a pass nine weeks on rebuilds"
    );
    assert!(
        doors::waits(&vault)?.is_empty(),
        "waits older than the eight-week window are dropped"
    );
    assert_eq!(
        doors::cell(&vault, "unknown", "user", 2, false)?,
        None,
        "a rebuild with no waits in its window keeps no cell"
    );
    Ok(())
}

/// A run whose root came in over a connection waits as `connected`, and one the host dispatched
/// itself as `hosted`.
#[test]
fn a_connection_dispatched_runs_wait_keys_as_connected() -> TestResult {
    const NOW: u64 = TUESDAY_LATE_SECS;
    let clock = ManualClock::new(NOW);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    // Opened as `tests/agent_powers.rs` opens its vault: install signing before the owner.
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.prepare_install_signing()?;
    let owner_id = vault.ensure_embedded_owner_actor()?;
    let owner =
        vault.authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())?;
    let agent = EntityId::from_bytes([0x93; 16])?;
    vault.create_agent_definition_as(
        &owner,
        &agent,
        &definition("fixture.idle_wait"),
        TimeRange {
            start: NOW,
            end: NOW,
        },
        NOW,
    )?;

    let dispatch = |origin: CallerOrigin| -> TestResult<AttemptId> {
        let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(&vault)
            .dispatch_with_context(
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(agent),
                    parent_attempt: None,
                    dedupe_key: None,
                    run_id: None,
                    now: NOW,
                },
                AgentSpawnContext::default().with_caller_origin(origin),
            )?
        else {
            panic!("the agent dispatches without running a model")
        };
        Ok(status.attempt.id)
    };
    let connected = dispatch(CallerOrigin::Connection {
        locality: CallerLocality::OnDevice,
    })?;
    let hosted = dispatch(CallerOrigin::NativeHost)?;

    clock.set(NOW + 1);
    let mut leased = Vec::new();
    for _ in 0..2 {
        let ClaimOutcome::Claimed(row) = AttemptQueue::new(&vault).claim(ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: NOW + 1,
        })?
        else {
            panic!("both dispatched attempts are ready to lease")
        };
        leased.push(row);
    }
    let row_of = |id: AttemptId| {
        leased
            .iter()
            .find(|row| row.id == id)
            .expect("each dispatched attempt is leased")
    };

    let connected_key = wait_key(0x69)?;
    let hosted_key = wait_key(0x6A)?;
    park(
        &vault,
        row_of(connected),
        &connected_key,
        llm::DreamerTrapKind::HumanResponse,
        (NOW + 2) * 1_000,
    )?;
    park(
        &vault,
        row_of(hosted),
        &hosted_key,
        llm::DreamerTrapKind::HumanResponse,
        (NOW + 3) * 1_000,
    )?;

    let waits = doors::waits(&vault)?;
    let kind_of = |key: WaitKey| {
        waits
            .iter()
            .find(|wait| wait.key == key)
            .map(|wait| wait.session_kind)
    };
    assert_eq!(
        kind_of(connected_key),
        Some("connected"),
        "a run admitted over a connection waits as connected"
    );
    assert_eq!(
        kind_of(hosted_key),
        Some("hosted"),
        "a run the host dispatched waits as hosted"
    );
    Ok(())
}

/// An owner-created Base agent at ceiling Proposed, as `tests/agent_powers.rs` defines one.
fn definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "idle wait fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("define_agent"),
        )]),
        None,
        true,
        None,
    )
}
