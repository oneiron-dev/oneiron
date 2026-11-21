//! L2-37 PR-2 (ARCH-0067 #idle-fold-policy): a minute before the provider lets a parked run's
//! cached prompt prefix go, the idle pass makes one call for its wait, Fold or Expire, by E+ over
//! the wait's return cell. Fold seals the run's pending kind marks with no model call, so a return
//! after the prefix is gone writes the smaller context; the resumed run takes the folds as its
//! first brief boundary. A thin cell takes the cold-start rule D (RULING L2-37-COLD-START = B;
//! its window in `tests/idle_fold_cold_start.rs`).
//!
//! Each wait parks as a canonical run does (the fixture of `tests/idle_wait_returns.rs`): the run
//! parks on its wait, its trap opens and waits, and the try's park binds the trap through the
//! public `park_and_bind_wait_trap`; a reply comes through the public `WaitDeliveries::deliver`.
//! The due row is written through the public `idle_fold::record_cache_horizon` and the pass runs
//! through the public `idle_fold::run_due_idle_calls`, as the resident pump calls them. The run's
//! step outputs, its kind mark, the return cell and the call made read and write through
//! `oneiron::test_doors::idle_fold`, built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::{WaitDeliveries, WaitKey, park_and_bind_wait_trap};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt, ParkDreamerAttempt,
};
use oneiron::edge::EdgeActorClass;
use oneiron::idle_fold::{self, CachedPrefixHorizon};
use oneiron::llm::registry::{ModelRegistryRow, ModelWireFormat};
use oneiron::llm::{self, LlmCatalogCost, LlmCatalogEntry, LlmUsage, ServedCacheHorizon};
use oneiron::test_doors::idle_fold::{self as doors, FoldLedgerView, IdleCallView};
use oneiron::{DreamerParkCause, EntityId, ModelId, ModelLocality, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "idle-fold-horizon";
/// Tue 14 Nov 2023 22:13:20 UTC: band 5 on a weekday.
const PARKED_SECS: u64 = 1_700_000_000;
const PARKED_MS: u64 = PARKED_SECS * 1_000;
/// The model that answered the run's last turn, whose catalog prices the call.
const MODEL: &str = "local/idle-fold@r1";
/// The answer's send went out two seconds before the park, and the provider keeps its prefix
/// five minutes from the send.
const SENT_MS: u64 = PARKED_MS - 2_000;
const LIFETIME_SECS: u32 = 300;
/// The call is due a minute before the prefix goes: 238 s into the wait.
const DUE_MS: u64 = SENT_MS + 300_000 - 60_000;
/// The cached prefix, in prompt tokens.
const PREFIX_TOKENS: u64 = 40_000;
/// Each step's observation, 4,000 bytes: about 1,000 prompt tokens.
const OBSERVATION_BYTES: usize = 4_000;

/// A temporary device vault with a process-memory device keystore and its embedded owner, and
/// the answering model's catalog row: a cache read at 0.30 and a write at 3.75 per million.
fn open_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor()?;
    vault.put_model_registry_row(&ModelRegistryRow {
        version: 1,
        wire: ModelWireFormat::Local,
        catalog: LlmCatalogEntry {
            model: model(),
            display_name: "idle fold fixture".into(),
            locality: ModelLocality::OnDevice,
            context_window_tokens: 200_000,
            max_output_tokens: None,
            cost: Some(LlmCatalogCost {
                input_per_million: "3.00".into(),
                output_per_million: "15.00".into(),
                cache_read_per_million: Some("0.30".into()),
                cache_write_per_million: Some("3.75".into()),
                currency: Some("USD".into()),
            }),
            capabilities: vec![],
            metadata: Default::default(),
        },
        scores: Default::default(),
        fetched_at: Default::default(),
        tokens_per_o200k: None,
        answer_tokens_per_o200k: None,
        stale_since: None,
        source_rows: None,
    })?;
    Ok((dir, vault))
}

fn model() -> ModelId {
    ModelId::new(MODEL).expect("the fixture's model id is valid")
}

/// The prefix the run's last turn answer left cached.
fn prefix() -> CachedPrefixHorizon {
    CachedPrefixHorizon {
        horizon: ServedCacheHorizon {
            sent_unix_ms: SENT_MS,
            lifetime_secs: LIFETIME_SECS,
            tokens: PREFIX_TOKENS,
        },
        model: model(),
    }
}

/// The run's own agent, the byline of the folds its marks ask for.
fn agent() -> TestResult<EntityId> {
    Ok(EntityId::from_bytes([0x93; 16])?)
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

/// A run of three finished steps whose first two outputs are marked for a fold by kind, parked
/// on a fresh human wait at `PARKED_MS`, as a canonical host parks one. Returns the parked try,
/// its wait key and the mark's fold number.
fn parked_run_with_a_kind_mark(
    vault: &Vault,
    seed: u8,
) -> TestResult<(AttemptRecord, WaitKey, u64)> {
    let key = wait_key(seed)?;
    let observation: &[u8] = &[b'o'; OBSERVATION_BYTES];
    doors::seed_step_observations(vault, key.run, &[observation, observation, observation])?;
    let fold = doors::mark_output_fold(vault, key.run, (0, 1), 2)?;
    let row = leased_try(vault, &format!("idle-fold-{seed}"))?;
    park(vault, &row, &key, PARKED_MS)?;
    Ok((row, key, fold))
}

/// Parks `row`'s run on `key` under a human-response trap at `now_ms`, as a canonical host does:
/// the run parks on its wait, its trap opens and waits, and the try's park binds the trap.
fn park(vault: &Vault, row: &AttemptRecord, key: &WaitKey, now_ms: u64) -> TestResult {
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
    let trap = llm::open_trap(
        vault,
        &ctx,
        llm::DreamerTrapKind::HumanResponse,
        step,
        "code-run wait",
    )?;
    assert_eq!(
        llm::register_wait(vault, &trap, now_ms)?,
        llm::DreamerTrapState::Waiting,
        "the trap waits for its signal"
    );
    let woke = park_and_bind_wait_trap(
        vault,
        ParkDreamerAttempt {
            attempt_id: row.id,
            reason: "idle fold park".to_owned(),
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

/// The cell of the fixture's waits: a weekday band-5 human wait of a run with no dispatch input.
fn put_own_cell(vault: &Vault, returned_after_secs: &[u32]) -> TestResult {
    doors::put_cell(
        vault,
        ("unknown", "user"),
        (5, false),
        returned_after_secs,
        0,
    )?;
    Ok(())
}

/// A parked run whose waits come back long after its prefix is gone folds its kind marks at the
/// cache horizon: the pass at the due minute lands the fold, records the call, drops the due row
/// and leaves the folds for the run's next entry as its brief boundary.
#[test]
fn a_parked_run_folds_its_kind_marks_at_the_cache_horizon() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0x71)?;
    // Thirty earlier waits of its cell came back an hour in: none within the prefix's last minute.
    put_own_cell(&vault, &[3_600; 30])?;

    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );
    assert_eq!(
        doors::due_ms(&vault, &key)?,
        Some(DUE_MS),
        "the call is due a minute before the prefix goes"
    );
    assert_eq!(idle_fold::next_idle_call_due_ms(&vault)?, Some(DUE_MS));

    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS - 1, &mut |_| None)?.made,
        0,
        "no call before it is due"
    );
    assert_eq!(doors::idle_call(&vault, &key)?, None);

    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |_| None)?.made,
        1,
        "the pass at the due minute makes the call"
    );
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            // The two folded observations, four bytes to a token.
            tokens: 2 * OBSERVATION_BYTES as u64 / 4,
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "E+ folds: every return comes after the prefix is gone"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?,
        FoldLedgerView {
            pending_marks: Vec::new(),
            kind_folds: vec![fold],
        },
        "the kind mark landed as its fold"
    );
    assert_eq!(doors::due_ms(&vault, &key)?, None, "the due row is gone");
    assert_eq!(idle_fold::next_idle_call_due_ms(&vault)?, None);
    assert_eq!(
        doors::take_fold_boundary(&vault, key.run)?,
        Some(vec![fold]),
        "the run's next entry takes the fold as its brief boundary"
    );
    assert_eq!(
        doors::take_fold_boundary(&vault, key.run)?,
        None,
        "the boundary is taken once"
    );
    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS + 60_000, &mut |_| None)?.made,
        0,
        "a wait gets one call"
    );
    Ok(())
}

/// Two kind marks over one step fold its output once: the step shows the first fold's stub
/// (`FoldLedger::kind_covering`), so the call counts that output's tokens once, not per mark.
#[test]
fn overlapping_kind_marks_count_a_shared_output_once() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0x76)?;
    let observation: &[u8] = &[b'o'; OBSERVATION_BYTES];
    doors::seed_step_observations(&vault, key.run, &[observation, observation, observation])?;
    let first = doors::mark_output_fold(&vault, key.run, (0, 1), 2)?;
    let second = doors::mark_output_fold(&vault, key.run, (1, 2), 2)?;
    let row = leased_try(&vault, "idle-fold-overlap")?;
    park(&vault, &row, &key, PARKED_MS)?;
    put_own_cell(&vault, &[3_600; 30])?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);

    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |_| None)?.made,
        1
    );
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 2,
            // Steps 0, 1 and 2, each once: step 1 lies under both marks.
            tokens: 3 * OBSERVATION_BYTES as u64 / 4,
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "the shared step's output counts once"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?,
        FoldLedgerView {
            pending_marks: Vec::new(),
            kind_folds: vec![first, second],
        },
        "both marks landed as folds"
    );
    Ok(())
}

/// When the waits of its cell come back within the prefix's last minute, a warm read beats a
/// cold write of the folded prefix: the call is Expire and the mark stays pending.
#[test]
fn a_wait_whose_returns_fall_in_the_last_minute_expires() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0x72)?;
    // Thirty earlier waits came back 250 s in: inside [238 s, 298 s).
    put_own_cell(&vault, &[250; 30])?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);

    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |_| None)?.made,
        1
    );
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Expire {
            keeps: 0,
            at_ms: DUE_MS
        }),
        "E+ lets the prefix go: its returns read it warm"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?,
        FoldLedgerView {
            pending_marks: vec![fold],
            kind_folds: Vec::new(),
        },
        "nothing folds; the mark waits for the run's next breakpoint"
    );
    assert_eq!(doors::take_fold_boundary(&vault, key.run)?, None);
    assert_eq!(doors::due_ms(&vault, &key)?, None, "the due row is gone");
    Ok(())
}

/// A cell whose waits still waiting at the call's elapsed time are below the person-wait floor
/// of thirty, at every level of its back-off, is a cold start (RULING L2-37-COLD-START = B): rule
/// D keeps, and a Keep whose refresh sends nothing falls back to the call after the Keeps, which
/// folds the run's kind mark.
#[test]
fn a_wait_whose_cell_is_thin_takes_the_cold_start_rule() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0x73)?;
    // Twenty-nine waits, all of which would favour Fold: one short of the floor.
    put_own_cell(&vault, &[3_600; 29])?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);

    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        None
    })?;
    assert_eq!(made.made, 1);
    assert_eq!(asked, vec![key], "rule D asks for a refresh");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            tokens: 2 * OBSERVATION_BYTES as u64 / 4,
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "the Keep sent nothing, so the run's kind mark folds"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?.kind_folds,
        vec![fold],
        "the kind mark landed as its fold"
    );
    Ok(())
}

/// A reply that lands before the horizon closes the wait and drops its due call in the same
/// commit: the pass at the due minute makes no call, and the run folds nothing while away.
#[test]
fn a_reply_landing_before_the_horizon_cancels_the_call() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0x74)?;
    put_own_cell(&vault, &[3_600; 30])?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);

    let delivered = WaitDeliveries::canonical(&vault).deliver(
        key.wait_id,
        &serde_json::json!({"answer": "done"}),
        PARKED_MS + 100_000,
    )?;
    assert_eq!(delivered, 1, "the answer delivers to its one waiter");
    assert_eq!(
        doors::due_ms(&vault, &key)?,
        None,
        "the reply's commit drops the due call"
    );

    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |_| None)?.made,
        0,
        "no call for a run that came back"
    );
    assert_eq!(doors::idle_call(&vault, &key)?, None);
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?.pending_marks,
        vec![fold],
        "the mark waits for the resumed run's own breakpoint"
    );
    assert!(
        !idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "a wait already answered takes no due call"
    );
    assert_eq!(doors::due_ms(&vault, &key)?, None);
    Ok(())
}

/// Only an answer whose served receipt names a cached prefix gives its run a horizon: a receipt
/// with no `cache_horizon` key, or a provider usage object that is not a served receipt, gives
/// none, and a parked run with no horizon gets no idle call.
#[test]
fn an_answer_with_no_cache_horizon_gets_no_idle_call() -> TestResult {
    let served = |horizon: Option<serde_json::Value>| {
        let mut receipt = serde_json::json!({
            "rung": 0,
            "usage": {},
            (LlmUsage::SERVED_MODEL_ID_KEY): MODEL,
        });
        if let Some(horizon) = horizon {
            receipt[LlmUsage::SERVED_CACHE_HORIZON_KEY] = horizon;
        }
        let mut usage = LlmUsage::zero();
        usage.raw_provider = receipt;
        usage
    };
    let stamp = serde_json::json!({
        "sent_unix_ms": SENT_MS,
        "lifetime_secs": LIFETIME_SECS,
        "tokens": PREFIX_TOKENS,
    });
    assert_eq!(
        CachedPrefixHorizon::of_answer(&served(Some(stamp.clone()))),
        Some(prefix()),
        "a stamped served receipt names the prefix and its answering model"
    );
    assert_eq!(
        CachedPrefixHorizon::of_answer(&served(None)),
        None,
        "a served receipt with no stamp names none"
    );
    let mut provider_usage = LlmUsage::zero();
    provider_usage.raw_provider = serde_json::json!({
        (LlmUsage::SERVED_MODEL_ID_KEY): MODEL,
        (LlmUsage::SERVED_CACHE_HORIZON_KEY): stamp,
    });
    assert_eq!(
        CachedPrefixHorizon::of_answer(&provider_usage),
        None,
        "a provider's own usage object is never read as a served receipt"
    );

    let (_dir, vault) = open_vault()?;
    let (_row, key, fold) = parked_run_with_a_kind_mark(&vault, 0x75)?;
    put_own_cell(&vault, &[3_600; 30])?;
    assert_eq!(idle_fold::next_idle_call_due_ms(&vault)?, None);
    assert_eq!(
        idle_fold::run_due_idle_calls(&vault, u64::MAX, &mut |_| None)?.made,
        0,
        "a parked run with no horizon gets no call"
    );
    assert_eq!(doors::idle_call(&vault, &key)?, None);
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?.pending_marks,
        vec![fold]
    );
    Ok(())
}
