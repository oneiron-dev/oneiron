//! L2-37 PR-3 (ARCH-0067 #idle-fold-policy): E+ may Keep a parked run's cached prompt prefix with
//! one refresh, re-arming its due idle call on the refreshed horizon. A Keep whose refresh sends
//! nothing falls back to Fold or Expire, and a wait at its last ask is never kept. A thin cell
//! still decides Expire (RULING L2-37-COLD-START = A).
//!
//! Each wait parks as a canonical run does (the fixture of `tests/idle_wait_returns.rs`): the run
//! parks on its wait, its trap opens and waits, and the try's park binds the trap through the
//! public `park_and_bind_wait_trap`. The due row is written through the public
//! `idle_fold::record_cache_horizon` and the pass runs through the public
//! `idle_fold::run_due_idle_calls`, as the resident pump calls them, with a refresh closure that
//! records the keys it was asked for and returns the horizon its answer stamped. The return cell
//! and the call made read and write through `oneiron::test_doors::idle_fold`, built only under
//! `--cfg oneiron_test_support`.
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
use oneiron::llm::{self, LlmCatalogCost, LlmCatalogEntry, ServedCacheHorizon};
use oneiron::test_doors::idle_fold::{self as doors, IdleCallView};
use oneiron::{DreamerParkCause, EntityId, ModelId, ModelLocality, Vault, VaultConfig, WriteActor};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "idle-fold-keep";
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

/// A temporary device vault with a process-memory device keystore and its embedded owner, and
/// the answering model's catalog row: a cache read at 0.30, a write at 3.75 and an output token
/// at 15.00 per million.
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

/// E+ keeps a prefix whose returns fall inside its next lifetime: a warm return after one Keep
/// beats a cold rewrite. The run holds no kind mark, so Fold is never offered.
#[test]
fn e_plus_keeps_a_prefix_whose_returns_fall_inside_its_next_lifetime() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0x81)?;
    let row = leased_try(&vault, "idle-fold-keep-1")?;
    park(&vault, &row, &key, PARKED_MS)?;
    // Thirty earlier waits came back 360 s in: after the hold [238 s, 298 s) but inside the next
    // lifetime [238 s, 478 s).
    put_own_cell(&vault, &[360; 30])?;
    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );
    assert_eq!(
        doors::due_ms(&vault, &key)?,
        Some(DUE_MS),
        "the call is due a minute before the prefix goes"
    );
    // Costs at the ask (C = 40,000, read 0.30, write 3.75, output 15.00 per million):
    // - Expire: no return within the hold, 30 cold rewrites: 30 * 40,000 * 3.75 / 1e6 = $4.50.
    // - Fold: infinite (no kind mark, F = 0).
    // - Keep: 30 pings (30 * (40,000 * 0.30 / 1e6 + 15.00 / 1e6) = $0.36045) plus 30 warm reads
    //   within the next lifetime (30 * 40,000 * 0.30 / 1e6 = $0.36) plus E1 ($0: every return falls
    //   before t1 = 478 s) = $0.72045. Keep wins.
    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        Some(ServedCacheHorizon {
            sent_unix_ms: DUE_MS,
            lifetime_secs: 300,
            tokens: PREFIX_TOKENS,
        })
    })?;
    assert_eq!(made.made, 1, "the pass at the due minute makes the call");
    assert!(made.ended.is_empty(), "a kept wait is asked again");
    assert_eq!(asked, vec![key], "the refresh goes out once, for the wait");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Keep {
            keeps: 1,
            at_ms: DUE_MS,
        }),
        "E+ keeps: a warm return after one Keep beats a cold rewrite"
    );
    assert_eq!(doors::due_keeps(&vault, &key)?, Some(1));
    assert_eq!(
        doors::due_ms(&vault, &key)?,
        Some(DUE_MS + 300_000 - 60_000),
        "the due row re-arms on the refreshed horizon"
    );
    Ok(())
}

/// A kept wait is asked again before its refreshed horizon: a pass before the re-armed due time
/// makes no call, and the pass at it ends the wait when the cell now favours Expire.
#[test]
fn a_kept_wait_is_asked_again_before_its_refreshed_horizon() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0x82)?;
    let row = leased_try(&vault, "idle-fold-keep-2")?;
    park(&vault, &row, &key, PARKED_MS)?;
    put_own_cell(&vault, &[360; 30])?;
    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );
    let mut asked_first = Vec::new();
    let first = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked_first.push(*wait);
        Some(ServedCacheHorizon {
            sent_unix_ms: DUE_MS,
            lifetime_secs: 300,
            tokens: PREFIX_TOKENS,
        })
    })?;
    assert_eq!(first.made, 1, "the first pass keeps");
    assert!(first.ended.is_empty());
    let rearmed_due = DUE_MS + 300_000 - 60_000;
    assert_eq!(doors::due_ms(&vault, &key)?, Some(rearmed_due));

    let mut asked_early = Vec::new();
    let early = idle_fold::run_due_idle_calls(&vault, rearmed_due - 1, &mut |wait| {
        asked_early.push(*wait);
        Some(ServedCacheHorizon {
            sent_unix_ms: rearmed_due - 1,
            lifetime_secs: 300,
            tokens: PREFIX_TOKENS,
        })
    })?;
    assert_eq!(early.made, 0, "no call before the re-armed due time");
    assert!(early.ended.is_empty());
    assert!(asked_early.is_empty(), "no refresh before the call is due");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Keep {
            keeps: 1,
            at_ms: DUE_MS,
        }),
        "the first call still stands"
    );

    // At 478 s into the wait every return (360 s) already passed, so the cell reads thin and the
    // call is Expire with the one Keep it got before.
    let mut asked_second = Vec::new();
    let second = idle_fold::run_due_idle_calls(&vault, rearmed_due, &mut |wait| {
        asked_second.push(*wait);
        None
    })?;
    assert_eq!(
        second.made, 1,
        "the pass at the re-armed due time makes the call"
    );
    assert_eq!(second.ended, vec![key], "an expired wait ends");
    assert!(asked_second.is_empty(), "Expire asks no refresh");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Expire {
            keeps: 1,
            at_ms: rearmed_due,
        }),
        "the second call is not a Keep"
    );
    assert_eq!(doors::due_ms(&vault, &key)?, None, "the due row is gone");
    assert_eq!(doors::due_keeps(&vault, &key)?, None);
    Ok(())
}

/// A Keep whose refresh sends nothing falls back to Expire when the run holds no kind mark: Fold
/// would rewrite the whole prefix cold, which never beats letting it go.
#[test]
fn a_keep_whose_refresh_sends_nothing_falls_back_to_expire() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0x83)?;
    let row = leased_try(&vault, "idle-fold-keep-3")?;
    park(&vault, &row, &key, PARKED_MS)?;
    put_own_cell(&vault, &[360; 30])?;
    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );
    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        None
    })?;
    assert_eq!(made.made, 1, "the pass makes the fallback call");
    assert_eq!(made.ended, vec![key]);
    assert_eq!(asked, vec![key], "the refresh was asked once");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Expire {
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "a Keep that sent nothing falls back to Expire"
    );
    assert_eq!(doors::due_ms(&vault, &key)?, None, "the due row is gone");
    Ok(())
}

/// A wait at its last ask is not kept: with one ask left Keep is infinite, so the refresh never
/// goes out and the call is Expire.
#[test]
fn a_wait_at_its_last_ask_is_not_kept() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0x84)?;
    let row = leased_try(&vault, "idle-fold-keep-4")?;
    park(&vault, &row, &key, PARKED_MS)?;
    put_own_cell(&vault, &[360; 30])?;
    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );
    doors::set_due_keeps(&vault, &key, 35)?;
    assert_eq!(doors::due_keeps(&vault, &key)?, Some(35));
    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        Some(ServedCacheHorizon {
            sent_unix_ms: DUE_MS,
            lifetime_secs: 300,
            tokens: PREFIX_TOKENS,
        })
    })?;
    assert_eq!(made.made, 1, "the pass makes the call");
    assert_eq!(made.ended, vec![key]);
    assert!(asked.is_empty(), "the refresh is not asked at the last ask");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Expire {
            keeps: 35,
            at_ms: DUE_MS,
        }),
        "a wait at its last ask is not kept"
    );
    assert_eq!(doors::due_ms(&vault, &key)?, None, "the due row is gone");
    Ok(())
}
