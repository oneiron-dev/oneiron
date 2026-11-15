//! L2-37 PR-4 (ARCH-0067 #idle-fold-policy; RULING L2-37-COLD-START = B, RULING
//! L2-37-RULE-D-SETTING = A): a parked wait whose return cell is too thin to read is a cold start,
//! and its idle call takes the fixed rule D. Keep the cached prefix warm through the owner's
//! window, the catalogue key `idle_fold.cold_start_keep_through_secs` (thirty minutes unless the
//! owner sets it, 0 keeping nothing, an unreadable row reading 0), then Fold the run's kind marks
//! at the next timer, or Expire when it holds none. At the fixture's five-minute lifetime the first
//! call comes 240 s after the answer and each Keep moves the next one 240 s on, so a window of
//! `w` seconds gives `max(1, ceil(w / 240) - 1)` Keeps.
//!
//! The fixture is `tests/idle_fold_horizon.rs`'s: each wait parks as a canonical run does, the
//! due row is written through the public `idle_fold::record_cache_horizon` and the pass runs
//! through the public `idle_fold::run_due_idle_calls` with a refresh closure that stands in for
//! the pump's send. The owner sets the window through `Vault::set_setting`, the generic set that
//! `vault.settings.set` calls. The run's step outputs, its kind mark, the due row's Keeps, a
//! damaged setting row and the call made read and write through `oneiron::test_doors`, built only
//! under `--cfg oneiron_test_support`.
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
use oneiron::setting::{
    self, ScopeKind, SetBy, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
};
use oneiron::store::GateDecisionId;
use oneiron::test_doors::idle_fold::{self as doors, FoldLedgerView, IdleCallView};
use oneiron::test_doors::setting::plant_undecodable_row;
use oneiron::{DreamerParkCause, EntityId, ModelId, ModelLocality, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "idle-fold-cold-start";
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

/// The cold-start keep window's catalogue key.
const KEEP_THROUGH: &str = "idle_fold.cold_start_keep_through_secs";
/// The default window's Keeps at the fixture's lifetime: `ceil(1800 / 240) - 1`.
const DEFAULT_KEEPS: u32 = 7;
/// A Keep re-arms the call a lifetime less a minute after its refresh.
const PERIOD_MS: u64 = 240_000;
/// The two folded observations, four bytes to a token.
const FOLDED_TOKENS: u64 = 2 * OBSERVATION_BYTES as u64 / 4;

/// The refresh's answer: the prefix cached again from `sent_ms`.
fn refreshed_at(sent_ms: u64) -> Option<ServedCacheHorizon> {
    Some(ServedCacheHorizon {
        sent_unix_ms: sent_ms,
        lifetime_secs: LIFETIME_SECS,
        tokens: PREFIX_TOKENS,
    })
}

/// Sets the cold-start keep window to `secs` as the vault's owner.
fn owner_sets_keep_through(vault: &Vault, secs: u64) -> TestResult {
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let outcome = vault.set_setting(
        SettingCaller::Owner(&proof),
        SetSetting {
            key: KEEP_THROUGH.to_owned(),
            item: None,
            scope: SettingScope::Vault,
            mode: SettingMode::Value,
            value: Some(json!(secs)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    )?;
    assert!(
        matches!(&outcome, SetSettingOutcome::Applied { value, .. } if *value == json!(secs)),
        "the owner's change applies: {outcome:?}"
    );
    Ok(())
}

/// The window is a catalogue key the owner alone sets, at the vault.
#[test]
fn the_cold_start_window_is_an_owner_key_at_the_vault() -> TestResult {
    let spec = setting::spec_named(KEEP_THROUGH)?;
    assert_eq!(spec.name, KEEP_THROUGH);
    assert_eq!(spec.set_by, SetBy::Owner, "the owner alone sets it");
    assert!(
        matches!(spec.scopes, [ScopeKind::Vault]),
        "it is set at the vault"
    );
    Ok(())
}

/// A wait with no return history is a cold start: each call while the wait has had fewer than
/// the default window's seven Keeps sends one refresh and re-arms on its horizon, and the run's
/// kind marks wait.
#[test]
fn a_cold_start_keeps_its_prefix_warm_through_the_default_window() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0xa1)?;
    assert!(
        idle_fold::record_cache_horizon(&vault, &key, row.id, agent()?, &prefix())?,
        "the parked wait takes its due idle call"
    );

    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        refreshed_at(DUE_MS)
    })?;
    assert_eq!(made.made, 1, "the pass makes the call");
    assert!(made.ended.is_empty(), "a kept wait goes on");
    assert_eq!(asked, vec![key], "the refresh goes out once, for the wait");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Keep {
            keeps: 1,
            at_ms: DUE_MS,
        }),
        "a cold start keeps"
    );
    let second_due = DUE_MS + PERIOD_MS;
    assert_eq!(
        doors::due_ms(&vault, &key)?,
        Some(second_due),
        "the call re-arms on the refreshed horizon"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?.pending_marks,
        vec![fold],
        "nothing folds while the prefix is kept"
    );

    // Six Keeps so far: the seventh is still inside the window.
    doors::set_due_keeps(&vault, &key, DEFAULT_KEEPS - 1)?;
    let mut asked_again = Vec::new();
    idle_fold::run_due_idle_calls(&vault, second_due, &mut |wait| {
        asked_again.push(*wait);
        refreshed_at(second_due)
    })?;
    assert_eq!(asked_again, vec![key], "the seventh Keep sends its refresh");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Keep {
            keeps: DEFAULT_KEEPS,
            at_ms: second_due,
        }),
        "the seventh Keep is the window's last"
    );
    Ok(())
}

/// Once a cold start has had the window's Keeps, the next call folds the run's kind marks with
/// no refresh, and the wait ends.
#[test]
fn a_cold_start_folds_its_kind_marks_once_its_keeps_are_spent() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0xa2)?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);
    doors::set_due_keeps(&vault, &key, DEFAULT_KEEPS)?;

    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        refreshed_at(DUE_MS)
    })?;
    assert_eq!(made.made, 1, "the pass makes the call");
    assert_eq!(made.ended, vec![key], "a folded wait ends");
    assert!(asked.is_empty(), "no refresh after the window's Keeps");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            tokens: FOLDED_TOKENS,
            keeps: DEFAULT_KEEPS,
            at_ms: DUE_MS,
        }),
        "the call after the Keeps folds"
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
    Ok(())
}

/// A cold start whose run holds no kind mark lets the prefix expire once its Keeps are spent.
#[test]
fn a_cold_start_with_no_kind_mark_expires_once_its_keeps_are_spent() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = wait_key(0xa3)?;
    let row = leased_try(&vault, "idle-fold-cold-start-3")?;
    park(&vault, &row, &key, PARKED_MS)?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);
    doors::set_due_keeps(&vault, &key, DEFAULT_KEEPS)?;

    let mut asked = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        refreshed_at(DUE_MS)
    })?;
    assert_eq!(made.made, 1, "the pass makes the call");
    assert_eq!(made.ended, vec![key], "an expired wait ends");
    assert!(asked.is_empty(), "no refresh after the window's Keeps");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Expire {
            keeps: DEFAULT_KEEPS,
            at_ms: DUE_MS,
        }),
        "with nothing to fold the prefix expires"
    );
    Ok(())
}

/// The owner turns the cold-start keep off with a window of 0: the first call folds the run's
/// kind marks at once, with no refresh.
#[test]
fn the_owner_turns_the_cold_start_keep_off_with_zero() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0xa4)?;
    owner_sets_keep_through(&vault, 0)?;
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
        refreshed_at(DUE_MS)
    })?;
    assert_eq!(made.made, 1, "the pass makes the call");
    assert!(asked.is_empty(), "a window of 0 keeps nothing");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            tokens: FOLDED_TOKENS,
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "the first call folds"
    );
    assert_eq!(
        doors::fold_ledger(&vault, key.run)?.kind_folds,
        vec![fold],
        "the kind mark landed as its fold"
    );
    Ok(())
}

/// A shorter window keeps fewer times: ten minutes give `ceil(600 / 240) - 1 = 2` Keeps, so the
/// call after the second Keep folds, where the default window would keep again.
#[test]
fn a_shorter_owner_window_keeps_fewer_times() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0xa5)?;
    owner_sets_keep_through(&vault, 600)?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);
    doors::set_due_keeps(&vault, &key, 1)?;

    let mut asked = Vec::new();
    idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        refreshed_at(DUE_MS)
    })?;
    assert_eq!(asked, vec![key], "the second Keep sends its refresh");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Keep {
            keeps: 2,
            at_ms: DUE_MS,
        }),
        "the second Keep is the window's last"
    );

    let second_due = DUE_MS + PERIOD_MS;
    let mut asked_again = Vec::new();
    let made = idle_fold::run_due_idle_calls(&vault, second_due, &mut |wait| {
        asked_again.push(*wait);
        refreshed_at(second_due)
    })?;
    assert_eq!(made.ended, vec![key], "a folded wait ends");
    assert!(asked_again.is_empty(), "no third Keep");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            tokens: FOLDED_TOKENS,
            keeps: 2,
            at_ms: second_due,
        }),
        "the call after the owner's two Keeps folds"
    );
    assert_eq!(doors::fold_ledger(&vault, key.run)?.kind_folds, vec![fold]);
    Ok(())
}

/// A window row that does not decode reads as the key's strictest value, 0: the cold start keeps
/// nothing and folds at its first call.
#[test]
fn an_unreadable_window_row_keeps_nothing() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let (row, key, fold) = parked_run_with_a_kind_mark(&vault, 0xa6)?;
    plant_undecodable_row(&vault, KEEP_THROUGH, SettingScope::Vault)?;
    assert!(idle_fold::record_cache_horizon(
        &vault,
        &key,
        row.id,
        agent()?,
        &prefix()
    )?);

    let mut asked = Vec::new();
    idle_fold::run_due_idle_calls(&vault, DUE_MS, &mut |wait| {
        asked.push(*wait);
        refreshed_at(DUE_MS)
    })?;
    assert!(asked.is_empty(), "an unreadable window keeps nothing");
    assert_eq!(
        doors::idle_call(&vault, &key)?,
        Some(IdleCallView::Fold {
            folds: 1,
            tokens: FOLDED_TOKENS,
            keeps: 0,
            at_ms: DUE_MS,
        }),
        "the first call folds"
    );
    assert_eq!(doors::fold_ledger(&vault, key.run)?.kind_folds, vec![fold]);
    Ok(())
}
