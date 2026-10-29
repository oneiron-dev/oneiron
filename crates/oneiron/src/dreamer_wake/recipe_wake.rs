//! The wake policy's recipe lane (ARCH-0026 #wake). Each receipt runs its
//! recipe's body over the input row the policy outbox holds for it, and the
//! input leaves the outbox in the commit that does the recipe's work. A
//! stopped or deferred wake keeps its input and reports Park or Deferred,
//! so the trigger is never lost.

use rmpv::Value;

use crate::Vault;
use crate::dreamer_runner::{
    DREAMER_RECIPE_WAKE_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerParkCause, DreamerRunnerStore,
    EnqueueDreamerVaultCleanupAttempt,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::deadline::WakeCancellation;
use super::driver::{DREAMER_CANCELLED_PARK_REASON, DREAMER_PAUSED_PARK_REASON};
use super::policy::{
    WakePolicyTrigger, WakeRecipe, take_wake_recipe_input_in_txn, wake_policy_input_covers,
};
use super::read_phase::{OnStale, READ_PHASE_STARVATION_SECS, ReadWrite, WakeStop};
use super::scheduling::WakeTurnSubject;
use super::types::{DreamerAttemptExecution, WakeAttemptContext, WakeTrigger};

fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer recipe wake".into())
}

/// Runs one recipe receipt. A receipt whose input an earlier receipt for
/// the same recipe already took settles with nothing to do: that receipt's
/// body read the coalesced range this one names.
pub(crate) fn execute(
    attempt: &DreamerAdmittedAttempt,
    ctx: &WakeAttemptContext<'_>,
) -> Result<DreamerAttemptExecution> {
    if attempt.status.payload.attempt_type != DREAMER_RECIPE_WAKE_ATTEMPT_KIND {
        return Err(invalid());
    }
    let trigger: WakePolicyTrigger =
        serde_json::from_str(attempt.status.payload.input.as_str().ok_or_else(invalid)?)
            .map_err(|_| invalid())?;
    if trigger.turn_count == 0 && trigger.record_count == 0 && trigger.nightly_count == 0 {
        return Err(invalid());
    }
    let now = ctx.now_ms / 1_000;
    match trigger.recipe {
        WakeRecipe::Continuous => {
            if let Some(execution) = continuous(ctx, attempt, &trigger, now)? {
                return Ok(execution);
            }
        }
        WakeRecipe::Nightly => nightly(ctx.vault, attempt, &trigger, now)?,
        WakeRecipe::Weave => {
            ctx.vault.with_write_txn_grouped(|txn| {
                if take_wake_recipe_input_in_txn(ctx.vault, txn, &trigger)?.is_some() {
                    super::recipes::weave_in_txn(ctx.vault, txn, attempt, now)?;
                }
                Ok(())
            })?;
            ctx.vault.store.notify_attempt_observers();
        }
    }
    Ok(DreamerAttemptExecution::Completed {
        completed_units: 0,
        step_hashes: Vec::new(),
    })
}

/// Continuous: the sieve reads what landed and a due window goes to the
/// projector, through the turn producer's own door. A turn that came in by
/// no turn door (one sync applied, say) is read here. The sieve then reads
/// on while this pass has time; what is left waits for the next wake. A
/// stopped or deferred wake keeps its input and reports Park or Deferred,
/// so the trigger is never lost.
fn continuous(
    ctx: &WakeAttemptContext<'_>,
    attempt: &DreamerAdmittedAttempt,
    trigger: &WakePolicyTrigger,
    now: u64,
) -> Result<Option<DreamerAttemptExecution>> {
    let vault = ctx.vault;
    if !wake_policy_input_covers(vault, trigger)? {
        return Ok(None);
    }
    let stop = WakeStop::new(ctx.cancel);
    // The receipt's queue time is its attempt row's creation, in seconds.
    let on_stale =
        if now.saturating_sub(attempt.status.attempt.created_at) >= READ_PHASE_STARVATION_SECS {
            OnStale::OneWriter
        } else {
            OnStale::Defer
        };
    match vault.wake_dreamer_on_turn_until(WakeTurnSubject::Vault, now, stop, on_stale)? {
        ReadWrite::Written(_) => {}
        ReadWrite::Stopped => {
            let (reason, cause) = if ctx.cancel.is_some_and(WakeCancellation::is_paused) {
                (
                    DREAMER_PAUSED_PARK_REASON.to_owned(),
                    DreamerParkCause::Paused,
                )
            } else {
                (
                    DREAMER_CANCELLED_PARK_REASON.to_owned(),
                    DreamerParkCause::Cancelled,
                )
            };
            return Ok(Some(DreamerAttemptExecution::Park { reason, cause }));
        }
        ReadWrite::Deferred => {
            return Ok(Some(DreamerAttemptExecution::Deferred {
                completed_units: 0,
                retry_at: now.saturating_add(1),
                step_hashes: Vec::new(),
            }));
        }
    }
    while !ctx.deadline.expired()
        && matches!(
            vault.sieve_pass_until(now, stop, OnStale::Defer, false)?,
            ReadWrite::Written(commit) if commit.pass.more
        )
    {}
    vault.with_write_txn_grouped(|txn| {
        if take_wake_recipe_input_in_txn(vault, txn, trigger)?.is_some() {
            let policy = super::recipes::policy_in_txn(vault, txn)?;
            let store = DreamerRunnerStore::new(vault);
            for span in super::sieve::recipe_spans_in_txn(
                vault,
                txn,
                policy.continuous_rung_spans as usize,
            )? {
                if !span.owed.is_empty() {
                    super::sieve::enqueue_rungs_in_txn(
                        &store,
                        txn,
                        &attempt.status,
                        &span,
                        false,
                        now,
                    )?;
                }
            }
            vault.enqueue_live_health_review_in_txn(txn, &attempt.status.attempt, now)?;
        }
        Ok(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(None)
}

/// Nightly: the cadence wake registers the Timer wake's maintenance (the
/// vault cleanup pass, the Coach's nightly jobs, the Dreamer's curator,
/// harness audit, NOTE review and each resident's own dreaming) as this receipt's children on its run tree, in the commit
/// that takes its input. They run on the elected home's next Timer pass.
fn nightly(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    trigger: &WakePolicyTrigger,
    now: u64,
) -> Result<()> {
    let parent = attempt.status.attempt.id;
    let run_id = attempt.status.attempt.run_id.clone();
    let key = format!("nightly:{}", bytes_to_hex_lower(parent.as_bytes()));
    let store = DreamerRunnerStore::new(vault);
    // Each resident's own dreaming (OF-490), read before the commit opens.
    let residents = vault.dreaming_residents()?;
    let taken = vault.with_write_txn_grouped(|txn| {
        if take_wake_recipe_input_in_txn(vault, txn, trigger)?.is_none() {
            return Ok(false);
        }
        super::nightly::children_in_txn(vault, txn, attempt, now)?;
        super::nightly::schedule_remainder_in_txn(vault, txn, attempt, now)?;
        super::arc_backstop::enqueue_stale_arcs_in_txn(
            vault,
            txn,
            Some(parent),
            run_id.as_deref(),
            now,
        )?;
        store.enqueue_vault_cleanup_in_txn(
            txn,
            EnqueueDreamerVaultCleanupAttempt {
                trigger: WakeTrigger::Timer,
                input: Value::Nil,
                parent_attempt: Some(parent),
                dedupe_key: Some(key.clone()),
                run_id: run_id.clone(),
                now,
            },
        )?;
        store.enqueue_consolidation_strength_in_txn(txn, parent, run_id.clone(), now)?;
        store.enqueue_coach_retrieval_tune_in_txn(
            txn,
            Some(parent),
            Some(&key),
            run_id.clone(),
            now,
        )?;
        store.enqueue_honesty_audits_in_txn(txn, Some(parent), Some(&key), run_id.clone(), now)?;
        store.enqueue_coach_nightly_in_txn(txn, Some(parent), Some(&key), run_id.clone(), now)?;
        store.enqueue_dreamer_nightly_in_txn(txn, Some(parent), Some(&key), run_id.clone(), now)?;
        store.enqueue_note_review_in_txn(txn, Some(parent), Some(&key), run_id.clone(), now)?;
        for resident in &residents {
            // A resident whose free-time cycle opened at the boundary now
            // falls after dreams as that cycle's own-time item instead (FIX
            // 4453, FIX 5662); a cycle that did not open leaves its nightly
            // dreaming in place, as for every resident without a policy.
            if crate::dreamer_runner::free_time_owns_reflection_in_txn(vault, txn, *resident, now)?
            {
                continue;
            }
            store.enqueue_resident_dream_in_txn(
                txn,
                *resident,
                Some(parent),
                Some(&key),
                run_id.clone(),
                now,
            )?;
        }
        Ok(true)
    })?;
    if taken {
        vault.store.notify_attempt_observers();
    }
    Ok(())
}
