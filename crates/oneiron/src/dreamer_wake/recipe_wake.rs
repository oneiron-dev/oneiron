//! The wake policy's recipe lane (ARCH-0026 #wake). Each receipt runs its
//! recipe's body over the input row the policy outbox holds for it, and the
//! input leaves the outbox in the commit that does the recipe's work.

use rmpv::Value;

use crate::Vault;
use crate::dreamer_runner::{
    DREAMER_RECIPE_WAKE_ATTEMPT_KIND, DreamerAdmittedAttempt, DreamerRunnerStore,
    EnqueueDreamerVaultCleanupAttempt,
};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::policy::{
    WakePolicyTrigger, WakeRecipe, take_wake_recipe_input_in_txn, wake_policy_input_covers,
};
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
        WakeRecipe::Continuous => continuous(ctx, attempt, &trigger, now)?,
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
    Ok(DreamerAttemptExecution::Completed { completed_units: 0 })
}

/// Continuous: the sieve reads what landed and a due window goes to the
/// projector, through the turn producer's own door. A turn that came in by
/// no turn door (one sync applied, say) is read here. The sieve then reads
/// on while this pass has time; what is left waits for the next wake.
fn continuous(
    ctx: &WakeAttemptContext<'_>,
    attempt: &DreamerAdmittedAttempt,
    trigger: &WakePolicyTrigger,
    now: u64,
) -> Result<()> {
    let vault = ctx.vault;
    if !wake_policy_input_covers(vault, trigger)? {
        return Ok(());
    }
    vault.wake_dreamer_on_turn(WakeTurnSubject::Vault, now)?;
    while !ctx.deadline.expired() && vault.sieve_pass(now)?.more {}
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
                    super::sieve::enqueue_rungs_in_txn(&store, txn, attempt, &span, false, now)?;
                }
            }
        }
        Ok(())
    })?;
    vault.store.notify_attempt_observers();
    Ok(())
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
