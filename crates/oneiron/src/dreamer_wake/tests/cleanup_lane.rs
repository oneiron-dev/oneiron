use super::*;
use crate::vault_cleanup::{CleanupPosture, cleanup_proposals, set_cleanup_posture};

fn timer_input(node: u64) -> RunWakePass {
    let mut input = run_input(DreamerConsolidationScope::Macro, node, 20);
    input.trigger = WakeTrigger::Timer;
    input
}

fn request_timer(vault: &Vault, store: &DreamerRunnerStore<'_>) -> Result<AttemptId> {
    request_wake(
        store,
        WakeTrigger::Timer,
        DreamerConsolidationScope::Macro,
        DreamerAttemptPayload {
            attempt_type: "timer".to_owned(),
            input: Value::Nil,
            parent_attempt: None,
        },
        Some("cleanup-lane-test".to_owned()),
        None,
        10,
    )?;
    let queued = AttemptQueue::new(vault).list()?;
    Ok(queued
        .into_iter()
        .find(|row| row.kind == crate::dreamer_runner::DREAMER_VAULT_CLEANUP_ATTEMPT_KIND)
        .expect("timer enqueued cleanup")
        .id)
}

#[test]
fn timer_driver_executes_cleanup_without_a_consolidation_home_node_and_settles() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let summary = EntityId::now();
    vault.put_entity(
        &summary,
        crate::registry::ENTITY_TYPE_SUMMARY,
        occurred(1),
        1,
        b"summary",
    )?;
    let cleanup = request_timer(&vault, &store)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, "cleanup", frozen_deadline(0, 180_000));
    let mut executor = CompletingExecutor {
        completed_units: 50,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        timer_input(node),
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    assert_eq!(
        executor.executed, 0,
        "cleanup is an engine job, not consolidation input"
    );
    assert_eq!(
        store
            .status(cleanup)?
            .expect("regression fixture")
            .attempt
            .state,
        AttemptState::Completed
    );
    assert_eq!(cleanup_proposals(&vault)?.len(), 1);
    assert!(!vault.is_deleted_shell(&summary)?);
    let budget = store.budget("cleanup")?.expect("regression fixture");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000);
    assert!(store.budget_reservation("cleanup", cleanup)?.is_none());
    Ok(())
}

#[test]
fn cleanup_failure_parks_and_refunds_without_leaving_partial_proposals() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let id = EntityId::now();
    vault.put_entity(
        &id,
        crate::registry::ENTITY_TYPE_SUMMARY,
        occurred(1),
        1,
        b"summary",
    )?;
    vault.with_write_txn(|txn| {
        vault
            .store
            .entities
            .put(txn, id.as_bytes(), b"bad header")?;
        Ok(())
    })?;
    let cleanup = request_timer(&vault, &store)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, "cleanup", frozen_deadline(0, 180_000));
    let mut executor = CompletingExecutor {
        completed_units: 50,
        executed: 0,
    };
    assert!(
        block_on_ready(driver.run_wake_pass(
            timer_input(node),
            &mut executor,
            &WakeCancellation::new()
        ))
        .is_err()
    );
    assert!(store.parked_attempt(cleanup)?.is_some());
    assert_eq!(
        store
            .budget("cleanup")?
            .expect("regression fixture")
            .reserved_units,
        0
    );
    assert_eq!(
        store
            .budget("cleanup")?
            .expect("regression fixture")
            .remaining_units,
        10_000
    );
    assert!(store.budget_reservation("cleanup", cleanup)?.is_none());
    assert!(cleanup_proposals(&vault)?.is_empty());
    assert_eq!(executor.executed, 0);
    Ok(())
}

#[test]
fn cleanup_obeys_cancellation_and_budget_denial_before_dispatch() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let cleanup = request_timer(&vault, &store)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, "cleanup", frozen_deadline(0, 180_000));
    let mut executor = CompletingExecutor {
        completed_units: 50,
        executed: 0,
    };
    let cancel = WakeCancellation::new();
    cancel.cancel();
    assert_eq!(
        block_on_ready(driver.run_wake_pass(timer_input(node), &mut executor, &cancel))?.stop,
        WakePassStop::Cancelled
    );
    let mut input = timer_input(node);
    input.budget_total_units = 1;
    assert_eq!(
        block_on_ready(driver.run_wake_pass(input, &mut executor, &WakeCancellation::new()))?.stop,
        WakePassStop::BudgetExhausted
    );
    assert_eq!(
        store
            .status(cleanup)?
            .expect("regression fixture")
            .attempt
            .state,
        AttemptState::Queued
    );
    assert!(cleanup_proposals(&vault)?.is_empty());
    assert!(set_cleanup_posture(&vault, CleanupPosture::AutoWithDigest).is_err());
    Ok(())
}

#[test]
fn cleanup_dispatch_waits_for_timer_macro_and_respects_the_deadline() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let cleanup = request_timer(&vault, &store)?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let mut executor = CompletingExecutor {
        completed_units: 50,
        executed: 0,
    };
    let cancel = WakeCancellation::new();
    let mut driver = DreamerWakeDriver::new(&vault, "cleanup", frozen_deadline(0, 180_000));
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Macro, node, 20),
        &mut executor,
        &cancel,
    ))?;
    assert_eq!(
        store
            .status(cleanup)?
            .expect("cleanup attempt")
            .attempt
            .state,
        AttemptState::Queued
    );
    let mut driver = DreamerWakeDriver::new(&vault, "cleanup", frozen_deadline(180_000, 180_000));
    let report = block_on_ready(driver.run_wake_pass(timer_input(node), &mut executor, &cancel))?;
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    assert_eq!(
        store
            .status(cleanup)?
            .expect("cleanup attempt")
            .attempt
            .state,
        AttemptState::Queued
    );
    assert!(store.budget_reservation("cleanup", cleanup)?.is_none());
    assert!(cleanup_proposals(&vault)?.is_empty());
    assert_eq!(executor.executed, 0);
    Ok(())
}
