//! The Coach's nightly retrieval tune (owner ruling 2026-10-16): a Timer wake
//! runs it on the Dreamer's runner under the Coach's stamp.
use super::*;

#[test]
fn timer_wake_runs_the_coach_retrieval_tune_under_the_coach_stamp() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    request_wake(
        &store,
        WakeTrigger::Timer,
        DreamerConsolidationScope::Macro,
        DreamerAttemptPayload {
            attempt_type: "timer".to_owned(),
            input: Value::Nil,
            parent_attempt: None,
        },
        Some("coach-tune-test".to_owned()),
        None,
        10,
    )?;
    let mut tunes = Vec::new();
    for row in AttemptQueue::new(&vault).list()? {
        if store
            .status(row.id)?
            .is_some_and(|status| status.payload.attempt_type == "coach.retrieval_tune")
        {
            tunes.push(row.id);
        }
    }
    let [tune] = tunes[..] else {
        panic!("a Timer wake enqueues one Coach retrieval tune, found {tunes:?}");
    };
    let coach = crate::codebase::entity_id_from_hash_material(b"oneiron.coach.authority.v1", &[])?;
    assert_eq!(
        vault
            .dreamer_attempt_authority(tune)?
            .expect("stamped at enqueue")
            .actor,
        coach
    );

    let blend = vault.store.retrieval_blend_weight_table()?;
    let node = crate::identity::load_or_mint_client_id(&vault)?;
    let mut input = run_input(DreamerConsolidationScope::Macro, node, 20);
    input.trigger = WakeTrigger::Timer;
    let mut driver = DreamerWakeDriver::new(&vault, "coach", frozen_deadline(0, 180_000));
    let mut executor = CompletingExecutor {
        completed_units: 50,
        executed: 0,
    };
    block_on_ready(driver.run_wake_pass(input, &mut executor, &WakeCancellation::new()))?;
    assert_eq!(
        store.status(tune)?.expect("tune row").attempt.state,
        AttemptState::Completed,
        "too few gated rewards is a quiet night, not a failure"
    );
    assert_eq!(vault.store.retrieval_blend_weight_table()?, blend);
    Ok(())
}
