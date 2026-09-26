use super::*;
use crate::attempt_queue::AttemptQueue;
use crate::claim::{ClaimApprovalStatus, ClaimSubject};
use crate::config::VaultConfig;
use crate::dreamer_runner::DreamerConsolidationScope;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EdgeActorClass, EntityId};
use rmpv::Value;

fn open() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}
fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}
fn claim(vault: &Vault, source: ClaimSource, at_time: u64) -> Result<()> {
    claims(vault, source, 1, at_time)
}
fn claims(vault: &Vault, source: ClaimSource, count: usize, at_time: u64) -> Result<()> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, at(at_time), at_time, b"actor")?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        at(at_time),
        at_time,
        b"subject",
    )?;
    let author = WriteActor::new(
        actor,
        if source == ClaimSource::Generated {
            EdgeActorClass::Agent
        } else {
            EdgeActorClass::Human
        },
    );
    let envelope = WriteEnvelope::new(
        author,
        source,
        WriteProvenance::new(Value::from("wake-policy-batch-fixture"))?,
        if source == ClaimSource::Generated {
            ClaimApprovalStatus::Proposed
        } else {
            ClaimApprovalStatus::Approved
        },
    );
    let mut batch = vault.batch();
    for index in 0..count {
        batch = batch.claim_candidate(
            &EntityId::now(),
            ClaimCandidate::new(
                "profile.preference",
                ClaimSubject::Entity(subject),
                Value::from(format!("value-{index}")),
                0.9,
            ),
            &envelope,
            at(at_time),
            at_time,
        );
    }
    batch.commit()?;
    Ok(())
}
fn idle(last: u64) -> WakeIdleState {
    WakeIdleState {
        running_turns: false,
        live_background_work: false,
        compute_available: true,
        last_inbound_at: last,
    }
}
fn row(vault: &Vault, row: DreamerWakePolicy) -> Result<()> {
    row.validate()?;
    let mut txn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut txn, POLICY_KEY, &serde_json::to_vec(&row).unwrap())?;
    txn.commit()?;
    Ok(())
}
fn v3() -> DreamerWakePolicy {
    DreamerWakePolicy {
        wake_grain_turns: 1,
        new_records: 50,
        longest_wait_secs: 8 * 3600,
        nightly_secs: 24 * 3600,
        idle_secs: 3600,
    }
}

#[test]
fn explicit_threshold_and_generated_only_growth() -> Result<()> {
    let (_dir, vault) = open();
    row(&vault, v3())?;
    // The non-Generated source is what counts, never actor/subject scaffolding.
    claims(&vault, ClaimSource::UserStated, 49, 10)?;
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(0), 3601)?,
        WakePolicyDecision::ArmIdle {
            due_at: 10 + 8 * 3600
        }
    );
    claims(&vault, ClaimSource::Generated, 60, 11)?;
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3601)?.decision,
        WakePolicyDecision::ArmIdle {
            due_at: 10 + 8 * 3600
        }
    );
    assert!(AttemptQueue::new(&vault).list()?.is_empty());
    claim(&vault, ClaimSource::Observed, 12)?;
    let outcome = vault.enqueue_due_dreamer_wake(idle(0), 3601)?;
    assert_eq!(
        outcome.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave
        }
    );
    assert!(outcome.attempt.is_some());
    assert!(
        vault
            .enqueue_due_dreamer_wake(idle(0), 3601)?
            .attempt
            .is_none(),
        "same rows never wake twice"
    );
    claims(&vault, ClaimSource::Generated, 50, 3602)?;
    let only_generated = vault.enqueue_due_dreamer_wake(idle(0), 3603)?;
    assert!(
        only_generated.attempt.is_none(),
        "Generated growth cannot enqueue a wake"
    );
    // A pre-existing Nightly input may still have a one-shot due time; the
    // Generated rows did not add to it.
    assert_eq!(
        only_generated.decision,
        WakePolicyDecision::ArmIdle {
            due_at: 10 + 24 * 3600
        }
    );
    Ok(())
}

#[test]
fn quiet_window_cancels_on_inbound_or_running_work_and_longest_wait_fires() -> Result<()> {
    let (_dir, vault) = open();
    row(&vault, v3())?;
    claim(&vault, ClaimSource::UserStated, 1)?;
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(100), 3699)?,
        WakePolicyDecision::ArmIdle { due_at: 3700 }
    );
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(3699), 3700)?.decision,
        WakePolicyDecision::ArmIdle { due_at: 7299 }
    );
    assert_eq!(
        vault.evaluate_dreamer_wake(
            WakeIdleState {
                running_turns: true,
                ..idle(0)
            },
            9000
        )?,
        WakePolicyDecision::Silent
    );
    assert_eq!(
        vault.evaluate_dreamer_wake(
            WakeIdleState {
                live_background_work: true,
                ..idle(0)
            },
            9000
        )?,
        WakePolicyDecision::Silent
    );
    // Bootstrap with less than 50 records waits until the first configured
    // longest-wait boundary; one timed wake establishes its durable baseline.
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3601)?.decision,
        WakePolicyDecision::ArmIdle {
            due_at: 1 + 8 * 3600
        }
    );
    // A default row sees a user TURN as one-per-turn once quiet.
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("spkr"), Value::from("user"))]),
    )
    .unwrap();
    vault.put_entity(&EntityId::now(), ENTITY_TYPE_TURN, at(3602), 3602, &body)?;
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3603)?.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Continuous
        }
    );
    claim(&vault, ClaimSource::Observed, 3604)?;
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(0), 1 + 8 * 3600 - 1)?,
        WakePolicyDecision::ArmIdle {
            due_at: 1 + 8 * 3600
        }
    );
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(0), 1 + 8 * 3600)?,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave
        }
    );
    Ok(())
}

#[test]
fn bad_policy_rows_fail_closed() -> Result<()> {
    let (_dir, vault) = open();
    row(&vault, v3())?;
    let mut txn = vault.store.env.write_txn()?;
    vault
        .store
        .vault_meta
        .put(&mut txn, POLICY_KEY, b"{\"idle_secs\":0}")?;
    txn.commit()?;
    assert!(vault.evaluate_dreamer_wake(idle(0), 100).is_err());
    Ok(())
}

#[test]
fn authenticated_owner_writes_policy_and_foreign_proof_cannot() -> Result<()> {
    let (_dir, vault) = open();
    let (_other_dir, other) = open();
    let actor = EntityId::now();
    other.put_entity(&actor, ENTITY_TYPE_PERSON, at(1), 1, b"owner")?;
    let proof = other.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    let policy = v3();
    assert_eq!(
        vault
            .set_dreamer_wake_policy(&proof, policy)
            .unwrap_err()
            .kind(),
        crate::ErrorKind::ConsentOwnerNotAuthenticated
    );
    other.set_dreamer_wake_policy(&proof, policy)?;
    assert_eq!(other.dreamer_wake_policy()?, policy);
    assert_eq!(vault.dreamer_wake_policy()?.wake_grain_turns, 1);
    Ok(())
}

struct NoPartitionExecutor;
impl crate::dreamer_wake::DreamerAttemptExecutor for NoPartitionExecutor {
    async fn execute(
        &mut self,
        _attempt: &crate::dreamer_runner::DreamerAdmittedAttempt,
        _ctx: &mut crate::dreamer_wake::WakeAttemptContext<'_>,
    ) -> Result<crate::dreamer_wake::DreamerAttemptExecution> {
        panic!("policy receipt must not reach consolidation partition decoder");
    }
}
#[test]
fn policy_wake_is_executable_and_completes_in_the_production_driver() -> Result<()> {
    let (_dir, vault) = open();
    let mut config = v3();
    config.new_records = 1;
    let owner = EntityId::now();
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, at(1), 1, b"owner")?;
    let proof = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )?;
    vault.set_dreamer_wake_policy(&proof, config)?;
    assert_eq!(vault.dreamer_wake_policy()?, config);
    claim(&vault, ClaimSource::UserStated, 10)?;
    let outcome = vault.enqueue_due_dreamer_wake(idle(0), 3601)?;
    assert!(outcome.attempt.is_some());
    let mut driver = crate::dreamer_wake::DreamerWakeDriver::new(
        &vault,
        "policy-wake",
        crate::dreamer_wake::WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let report = crate::dreamer_wake::block_on_ready(driver.run_wake_pass(
        crate::dreamer_wake::RunWakePass {
            trigger: crate::dreamer_wake::WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "policy-test".into(),
            budget_total_units: 1_000,
            reserve_units: 10,
            now: 3601,
        },
        &mut NoPartitionExecutor,
        &crate::dreamer_wake::WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 1);
    let inputs = vault.dreamer_wake_recipe_inputs()?;
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].recipe, WakeRecipe::Weave);
    assert_eq!(inputs[0].record_count, 1);
    assert_eq!(inputs[0].after_record, None);
    assert_eq!(
        AttemptQueue::new(&vault).list()?[0].state,
        crate::attempt_queue::AttemptState::Completed
    );
    Ok(())
}

#[test]
fn missing_recipe_input_cannot_complete_dispatch_receipt() -> Result<()> {
    let (_dir, vault) = open();
    let mut policy = v3();
    policy.new_records = 1;
    row(&vault, policy)?;
    claim(&vault, ClaimSource::UserStated, 1)?;
    assert!(
        vault
            .enqueue_due_dreamer_wake(idle(0), 3601)?
            .attempt
            .is_some()
    );
    vault.with_write_txn(|txn| {
        vault
            .store
            .vault_meta
            .delete(txn, &[OUTBOX_PREFIX, &[WakeRecipe::Weave.key()]].concat())?;
        Ok(())
    })?;
    let mut driver = crate::dreamer_wake::DreamerWakeDriver::new(
        &vault,
        "policy-missing-input",
        crate::dreamer_wake::WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    let result = crate::dreamer_wake::block_on_ready(driver.run_wake_pass(
        crate::dreamer_wake::RunWakePass {
            trigger: crate::dreamer_wake::WakeTrigger::Event,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 1,
            lease_owner: "policy-missing-input".into(),
            budget_total_units: 1_000,
            reserve_units: 10,
            now: 3601,
        },
        &mut NoPartitionExecutor,
        &crate::dreamer_wake::WakeCancellation::new(),
    ));
    assert!(result.is_err(), "a lost recipe handoff cannot complete");
    let row = AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .next()
        .expect("dispatch attempt");
    assert_ne!(row.state, crate::attempt_queue::AttemptState::Completed);
    assert!(
        DreamerRunnerStore::new(&vault)
            .parked_attempt(row.id)?
            .is_some()
    );
    Ok(())
}

#[test]
fn late_replayed_explicit_row_after_wake_is_not_lost_by_learned_at() -> Result<()> {
    let (_dir, vault) = open();
    let mut config = v3();
    config.new_records = 1;
    row(&vault, config)?;
    claim(&vault, ClaimSource::UserStated, 10)?;
    assert!(
        vault
            .enqueue_due_dreamer_wake(idle(0), 3601)?
            .attempt
            .is_some()
    );
    // The second record arrives AFTER the first wake, but carries an older
    // learned_at. The mutation cursor follows commit order, not that stamp.
    claim(&vault, ClaimSource::UserStated, 5)?;
    assert!(
        vault
            .enqueue_due_dreamer_wake(idle(0), 3602)?
            .attempt
            .is_some()
    );
    assert!(
        vault
            .enqueue_due_dreamer_wake(idle(0), 3602)?
            .attempt
            .is_none()
    );
    let pending = vault.dreamer_wake_recipe_inputs()?;
    assert_eq!(
        pending.len(),
        1,
        "repeat Weave wakes merge into one durable input"
    );
    assert_eq!(pending[0].record_count, 2);
    assert_eq!(pending[0].after_record, None);
    Ok(())
}

#[test]
fn continuous_wake_does_not_consume_pending_weave_records() -> Result<()> {
    let (_dir, vault) = open();
    row(&vault, v3())?;
    claims(&vault, ClaimSource::UserStated, 48, 1)?;
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(vec![("spkr".into(), "user".into())]))
        .unwrap();
    vault.put_entity(&EntityId::now(), ENTITY_TYPE_TURN, at(2), 2, &body)?;
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3601)?.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Continuous
        }
    );
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(0), 3602)?,
        WakePolicyDecision::ArmIdle {
            due_at: 1 + 8 * 3600
        }
    );
    claim(&vault, ClaimSource::UserStated, 3)?;
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3602)?.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Weave
        }
    );
    Ok(())
}

#[test]
fn nightly_recipe_is_a_separate_row_dial() -> Result<()> {
    let (_dir, vault) = open();
    row(
        &vault,
        DreamerWakePolicy {
            wake_grain_turns: 100,
            new_records: 100,
            longest_wait_secs: 2 * 86_400,
            nightly_secs: 3_600,
            idle_secs: 60,
        },
    )?;
    claim(&vault, ClaimSource::UserStated, 1)?;
    assert_eq!(
        vault.evaluate_dreamer_wake(idle(0), 3_600)?,
        WakePolicyDecision::ArmIdle { due_at: 3_601 }
    );
    assert_eq!(
        vault.enqueue_due_dreamer_wake(idle(0), 3_601)?.decision,
        WakePolicyDecision::Enqueue {
            recipe: WakeRecipe::Nightly
        }
    );
    assert_eq!(
        vault.dreamer_wake_recipe_inputs()?[0].recipe,
        WakeRecipe::Nightly
    );
    Ok(())
}

#[test]
fn repeated_continuous_receipts_do_not_double_count_pending_weave_or_nightly() -> Result<()> {
    let (_dir, vault) = open();
    let mut policy = v3();
    policy.new_records = 100;
    row(&vault, policy)?;
    claim(&vault, ClaimSource::UserStated, 1)?;
    for (at_time, now) in [(2, 3601), (3, 3602)] {
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &Value::Map(vec![("spkr".into(), "user".into())]))
            .unwrap();
        vault.put_entity(
            &EntityId::now(),
            ENTITY_TYPE_TURN,
            at(at_time),
            at_time,
            &body,
        )?;
        assert_eq!(
            vault.enqueue_due_dreamer_wake(idle(0), now)?.decision,
            WakePolicyDecision::Enqueue {
                recipe: WakeRecipe::Continuous
            }
        );
    }
    let pending = vault.dreamer_wake_recipe_inputs()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].turn_count, 2);
    assert_eq!(
        pending[0].record_count, 3,
        "claim plus two user turns, not cumulative double count"
    );
    assert_eq!(pending[0].nightly_count, 3);
    Ok(())
}

#[test]
fn zero_compute_suspends_even_with_due_explicit_input() -> Result<()> {
    let (_dir, vault) = open();
    let mut policy = v3();
    policy.new_records = 1;
    row(&vault, policy)?;
    claim(&vault, ClaimSource::UserStated, 1)?;
    let no_compute = WakeIdleState {
        compute_available: false,
        ..idle(0)
    };
    assert_eq!(
        vault.evaluate_dreamer_wake(no_compute, 3601)?,
        WakePolicyDecision::Silent
    );
    assert!(
        vault
            .enqueue_due_dreamer_wake(no_compute, 3601)?
            .attempt
            .is_none()
    );
    assert!(vault.dreamer_wake_recipe_inputs()?.is_empty());
    Ok(())
}
