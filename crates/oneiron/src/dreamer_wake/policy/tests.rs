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
    POLICY.put(&vault.store, &mut txn, &(), &row)?;
    txn.commit()?;
    Ok(())
}
fn v3() -> DreamerWakePolicy {
    DreamerWakePolicy {
        wake_grain_turns: 1,
        agent_cadence: serde_json::from_str::<DreamerWakePolicy>(DEFAULT_POLICY)
            .expect("shipped wake policy")
            .agent_cadence,
        new_records: 50,
        longest_wait_secs: 8 * 3600,
        nightly_secs: 24 * 3600,
        idle_secs: 60,
        quiet_weave_secs: 3600,
        weave_recipe_priority: crate::dreamer_wake::WeaveRecipePriority::BeforeConnectorEvent,
    }
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
        OUTBOX.delete(&vault.store, txn, &[WakeRecipe::Weave.key()])?;
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
            host_scope: None,
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
