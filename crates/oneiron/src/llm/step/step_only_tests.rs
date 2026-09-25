//! STEP-ONLY waits reuse C9 while leaving the queue and run-tree runnable.

use super::step_only::{consume_step_wait_in_txn, open_step_wait_in_txn, signal_step_wait_in_txn};
use super::trap::{
    EncodedTrapClaim, encode_trap_claim_value, envelope_from_claim_body, open_trap_in_txn,
    trap_head,
};
use super::trap_binding::TrapBindingScope;
use super::{
    DREAMER_TRAP_PREDICATE, DreamerTrapKind, DreamerTrapState, DurableStepContext, TrapRef,
    consume_trap_signal, open_trap, register_wait, send_trap_signal,
};
use crate::Vault;
use crate::attempt_queue::{AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome};
use crate::claim::ClaimSubject;
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use crate::write_envelope::{ClaimCandidate, WriteActor};

fn fixture(vault: &Vault) -> Result<DurableStepContext<'_>> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 10, end: 10 },
        10,
        b"actor",
    )?;
    let status = match DreamerRunnerStore::new(vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "step-only-test".into(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some("step-only-run".into()),
        now: 10,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    Ok(DurableStepContext {
        vault,
        attempt_id: status.attempt.id,
        run_id: status.attempt.run_id,
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject: actor,
        deadline: None,
        now_ms: 10_000,
    })
}

#[test]
fn signal_before_wait_is_visible_in_the_same_transaction() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let trap = vault.with_write_txn(|wtxn| {
        let trap = open_step_wait_in_txn(&vault, wtxn, &ctx, [1; 32])?;
        // The TASK answer may land before the first tasks.wait observation.
        signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001)?;
        signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001)?;
        assert!(consume_step_wait_in_txn(&vault, wtxn, &trap, 10_002)?);
        assert!(!consume_step_wait_in_txn(&vault, wtxn, &trap, 10_003)?);
        signal_step_wait_in_txn(&vault, wtxn, &trap, 10_004)?;
        Ok(trap)
    })?;
    assert_eq!(
        trap_head(&vault, &trap.trap_claim_id)?.1.state,
        DreamerTrapState::Consumed
    );
    assert!(!vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 10_005))?);
    Ok(())
}

#[test]
fn wait_before_signal_keeps_the_attempt_runnable() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let runner = DreamerRunnerStore::new(&vault);
    let before = runner.status(ctx.attempt_id)?.expect("attempt");
    let run_before = runner.run_tree(ctx.attempt_id)?;
    let trap = vault.with_write_txn(|wtxn| open_step_wait_in_txn(&vault, wtxn, &ctx, [2; 32]))?;
    assert!(!vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 10_001))?);
    assert_eq!(runner.status(ctx.attempt_id)?.expect("attempt"), before);
    assert_eq!(runner.run_tree(ctx.attempt_id)?, run_before);
    assert!(runner.parked_attempt(ctx.attempt_id)?.is_none());
    let claimed = AttemptQueue::new(&vault).claim(ClaimAttempt {
        lease_owner: "step-only-worker".into(),
        now: 11,
    })?;
    let ClaimOutcome::Claimed(claimed) = claimed else {
        panic!("attempt remains claimable")
    };
    assert_eq!(claimed.id, ctx.attempt_id);
    assert_eq!(claimed.state, AttemptState::Leased);
    vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &trap, 12_000))?;
    assert!(vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 12_001))?);
    assert_eq!(
        runner.status(ctx.attempt_id)?.expect("attempt").attempt,
        claimed
    );
    assert_eq!(runner.run_tree(ctx.attempt_id)?, run_before);
    assert!(runner.parked_attempt(ctx.attempt_id)?.is_none());
    Ok(())
}

#[test]
fn concurrent_consumers_observe_exactly_one_transition() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let trap = vault.with_write_txn(|wtxn| {
        let trap = open_step_wait_in_txn(&vault, wtxn, &ctx, [3; 32])?;
        signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001)?;
        Ok(trap)
    })?;
    let results = std::thread::scope(|scope| {
        let consume =
            || vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 10_002));
        let first = scope.spawn(consume);
        let second = scope.spawn(consume);
        [
            first.join().expect("first consumer"),
            second.join().expect("second consumer"),
        ]
    });
    let [first, second] = results;
    assert_ne!(first?, second?);
    Ok(())
}

#[test]
fn step_wait_rejects_forged_hash_and_attempt() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let other = fixture(&vault)?;
    let trap = vault.with_write_txn(|wtxn| open_step_wait_in_txn(&vault, wtxn, &ctx, [4; 32]))?;
    let bad_hash = TrapRef {
        step_hash: [5; 32],
        ..trap
    };
    let bad_kind = TrapRef {
        kind: DreamerTrapKind::Consent,
        ..trap
    };
    for invalid in [bad_hash, bad_kind] {
        assert!(matches!(
            vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &invalid, 10_001)),
            Err(Error::InvalidClaimBody(_))
        ));
        assert!(matches!(
            vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &invalid, 10_001)),
            Err(Error::InvalidClaimBody(_))
        ));
    }
    let (head_id, _) = trap_head(&vault, &trap.trap_claim_id)?;
    let body = vault.get_claim(&head_id)?.expect("head");
    let envelope = envelope_from_claim_body(&body)?;
    let forged = EntityId::now();
    vault.with_write_txn(|wtxn| {
        let candidate = ClaimCandidate::new(
            DREAMER_TRAP_PREDICATE,
            ClaimSubject::Entity(ctx.subject),
            encode_trap_claim_value(&EncodedTrapClaim {
                kind: trap.kind,
                attempt_id: other.attempt_id,
                step_hash: trap.step_hash,
                state: DreamerTrapState::Sent,
                at: 10_001,
                note: String::new(),
            }),
            1.0,
        );
        vault
            .batch_in()
            .claim_candidate(
                &forged,
                candidate,
                &envelope,
                TimeRange {
                    start: 10_001,
                    end: 10_001,
                },
                10_001,
            )
            .apply(wtxn)?;
        vault.supersede_claim_in_txn(wtxn, &forged, &head_id, 10_001)
    })?;
    assert!(matches!(
        vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &trap, 10_002)),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(matches!(
        vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 10_002)),
        Err(Error::InvalidClaimBody(_))
    ));
    assert_eq!(
        trap_head(&vault, &trap.trap_claim_id)?.1.state,
        DreamerTrapState::Sent
    );
    Ok(())
}

#[test]
fn step_only_and_attempt_scoped_doors_cannot_cross() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let runner = DreamerRunnerStore::new(&vault);
    let trap = vault.with_write_txn(|wtxn| open_step_wait_in_txn(&vault, wtxn, &ctx, [6; 32]))?;
    assert!(matches!(
        send_trap_signal(&vault, &trap.trap_claim_id, trap.step_hash, 10_001),
        Err(Error::InvalidClaimBody(_))
    ));
    let waiting_id = trap_head(&vault, &trap.trap_claim_id)?.0;
    assert!(matches!(
        send_trap_signal(&vault, &waiting_id, trap.step_hash, 10_001),
        Err(Error::InvalidClaimBody(_))
    ));
    vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001))?;
    assert!(matches!(
        consume_trap_signal(&vault, &runner, &trap, 10_002),
        Err(Error::InvalidClaimBody(_))
    ));
    // A different wait owner may park the run; consuming this step must not
    // clear, replace, or otherwise touch that owner's row.
    let parked = runner.park_attempt(ParkDreamerAttempt {
        attempt_id: ctx.attempt_id,
        reason: "other wait".into(),
        park_owner: "other-owner".into(),
        now: 11,
    })?;
    assert!(vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 12_000))?);
    assert_eq!(runner.parked_attempt(ctx.attempt_id)?, Some(parked));
    let legacy = open_trap(
        &vault,
        &ctx,
        DreamerTrapKind::HumanResponse,
        [7; 32],
        "legacy",
    )?;
    assert!(matches!(
        vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &legacy, 12_001)),
        Err(Error::InvalidClaimBody(_))
    ));
    assert!(matches!(
        vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &legacy, 12_001)),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}

#[test]
fn created_step_wait_accepts_signal_without_losing_it_to_registration() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    // Exercise C9's second legal ordering directly, before the public open
    // helper's Waiting transition. The normal helper co-commits both states.
    let trap = vault.with_write_txn(|wtxn| {
        let trap = open_trap_in_txn(
            &vault,
            wtxn,
            &ctx,
            DreamerTrapKind::HumanResponse,
            [8; 32],
            "",
            TrapBindingScope::StepOnly,
        )?;
        assert!(!consume_step_wait_in_txn(&vault, wtxn, &trap, 10_001)?);
        signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001)?;
        Ok(trap)
    })?;
    assert_eq!(
        register_wait(&vault, &trap, 10_002)?,
        DreamerTrapState::Sent
    );
    assert!(vault.with_write_txn(|wtxn| consume_step_wait_in_txn(&vault, wtxn, &trap, 10_003))?);
    Ok(())
}

#[test]
fn aborted_step_wait_writes_no_anchor_or_binding() -> Result<()> {
    let (_dir, vault) =
        crate::test_util::open_test_vault_with(crate::config::VaultConfig::device());
    let ctx = fixture(&vault)?;
    let trap = {
        let mut wtxn = vault.store.env.write_txn()?;
        open_step_wait_in_txn(&vault, &mut wtxn, &ctx, [9; 32])?
    };
    assert!(vault.get_claim(&trap.trap_claim_id)?.is_none());
    assert!(matches!(
        vault.with_write_txn(|wtxn| signal_step_wait_in_txn(&vault, wtxn, &trap, 10_001)),
        Err(Error::InvalidClaimBody(_))
    ));
    Ok(())
}
