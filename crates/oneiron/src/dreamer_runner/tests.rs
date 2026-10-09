use crate::attempt_queue::{AttemptState, CleanupAttemptLeases, RetryAttempt, RetryOutcome};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK};
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteProvenance;

use super::*;
use crate::error::ArtifactError;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn enqueue_attempt(
    runner: &DreamerRunnerStore<'_>,
    name: &str,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: name.to_owned(),
        input: Value::from(format!("input:{name}")),
        parent_attempt: None,
        dedupe_key: None,
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
    }
}

fn enqueue_consolidation_attempt(
    runner: &DreamerRunnerStore<'_>,
    scope: DreamerConsolidationScope,
    dedupe_key: Option<&str>,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    match runner.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope,
        input: Value::from(format!("input:{}", scope.as_str())),
        parent_attempt: None,
        dedupe_key: dedupe_key.map(str::to_owned),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
    }
}

fn admit_consolidation(
    runner: &DreamerRunnerStore<'_>,
    scope: DreamerConsolidationScope,
    local_node_id: u64,
    lease_owner: &str,
    now: u64,
) -> Result<DreamerConsolidationAdmissionOutcome> {
    runner.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
        scope,
        local_node_id,
        claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
        claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
        admission: AdmitDreamerAttempt {
            lease_owner: lease_owner.to_owned(),
            now,
            budget_id: format!("wake:{}", scope.as_str()),
            budget_total_units: 10,
            reserve_units: 1,
            started_milestone: None,
        },
    })
}

fn tournament_admission(
    predicate: &str,
    sample_count: u32,
    incumbent_confidence: f32,
    evidence_state: DreamerClaimEvidenceState,
    uncertainty_tau: f32,
    budget_axes: DreamerTournamentBudgetAxes,
) -> DreamerClaimAuthoringAdmission {
    DreamerClaimAuthoringAdmission::Tournament(DreamerTournamentAdmission {
        claim: DreamerTournamentClaim {
            predicate: predicate.to_owned(),
            sample_count,
            incumbent_confidence,
            evidence_state,
        },
        uncertainty_tau,
        budget_axes,
    })
}

fn different_node_id(node_id: u64) -> u64 {
    if node_id == u64::MAX { 1 } else { node_id + 1 }
}

fn test_ready_key(ready_at: u64, id: AttemptId) -> [u8; 24] {
    let mut key = [0_u8; 24];
    key[..8].copy_from_slice(&ready_at.to_be_bytes());
    key[8..].copy_from_slice(id.as_bytes());
    key
}

fn rewrite_ready_key(
    vault: &Vault,
    id: AttemptId,
    from_ready_at: u64,
    to_ready_at: u64,
) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .attempt_ready
        .delete(&mut wtxn, &test_ready_key(from_ready_at, id))?;
    vault
        .store
        .attempt_ready
        .put(&mut wtxn, &test_ready_key(to_ready_at, id), id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

fn attempt_dedupe_points_to(vault: &Vault, id: AttemptId) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    for row in vault.store.attempt_dedupe.iter(&rtxn)? {
        let (_key, value) = row?;
        if *value == *id.as_bytes() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn milestone_fixture(vault: &Vault, claim_id: EntityId, at: u64) -> Result<DreamerMilestoneClaim> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_TASK,
        occurred(at),
        at,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("dreamer-runner-test"))?,
        ClaimApprovalStatus::Approved,
    );
    Ok(DreamerMilestoneClaim {
        claim_id,
        subject,
        kind: DreamerMilestoneKind::Started,
        envelope,
        occurred: occurred(at),
        learned_at: at,
    })
}

#[cfg(feature = "sync")]
fn write_milestone_for_attempt(
    vault: &Vault,
    attempt_id: AttemptId,
    claim_id: EntityId,
    kind: DreamerMilestoneKind,
    at: u64,
) -> Result<()> {
    let mut milestone = milestone_fixture(vault, claim_id, at)?;
    milestone.kind = kind;
    let attempt = AttemptQueue::new(vault)
        .get(attempt_id)?
        .ok_or(Error::EntityNotFound)?;
    let mut wtxn = vault.store.env.write_txn()?;
    apply_milestone_claim_in_txn(vault, &mut wtxn, &attempt, milestone)?;
    wtxn.commit()?;
    Ok(())
}

#[cfg(feature = "sync")]
fn write_dreamer_boundary_claim(
    vault: &Vault,
    claim_id: EntityId,
    predicate: &'static str,
    at: u64,
) -> Result<()> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(at), at, b"actor")?;
    vault.put_entity(
        &subject,
        ENTITY_TYPE_TASK,
        occurred(at),
        at,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(actor, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::from("dreamer-sync-boundary-test"))?,
        ClaimApprovalStatus::Approved,
    );
    let candidate = crate::write_envelope::ClaimCandidate::new(
        predicate,
        ClaimSubject::Entity(subject),
        Value::from(predicate),
        1.0,
    );
    vault
        .batch()
        .claim_candidate(&claim_id, candidate, &envelope, occurred(at), at)
        .commit()
}

#[test]
fn tournament_budget_trap_uses_authoritative_candidate_after_ready_repairs() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queue = AttemptQueue::new(&vault);

    let reserved =
        enqueue_consolidation_attempt(&runner, DreamerConsolidationScope::Micro, None, 10)?;
    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(first)) =
        runner.admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: DreamerClaimAuthoringAdmission::single_pass(),
            admission: AdmitDreamerAttempt {
                lease_owner: "reserved-worker".to_owned(),
                now: 20,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 10,
                reserve_units: 10,
                started_milestone: None,
            },
        })?
    else {
        panic!("expected reserved admission");
    };
    // Each retry mints the fresh row that carries the ready entry; the fixture
    // now tracks those ids rather than the finalized sources.
    let RetryOutcome::Retried(reserved_retry) = queue.retry(RetryAttempt {
        id: reserved.attempt.id,
        lease_owner: "reserved-worker".to_owned(),
        attempt_count: first.status.attempt.attempt_count,
        backoff_until: 2,
        last_error: Some("lease_timeout".to_owned()),
        now: 21,
    })?;

    let stale = enqueue_consolidation_attempt(&runner, DreamerConsolidationScope::Micro, None, 30)?;
    let ClaimOutcome::Claimed(stale_claim) = queue.claim_kind(
        DreamerConsolidationScope::Micro.attempt_kind(),
        ClaimAttempt {
            lease_owner: "stale-prep".to_owned(),
            now: 31,
        },
    )?
    else {
        panic!("expected to claim stale fixture attempt");
    };
    assert_eq!(stale_claim.id, stale.attempt.id);
    let RetryOutcome::Retried(stale_retry) = queue.retry(RetryAttempt {
        id: stale.attempt.id,
        lease_owner: "stale-prep".to_owned(),
        attempt_count: stale_claim.attempt_count,
        backoff_until: 1,
        last_error: Some("lease_timeout".to_owned()),
        now: 32,
    })?;
    rewrite_ready_key(&vault, stale_retry.id, 1, 0)?;

    let axes = DreamerTournamentBudgetAxes {
        fanout_m: 2,
        depth_k: 3,
        reserve_units_per_step: 2,
    };
    let DreamerConsolidationAdmissionOutcome::ClaimAuthoringBudgetTrap(trap) = runner
        .admit_next_consolidation(AdmitDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            local_node_id: 77,
            claim_authoring_tier: DreamerClaimAuthoringBatchTier::batch(),
            claim_authoring: tournament_admission(
                "pattern.sleep",
                3,
                0.4,
                DreamerClaimEvidenceState::Uncontested,
                0.7,
                axes,
            ),
            admission: AdmitDreamerAttempt {
                lease_owner: "tournament-worker".to_owned(),
                now: 40,
                budget_id: "wake:micro".to_owned(),
                budget_total_units: 10,
                reserve_units: 0,
                started_milestone: None,
            },
        })?
    else {
        panic!("expected tournament BudgetTrap for stale ready candidate");
    };

    assert_eq!(trap.attempt_id, stale_retry.id);
    assert_eq!(trap.budget.remaining_units, 0);
    assert_eq!(trap.budget.reserved_units, 10);
    let stale_status = runner
        .status(stale_retry.id)?
        .expect("paused stale attempt");
    assert_eq!(stale_status.attempt.state, AttemptState::Paused);
    let reserved_status = runner.status(reserved_retry.id)?.expect("reserved attempt");
    assert_eq!(reserved_status.attempt.state, AttemptState::Scheduled);
    assert_eq!(
        runner.budget_reservation("wake:micro", reserved.attempt.id)?,
        Some(first.reservation)
    );
    Ok(())
}

#[test]
fn dreamer_payload_round_trips_with_pinned_keys() -> Result<()> {
    let payload = DreamerAttemptPayload {
        attempt_type: "expand".to_owned(),
        input: Value::from("seed"),
        parent_attempt: None,
    };
    let encoded = encode_dreamer_attempt_payload(&payload)?;
    let decoded = decode_dreamer_attempt_payload(&encoded)?;
    assert_eq!(decoded, payload);
    assert_eq!(
        DREAMER_ATTEMPT_PAYLOAD_KEYS,
        ["schema_version", "job_type", "input", "parent_job"]
    );
    Ok(())
}

#[test]
fn dreamer_complete_fail_reject_non_dreamer_queue_rows_before_mutation() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let queue = crate::attempt_queue::AttemptQueue::new(&vault);
    let companion = match queue.enqueue(crate::attempt_queue::EnqueueAttempt {
        kind: "companion".to_owned(),
        payload: b"not-dreamer".to_vec(),
        dedupe_key: None,
        run_id: None,
        now: 10,
    })? {
        crate::attempt_queue::EnqueueOutcome::Enqueued(record)
        | crate::attempt_queue::EnqueueOutcome::Existing(record) => record,
    };
    let crate::attempt_queue::ClaimOutcome::Claimed(claimed) = queue.claim_kind(
        "companion",
        crate::attempt_queue::ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 11,
        },
    )?
    else {
        panic!("expected companion attempt to be leased");
    };
    assert_eq!(claimed.id, companion.id);

    let runner = DreamerRunnerStore::new(&vault);
    runner
        .complete(CompleteDreamerAttempt {
            id: claimed.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            now: 12,
        })
        .expect_err("non-Dreamer queue row must be rejected before complete");
    assert_eq!(
        queue.get(claimed.id)?.expect("companion row remains").state,
        AttemptState::Leased,
        "complete guard must not mutate the generic queue row"
    );

    runner
        .fail(FailDreamerAttempt {
            id: claimed.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed.attempt_count,
            reason: "should-not-commit".to_owned(),
            now: 13,
        })
        .expect_err("non-Dreamer queue row must be rejected before fail");
    assert_eq!(
        queue.get(claimed.id)?.expect("companion row remains").state,
        AttemptState::Leased,
        "fail guard must not mutate the generic queue row"
    );

    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn dreamer_durable_milestone_backfill_fails_closed_on_malformed_claim_body() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue_attempt(&runner, "expand", 10)?;
    write_milestone_for_attempt(
        &vault,
        queued.attempt.id,
        EntityId::now(),
        DreamerMilestoneKind::Started,
        20,
    )?;

    let corrupt_claim = EntityId::now();
    let mut raw = Vec::new();
    raw.push(ENTITY_TYPE_CLAIM);
    raw.extend_from_slice(&25_u64.to_be_bytes());
    raw.extend_from_slice(&25_u64.to_be_bytes());
    raw.extend_from_slice(&25_u64.to_be_bytes());
    raw.extend_from_slice(b"not a claim body");
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .entities
            .put(wtxn, corrupt_claim.as_bytes(), &raw)?;
        Ok(())
    })?;

    runner
        .latest_durable_milestone(queued.attempt.id)
        .expect_err("malformed claim body must fail the one-time backfill");
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        !super::milestone::MILESTONE_INDEX_BACKFILLED.contains(&vault.store, &rtxn, &())?,
        "failed backfill must not mark the milestone index complete"
    );

    Ok(())
}

#[test]
fn dreamer_sync_topology_change_reelects_and_gates_macro() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let local = runner.local_home_node_candidate(true, true, false)?;
    let cloud = DreamerHomeNodeCandidate::cloud(different_node_id(local.node_id), true);
    let queued = enqueue_consolidation_attempt(
        &runner,
        DreamerConsolidationScope::Macro,
        Some("topology-change"),
        1,
    )?;

    let home = runner.sync_topology_changed(&[local, cloud], 10)?.unwrap();
    assert_eq!(home.node_id, cloud.node_id);
    assert_eq!(home.class, DreamerHomeNodeClass::CloudAttached);
    assert_eq!(runner.home_node_designation()?, Some(home));
    assert_eq!(
        admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            local.node_id,
            "local",
            12
        )?,
        DreamerConsolidationAdmissionOutcome::NotHomeNode(home)
    );
    assert_eq!(
        runner.status(queued.attempt.id)?.unwrap().attempt.state,
        AttemptState::Queued
    );

    // Only a host-authorized change to this cloud's attachment may promote
    // the local node. A socket interruption is not such a change.
    let detached = DreamerHomeNodeCandidate::cloud(cloud.node_id, false);
    let home = runner
        .sync_topology_changed(&[local, detached], 13)?
        .unwrap();
    assert_eq!(home.node_id, local.node_id);
    assert_eq!(runner.home_node_designation()?, Some(home));
    assert!(matches!(
        admit_consolidation(
            &runner,
            DreamerConsolidationScope::Macro,
            local.node_id,
            "local",
            14
        )?,
        DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(_))
    ));
    Ok(())
}

#[test]
fn dreamer_macro_consolidation_admits_only_the_elected_home_node() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let local = runner.local_home_node_candidate(true, true, false)?;
    let primary = DreamerHomeNodeCandidate::primary_device(different_node_id(local.node_id));
    let designation = runner
        .elect_home_node(&[primary, local], 100)?
        .expect("always-on local wins");
    assert_eq!(designation.node_id, local.node_id);

    let macro_attempt = enqueue_consolidation_attempt(
        &runner,
        DreamerConsolidationScope::Macro,
        Some("home-macro:bucket-pair"),
        10,
    )?;

    let non_home = admit_consolidation(
        &runner,
        DreamerConsolidationScope::Macro,
        primary.node_id,
        "primary",
        20,
    );
    assert!(matches!(
        non_home,
        Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_)))
    ));
    let still_queued = runner
        .status(macro_attempt.attempt.id)?
        .expect("macro attempt");
    assert_eq!(still_queued.attempt.state, AttemptState::Queued);
    assert_eq!(still_queued.attempt.attempt_count, 0);

    let DreamerConsolidationAdmissionOutcome::Admission(DreamerAdmissionOutcome::Admitted(
        admitted,
    )) = admit_consolidation(
        &runner,
        DreamerConsolidationScope::Macro,
        local.node_id,
        "home",
        21,
    )?
    else {
        panic!("elected home node should admit MACRO consolidation");
    };
    assert_eq!(admitted.status.attempt.id, macro_attempt.attempt.id);
    assert_eq!(
        admitted.status.attempt.kind,
        DREAMER_CONSOLIDATION_MACRO_ATTEMPT_KIND
    );
    assert_eq!(admitted.status.attempt.lease_owner.as_deref(), Some("home"));
    Ok(())
}

#[test]
fn dreamer_macro_consolidation_rejects_spoofed_remote_home_node_id() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let local = runner.local_home_node_candidate(true, false, true)?;
    let remote_home = DreamerHomeNodeCandidate::cloud(different_node_id(local.node_id), true);
    let designation = runner
        .elect_home_node(&[local, remote_home], 100)?
        .expect("attached cloud wins");
    assert_eq!(designation.node_id, remote_home.node_id);

    let macro_attempt =
        enqueue_consolidation_attempt(&runner, DreamerConsolidationScope::Macro, None, 10)?;

    let spoofed_home_id = admit_consolidation(
        &runner,
        DreamerConsolidationScope::Macro,
        designation.node_id,
        "spoof",
        20,
    );
    assert!(matches!(
        spoofed_home_id,
        Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_)))
    ));

    let honest_local = admit_consolidation(
        &runner,
        DreamerConsolidationScope::Macro,
        local.node_id,
        "local",
        21,
    )?;
    let DreamerConsolidationAdmissionOutcome::NotHomeNode(home) = honest_local else {
        panic!("honest local caller must be denied remote-home work");
    };
    assert_eq!(home.node_id, remote_home.node_id);
    let still_queued = runner
        .status(macro_attempt.attempt.id)?
        .expect("macro attempt");
    assert_eq!(still_queued.attempt.state, AttemptState::Queued);
    assert_eq!(still_queued.attempt.attempt_count, 0);
    Ok(())
}

#[test]
fn dreamer_macro_consolidation_without_home_does_not_claim() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let local = runner.local_home_node_candidate(true, true, false)?;
    let macro_attempt =
        enqueue_consolidation_attempt(&runner, DreamerConsolidationScope::Macro, None, 10)?;

    let outcome = admit_consolidation(
        &runner,
        DreamerConsolidationScope::Macro,
        local.node_id,
        "worker",
        20,
    )?;
    assert_eq!(outcome, DreamerConsolidationAdmissionOutcome::NoHomeNode);
    let still_queued = runner
        .status(macro_attempt.attempt.id)?
        .expect("macro attempt");
    assert_eq!(still_queued.attempt.state, AttemptState::Queued);
    assert_eq!(still_queued.attempt.attempt_count, 0);
    Ok(())
}

#[test]
fn dreamer_admission_claims_attempt_reserves_budget_and_writes_started_milestone_atomically()
-> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue_attempt(&runner, "expand", 10)?;
    let claim_id = EntityId::now();
    let milestone = milestone_fixture(&vault, claim_id, 20)?;
    let milestone_subject = milestone.subject;

    let admitted = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "dreamer-worker".to_owned(),
        now: 20,
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 4,
        started_milestone: Some(milestone),
    })?;

    let DreamerAdmissionOutcome::Admitted(admitted) = admitted else {
        panic!("expected admitted Dreamer attempt");
    };
    assert_eq!(admitted.status.attempt.id, queued.attempt.id);
    assert_eq!(admitted.status.attempt.state, AttemptState::Leased);
    assert_eq!(
        admitted.status.attempt.lease_owner.as_deref(),
        Some("dreamer-worker")
    );
    assert_eq!(admitted.status.attempt.attempt_count, 1);
    assert_eq!(admitted.budget.remaining_units, 6);
    assert_eq!(admitted.budget.reserved_units, 4);
    assert_eq!(admitted.reservation.budget_id, "wake");
    assert_eq!(admitted.reservation.attempt_id, queued.attempt.id);
    assert_eq!(admitted.reservation.reserved_units, 4);

    let stored_budget = runner.budget("wake")?.expect("budget row");
    assert_eq!(stored_budget, admitted.budget);
    assert_eq!(runner.remaining_budget("wake")?, Some(6));
    assert_eq!(
        runner.budget_reservation("wake", queued.attempt.id)?,
        Some(admitted.reservation)
    );
    let stored_claim = vault
        .get_claim(&claim_id)?
        .expect("started milestone claim");
    assert_eq!(stored_claim.predicate, DREAMER_MILESTONE_PREDICATE);
    assert_eq!(
        stored_claim.subject,
        ClaimSubject::Entity(milestone_subject)
    );
    assert_eq!(stored_claim.approval, ClaimApprovalStatus::Approved);

    let Value::Map(entries) = stored_claim.value else {
        panic!("milestone value must be a map");
    };
    assert!(entries.iter().any(|(key, value)| {
        key.as_str() == Some(KEY_MILESTONE)
            && value.as_str() == Some(DreamerMilestoneKind::Started.as_str())
    }));
    assert!(entries.iter().any(|(key, value)| {
        key.as_str() == Some(KEY_ATTEMPT_ID)
            && matches!(value, Value::Binary(bytes) if bytes.as_slice() == queued.attempt.id.as_bytes())
    }));

    Ok(())
}

#[test]
fn dreamer_admission_budget_denial_does_not_lease_or_persist_budget() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let stale = match runner.enqueue(EnqueueDreamerAttempt {
        attempt_type: "stale".to_owned(),
        input: Value::from("stale"),
        parent_attempt: None,
        dedupe_key: Some("stale-dedupe".to_owned()),
        run_id: None,
        now: 5,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    };
    let queued = enqueue_attempt(&runner, "expand", 10)?;
    let stale_ready_key = test_ready_key(5, stale.attempt.id);
    {
        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .attempt_records
            .delete(&mut wtxn, stale.attempt.id.as_bytes())?;
        wtxn.commit()?;
    }
    assert!(
        attempt_dedupe_points_to(&vault, stale.attempt.id)?,
        "fixture must leave a stale dedupe index before denial"
    );

    let denied = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "dreamer-worker".to_owned(),
        now: 20,
        budget_id: "wake".to_owned(),
        budget_total_units: 3,
        reserve_units: 4,
        started_milestone: None,
    })?;

    let DreamerAdmissionOutcome::BudgetExhausted(budget) = denied else {
        panic!("expected budget denial");
    };
    assert_eq!(budget.remaining_units, 3);
    assert_eq!(budget.reserved_units, 0);
    assert!(
        runner.budget("wake")?.is_none(),
        "denied admission must not commit an initialized budget row"
    );
    assert!(
        runner
            .budget_reservation("wake", queued.attempt.id)?
            .is_none(),
        "denied admission must not commit a child reservation row"
    );
    let status = runner.status(queued.attempt.id)?.expect("queued attempt");
    assert_eq!(status.attempt.state, AttemptState::Queued);
    assert_eq!(status.attempt.attempt_count, 0);
    assert!(status.attempt.lease_owner.is_none());
    let rtxn = vault.store.env.read_txn()?;
    assert!(
        vault
            .store
            .attempt_ready
            .get(&rtxn, &stale_ready_key)?
            .is_none(),
        "budget denial must commit stale ready-row repairs"
    );
    drop(rtxn);
    assert!(
        !attempt_dedupe_points_to(&vault, stale.attempt.id)?,
        "budget denial must commit stale dedupe cleanup"
    );

    Ok(())
}

#[test]
fn park_row_ownership_enforced() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue_attempt(&runner, "expand", 10)?;

    // Same-owner park → re-park round-trip refreshes the row.
    runner.park_attempt(ParkDreamerAttempt {
        attempt_id: queued.attempt.id,
        reason: "first park".to_owned(),
        park_owner: "owner-a".to_owned(),
        now: 20,
    })?;
    let reparked = runner.park_attempt(ParkDreamerAttempt {
        attempt_id: queued.attempt.id,
        reason: "refreshed park".to_owned(),
        park_owner: "owner-a".to_owned(),
        now: 21,
    })?;
    assert_eq!(runner.parked_attempt(queued.attempt.id)?, Some(reparked));

    // A DIFFERENT owner must not overwrite the row.
    let error = runner
        .park_attempt(ParkDreamerAttempt {
            attempt_id: queued.attempt.id,
            reason: "steal park".to_owned(),
            park_owner: "owner-b".to_owned(),
            now: 22,
        })
        .expect_err("overwrite by other owner refused");
    assert!(matches!(
        error,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))
    ));
    let parked = runner
        .parked_attempt(queued.attempt.id)?
        .expect("row intact");
    assert_eq!(parked.park_owner, "owner-a");
    assert_eq!(parked.reason, "refreshed park");

    // A DIFFERENT owner must not resume (delete) the row.
    let error = runner
        .resume_parked(queued.attempt.id, "owner-b", 23)
        .expect_err("unpark by other owner refused");
    assert!(matches!(
        error,
        Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_))
    ));
    assert!(
        runner.parked_attempt(queued.attempt.id)?.is_some(),
        "row intact"
    );

    // The recorded owner resumes; a second resume is an idempotent no-op.
    let resumed = runner
        .resume_parked(queued.attempt.id, "owner-a", 24)?
        .expect("resumed status");
    assert_eq!(resumed.attempt.id, queued.attempt.id);
    assert!(runner.parked_attempt(queued.attempt.id)?.is_none());
    assert!(
        runner
            .resume_parked(queued.attempt.id, "owner-a", 25)?
            .is_none()
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[test]
fn dreamer_sync_boundary_exports_claims_not_runner_private_rows() -> Result<()> {
    use crate::sync::bridge::Materializer;
    use crate::sync::loro_support::map_get_bytes;
    use crate::sync::schema::create_window_doc;
    use crate::sync::types::WindowKey;
    use crate::sync::window;
    use loro::{ExportMode, LoroDoc};

    let learned_at = 1_772_000_000;
    let window_key = WindowKey::from_timestamp(learned_at);
    let (_dir_a, vault_a) = open_vault();
    let runner_a = DreamerRunnerStore::new(&vault_a);
    let queued = enqueue_attempt(&runner_a, "expand", learned_at)?;
    let milestone_id = EntityId::now();
    let milestone = milestone_fixture(&vault_a, milestone_id, learned_at)?;

    runner_a.admit_next(AdmitDreamerAttempt {
        lease_owner: "dreamer-worker".to_owned(),
        now: learned_at,
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 4,
        started_milestone: Some(milestone),
    })?;
    runner_a.park_attempt(ParkDreamerAttempt {
        attempt_id: queued.attempt.id,
        reason: "waiting for wake budget settle".to_owned(),
        park_owner: "dreamer-worker".to_owned(),
        now: learned_at + 1,
    })?;

    let consent_id = EntityId::now();
    let effect_id = EntityId::now();
    let checkpoint_id = EntityId::now();
    write_dreamer_boundary_claim(&vault_a, consent_id, "dreamer.consent", learned_at)?;
    write_dreamer_boundary_claim(&vault_a, effect_id, "dreamer.effect", learned_at)?;
    write_dreamer_boundary_claim(&vault_a, checkpoint_id, "dreamer.checkpoint", learned_at)?;

    let durable_claims = [milestone_id, consent_id, effect_id, checkpoint_id];
    let doc_a = create_window_doc("node-a", &window_key);
    let mirrored = window::reverse_rematerialize(&vault_a, &doc_a, &window_key)?;
    assert!(
        mirrored >= durable_claims.len() as u32,
        "reverse rematerialize must mirror durable Dreamer claims"
    );

    let entities = doc_a.get_map("entities");
    for claim_id in durable_claims {
        assert_eq!(
            map_get_bytes(&entities, claim_id.to_hex().as_str()).as_deref(),
            vault_a.get_raw(&claim_id)?.as_deref(),
            "durable Dreamer claim must be present in the sync doc"
        );
    }

    let queued_as_entity = EntityId::from_bytes(*queued.attempt.id.as_bytes())?;
    assert!(
        map_get_bytes(&entities, queued_as_entity.to_hex().as_str()).is_none(),
        "queue attempt rows and leases must not be emitted as sync entities"
    );
    assert!(
        map_get_bytes(&entities, "dreamer:budget:wake").is_none(),
        "private runner keys must not be emitted into the sync entity map"
    );
    assert!(
        map_get_bytes(&entities, "dreamer:budget_reservation:wake").is_none(),
        "private child budget reservations must not be emitted into the sync entity map"
    );

    let snapshot = doc_a.export(ExportMode::Snapshot).unwrap();
    let doc_b = LoroDoc::from_snapshot(&snapshot).unwrap();
    let (_dir_b, vault_b) = open_vault();
    let materializer = Materializer::new();
    let restored = window::forward_rematerialize(&vault_b, &doc_b, &materializer, &window_key)?;
    assert!(
        restored >= durable_claims.len() as u32,
        "forward rematerialize must restore durable Dreamer claims"
    );
    for claim_id in durable_claims {
        assert!(
            vault_b.get_claim(&claim_id)?.is_some(),
            "durable Dreamer claim must survive CRDT sync"
        );
    }

    let rtxn = vault_b.store.env.read_txn()?;
    assert!(
        vault_b
            .store
            .attempt_records
            .get(&rtxn, queued.attempt.id.as_bytes())?
            .is_none(),
        "queue leases must remain private to the runner store"
    );
    assert!(
        !super::admission::BUDGET.contains(&vault_b.store, &rtxn, &"wake".to_owned())?,
        "private budget rows must not sync"
    );
    assert!(
        !super::admission::BUDGET_RESERVATION.contains(
            &vault_b.store,
            &rtxn,
            &super::admission::BudgetReservationKey {
                budget_id: "wake".to_owned(),
                attempt_id: queued.attempt.id,
            },
        )?,
        "private budget reservation rows must not sync"
    );
    assert!(
        !super::store::RUN_TREE.contains(&vault_b.store, &rtxn, &queued.attempt.id)?,
        "private run-tree rows must not sync"
    );
    assert!(
        !super::store::PARKED.contains(&vault_b.store, &rtxn, &queued.attempt.id)?,
        "private parked rows must not sync"
    );

    Ok(())
}

#[test]
fn checkpoint_charge_and_park_are_atomic_and_receipt_retires_on_completion() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue_attempt(&runner, "charged-checkpoint", 10)?;
    let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "dreamer-worker".to_owned(),
        now: 20,
        budget_id: "wake".to_owned(),
        budget_total_units: 20,
        reserve_units: 8,
        started_milestone: None,
    })?
    else {
        panic!("admitted attempt");
    };
    let hash = [0x53; 32];
    let settlement = SettleDreamerBudget {
        budget_id: "wake".to_owned(),
        child_attempt: queued.attempt.id,
        actual_units: 5,
        now: 30,
    };
    let park = ParkDreamerAttempt {
        attempt_id: queued.attempt.id,
        reason: "late terminal".to_owned(),
        park_owner: "dreamer-worker".to_owned(),
        now: 30,
    };
    let mut invalid = park.clone();
    invalid.park_owner.clear();
    assert!(
        runner
            .settle_checkpoint_budget(settlement.clone(), &[hash], invalid)
            .is_err()
    );
    assert_eq!(runner.budget("wake")?.expect("budget").remaining_units, 12);
    assert!(
        runner
            .budget_reservation("wake", queued.attempt.id)?
            .is_some()
    );
    assert!(runner.parked_attempt(queued.attempt.id)?.is_none());
    assert!(!runner.checkpoint_step_charged(queued.attempt.id, &hash)?);

    runner.settle_checkpoint_budget(settlement, &[hash], park)?;
    assert_eq!(runner.budget("wake")?.expect("budget").remaining_units, 15);
    assert!(
        runner
            .budget_reservation("wake", queued.attempt.id)?
            .is_none()
    );
    assert!(runner.parked_attempt(queued.attempt.id)?.is_some());
    assert!(runner.checkpoint_step_charged(queued.attempt.id, &hash)?);

    runner.resume_parked(queued.attempt.id, "dreamer-worker", 40)?;
    runner.complete(CompleteDreamerAttempt {
        id: queued.attempt.id,
        lease_owner: "dreamer-worker".to_owned(),
        attempt_count: admitted.status.attempt.attempt_count,
        now: 50,
    })?;
    assert!(!runner.checkpoint_step_charged(queued.attempt.id, &hash)?);
    Ok(())
}

#[test]
fn dreamer_settle_rejects_actual_usage_beyond_remaining_budget() -> Result<()> {
    let (_dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);
    let queued = enqueue_attempt(&runner, "settle-overspend", 10)?;

    let DreamerAdmissionOutcome::Admitted(admitted) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "dreamer-worker".to_owned(),
        now: 20,
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 8,
        started_milestone: None,
    })?
    else {
        panic!("expected admitted Dreamer attempt");
    };
    assert_eq!(admitted.budget.remaining_units, 2);
    assert_eq!(admitted.budget.reserved_units, 8);

    let result = runner.settle_budget(SettleDreamerBudget {
        budget_id: "wake".to_owned(),
        child_attempt: queued.attempt.id,
        actual_units: 11,
        now: 30,
    });
    assert!(matches!(
        result,
        Err(Error::Artifact(ArtifactError::InvalidAttemptQueueRecord(_)))
    ));
    let budget = runner.budget("wake")?.expect("unchanged budget");
    assert_eq!(budget.budget_id, admitted.budget.budget_id);
    assert_eq!(budget.total_units, admitted.budget.total_units);
    assert_eq!(budget.remaining_units, 2);
    assert_eq!(budget.reserved_units, 8);
    let reservation = runner
        .budget_reservation("wake", queued.attempt.id)?
        .expect("reservation must survive rejected settlement");
    assert_eq!(reservation.budget_id, admitted.reservation.budget_id);
    assert_eq!(reservation.attempt_id, queued.attempt.id);
    assert_eq!(reservation.reserved_units, 8);

    Ok(())
}

#[test]
fn dreamer_admission_reuses_existing_reservation_after_lease_timeout_requeue() -> Result<()> {
    let clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let runner = DreamerRunnerStore::new(&vault);
    let queue = AttemptQueue::new(&vault);
    let queued = enqueue_attempt(&runner, "requeued", 10)?;

    let DreamerAdmissionOutcome::Admitted(first) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "first-worker".to_owned(),
        now: {
            clock.set(20);
            20
        },
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 8,
        started_milestone: None,
    })?
    else {
        panic!("expected first admission");
    };
    assert_eq!(first.status.attempt.id, queued.attempt.id);
    assert_eq!(first.status.attempt.attempt_count, 1);
    assert_eq!(first.budget.remaining_units, 2);
    assert_eq!(first.budget.reserved_units, 8);
    let first_budget = first.budget.clone();
    let first_reservation = first.reservation.clone();

    let report = queue.cleanup_leases(CleanupAttemptLeases {
        now: {
            clock.set(40);
            40
        },
        lease_timeout_secs: 10,
    })?;
    assert_eq!(report.stale_requeued, 1);
    let requeued = runner.status(queued.attempt.id)?.expect("requeued attempt");
    assert_eq!(requeued.attempt.state, AttemptState::Queued);
    assert_eq!(
        requeued.attempt.last_error.as_deref(),
        Some("lease_timeout")
    );

    let DreamerAdmissionOutcome::Admitted(second) = runner.admit_next(AdmitDreamerAttempt {
        lease_owner: "second-worker".to_owned(),
        now: {
            clock.set(50);
            50
        },
        budget_id: "wake".to_owned(),
        budget_total_units: 10,
        reserve_units: 8,
        started_milestone: None,
    })?
    else {
        panic!("expected second admission");
    };
    assert_eq!(second.status.attempt.id, queued.attempt.id);
    assert_eq!(second.status.attempt.state, AttemptState::Leased);
    assert_eq!(second.status.attempt.attempt_count, 2);
    assert_eq!(
        second.status.attempt.lease_owner.as_deref(),
        Some("second-worker")
    );
    assert_eq!(second.budget, first_budget);
    assert_eq!(second.reservation, first_reservation);
    assert_eq!(
        runner.budget("wake")?.expect("unchanged budget"),
        first_budget
    );
    assert_eq!(
        runner.budget_reservation("wake", queued.attempt.id)?,
        Some(first_reservation)
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// ONE-1400 — clustering adapter authority boundary
// ---------------------------------------------------------------------------

/// Snapshot of every durable surface the clustering adapter is forbidden to
/// touch: raw vault bytes, attempt rows (records/ready/dedupe), claim and
/// topology rows (both live in `entities` / `vault_meta`), and the LMDB file
/// size. Compared before and after a `propose_claim_cohorts` call.
#[derive(Debug, PartialEq, Eq)]
struct VaultWriteSurfaces {
    data_file_len: u64,
    entities: Vec<(Vec<u8>, Vec<u8>)>,
    vault_meta: Vec<(Vec<u8>, Vec<u8>)>,
    attempt_records: Vec<(Vec<u8>, Vec<u8>)>,
    attempt_ready: Vec<(Vec<u8>, Vec<u8>)>,
    attempt_dedupe: Vec<(Vec<u8>, Vec<u8>)>,
    type_index: Vec<(Vec<u8>, Vec<u8>)>,
    edges_out: Vec<(Vec<u8>, Vec<u8>)>,
}

fn dump_db(
    db: &crate::overlay_db::OverlayDb,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut rows = Vec::new();
    for row in db.iter(rtxn)? {
        let (key, value) = row?;
        rows.push((key.into_owned(), value.into_owned()));
    }
    Ok(rows)
}

fn vault_write_surfaces(dir: &std::path::Path, vault: &Vault) -> Result<VaultWriteSurfaces> {
    let data_file_len = std::fs::metadata(dir.join("data.mdb"))?.len();
    let rtxn = vault.store.env.read_txn()?;
    Ok(VaultWriteSurfaces {
        data_file_len,
        entities: dump_db(&vault.store.entities, &rtxn)?,
        vault_meta: dump_db(&vault.store.vault_meta, &rtxn)?,
        attempt_records: dump_db(&vault.store.attempt_records, &rtxn)?,
        attempt_ready: dump_db(&vault.store.attempt_ready, &rtxn)?,
        attempt_dedupe: dump_db(&vault.store.attempt_dedupe, &rtxn)?,
        type_index: dump_db(&vault.store.type_index, &rtxn)?,
        edges_out: dump_db(&vault.store.edges_out, &rtxn)?,
    })
}

fn cluster_fixture_claims() -> Vec<crate::cluster::ClusterClaim> {
    let subject = crate::test_util::entity(0x70);
    // Two near-parallel vectors (cluster together) plus one orthogonal
    // (singleton) — enough that the adapter returns real, non-trivial data.
    [
        (0x01_u8, vec![1.0_f32, 0.0, 0.0, 0.0]),
        (0x02, vec![0.995, 0.0998, 0.0, 0.0]),
        (0x03, vec![0.0, 1.0, 0.0, 0.0]),
    ]
    .into_iter()
    .map(|(seed, embedding)| crate::cluster::ClusterClaim {
        claim_id: crate::test_util::entity(seed),
        subject: ClaimSubject::Entity(subject),
        predicate: "person.name".to_owned(),
        world: None,
        facet: None,
        embedding,
    })
    .collect()
}

#[test]
fn dreamer_decides_not_tool() -> Result<()> {
    let (dir, vault) = open_vault();
    let runner = DreamerRunnerStore::new(&vault);

    // Seed real state first, so the comparison is against a populated vault
    // rather than an empty one: an attempt row, and a claim/topology-bearing
    // entity row.
    enqueue_attempt(&runner, "cluster-boundary", 10)?;
    let claim_id = EntityId::now();
    vault.put_entity(
        &claim_id,
        ENTITY_TYPE_TASK,
        occurred(10),
        10,
        &crate::habit::task_body_for_test(crate::habit::TaskRole::Task),
    )?;

    let before = vault_write_surfaces(dir.path(), &vault)?;

    // Call the tool repeatedly, including with inputs that fail validation —
    // neither the success nor the failure path may write.
    let claims = cluster_fixture_claims();
    for _ in 0..3 {
        let assignments =
            runner.propose_claim_cohorts(&claims, crate::cluster::ClusterOptions::default())?;
        assert!(!assignments.cohorts.is_empty());
    }
    assert!(
        runner
            .propose_claim_cohorts(
                &claims,
                crate::cluster::ClusterOptions {
                    cohesion_threshold: 2.0,
                },
            )
            .is_err()
    );

    let after = vault_write_surfaces(dir.path(), &vault)?;
    assert_eq!(
        before, after,
        "clustering must not change vault bytes, attempt rows, claims, or topology rows"
    );
    Ok(())
}
