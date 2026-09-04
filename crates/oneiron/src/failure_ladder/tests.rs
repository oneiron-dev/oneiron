//! ONE-1887 failure-ladder tests, mapped 1:1 to the brief's acceptance
//! criteria: classification, bounded retry through ONE-1795's fresh-row API,
//! the bounded cycle-safe lineage walk, terminal routing, the agent-only
//! repair vocabulary, and `report_blocked` intake as an Issues-only path.

use rmpv::Value;

use super::*;
use crate::VaultConfig;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::agent_dispatch::{AgentDispatchOutcome, DispatchAgent};
use crate::attempt_queue::{AttemptState, ClaimAttempt, ClaimOutcome};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use crate::temporal::TimeRange;
use crate::test_util::entity as test_id;

/// This module's own source, read for the mechanical negative-scope proofs.
const FAILURE_LADDER_SOURCE: &str = include_str!("../failure_ladder.rs");
/// The healer-slot wrapper's source, read for the same proofs.
const AGENT_DISPATCH_SOURCE: &str = include_str!("../agent_dispatch.rs");

const LEASE_OWNER: &str = "failure-ladder-worker";
const RUN_ID: &str = "run-1887";
/// The caller's existing backoff policy picks this; the ladder only forwards it.
const RETRY_AT: u64 = 5;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

/// A stored, dispatchable AGENT_DEF row the failure scope can bind to.
fn put_scope_agent(vault: &Vault, seed: u8, agent_id: &str) -> Result<EntityId> {
    let id = test_id(seed);
    let definition = AgentDefinition::new(
        agent_id,
        "Failure ladder fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from(agent_id))]),
        None,
        true,
        None,
    );
    vault.put_agent_definition(&id, &definition, TimeRange { start: 1, end: 1 }, 1)?;
    Ok(id)
}

fn dispatch_attempt(vault: &Vault, agent_ref: EntityId, now: u64) -> Result<AttemptRecord> {
    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent_ref),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN_ID.to_owned()),
            now,
        })?
    else {
        panic!("expected a fresh dispatch");
    };
    Ok(status.attempt)
}

fn claim(vault: &Vault, expected: AttemptId, now: u64) -> Result<AttemptRecord> {
    let ClaimOutcome::Claimed(record) = AttemptQueue::new(vault).claim(ClaimAttempt {
        lease_owner: LEASE_OWNER.to_owned(),
        now,
    })?
    else {
        panic!("expected a claim");
    };
    assert_eq!(record.id, expected);
    Ok(record)
}

/// A dispatched agent attempt, claimed and leased — the exact shape the ladder
/// is called on.
fn leased_dispatch(vault: &Vault, agent_ref: EntityId, now: u64) -> Result<AttemptRecord> {
    let dispatched = dispatch_attempt(vault, agent_ref, now)?;
    claim(vault, dispatched.id, now)
}

fn evidence(verdict: TypedFailureVerdict, tier: Option<DetectorTier>) -> TypedFailureEvidence {
    TypedFailureEvidence {
        evidence_ref: Some(test_id(0x53).to_hex()),
        verdict,
        tier,
        stable_reason: "detector.stable_code".to_owned(),
    }
}

fn transient() -> TypedFailureEvidence {
    evidence(
        TypedFailureVerdict::Retryable,
        Some(DetectorTier::T1Tripwire),
    )
}

fn permanent() -> TypedFailureEvidence {
    evidence(
        TypedFailureVerdict::NonRetryable,
        Some(DetectorTier::T3Judge),
    )
}

fn indeterminate() -> TypedFailureEvidence {
    TypedFailureEvidence {
        evidence_ref: None,
        verdict: TypedFailureVerdict::Indeterminate,
        tier: None,
        stable_reason: "detector.no_evidence".to_owned(),
    }
}

fn failure_input(
    record: &AttemptRecord,
    evidence: TypedFailureEvidence,
    now: u64,
) -> HandleAttemptFailure {
    HandleAttemptFailure {
        attempt_id: record.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: record.attempt_count,
        evidence,
        blocked_reports: Vec::new(),
        pre_fail_checkpoint_ref: test_id(0x51),
        qa_thread_ref: test_id(0x52),
        retry_at: RETRY_AT,
        now,
    }
}

fn auto_policy(agent_ref: EntityId) -> FailureScopePolicy {
    FailureScopePolicy::auto(FailureScope {
        agent_ref: agent_ref.to_hex(),
        skill_ref: None,
    })
}

fn policy_with(agent_ref: EntityId, limit: u16, mode: FailureEscalationMode) -> FailureScopePolicy {
    FailureScopePolicy {
        max_consecutive_transients: NonZeroU16::new(limit).expect("non-zero limit"),
        escalation_mode: mode,
        ..auto_policy(agent_ref)
    }
}

/// A durable ONE-1686 witness MESSAGE row, standing in for a `report_blocked`
/// receipt until 1686 lands its own receipt kind.
fn put_receipt_message(vault: &Vault, seed: u8, order: u32) -> Result<EntityId> {
    let id = test_id(seed);
    let body = crate::gate::canonical_witness_message_body_for_test(
        "user",
        "dialogue",
        "blocked report",
        true,
        order,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(&id, TimeRange { start: 7, end: 7 }, 7, &body)
        .commit()?;
    Ok(id)
}

/// Rewrites ONE ancestor row's `retry_of` pointer.
///
/// A CYCLIC chain cannot be minted through the public retry API — that is the
/// point of the pathology — so the fixture writes the loop directly. Production
/// ladder code never writes an ATTEMPT row; only this fixture does.
fn repoint_retry_of(vault: &Vault, id: AttemptId, retry_of: Option<AttemptId>) -> Result<()> {
    let mut record = AttemptQueue::new(vault)
        .get(id)?
        .expect("ancestor row exists");
    record.retry_of = retry_of;
    let mut encoded = vec![crate::attempt_queue::ATTEMPT_RECORD_VERSION];
    encoded.append(&mut rmp_serde::to_vec_named(&record).expect("encode attempt record"));
    let mut wtxn = vault.store.env.write_txn()?;
    vault
        .store
        .attempt_records
        .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
    wtxn.commit()?;
    Ok(())
}

fn delete_attempt_record(vault: &Vault, id: AttemptId) -> Result<()> {
    let record = AttemptQueue::new(vault).get(id)?.expect("row exists");
    let mut wtxn = vault.store.env.write_txn()?;
    vault.store.delete_attempt_run_index_in_txn(
        &mut wtxn,
        record.run_id.as_deref(),
        id.as_bytes(),
    )?;
    vault
        .store
        .attempt_records
        .delete(&mut wtxn, id.as_bytes())?;
    wtxn.commit()?;
    Ok(())
}

/// Drives `count` consecutive transient failures, returning every row minted
/// along the way (oldest first) plus the still-leased newest row.
fn transient_chain(
    vault: &Vault,
    agent_ref: EntityId,
    policy: &FailureScopePolicy,
    retries: u64,
) -> Result<Vec<AttemptRecord>> {
    let ladder = FailureLadder::new(vault);
    let mut leased = leased_dispatch(vault, agent_ref, 10)?;
    let mut rows = Vec::new();
    for step in 0..retries {
        let now = 20 + step;
        let outcome = ladder
            .handle_attempt_failure(failure_input(&leased, transient(), now), policy.clone())?;
        let FailureLadderOutcome::Retried {
            scheduled_attempt, ..
        } = outcome
        else {
            panic!("expected a retry at step {step}");
        };
        rows.push(leased);
        leased = claim(vault, scheduled_attempt.id, now + 1)?;
    }
    rows.push(leased);
    Ok(rows)
}

fn healer_case(outcome: &FailureLadderOutcome) -> &HealerCase {
    let FailureLadderOutcome::Healer { case, .. } = outcome else {
        panic!("expected a healer outcome, got {outcome:?}");
    };
    case
}

fn human_surface(outcome: &FailureLadderOutcome) -> &SurfacedFailure {
    let FailureLadderOutcome::Human(surface) = outcome else {
        panic!("expected a human surface, got {outcome:?}");
    };
    surface
}

fn every_repair_route(agent_ref: &str, checkpoint_ref: &str) -> Vec<HealerRepairRoute> {
    vec![
        HealerRepairRoute::SkillEdit {
            agent_ref: agent_ref.to_owned(),
            skill_ref: test_id(0x54).to_hex(),
            patch_ref: test_id(0x55).to_hex(),
            diagnosis_ref: test_id(0x56).to_hex(),
        },
        HealerRepairRoute::PromptInjectAndForkResume {
            agent_ref: agent_ref.to_owned(),
            prompt_ref: test_id(0x57).to_hex(),
            checkpoint_ref: checkpoint_ref.to_owned(),
            diagnosis_ref: test_id(0x56).to_hex(),
        },
        HealerRepairRoute::Environment {
            agent_ref: agent_ref.to_owned(),
            environment_ref: test_id(0x58).to_hex(),
            repair_ref: test_id(0x59).to_hex(),
            diagnosis_ref: test_id(0x56).to_hex(),
        },
        HealerRepairRoute::EscalateWithDiagnosis {
            agent_ref: agent_ref.to_owned(),
            diagnosis_ref: test_id(0x56).to_hex(),
        },
    ]
}

// ── classification ──────────────────────────────────────────────────────────

#[test]
fn classifies_typed_retryable_nonretryable_and_indeterminate() {
    assert_eq!(classify_failure(&transient()), FailureClass::Transient);
    assert_eq!(classify_failure(&permanent()), FailureClass::Permanent);
    assert_eq!(classify_failure(&indeterminate()), FailureClass::Ambiguous);
    assert_eq!(
        classify_failure(&evidence(
            TypedFailureVerdict::NonRetryable,
            Some(DetectorTier::T1Tripwire)
        )),
        FailureClass::Permanent,
        "a non-retryable verdict is permanent at every tier"
    );
}

#[test]
fn t2_retryable_classifies_ambiguous_not_transient() {
    for tier in [
        Some(DetectorTier::T2Classifier),
        Some(DetectorTier::T3Judge),
        None,
    ] {
        assert_eq!(
            classify_failure(&evidence(TypedFailureVerdict::Retryable, tier)),
            FailureClass::Ambiguous,
            "only T1 tripwire evidence may spend an automatic retry"
        );
    }
}

// ── bounded retry ───────────────────────────────────────────────────────────

#[test]
fn first_transient_retry_mints_distinct_scheduled_child() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;

    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, transient(), 20),
        auto_policy(agent_ref),
    )?;

    let FailureLadderOutcome::Retried {
        source_attempt_id,
        scheduled_attempt,
        consecutive_transients,
    } = outcome
    else {
        panic!("expected a retry");
    };
    assert_eq!(source_attempt_id, leased.id);
    assert_ne!(scheduled_attempt.id, leased.id);
    assert_eq!(scheduled_attempt.retry_of, Some(leased.id));
    assert_eq!(scheduled_attempt.state, AttemptState::Scheduled);
    assert_eq!(scheduled_attempt.attempt_count, 0);
    assert_eq!(scheduled_attempt.scheduled_at, Some(RETRY_AT));
    assert_eq!(consecutive_transients.get(), 1);

    let queue = AttemptQueue::new(&vault);
    let source = queue.get(leased.id)?.expect("source row");
    assert_eq!(source.state, AttemptState::Failed);
    Ok(())
}

#[test]
fn second_transient_uses_retry_of_depth_not_attempt_count() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 1)?;
    let second = rows.last().expect("second try").clone();

    // Every retry resets the per-row lease fence, so depth cannot come from it.
    assert_eq!(second.attempt_count, 1, "one lease generation on this row");
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&second, transient(), 40), policy)?;

    let FailureLadderOutcome::Retried {
        scheduled_attempt,
        consecutive_transients,
        ..
    } = outcome
    else {
        panic!("expected a second retry");
    };
    assert_eq!(consecutive_transients.get(), 2, "ordinal is retry_of depth");
    assert_eq!(scheduled_attempt.retry_of, Some(second.id));
    assert_eq!(scheduled_attempt.attempt_count, 0);
    Ok(())
}

#[test]
fn third_transient_routes_auto_healer_without_fourth_attempt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
    let third = rows.last().expect("third try").clone();
    let queue = AttemptQueue::new(&vault);
    let before = queue.list()?.len();

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&third, transient(), 60), policy)?;

    let case = healer_case(&outcome);
    assert_eq!(case.failure_class, FailureClass::Transient);
    assert_eq!(case.consecutive_transients, 3);
    assert_eq!(case.failing_attempt_id, third.id);

    assert_eq!(
        queue.get(third.id)?.expect("third row").state,
        AttemptState::Failed
    );
    // A reserved slot enqueues nothing, so the failed source has no retry child.
    assert_eq!(queue.list()?.len(), before, "no fourth attempt was minted");
    assert!(
        queue
            .list()?
            .iter()
            .all(|row| row.retry_of != Some(third.id)),
        "the failed source must have no retry_of child"
    );
    Ok(())
}

#[test]
fn custom_threshold_one_escalates_first_transient() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let policy = policy_with(agent_ref, 1, FailureEscalationMode::Auto);

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, transient(), 20), policy)?;

    let case = healer_case(&outcome);
    assert_eq!(case.consecutive_transients, 1);
    assert_eq!(
        AttemptQueue::new(&vault)
            .get(leased.id)?
            .expect("row")
            .state,
        AttemptState::Failed,
        "N=1 terminalizes the very first transient"
    );
    Ok(())
}

#[test]
fn human_mode_skips_healer_at_threshold() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let policy = policy_with(agent_ref, 1, FailureEscalationMode::Human);

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, transient(), 20), policy)?;

    let surface = human_surface(&outcome);
    assert_eq!(surface.failure_class, FailureClass::Transient);
    assert_eq!(surface.consecutive_transients, 1);
    assert_eq!(surface.healer_slot, None, "Human mode spawns no healer");
    assert_eq!(surface.diagnosis, None);
    Ok(())
}

// ── terminal routing ────────────────────────────────────────────────────────

#[test]
fn permanent_fails_then_routes_healer_and_surface() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;

    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, permanent(), 20),
        auto_policy(agent_ref),
    )?;

    let FailureLadderOutcome::Healer {
        failed_attempt,
        case,
        slot,
        surface,
    } = &outcome
    else {
        panic!("expected a healer outcome");
    };
    assert_eq!(failed_attempt.state, AttemptState::Failed);
    assert_eq!(case.failure_class, FailureClass::Permanent);
    assert_eq!(
        case.consecutive_transients, 0,
        "permanent ordinals are stamped 0 by policy"
    );
    assert_eq!(case.pre_fail_checkpoint_ref, test_id(0x51).to_hex());
    assert_eq!(case.qa_thread_ref, test_id(0x52).to_hex());
    assert_eq!(slot, &HealerSlotOutcome::Reserved { case: case.clone() });
    // The card data is emitted IMMEDIATELY; a diagnosis may still be pending.
    assert_eq!(surface.failure_class, FailureClass::Permanent);
    assert_eq!(surface.pathology, None);
    assert_eq!(surface.diagnosis, None);
    assert_eq!(surface.healer_slot.as_ref(), Some(slot));
    Ok(())
}

#[test]
fn ambiguous_fails_and_surfaces_without_retry_or_healer() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let queue = AttemptQueue::new(&vault);
    let before = queue.list()?.len();

    let ambiguous = evidence(
        TypedFailureVerdict::Retryable,
        Some(DetectorTier::T2Classifier),
    );
    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, ambiguous, 20),
        auto_policy(agent_ref),
    )?;

    let surface = human_surface(&outcome);
    assert_eq!(surface.failure_class, FailureClass::Ambiguous);
    assert_eq!(surface.consecutive_transients, 0);
    assert_eq!(surface.healer_slot, None);
    assert_eq!(surface.pathology, None);
    assert_eq!(queue.list()?.len(), before, "zero blind retries");
    assert_eq!(
        queue.get(leased.id)?.expect("row").state,
        AttemptState::Failed
    );
    Ok(())
}

#[test]
fn indeterminate_without_evidence_ref_classifies_ambiguous() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;

    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, indeterminate(), 20),
        auto_policy(agent_ref),
    )?;

    let surface = human_surface(&outcome);
    assert_eq!(surface.failure_class, FailureClass::Ambiguous);
    assert_eq!(surface.evidence_ref, None);

    // A determinate verdict missing either field, and an empty stable_reason,
    // are both refused BEFORE any transition instead.
    let leased = leased_dispatch(&vault, agent_ref, 30)?;
    let ladder = FailureLadder::new(&vault);
    let mut no_tier = transient();
    no_tier.tier = None;
    let mut blank_reason = transient();
    blank_reason.stable_reason = "   ".to_owned();
    for bad in [no_tier, blank_reason] {
        let error = ladder
            .handle_attempt_failure(failure_input(&leased, bad, 40), auto_policy(agent_ref))
            .expect_err("invalid typed evidence is an invalid-config refusal");
        assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    }
    assert_eq!(
        AttemptQueue::new(&vault)
            .get(leased.id)?
            .expect("row")
            .state,
        AttemptState::Leased
    );
    Ok(())
}

// ── lineage ─────────────────────────────────────────────────────────────────

#[test]
fn missing_retry_parent_is_pathology_not_fresh_chain() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 1)?;
    let source = rows[0].id;
    let second = rows[1].clone();
    delete_attempt_record(&vault, source)?;

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&second, transient(), 40), policy)?;

    let surface = human_surface(&outcome);
    assert_eq!(
        surface.pathology,
        Some(RetryLineagePathology::MissingAncestor {
            missing_attempt_id: source
        }),
        "a missing parent is a pathology, never 'zero previous retries'"
    );
    assert_eq!(surface.failure_class, FailureClass::Ambiguous);
    assert_eq!(surface.consecutive_transients, 0);
    assert_eq!(surface.healer_slot, None);
    Ok(())
}

#[test]
fn retry_cycle_is_pathology_and_walk_is_bounded() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    // The chain is BUILT with headroom (N=4) purely so three retries land and
    // leave a four-row lineage; under the default N=3 the third consecutive
    // transient terminalizes instead of retrying. The bound under test is the
    // limit passed to each `retry_lineage_walk` call below, not this one.
    let policy = policy_with(agent_ref, 4, FailureEscalationMode::Auto);
    let rows = transient_chain(&vault, agent_ref, &policy, 3)?;
    let queue = AttemptQueue::new(&vault);
    let current = queue.get(rows[3].id)?.expect("newest row");

    // The out-of-bound ancestor is DELETED. At N=3 the walk stops at the
    // threshold after exactly N-1 = 2 ancestor reads and never sees it; at N=4
    // the same walk reaches it, which is what proves the earlier stop was the
    // bound and not luck.
    delete_attempt_record(&vault, rows[0].id)?;
    assert_eq!(
        retry_lineage_walk(&queue, &current, NonZeroU16::new(3).expect("three"))?,
        RetryOrdinal::AtLimit(NonZeroU16::new(3).expect("three"))
    );
    assert_eq!(
        retry_lineage_walk(&queue, &current, NonZeroU16::new(4).expect("four"))?,
        RetryOrdinal::Pathology(RetryLineagePathology::MissingAncestor {
            missing_attempt_id: rows[0].id
        })
    );

    // A cycle inside the bound is a pathology, whatever the evidence says.
    repoint_retry_of(&vault, rows[1].id, Some(rows[2].id))?;
    assert_eq!(
        retry_lineage_walk(&queue, &current, NonZeroU16::new(3).expect("three"))?,
        RetryOrdinal::Pathology(RetryLineagePathology::Cycle {
            repeated_attempt_id: rows[2].id
        })
    );

    // The walk is a point-read chain, never a queue scan.
    assert!(!FAILURE_LADDER_SOURCE.contains(".list()"));
    assert!(!FAILURE_LADDER_SOURCE.contains(".list_run("));
    assert!(!FAILURE_LADDER_SOURCE.contains("attempt_count as"));
    Ok(())
}

#[test]
fn cycle_at_threshold_node_is_pathology_not_at_limit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    // current → p1 → p2 → p1, with N = 3.
    let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
    let (p2, p1, current) = (rows[0].id, rows[1].id, rows[2].id);
    repoint_retry_of(&vault, p2, Some(p1))?;

    let queue = AttemptQueue::new(&vault);
    let walk = retry_lineage_walk(
        &queue,
        &queue.get(current)?.expect("current row"),
        NonZeroU16::new(3).expect("three"),
    )?;
    assert_eq!(
        walk,
        RetryOrdinal::Pathology(RetryLineagePathology::Cycle {
            repeated_attempt_id: p1
        }),
        "the repeated-pointer check runs BEFORE the threshold return"
    );
    Ok(())
}

#[test]
fn permanent_with_cyclic_lineage_surfaces_as_pathology() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
    repoint_retry_of(&vault, rows[0].id, Some(rows[1].id))?;
    let current = rows[2].clone();

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&current, permanent(), 60), policy)?;

    let surface = human_surface(&outcome);
    assert_eq!(
        surface.failure_class,
        FailureClass::Ambiguous,
        "pathology outranks the permanent class and never mints a HealerCase"
    );
    assert_eq!(
        surface.pathology,
        Some(RetryLineagePathology::Cycle {
            repeated_attempt_id: rows[1].id
        })
    );
    assert_eq!(surface.healer_slot, None);
    assert_eq!(surface.consecutive_transients, 0);
    Ok(())
}

#[test]
fn pathology_surface_carries_typed_kind_and_offending_attempt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let rows = transient_chain(&vault, agent_ref, &policy, 1)?;
    delete_attempt_record(&vault, rows[0].id)?;

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&rows[1], indeterminate(), 40), policy)?;

    let pathology = human_surface(&outcome)
        .pathology
        .clone()
        .expect("a typed pathology carrier");
    let wire = serde_json::to_string(&pathology).expect("pathology serializes");
    assert!(
        wire.contains("MissingAncestor"),
        "typed kind rides the wire"
    );
    assert!(
        wire.contains("missing_attempt_id"),
        "the offending attempt rides the wire beside its kind"
    );
    match pathology {
        RetryLineagePathology::MissingAncestor { missing_attempt_id } => {
            assert_eq!(missing_attempt_id, rows[0].id);
        }
        RetryLineagePathology::Cycle { .. } => panic!("expected a missing-ancestor pathology"),
    }
    Ok(())
}

// ── fences ──────────────────────────────────────────────────────────────────

#[test]
fn scope_agent_mismatch_is_rejected_before_transition() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let other_ref = put_scope_agent(&vault, 0x33, "oneiron.agent.other")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let ladder = FailureLadder::new(&vault);

    let error = ladder
        .handle_attempt_failure(
            failure_input(&leased, permanent(), 20),
            auto_policy(other_ref),
        )
        .expect_err("a foreign scope cannot terminalize this row");
    assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    assert_eq!(
        AttemptQueue::new(&vault)
            .get(leased.id)?
            .expect("row")
            .state,
        AttemptState::Leased,
        "the refusal lands BEFORE any transition"
    );

    // A row that carries no agent-dispatch lineage at all is refused the same
    // way: there is nothing to bind the scope to.
    let EnqueueDreamerAttemptOutcome::Enqueued(plain) =
        DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
            attempt_type: "plain.worker".to_owned(),
            input: Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(RUN_ID.to_owned()),
            now: 30,
        })?
    else {
        panic!("expected a fresh enqueue");
    };
    let plain = claim(&vault, plain.attempt.id, 31)?;
    let error = ladder
        .handle_attempt_failure(
            failure_input(&plain, permanent(), 32),
            auto_policy(agent_ref),
        )
        .expect_err("a non-dispatch row has no scope binding");
    assert_eq!(error.kind(), crate::ErrorKind::InvalidConfig);
    assert_eq!(
        AttemptQueue::new(&vault).get(plain.id)?.expect("row").state,
        AttemptState::Leased
    );
    Ok(())
}

#[test]
fn second_failure_input_on_failed_row_routes_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let ladder = FailureLadder::new(&vault);
    let policy = auto_policy(agent_ref);
    ladder.handle_attempt_failure(failure_input(&leased, permanent(), 20), policy.clone())?;
    let queue = AttemptQueue::new(&vault);
    let after_winner = queue.list()?.len();

    let error = ladder
        .handle_attempt_failure(failure_input(&leased, permanent(), 30), policy)
        .expect_err("the losing failure input routes nothing");
    assert_eq!(
        error.kind(),
        crate::ErrorKind::InvalidAttemptQueueTransition
    );
    assert_eq!(queue.list()?.len(), after_winner, "no second route ran");
    assert_eq!(
        queue.get(leased.id)?.expect("row").updated_at,
        20,
        "the winner's terminal transition is authoritative"
    );
    Ok(())
}

// ── report_blocked intake ───────────────────────────────────────────────────

#[test]
fn report_blocked_intake_is_issues_only_and_non_triggering() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let receipt = put_receipt_message(&vault, 0x61, 0)?;
    let queue = AttemptQueue::new(&vault);
    let before = queue.list()?;

    let entry = ingest_report_blocked(
        &vault,
        BlockedReportRef {
            receipt_ref: receipt.to_hex(),
        },
    )?;

    assert!(entry.semi_trusted, "a report is evidence, never an arm");
    assert_eq!(entry.report.receipt_ref, receipt.to_hex());
    // Zero queue, dispatch, landing, and human mutations.
    assert_eq!(queue.list()?, before);
    let row = queue.get(leased.id)?.expect("row");
    assert_eq!(row.state, AttemptState::Leased);
    assert!(row.cancel_receipts().is_empty());
    assert_eq!(row.cancellation(), None);
    Ok(())
}

#[test]
fn unverifiable_blocked_report_is_dropped_with_typed_note() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let receipt = put_receipt_message(&vault, 0x61, 0)?;
    // Valid hex that resolves to nothing, plus a ref that is not hex at all.
    let ghost = test_id(0x62).to_hex();
    let reports = vec![
        BlockedReportRef {
            receipt_ref: receipt.to_hex(),
        },
        BlockedReportRef {
            receipt_ref: ghost.clone(),
        },
        BlockedReportRef {
            receipt_ref: "not-hex".to_owned(),
        },
    ];

    let verified = verify_blocked_reports(&vault, &reports)?;
    assert_eq!(
        verified,
        vec![
            BlockedReportVerification::Verified(reports[0].clone()),
            BlockedReportVerification::Dropped { receipt_ref: ghost },
            BlockedReportVerification::Dropped {
                receipt_ref: "not-hex".to_owned()
            },
        ]
    );
    assert_eq!(
        ingest_report_blocked(&vault, reports[1].clone())
            .expect_err("an unverifiable ref is refused")
            .kind(),
        crate::ErrorKind::InvalidConfig
    );

    // The dropped values never reach a case or a card.
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let mut input = failure_input(&leased, permanent(), 20);
    input.blocked_reports = reports.clone();
    let outcome =
        FailureLadder::new(&vault).handle_attempt_failure(input, auto_policy(agent_ref))?;
    let case = healer_case(&outcome);
    assert_eq!(case.blocked_reports, vec![reports[0].clone()]);
    Ok(())
}

#[test]
fn report_blocked_cannot_override_typed_classification() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let receipt = put_receipt_message(&vault, 0x61, 0)?;
    let report = BlockedReportRef {
        receipt_ref: receipt.to_hex(),
    };
    let ladder = FailureLadder::new(&vault);
    let policy = auto_policy(agent_ref);

    // Attached to a transient below the limit, the report changes nothing.
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let mut input = failure_input(&leased, transient(), 20);
    input.blocked_reports = vec![report.clone()];
    let outcome = ladder.handle_attempt_failure(input, policy.clone())?;
    let FailureLadderOutcome::Retried {
        scheduled_attempt, ..
    } = outcome
    else {
        panic!("a verified report cannot turn a T1 transient into anything else");
    };

    // Attached to a permanent failure it rides the case but does not reclassify.
    let leased = claim(&vault, scheduled_attempt.id, 40)?;
    let mut input = failure_input(&leased, permanent(), 50);
    input.blocked_reports = vec![report.clone()];
    let outcome = ladder.handle_attempt_failure(input, policy)?;
    let case = healer_case(&outcome);
    assert_eq!(case.failure_class, FailureClass::Permanent);
    assert_eq!(case.blocked_reports, vec![report]);
    Ok(())
}

// ── composition and healer vocabulary ───────────────────────────────────────

#[test]
fn handle_attempt_failure_composes_queue_healer_and_surface() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let policy = auto_policy(agent_ref);
    let queue = AttemptQueue::new(&vault);

    // Two retries, then the threshold escalation — one end-to-end drive.
    let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&rows[2], transient(), 60), policy)?;

    let FailureLadderOutcome::Healer {
        failed_attempt,
        case,
        slot,
        surface,
    } = &outcome
    else {
        panic!("expected the threshold healer outcome");
    };
    assert_eq!(failed_attempt.id, rows[2].id);
    assert_eq!(failed_attempt.state, AttemptState::Failed);
    assert_eq!(case.case_ref, failure_case_ref(rows[2].id));
    assert_ne!(case.case_ref, failure_card_ref(rows[2].id));
    assert_eq!(case.evidence_ref, test_id(0x53).to_hex());
    assert_eq!(case.scope.agent_ref, agent_ref.to_hex());
    assert_eq!(slot, &HealerSlotOutcome::Reserved { case: case.clone() });
    assert_eq!(surface.consecutive_transients, 3);
    assert_eq!(surface.evidence_ref, Some(test_id(0x53)));
    assert_eq!(surface.pre_fail_checkpoint_ref, test_id(0x51));

    // Exactly one row per try: three tries, no fourth.
    assert_eq!(queue.list()?.len(), 3);
    Ok(())
}

#[test]
fn healer_repair_route_cannot_target_task_payload() {
    let agent_ref = test_id(0x31).to_hex();
    let checkpoint_ref = test_id(0x51).to_hex();
    for route in every_repair_route(&agent_ref, &checkpoint_ref) {
        // Exhaustive: a task-targeted variant would fail to compile here.
        let named = match &route {
            HealerRepairRoute::SkillEdit { agent_ref, .. }
            | HealerRepairRoute::PromptInjectAndForkResume { agent_ref, .. }
            | HealerRepairRoute::Environment { agent_ref, .. }
            | HealerRepairRoute::EscalateWithDiagnosis { agent_ref, .. } => agent_ref,
        };
        assert_eq!(named, &agent_ref, "every route names the failing AGENT");
        let wire = serde_json::to_string(&route).expect("route serializes");
        assert!(!wire.contains("task"), "no repair route may name a task");
        assert!(
            !wire.contains("payload"),
            "no repair route carries a payload"
        );
        assert!(
            !wire.contains("attempt"),
            "no repair route reopens an attempt"
        );
    }
}

#[test]
fn prompt_inject_route_uses_prefail_checkpoint_not_terminal_attempt() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, permanent(), 20),
        auto_policy(agent_ref),
    )?;
    let case = healer_case(&outcome);

    let route = HealerRepairRoute::PromptInjectAndForkResume {
        agent_ref: case.scope.agent_ref.clone(),
        prompt_ref: test_id(0x57).to_hex(),
        checkpoint_ref: case.pre_fail_checkpoint_ref.clone(),
        diagnosis_ref: test_id(0x56).to_hex(),
    };
    let HealerRepairRoute::PromptInjectAndForkResume { checkpoint_ref, .. } = &route else {
        panic!("constructed the fork-resume route");
    };
    assert_eq!(checkpoint_ref, &test_id(0x51).to_hex());
    assert_ne!(
        checkpoint_ref,
        &crate::entity_id::bytes_to_hex_lower(leased.id.as_bytes()),
        "a fork resumes from the pre-fail checkpoint, never the terminal attempt"
    );
    Ok(())
}

#[test]
fn reserved_healer_slot_is_explicit_outcome() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let policy = auto_policy(agent_ref);
    assert_eq!(policy.healer_slot, HealerSlot::Reserved);
    assert_eq!(
        policy.max_consecutive_transients,
        DEFAULT_MAX_CONSECUTIVE_TRANSIENTS
    );
    assert_eq!(policy.escalation_mode, FailureEscalationMode::Auto);

    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, permanent(), 20), policy)?;
    let FailureLadderOutcome::Healer { slot, .. } = &outcome else {
        panic!("a reserved slot is a typed outcome, not a dropped case");
    };
    assert!(matches!(slot, HealerSlotOutcome::Reserved { .. }));
    Ok(())
}

#[test]
fn healer_outcomes_carry_immediate_surface_data() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;

    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, permanent(), 20),
        auto_policy(agent_ref),
    )?;
    let FailureLadderOutcome::Healer {
        case,
        slot,
        surface,
        ..
    } = &outcome
    else {
        panic!("expected a healer outcome");
    };

    // Every healer outcome carries card-input data immediately, with the
    // diagnosis still pending.
    assert_eq!(surface.diagnosis, None);
    assert_eq!(surface.healer_slot.as_ref(), Some(slot));
    assert_eq!(surface.failed_attempt.id, case.failing_attempt_id);
    assert_eq!(surface.qa_thread_ref, test_id(0x52));
    assert!(surface.blocked_reports.is_empty());
    Ok(())
}

#[test]
fn healer_code_exposes_no_force_cancel_handle() -> Result<()> {
    for source in [FAILURE_LADDER_SOURCE, AGENT_DISPATCH_SOURCE] {
        for banned in ["force_cancel", "ForceAttemptCancel", "ForceCancel"] {
            assert!(
                !source.contains(banned),
                "no healer path may reach {banned}; a soft stop rides ONE-1896's \
                 public request/landing API instead"
            );
        }
    }

    // Behaviourally too: a healer-routed failure records no cancellation.
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&leased, permanent(), 20),
        auto_policy(agent_ref),
    )?;

    let row = AttemptQueue::new(&vault).get(leased.id)?.expect("row");
    assert_eq!(row.cancellation(), None);
    assert!(row.cancel_receipts().is_empty());
    assert_eq!(row.cancel_pressure().requests, 0);
    Ok(())
}
