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

mod custom_review;
mod drill;
mod failure_integrity;

const LEASE_OWNER: &str = "failure-ladder-worker";
const RUN_ID: &str = "run-1887";
/// The caller's existing backoff policy picks this; the ladder only forwards it.
const RETRY_AT: u64 = 5;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

/// A stored, dispatchable AGENT_DEF row the failure scope can bind to.
fn put_scope_agent(vault: &Vault, seed: u8, agent_id: &str) -> Result<EntityId> {
    put_scope_agent_with_ceiling(vault, seed, agent_id, AgentCeiling::Proposed)
}

fn put_scope_agent_with_ceiling(
    vault: &Vault,
    seed: u8,
    agent_id: &str,
    ceiling: AgentCeiling,
) -> Result<EntityId> {
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
        ceiling,
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

/// A canonical report-blocked receipt fixture. Actual dispatch and refusal
/// of guest-created receipts are covered by the code-run boundary tests.
fn put_receipt_message(vault: &Vault, seed: u8, order: u32) -> Result<EntityId> {
    let id = test_id(seed);
    let body = crate::gate::canonical_witness_message_body_for_test(
        "companion",
        crate::code_run::blocked::BLOCKED_REPORT_MESSAGE_TYPE,
        &crate::code_run::blocked::BlockedReceipt::new(
            crate::code_run::blocked::BlockedCategory::Tool,
            "blocked report",
        )?
        .content()?,
        false,
        order,
    )?;
    vault
        .batch()
        .put_canonical_message_for_test(&id, TimeRange { start: 7, end: 7 }, 7, &body)
        .commit()?;
    Ok(id)
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
    let FailureLadderOutcome::Healer(healer) = outcome else {
        panic!("expected a healer outcome, got {outcome:?}");
    };
    &healer.case
}

fn human_surface(outcome: &FailureLadderOutcome) -> &SurfacedFailure {
    let FailureLadderOutcome::Human(surface) = outcome else {
        panic!("expected a human surface, got {outcome:?}");
    };
    surface
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
    assert_eq!(
        DreamerRunnerStore::new(&vault)
            .run_tree(scheduled_attempt.id)?
            .unwrap()
            .attempt_id,
        scheduled_attempt.id,
        "a retry must carry its private runner tree in the same transaction"
    );
    assert_eq!(consecutive_transients.get(), 1);

    let queue = AttemptQueue::new(&vault);
    let source = queue.get(leased.id)?.expect("source row");
    assert_eq!(source.state, AttemptState::Failed);
    Ok(())
}

// ── terminal routing ────────────────────────────────────────────────────────

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
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let ladder = FailureLadder::new(&vault);
    let policy = auto_policy(agent_ref);
    store_clock.set(20);
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

    let FailureLadderOutcome::Healer(healer) = &outcome else {
        panic!("expected the threshold healer outcome");
    };
    let HealerOutcome {
        case,
        slot,
        surface,
    } = healer.as_ref();
    assert_eq!(surface.failed_attempt.id, rows[2].id);
    assert_eq!(surface.failed_attempt.state, AttemptState::Failed);
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
fn malformed_healer_scope_cannot_commit_a_failure_or_case() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let healer = put_scope_agent(&vault, 0x32, "oneiron.agent.healer")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    for (skill_ref, expected) in [
        ("not-a-reference".to_owned(), crate::ErrorKind::InvalidKey),
        (
            "1234567890abcdef1234567890abcdef".to_uppercase(),
            crate::ErrorKind::InvalidConfig,
        ),
    ] {
        for slot in [
            crate::agent_dispatch::HealerSlot::Reserved,
            crate::agent_dispatch::HealerSlot::AgentDef {
                agent_def_ref: healer.to_hex(),
            },
        ] {
            let mut policy = auto_policy(agent_ref);
            policy.healer_slot = slot;
            policy.scope.skill_ref = Some(skill_ref.clone());
            let error = FailureLadder::new(&vault)
                .handle_attempt_failure(failure_input(&leased, permanent(), 20), policy)
                .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert_eq!(
                AttemptQueue::new(&vault).get(leased.id)?.unwrap().state,
                AttemptState::Leased
            );
            let key = [
                b"healer:case:v1:".as_slice(),
                failure_case_ref(leased.id).as_bytes(),
            ]
            .concat();
            let txn = vault.store.env.read_txn()?;
            assert!(vault.store.vault_meta.get(&txn, &key)?.is_none());
        }
    }
    Ok(())
}

/// The runner's production typed-evidence door, not a direct policy-unit call.
#[test]
fn runner_typed_failure_dispatches_case_bound_propose_only_healer() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let healer = put_scope_agent(&vault, 0x32, "oneiron.agent.healer")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    let mut policy = auto_policy(agent);
    policy.healer_slot = crate::agent_dispatch::HealerSlot::AgentDef {
        agent_def_ref: healer.to_hex(),
    };
    let runner = DreamerRunnerStore::new(&vault);
    let outcome = runner.fail_agent_dispatch_with_evidence(
        failure_input(&leased, permanent(), 20),
        policy.clone(),
    )?;
    let FailureLadderOutcome::Healer(result) = outcome else {
        panic!("permanent evidence must dispatch a healer");
    };
    let HealerSlotOutcome::Dispatched(status) = &result.slot else {
        panic!("configured healer must dispatch");
    };
    assert_eq!(status.input.healer_case.as_ref(), Some(&result.case));
    assert_eq!(status.attempt.run_id, leased.run_id);
    assert_eq!(status.input.definition.ceiling, AgentCeiling::Proposed);
    assert_eq!(status.input.depth_remaining, Some(1));
    assert_eq!(
        AttemptQueue::new(&vault).get(leased.id)?.unwrap().state,
        AttemptState::Failed
    );
    assert!(
        runner
            .fail_agent_dispatch_with_evidence(failure_input(&leased, permanent(), 21), policy,)
            .is_err(),
        "a second delivery must not dispatch another healer"
    );
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), 2);
    Ok(())
}

#[test]
fn runner_untyped_failure_cannot_bypass_agent_dispatch_ladder() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent, 10)?;
    DreamerRunnerStore::new(&vault)
        .fail(crate::dreamer_runner::FailDreamerAttempt {
            id: leased.id,
            lease_owner: LEASE_OWNER.into(),
            attempt_count: leased.attempt_count,
            reason: "opaque prose".into(),
            now: 20,
        })
        .expect_err("agent failure requires typed evidence");
    assert_eq!(
        AttemptQueue::new(&vault).get(leased.id)?.unwrap().state,
        AttemptState::Leased
    );
    Ok(())
}

/// One bounded healer executes its reference-context handoff through ScopedRead
/// before it diagnoses. Merely copying case refs into an enqueue payload is
/// insufficient to pass this composition test.
#[test]
fn permanent_failure_healer_reads_diagnostic_and_emits_case_bound_proposal() -> Result<()> {
    use crate::agent_dispatch::{DispatchHealer, HealerSlot};
    use crate::edge::EdgeActorClass;
    use crate::self_heal::{
        DiagnosticCriticality, DiagnosticEvent, DiagnosticEventClass, DiagnosticReplayCoordinate,
        DiagnosticSourceKind, RepairConsentRoute, RepairOperation, diagnostic_event_id,
        encode_diagnostic_event_body,
    };
    use crate::write_envelope::WriteActor;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    let agent = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let healer = put_scope_agent(&vault, 0x32, "oneiron.agent.healer")?;
    let checkpoint = test_id(0x51);
    let thread = test_id(0x52);
    vault.put_entity(
        &checkpoint,
        crate::registry::ENTITY_TYPE_ASSET,
        TimeRange { start: 1, end: 1 },
        1,
        b"pre-fail checkpoint fixture",
    )?;
    vault.put_entity(
        &thread,
        crate::registry::ENTITY_TYPE_CONVERSATION,
        TimeRange { start: 1, end: 1 },
        1,
        &crate::conversation::ConversationBody::default().to_bytes()?,
    )?;
    let diagnostic = DiagnosticEvent {
        detector_id: "test.permanent_failure".into(),
        event_class: DiagnosticEventClass::McpActionRejected,
        actor_class: "system".into(),
        actor_ref: None,
        source: DiagnosticSourceKind::Receipt,
        criticality: DiagnosticCriticality::Normal,
        expected: Value::from(1),
        actual: Value::from(0),
        delta: Value::from(-1),
        replay: DiagnosticReplayCoordinate {
            content_hash: [7; 32],
            run_ref: Some(RUN_ID.into()),
            checkpoint_ref: Some(checkpoint.to_hex()),
        },
        evidence_refs: vec![checkpoint],
        untrusted_detail: None,
        valid_from: 1,
        valid_to: None,
    };
    let diagnostic_id = diagnostic_event_id(
        &diagnostic.detector_id,
        &encode_diagnostic_event_body(&diagnostic)?,
    );
    vault.emit_diagnostic_event(&diagnostic_id, &diagnostic)?;
    crate::test_util::authorize_readers(&vault, &[healer.to_hex().as_str()]);
    let leased = leased_dispatch(&vault, agent, 10)?;
    let mut input = failure_input(&leased, permanent(), 20);
    input.evidence.evidence_ref = Some(diagnostic_id.to_hex());
    input.pre_fail_checkpoint_ref = checkpoint;
    input.qa_thread_ref = thread;
    let mut policy = auto_policy(agent);
    policy.healer_slot = HealerSlot::AgentDef {
        agent_def_ref: healer.to_hex(),
    };
    let FailureLadderOutcome::Healer(routed) =
        DreamerRunnerStore::new(&vault).fail_agent_dispatch_with_evidence(input, policy)?
    else {
        panic!("permanent evidence routes a healer");
    };
    let HealerSlotOutcome::Dispatched(dispatched) = &routed.slot else {
        panic!("case-bound healer dispatched");
    };
    assert_eq!(dispatched.input.depth_remaining, Some(1));
    let case = dispatched
        .input
        .healer_case
        .as_ref()
        .expect("healer receives case refs");
    assert_eq!(case.evidence_ref, diagnostic_id.to_hex());
    assert_eq!(case.pre_fail_checkpoint_ref, checkpoint.to_hex());
    assert_eq!(case.qa_thread_ref, thread.to_hex());
    let actor = WriteActor::new(healer, EdgeActorClass::Agent);
    let registration = vault.register_prod_healer(actor);
    let read = vault.scoped_read(
        crate::claim::ScopedReadActorKey::new(healer.to_hex()).expect("healer identity"),
    );
    assert!(
        read.read(&[crate::claim::PointRead::id(checkpoint)], None)?
            .single()
            .value
            .is_some()
    );
    assert!(
        read.read(&[crate::claim::PointRead::id(thread)], None)?
            .single()
            .value
            .is_some()
    );
    let (read_id, observed) = registration
        .failure_corpus()?
        .value
        .into_iter()
        .find(|(id, _)| id.to_hex() == case.evidence_ref)
        .expect("healer can read its durable diagnostic through ScopedRead");
    assert_eq!(read_id, diagnostic_id);
    assert_eq!(
        observed.replay.checkpoint_ref.as_deref(),
        Some(case.pre_fail_checkpoint_ref.as_str())
    );
    let route = match observed.event_class {
        DiagnosticEventClass::McpActionRejected => HealerRepairRoute::PromptInjectAndForkResume {
            agent_ref: case.scope.agent_ref.clone(),
            prompt_ref: observed.evidence_refs[0].to_hex(),
            checkpoint_ref: case.pre_fail_checkpoint_ref.clone(),
            diagnosis_ref: read_id.to_hex(),
        },
        _ => panic!("unexpected detector family"),
    };
    let ClaimOutcome::Claimed(healer_lease) = AttemptQueue::new(&vault).claim(ClaimAttempt {
        lease_owner: LEASE_OWNER.into(),
        now: 21,
    })?
    else {
        panic!("healer lease");
    };
    assert_eq!(healer_lease.id, dispatched.attempt.id);
    let proposal_id = test_id(0x81);
    let bundle = AgentDispatcher::new(&vault).propose_healer_repair(
        healer_lease.id,
        LEASE_OWNER,
        healer_lease.attempt_count,
        proposal_id,
        route.clone(),
        "healer-read-session",
    )?;
    assert_eq!(
        bundle.proposals()[0].route(),
        RepairConsentRoute::HumanReview
    );
    assert!(matches!(&bundle.proposals()[0].proposal().operation,
        RepairOperation::FixAgent {case_ref, route: actual}
            if case_ref == &case.case_ref && actual == &route));
    assert_eq!(
        vault.healer_proposal(&proposal_id)?.unwrap().state,
        crate::self_heal::healer_host::ProposalState::Proposed
    );
    let above = put_scope_agent_with_ceiling(
        &vault,
        0x33,
        "oneiron.agent.above_propose",
        AgentCeiling::Auto,
    )?;
    let error = AgentDispatcher::new(&vault)
        .dispatch_healer_slot(DispatchHealer {
            slot: HealerSlot::AgentDef {
                agent_def_ref: above.to_hex(),
            },
            case: routed.case.clone(),
            run_id: Some(RUN_ID.into()),
            now: 22,
        })
        .expect_err("above-Proposed healer cannot be dispatched");
    assert_eq!(error.kind(), crate::ErrorKind::AgentNotDispatchable);
    assert_eq!(
        AttemptQueue::new(&vault).list()?.len(),
        2,
        "a proposal never executes a fork or task retry"
    );
    Ok(())
}
