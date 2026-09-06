use super::*;
use crate::attempt_queue::{
    AcceptAttemptLanding, AttemptResumePoint, FinishAttemptLanding, FinishLandingOutcome,
    LandingOutcome, LandingTrigger,
};
use crate::genui::{
    FailureDiagnosisState, HealerQaFeed, SurfacedFailureCardInput, surfaced_failure_card,
};
use crate::run_tree::RunTreeAdapter;

#[test]
fn cancelled_landing_predecessor_counts_toward_transient_limit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let queue = AttemptQueue::new(&vault);
    let LandingOutcome::Landing(_) = queue.accept_landing(AcceptAttemptLanding {
        id: leased.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: leased.attempt_count,
        trigger: LandingTrigger::BudgetWarning,
        status: None,
        resume_point: Some(AttemptResumePoint::new("checkpoint", 11)),
        request_sequence: None,
        now: 11,
    })?
    else {
        panic!("expected a fresh landing");
    };
    let FinishLandingOutcome::HandedOff { landed, successor } =
        queue.finish_landing(FinishAttemptLanding {
            id: leased.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: leased.attempt_count,
            hand_off: true,
            scheduled_at: None,
            now: 12,
        })?
    else {
        panic!("expected a landing successor");
    };
    assert_eq!(landed.state, AttemptState::Cancelled);
    assert_eq!(successor.retry_of, Some(landed.id));
    let failing = claim(&vault, successor.id, 13)?;
    let before = queue.list()?.len();

    let outcome = FailureLadder::new(&vault).handle_attempt_failure(
        failure_input(&failing, transient(), 20),
        policy_with(agent_ref, 2, FailureEscalationMode::Human),
    )?;
    let surface = human_surface(&outcome);
    assert_eq!(surface.failure_class, FailureClass::Transient);
    assert_eq!(surface.consecutive_transients, 2);
    assert_eq!(surface.failed_attempt.state, AttemptState::Failed);
    assert_eq!(surface.healer_slot, None);
    assert_eq!(
        queue.list()?.len(),
        before,
        "no retry or healer was enqueued"
    );
    assert_eq!(queue.get(landed.id)?, Some(landed));
    Ok(())
}

#[test]
fn public_card_and_ladder_emit_the_same_verified_blocked_reports() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let receipt = put_receipt_message(&vault, 0x61, 0)?;
    let report = BlockedReportRef {
        receipt_ref: receipt.to_hex(),
    };
    let reports = vec![
        BlockedReportRef {
            receipt_ref: "not-hex".to_owned(),
        },
        BlockedReportRef {
            receipt_ref: agent_ref.to_hex(),
        },
        report.clone(),
    ];
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let mut input = failure_input(&leased, permanent(), 20);
    input.blocked_reports = reports.clone();
    let outcome =
        FailureLadder::new(&vault).handle_attempt_failure(input, auto_policy(agent_ref))?;
    let FailureLadderOutcome::Healer { case, surface, .. } = outcome else {
        panic!("expected a reserved healer and immediate surface");
    };

    // Read the post-fail tree, but send the ORIGINAL unfiltered reports to the
    // public door so a caller cannot bypass the ladder's verification floor.
    let card = surfaced_failure_card(
        &vault,
        SurfacedFailureCardInput {
            failure_class: surface.failure_class,
            consecutive_transients: surface.consecutive_transients,
            pathology: surface.pathology,
            tree: RunTreeAdapter::new(&vault).read_run(RUN_ID)?,
            failing_attempt_id: leased.id,
            diagnosis: FailureDiagnosisState::ReservedHealerSlot,
            blocked_reports: reports,
            qa: HealerQaFeed {
                thread_ref: surface.qa_thread_ref.to_hex(),
                entries: Vec::new(),
            },
        },
    )?;
    assert_eq!(card.blocked_reports, vec![report]);
    assert_eq!(card.blocked_reports, case.blocked_reports);
    assert_eq!(card.blocked_reports, surface.blocked_reports);
    Ok(())
}
