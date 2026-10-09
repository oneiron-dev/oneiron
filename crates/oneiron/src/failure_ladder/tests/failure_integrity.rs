use super::*;
use crate::attempt_queue::{AcceptAttemptLanding, LandingOutcome, LandingTrigger};
use crate::error::ArtifactError;
use crate::genui::{
    FailureDiagnosisState, HealerQaFeed, SurfacedFailureCardInput, surfaced_failure_card,
};
use crate::run_tree::RunTreeAdapter;

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
    let FailureLadderOutcome::Healer(healer) = outcome else {
        panic!("expected a reserved healer and immediate surface");
    };
    let HealerOutcome { case, surface, .. } = *healer;

    // Read the post-fail tree, but send the ORIGINAL unfiltered reports to the
    // public door so a caller cannot bypass the ladder's verification floor.
    let card = surfaced_failure_card(
        &vault,
        SurfacedFailureCardInput {
            failure_class: surface.failure_class,
            consecutive_transients: surface.consecutive_transients,
            pathology: surface.pathology,
            retry_lineage_limit: auto_policy(agent_ref).max_consecutive_transients,
            tree: RunTreeAdapter::new(&vault).read_run(RUN_ID)?,
            failing_attempt_id: leased.id,
            pre_fail_checkpoint_ref: surface.pre_fail_checkpoint_ref,
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

/// Reach each lifecycle state through queue verbs, never by rewriting a row.
fn card_attempt_in_state(
    vault: &Vault,
    agent_ref: EntityId,
    state: AttemptState,
) -> Result<AttemptRecord> {
    use crate::attempt_queue::{
        AbandonAttempt, AbandonOutcome, AttemptInterventionKind, AttemptResultRef, CompleteAttempt,
        CompleteOutcome, InterveneAttempt,
    };

    let queue = AttemptQueue::new(vault);
    let dispatched = dispatch_attempt(vault, agent_ref, 10)?;
    let current = match state {
        AttemptState::Queued | AttemptState::Paused | AttemptState::Cancelled => dispatched,
        AttemptState::Leased
        | AttemptState::Completed
        | AttemptState::Failed
        | AttemptState::Scheduled
        | AttemptState::Landing
        | AttemptState::Abandoned => claim(vault, dispatched.id, 20)?,
    };
    match state {
        AttemptState::Queued | AttemptState::Leased => Ok(current),
        AttemptState::Paused | AttemptState::Cancelled => {
            let intervention = queue.intervene(InterveneAttempt {
                id: current.id,
                kind: if state == AttemptState::Paused {
                    AttemptInterventionKind::Pause
                } else {
                    AttemptInterventionKind::Cancel
                },
                actor: LEASE_OWNER.to_owned(),
                note: None,
                now: 30,
            })?;
            Ok(intervention.record)
        }
        AttemptState::Completed => {
            let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
                id: current.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: current.attempt_count,
                now: 30,
            })?
            else {
                panic!("expected a fresh completion");
            };
            Ok(completed)
        }
        AttemptState::Failed => {
            let FailureLadderOutcome::Healer(healed) = FailureLadder::new(vault)
                .handle_attempt_failure(
                    failure_input(&current, permanent(), 30),
                    auto_policy(agent_ref),
                )?
            else {
                panic!("expected a fresh typed failure");
            };
            Ok(healed.surface.failed_attempt)
        }
        AttemptState::Scheduled => {
            let RetryOutcome::Retried(scheduled) = queue.retry(RetryAttempt {
                id: current.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: current.attempt_count,
                backoff_until: 40,
                last_error: Some("detector.stable_code".to_owned()),
                now: 30,
            })?;
            Ok(scheduled)
        }
        AttemptState::Landing => {
            let LandingOutcome::Landing(landing) = queue.accept_landing(AcceptAttemptLanding {
                id: current.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: current.attempt_count,
                trigger: LandingTrigger::BudgetWarning,
                status: None,
                resume_point: None,
                request_sequence: None,
                now: 30,
            })?
            else {
                panic!("expected a fresh landing");
            };
            Ok(landing)
        }
        AttemptState::Abandoned => {
            let AbandonOutcome::Abandoned(abandoned) = queue.abandon(AbandonAttempt {
                id: current.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: current.attempt_count,
                result_ref: AttemptResultRef::new("blob-artifact:aa@1")?,
                reason: "executor stopped without delivering".to_owned(),
                now: 30,
            })?
            else {
                panic!("expected a fresh abandonment");
            };
            Ok(abandoned)
        }
    }
}

#[test]
fn abandoned_attempt_routes_no_late_failure() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let abandoned = card_attempt_in_state(&vault, agent_ref, AttemptState::Abandoned)?;
    assert!(abandoned.state.is_terminal());
    assert!(!abandoned.state.is_running());
    assert_eq!(abandoned.lease_owner, None);
    let queue = AttemptQueue::new(&vault);
    let before = queue.list()?;
    let tree = RunTreeAdapter::new(&vault).read_run(RUN_ID)?;

    // Late evidence cannot reopen the terminal row or route a retry, healer, or surface.
    for (evidence, expected_action) in [
        (transient(), "retry"),
        (permanent(), "fail"),
        (indeterminate(), "fail"),
    ] {
        let error = FailureLadder::new(&vault)
            .handle_attempt_failure(
                failure_input(&abandoned, evidence, 40),
                auto_policy(agent_ref),
            )
            .expect_err("an abandoned attempt must stay settled");
        assert!(matches!(
            error,
            Error::Artifact(ArtifactError::InvalidAttemptQueueTransition { action, state: "abandoned" })
                if action == expected_action
        ));
        assert_eq!(queue.list()?, before, "no row was changed or enqueued");
        assert_eq!(RunTreeAdapter::new(&vault).read_run(RUN_ID)?, tree);
    }
    Ok(())
}
