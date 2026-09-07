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

fn pathology_card_input(
    vault: &Vault,
    surface: &SurfacedFailure,
    limit: NonZeroU16,
) -> Result<SurfacedFailureCardInput> {
    Ok(SurfacedFailureCardInput {
        failure_class: surface.failure_class,
        consecutive_transients: surface.consecutive_transients,
        pathology: surface.pathology.clone(),
        retry_lineage_limit: limit,
        tree: RunTreeAdapter::new(vault).read_run(RUN_ID)?,
        failing_attempt_id: surface.failed_attempt.id,
        pre_fail_checkpoint_ref: surface.pre_fail_checkpoint_ref,
        diagnosis: FailureDiagnosisState::NotRun,
        blocked_reports: surface.blocked_reports.clone(),
        qa: HealerQaFeed {
            thread_ref: surface.qa_thread_ref.to_hex(),
            entries: Vec::new(),
        },
    })
}

#[test]
fn public_card_rejects_fabricated_pathology_and_missing_failing_row() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    let policy = auto_policy(agent_ref);
    let limit = policy.max_consecutive_transients;
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, indeterminate(), 20), policy)?;
    let input = pathology_card_input(&vault, human_surface(&outcome), limit)?;
    let missing = AttemptId::from_bytes(&[0x7a; 16])?;
    let before = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        surfaced_failure_card(&vault, input.clone())?.pathology,
        None
    );
    for pathology in [
        RetryLineagePathology::MissingAncestor {
            missing_attempt_id: missing,
        },
        RetryLineagePathology::Cycle {
            repeated_attempt_id: leased.id,
        },
    ] {
        let mut forged = input.clone();
        forged.pathology = Some(pathology);
        assert!(matches!(
            surfaced_failure_card(&vault, forged),
            Err(Error::InvalidConfig(_))
        ));
    }

    // A missing current row is not proof of a missing retry ancestor.
    let mut absent = input;
    absent.failing_attempt_id = missing;
    absent.tree.roots[0].attempt_id = crate::entity_id::bytes_to_hex_lower(missing.as_bytes());
    assert_eq!(
        surfaced_failure_card(&vault, absent.clone())?.pathology,
        None
    );
    absent.pathology = Some(RetryLineagePathology::MissingAncestor {
        missing_attempt_id: missing,
    });
    assert!(matches!(
        surfaced_failure_card(&vault, absent),
        Err(Error::InvalidConfig(_))
    ));
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    Ok(())
}

#[test]
fn public_card_pathology_must_match_exact_bounded_lineage_and_class() -> Result<()> {
    for cycle in [false, true] {
        let (_dir, vault) = open_vault();
        let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
        let policy = auto_policy(agent_ref);
        let limit = policy.max_consecutive_transients;
        let rows = transient_chain(&vault, agent_ref, &policy, 2)?;
        let current = &rows[2];
        let expected = if cycle {
            // current -> parent -> oldest -> parent repeats at threshold N=3.
            repoint_retry_of(&vault, rows[0].id, Some(rows[1].id))?;
            RetryLineagePathology::Cycle {
                repeated_attempt_id: rows[1].id,
            }
        } else {
            delete_attempt_record(&vault, rows[0].id)?;
            RetryLineagePathology::MissingAncestor {
                missing_attempt_id: rows[0].id,
            }
        };
        let outcome = FailureLadder::new(&vault)
            .handle_attempt_failure(failure_input(current, permanent(), 60), policy)?;
        let surface = human_surface(&outcome);
        assert_eq!(surface.pathology.as_ref(), Some(&expected));
        let input = pathology_card_input(&vault, surface, limit)?;
        let before = AttemptQueue::new(&vault).list()?;
        let card = surfaced_failure_card(&vault, input.clone())?;
        assert_eq!(card.pathology, Some(expected.clone()));
        assert_eq!(card.failure_class, FailureClass::Ambiguous);
        assert_eq!(card.consecutive_transients, 0);
        assert_eq!(card.diagram.tree, input.tree);

        for class in [
            FailureClass::Transient,
            FailureClass::Permanent,
            FailureClass::Ambiguous,
        ] {
            for count in [0, 1, 3, u16::MAX] {
                let mut changed = input.clone();
                changed.failure_class = class;
                changed.consecutive_transients = count;
                let result = surfaced_failure_card(&vault, changed);
                if class == FailureClass::Ambiguous && count == 0 {
                    assert_eq!(result?.pathology, Some(expected.clone()));
                } else {
                    assert!(
                        matches!(result, Err(Error::InvalidConfig(_))),
                        "{class:?} + {count}"
                    );
                }
            }
        }

        let unrelated = AttemptId::from_bytes(&[0x7a; 16])?;
        for claimed in [
            RetryLineagePathology::MissingAncestor {
                missing_attempt_id: unrelated,
            },
            RetryLineagePathology::Cycle {
                repeated_attempt_id: unrelated,
            },
            // Correct lineage IDs with the wrong kind still are not the computed pathology.
            RetryLineagePathology::MissingAncestor {
                missing_attempt_id: rows[1].id,
            },
            RetryLineagePathology::Cycle {
                repeated_attempt_id: rows[0].id,
            },
        ] {
            let mut forged = input.clone();
            forged.pathology = Some(claimed);
            assert!(matches!(
                surfaced_failure_card(&vault, forged),
                Err(Error::InvalidConfig(_))
            ));
        }

        // N=2 stops before either condition. The card must not perform a deeper probe.
        for bound in [1, 2] {
            let mut bounded = input.clone();
            bounded.retry_lineage_limit = NonZeroU16::new(bound).expect("positive bound");
            assert!(matches!(
                surfaced_failure_card(&vault, bounded),
                Err(Error::InvalidConfig(_))
            ));
        }
        let mut no_claim = input;
        no_claim.pathology = None;
        assert_eq!(surfaced_failure_card(&vault, no_claim)?.pathology, None);
        assert_eq!(
            AttemptQueue::new(&vault).list()?,
            before,
            "card validation is read-only"
        );
    }
    Ok(())
}

#[test]
fn public_card_accepts_self_cycle_at_one_row_limit() -> Result<()> {
    let (_dir, vault) = open_vault();
    let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
    let leased = leased_dispatch(&vault, agent_ref, 10)?;
    repoint_retry_of(&vault, leased.id, Some(leased.id))?;
    let policy = policy_with(agent_ref, 1, FailureEscalationMode::Auto);
    let limit = policy.max_consecutive_transients;
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, permanent(), 20), policy)?;
    let input = pathology_card_input(&vault, human_surface(&outcome), limit)?;
    let before = AttemptQueue::new(&vault).list()?;
    let card = surfaced_failure_card(&vault, input)?;
    assert_eq!(
        card.pathology,
        Some(RetryLineagePathology::Cycle {
            repeated_attempt_id: leased.id,
        })
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    Ok(())
}
