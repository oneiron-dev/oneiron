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
            let FailOutcome::Failed(failed) = queue.fail(FailAttempt {
                id: current.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: current.attempt_count,
                reason: "detector.stable_code".to_owned(),
                now: 30,
            })?
            else {
                panic!("expected a fresh failure");
            };
            Ok(failed)
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
            Error::InvalidAttemptQueueTransition { action, state: "abandoned" }
                if action == expected_action
        ));
        assert_eq!(queue.list()?, before, "no row was changed or enqueued");
        assert_eq!(RunTreeAdapter::new(&vault).read_run(RUN_ID)?, tree);
    }
    Ok(())
}

#[test]
fn public_card_requires_persisted_failed_state_for_every_class() -> Result<()> {
    use crate::run_tree::RunTreeStatus;

    for state in [
        AttemptState::Queued,
        AttemptState::Leased,
        AttemptState::Paused,
        AttemptState::Completed,
        AttemptState::Failed,
        AttemptState::Cancelled,
        AttemptState::Scheduled,
        AttemptState::Landing,
        AttemptState::Abandoned,
    ] {
        let (_dir, vault) = open_vault();
        let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
        let current = card_attempt_in_state(&vault, agent_ref, state)?;
        let queue = AttemptQueue::new(&vault);
        assert_eq!(current.state, state);
        assert_eq!(queue.get(current.id)?, Some(current.clone()));
        let before = queue.list()?;
        let original_tree = RunTreeAdapter::new(&vault).read_run(RUN_ID)?;
        let mut tree = original_tree.clone();
        // A Scheduled retry is rendered under its Failed source. That parent's
        // state must not authorize a failure card for the still-scheduled child.
        let node = if state == AttemptState::Scheduled {
            assert_eq!(tree.roots[0].status, RunTreeStatus::Failed);
            &mut tree.roots[0].children[0]
        } else {
            &mut tree.roots[0]
        };
        assert_eq!(node.attempt_id, bytes_to_hex_lower(current.id.as_bytes()));
        if state == AttemptState::Abandoned {
            assert_eq!(node.status, RunTreeStatus::Abandoned);
            assert_eq!(node.failure, None, "a stop reason is not a diagnosed fault");
            assert_eq!(
                node.result_ref.as_deref(),
                Some(current.result_ref().expect("abandoned exhaust").as_str())
            );
        }
        if state == AttemptState::Failed {
            assert_eq!(node.status, RunTreeStatus::Failed);
        } else {
            assert_ne!(node.status, RunTreeStatus::Failed);
            node.status = RunTreeStatus::Failed;
        }
        let ordinal = NonZeroU16::new(if state == AttemptState::Scheduled {
            2
        } else {
            1
        })
        .expect("positive ordinal");
        let limit = DEFAULT_MAX_CONSECUTIVE_TRANSIENTS;
        // The shared walker remains valid before fail; only the card door adds
        // the persisted-state requirement, independent of the claimed class.
        assert_eq!(
            retry_lineage_walk(&queue, &current, limit)?,
            RetryOrdinal::BelowLimit(ordinal)
        );
        for class in [
            FailureClass::Transient,
            FailureClass::Permanent,
            FailureClass::Ambiguous,
        ] {
            let count = if class == FailureClass::Transient {
                ordinal.get()
            } else {
                0
            };
            let result = surfaced_failure_card(
                &vault,
                SurfacedFailureCardInput {
                    failure_class: class,
                    consecutive_transients: count,
                    pathology: None,
                    retry_lineage_limit: limit,
                    tree: tree.clone(),
                    failing_attempt_id: current.id,
                    pre_fail_checkpoint_ref: test_id(0x51),
                    diagnosis: FailureDiagnosisState::NotRun,
                    blocked_reports: Vec::new(),
                    qa: HealerQaFeed {
                        thread_ref: test_id(0x52).to_hex(),
                        entries: Vec::new(),
                    },
                },
            );
            if state == AttemptState::Failed {
                let card = result?;
                assert_eq!(card.failure_class, class);
                assert_eq!(card.consecutive_transients, count);
                assert_eq!(card.pathology, None);
                assert_eq!(card.diagram.tree, original_tree);
            } else {
                assert!(
                    matches!(result, Err(Error::InvalidConfig(message))
                        if message == "failure card lineage requires a stored Failed attempt"),
                    "{state:?} must not produce a {class:?} failure card"
                );
            }
        }
        assert_eq!(queue.list()?, before, "card validation is read-only");
        assert_eq!(RunTreeAdapter::new(&vault).read_run(RUN_ID)?, original_tree);
    }
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
fn public_card_transient_count_matches_stored_retry_ordinal() -> Result<()> {
    for (retries, expected) in [
        (
            1,
            RetryOrdinal::BelowLimit(NonZeroU16::new(2).expect("two")),
        ),
        (2, RetryOrdinal::AtLimit(DEFAULT_MAX_CONSECUTIVE_TRANSIENTS)),
    ] {
        let (_dir, vault) = open_vault();
        let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
        let policy = auto_policy(agent_ref);
        let limit = policy.max_consecutive_transients;
        let rows = transient_chain(&vault, agent_ref, &policy, retries)?;
        let current = rows.last().expect("stored retry chain");
        assert_eq!(current.attempt_count, 1, "lease count is not retry depth");
        // Terminalize through the existing ladder. The public card door also
        // permits Transient below the limit, provided its ordinal is exact.
        let outcome = FailureLadder::new(&vault)
            .handle_attempt_failure(failure_input(current, indeterminate(), 60), policy)?;
        let mut input = pathology_card_input(&vault, human_surface(&outcome), limit)?;
        input.failure_class = FailureClass::Transient;
        let before = AttemptQueue::new(&vault).list()?;
        assert_eq!(retry_lineage_ordinal(&vault, current.id, limit)?, expected);
        let ordinal = match expected {
            RetryOrdinal::BelowLimit(ordinal) | RetryOrdinal::AtLimit(ordinal) => ordinal.get(),
            RetryOrdinal::Pathology(_) => panic!("intact fixture lineage"),
        };
        for count in [0, 1, 2, 3, 4, u16::MAX] {
            let mut changed = input.clone();
            changed.consecutive_transients = count;
            let result = surfaced_failure_card(&vault, changed);
            if count == ordinal {
                let card = result?;
                assert_eq!(card.failure_class, FailureClass::Transient);
                assert_eq!(card.consecutive_transients, ordinal);
                assert_eq!(card.pathology, None);
                assert_eq!(card.diagram.tree, input.tree);
            } else {
                assert!(
                    matches!(result, Err(Error::InvalidConfig(_))),
                    "stored ordinal {ordinal} must reject count {count}"
                );
            }
        }
        assert_eq!(AttemptQueue::new(&vault).list()?, before);
    }
    Ok(())
}

#[test]
fn public_card_transient_count_stops_at_caller_lineage_bound() -> Result<()> {
    for bound in [1, 3] {
        let (_dir, vault) = open_vault();
        let agent_ref = put_scope_agent(&vault, 0x31, "oneiron.agent.failing")?;
        // Build four real retry rows with headroom, then hide an ancestor
        // beyond the bound. Neither the ladder nor the card may probe it.
        let build_policy = policy_with(agent_ref, 4, FailureEscalationMode::Auto);
        let rows = transient_chain(&vault, agent_ref, &build_policy, 3)?;
        delete_attempt_record(&vault, rows[0].id)?;
        let policy = policy_with(agent_ref, bound, FailureEscalationMode::Human);
        let limit = policy.max_consecutive_transients;
        let outcome = FailureLadder::new(&vault)
            .handle_attempt_failure(failure_input(&rows[3], transient(), 60), policy)?;
        let surface = human_surface(&outcome);
        assert_eq!(surface.failure_class, FailureClass::Transient);
        assert_eq!(surface.consecutive_transients, bound);
        assert_eq!(surface.pathology, None);
        let input = pathology_card_input(&vault, surface, limit)?;
        let before = AttemptQueue::new(&vault).list()?;
        let card = surfaced_failure_card(&vault, input.clone())?;
        assert_eq!(card.consecutive_transients, bound);
        assert_eq!(card.pathology, None);
        assert_eq!(card.diagram.tree, input.tree);
        for count in [0, 2, 4, u16::MAX] {
            let mut changed = input.clone();
            changed.consecutive_transients = count;
            assert!(
                matches!(
                    surfaced_failure_card(&vault, changed),
                    Err(Error::InvalidConfig(_))
                ),
                "bound {bound} must reject count {count}"
            );
        }
        assert_eq!(AttemptQueue::new(&vault).list()?, before);
    }
    Ok(())
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

    // A matching rendered node cannot substitute for the stored current row,
    // even when the caller claims there is no pathology.
    assert!(AttemptQueue::new(&vault).get(missing)?.is_none());
    let mut absent = input;
    absent.failing_attempt_id = missing;
    absent.tree.roots[0].attempt_id = crate::entity_id::bytes_to_hex_lower(missing.as_bytes());
    assert!(matches!(
        surfaced_failure_card(&vault, absent.clone()),
        Err(Error::InvalidConfig(_))
    ));
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
        // Omitting either a missing ancestor or a cycle cannot suppress it,
        // regardless of the failure class on the public card input.
        for class in [
            FailureClass::Transient,
            FailureClass::Permanent,
            FailureClass::Ambiguous,
        ] {
            let mut no_claim = input.clone();
            no_claim.failure_class = class;
            no_claim.pathology = None;
            assert!(matches!(
                surfaced_failure_card(&vault, no_claim),
                Err(Error::InvalidConfig(_))
            ));
        }
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
    let queue = AttemptQueue::new(&vault);
    let current = queue.get(leased.id)?.expect("stored leased attempt");
    assert_eq!(current.state, AttemptState::Leased);
    assert_eq!(
        retry_lineage_walk(&queue, &current, limit)?,
        RetryOrdinal::Pathology(RetryLineagePathology::Cycle {
            repeated_attempt_id: leased.id,
        })
    );
    assert!(matches!(
        retry_lineage_ordinal(&vault, leased.id, limit),
        Err(Error::InvalidConfig(message))
            if message == "failure card lineage requires a stored Failed attempt"
    ));
    assert_eq!(queue.get(leased.id)?, Some(current));
    // Only the card helper rejects the leased row. The ladder must still walk
    // it before failing it, then the public card must accept its real pathology.
    let outcome = FailureLadder::new(&vault)
        .handle_attempt_failure(failure_input(&leased, permanent(), 20), policy)?;
    let input = pathology_card_input(&vault, human_surface(&outcome), limit)?;
    let before = AttemptQueue::new(&vault).list()?;
    let mut suppressed = input.clone();
    suppressed.pathology = None;
    assert!(matches!(
        surfaced_failure_card(&vault, suppressed),
        Err(Error::InvalidConfig(_))
    ));
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
