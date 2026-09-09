//! Kill-spawn authority and state contract tests.

#[cfg(test)]
mod one_1698_tests {
    use super::super::*;
    use crate::VaultConfig;
    use crate::agent_def::{AgentCeiling, AgentScope};
    use crate::attempt_queue::{
        ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
        EnqueueOutcome,
    };
    use crate::claim::ClaimSource;
    use crate::temporal::TimeRange;

    /// The seeded row a `sys.*` logical id names, as a dispatch target.
    fn seeded_target(vault: &Vault, logical_id: &str) -> AgentDispatchTarget {
        let (id, _) = vault
            .get_seeded_agent_definition_by_logical_id(logical_id)
            .expect("seeded roster resolves")
            .expect("seeded row exists");
        AgentDispatchTarget::Custom(id)
    }

    /// An ordinary user-authored AGENT_DEF row, dispatchable and preset-free.
    fn put_custom_definition(vault: &Vault, id: &EntityId, agent_id: &str) -> Result<()> {
        let definition = AgentDefinition::new(
            agent_id,
            "custom dispatch fixture",
            "1",
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
        vault.put_agent_definition(id, &definition, TimeRange { start: 1, end: 1 }, 1)
    }

    fn dispatched_status(outcome: AgentDispatchOutcome) -> AgentDispatchStatus {
        let AgentDispatchOutcome::Dispatched(status) = outcome else {
            panic!("expected fresh dispatch");
        };
        status
    }

    fn dispatch_child(
        dispatcher: &AgentDispatcher<'_>,
        target: AgentDispatchTarget,
        parent: AttemptId,
        now: u64,
    ) -> Result<AgentDispatchStatus> {
        dispatcher
            .dispatch(DispatchAgent {
                target,
                parent_attempt: Some(parent),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .map(dispatched_status)
    }

    #[test]
    fn kill_authority_is_spawner_only_and_class_independent() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let custom_id = EntityId::from_bytes([0x61; 16])?;
        put_custom_definition(&vault, &custom_id, "custom")?;

        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 2)?);
        let non_spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 3)?);
        let system_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            4,
        )?;
        let custom_child = dispatch_child(
            &dispatcher,
            AgentDispatchTarget::Custom(custom_id),
            spawner.attempt.id,
            5,
        )?;
        let proposed_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.creative"),
            spawner.attempt.id,
            6,
        )?;

        let outcomes = [
            dispatcher.kill_spawn(&system_child.attempt.id, &spawner.attempt.id, 7)?,
            dispatcher.kill_spawn(&custom_child.attempt.id, &spawner.attempt.id, 8)?,
        ];
        let killed = outcomes
            .into_iter()
            .filter(|outcome| matches!(outcome, KillOutcome::Killed))
            .count();
        assert_eq!(killed, 2);

        let proposal =
            dispatcher.kill_spawn(&proposed_child.attempt.id, &non_spawner.attempt.id, 9)?;
        assert_eq!(
            proposal,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: proposed_child.attempt.id,
                proposer: non_spawner.attempt.id,
            })
        );

        let queue = AttemptQueue::new(&vault);
        assert_eq!(
            queue
                .get(system_child.attempt.id)?
                .expect("system child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            queue
                .get(custom_child.attempt.id)?
                .expect("custom child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            queue
                .get(proposed_child.attempt.id)?
                .expect("proposed child")
                .state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn spawner_authority_does_not_depend_on_target_class() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let custom_id = EntityId::from_bytes([0x62; 16])?;
        put_custom_definition(&vault, &custom_id, "custom")?;

        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 2)?);
        let system_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            3,
        )?;
        let custom_child = dispatch_child(
            &dispatcher,
            AgentDispatchTarget::Custom(custom_id),
            spawner.attempt.id,
            4,
        )?;

        let outcomes = [
            dispatcher.kill_spawn(&system_child.attempt.id, &spawner.attempt.id, 5)?,
            dispatcher.kill_spawn(&custom_child.attempt.id, &spawner.attempt.id, 6)?,
        ];
        assert_eq!(
            outcomes
                .into_iter()
                .filter(|outcome| matches!(outcome, KillOutcome::Killed))
                .count(),
            2
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(system_child.attempt.id)?
                .expect("system child")
                .state,
            AttemptState::Cancelled
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(custom_child.attempt.id)?
                .expect("custom child")
                .state,
            AttemptState::Cancelled
        );
        Ok(())
    }

    #[test]
    fn fabricated_and_terminal_killers_only_propose() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let fabricated = AttemptId::from_bytes(&[0xF1; 16])?;
        let fabricated_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            fabricated,
            1,
        )?;
        let fabricated_outcome =
            dispatcher.kill_spawn(&fabricated_child.attempt.id, &fabricated, 2)?;
        assert_eq!(
            fabricated_outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: fabricated_child.attempt.id,
                proposer: fabricated,
            })
        );

        let terminal_killer =
            dispatched_status(dispatcher.dispatch_default_base(None, None, None, 3)?);
        let terminal_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.keeper"),
            terminal_killer.attempt.id,
            4,
        )?;
        let queue = AttemptQueue::new(&vault);
        let cancelled = queue.intervene(InterveneAttempt {
            id: terminal_killer.attempt.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "runtime".to_owned(),
            note: None,
            now: 5,
        })?;
        assert_eq!(cancelled.effect, AttemptInterventionEffect::Cancelled);
        let terminal_outcome =
            dispatcher.kill_spawn(&terminal_child.attempt.id, &terminal_killer.attempt.id, 6)?;
        assert_eq!(
            terminal_outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: terminal_child.attempt.id,
                proposer: terminal_killer.attempt.id,
            })
        );
        assert_eq!(
            [fabricated_child.attempt.id, terminal_child.attempt.id]
                .into_iter()
                .filter(|id| {
                    queue
                        .get(*id)
                        .expect("read child")
                        .expect("child exists")
                        .state
                        == AttemptState::Queued
                })
                .count(),
            2
        );
        Ok(())
    }

    #[test]
    fn non_agent_killer_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(non_agent) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &DreamerAttemptPayload {
                    attempt_type: "maintenance".to_owned(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh non-agent attempt");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            non_agent.id,
            2,
        )?;

        let outcome = dispatcher.kill_spawn(&child.attempt.id, &non_agent.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: non_agent.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn malformed_agent_dispatch_killer_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        // A caller can enqueue a live "agent.dispatch" row carrying arbitrary input:
        // enqueue validates only the attempt-type string, never the dispatch codec.
        let EnqueueOutcome::Enqueued(malformed_killer) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: crate::dreamer_runner::encode_dreamer_attempt_payload(
                &DreamerAttemptPayload {
                    attempt_type: AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: Value::Nil,
                    parent_attempt: None,
                },
            )?,
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh malformed agent-dispatch attempt");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            malformed_killer.id,
            2,
        )?;

        // The killer is the child's named parent, but its input never decodes as a
        // valid agent dispatch, so it cannot be confirmed as a real killer. The old
        // `?` aborted with InvalidAgentDispatchInput; it must fail closed to Proposed
        // with the target left alive.
        let outcome = dispatcher.kill_spawn(&child.attempt.id, &malformed_killer.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: malformed_killer.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn undecodable_killer_envelope_proposes() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let queue = AttemptQueue::new(&vault);
        // The generic queue stores arbitrary payload bytes under any kind, so a caller
        // can enqueue a live dreamer-kind killer whose envelope never decodes as a
        // DreamerAttemptPayload (0xC1 is the reserved, never-valid MessagePack marker).
        let EnqueueOutcome::Enqueued(undecodable_killer) = queue.enqueue(EnqueueAttempt {
            kind: crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND.to_owned(),
            payload: vec![0xC1],
            dedupe_key: None,
            run_id: None,
            now: 1,
        })?
        else {
            panic!("expected fresh undecodable killer");
        };
        let dispatcher = AgentDispatcher::new(&vault);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            undecodable_killer.id,
            2,
        )?;

        // The killer is the child's named parent, but its envelope does not decode, so
        // it cannot be confirmed as a real killer. The old `?` aborted the call with a
        // decode error; it must fail closed to Proposed with the target left alive.
        let outcome = dispatcher.kill_spawn(&child.attempt.id, &undecodable_killer.id, 3)?;
        assert_eq!(
            outcome,
            KillOutcome::Proposed(KillProposal {
                spawn_attempt_id: child.attempt.id,
                proposer: undecodable_killer.id,
            })
        );
        assert_eq!(
            queue.get(child.attempt.id)?.expect("child exists").state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn leased_spawn_receives_cooperative_cancellation_request() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let queue = AttemptQueue::new(&vault);
        let ClaimOutcome::Claimed(claimed_spawner) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 3,
        })?
        else {
            panic!("expected spawner lease");
        };
        let ClaimOutcome::Claimed(claimed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 4,
        })?
        else {
            panic!("expected child lease");
        };
        assert_eq!(claimed_spawner.id, spawner.attempt.id);
        assert_eq!(claimed_child.id, child.attempt.id);

        let outcome = dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 5)?;
        assert_eq!(outcome, KillOutcome::CancellationRequested);
        let observed = queue.get(child.attempt.id)?.expect("child exists");
        assert_eq!(observed.state, AttemptState::Leased);
        assert_eq!(
            observed
                .events
                .iter()
                .filter(|event| event.kind == AttemptInterventionKind::Interrupt)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn kill_spawn_uses_current_leased_and_terminal_target_states() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let leased_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let completed_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.keeper"),
            spawner.attempt.id,
            3,
        )?;
        let queue = AttemptQueue::new(&vault);

        let ClaimOutcome::Claimed(claimed_spawner) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 4,
        })?
        else {
            panic!("expected spawner lease");
        };
        let ClaimOutcome::Claimed(claimed_leased_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 5,
        })?
        else {
            panic!("expected leased child lease");
        };
        let ClaimOutcome::Claimed(claimed_completed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-c".to_owned(),
            now: 6,
        })?
        else {
            panic!("expected completed child lease");
        };
        assert_eq!(claimed_spawner.id, spawner.attempt.id);
        assert_eq!(claimed_leased_child.id, leased_child.attempt.id);
        assert_eq!(claimed_completed_child.id, completed_child.attempt.id);

        let CompleteOutcome::Completed(completed) = queue.complete(CompleteAttempt {
            id: claimed_completed_child.id,
            lease_owner: "worker-c".to_owned(),
            attempt_count: claimed_completed_child.attempt_count,
            now: 7,
        })?
        else {
            panic!("expected completed child transition");
        };
        assert_eq!(completed.state, AttemptState::Completed);

        assert_eq!(
            dispatcher.kill_spawn(&leased_child.attempt.id, &spawner.attempt.id, 8)?,
            KillOutcome::CancellationRequested
        );
        assert_eq!(
            dispatcher.kill_spawn(&completed_child.attempt.id, &spawner.attempt.id, 9)?,
            KillOutcome::AlreadyTerminal
        );
        assert_eq!(
            queue
                .get(leased_child.attempt.id)?
                .expect("leased child exists")
                .state,
            AttemptState::Leased
        );
        assert_eq!(
            queue
                .get(completed_child.attempt.id)?
                .expect("completed child exists")
                .state,
            AttemptState::Completed
        );
        Ok(())
    }

    /// ONE-1896 §12: a LANDING spawner is live work and keeps its standing.
    ///
    /// The live-parent allow-list decides whether the killer is a real parent
    /// or an unconfirmable one; omitting `Landing` read a spawner that was
    /// tidying up as DEAD and downgraded its ask to a proposal — exactly when
    /// it needed to stop the children it was landing away from.
    #[test]
    fn a_landing_spawner_keeps_its_live_parent_standing() -> Result<()> {
        use crate::attempt_queue::{
            AcceptAttemptLanding, LandingOutcome, LandingTrigger, RejectAttemptCancel,
            RequestAttemptCancel,
        };

        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let queued_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let running_child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.keeper"),
            spawner.attempt.id,
            3,
        )?;
        let queue = AttemptQueue::new(&vault);

        let ClaimOutcome::Claimed(claimed_spawner) = queue.claim(ClaimAttempt {
            lease_owner: "worker-a".to_owned(),
            now: 4,
        })?
        else {
            panic!("expected spawner lease");
        };
        assert_eq!(claimed_spawner.id, spawner.attempt.id);

        // The spawner accepts a stop of its own and enters LANDING.
        queue.request_cancel(RequestAttemptCancel {
            id: spawner.attempt.id,
            actor: "peer-1".to_owned(),
            standing: CancelStanding::PeerAgent,
            trigger: LandingTrigger::CancelRequest,
            reason: None,
            now: 5,
        })?;
        let LandingOutcome::Landing(landing) = queue.accept_landing(AcceptAttemptLanding {
            id: spawner.attempt.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: claimed_spawner.attempt_count,
            trigger: LandingTrigger::CancelRequest,
            status: None,
            resume_point: None,
            request_sequence: None,
            now: 6,
        })?
        else {
            panic!("expected a fresh landing");
        };
        assert_eq!(landing.state, AttemptState::Landing);

        // Pre-lease child: stopped outright, exactly as a leased parent's is.
        assert_eq!(
            dispatcher.kill_spawn(&queued_child.attempt.id, &spawner.attempt.id, 7)?,
            KillOutcome::Killed
        );
        assert_eq!(
            queue
                .get(queued_child.attempt.id)?
                .expect("child exists")
                .state,
            AttemptState::Cancelled
        );

        // Running child: ASKED, never killed — peer standing is standing to ask.
        let ClaimOutcome::Claimed(claimed_child) = queue.claim(ClaimAttempt {
            lease_owner: "worker-b".to_owned(),
            now: 8,
        })?
        else {
            panic!("expected running child lease");
        };
        assert_eq!(claimed_child.id, running_child.attempt.id);
        assert_eq!(
            dispatcher.kill_spawn(&running_child.attempt.id, &spawner.attempt.id, 9)?,
            KillOutcome::CancellationRequested,
            "a landing parent may still ask its running child to stop"
        );
        let asked = queue
            .get(running_child.attempt.id)?
            .expect("running child exists");
        assert_eq!(asked.state, AttemptState::Leased);
        assert_eq!(asked.cancel_pressure().pending, 1);

        // Stale-generation completion stays typed and idempotent while the
        // sticky child answers with a refusal instead.
        let err = queue
            .complete(CompleteAttempt {
                id: running_child.attempt.id,
                lease_owner: "worker-b".to_owned(),
                attempt_count: claimed_child.attempt_count + 1,
                now: 10,
            })
            .expect_err("a stale generation cannot complete");
        assert!(matches!(
            err,
            Error::InvalidAttemptQueueTransition { action, state }
                if action == "complete" && state == "stale_attempt"
        ));
        let refusal = queue.reject_cancel(RejectAttemptCancel {
            id: running_child.attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed_child.attempt_count,
            reason: "mid-write".to_owned(),
            status: None,
            request_sequence: None,
            now: 11,
        })?;
        assert_eq!(refusal.record.state, AttemptState::Leased);
        assert_eq!(refusal.pressure.rejections, 1);
        // And the bound executor still completes its own current generation.
        let CompleteOutcome::Completed(done) = queue.complete(CompleteAttempt {
            id: running_child.attempt.id,
            lease_owner: "worker-b".to_owned(),
            attempt_count: claimed_child.attempt_count,
            now: 12,
        })?
        else {
            panic!("the bound executor completes its own attempt");
        };
        assert_eq!(done.state, AttemptState::Completed);
        Ok(())
    }

    #[test]
    fn already_cancelled_spawn_is_not_reported_killed_again() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;

        assert_eq!(
            dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 3)?,
            KillOutcome::Killed
        );
        assert_eq!(
            dispatcher.kill_spawn(&child.attempt.id, &spawner.attempt.id, 4)?,
            KillOutcome::AlreadyTerminal
        );
        assert_eq!(
            AttemptQueue::new(&vault)
                .get(child.attempt.id)?
                .expect("child exists")
                .state,
            AttemptState::Cancelled
        );
        Ok(())
    }

    #[test]
    fn non_dreamer_row_cannot_masquerade_as_spawn() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let spawner = dispatched_status(dispatcher.dispatch_default_base(None, None, None, 1)?);
        let child = dispatch_child(
            &dispatcher,
            seeded_target(&vault, "sys.scout"),
            spawner.attempt.id,
            2,
        )?;
        let queue = AttemptQueue::new(&vault);
        let EnqueueOutcome::Enqueued(masquerader) = queue.enqueue(EnqueueAttempt {
            kind: "worker".to_owned(),
            payload: child.attempt.payload,
            dedupe_key: None,
            run_id: None,
            now: 3,
        })?
        else {
            panic!("expected fresh masquerader");
        };

        let error = dispatcher
            .kill_spawn(&masquerader.id, &spawner.attempt.id, 4)
            .expect_err("non-dreamer target must be rejected");
        assert!(matches!(error, Error::InvalidAgentDispatchInput(_)));
        assert_eq!(
            queue
                .get(masquerader.id)?
                .expect("masquerader exists")
                .state,
            AttemptState::Queued
        );
        Ok(())
    }

    #[test]
    fn default_dispatch_rejects_cross_target_and_cross_parent_dedupe() -> Result<()> {
        let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
        let dispatcher = AgentDispatcher::new(&vault);
        let scout = dispatcher.dispatch(DispatchAgent {
            target: seeded_target(&vault, "sys.scout"),
            parent_attempt: None,
            dedupe_key: Some("shared".to_owned()),
            run_id: None,
            now: 1,
        })?;
        let AgentDispatchOutcome::Dispatched(_) = scout else {
            panic!("expected fresh scout dispatch");
        };
        let mismatch = dispatcher
            .dispatch_default_base(None, Some("shared".to_owned()), None, 2)
            .expect_err("cross-target dedupe must fail closed");
        let Error::InvalidAgentDispatchInput(reason) = mismatch else {
            panic!("expected invalid agent dispatch input");
        };
        assert_eq!(reason, "existing dedupe row targets a different agent");

        let first_default = dispatched_status(dispatcher.dispatch_default_base(
            None,
            Some("default-only".to_owned()),
            None,
            3,
        )?);
        let AgentDispatchOutcome::Existing(second_default) =
            dispatcher.dispatch_default_base(None, Some("default-only".to_owned()), None, 4)?
        else {
            panic!("expected parentless existing dispatch");
        };
        assert_eq!(second_default, first_default);

        let parent = AttemptId::from_bytes(&[0xD1; 16])?;
        let other_parent = AttemptId::from_bytes(&[0xD2; 16])?;
        let first_parented = dispatched_status(dispatcher.dispatch_default_base(
            Some(parent),
            Some("parent-owned".to_owned()),
            None,
            5,
        )?);
        let AgentDispatchOutcome::Existing(second_parented) = dispatcher.dispatch_default_base(
            Some(parent),
            Some("parent-owned".to_owned()),
            None,
            6,
        )?
        else {
            panic!("expected same-parent existing dispatch");
        };
        assert_eq!(second_parented, first_parented);

        let mismatch = dispatcher
            .dispatch_default_base(Some(other_parent), Some("parent-owned".to_owned()), None, 7)
            .expect_err("cross-parent dedupe must fail closed");
        let Error::InvalidAgentDispatchInput(reason) = mismatch else {
            panic!("expected invalid agent dispatch input");
        };
        assert_eq!(reason, "existing dedupe row belongs to a different parent");
        Ok(())
    }
}
