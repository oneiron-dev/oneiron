use super::*;
use crate::run_tree::RunTreeStatus;

#[test]
fn surfaced_failure_card_requires_existing_failed_status() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let stored_before = crate::AttemptQueue::new(&vault).get(failing)?;

    for status in [
        RunTreeStatus::Queued,
        RunTreeStatus::Running,
        RunTreeStatus::Paused,
        RunTreeStatus::Completed,
        RunTreeStatus::Cancelled,
    ] {
        let mut non_failed = tree.clone();
        non_failed.roots[0].status = status;
        let before = non_failed.clone();
        let error = surfaced_failure_card(
            &vault,
            card_input(failing, non_failed.clone(), feed.clone()),
        )
        .expect_err("a failure card cannot mark a non-Failed node");
        assert!(matches!(error, Error::InvalidConfig(_)), "{status:?}");
        assert_eq!(non_failed, before);
    }

    let card = surfaced_failure_card(&vault, card_input(failing, tree.clone(), feed.clone()))?;
    assert_eq!(card.diagram.tree, tree);
    assert_eq!(card.diagram.tree.roots[0].status, RunTreeStatus::Failed);
    assert_eq!(
        crate::AttemptQueue::new(&vault).get(failing)?,
        stored_before
    );

    // A matching Failed node must not mask another node with the same ID.
    for status in [RunTreeStatus::Failed, RunTreeStatus::Running] {
        let mut duplicate = tree.clone();
        let mut child = tree.roots[0].clone();
        child.status = status;
        duplicate.roots[0].children.push(child);
        let error = surfaced_failure_card(&vault, card_input(failing, duplicate, feed.clone()))
            .expect_err("duplicate IDs remain invalid even when one match is Failed");
        assert!(matches!(error, Error::InvalidConfig(_)));
    }
    Ok(())
}

#[test]
fn surfaced_failure_card_rejects_duplicate_authored_by_binding() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let thread = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let actor = put_actor(&vault, 0x66)?;
    let impostor = put_actor(&vault, 0x6c)?;
    let message = put_qa_message(&vault, 0x67, thread, Some(actor), 100, 0)?;
    let card_for = |author| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![qa_entry(message, author, 100)],
                },
            ),
        )
    };

    let card = card_for(actor)?;
    assert_eq!(card.qa.entries, vec![qa_entry(message, actor, 100)]);
    vault.put_edge(&message, EdgeKind::AuthoredBy, &impostor, 1.0)?;
    for author in [impostor, actor] {
        let error = card_for(author)
            .expect_err("neither author may claim a multiply-bound witnessed MESSAGE");
        assert!(matches!(error, Error::InvalidConfig(_)));
    }
    Ok(())
}

#[test]
fn surfaced_failure_card_accepts_canonical_witness_membership() -> Result<()> {
    use crate::edge::EdgeActorClass;
    use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};

    // Keep the production policy manifest so this exercises the real witness door.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::device())?;
    let (failing, tree) = failed_run(&vault)?;
    let actor = put_actor(&vault, 0x66)?;
    let conversation = crate::test_util::entity(0x64);
    let turn = crate::test_util::entity(0x65);
    let message = crate::test_util::entity(0x67);
    let foreign = put_container(&vault, 0x6a, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    vault
        .memory(actor, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: QA_MESSAGE_BODY.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
            occurred_at: 100,
        })
        .expect("witness a canonical Q&A message");

    let entry = qa_entry(message, actor, 100);
    let card_for = |thread: EntityId| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![entry.clone()],
                },
            ),
        )
    };
    for thread in [turn, conversation] {
        let card = card_for(thread)?;
        assert_eq!(card.qa.thread_ref, thread.to_hex());
        assert_eq!(card.qa.entries, vec![entry.clone()]);
        assert_eq!(card.diagram.tree, tree);
    }
    assert!(matches!(card_for(foreign), Err(Error::InvalidConfig(_))));

    // Isolate the writer's direct MESSAGE --BelongsTo--> CONVERSATION edge.
    assert!(vault.delete_edge(&turn, EdgeKind::ChildOf, &conversation)?);
    assert!(card_for(conversation).is_ok());
    vault.put_edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)?;

    // Without the direct edge, the writer's PartOf -> ChildOf path still binds.
    assert!(vault.delete_edge(&message, EdgeKind::BelongsTo, &conversation)?);
    assert!(card_for(conversation).is_ok());
    assert!(
        card_for(turn).is_ok(),
        "direct PartOf membership is preserved"
    );
    assert!(matches!(card_for(foreign), Err(Error::InvalidConfig(_))));
    let outer = put_container(&vault, 0x6b, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    vault.put_edge(&conversation, EdgeKind::ChildOf, &outer, 1.0)?;
    assert!(matches!(card_for(outer), Err(Error::InvalidConfig(_))));

    // A witnessed author alone cannot substitute for a membership path.
    assert!(vault.delete_edge(&message, EdgeKind::PartOf, &turn)?);
    assert!(matches!(
        card_for(conversation),
        Err(Error::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn surfaced_failure_card_validates_failure_class_and_transient_count() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let before = crate::AttemptQueue::new(&vault).list()?;
    for class in [
        FailureClass::Transient,
        FailureClass::Permanent,
        FailureClass::Ambiguous,
    ] {
        for count in [0, 1, 3, u16::MAX] {
            let mut input = card_input(failing, tree.clone(), feed.clone());
            input.failure_class = class;
            input.consecutive_transients = count;
            let result = surfaced_failure_card(&vault, input);
            if class != FailureClass::Transient && count != 0 {
                assert!(
                    matches!(result, Err(Error::InvalidConfig(_))),
                    "{class:?} with {count} transients must be rejected, not normalized"
                );
            } else {
                let card = result?;
                assert_eq!(card.failure_class, class);
                assert_eq!(card.consecutive_transients, count);
                assert_eq!(card.diagram.tree, tree);
            }
        }
    }
    assert_eq!(crate::AttemptQueue::new(&vault).list()?, before);
    Ok(())
}

fn put_repair_agent(vault: &crate::Vault, seed: u8, agent_id: &str) -> Result<EntityId> {
    use rmpv::Value;

    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimSource};

    let id = crate::test_util::entity(seed);
    let definition = AgentDefinition::new(
        agent_id,
        "Failure card fixture",
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
    vault.put_agent_definition(
        &id,
        &definition,
        crate::temporal::TimeRange { start: 1, end: 1 },
        1,
    )?;
    Ok(id)
}

fn failed_agent_run(vault: &crate::Vault, agent_ref: EntityId) -> Result<(AttemptId, RunTree)> {
    use crate::agent_dispatch::{
        AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
    };
    use crate::attempt_queue::{ClaimAttempt, ClaimOutcome, FailAttempt, FailOutcome};

    let AgentDispatchOutcome::Dispatched(status) =
        AgentDispatcher::new(vault).dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent_ref),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-card-agent".to_owned()),
            now: 10,
        })?
    else {
        panic!("expected a fresh agent dispatch");
    };
    let queue = crate::AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimAttempt {
        lease_owner: "card-agent-worker".to_owned(),
        now: 20,
    })?
    else {
        panic!("expected a claim");
    };
    assert_eq!(claimed.id, status.attempt.id);
    let FailOutcome::Failed(failed) = queue.fail(FailAttempt {
        id: claimed.id,
        lease_owner: "card-agent-worker".to_owned(),
        attempt_count: claimed.attempt_count,
        reason: "detector.stable_code".to_owned(),
        now: 30,
    })?
    else {
        panic!("expected a terminal failure");
    };
    let tree = crate::run_tree::RunTreeAdapter::new(vault).read_run("run-card-agent")?;
    Ok((failed.id, tree))
}

fn repair_routes(agent_ref: &str) -> [HealerRepairRoute; 4] {
    let reference = |seed| crate::test_util::entity(seed).to_hex();
    [
        HealerRepairRoute::SkillEdit {
            agent_ref: agent_ref.to_owned(),
            skill_ref: reference(0x71),
            patch_ref: reference(0x72),
            diagnosis_ref: reference(0x73),
        },
        HealerRepairRoute::PromptInjectAndForkResume {
            agent_ref: agent_ref.to_owned(),
            prompt_ref: reference(0x74),
            checkpoint_ref: reference(0x75),
            diagnosis_ref: reference(0x73),
        },
        HealerRepairRoute::Environment {
            agent_ref: agent_ref.to_owned(),
            environment_ref: reference(0x76),
            repair_ref: reference(0x77),
            diagnosis_ref: reference(0x73),
        },
        HealerRepairRoute::EscalateWithDiagnosis {
            agent_ref: agent_ref.to_owned(),
            diagnosis_ref: reference(0x73),
        },
    ]
}

#[test]
fn surfaced_failure_card_diagnosis_is_bound_to_dispatched_agent() -> Result<()> {
    let (_dir, vault) = card_vault();
    let agent = put_repair_agent(&vault, 0x31, "oneiron.agent.failure-card")?;
    let other = put_repair_agent(&vault, 0x32, "oneiron.agent.unrelated")?;
    let (failing, tree) = failed_agent_run(&vault, agent)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let before = crate::AttemptQueue::new(&vault).list()?;
    let agent_before = vault.get_raw(&agent)?;
    let other_before = vault.get_raw(&other)?;

    for agent_ref in [
        other.to_hex(),
        crate::test_util::entity(0x33).to_hex(),
        String::new(),
        "not-an-agent-ref".to_owned(),
    ] {
        for route in repair_routes(&agent_ref) {
            let mut input = card_input(failing, tree.clone(), feed.clone());
            input.diagnosis = FailureDiagnosisState::Diagnosed(route);
            let error = surfaced_failure_card(&vault, input)
                .expect_err("a diagnosis cannot repair a missing or unrelated agent");
            assert!(matches!(error, Error::InvalidConfig(_)));
        }
    }
    for route in repair_routes(&agent.to_hex()) {
        let mut input = card_input(failing, tree.clone(), feed.clone());
        input.diagnosis = FailureDiagnosisState::Diagnosed(route.clone());
        let card = surfaced_failure_card(&vault, input)?;
        assert_eq!(card.diagnosis, FailureDiagnosisState::Diagnosed(route));
        assert_eq!(card.diagram.tree, tree);
    }
    assert_eq!(crate::AttemptQueue::new(&vault).list()?, before);
    assert_eq!(vault.get_raw(&agent)?, agent_before);
    assert_eq!(vault.get_raw(&other)?, other_before);
    Ok(())
}

#[test]
fn surfaced_failure_card_diagnosis_requires_a_stored_agent_dispatch() -> Result<()> {
    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let missing = AttemptId::from_bytes(&[0x7a; 16])?;
    assert!(crate::AttemptQueue::new(&vault).get(missing)?.is_none());
    let mut missing_tree = tree.clone();
    missing_tree.roots[0].attempt_id = failing_hex(missing);
    let before = crate::AttemptQueue::new(&vault).list()?;

    for (attempt, tree) in [(failing, tree), (missing, missing_tree)] {
        // The initial card door remains usable without an agent-dispatch binding.
        for diagnosis in [
            FailureDiagnosisState::NotRun,
            FailureDiagnosisState::ReservedHealerSlot,
        ] {
            let mut input = card_input(attempt, tree.clone(), feed.clone());
            input.diagnosis = diagnosis.clone();
            assert_eq!(surfaced_failure_card(&vault, input)?.diagnosis, diagnosis);
        }
        for route in repair_routes(&crate::test_util::entity(0x31).to_hex()) {
            let mut input = card_input(attempt, tree.clone(), feed.clone());
            input.diagnosis = FailureDiagnosisState::Diagnosed(route);
            let error = surfaced_failure_card(&vault, input)
                .expect_err("diagnosed cards require a stored agent-dispatch target");
            assert!(matches!(error, Error::InvalidConfig(_)));
        }
    }
    assert_eq!(crate::AttemptQueue::new(&vault).list()?, before);
    Ok(())
}

#[test]
fn surfaced_failure_card_rejects_extra_canonical_membership_edges() -> Result<()> {
    use crate::store::Store;

    let (_dir, vault) = card_vault();
    let (failing, tree) = failed_run(&vault)?;
    let conversation = put_container(&vault, 0x64, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let turn = put_container(&vault, 0x65, crate::registry::ENTITY_TYPE_TURN)?;
    let foreign = put_container(&vault, 0x6a, crate::registry::ENTITY_TYPE_CONVERSATION)?;
    let foreign_turn = put_container(&vault, 0x6b, crate::registry::ENTITY_TYPE_TURN)?;
    let actor = put_actor(&vault, 0x66)?;
    let message = put_qa_message(&vault, 0x67, turn, Some(actor), 100, 0)?;
    vault.put_edge(&message, EdgeKind::BelongsTo, &conversation, 1.0)?;
    vault.put_edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)?;
    let card_for = |thread: EntityId| {
        surfaced_failure_card(
            &vault,
            card_input(
                failing,
                tree.clone(),
                HealerQaFeed {
                    thread_ref: thread.to_hex(),
                    entries: vec![qa_entry(message, actor, 100)],
                },
            ),
        )
    };
    for (source, kind, extra) in [
        (message, EdgeKind::PartOf, foreign_turn),
        (message, EdgeKind::BelongsTo, foreign),
        (turn, EdgeKind::ChildOf, foreign),
    ] {
        assert!(card_for(turn).is_ok());
        assert!(card_for(conversation).is_ok());
        if kind == EdgeKind::ChildOf {
            // The public writer rejects a second parent. Seed explicit corruption
            // through the raw store so the card reader still faces both bindings.
            assert!(matches!(
                vault.put_edge(&source, kind, &extra, 1.0),
                Err(Error::ChildOfCardinality)
            ));
            assert_eq!(vault.targets(&source, kind, None)?, vec![conversation]);
            let key_out = Store::encode_edge_key(&source, kind, &extra);
            let key_in = Store::encode_edge_key(&extra, kind, &source);
            let value =
                crate::edge::encode_edge_value(kind, 1.0, 100, crate::affect::Vad::NEUTRAL, None)?;
            vault.with_write_txn(|wtxn| {
                vault.store.edges_out.put(wtxn, &key_out, &value)?;
                vault.store.edges_in.put(wtxn, &key_in, &value)?;
                Ok(())
            })?;
        } else {
            vault.put_edge(&source, kind, &extra, 1.0)?;
        }
        assert!(vault.edge_exists(&source, kind, &extra)?);
        for requested in [turn, conversation, foreign_turn, foreign] {
            assert!(
                matches!(card_for(requested), Err(Error::InvalidConfig(_))),
                "a matching thread must not mask an extra {kind:?} edge"
            );
        }
        assert!(vault.delete_edge(&source, kind, &extra)?);
    }

    // Uniqueness alone is not enough: the two sole conversation bindings disagree.
    for (source, kind) in [(message, EdgeKind::BelongsTo), (turn, EdgeKind::ChildOf)] {
        assert!(vault.delete_edge(&source, kind, &conversation)?);
        vault.put_edge(&source, kind, &foreign, 1.0)?;
        for requested in [turn, conversation, foreign] {
            assert!(matches!(card_for(requested), Err(Error::InvalidConfig(_))));
        }
        assert!(vault.delete_edge(&source, kind, &foreign)?);
        vault.put_edge(&source, kind, &conversation, 1.0)?;
    }
    assert!(card_for(turn).is_ok());
    assert!(card_for(conversation).is_ok());

    // A direct PartOf conversation cannot conflict with a sole BelongsTo edge.
    assert!(vault.delete_edge(&message, EdgeKind::PartOf, &turn)?);
    vault.put_edge(&message, EdgeKind::PartOf, &conversation, 1.0)?;
    assert!(card_for(conversation).is_ok());
    assert!(vault.delete_edge(&message, EdgeKind::BelongsTo, &conversation)?);
    vault.put_edge(&message, EdgeKind::BelongsTo, &foreign, 1.0)?;
    for requested in [conversation, foreign] {
        assert!(matches!(card_for(requested), Err(Error::InvalidConfig(_))));
    }
    Ok(())
}

#[test]
fn surfaced_failure_card_requires_canonical_hex_in_every_repair_field() -> Result<()> {
    let (_dir, vault) = card_vault();
    let agent = put_repair_agent(&vault, 0xab, "oneiron.agent.failure-card")?;
    let (failing, tree) = failed_agent_run(&vault, agent)?;
    let checkpoint = crate::test_util::entity(0xac);
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let before = crate::AttemptQueue::new(&vault).list()?;
    for route in repair_routes(&agent.to_hex()) {
        let mut wire = serde_json::to_value(route).expect("route serializes");
        let fields = wire.as_object_mut().expect("tagged route object");
        for (name, value) in fields
            .iter_mut()
            .filter(|(name, _)| name.as_str() != "route")
        {
            // Give every field a valid spelling containing a-f, including both bindings.
            *value = serde_json::Value::String(match name.as_str() {
                "agent_ref" => agent.to_hex(),
                "checkpoint_ref" => checkpoint.to_hex(),
                _ => crate::test_util::entity(0xad).to_hex(),
            });
        }
        let mut input = card_input(failing, tree.clone(), feed.clone());
        input.pre_fail_checkpoint_ref = checkpoint;
        input.diagnosis = FailureDiagnosisState::Diagnosed(
            serde_json::from_value(wire.clone()).expect("typed valid route"),
        );
        let card = surfaced_failure_card(&vault, input.clone())?;
        assert_eq!(card.diagnosis, input.diagnosis);
        for (field, valid) in wire.as_object().expect("route object") {
            if field == "route" {
                continue;
            }
            let valid = valid.as_str().expect("reference string");
            let uppercase = valid.to_uppercase();
            assert_ne!(
                uppercase, valid,
                "uppercase fixture must differ for {field}"
            );
            for invalid in [
                String::new(),
                "not-an-entity-id".to_owned(),
                "g".repeat(32),
                valid[..31].to_owned(),
                format!("{valid}0"),
                uppercase,
            ] {
                let mut forged = wire.clone();
                forged[field] = serde_json::Value::String(invalid);
                let mut bad_input = input.clone();
                bad_input.diagnosis = FailureDiagnosisState::Diagnosed(
                    serde_json::from_value(forged).expect("strings remain a typed route"),
                );
                assert!(
                    matches!(
                        surfaced_failure_card(&vault, bad_input),
                        Err(Error::InvalidConfig(_))
                    ),
                    "{} must validate {field}",
                    wire["route"]
                );
            }
        }
    }
    assert_eq!(crate::AttemptQueue::new(&vault).list()?, before);
    Ok(())
}

#[test]
fn surfaced_failure_card_fork_requires_expected_nonterminal_checkpoint() -> Result<()> {
    let (_dir, vault) = card_vault();
    let agent = put_repair_agent(&vault, 0x31, "oneiron.agent.failure-card")?;
    let (failing, tree) = failed_agent_run(&vault, agent)?;
    let feed = HealerQaFeed {
        thread_ref: crate::test_util::entity(0x64).to_hex(),
        entries: Vec::new(),
    };
    let base = card_input(failing, tree, feed);
    let terminal = EntityId::from_hex(&failing_hex(failing))?;
    let before = crate::AttemptQueue::new(&vault).list()?;
    for (expected, checkpoint_ref, accepted) in [
        (base.pre_fail_checkpoint_ref, "not-hex".to_owned(), false),
        (
            base.pre_fail_checkpoint_ref,
            crate::test_util::entity(0x76).to_hex(),
            false,
        ),
        (base.pre_fail_checkpoint_ref, terminal.to_hex(), false),
        // Even caller context cannot make the failing attempt a pre-fail checkpoint.
        (terminal, terminal.to_hex(), false),
        (
            base.pre_fail_checkpoint_ref,
            base.pre_fail_checkpoint_ref.to_hex(),
            true,
        ),
    ] {
        let mut input = base.clone();
        input.pre_fail_checkpoint_ref = expected;
        let route = HealerRepairRoute::PromptInjectAndForkResume {
            agent_ref: agent.to_hex(),
            prompt_ref: crate::test_util::entity(0x74).to_hex(),
            checkpoint_ref,
            diagnosis_ref: crate::test_util::entity(0x73).to_hex(),
        };
        input.diagnosis = FailureDiagnosisState::Diagnosed(route.clone());
        let result = surfaced_failure_card(&vault, input);
        if accepted {
            assert_eq!(result?.diagnosis, FailureDiagnosisState::Diagnosed(route));
        } else {
            assert!(matches!(result, Err(Error::InvalidConfig(_))));
        }
    }
    assert_eq!(crate::AttemptQueue::new(&vault).list()?, before);
    Ok(())
}
