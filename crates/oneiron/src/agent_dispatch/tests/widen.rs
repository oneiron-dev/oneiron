//! Propose-widen is inert until an authenticated holder of the board above acts.

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::context_projection::ChatProjection;
use crate::store::GateDecisionId;

fn open_board_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault =
        Vault::open(dir.path(), VaultConfig::default()).expect("vault with default task policy");
    (dir, vault)
}

fn owner(vault: &Vault, id: EntityId) -> Result<AuthenticatedOwner> {
    vault.put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"board owner")?;
    vault.authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
}

fn board(vault: &Vault, actor: EntityId, row: EntityId) -> AttemptId {
    // The TASK and Owner fact are minted by the shipped facade, not raw rows.
    let creator = EntityId::from_bytes([0xE1; 16]).expect("first-party creator");
    vault
        .put_entity(&creator, ENTITY_TYPE_PERSON, t(1), 1, b"creator")
        .expect("creator");
    vault
        .memory(creator, EdgeActorClass::Agent)
        .tasks_create(
            &TaskCreateSpec::new(Value::from("board work"), None, Some(actor), Some(1))
                .with_assignee(TaskAssignee::AgentDef { agent_def_ref: row }),
        )
        .expect("board TASK")
        .route
        .expect("route")
        .local_attempt()
        .expect("board dispatch")
}

fn chat_turn(vault: &Vault) -> Result<EntityId> {
    let id = test_id(0xA7);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(
        &mut bytes,
        &Value::Map(vec![
            (Value::from("role"), Value::from("user")),
            (Value::from("text"), Value::from("board context")),
        ]),
    )
    .expect("turn bytes");
    vault.put_entity(&id, ENTITY_TYPE_TURN, t(1), 1, &bytes)?;
    Ok(id)
}

fn input(row: EntityId, parent: AttemptId, key: &str) -> DispatchAgent {
    DispatchAgent {
        target: AgentDispatchTarget::Custom(row),
        parent_attempt: Some(parent),
        dedupe_key: Some(key.to_owned()),
        run_id: None,
        now: 3,
    }
}

fn request() -> AgentSpawnContext {
    AgentSpawnContext::default().with_context_spec(ContextSpec {
        chat: ChatProjection::Recent { last_n: 1 },
        ..ContextSpec::excluded()
    })
}

fn proposed(outcome: AgentDispatchOutcome) -> Box<ContextWidenProposal> {
    let AgentDispatchOutcome::ProposedWiden(proposal) = outcome else {
        panic!("must propose")
    };
    proposal
}

#[test]
fn proposed_widen_is_inert_replay_bound_and_only_board_owner_lands() -> Result<()> {
    let (_dir, vault) = open_board_vault();
    let owner = owner(&vault, test_id(0xA0))?;
    let outsider = self::owner(&vault, test_id(0xB2))?;
    let row = put_row(&vault, 0xB3, "widen.agent", AgentCeiling::Auto)?;
    let turn = chat_turn(&vault)?;
    let board = board(&vault, owner.actor(), row);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch_with_context(
        input(row, board, "parent"),
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    let before = AttemptQueue::new(&vault).list()?;
    let proposal = proposed(
        dispatcher.dispatch_with_context(input(row, parent.attempt.id, "child"), request())?,
    );
    let mut retry = input(row, parent.attempt.id, "child");
    retry.now = 90;
    assert_eq!(
        proposed(dispatcher.dispatch_with_context(retry.clone(), request())?),
        proposal
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    assert!(
        dispatcher
            .resolve_attempt_context(parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    assert_eq!(
        dispatcher
            .approve_context_widen(&outsider, &proposal, 4)
            .expect_err("unrelated owner")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    let mut altered = (*proposal).clone();
    altered.requested_context.chat = ChatProjection::Recent { last_n: 2 };
    assert_eq!(
        dispatcher
            .approve_context_widen(&owner, &altered, 4)
            .expect_err("modified proposal")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    let landed = dispatched(dispatcher.approve_context_widen(&owner, &proposal, 5)?);
    assert_eq!(
        decode_dreamer_attempt_payload(&landed.attempt.payload)?.parent_attempt,
        Some(parent.attempt.id)
    );
    assert_eq!(landed.input.context_spec, request().context_spec);
    assert_eq!(
        landed.input.depth_remaining,
        Some(parent.input.depth_remaining.expect("depth") - 1)
    );
    assert_eq!(
        dispatcher
            .resolve_attempt_context(landed.attempt.id)?
            .chat_sections,
        vec![format!("tn_{}", turn.to_hex())]
    );
    assert_eq!(
        dispatcher
            .resolve_attempt_context(parent.attempt.id)?
            .chat_sections,
        vec![format!("tn_{}", turn.to_hex())]
    );
    let AgentDispatchOutcome::Existing(again) =
        dispatcher.approve_context_widen(&owner, &proposal, 6)?
    else {
        panic!("approval replay")
    };
    assert_eq!(again.attempt.id, landed.attempt.id);
    let AgentDispatchOutcome::Existing(again) =
        dispatcher.dispatch_with_context(retry, request())?
    else {
        panic!("dispatch replay")
    };
    assert_eq!(again.attempt.id, landed.attempt.id);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before.len() + 1);
    Ok(())
}

#[test]
fn owner_approval_cannot_exceed_board_live_recursive_slice() -> Result<()> {
    let (_dir, vault) = open_board_vault();
    let owner = owner(&vault, test_id(0xA0))?;
    let row = put_row(&vault, 0xB3, "widen.agent", AgentCeiling::Auto)?;
    chat_turn(&vault)?;
    let board = board(&vault, owner.actor(), row);
    let dispatcher = AgentDispatcher::new(&vault);
    let parent = dispatched(dispatcher.dispatch_with_context(
        input(row, board, "parent"),
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    let mut too_wide = request();
    too_wide.context_spec.as_mut().expect("spec").chat = ChatProjection::Recent { last_n: 2 };
    let proposal = proposed(
        dispatcher.dispatch_with_context(input(row, parent.attempt.id, "too-wide"), too_wide)?,
    );
    let before = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        dispatcher
            .approve_context_widen(&owner, &proposal, 4)
            .expect_err("board has only one turn")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    assert!(
        dispatcher
            .resolve_attempt_context(parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    assert_eq!(
        dispatcher
            .resolve_attempt_context(board)?
            .chat_sections
            .len(),
        1
    );
    // Its exact one-turn proposal is approvable, but later descendants still
    // cannot raise that newly widened bound without another board decision.
    let valid = proposed(
        dispatcher.dispatch_with_context(input(row, parent.attempt.id, "valid"), request())?,
    );
    let child = dispatched(dispatcher.approve_context_widen(&owner, &valid, 5)?);
    let grandchild = dispatched(dispatcher.dispatch(input(row, child.attempt.id, "grandchild"))?);
    assert_eq!(
        dispatcher
            .resolve_attempt_context(grandchild.attempt.id)?
            .chat_sections
            .len(),
        1
    );
    Ok(())
}

#[test]
fn missing_board_authority_depth_and_sibling_refusals_never_enqueue() -> Result<()> {
    let (_dir, vault) = open_board_vault();
    let owner = owner(&vault, test_id(0xA0))?;
    let row = put_row(&vault, 0xB3, "widen.agent", AgentCeiling::Auto)?;
    chat_turn(&vault)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 1,
        },
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    let proposal = proposed(
        dispatcher.dispatch_with_context(input(row, root.attempt.id, "root-request"), request())?,
    );
    assert!(proposal.board_attempt.is_none());
    assert_eq!(
        dispatcher
            .approve_context_widen(&owner, &proposal, 2)
            .expect_err("no board")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    let before = AttemptQueue::new(&vault).list()?;
    let bad_sibling = request().with_context_from(vec![test_id(0xB1)]);
    assert_eq!(
        dispatcher
            .dispatch_with_context(input(row, root.attempt.id, "bad-sibling"), bad_sibling)
            .expect_err("invalid sibling is not a proposal")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    let exhausted = dispatched(dispatcher.dispatch_with_context(
        input(row, root.attempt.id, "exhausted"),
        AgentSpawnContext::default().with_depth_remaining(0),
    )?);
    let before = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        dispatcher
            .dispatch_with_context(input(row, exhausted.attempt.id, "zero"), request())
            .expect_err("zero stays a refusal")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    Ok(())
}

#[test]
fn different_request_cannot_reuse_a_parked_dedupe_key() -> Result<()> {
    let (_dir, vault) = open_board_vault();
    let row = put_row(&vault, 0xB3, "widen.agent", AgentCeiling::Auto)?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 1,
        },
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    proposed(dispatcher.dispatch_with_context(input(row, root.attempt.id, "same"), request())?);
    let mut no_key = input(row, root.attempt.id, "unused");
    no_key.dedupe_key = None;
    let without_key = proposed(dispatcher.dispatch_with_context(no_key.clone(), request())?);
    no_key.now = 100;
    assert_eq!(
        proposed(dispatcher.dispatch_with_context(no_key, request())?),
        without_key
    );
    let mut changed = request();
    changed.depth_remaining = Some(1);
    assert_eq!(
        dispatcher
            .dispatch_with_context(input(row, root.attempt.id, "same"), changed)
            .expect_err("dedupe mismatch")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    Ok(())
}

#[test]
fn approval_does_not_skip_an_excluding_ancestor() -> Result<()> {
    let (_dir, vault) = open_board_vault();
    let owner = owner(&vault, test_id(0xA0))?;
    let row = put_row(&vault, 0xB3, "widen.agent", AgentCeiling::Auto)?;
    chat_turn(&vault)?;
    let seeded_board = board(&vault, owner.actor(), row);
    let task = EntityId::from_hex(
        AttemptQueue::new(&vault)
            .get(seeded_board)?
            .expect("board")
            .task_ref
            .as_deref()
            .expect("backlink"),
    )?;
    let dispatcher = AgentDispatcher::new(&vault);
    let ancestor = dispatched(dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(row),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now: 1,
        },
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    // Fixture a task-backed nested board through the transaction-composable
    // route door. Ownership still comes from tasks.create, never a raw fact.
    let mut txn = vault.store.env.write_txn()?;
    let nested = dispatched(dispatcher.dispatch_in_txn(
        &mut txn,
        Some(task),
        input(row, ancestor.attempt.id, "nested-board"),
        AgentSpawnContext::default(),
    )?);
    txn.commit()?;
    let parent = dispatched(dispatcher.dispatch(input(row, nested.attempt.id, "parent"))?);
    let proposal = proposed(
        dispatcher.dispatch_with_context(input(row, parent.attempt.id, "wide"), request())?,
    );
    let before = AttemptQueue::new(&vault).list()?;
    assert_eq!(
        dispatcher
            .approve_context_widen(&owner, &proposal, 4)
            .expect_err("board inherits an empty ancestor")
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&vault).list()?, before);
    assert!(
        dispatcher
            .resolve_attempt_context(ancestor.attempt.id)?
            .chat_sections
            .is_empty()
    );
    assert!(
        dispatcher
            .resolve_attempt_context(nested.attempt.id)?
            .chat_sections
            .is_empty()
    );
    assert!(
        dispatcher
            .resolve_attempt_context(parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    Ok(())
}

struct WorkflowWidenFixture {
    dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    parent: AgentDispatchStatus,
    board_row: EntityId,
    first: EntityId,
    second: EntityId,
    workflow_id: EntityId,
}

fn workflow_widen_fixture() -> Result<WorkflowWidenFixture> {
    let (dir, vault) = open_board_vault();
    let owner = owner(&vault, test_id(0xA0))?;
    let board_row = put_row(&vault, 0xB3, "workflow.board", AgentCeiling::Auto)?;
    let parent_row = put_row(&vault, 0xB4, "workflow.parent", AgentCeiling::Proposed)?;
    let first = put_row(&vault, 0xB5, "workflow.first", AgentCeiling::Auto)?;
    let second = put_row(&vault, 0xB6, "workflow.second", AgentCeiling::Auto)?;
    chat_turn(&vault)?;
    let board = board(&vault, owner.actor(), board_row);
    let parent = dispatched(AgentDispatcher::new(&vault).dispatch_with_context(
        input(parent_row, board, "workflow-parent"),
        AgentSpawnContext::default().with_context_spec(ContextSpec::excluded()),
    )?);
    let workflow_id = test_id(0xC0);
    vault.save_workflow(
        &workflow_id,
        &crate::agent_def::workflow::WorkflowDefinition::new("widened", vec![first, second])?,
        2,
    )?;
    Ok(WorkflowWidenFixture {
        dir,
        vault,
        owner,
        parent,
        board_row,
        first,
        second,
        workflow_id,
    })
}

fn workflow_widen_input(case: &WorkflowWidenFixture) -> DispatchAgent {
    DispatchAgent {
        target: AgentDispatchTarget::Workflow(case.workflow_id),
        ..input(case.first, case.parent.attempt.id, "workflow-widen")
    }
}

fn landed_workflow(outcome: AgentDispatchOutcome) -> WorkflowDispatchStatus {
    match outcome {
        AgentDispatchOutcome::WorkflowDispatched(status)
        | AgentDispatchOutcome::WorkflowExisting(status) => *status,
        other => panic!("workflow expected, got {other:?}"),
    }
}

#[test]
fn workflow_widen_parks_whole_composition_and_replays_one_wrapper_after_reopen() -> Result<()> {
    let case = workflow_widen_fixture()?;
    let mut dispatch = workflow_widen_input(&case);
    // No caller dedupe key: the exact proposal must still name just one wrapper.
    dispatch.dedupe_key = None;
    let dispatcher = AgentDispatcher::new(&case.vault);
    let before = AttemptQueue::new(&case.vault).list()?;
    let proposal = proposed(dispatcher.dispatch_with_context(dispatch.clone(), request())?);
    assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
    assert_eq!(
        proposed(dispatcher.dispatch_with_context(dispatch.clone(), request())?),
        proposal
    );
    assert!(
        dispatcher
            .resolve_attempt_context(case.parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    let outsider = owner(&case.vault, test_id(0xD1))?;
    assert_eq!(
        dispatcher
            .approve_context_widen(&outsider, &proposal, 4)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    let mut edited = (*proposal).clone();
    edited.requested_context.chat = ChatProjection::Recent { last_n: 2 };
    assert_eq!(
        dispatcher
            .approve_context_widen(&case.owner, &edited, 4)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
    let status = landed_workflow(dispatcher.approve_context_widen(&case.owner, &proposal, 5)?);
    assert_eq!(status.definition.steps, vec![case.first, case.second]);
    assert_eq!(status.attempt.state, AttemptState::Paused);
    assert_eq!(
        AttemptQueue::new(&case.vault).list()?.len(),
        before.len() + 2
    );
    assert_eq!(
        decode_dreamer_attempt_payload(&status.attempt.payload)?.parent_attempt,
        Some(case.parent.attempt.id)
    );
    assert!(
        dispatcher
            .dispatch(input(case.first, status.attempt.id, "wrapper-cannot-spawn"))
            .is_err()
    );
    let root = status.attempt.id;
    assert_eq!(
        case.vault
            .approve_once(&case.owner, proposal.consent.effect_digest)
            .unwrap_err()
            .kind(),
        ErrorKind::ConsentApproveOnceSpent
    );
    let parent_id = case.parent.attempt.id;
    let child_depth = case.parent.input.depth_remaining.unwrap() - 1;
    let first = case.first;
    let second = case.second;
    let WorkflowWidenFixture {
        dir, vault, owner, ..
    } = case;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let dispatcher = AgentDispatcher::new(&vault);
    let AgentDispatchOutcome::WorkflowExisting(replayed) =
        dispatcher.approve_context_widen(&owner, &proposal, 6)?
    else {
        panic!("typed approval replay")
    };
    assert_eq!(replayed.attempt.id, root);
    let AgentDispatchOutcome::WorkflowExisting(replayed) =
        dispatcher.dispatch_with_context(dispatch, request())?
    else {
        panic!("typed dispatch replay")
    };
    assert_eq!(replayed.attempt.id, root);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before.len() + 2);
    let expected_chat = vec![format!("tn_{}", test_id(0xA7).to_hex())];
    assert_eq!(
        dispatcher.resolve_attempt_context(parent_id)?.chat_sections,
        expected_chat
    );
    let mut executed = Vec::new();
    for (ordinal, requested) in [first, second].into_iter().enumerate() {
        let progress = dispatcher.run_workflow_step(
            root,
            "widen-host",
            10 + ordinal as u64,
            |status, context| {
                assert_eq!(context.chat_sections, expected_chat);
                assert_eq!(status.input.depth_remaining, Some(child_depth));
                assert_eq!(status.input.definition.ceiling, AgentCeiling::Proposed);
                assert_eq!(status.input.definition.forked_from, Some(requested));
                executed.push(status.input.target.agent_definition_ref()?);
                crate::attempt_queue::AttemptResultRef::new(format!("artifact:widen-{ordinal}"))
            },
        )?;
        if ordinal == 0 {
            assert!(matches!(progress, WorkflowProgress::Advanced(_)));
        } else {
            assert_eq!(progress, WorkflowProgress::Completed);
        }
    }
    assert_eq!(
        dispatcher.run_workflow_step(root, "widen-host", 20, |_, _| panic!("replay executed"))?,
        WorkflowProgress::Completed
    );
    let report = dispatcher.workflow_status(root)?;
    assert_eq!(
        report
            .results
            .iter()
            .map(|r| (
                r.ordinal,
                r.requested_agent.clone(),
                r.dispatched_agent.clone(),
                r.result_ref.as_str()
            ))
            .collect::<Vec<_>>(),
        vec![
            (0, first.to_hex(), executed[0].to_hex(), "artifact:widen-0"),
            (1, second.to_hex(), executed[1].to_hex(), "artifact:widen-1"),
        ]
    );
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), before.len() + 3);
    Ok(())
}

#[test]
fn workflow_widen_rejects_stale_composition_leaf_and_revoked_authority_without_spending()
-> Result<()> {
    for change in [
        "workflow",
        "later-composition",
        "later-revoked",
        "parent-revoked",
        "board-revoked",
    ] {
        let case = workflow_widen_fixture()?;
        let dispatcher = AgentDispatcher::new(&case.vault);
        let proposal =
            proposed(dispatcher.dispatch_with_context(workflow_widen_input(&case), request())?);
        let before = AttemptQueue::new(&case.vault).list()?;
        if change == "workflow" {
            let mut edited = case.vault.get_workflow(&case.workflow_id)?.unwrap();
            edited.steps.reverse();
            edited.revision += 1;
            case.vault
                .update_workflow(&case.workflow_id, 1, &edited, 4)?;
        } else {
            let row = match change {
                "parent-revoked" => case.parent.input.target.agent_definition_ref()?,
                "board-revoked" => case.board_row,
                _ => case.second,
            };
            let mut edited = case.vault.get_agent_definition(&row)?.unwrap();
            if change == "later-composition" {
                edited.version = "changed-after-proposal".into();
            } else {
                edited.version = "revoked-after-proposal".into();
                edited.enabled = false;
            }
            case.vault.update_agent_definition(&row, &edited, t(4), 4)?;
        }
        let error = dispatcher
            .approve_context_widen(&case.owner, &proposal, 5)
            .unwrap_err();
        assert_eq!(
            error.kind(),
            if change.ends_with("revoked") {
                ErrorKind::AgentDefinitionDisabled
            } else {
                ErrorKind::InvalidAgentDispatchInput
            }
        );
        assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
        // Observable consent door: failed approval left no receipt or spent marker.
        case.vault
            .approve_once(&case.owner, proposal.consent.effect_digest)?;
    }
    Ok(())
}

#[test]
fn workflow_widen_late_prepare_failure_rolls_back_consent_forks_slice_and_queue() -> Result<()> {
    let case = workflow_widen_fixture()?;
    let dispatcher = AgentDispatcher::new(&case.vault);
    let proposal =
        proposed(dispatcher.dispatch_with_context(workflow_widen_input(&case), request())?);
    let fork = |id| -> Result<EntityId> {
        super::super::attenuation::attenuated_fork_id(
            id,
            &super::super::attenuation::source_content_fingerprint(
                &case.vault.get_agent_definition(&id)?.unwrap(),
            )?,
            case.parent.attempt.id,
            None,
        )
    };
    let first_fork = fork(case.first)?;
    let later_fork = fork(case.second)?;
    // The later fork fails only after approval has minted/spent and preparation
    // has written the earlier fork in the same (ultimately aborted) transaction.
    let foreign = case.vault.get_agent_definition(&case.board_row)?.unwrap();
    case.vault
        .put_agent_definition(&later_fork, &foreign, t(4), 4)?;
    let before = AttemptQueue::new(&case.vault).list()?;
    assert_eq!(
        dispatcher
            .approve_context_widen(&case.owner, &proposal, 5)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
    assert!(case.vault.get_raw(&first_fork)?.is_none());
    assert!(
        dispatcher
            .resolve_attempt_context(case.parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    assert_eq!(
        proposed(dispatcher.dispatch_with_context(workflow_widen_input(&case), request())?),
        proposal
    );
    case.vault
        .approve_once(&case.owner, proposal.consent.effect_digest)?;
    Ok(())
}

#[test]
fn workflow_widen_revalidates_settled_siblings_and_keeps_structural_refusals() -> Result<()> {
    let case = workflow_widen_fixture()?;
    let dispatcher = AgentDispatcher::new(&case.vault);
    let parent_row = case.parent.input.target.agent_definition_ref()?;
    let (sibling, _) = sibling_task(
        &case.vault,
        parent_row,
        0xD4,
        Some(TaskTerminalDisposition::Completed),
    );
    let spawn = request().with_context_from(vec![sibling]);
    let proposal = proposed(dispatcher.dispatch_with_context(workflow_widen_input(&case), spawn)?);
    case.vault.batch().delete(&sibling).commit()?;
    let before = AttemptQueue::new(&case.vault).list()?;
    assert_eq!(
        dispatcher
            .approve_context_widen(&case.owner, &proposal, 5)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
    assert!(
        dispatcher
            .resolve_attempt_context(case.parent.attempt.id)?
            .chat_sections
            .is_empty()
    );
    case.vault
        .approve_once(&case.owner, proposal.consent.effect_digest)?;
    let exhausted = dispatched(dispatcher.dispatch_with_context(
        input(case.first, case.parent.attempt.id, "workflow-exhausted"),
        AgentSpawnContext::default().with_depth_remaining(0),
    )?);
    let before = AttemptQueue::new(&case.vault).list()?;
    let mut dispatch = workflow_widen_input(&case);
    dispatch.parent_attempt = Some(exhausted.attempt.id);
    dispatch.dedupe_key = Some("workflow-zero".into());
    assert_eq!(
        dispatcher
            .dispatch_with_context(dispatch, request())
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidAgentDispatchInput
    );
    assert_eq!(AttemptQueue::new(&case.vault).list()?, before);
    Ok(())
}
