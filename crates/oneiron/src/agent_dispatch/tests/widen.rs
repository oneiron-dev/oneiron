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
