//! UNBUILT3-22 (FIX PROJECT-LEADER-NOT-RESIDENT; RULED
//! LEADER-RESIDENT-EXISTING-PROJECTS = A; ARCH-0067 #agents: "The leader is a
//! persistent resident with an inbox and a wake dial, so a message from a
//! person wakes it"). A project minted from a card binds its leader as the
//! resident of its home room in the birth write, under the minting owner's
//! tap. A person's turn there then wakes the leader once, after the default
//! wake hold (AGM-4 = C), in that project and that room. One leader
//! definition that leads two projects wakes in each project's room.

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchStatus, AgentDispatcher, RESIDENT_WAKE_HOLD_DEFAULT_SECS,
    resident_attempt_wakes_for_room,
};
use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    PROJECT_PROPOSAL_MINT_ACTION_ID, ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::store::GateDecisionId;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

/// A person's plain turn in `room`: no mention, no thread, no TASK.
fn speak(
    vault: &Vault,
    person: EntityId,
    room: EntityId,
    turn: EntityId,
    message: EntityId,
) -> TestResult {
    vault
        .memory(person, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "How is the index coming along?".into(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(())
}

/// The message a card is drafted from: the owner's turn in the home room
/// of a project the owner stands in.
fn source_message(vault: &Vault, owner: EntityId) -> TestResult<EntityId> {
    let root = vault.root_project()?;
    let staging = EntityId::now();
    let mut record = ProjectRecord::new(staging, Some(root), root, owner)?;
    record.roster.push(owner.to_hex());
    vault.put_project(staging, &record, 1)?;
    let message = EntityId::now();
    speak(
        vault,
        owner,
        EntityId::from_hex(&record.home_room)?,
        EntityId::now(),
        message,
    )?;
    Ok(message)
}

/// Mints a project from a card the owner taps, led by `leader`.
fn mint(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    leader: EntityId,
    source: EntityId,
    card_id: &str,
) -> TestResult<EntityId> {
    let card = ProjectProposalCard::new(
        card_id,
        "principal:owner",
        source.to_hex(),
        ProjectGoalDraft {
            goal: "Build the evidence index".into(),
            why: "Find records fast".into(),
            axes: vec!["coverage".into()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: leader.to_hex(),
            board_human_refs: vec![owner.to_hex()],
            budget_share_bps: 1250,
            starting_skill_refs: vec![],
        },
    )?;
    let tap = ConsentActionRequest::new(
        card_id,
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "principal:owner".into(),
        },
        ConsentSurface::CompanionConversation,
        4,
    )?;
    let signer = vault.owner_project_signer(issuer)?;
    let receipt = vault.mint_project_from_card(&card, &tap, proof, &signer)?;
    Ok(EntityId::from_hex(&receipt.project_id)?)
}

/// A fresh vault, its owner and owner proof, the host's slip issuer and the
/// seeded leader definition (the root project's leader).
fn fixture(dir: &tempfile::TempDir) -> TestResult<(Vault, EntityId, AuthenticatedOwner, EntityId)> {
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())?;
    let leader = EntityId::from_hex(
        &vault
            .project(vault.root_project()?)?
            .ok_or("the root project")?
            .leader,
    )?;
    Ok((vault, owner, proof, leader))
}

fn host_issuer(vault: &Vault) -> TestResult<HostSlipIssuer> {
    let issuer = HostSlipIssuer::from_secret(b"project-leader-resident-test-host")?;
    vault.ensure_host_root_slip(&issuer)?;
    Ok(issuer)
}

fn home_room(vault: &Vault, project: EntityId) -> TestResult<EntityId> {
    Ok(EntityId::from_hex(
        &vault
            .project(project)?
            .ok_or("the minted project")?
            .home_room,
    )?)
}

/// The staged wake of `agent` for `turn` in `room`, and when it was staged.
fn staged_at(vault: &Vault, agent: EntityId, room: EntityId, turn: EntityId) -> TestResult<u64> {
    let staged = vault.staged_room_wakes()?;
    staged
        .iter()
        .find(|row| row.wake.agent == agent && row.wake.room == room && row.wake.turn == turn)
        .map(|row| row.staged_at)
        .ok_or_else(|| {
            format!("a person's turn in the home room stages its leader's wake: {staged:?}").into()
        })
}

fn dispatched(outcome: &AgentDispatchOutcome) -> TestResult<&AgentDispatchStatus> {
    match outcome {
        AgentDispatchOutcome::Dispatched(status) => Ok(status),
        other => Err(format!("a new room wake run, got {other:?}").into()),
    }
}

fn room_wake_key(agent: EntityId, turn: EntityId) -> String {
    format!(
        "agent.dispatch:resident:{}:room:{}",
        agent.to_hex(),
        turn.to_hex()
    )
}

#[test]
fn a_person_in_the_home_room_wakes_the_projects_leader() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner, proof, leader) = fixture(&dir)?;
    let source = source_message(&vault, owner)?;
    let issuer = host_issuer(&vault)?;
    let project = mint(
        &vault,
        &proof,
        &issuer,
        owner,
        leader,
        source,
        "leader-resident-1",
    )?;
    let home = home_room(&vault, project)?;
    let turn = EntityId::now();
    speak(&vault, owner, home, turn, EntityId::now())?;

    let staged = staged_at(&vault, leader, home, turn)?;
    let due = staged + u64::from(RESIDENT_WAKE_HOLD_DEFAULT_SECS);
    let dispatcher = AgentDispatcher::new(&vault);
    let early = dispatcher.dispatch_resident_inbox(leader, 16, staged)?;
    assert!(
        early.outcomes.is_empty(),
        "the wake holds for the default hold: {:?}",
        early.outcomes
    );
    assert_eq!(early.held_until, Some(due));

    let pass = dispatcher.dispatch_resident_inbox(leader, 16, due)?;
    assert_eq!(
        pass.outcomes.len(),
        1,
        "one wake for the one turn: {:?}",
        pass.outcomes
    );
    let status = dispatched(&pass.outcomes[0])?;
    assert!(resident_attempt_wakes_for_room(&status.attempt, leader));
    assert_eq!(
        status.attempt.dedupe_key.as_deref(),
        Some(room_wake_key(leader, turn).as_str())
    );
    assert_eq!(status.input.project_ref, Some(project));
    assert_eq!(
        vault.agent_run_work_room(status.attempt.id, leader)?,
        Some(home)
    );
    assert!(
        dispatcher
            .dispatch_resident_inbox(leader, 16, due + 1)?
            .outcomes
            .is_empty(),
        "a taken turn wakes the leader once"
    );
    Ok(())
}

#[test]
fn one_leader_definition_leads_two_projects_and_each_room_wakes_it() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, owner, proof, leader) = fixture(&dir)?;
    let source_a = source_message(&vault, owner)?;
    let source_b = source_message(&vault, owner)?;
    let issuer = host_issuer(&vault)?;
    let project_a = mint(
        &vault,
        &proof,
        &issuer,
        owner,
        leader,
        source_a,
        "leader-resident-a",
    )?;
    let project_b = mint(
        &vault,
        &proof,
        &issuer,
        owner,
        leader,
        source_b,
        "leader-resident-b",
    )?;
    let home_a = home_room(&vault, project_a)?;
    let home_b = home_room(&vault, project_b)?;
    assert_ne!(home_a, home_b);
    let turn_a = EntityId::now();
    speak(&vault, owner, home_a, turn_a, EntityId::now())?;
    let turn_b = EntityId::now();
    speak(&vault, owner, home_b, turn_b, EntityId::now())?;

    let due = staged_at(&vault, leader, home_a, turn_a)?
        .max(staged_at(&vault, leader, home_b, turn_b)?)
        + u64::from(RESIDENT_WAKE_HOLD_DEFAULT_SECS);
    let dispatcher = AgentDispatcher::new(&vault);
    let pass = dispatcher.dispatch_resident_inbox(leader, 16, due)?;
    assert_eq!(
        pass.outcomes.len(),
        2,
        "one wake per project room: {:?}",
        pass.outcomes
    );
    let mut woke = Vec::new();
    for outcome in &pass.outcomes {
        let status = dispatched(outcome)?;
        let room = vault
            .agent_run_work_room(status.attempt.id, leader)?
            .ok_or("a room wake run works in its room")?;
        assert!(
            status.input.carried_wake_keys.is_empty(),
            "a wake carries no other room's turn"
        );
        woke.push((
            status.input.project_ref,
            room,
            status.attempt.dedupe_key.clone(),
        ));
    }
    woke.sort_by_key(|(project, _, _)| project.map(|id| id.to_hex()));
    let mut expected = vec![
        (Some(project_a), home_a, Some(room_wake_key(leader, turn_a))),
        (Some(project_b), home_b, Some(room_wake_key(leader, turn_b))),
    ];
    expected.sort_by_key(|(project, _, _)| project.map(|id| id.to_hex()));
    assert_eq!(woke, expected);
    Ok(())
}
