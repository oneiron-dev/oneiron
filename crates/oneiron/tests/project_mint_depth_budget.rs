//! A card mint derives the child's depth budget from its parent, as a spawn
//! does, so a thread converts under a minted project
//! (T0F-PROJECT-CONVERSION-DEPTH-BUDGET).
use oneiron::authority::HostSlipIssuer;
use oneiron::edge::EdgeActorClass;
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    PROJECT_PROPOSAL_MINT_ACTION_ID, ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EntityId, Result, TimeRange, Vault};

fn speak(
    vault: &Vault,
    host: EntityId,
    room: EntityId,
    turn: EntityId,
    message: EntityId,
    parent: Option<EntityId>,
    at: u64,
) {
    vault
        .memory(host, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "thread message".into(),
                metadata: Some(match parent {
                    Some(id) => serde_json::json!({"room_thread_of":id.to_hex()}),
                    None => serde_json::json!({}),
                }),
                is_visible: true,
                order: 0,
                parts: None,
                quote: None,
            }],
            occurred_at: at,
            thread_audience: None,
            assertions: Default::default(),
        })
        .expect("room speech");
}

/// The host's slip issuer, rooted in `vault`'s authority log: the owner's
/// project signer signs mints and conversions with its host-held slip.
fn host_issuer(vault: &Vault) -> HostSlipIssuer {
    let issuer =
        HostSlipIssuer::from_secret(b"project-mint-depth-budget-test-host").expect("host issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    issuer
}

/// A person the roster seats; the task holder is a member, as a
/// conversion's task move requires.
fn put_person(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(())
}

fn mint_card(
    message: EntityId,
    leader: EntityId,
    board: Vec<String>,
) -> Result<ProjectProposalCard> {
    ProjectProposalCard::new(
        "proposal-1",
        "principal:owner",
        message.to_hex(),
        ProjectGoalDraft {
            goal: "Build index".into(),
            why: "Find evidence".into(),
            axes: vec!["coverage".into()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: leader.to_hex(),
            board_human_refs: board,
            budget_share_bps: 1250,
            starting_skill_refs: vec![],
        },
    )
}

fn mint_request() -> Result<ConsentActionRequest> {
    ConsentActionRequest::new(
        "proposal-1",
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "principal:owner".into(),
        },
        ConsentSurface::CompanionConversation,
        4,
    )
}

#[test]
fn card_mint_derives_depth_budget_from_parent() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner =
        vault.authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())?;
    // The staging project only hosts the mint's source message; the mint's
    // parent is the root.
    let staging_id = EntityId::now();
    let staging = ProjectRecord::new(
        staging_id,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner_id,
    )
    .expect("fixture");
    vault.put_project(staging_id, &staging, 1)?;
    let staging_room = EntityId::from_hex(&staging.home_room)?;
    let message = EntityId::now();
    speak(
        &vault,
        owner_id,
        staging_room,
        EntityId::now(),
        message,
        None,
        2,
    );
    let issuer = host_issuer(&vault);
    let signer = vault.owner_project_signer(&issuer)?;
    let root = vault.project(vault.root_project()?)?.expect("root");
    let leader = EntityId::from_hex(&root.leader)?;
    let card = mint_card(message, leader, vec![owner_id.to_hex()])?;
    let request = mint_request()?;
    let receipt = vault.mint_project_from_card(&card, &request, &owner, &signer)?;
    let id = EntityId::from_hex(&receipt.project_id)?;
    let minted = vault.project(id)?.expect("minted project");
    assert_eq!(minted.depth_limit, root.depth_limit);
    assert_eq!(
        minted.depth_remaining,
        root.depth_remaining.checked_sub(1).expect("root budget")
    );
    Ok(())
}

#[test]
fn conversion_under_minted_project_spends_one_level() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let owner =
        vault.authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())?;
    let holder = EntityId::from_bytes([0xE1; 16])?;
    put_person(&vault, holder)?;
    let staging_id = EntityId::now();
    let staging = ProjectRecord::new(
        staging_id,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner_id,
    )
    .expect("fixture");
    vault.put_project(staging_id, &staging, 1)?;
    let staging_room = EntityId::from_hex(&staging.home_room)?;
    let source_message = EntityId::now();
    speak(
        &vault,
        owner_id,
        staging_room,
        EntityId::now(),
        source_message,
        None,
        2,
    );
    let issuer = host_issuer(&vault);
    let signer = vault.owner_project_signer(&issuer)?;
    let leader = EntityId::from_hex(&vault.project(vault.root_project()?)?.expect("root").leader)?;
    // The holder sits on the minted board, so its open task binds and moves.
    let card = mint_card(
        source_message,
        leader,
        vec![owner_id.to_hex(), holder.to_hex()],
    )?;
    let request = mint_request()?;
    let receipt = vault.mint_project_from_card(&card, &request, &owner, &signer)?;
    let minted_id = EntityId::from_hex(&receipt.project_id)?;
    let minted = vault.project(minted_id)?.expect("minted project");
    let room = EntityId::from_hex(&minted.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    speak(&vault, owner_id, room, trunk, EntityId::now(), None, 5);
    let thread = EntityId::now();
    speak(&vault, owner_id, room, thread, message, Some(trunk), 5);
    let task = vault
        .memory(holder, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("work"),
            Some("task".into()),
            None,
            Some(5),
        ))
        .expect("task created")
        .task_ref
        .expect("open task effects");
    vault.bind_room_thread_task(owner_id, room, thread, task)?;
    let child_id = EntityId::now();
    let child = vault
        .convert_thread_to_project(
            &owner, &signer, room, thread, message, child_id, None, None, 6,
        )
        .expect("conversion under a minted project");
    assert_eq!(child.leader, holder.to_hex());
    assert_eq!(child.tasks, vec![task.to_hex()]);
    assert_eq!(
        child.depth_remaining,
        minted
            .depth_remaining
            .checked_sub(1)
            .expect("minted budget")
    );
    assert_eq!(vault.thread_project(room, thread)?, Some(child_id));
    Ok(())
}
