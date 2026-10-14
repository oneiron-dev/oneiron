//! Sol R1 F1 on FACET-READ: a room turn holds the facet its project's slice
//! had when the turn opened. An owner re-signing that slice to another facet
//! mid-turn only narrows the turn; a new turn reads the new facet.
use super::super::*;
use super::authority::{FIXTURE_HOST, sign_project};
use crate::authority::HostSlipIssuer;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::federation::{ScopeAxis, ScopeId};
use crate::memory::ClaimInput;
use crate::pipeline::{
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, WorldAuthoritySet, world_access_claim_body,
};
use crate::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};

fn note(subject: EntityId, value: &str) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: "note.topic".into(),
        subject_ref: subject.to_hex(),
        value: serde_json::json!(value),
        confidence: 1.0,
        source: "user_stated".into(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

#[test]
fn a_room_turn_keeps_the_facet_it_opened_with() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(crate::VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = EntityId::now();
    let (work, home) = (EntityId::now(), EntityId::now());
    for (id, kind) in [
        (agent, ENTITY_TYPE_PERSON),
        (work, ENTITY_TYPE_FACET),
        (home, ENTITY_TYPE_FACET),
    ] {
        vault.put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"fixture")?;
    }
    let base_only = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        agent,
        &WorldAuthoritySet::new(true, [])?,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )?;
    vault.put_claim(
        &EntityId::now(),
        &base_only,
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    let root = vault.root_project()?;
    let project = EntityId::now();
    let mut record = ProjectRecord::new(project, Some(root), root, owner)?;
    record.slice.facet = Some(work);
    record.roster.push(agent.to_hex());
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    // The agent is the vault's own, bound under the host that signs the
    // project below. Binding roots the vault, so it follows the project.
    let issuer = HostSlipIssuer::from_secret(FIXTURE_HOST)?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.bind_host_actor_for_test(&issuer, agent, "agent")?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let noted = |value: &str, facet: EntityId| -> Result<String> {
        let receipt = host.claim_upsert(&note(room, value)).expect("note");
        let hex = host
            .get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("the owner reads the note")
            .id_hex;
        vault.put_edge(&EntityId::from_hex(&hex)?, EdgeKind::FacetOf, &facet, 1.0)?;
        Ok(hex)
    };
    let (at_work, at_home) = (noted("lantern desk", work)?, noted("lantern porch", home)?);
    let agent = vault.memory(agent, EdgeActorClass::Agent);
    let reads = |turn: &crate::memory::RoomTurnHandle<'_>, hex: &str| {
        turn.get_entity(hex).expect("entity read").value.is_some()
    };

    let turn = agent.for_room_turn(room).expect("open room turn");
    assert_eq!(
        turn.scope().expect("turn scope").facets,
        ScopeAxis::Some([ScopeId(work)].into()),
        "the turn reports the room's facet"
    );
    assert!(reads(&turn, &at_work));
    assert!(
        !reads(&turn, &at_home),
        "a home note is outside a work room"
    );

    // The owner re-signs the project's slice to home.
    let mut resigned = vault.project(project)?.expect("project");
    resigned.slice.facet = Some(home);
    sign_project(&vault, project, &mut resigned, owner)?;
    vault.put_project(project, &resigned, 2)?;
    assert!(
        reads(
            &agent.for_room_turn(room).expect("open room turn"),
            &at_home
        ),
        "a new turn reads the room's new facet"
    );
    assert!(
        !reads(&turn, &at_home),
        "the open turn never reads a facet it opened without"
    );
    assert!(!reads(&turn, &at_work), "and keeps the narrowing");
    assert_eq!(turn.scope().expect("turn scope").facets, ScopeAxis::Bottom);
    Ok(())
}
