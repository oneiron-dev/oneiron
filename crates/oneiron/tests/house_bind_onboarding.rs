//! HOUSE-BIND = A (the owner, 10 Nov 07:43): a workspace whose house is a
//! seeded agent onboards its first member. Onboarding's first step used to
//! anchor the house agent to the workspace's ORG, and every seeded agent is
//! already anchored to its own model PERSON, so the step was refused
//! ("already bound differently") and no member could join. The house now
//! keeps its model PERSON, and the step only settles the workspace preset.
//!
//! No `cfg` is needed and every door used here is on main, so the file builds
//! there for the red run.

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantPreset, FederationGrantRole};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::actor_subject_anchor;
use oneiron::{
    CompanionBirthIntent, CompanionChoice, EntityId, MemberGrantBundle, MemberOnboardingIntent,
    Result, TimeRange, Vault, VaultConfig, WorkspaceRosterPreset, WorkspaceRosterRole, WriteActor,
};

const WORKSPACE: &str = "house-bind-onboarding-workspace";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const VAULT_ID: u64 = 41;

fn id(seed: u8) -> Result<EntityId> {
    Ok(EntityId::from_bytes([seed; 16])?)
}

/// A plain row of `entity_type` at `seed`, as a host's own import writes one.
fn seed_row(vault: &Vault, seed: u8, entity_type: u8) -> Result<EntityId> {
    let row = id(seed)?;
    vault.put_entity(
        &row,
        entity_type,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        b"house bind onboarding fixture",
    )?;
    Ok(row)
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "house bind onboarding fixture",
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
        ClaimSource::Imported,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from(agent_id),
        )]),
        None,
        true,
        None,
    )
}

#[test]
fn a_workspace_whose_house_is_a_seeded_agent_onboards_its_first_member() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof =
        vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let org = seed_row(&vault, 0xB2, ENTITY_TYPE_ORG)?;
    let member = seed_row(&vault, 0xA1, ENTITY_TYPE_PERSON)?;
    let member_facet = seed_row(&vault, 0xA3, ENTITY_TYPE_FACET)?;
    let companion_facet = seed_row(&vault, 0xC3, ENTITY_TYPE_FACET)?;
    let profile_grant = id(0xC5)?;
    // The workspace's shared vault, the owner its Owner: the grant that
    // authorizes the onboarding.
    vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], vault.now_recorded_at())?;

    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let now = vault.now_recorded_at();
    let anchor = actor_subject_anchor(&vault, &house, now)?.expect("a seeded agent's anchor");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    let intent = MemberOnboardingIntent {
        onboarding_id: "house-bind-onboarding".to_owned(),
        workspace: preset,
        person_ref: member,
        actor_ref: id(0xA5)?,
        actor_definition: definition("garden.member"),
        work_facet_ref: member_facet,
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: id(0xA6)?,
            role: FederationGrantRole::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: id(0xC1)?,
            actor_ref: id(0xC2)?,
            work_facet_ref: companion_facet,
            profile_grant_ref: profile_grant,
            actor_definition: definition("garden.companion"),
            display_name: "Quillfeather".to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: now,
    };

    let outcome = vault
        .onboard_workspace_member(intent, &WriteActor::new(owner, EdgeActorClass::Human), None)
        .expect("the first member onboards: step 1 leaves the seeded house's anchor alone");
    assert_eq!(outcome.person_ref, member);

    let later = vault.now_recorded_at();
    assert_eq!(
        actor_subject_anchor(&vault, &house, later)?,
        Some(anchor),
        "the house keeps its model PERSON anchor"
    );
    let roster = vault.workspace_roster(WORKSPACE, later)?;
    let house_row = roster
        .iter()
        .find(|entry| matches!(entry.role, WorkspaceRosterRole::HouseMind))
        .expect("the roster's house mind row");
    assert_eq!(house_row.actor_ref, house);
    assert_eq!(
        house_row.subject_ref, org,
        "the house row names the ORG its preset says it runs"
    );
    Ok(())
}
