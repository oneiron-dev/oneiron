//! COMPANION-LEADER (the owner, 11 Nov; ONEIRON-ARCH-0063 #companion-split):
//! "One agent never serves as both a person's companion and their company's
//! companion by default, because their loyalties can diverge. A sole owner
//! may bind them on purpose." The sole owner's own act is the purpose
//! (Engine RULING 18:45 on ASK L3-19-ON-PURPOSE, A).
//!
//! A workspace's house is a seeded agent with its own model PERSON. A member
//! who brings that agent as her own companion, into the workspace it runs or
//! while she belongs to a workspace it runs, is refused at her onboarding's
//! first step, and so is a co-owner. The same agent brought where it runs no
//! workspace of hers still lands, and so does the vault's one live owner
//! bringing it into the workspace it runs.
//!
//! No `cfg` is needed and every door used here is on main, so the file builds
//! there for the red run: `cargo test -p oneiron --all-features --test
//! companion_split`.

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantPreset, FederationGrantRole, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::actor_subject_anchor;
use oneiron::{
    AccessGrant, CompanionBirthIntent, CompanionChoice, EntityId, MemberGrantBundle,
    MemberOnboardingIntent, Result, TimeRange, Vault, VaultConfig, WorkspaceRosterPreset,
    WriteActor,
};

/// The two workspaces' shared vaults. Not 7, the own-device residence
/// scope's id, whose Owner grants read as device access.
const VAULT_A: u64 = 41;
const VAULT_B: u64 = 42;
const WORKSPACE_A: &str = "companion-split-a";
const WORKSPACE_B: &str = "companion-split-b";
/// The words the refusal carries.
const SPLIT: &str = "only a sole owner binds them both";

/// A plain row of `entity_type`, as a host's own import writes one.
fn seed_row(vault: &Vault, entity_type: u8) -> Result<EntityId> {
    let row = EntityId::now();
    vault.put_entity(
        &row,
        entity_type,
        TimeRange {
            start: 100,
            end: 100,
        },
        100,
        b"companion split fixture",
    )?;
    Ok(row)
}

fn proof(vault: &Vault, person: EntityId) -> Result<AuthenticatedOwner> {
    vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "companion split fixture",
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

/// A vault whose embedded owner owns both workspaces' shared vaults, with
/// the two seeded agents a workspace can name as its house.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    writer: WriteActor,
    org: EntityId,
    /// `sys.default`: the agent members bring as their companion here.
    agent: EntityId,
    /// `sys.team_lead`: a house that is no one's companion.
    other_house: EntityId,
    /// A second Owner of `VAULT_A`, when the fixture seats one.
    co_owner: Option<EntityId>,
}

/// [`Fixture`], with a second PERSON seated as an Owner of `VAULT_A` beside
/// the embedded owner when `with_co_owner`: her founding invitation accepted.
fn fixture_with(with_co_owner: bool) -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = proof(&vault, owner)?;
    let now = vault.now_recorded_at();
    let co_owner = if with_co_owner {
        Some(seed_row(&vault, ENTITY_TYPE_PERSON)?)
    } else {
        None
    };
    match co_owner {
        None => {
            vault.initialize_shared_vault(&owner_proof, VAULT_A, None, &[], now)?;
        }
        Some(co_owner) => {
            vault.initialize_shared_vault(
                &owner_proof,
                VAULT_A,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                    InitialSharedMember {
                        member_ref: co_owner,
                        role: Some(FederationGrantRole::Owner),
                    },
                ],
                now,
            )?;
            let co_proof = proof(&vault, co_owner)?;
            let invitation = vault
                .shared_invitations(&co_proof, VAULT_A)?
                .into_iter()
                .find(|open| open.role == FederationGrantRole::Owner)
                .expect("the co-owner's founding invitation");
            vault.accept_shared_invitation(&co_proof, VAULT_A, &invitation.id)?;
        }
    }
    vault.initialize_shared_vault(&owner_proof, VAULT_B, None, &[], vault.now_recorded_at())?;
    let org = seed_row(&vault, ENTITY_TYPE_ORG)?;
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let (other_house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
        .expect("sys.team_lead is seeded on open");
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        writer: WriteActor::new(owner, EdgeActorClass::Human),
        org,
        agent,
        other_house,
        co_owner,
    })
}

fn fixture() -> Result<Fixture> {
    fixture_with(false)
}

impl Fixture {
    fn preset(&self, workspace_ref: &str, vault_id: u64, house: EntityId) -> WorkspaceRosterPreset {
        WorkspaceRosterPreset {
            workspace_ref: workspace_ref.to_owned(),
            workspace_vault_id: vault_id,
            org_ref: self.org,
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        }
    }

    /// `member` brings `actor` as the companion she already has: its model
    /// PERSON, her companion-profile grant over it, her own consent.
    fn bring(&self, member: EntityId, actor: EntityId) -> Result<CompanionChoice> {
        let person = actor_subject_anchor(&self.vault, &actor, self.vault.now_recorded_at())?
            .expect("a seeded agent is anchored to its model PERSON");
        self.vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant::companion_profile_read(member, person, None, 1),
        )?;
        Ok(CompanionChoice::Bring {
            person,
            actor,
            work_facet: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            proof: proof(&self.vault, member)?,
        })
    }

    /// A work companion born for `member`'s onboarding.
    fn birth(&self, agent_id: &str) -> Result<CompanionChoice> {
        Ok(CompanionChoice::Work(CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            profile_grant_ref: EntityId::now(),
            actor_definition: definition(agent_id),
            display_name: "yuki".to_owned(),
        }))
    }

    /// `member` joins `workspace` with `companion`, the owner writing.
    fn onboard(
        &self,
        onboarding_id: &str,
        workspace: WorkspaceRosterPreset,
        member: EntityId,
        companion: CompanionChoice,
    ) -> Result<()> {
        let profile_grant = companion.birth().map(|birth| birth.profile_grant_ref);
        let intent = MemberOnboardingIntent {
            onboarding_id: onboarding_id.to_owned(),
            workspace,
            person_ref: member,
            actor_ref: EntityId::now(),
            actor_definition: definition(&format!("garden.member.{onboarding_id}")),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            grant_bundle: MemberGrantBundle {
                federation_grant_ref: EntityId::now(),
                role: FederationGrantRole::Member,
                preset: FederationGrantPreset::Member,
                companion_profile_grant_ref: profile_grant,
            },
            companion,
            delegated_mailbox: None,
            occurred_at: self.vault.now_recorded_at(),
        };
        self.vault
            .onboard_workspace_member(intent, &self.writer, None)
            .map(|_| ())
    }
}

fn assert_split(result: Result<()>, case: &str) {
    let error = result.expect_err(case);
    assert!(
        error.to_string().contains(SPLIT),
        "{case}: refused for the split, not for {error}"
    );
}

#[test]
fn a_member_who_brings_the_house_of_the_workspace_she_joins_is_refused() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    assert_split(
        fx.onboard(
            "bring-own-house",
            fx.preset(WORKSPACE_A, VAULT_A, fx.agent),
            member,
            companion,
        ),
        "the agent that runs her workspace is not also her companion",
    );
    Ok(())
}

#[test]
fn a_member_who_brings_the_house_of_a_workspace_she_is_in_is_refused() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let born = fx.birth("garden.companion.b")?;
    fx.onboard(
        "join-b",
        fx.preset(WORKSPACE_B, VAULT_B, fx.agent),
        member,
        born,
    )
    .expect("she joins the workspace sys.default runs, with a work companion");
    let companion = fx.bring(member, fx.agent)?;
    assert_split(
        fx.onboard(
            "bring-house-of-b",
            fx.preset(WORKSPACE_A, VAULT_A, fx.other_house),
            member,
            companion,
        ),
        "the agent that runs a workspace she is in is not also her companion",
    );
    Ok(())
}

#[test]
fn a_member_brings_an_agent_that_runs_no_workspace_of_hers() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    fx.onboard(
        "bring-elsewhere",
        fx.preset(WORKSPACE_A, VAULT_A, fx.other_house),
        member,
        companion,
    )
    .expect("her companion runs no workspace she belongs to");
    Ok(())
}

#[test]
fn the_sole_owner_brings_the_house_of_her_own_workspace() -> Result<()> {
    let fx = fixture()?;
    let companion = fx.bring(fx.owner, fx.agent)?;
    fx.onboard(
        "owner-brings-house",
        fx.preset(WORKSPACE_A, VAULT_A, fx.agent),
        fx.owner,
        companion,
    )
    .expect("the sole owner binds her companion as her company's on purpose");
    Ok(())
}

#[test]
fn a_co_owner_who_brings_the_house_of_her_workspace_is_refused() -> Result<()> {
    let fx = fixture_with(true)?;
    let co_owner = fx.co_owner.expect("the fixture seats a co-owner");
    let companion = fx.bring(co_owner, fx.agent)?;
    assert_split(
        fx.onboard(
            "co-owner-brings-house",
            fx.preset(WORKSPACE_A, VAULT_A, fx.agent),
            co_owner,
            companion,
        ),
        "a co-owner is not the sole owner, so she is refused",
    );
    Ok(())
}
