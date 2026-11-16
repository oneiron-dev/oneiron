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
//! Her company is the org, not the workspace (Engine RULING
//! L3-19-ORG-SCOPE = A, 16 Nov): bringing the house of another workspace of
//! her org is refused too. A door that publishes a new workspace of her org
//! run by her companion is refused as well, whether an owner establishes it
//! or another member's onboarding does, unless she is the sole owner.
//!
//! Her companion is read through the identity redirects: once an identity
//! merge folds her companion's PERSON into a house's model PERSON, a
//! workspace of her org run by that house is refused (review round 2 of
//! #7656).
//!
//! An onboarding that reserved her slot before its workspace was
//! established is refused when it establishes it, if her companion runs it
//! by then (review round 1 of #7656). That case stops an onboarding after
//! its first step through `oneiron::test_doors::roster_slot_reservation`,
//! so it runs only under `--cfg oneiron_test_support`; the other cases use
//! doors on main: `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p
//! oneiron --all-features --test companion_split`.

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{FederationGrantPreset, FederationGrantRole, InitialSharedMember};
use oneiron::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    SurvivorshipPlan,
};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::actor_subject_anchor;
use oneiron::{
    AccessGrant, CompanionBirthIntent, CompanionChoice, EntityId, MemberGrantBundle,
    MemberOnboardingIntent, Result, TimeRange, Vault, VaultConfig, WorkCompanionPolicy,
    WorkspaceRosterPreset, WriteActor,
};

/// The shared vault both workspaces run in. A store creates one shared vault
/// (its creation row is a single row), and the split check reads the
/// workspaces' presets, not their vault ids. Not 7, the own-device residence
/// scope's id, whose Owner grants read as device access.
const VAULT_ID: u64 = 41;
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

/// A vault whose embedded owner owns the workspaces' shared vault, with
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
    /// A second Owner of `VAULT_ID`, when the fixture seats one.
    co_owner: Option<EntityId>,
}

/// [`Fixture`], with a second PERSON seated as an Owner of `VAULT_ID` beside
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
            vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], now)?;
        }
        Some(co_owner) => {
            vault.initialize_shared_vault(
                &owner_proof,
                VAULT_ID,
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
                .shared_invitations(&co_proof, VAULT_ID)?
                .into_iter()
                .find(|open| open.role == FederationGrantRole::Owner)
                .expect("the co-owner's founding invitation");
            vault.accept_shared_invitation(&co_proof, VAULT_ID, &invitation.id)?;
        }
    }
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
        let intent = self.intent(onboarding_id, workspace, member, companion)?;
        self.vault
            .onboard_workspace_member(intent, &self.writer, None)
            .map(|_| ())
    }

    /// The onboarding intent of `member` joining `workspace` with
    /// `companion`.
    fn intent(
        &self,
        onboarding_id: &str,
        workspace: WorkspaceRosterPreset,
        member: EntityId,
        companion: CompanionChoice,
    ) -> Result<MemberOnboardingIntent> {
        let profile_grant = companion.birth().map(|birth| birth.profile_grant_ref);
        Ok(MemberOnboardingIntent {
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
        })
    }
}

fn assert_split(result: Result<()>, case: &str) {
    let error = result.expect_err(case);
    assert!(
        error.to_string().contains(SPLIT),
        "{case}: refused for the split, not for {error}"
    );
}

impl Fixture {
    /// The owner establishes `workspace`, as `establish_workspace_preset`
    /// does before anyone is onboarded.
    fn establish(&self, workspace: &WorkspaceRosterPreset) -> Result<()> {
        self.vault.establish_workspace_preset(
            workspace,
            WorkCompanionPolicy::default(),
            &proof(&self.vault, self.owner)?,
        )
    }

    /// Whether `workspace_ref` has a stored preset.
    fn is_published(&self, workspace_ref: &str) -> bool {
        self.vault.workspace_work_companion(workspace_ref).is_ok()
    }

    /// The model PERSON `actor` is anchored to.
    fn model_person(&self, actor: EntityId) -> Result<EntityId> {
        Ok(
            actor_subject_anchor(&self.vault, &actor, self.vault.now_recorded_at())?
                .expect("a seeded agent is anchored to its model PERSON")
                .subject_ref,
        )
    }

    /// Merges PERSON `source` into PERSON `survivor`. An identity op is
    /// sealed with this install's machine key, which a host loads from its
    /// keystore after each open.
    fn merge(&self, source: EntityId, survivor: EntityId) -> Result<()> {
        self.vault
            .install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        self.vault.prepare_install_signing()?;
        let outcome = self.vault.apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: vec![source],
                survivor,
                evidence: IdentityOpEvidence {
                    refs: Vec::new(),
                    rationale: "companion split fixture".to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            self.vault.now_recorded_at(),
        )?;
        assert!(
            matches!(outcome, IdentityOpOutcome::Applied { .. }),
            "the merge did not apply: {outcome:?}"
        );
        Ok(())
    }
}

#[test]
fn a_member_who_brings_the_house_of_the_workspace_she_joins_is_refused() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    assert_split(
        fx.onboard(
            "bring-own-house",
            fx.preset(WORKSPACE_A, VAULT_ID, fx.agent),
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
        fx.preset(WORKSPACE_B, VAULT_ID, fx.agent),
        member,
        born,
    )
    .expect("she joins the workspace sys.default runs, with a work companion");
    let companion = fx.bring(member, fx.agent)?;
    assert_split(
        fx.onboard(
            "bring-house-of-b",
            fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
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
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
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
        fx.preset(WORKSPACE_A, VAULT_ID, fx.agent),
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
            fx.preset(WORKSPACE_A, VAULT_ID, fx.agent),
            co_owner,
            companion,
        ),
        "a co-owner is not the sole owner, so she is refused",
    );
    Ok(())
}

/// Engine RULING L3-19-ORG-SCOPE = A, case 1 of OPUS-SECREAD-A's second
/// read: workspace B of her org is run by sys.default, and she holds no
/// slot in B. Joining workspace A of the same org, she brings sys.default.
#[test]
fn a_member_who_brings_the_house_of_another_workspace_of_her_org_is_refused() -> Result<()> {
    let fx = fixture()?;
    let colleague = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let born = fx.birth("garden.companion.colleague")?;
    fx.onboard(
        "colleague-joins-b",
        fx.preset(WORKSPACE_B, VAULT_ID, fx.agent),
        colleague,
        born,
    )
    .expect("a colleague establishes workspace B, run by sys.default");
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    assert_split(
        fx.onboard(
            "bring-house-of-her-org",
            fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
            member,
            companion,
        ),
        "the agent that runs another workspace of her org is not also her companion",
    );
    Ok(())
}

/// Case 2 of the second read: she is in workspace A with sys.default as her
/// companion, and the owner establishes workspace B of the same org with
/// sys.default as its house. The refused publish writes nothing.
#[test]
fn an_owner_cannot_establish_a_workspace_of_her_org_run_by_her_companion() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    fx.onboard(
        "join-a-with-companion",
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
        member,
        companion,
    )
    .expect("no workspace of her org is run by her companion yet");
    assert_split(
        fx.establish(&fx.preset(WORKSPACE_B, VAULT_ID, fx.agent)),
        "a new workspace of her org is not run by her companion",
    );
    assert!(
        !fx.is_published(WORKSPACE_B),
        "the refused establish publishes no preset"
    );
    Ok(())
}

/// The same publish through the onboarding door: a newcomer's onboarding
/// would establish workspace B of her org, run by her companion. It is
/// refused at its establish step, and B stays unpublished.
#[test]
fn an_onboarding_cannot_establish_a_workspace_of_her_org_run_by_her_companion() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let companion = fx.bring(member, fx.agent)?;
    fx.onboard(
        "join-a-with-companion",
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
        member,
        companion,
    )
    .expect("no workspace of her org is run by her companion yet");
    let newcomer = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let born = fx.birth("garden.companion.newcomer")?;
    assert_split(
        fx.onboard(
            "newcomer-establishes-b",
            fx.preset(WORKSPACE_B, VAULT_ID, fx.agent),
            newcomer,
            born,
        ),
        "an onboarding does not establish a workspace of her org run by her companion",
    );
    assert!(
        !fx.is_published(WORKSPACE_B),
        "the refused establish step publishes no preset"
    );
    Ok(())
}

/// The sole owner, in workspace A with sys.default as her companion,
/// establishes workspace B of her org with sys.default as its house: her
/// own act, on purpose.
#[test]
fn the_sole_owner_establishes_a_workspace_of_her_org_run_by_her_companion() -> Result<()> {
    let fx = fixture()?;
    let companion = fx.bring(fx.owner, fx.agent)?;
    fx.onboard(
        "owner-joins-a",
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
        fx.owner,
        companion,
    )
    .expect("no workspace of her org is run by her companion yet");
    fx.establish(&fx.preset(WORKSPACE_B, VAULT_ID, fx.agent))
        .expect("the sole owner binds her companion as her company's on purpose");
    assert!(fx.is_published(WORKSPACE_B), "workspace B is established");
    Ok(())
}

/// Review round 2 of #7656: she is in workspace A with a work companion,
/// and that companion's PERSON is then merged into sys.default's model
/// PERSON. Her companion row still names the merged PERSON, but the house of
/// a new workspace B of her org is now that same PERSON, so the owner's
/// establish is refused and B stays unpublished.
#[test]
fn an_owner_cannot_establish_a_workspace_run_by_her_merged_companion() -> Result<()> {
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let born = fx.birth("garden.companion.merged")?;
    let companion = born.person_ref();
    fx.onboard(
        "join-a-with-work-companion",
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
        member,
        born,
    )
    .expect("her work companion runs no workspace of her org");
    fx.merge(companion, fx.model_person(fx.agent)?)?;
    assert_split(
        fx.establish(&fx.preset(WORKSPACE_B, VAULT_ID, fx.agent)),
        "a house her companion was merged into is still her companion",
    );
    assert!(
        !fx.is_published(WORKSPACE_B),
        "the refused establish publishes no preset"
    );
    Ok(())
}

/// Review round 1 of #7656: her onboarding into workspace B (run by
/// sys.default) has reserved her slot and stopped before B is established,
/// so no reserve can read B's house yet. Meanwhile she joins workspace A
/// bringing sys.default as her companion, which lands: no house of a
/// workspace she is in is her companion yet. When the first onboarding
/// resumes and establishes B, the house of B would be her companion, so it
/// is refused there.
#[cfg(oneiron_test_support)]
#[test]
fn a_reserved_slot_in_an_unestablished_workspace_still_keeps_the_split() -> Result<()> {
    use oneiron::test_doors::roster_slot_reservation::reserve_member_slot;
    let fx = fixture()?;
    let member = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let born = fx.birth("garden.companion.b")?;
    let first = fx.intent(
        "join-b-paused",
        fx.preset(WORKSPACE_B, VAULT_ID, fx.agent),
        member,
        born,
    )?;
    reserve_member_slot(&fx.vault, first.clone(), &fx.writer)
        .expect("her slot in workspace B is reserved");
    let companion = fx.bring(member, fx.agent)?;
    fx.onboard(
        "bring-house-of-b-early",
        fx.preset(WORKSPACE_A, VAULT_ID, fx.other_house),
        member,
        companion,
    )
    .expect("no published workspace of hers is run by her companion yet");
    assert_split(
        fx.vault
            .onboard_workspace_member(first, &fx.writer, None)
            .map(|_| ()),
        "the workspace her paused onboarding establishes is run by her companion",
    );
    Ok(())
}
