//! Member offboarding (ARCH-0063 [INB-07]; Engine RULINGs INB-07-OFFBOARD =
//! A1 + B1, OFFBOARD-ROOMS = A, OFFBOARD-PENDING-ASKS = A,
//! OFFBOARD-SEAT-AUTHORITY = A, OFFBOARD-CHECK-INS = B): "revoke the actor,
//! keep the person" (ARCH-0063:152), and "the member seat and the inquiry
//! edge end together" (ARCH-0043:166).
//!
//! The vault's owner, or an admin with the workspace-settings power,
//! offboards a member in one writer: a standing seat ends as
//! `vault.members.remove` ends it, the member's actor and a work companion
//! born here are switched off with their PERSONs kept, a brought companion
//! is only detached, both leave every room with its history kept, the
//! leaver's open member asks are declined, and the roster row goes.
//!
//! Public paths only, no `cfg`: `cargo test --locked -p oneiron
//! --all-features --test workspace_member_offboard`. On main the file does
//! not build: `Vault::offboard_workspace_member` does not exist.

use oneiron::access_grant::AccessGrantStatus;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice, MembershipAction};
use oneiron::edge::{EdgeActorClass, EdgeKind};
use oneiron::federation::{
    FederationGrantPreset, FederationGrantRole as Role, InitialSharedMember, MemberAskChange,
    MemberAskStatus, decode_federation_grant_body,
};
use oneiron::registry::{
    ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use oneiron::store::GateDecisionId;
use oneiron::subject_model::actor_subject_anchor;
use oneiron::workspace_roster::{
    MemberOffboardingIntent, MemberOffboardingOutcome, OffboardedCompanionKind,
};
use oneiron::{
    AccessGrant, CompanionBirthIntent, CompanionChoice, EntityId, Error, MemberGrantBundle,
    MemberOnboardingIntent, Result, TimeRange, Vault, VaultConfig, WorkspaceRosterPreset,
    WorkspaceRosterRole, WriteActor,
};

const WORKSPACE: &str = "workspace-member-offboard";
/// The workspace's shared vault. Not 7, the own-device residence scope's id,
/// whose Owner grants read as device access.
const VAULT_ID: u64 = 41;

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
        b"workspace member offboard fixture",
    )?;
    Ok(row)
}

fn proof(vault: &Vault, person: EntityId) -> Result<AuthenticatedOwner> {
    vault.authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "workspace member offboard fixture",
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

/// A vault whose embedded owner owns the workspace's shared vault, with a
/// second PERSON seated at `second_role` when one is asked for.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    second: Option<EntityId>,
    preset: WorkspaceRosterPreset,
}

/// What one onboarding made, as the offboarding tests read it back.
struct Onboarded {
    member: EntityId,
    actor: EntityId,
    companion_person: EntityId,
    companion_actor: EntityId,
    companion_facet: EntityId,
    profile_grant: Option<EntityId>,
}

fn fixture(second_role: Option<Role>) -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner_proof = proof(&vault, owner)?;
    let now = vault.now_recorded_at();
    let second = match second_role {
        None => {
            vault.initialize_shared_vault(&owner_proof, VAULT_ID, None, &[], now)?;
            None
        }
        Some(role) => {
            let second = seed_row(&vault, ENTITY_TYPE_PERSON)?;
            vault.initialize_shared_vault(
                &owner_proof,
                VAULT_ID,
                None,
                &[
                    InitialSharedMember {
                        member_ref: owner,
                        role: Some(Role::Owner),
                    },
                    InitialSharedMember {
                        member_ref: second,
                        role: Some(role),
                    },
                ],
                now,
            )?;
            let second_proof = proof(&vault, second)?;
            let invitation = vault
                .shared_invitations(&second_proof, VAULT_ID)?
                .into_iter()
                .find(|open| open.role == role)
                .expect("the second person's founding invitation");
            vault.accept_shared_invitation(&second_proof, VAULT_ID, &invitation.id)?;
            Some(second)
        }
    };
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")?
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: VAULT_ID,
        org_ref: seed_row(&vault, ENTITY_TYPE_ORG)?,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    Ok(Fixture {
        _dir: dir,
        vault,
        owner,
        owner_proof,
        second,
        preset,
    })
}

impl Fixture {
    /// A new member onboarded by the owner with a work companion born here.
    fn onboard_with_work_companion(&self, onboarding_id: &str) -> Result<Onboarded> {
        let companion = CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            profile_grant_ref: EntityId::now(),
            actor_definition: definition(&format!("garden.companion.{onboarding_id}")),
            display_name: "yuki".to_owned(),
        };
        let onboarded = Onboarded {
            member: seed_row(&self.vault, ENTITY_TYPE_PERSON)?,
            actor: EntityId::now(),
            companion_person: companion.person_ref,
            companion_actor: companion.actor_ref,
            companion_facet: companion.work_facet_ref,
            profile_grant: Some(companion.profile_grant_ref),
        };
        self.onboard(onboarding_id, &onboarded, CompanionChoice::Work(companion))?;
        Ok(onboarded)
    }

    /// A new member onboarded by the owner bringing `sys.team_lead`, an
    /// agent that runs no workspace of hers, as the companion she already
    /// has: its model PERSON, her companion-profile grant over it, her own
    /// consent.
    fn onboard_bringing_companion(&self, onboarding_id: &str) -> Result<Onboarded> {
        let member = seed_row(&self.vault, ENTITY_TYPE_PERSON)?;
        let (agent, _) = self
            .vault
            .get_seeded_agent_definition_by_logical_id("sys.team_lead")?
            .expect("sys.team_lead is seeded on open");
        let person = actor_subject_anchor(&self.vault, &agent, self.vault.now_recorded_at())?
            .expect("a seeded agent is anchored to its model PERSON");
        let own_grant = EntityId::now();
        self.vault.create_access_grant(
            &own_grant,
            &AccessGrant::companion_profile_read(member, person, None, 1),
        )?;
        let onboarded = Onboarded {
            member,
            actor: EntityId::now(),
            companion_person: person,
            companion_actor: agent,
            companion_facet: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            profile_grant: Some(own_grant),
        };
        self.onboard(
            onboarding_id,
            &onboarded,
            CompanionChoice::Bring {
                person,
                actor: agent,
                work_facet: onboarded.companion_facet,
                proof: proof(&self.vault, member)?,
            },
        )?;
        Ok(onboarded)
    }

    fn onboard(
        &self,
        onboarding_id: &str,
        onboarded: &Onboarded,
        companion: CompanionChoice,
    ) -> Result<()> {
        let profile_grant = companion.birth().map(|birth| birth.profile_grant_ref);
        let intent = MemberOnboardingIntent {
            onboarding_id: onboarding_id.to_owned(),
            workspace: self.preset.clone(),
            person_ref: onboarded.member,
            actor_ref: onboarded.actor,
            actor_definition: definition(&format!("garden.member.{onboarding_id}")),
            work_facet_ref: seed_row(&self.vault, ENTITY_TYPE_FACET)?,
            grant_bundle: MemberGrantBundle {
                federation_grant_ref: EntityId::now(),
                role: Role::Member,
                preset: FederationGrantPreset::Member,
                companion_profile_grant_ref: profile_grant,
            },
            companion,
            delegated_mailbox: None,
            occurred_at: self.vault.now_recorded_at(),
        };
        self.vault
            .onboard_workspace_member(
                intent,
                &WriteActor::new(self.owner, EdgeActorClass::Human),
                None,
            )
            .map(|_| ())
    }

    fn offboard(
        &self,
        offboarding_id: &str,
        member: EntityId,
        by: &AuthenticatedOwner,
    ) -> Result<MemberOffboardingOutcome> {
        self.vault.offboard_workspace_member(
            MemberOffboardingIntent {
                offboarding_id: offboarding_id.to_owned(),
                workspace_ref: WORKSPACE.to_owned(),
                person_ref: member,
                check_in_ref: None,
            },
            by,
            oneiron::authority::ActSurface::ThisInstall,
        )
    }

    /// A group room the owner opens, then `people` join.
    fn room_with(&self, people: &[EntityId]) -> Result<EntityId> {
        let room = EntityId::now();
        let owner = WriteActor::new(self.owner, EdgeActorClass::Human);
        let now = self.vault.now_recorded_at();
        let body = ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![self.owner],
            ..Default::default()
        };
        self.vault.create_conversation(room, &body, owner, now)?;
        for person in people {
            self.vault.join_member(
                room,
                *person,
                owner,
                self.vault.now_recorded_at(),
                HistoryChoice::Inherit,
            )?;
        }
        Ok(room)
    }

    /// The role `member` holds in the shared vault now, read from its live
    /// grant rows.
    fn role_of(&self, member: EntityId) -> Option<Role> {
        self.vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .into_iter()
            .find_map(|id| {
                let body = self.vault.get(&id).expect("grant row")?;
                let grant = decode_federation_grant_body(&body).ok()?;
                (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
            })
    }

    fn enabled(&self, actor: EntityId) -> Result<bool> {
        Ok(self
            .vault
            .get_agent_definition(&actor)?
            .expect("the actor's definition stays")
            .enabled)
    }

    /// Whether the workspace roster still lists `member`'s companion row.
    fn on_roster(&self, member: EntityId) -> Result<bool> {
        Ok(self
            .vault
            .workspace_roster(WORKSPACE, self.vault.now_recorded_at())?
            .into_iter()
            .any(|entry| {
                entry.role == WorkspaceRosterRole::PrincipalCompanion
                    && entry.principal_ref == Some(member)
            }))
    }
}

#[test]
fn the_owner_offboards_a_member_the_seat_and_actors_end_and_the_people_stay() -> Result<()> {
    let fx = fixture(None)?;
    let member = fx.onboard_with_work_companion("offboard-work")?;
    let room = fx.room_with(&[member.member, member.companion_person])?;
    assert_eq!(fx.role_of(member.member), Some(Role::Member));
    assert!(fx.enabled(member.actor)? && fx.enabled(member.companion_actor)?);
    assert!(fx.on_roster(member.member)?);

    let outcome = fx.offboard("offboard-work-1", member.member, &fx.owner_proof)?;

    assert!(!outcome.replayed);
    assert!(
        outcome.seat_receipt.is_some(),
        "a standing seat ends through the removal door, with its receipt"
    );
    assert_eq!(fx.role_of(member.member), None, "the seat ended");
    assert!(!fx.enabled(member.actor)?, "the member's actor is off");
    assert!(
        !fx.enabled(member.companion_actor)?,
        "a work companion born here is off"
    );
    assert_eq!(
        outcome.actors_switched_off,
        vec![member.actor, member.companion_actor]
    );
    for person in [member.member, member.companion_person] {
        assert_eq!(
            fx.vault.get_entity_type(&person)?,
            Some(ENTITY_TYPE_PERSON),
            "the PERSON stays"
        );
    }
    let profile_grant = member.profile_grant.expect("a born companion's grant");
    assert_eq!(
        fx.vault
            .get_access_grant(&profile_grant)?
            .expect("the grant row stays")
            .status,
        AccessGrantStatus::Revoked,
        "the profile grant minted for the born companion is revoked"
    );
    assert!(outcome.access_grants_revoked.contains(&profile_grant));
    let companion = outcome.companion.expect("the member had a companion");
    assert_eq!(companion.kind, OffboardedCompanionKind::Work);
    assert!(companion.switched_off && !companion.facet_detached);
    assert!(!fx.on_roster(member.member)?, "the roster row went");

    let members = fx.vault.members(room)?;
    assert!(!members.contains(&member.member) && !members.contains(&member.companion_person));
    assert!(
        members.contains(&fx.owner),
        "the room stays with the others"
    );
    let ledger = fx.vault.membership_ledger(room)?;
    for person in [member.member, member.companion_person] {
        assert!(
            ledger
                .iter()
                .any(|row| row.person == person && row.action == MembershipAction::Join),
            "the room keeps the join"
        );
        assert!(
            ledger
                .iter()
                .any(|row| row.person == person && row.action == MembershipAction::Leave),
            "the leave is a row of its own"
        );
    }
    assert_eq!(outcome.rooms_left.len(), 2);
    Ok(())
}

#[test]
fn a_replay_answers_the_first_offboarding_and_its_id_names_one_member() -> Result<()> {
    let fx = fixture(None)?;
    let first = fx.onboard_with_work_companion("offboard-replay-a")?;
    let second = fx.onboard_with_work_companion("offboard-replay-b")?;

    let done = fx.offboard("offboard-replay", first.member, &fx.owner_proof)?;
    let again = fx.offboard("offboard-replay", first.member, &fx.owner_proof)?;
    assert!(again.replayed);
    assert_eq!(again.completed_at, done.completed_at);
    assert!(
        again.actors_switched_off.is_empty(),
        "a replay writes nothing"
    );

    let reused = fx.offboard("offboard-replay", second.member, &fx.owner_proof);
    assert!(
        matches!(&reused, Err(Error::InvalidClaimBody(reason)) if reason.contains("already used")),
        "one offboarding id names one member: {reused:?}"
    );
    assert!(fx.enabled(second.actor)?, "the refused id touched no one");
    assert!(fx.on_roster(second.member)?);
    Ok(())
}

#[test]
fn a_brought_companion_is_detached_and_keeps_running() -> Result<()> {
    let fx = fixture(None)?;
    let member = fx.onboard_bringing_companion("offboard-bring")?;
    assert!(
        fx.vault
            .edges_out(&member.companion_person)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == member.companion_facet),
        "onboarding associated her work facet"
    );

    let outcome = fx.offboard("offboard-bring-1", member.member, &fx.owner_proof)?;

    let companion = outcome.companion.expect("the member had a companion");
    assert_eq!(companion.kind, OffboardedCompanionKind::Brought);
    assert!(!companion.switched_off && companion.facet_detached);
    assert!(
        fx.enabled(member.companion_actor)?,
        "her member's own companion keeps running"
    );
    assert_eq!(outcome.actors_switched_off, vec![member.actor]);
    assert!(
        !fx.vault
            .edges_out(&member.companion_person)?
            .iter()
            .any(|edge| edge.kind == EdgeKind::HasFacet && edge.target == member.companion_facet),
        "her work facet here is detached"
    );
    let own_grant = member.profile_grant.expect("the member's own grant");
    assert_eq!(
        fx.vault
            .get_access_grant(&own_grant)?
            .expect("the grant row")
            .status,
        AccessGrantStatus::Active,
        "the member's own grant over her own companion is theirs to keep"
    );
    Ok(())
}

#[test]
fn a_plain_member_cannot_offboard_and_nothing_changes() -> Result<()> {
    let fx = fixture(Some(Role::Member))?;
    let member = fx.onboard_with_work_companion("offboard-refused")?;
    let plain = proof(&fx.vault, fx.second.expect("the second person"))?;

    let refused = fx.offboard("offboard-refused-1", member.member, &plain);

    assert!(
        matches!(&refused, Err(Error::InvalidClaimBody(reason)) if reason.contains("offboarding is a workspace act")),
        "a plain member holds no workspace power: {refused:?}"
    );
    assert_eq!(fx.role_of(member.member), Some(Role::Member));
    assert!(fx.enabled(member.actor)? && fx.enabled(member.companion_actor)?);
    assert!(fx.on_roster(member.member)?);
    Ok(())
}

#[test]
fn an_admin_offboards_under_the_settings_power() -> Result<()> {
    let fx = fixture(Some(Role::Admin))?;
    let member = fx.onboard_with_work_companion("offboard-admin")?;
    let admin = proof(&fx.vault, fx.second.expect("the admin"))?;

    let outcome = fx.offboard("offboard-admin-1", member.member, &admin)?;

    assert!(outcome.seat_receipt.is_some());
    assert_eq!(fx.role_of(member.member), None);
    assert!(!fx.enabled(member.actor)?);
    assert!(!fx.on_roster(member.member)?);
    assert_eq!(
        fx.role_of(fx.second.expect("the admin")),
        Some(Role::Admin),
        "the admin keeps their own seat"
    );
    Ok(())
}

#[test]
fn a_member_whose_seat_already_ended_is_offboarded_with_no_second_removal() -> Result<()> {
    let fx = fixture(None)?;
    let member = fx.onboard_with_work_companion("offboard-left")?;
    fx.vault
        .remove_shared_member(&fx.owner_proof, VAULT_ID, member.member, None)?;
    assert_eq!(fx.role_of(member.member), None);
    assert!(
        fx.enabled(member.actor)?,
        "removing the seat alone leaves the actor running"
    );

    let outcome = fx.offboard("offboard-left-1", member.member, &fx.owner_proof)?;

    assert_eq!(outcome.seat_receipt, None, "no seat stood to end");
    assert!(!fx.enabled(member.actor)? && !fx.enabled(member.companion_actor)?);
    assert!(!fx.on_roster(member.member)?);
    Ok(())
}

#[test]
fn the_leavers_open_member_asks_are_declined() -> Result<()> {
    let fx = fixture(None)?;
    let member = fx.onboard_with_work_companion("offboard-steward")?;
    fx.vault.change_shared_member_role(
        &fx.owner_proof,
        VAULT_ID,
        member.member,
        Role::Steward,
        None,
    )?;
    let invitee = seed_row(&fx.vault, ENTITY_TYPE_PERSON)?;
    let ask = fx.vault.ask_shared_member_change(
        &proof(&fx.vault, member.member)?,
        VAULT_ID,
        MemberAskChange::Add {
            member: invitee.to_hex(),
            role: None,
        },
    )?;
    assert_eq!(ask.status, MemberAskStatus::Open);

    let outcome = fx.offboard("offboard-steward-1", member.member, &fx.owner_proof)?;

    assert_eq!(outcome.member_asks_declined, vec![ask.id.clone()]);
    let closed = fx
        .vault
        .shared_member_asks(&fx.owner_proof, VAULT_ID)?
        .into_iter()
        .find(|row| row.id == ask.id)
        .expect("the ask stays on record");
    assert_eq!(
        closed.status,
        MemberAskStatus::Declined {
            by: fx.owner.to_hex()
        }
    );
    Ok(())
}
