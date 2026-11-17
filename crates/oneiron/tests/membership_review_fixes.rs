//! Pass 28 R2b, the Sol xhigh review's fixes (legs/r2b-sol-review, 16 Nov): a membership
//! writer gives a member Grant only where its giver may give it, never gives the owner's
//! agent Grant as a member row, and never takes equal row bytes for a giving.
//!
//! - P1-1: a founding Owner invitation accepted after its inviter stopped being an Owner
//!   gives nothing: the inviter's standing is judged again when it is accepted.
//! - P2-1: a Steward's attached `engine.controls` grant (the owner's agent Grant, given by its
//!   own act) is no member row: a role change of that Steward goes through, and the move off
//!   Steward drops the controls grant, its end riding the change's record.
//! - P2-2: onboarding's replay writes nothing only when the row stands on its giving: an equal
//!   row that arrived ahead of any act is given by the step.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test membership_review_fixes`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    EngineControlActor, EngineControlClass, FederationGrant, FederationGrantPreset,
    FederationGrantRole as Role, FederationGrantScope, InitialSharedMember,
    decode_federation_grant_body, decode_federation_grant_body_keyed,
};
use oneiron::registry::{
    ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON,
};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::put_unkeyed_member_grant;
use oneiron::test_doors::grant_standing::{
    grant_line, grant_row, standing_grant_act, standing_member_grant_act,
};
use oneiron::test_support::{
    bind_host_actor, bind_host_owner, provision_act_carrier, provision_engine_machines,
};
use oneiron::{
    CompanionBirthIntent, CompanionChoice, EntityId, MemberGrantBundle, MemberOnboardingIntent,
    Vault, VaultConfig, WorkspaceRosterPreset, WriteActor,
};
use oneiron_keystore::MemoryKeystore;

const SHARED: u64 = 42;

/// A rooted install whose key carries acts, and its owner.
struct Install {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn carrier_install() -> Install {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    Install {
        _dir: dir,
        vault,
        issuer,
        owner,
    }
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `owner` shares the vault as its Owner and invites each of `invited` at its role.
fn share(vault: &Vault, owner: EntityId, invited: &[(EntityId, Role)]) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(Role::Owner),
    }];
    members.extend(invited.iter().map(|(member, role)| InitialSharedMember {
        member_ref: *member,
        role: Some(*role),
    }));
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &members,
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
}

/// The id of `member`'s open founding invitation at `role`.
fn invitation(vault: &Vault, member: EntityId, role: Role) -> String {
    vault
        .shared_invitations(&proof(vault, member), SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation")
        .id
}

/// `member` accepts its founding invitation at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let id = invitation(vault, member, role);
    vault
        .accept_shared_invitation(&proof(vault, member), SHARED, &id)
        .expect("the member accepts");
}

/// `member`'s Grant rows in the shared vault: each id and its terms.
fn member_rows(vault: &Vault, member: EntityId) -> Vec<(EntityId, FederationGrant)> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .filter_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member
                && grant.role != Role::Delegate
                && grant.scope == FederationGrantScope::vault(SHARED))
            .then_some((id, grant))
        })
        .collect()
}

/// The terms of the live Grant row `id`.
fn row_terms(vault: &Vault, id: EntityId) -> Option<FederationGrant> {
    grant_row(vault, id)
        .expect("row read")
        .map(|body| decode_federation_grant_body(&body).expect("grant body"))
}

/// The act row `id` stands on now as a member's Grant.
fn standing(vault: &Vault, id: EntityId) -> Option<[u8; 32]> {
    standing_member_grant_act(vault, id, vault.now_recorded_at()).expect("standing read")
}

#[test]
fn a_founding_owner_invitation_accepted_after_its_inviter_lost_owner_gives_nothing() {
    let install = carrier_install();
    let vault = &install.vault;
    let (first, second) = (EntityId::now(), EntityId::now());
    person(vault, first);
    person(vault, second);
    share(
        vault,
        install.owner,
        &[(first, Role::Owner), (second, Role::Owner)],
    );
    accept(vault, first, Role::Owner);
    // The first invitee, now an Owner, removes the creator as Owner; the creator keeps Admin.
    bind_host_actor(vault, &install.issuer, first, "human").expect("the first Owner's binding");
    let first_proof = proof(vault, first);
    let act = vault
        .propose_remove_owner(
            &first_proof,
            SHARED,
            install.owner,
            None,
            Some(Role::Admin),
            false,
        )
        .expect("the other Owner starts remove_owner");
    vault
        .execute_completed_shared_act(&first_proof, &act.id, Some(&install.issuer))
        .expect("remove_owner runs, the creator kept as an Admin");
    bind_host_owner(vault, &install.issuer, install.owner).expect("the creator's binding again");
    let kept: Vec<Role> = member_rows(vault, install.owner)
        .into_iter()
        .map(|(_, grant)| grant.role)
        .collect();
    assert_eq!(kept, vec![Role::Admin], "the creator is an Admin now");
    // The creator's founding Owner invitation to the second invitee still waits.
    let waiting = invitation(vault, second, Role::Owner);
    let refused = vault
        .accept_shared_invitation(&proof(vault, second), SHARED, &waiting)
        .err()
        .expect("an Admin inviter gives no Owner role");
    assert!(
        format!("{refused:?}").contains("only an owner of the vault gives"),
        "refused by the inviter's standing now: {refused:?}"
    );
    assert!(
        member_rows(vault, second).is_empty(),
        "the refused acceptance writes no grant"
    );
}

#[test]
fn a_stewards_role_change_never_gives_its_engine_controls_grant_and_ends_it() {
    let install = carrier_install();
    let vault = &install.vault;
    let steward = EntityId::now();
    person(vault, steward);
    share(vault, install.owner, &[(steward, Role::Steward)]);
    accept(vault, steward, Role::Steward);
    let membership = match member_rows(vault, steward).as_slice() {
        [(id, grant)] if grant.role == Role::Steward => *id,
        rows => panic!("one Steward membership row, not {rows:?}"),
    };
    let class = EngineControlClass::WakeCadence;
    let owner_proof = proof(vault, install.owner);
    let controls = vault
        .grant_engine_controls(&owner_proof, steward, &BTreeSet::from([class]))
        .expect("the owner's engine.controls grant to his Steward");
    assert!(
        standing_grant_act(vault, controls, vault.now_recorded_at())
            .expect("standing read")
            .is_some(),
        "the controls grant stands on the owner's agent Grant act"
    );

    vault
        .change_shared_member_role(&owner_proof, SHARED, steward, Role::Member, None)
        .expect(
            "the Owner changes the Steward's role: the controls grant is given as no member row",
        );
    let terms = row_terms(vault, membership).expect("the membership row");
    assert_eq!(terms.role, Role::Member, "the membership is rewritten");
    assert!(
        standing(vault, membership).is_some(),
        "the rewritten membership stands on its giving"
    );
    assert!(
        row_terms(vault, controls).is_none(),
        "the move off Steward drops the controls grant"
    );
    assert!(
        matches!(
            grant_line(vault, controls).expect("line read"),
            Some((_, true))
        ),
        "the change's record ended the controls grant's line"
    );
    assert!(
        !vault
            .engine_control_allowed(EngineControlActor::Holder(steward), class)
            .expect("check"),
        "the former Steward keeps no engine control"
    );
}

/// The workspace's shared vault in the onboarding test. Not 7, the own-device residence
/// scope's id.
const WORKSPACE_VAULT: u64 = 41;

/// A plain row of `entity_type` at `id`, as a host's own import writes one.
fn seed_row_at(vault: &Vault, id: EntityId, entity_type: u8) -> EntityId {
    vault
        .put_entity(
            &id,
            entity_type,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"membership review fixes fixture",
        )
        .expect("a seeded row");
    id
}

fn definition(agent_id: &str) -> AgentDefinition {
    AgentDefinition::new(
        agent_id,
        "membership review fixes fixture",
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

/// A carrier install whose owner owns the workspace's shared vault, with `member` a live
/// PERSON there; the vault's dir, the vault and its owner.
fn workspace_install(member: EntityId) -> (tempfile::TempDir, Vault, EntityId) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let (_, owner) = provision_act_carrier(&vault);
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            WORKSPACE_VAULT,
            None,
            &[],
            vault.now_recorded_at(),
        )
        .expect("the workspace's shared vault");
    seed_row_at(&vault, member, ENTITY_TYPE_PERSON);
    (dir, vault, owner)
}

/// `owner` onboards `member` as a Member of the workspace, its Grant at `grant`.
fn onboard(vault: &Vault, owner: EntityId, member: EntityId, grant: EntityId) {
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("seeded definitions")
        .expect("sys.default is seeded on open");
    let profile_grant = EntityId::now();
    let intent = MemberOnboardingIntent {
        onboarding_id: format!("membership-review-fixes-{}", grant.to_hex()),
        workspace: WorkspaceRosterPreset {
            workspace_ref: "membership-review-fixes-workspace".to_owned(),
            workspace_vault_id: WORKSPACE_VAULT,
            org_ref: seed_row_at(vault, EntityId::now(), ENTITY_TYPE_ORG),
            venture_name: "Garden Works".to_owned(),
            house_display_name: None,
            house_actor_ref: house,
            house_identity_ref: None,
        },
        person_ref: member,
        actor_ref: EntityId::now(),
        actor_definition: definition("garden.member"),
        work_facet_ref: seed_row_at(vault, EntityId::now(), ENTITY_TYPE_FACET),
        grant_bundle: MemberGrantBundle {
            federation_grant_ref: grant,
            role: Role::Member,
            preset: FederationGrantPreset::Member,
            companion_profile_grant_ref: Some(profile_grant),
        },
        companion: CompanionChoice::Work(CompanionBirthIntent {
            person_ref: EntityId::now(),
            actor_ref: EntityId::now(),
            work_facet_ref: seed_row_at(vault, EntityId::now(), ENTITY_TYPE_FACET),
            profile_grant_ref: profile_grant,
            actor_definition: definition("garden.companion"),
            display_name: "yuki".to_owned(),
        }),
        delegated_mailbox: None,
        occurred_at: vault.now_recorded_at(),
    };
    vault
        .onboard_workspace_member(intent, &WriteActor::new(owner, EdgeActorClass::Human), None)
        .expect("the member onboards");
}

#[test]
fn onboarding_gives_a_member_row_whose_equal_bytes_stand_on_no_giving() {
    let member = EntityId::now();
    // One install onboards the member: its step gives the row the bundle names, and those
    // terms are what the step expects of this member on any install with the same policy.
    let (_first_dir, first, first_owner) = workspace_install(member);
    let given = EntityId::now();
    onboard(&first, first_owner, member, given);
    let body = grant_row(&first, given)
        .expect("row read")
        .expect("the given row");
    let (terms, _) = decode_federation_grant_body_keyed(&body).expect("the given row's terms");
    assert!(
        standing(&first, given).is_some(),
        "an onboarding's row stands on its giving"
    );

    // On another install the same terms arrive at the bundle's id ahead of any act.
    let (_second_dir, second, second_owner) = workspace_install(member);
    let ahead = EntityId::now();
    put_unkeyed_member_grant(&second, ahead, &terms).expect("a row with no act");
    assert_eq!(
        standing(&second, ahead),
        None,
        "a row with no act stands for nothing"
    );
    onboard(&second, second_owner, member, ahead);
    assert!(
        standing(&second, ahead).is_some(),
        "the step gave the row: equal bytes were no giving"
    );
}
