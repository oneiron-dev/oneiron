//! An org Admin's named power stands on the owner's stored setup (FIX-LIST
//! row 4887). Engine RULING FIX-4887-ORG-ADMIN-POLICY = A (15 Nov 19:31, the
//! lead, following canon federation:27 / ARCH-0043:226: "Org admin power is
//! a fixed allowlist of named powers, never a blanket role"): when an org
//! policy is stored, an Admin's act also needs `policy.authorize(writer,
//! power)`. Owner and Deputy grants are unchanged; with no org or no policy,
//! today's rule holds.
//!
//! Red on the base (#8371's head): an Admin whose setup names only AddMember
//! still assigns a role through its grant, and an Admin the setup leaves out
//! still adds a member. Guards (pass on the base too): an Admin's acts with
//! no stored setup, the Owner's act under a setup that names only another
//! power, and a setup stored for an org that no preset here names.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_admin_setup_policy`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "admin_step_up/fixture.rs"]
mod admin_step_up;

use std::collections::BTreeSet;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, OrgAdminPolicy, OrgAdminPower,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EntityId, Vault};

const SHARED: u64 = 42;
const WORKSPACE: &str = "T-setup-policy";

/// The gate's refusal of a write no role or named power authorizes
/// (`ClaimError::ActorLacksClaimAuthority`), named by its variant.
const NO_AUTHORITY: &str = "ActorLacksClaimAuthority";

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

/// `person`'s proof with no credential of its own.
fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// The role `member` holds in the shared vault now, read from its grant rows.
fn role_of(vault: &Vault, member: EntityId) -> Option<Role> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = oneiron::federation::decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member && grant.role != Role::Delegate).then_some(grant.role)
        })
}

/// `member` accepts its one open invitation at `role`.
fn accept_invitation(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("the member's invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("an open invitation at the role");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// Whether `member` holds an open invitation at `role`.
fn invited_at(vault: &Vault, member: EntityId, role: Role) -> bool {
    vault
        .shared_invitations(&proof(vault, member), SHARED)
        .expect("the member's invitations")
        .into_iter()
        .any(|open| open.role == role)
}

/// `result` is the gate's refusal for want of a role or named power.
fn refused_for_authority<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>, what: &str) {
    let error = result.expect_err(what);
    assert!(
        format!("{error:?}").contains(NO_AUTHORITY),
        "{what}: refused for another reason: {error:?}"
    );
}

/// A rooted shared vault with its embedded owner as Owner and an Admin who
/// accepted its founding invitation, whose workspace preset names `org`.
/// The host key stays bound to the owner until [`Org::admin_acts`].
struct Org {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
    org: EntityId,
}

fn org() -> Org {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, owner) = admin_step_up::rooted_vault(dir.path());
    let admin = EntityId::now();
    person(&vault, admin);
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[member(owner, Role::Owner), member(admin, Role::Admin)],
            1,
        )
        .expect("a shared vault with an Admin");
    accept_invitation(&vault, admin, Role::Admin);
    assert_eq!(role_of(&vault, admin), Some(Role::Admin));
    let org = EntityId::now();
    vault
        .put_entity(
            &org,
            ENTITY_TYPE_ORG,
            TimeRange { start: 1, end: 1 },
            1,
            b"setup policy org",
        )
        .expect("org row");
    let (house, _) = vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let preset = WorkspaceRosterPreset {
        workspace_ref: WORKSPACE.to_owned(),
        workspace_vault_id: SHARED,
        org_ref: org,
        venture_name: "Garden Works".to_owned(),
        house_display_name: None,
        house_actor_ref: house,
        house_identity_ref: None,
    };
    vault
        .establish_workspace_preset(&preset, WorkCompanionPolicy::Choose, &proof(&vault, owner))
        .expect("the owner stores the workspace");
    Org {
        _dir: dir,
        vault,
        issuer,
        owner,
        admin,
        org,
    }
}

impl Org {
    /// Stores the owner's one-time setup for `org`: `admins` hold `powers`.
    fn configure(&self, org: EntityId, admins: &[EntityId], powers: &[OrgAdminPower]) {
        let policy = OrgAdminPolicy::new(
            org,
            admins.iter().copied().collect::<BTreeSet<_>>(),
            powers.iter().copied().collect::<BTreeSet<_>>(),
        )
        .expect("a well-formed setup");
        self.vault
            .configure_org_admin(&policy)
            .expect("the owner's setup is stored");
    }

    /// Binds the host key to the Admin and returns its proof on a session
    /// that stepped up (L7-17), so only the setup can refuse its act.
    fn admin_acts(&self) -> AuthenticatedOwner {
        admin_step_up::bind_human_writer(&self.vault, &self.issuer, self.admin);
        admin_step_up::stepped_up_proof(&self.vault, &self.issuer, self.admin)
    }

    /// A new live PERSON with no role.
    fn newcomer(&self) -> EntityId {
        let id = EntityId::now();
        person(&self.vault, id);
        id
    }
}

#[test]
fn an_admin_whose_setup_names_only_add_member_cannot_assign_a_role() {
    let org = org();
    org.configure(org.org, &[org.admin], &[OrgAdminPower::AddMember]);
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("the setup's AddMember lands");
    accept_invitation(&org.vault, member, Role::Member);
    assert_eq!(role_of(&org.vault, member), Some(Role::Member));
    refused_for_authority(
        org.vault
            .change_shared_member_role(&admin, SHARED, member, Role::Admin, None),
        "an Admin's AssignRole that its org's setup does not name",
    );
    assert_eq!(
        role_of(&org.vault, member),
        Some(Role::Member),
        "the refused AssignRole leaves the member's role"
    );
}

#[test]
fn an_admin_the_setup_leaves_out_has_no_org_power() {
    let org = org();
    let named = org.newcomer();
    org.configure(
        org.org,
        &[named],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    );
    let member = org.newcomer();
    let admin = org.admin_acts();

    refused_for_authority(
        org.vault
            .add_shared_member(&admin, SHARED, member, Some(Role::Member)),
        "an Admin's AddMember when the org's setup names another admin",
    );
    assert!(
        !invited_at(&org.vault, member, Role::Member),
        "the refused AddMember writes no invitation"
    );
}

#[test]
fn an_admin_with_no_stored_setup_keeps_its_grants_powers() {
    let org = org();
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("an Admin adds a Member with no setup stored");
    accept_invitation(&org.vault, member, Role::Member);
    org.vault
        .change_shared_member_role(&admin, SHARED, member, Role::Admin, None)
        .expect("an Admin assigns a role with no setup stored");
    assert_eq!(role_of(&org.vault, member), Some(Role::Admin));
}

#[test]
fn the_owner_is_not_narrowed_by_the_setup() {
    let org = org();
    org.configure(org.org, &[org.admin], &[OrgAdminPower::AddMember]);
    let member = org.newcomer();
    let owner = proof(&org.vault, org.owner);

    org.vault
        .add_shared_member(&owner, SHARED, member, Some(Role::Member))
        .expect("the Owner adds a Member");
    accept_invitation(&org.vault, member, Role::Member);
    org.vault
        .change_shared_member_role(&owner, SHARED, member, Role::Admin, None)
        .expect("the Owner assigns a role the Admins' setup does not name");
    assert_eq!(role_of(&org.vault, member), Some(Role::Admin));
}

#[test]
fn a_setup_for_an_org_no_preset_here_names_narrows_nothing() {
    let org = org();
    let elsewhere = EntityId::now();
    org.configure(elsewhere, &[org.admin], &[OrgAdminPower::AddMember]);
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("an Admin adds a Member");
    accept_invitation(&org.vault, member, Role::Member);
    org.vault
        .change_shared_member_role(&admin, SHARED, member, Role::Admin, None)
        .expect("an Admin assigns a role: the stored setup is another org's");
    assert_eq!(role_of(&org.vault, member), Some(Role::Admin));
}
