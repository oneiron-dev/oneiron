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
//!
//! The owner's amend (RULING ORG-ADMIN-SETUP-AMEND, the lead 16 Nov 02:1x =
//! B): `vault.org_admin.amend` replaces a stored setup's Admins and named
//! powers, and may add a power the setup lacks; no Admin or agent can amend.
//! The amend's answer names the Admins and powers it added and took away,
//! and whether it widens the setup (RULING ORG-ADMIN-AMEND-CONFIRM-RECEIPT =
//! A, Engine 16 Nov 02:27; its receipt is `org_admin_amend_receipt`'s).
//! The amend rows call the verb by name as the embedded owner, so on a tree
//! without it each fails at run time as an unknown verb; an Admin's or an
//! agent's amend is refused on both trees.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_admin_setup_policy`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
#[path = "admin_step_up/fixture.rs"]
mod admin_step_up;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, OrgAdminPolicy, OrgAdminPower,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::workspace_roster::{WorkCompanionPolicy, WorkspaceRosterPreset};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

const SHARED: u64 = 42;
const WORKSPACE: &str = "T-setup-policy";

/// The gate's refusal of a write no role or named power authorizes
/// (`ClaimError::ActorLacksClaimAuthority`), named by its variant.
const NO_AUTHORITY: &str = "ActorLacksClaimAuthority";

const AMEND: &str = "vault.org_admin.amend";
/// The amend's refusal with no stored setup (`OrgAdminError::NotConfigured`).
const NOT_CONFIGURED: &str = "organization administration is not configured";

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
    org_with(admin_step_up::rooted_vault)
}

/// [`org`] on a vault this process owns: the handle holds the writer lease,
/// so the owner verbs answer the embedded owner on it.
fn owned_org() -> Org {
    org_with(rooted_owned_vault)
}

/// `admin_step_up::rooted_vault`, opened with the writer lease.
fn rooted_owned_vault(dir: &Path) -> (Vault, HostSlipIssuer, EntityId) {
    let vault = Vault::open_owned(dir, VaultConfig::device()).expect("owned vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    (vault, issuer, owner)
}

fn org_with(rooted: fn(&Path) -> (Vault, HostSlipIssuer, EntityId)) -> Org {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, issuer, owner) = rooted(dir.path());
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

    /// The owner's amend of this org's setup through the verb: `admins`
    /// hold `powers` from now on.
    fn amend(&self, admins: &[EntityId], powers: &[OrgAdminPower]) -> Result<Value, String> {
        self.amend_as(self.owner, EdgeActorClass::Human, admins, powers)
    }

    /// `caller`'s call of the amend verb at `class`, on this handle.
    fn amend_as(
        &self,
        caller: EntityId,
        class: EdgeActorClass,
        admins: &[EntityId],
        powers: &[OrgAdminPower],
    ) -> Result<Value, String> {
        let policy = OrgAdminPolicy::new(
            self.org,
            admins.iter().copied().collect::<BTreeSet<_>>(),
            powers.iter().copied().collect::<BTreeSet<_>>(),
        )
        .expect("a well-formed setup");
        let input = json!({ "policy": serde_json::to_value(&policy).expect("the policy as JSON") });
        oneiron::task_verb::sdk::invoke(&self.vault.memory(caller, class), AMEND, input)
            .map_err(|error| format!("{error:?}"))
    }

    /// The powers this org's stored setup gives `admin`.
    fn stored_powers(&self, admin: EntityId) -> Vec<OrgAdminPower> {
        self.vault
            .org_admin_policy(self.org)
            .expect("a stored setup")
            .visible_powers(admin)
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

#[test]
fn the_owner_seats_a_later_admin_by_an_amend() {
    let org = owned_org();
    let named = org.newcomer();
    org.configure(org.org, &[named], &[OrgAdminPower::AddMember]);
    let amended = org
        .amend(&[named, org.admin], &[OrgAdminPower::AddMember])
        .expect("the owner's amend lands");
    assert_eq!(
        amended.get("amended"),
        Some(&Value::Bool(true)),
        "{amended}"
    );
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("the AddMember of an Admin the amend seated lands");
    assert!(invited_at(&org.vault, member, Role::Member));
}

#[test]
fn an_amend_drops_a_power() {
    let org = owned_org();
    org.configure(
        org.org,
        &[org.admin],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    );
    org.amend(&[org.admin], &[OrgAdminPower::AddMember])
        .expect("the owner's amend lands");
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("the AddMember the amend kept lands");
    accept_invitation(&org.vault, member, Role::Member);
    refused_for_authority(
        org.vault
            .change_shared_member_role(&admin, SHARED, member, Role::Admin, None),
        "an Admin's AssignRole that the amend dropped",
    );
    assert_eq!(role_of(&org.vault, member), Some(Role::Member));
}

/// RULING ORG-ADMIN-SETUP-AMEND = B (the lead 16 Nov 02:1x): the owner may
/// add a power the stored setup lacks, and an Admin's act under it lands.
#[test]
fn an_owner_amend_adds_a_power_and_a_later_admin_act_under_it_lands() {
    let org = owned_org();
    org.configure(org.org, &[org.admin], &[OrgAdminPower::AddMember]);
    org.amend(
        &[org.admin],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    )
    .expect("the owner's amend that adds a power lands");
    assert_eq!(
        org.stored_powers(org.admin),
        vec![OrgAdminPower::AddMember, OrgAdminPower::AssignRole]
    );
    let member = org.newcomer();
    let admin = org.admin_acts();

    org.vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("the Admin's AddMember lands");
    accept_invitation(&org.vault, member, Role::Member);
    org.vault
        .change_shared_member_role(&admin, SHARED, member, Role::Admin, None)
        .expect("the Admin's AssignRole the amend added lands");
    assert_eq!(role_of(&org.vault, member), Some(Role::Admin));
}

#[test]
fn an_amend_needs_a_stored_setup() {
    let org = owned_org();

    let refusal = org
        .amend(&[org.admin], &[OrgAdminPower::AddMember])
        .expect_err("an amend with no setup stored");
    assert!(
        refusal.contains(NOT_CONFIGURED),
        "refused for another reason: {refusal}"
    );
    assert!(
        org.vault.org_admin_policy(org.org).is_err(),
        "the refused amend stores no setup"
    );
}

#[test]
fn only_the_owner_amends_the_setup() {
    let org = owned_org();
    org.configure(org.org, &[org.admin], &[OrgAdminPower::AddMember]);
    let named = org.newcomer();
    let (house, _) = org
        .vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .expect("read the seeded agents")
        .expect("sys.default is seeded on open");
    let widened = [OrgAdminPower::AddMember, OrgAdminPower::AssignRole];

    org.amend_as(
        org.admin,
        EdgeActorClass::Human,
        &[org.admin, named],
        &widened,
    )
    .expect_err("an Admin's amend of the owner's setup");
    org.amend_as(house, EdgeActorClass::Agent, &[org.admin, named], &widened)
        .expect_err("an agent's amend of the owner's setup");
    assert!(
        org.stored_powers(named).is_empty(),
        "the refused amends seat no one"
    );
    assert_eq!(
        org.stored_powers(org.admin),
        vec![OrgAdminPower::AddMember],
        "the refused amends add no power"
    );
}

/// RULING ORG-ADMIN-AMEND-CONFIRM-RECEIPT = A: the answer names what the
/// amend changed, and an amend that seats an Admin or adds a power widens.
#[test]
fn an_amend_names_what_it_changed_and_that_it_widens() {
    let org = owned_org();
    let named = org.newcomer();
    org.configure(org.org, &[org.admin], &[OrgAdminPower::AddMember]);
    let amended = org
        .amend(
            &[named],
            &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
        )
        .expect("the owner's amend lands");
    assert_eq!(amended["amended"], json!(true), "{amended}");
    assert_eq!(amended["added_admins"], json!([named]), "{amended}");
    assert_eq!(amended["removed_admins"], json!([org.admin]), "{amended}");
    assert_eq!(
        amended["added_powers"],
        json!([OrgAdminPower::AssignRole]),
        "{amended}"
    );
    assert_eq!(amended["dropped_powers"], json!([]), "{amended}");
    assert_eq!(amended["widens"], json!(true), "{amended}");
}

/// An amend that only unseats an Admin and drops a power narrows, so it is
/// not marked as widening; an amend equal to the stored setup changes
/// nothing.
#[test]
fn a_narrowing_amend_is_not_marked_as_widening() {
    let org = owned_org();
    let named = org.newcomer();
    org.configure(
        org.org,
        &[org.admin, named],
        &[OrgAdminPower::AddMember, OrgAdminPower::AssignRole],
    );
    let narrowed = org
        .amend(&[org.admin], &[OrgAdminPower::AddMember])
        .expect("the owner's narrowing amend lands");
    assert_eq!(narrowed["amended"], json!(true), "{narrowed}");
    assert_eq!(narrowed["added_admins"], json!([]), "{narrowed}");
    assert_eq!(narrowed["removed_admins"], json!([named]), "{narrowed}");
    assert_eq!(narrowed["added_powers"], json!([]), "{narrowed}");
    assert_eq!(
        narrowed["dropped_powers"],
        json!([OrgAdminPower::AssignRole]),
        "{narrowed}"
    );
    assert_eq!(narrowed["widens"], json!(false), "{narrowed}");

    let same = org
        .amend(&[org.admin], &[OrgAdminPower::AddMember])
        .expect("an amend equal to the stored setup");
    assert_eq!(same["amended"], json!(false), "{same}");
    assert_eq!(same["removed_admins"], json!([]), "{same}");
    assert_eq!(same["dropped_powers"], json!([]), "{same}");
    assert_eq!(same["widens"], json!(false), "{same}");
}
