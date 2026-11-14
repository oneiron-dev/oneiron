//! An org Admin's act stands on a current MFA step-up (L7-17 PR 2). Canon
//! (identity.md #pqc-1-mfa): "Org admins must use MFA, because any one
//! admin can act alone". Engine rulings L7-17-ORG-ADMIN-MFA = A (14 Nov
//! 03:02: the weave Admin's step-up, bound to the session slip) and
//! L7-17-ORG-ADMIN-ACTS = A (14 Nov 18:29: the Admin powers and the
//! delegate mint, in the engine, in the acting writer; the Owner exempt;
//! a managed person on the supervisor's signed `mfa_verified` claim).
//!
//! Red on main: an Admin's AddMember on a credential with no step-up lands;
//! so does one on a second credential when only the first stepped up, and a
//! managed Admin's with no supervisor MFA claim. Guards (pass on main too):
//! the same acts after a TOTP step-up on the request's own credential, an
//! invitation an Admin made accepted with no step-up of the inviter's, the
//! Owner's act with none, and a managed Admin's act on the claim.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test org_admin_step_up`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "admin_step_up/fixture.rs"]
mod admin_step_up;

use oneiron::authority::HostSlipIssuer;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::managed_person::managed_person_proof;
use oneiron::{EntityId, Vault};

const SHARED: u64 = 42;

/// The refusal's typed code (`oneiron::federation::ORG_ADMIN_STEP_UP_REQUIRED`
/// on the head), named by its text so this file reads the same on main.
const STEP_UP_REQUIRED_CODE: &str = "org_admin_step_up_required";

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

/// `result` is a refusal for want of the Admin's step-up.
fn refused_for_step_up<T: std::fmt::Debug, E: std::fmt::Debug>(result: Result<T, E>, what: &str) {
    let error = result.expect_err(what);
    assert!(
        format!("{error:?}").contains(STEP_UP_REQUIRED_CODE),
        "{what}: refused for another reason: {error:?}"
    );
}

/// A rooted shared vault: its embedded owner as Owner and an Admin, who
/// accepted its founding invitation. The host key stays bound to the owner;
/// a test binds it to the Admin before the Admin acts
/// ([`Shared::admin_acts`]).
struct Shared {
    _dir: tempfile::TempDir,
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    admin: EntityId,
}

fn shared() -> Shared {
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
    Shared {
        _dir: dir,
        vault,
        issuer,
        owner,
        admin,
    }
}

impl Shared {
    /// Binds the host key to the Admin, as its own device binding does: the
    /// rooted vault's gate admits a writer only on a live binding.
    fn admin_acts(&self) {
        admin_step_up::bind_human_writer(&self.vault, &self.issuer, self.admin);
    }

    /// A new live PERSON with no role.
    fn newcomer(&self) -> EntityId {
        let id = EntityId::now();
        person(&self.vault, id);
        id
    }
}

#[test]
fn an_admins_act_without_a_step_up_is_refused() {
    let shared = shared();
    let member = shared.newcomer();
    shared.admin_acts();
    let credential = admin_step_up::credential(&shared.vault, &shared.issuer, shared.admin);
    let admin = admin_step_up::proof_on(&shared.vault, shared.admin, &credential);

    refused_for_step_up(
        shared
            .vault
            .add_shared_member(&admin, SHARED, member, Some(Role::Member)),
        "an Admin's AddMember on a credential with no step-up",
    );
    assert!(
        !invited_at(&shared.vault, member, Role::Member),
        "the refused AddMember writes no invitation"
    );
}

#[test]
fn an_admins_acts_land_after_a_step_up_on_its_own_credential() {
    let shared = shared();
    let member = shared.newcomer();
    shared.admin_acts();
    let admin = admin_step_up::stepped_up_proof(&shared.vault, &shared.issuer, shared.admin);

    shared
        .vault
        .add_shared_member(&admin, SHARED, member, Some(Role::Member))
        .expect("a stepped-up Admin adds a Member");
    // The accept judges the inviter's standing alone: the step-up bound at
    // the invitation's creation.
    accept_invitation(&shared.vault, member, Role::Member);
    assert_eq!(role_of(&shared.vault, member), Some(Role::Member));
    shared
        .vault
        .change_shared_member_role(&admin, SHARED, member, Role::Admin, None)
        .expect("the same session assigns the Admin role");
    assert_eq!(role_of(&shared.vault, member), Some(Role::Admin));
}

#[test]
fn a_step_up_on_another_credential_counts_for_nothing() {
    let shared = shared();
    let [first_member, second_member] = [shared.newcomer(), shared.newcomer()];
    shared.admin_acts();
    let first = admin_step_up::credential(&shared.vault, &shared.issuer, shared.admin);
    admin_step_up::enroll_totp_and_step_up(&shared.vault, &first);
    let second = admin_step_up::credential(&shared.vault, &shared.issuer, shared.admin);

    refused_for_step_up(
        shared.vault.add_shared_member(
            &admin_step_up::proof_on(&shared.vault, shared.admin, &second),
            SHARED,
            first_member,
            Some(Role::Member),
        ),
        "an Admin's AddMember on a session that never stepped up",
    );
    assert!(!invited_at(&shared.vault, first_member, Role::Member));
    shared
        .vault
        .add_shared_member(
            &admin_step_up::proof_on(&shared.vault, shared.admin, &first),
            SHARED,
            second_member,
            Some(Role::Member),
        )
        .expect("the session that stepped up adds a Member");
    assert!(invited_at(&shared.vault, second_member, Role::Member));
}

#[test]
fn the_owners_act_needs_no_step_up() {
    let shared = shared();
    let member = shared.newcomer();

    shared
        .vault
        .add_shared_member(
            &proof(&shared.vault, shared.owner),
            SHARED,
            member,
            Some(Role::Member),
        )
        .expect("the Owner adds a Member with no step-up");
    assert!(invited_at(&shared.vault, member, Role::Member));
}

#[test]
fn a_managed_admins_act_stands_on_the_supervisors_mfa_claim() {
    let shared = shared();
    let [refused_member, admitted_member] = [shared.newcomer(), shared.newcomer()];
    shared.admin_acts();

    let without =
        managed_person_proof(&shared.vault, shared.admin, false).expect("a managed person's proof");
    refused_for_step_up(
        shared
            .vault
            .add_shared_member(&without, SHARED, refused_member, Some(Role::Member)),
        "a managed Admin's AddMember with no supervisor MFA claim",
    );
    assert!(!invited_at(&shared.vault, refused_member, Role::Member));

    let with = managed_person_proof(&shared.vault, shared.admin, true)
        .expect("a managed person's proof on the supervisor's MFA claim");
    shared
        .vault
        .add_shared_member(&with, SHARED, admitted_member, Some(Role::Member))
        .expect("a managed Admin's AddMember on the supervisor's MFA claim");
    assert!(invited_at(&shared.vault, admitted_member, Role::Member));
}
