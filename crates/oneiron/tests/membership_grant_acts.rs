//! Pass 28 R2b: a shared vault's membership writers give each member Grant by a signed act in
//! the writer's own transaction, and end it by a counted record (Engine RULING
//! GRANT-ACT-FAILURE-POLICY = A, 16 Nov 03:42).
//!
//! - The creator's grant (W12), an accepted invitation (W10) and a role change (W10) each stand
//!   on their giving; the row a role change replaced stands for nothing when put back.
//! - A giving refuses on an install with no live install key, and writes nothing.
//! - A leave (W11) is never refused: its record ends the member's line in its writer, or
//!   waits pending on an install whose key is not loaded and ends it once the key loads.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test membership_grant_acts`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, InitialSharedMember,
    decode_federation_grant_body, decode_federation_grant_body_keyed,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::put_keyed_member_grant;
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_member_grant_act};
use oneiron::test_support::{bind_host_actor, bind_host_owner, provision_engine_machines};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const SHARED: u64 = 42;

/// A rooted install whose key carries acts, its keystore and its owner.
struct Install {
    dir: tempfile::TempDir,
    vault: Vault,
    keystore: Arc<MemoryKeystore>,
    issuer: HostSlipIssuer,
    owner: EntityId,
}

fn carrier_install() -> Install {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let keystore = Arc::new(MemoryKeystore::default());
    vault.install_device_keystore(keystore.clone());
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    Install {
        dir,
        vault,
        keystore,
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

/// `member` accepts its founding invitation at `role`.
fn accept(vault: &Vault, member: EntityId, role: Role) {
    let member_proof = proof(vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == role)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
}

/// `member`'s membership Grant row in the shared vault: its id and terms.
fn member_row(vault: &Vault, member: EntityId) -> Option<(EntityId, FederationGrant)> {
    vault
        .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
        .expect("grants")
        .into_iter()
        .find_map(|id| {
            let body = vault.get(&id).expect("grant row")?;
            let grant = decode_federation_grant_body(&body).ok()?;
            (grant.member_ref == member
                && grant.role != Role::Delegate
                && grant.scope == FederationGrantScope::vault(SHARED))
            .then_some((id, grant))
        })
}

/// The act row `id` stands on now as a member's Grant.
fn standing(vault: &Vault, id: EntityId) -> Option<[u8; 32]> {
    standing_member_grant_act(vault, id, vault.now_recorded_at()).expect("standing read")
}

/// `member` leaves, with the host key bound to it for its act, then bound back to the owner.
fn leave(install: &Install, vault: &Vault, member: EntityId) {
    bind_host_actor(vault, &install.issuer, member, "human").expect("the member's binding");
    vault
        .leave_shared_vault(&proof(vault, member), SHARED, None)
        .expect("a leave is never refused");
    bind_host_owner(vault, &install.issuer, install.owner).expect("the owner's binding again");
}

#[test]
fn the_creators_grant_stands_on_its_giving() {
    let install = carrier_install();
    let vault = &install.vault;
    share(vault, install.owner, &[]);
    let (id, grant) = member_row(vault, install.owner).expect("the creator's grant");
    assert_eq!(grant.role, Role::Owner);
    let act = standing(vault, id).expect("the creator's grant stands on a counted giving");
    assert_eq!(
        grant_line(vault, id).expect("line read"),
        Some((Some(act), false)),
        "the fold's line names that giving, not ended"
    );
}

#[test]
fn an_accepted_invitation_stands_on_its_giving() {
    let install = carrier_install();
    let vault = &install.vault;
    let member = EntityId::now();
    person(vault, member);
    share(vault, install.owner, &[(member, Role::Member)]);
    assert!(
        member_row(vault, member).is_none(),
        "an invitation writes no grant"
    );
    accept(vault, member, Role::Member);
    let (id, grant) = member_row(vault, member).expect("the accepted member's grant");
    assert_eq!(grant.role, Role::Member);
    assert!(
        standing(vault, id).is_some(),
        "the accepted member's grant stands on the inviter's giving"
    );
}

#[test]
fn a_role_change_gives_the_row_again_and_the_old_row_stands_for_nothing() {
    let install = carrier_install();
    let vault = &install.vault;
    let member = EntityId::now();
    person(vault, member);
    share(vault, install.owner, &[(member, Role::Member)]);
    accept(vault, member, Role::Member);
    let (id, _) = member_row(vault, member).expect("the member's grant");
    let first = standing(vault, id).expect("the member's grant stands");
    let old_body = grant_row(vault, id)
        .expect("row read")
        .expect("the live row");
    vault
        .change_shared_member_role(
            &proof(vault, install.owner),
            SHARED,
            member,
            Role::Viewer,
            None,
        )
        .expect("the Owner changes the member's role");
    let (changed, grant) = member_row(vault, member).expect("the changed grant");
    assert_eq!(changed, id, "a role change rewrites the row in place");
    assert_eq!(grant.role, Role::Viewer);
    let second = standing(vault, id).expect("the rewritten row stands on its own giving");
    assert_ne!(second, first, "the rewrite is a new giving");
    // The Member row's exact bytes, put back with no act, stand for nothing: the line's
    // giving now commits to the Viewer terms.
    let (old_grant, old_key) = decode_federation_grant_body_keyed(&old_body).expect("old body");
    let old_key = old_key.expect("the Member row was keyed by its giving");
    put_keyed_member_grant(vault, id, &old_grant, &old_key).expect("the old row put back");
    assert_eq!(
        standing(vault, id),
        None,
        "a replaced row put back stands for nothing"
    );
}

#[test]
fn a_giving_refuses_on_an_install_with_no_install_key() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("fresh vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let refused = vault.initialize_shared_vault(
        &proof(&vault, owner),
        SHARED,
        None,
        &[InitialSharedMember {
            member_ref: owner,
            role: Some(Role::Owner),
        }],
        vault.now_recorded_at(),
    );
    assert!(
        refused.is_err(),
        "the creator's giving refuses: this install carries no act"
    );
    assert!(
        vault
            .entities_by_type(ENTITY_TYPE_FEDERATION_GRANT)
            .expect("grants")
            .is_empty(),
        "nothing was written"
    );
}

#[test]
fn a_leave_ends_the_members_line_in_its_writer() {
    let install = carrier_install();
    let vault = &install.vault;
    let member = EntityId::now();
    person(vault, member);
    share(vault, install.owner, &[(member, Role::Member)]);
    accept(vault, member, Role::Member);
    let (id, _) = member_row(vault, member).expect("the member's grant");
    let given = standing(vault, id).expect("the member's grant stands");
    leave(&install, vault, member);
    assert!(
        member_row(vault, member).is_none(),
        "the leave drops the row"
    );
    assert_eq!(
        grant_line(vault, id).expect("line read"),
        Some((Some(given), true)),
        "the leave's record ended the line in its writer"
    );
    assert_eq!(standing(vault, id), None);
}

#[test]
fn a_leave_with_no_loaded_key_is_never_refused_and_ends_the_line_once_the_key_loads() {
    let install = carrier_install();
    let member = EntityId::now();
    person(&install.vault, member);
    share(&install.vault, install.owner, &[(member, Role::Member)]);
    accept(&install.vault, member, Role::Member);
    let (id, _) = member_row(&install.vault, member).expect("the member's grant");
    let given = standing(&install.vault, id).expect("the member's grant stands");
    // The same install opened again with no keystore: no install key can load.
    let Install {
        dir,
        vault,
        keystore,
        issuer,
        owner,
    } = install;
    drop(vault);
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("the vault again");
    let reopened = Install {
        dir,
        vault,
        keystore,
        issuer,
        owner,
    };
    let vault = &reopened.vault;
    leave(&reopened, vault, member);
    assert!(
        member_row(vault, member).is_none(),
        "the leave drops the row"
    );
    assert_eq!(
        grant_line(vault, id).expect("line read"),
        Some((Some(given), false)),
        "the leave's record waits pending while no key is loaded"
    );
    // The key loads before the next membership writer opens, and the owed record is carried.
    vault.install_device_keystore(reopened.keystore.clone());
    let invitee = EntityId::now();
    person(vault, invitee);
    vault
        .add_shared_member(
            &proof(vault, reopened.owner),
            SHARED,
            invitee,
            Some(Role::Member),
        )
        .expect("the Owner invites another member");
    assert_eq!(
        grant_line(vault, id).expect("line read"),
        Some((Some(given), true)),
        "the owed record ended the line once the key loaded"
    );
}
