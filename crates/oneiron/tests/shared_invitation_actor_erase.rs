//! A hard erase of a person leaves no trace of them in the shared vault's
//! invitations (SHARED-INVITATION-ACTOR-ERASE; the shared-act family's rule,
//! Engine RULING ROW4-SHARED-ACT-ERASE = B with the lead's condition, 13 Nov
//! 21:09). On main neither invitation table had an actor scrub: an erased
//! invitee's invitation and the key they bound stayed under their id, and an
//! erased inviter's id stayed in each invitation they issued. Now:
//! - the person's own invitations and bound keys are gone;
//! - another person's invitation keeps its scaffold, the erased marker where
//!   its inviter named them, and it no longer admits; its invitee still
//!   declines it.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test shared_invitation_actor_erase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, SharedInvitation, SharedInvitationState,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::shared_invitation_rows::{bind_invitation_key, rows_naming};
use oneiron::{DeleteReason, EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;
/// The marker an erased person's slot holds.
const ERASED: &str = "erased";

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// `admin`'s proof for an Admin's membership act. An org Admin's act stands
/// on an MFA step-up (L7-17); this person holds no slip, so the proof
/// carries a managed supervisor's `mfa_verified` claim. Only the org-admin
/// step-up reads it.
fn admin_proof(vault: &Vault, admin: EntityId) -> AuthenticatedOwner {
    vault
        .bind_managed_mfa_verified(proof(vault, admin))
        .expect("the supervisor's MFA claim binds")
}

/// A vault and its embedded owner. An erase signs its receipt with the
/// install's device key, which the delete door loads from the keystore a
/// host installs.
fn vault_and_owner(dir: &std::path::Path) -> (Vault, EntityId) {
    let vault = Vault::open(dir, VaultConfig::default()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    (vault, owner)
}

/// The shared vault with `owner` as its Owner and, when named, `member` at
/// its role, who accepts the founding invitation.
fn share(vault: &Vault, owner: EntityId, member: Option<(EntityId, Role)>) {
    let mut members = vec![InitialSharedMember {
        member_ref: owner,
        role: Some(Role::Owner),
    }];
    members.extend(member.map(|(member, role)| InitialSharedMember {
        member_ref: member,
        role: Some(role),
    }));
    vault
        .initialize_shared_vault(&proof(vault, owner), SHARED, None, &members, 1)
        .expect("a shared vault");
    if let Some((member, role)) = member {
        let member_proof = proof(vault, member);
        let invitation = vault
            .shared_invitations(&member_proof, SHARED)
            .expect("the member's invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
            .expect("the member accepts");
    }
}

/// `invitee`'s one pending invitation into the shared vault.
fn pending_invitation(vault: &Vault, invitee: EntityId) -> SharedInvitation {
    let mut open = vault
        .shared_invitations(&proof(vault, invitee), SHARED)
        .expect("the invitee's invitations");
    assert_eq!(open.len(), 1, "one pending invitation: {open:?}");
    open.remove(0)
}

fn hard_erase(vault: &Vault, person: EntityId) {
    vault
        .delete_entity_with_reason(&person, DeleteReason::UserHardDelete)
        .expect("hard erase");
}

#[test]
fn an_erased_invitees_invitation_and_key_rows_are_gone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let invitee = person(&vault);
    share(&vault, owner, None);
    vault
        .add_shared_member(&proof(&vault, owner), SHARED, invitee, Some(Role::Member))
        .expect("the Owner invites a Member");
    let invitation = pending_invitation(&vault, invitee);
    bind_invitation_key(&vault, invitee, &invitation.id, [7; 32]).expect("the bound key");
    let before = rows_naming(&vault, invitee).expect("rows");
    assert_eq!(
        before.len(),
        2,
        "before the erase the invitation and its key row name the invitee: {before:?}"
    );

    hard_erase(&vault, invitee);

    assert_eq!(
        rows_naming(&vault, invitee).expect("rows"),
        Vec::<String>::new(),
        "no invitation row holds the erased invitee's id"
    );
    assert_eq!(
        vault.get(&invitee).expect("the lookup"),
        None,
        "the erased id resolves to nothing"
    );
}

#[test]
fn an_erased_inviters_name_leaves_the_invitation_and_it_no_longer_admits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let admin = person(&vault);
    let invitee = person(&vault);
    share(&vault, owner, Some((admin, Role::Admin)));
    vault
        .add_shared_member(
            &admin_proof(&vault, admin),
            SHARED,
            invitee,
            Some(Role::Member),
        )
        .expect("the Admin invites a Member");
    let before = pending_invitation(&vault, invitee);
    assert_eq!(before.inviter, admin.to_hex());

    hard_erase(&vault, admin);

    assert_eq!(
        rows_naming(&vault, admin).expect("rows"),
        Vec::<String>::new(),
        "no invitation row holds the erased inviter's id"
    );
    let after = pending_invitation(&vault, invitee);
    assert_eq!(after.inviter, ERASED, "the inviter slot holds the marker");
    assert_eq!(
        (after.id.as_str(), after.role, after.state.clone()),
        (
            before.id.as_str(),
            Role::Member,
            SharedInvitationState::Pending
        ),
        "the invitation keeps its scaffold"
    );
    let refused = vault.accept_shared_invitation(&proof(&vault, invitee), SHARED, &after.id);
    let reason = refused.expect_err("an invitation whose inviter was erased does not admit");
    assert!(
        reason.to_string().contains("inviter's identity was erased"),
        "the invitee reads why: {reason}"
    );
}

#[test]
fn an_invitee_still_declines_an_invitation_whose_inviter_was_erased() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let admin = person(&vault);
    let invitee = person(&vault);
    share(&vault, owner, Some((admin, Role::Admin)));
    vault
        .add_shared_member(
            &admin_proof(&vault, admin),
            SHARED,
            invitee,
            Some(Role::Member),
        )
        .expect("the Admin invites a Member");

    hard_erase(&vault, admin);

    let invitation = pending_invitation(&vault, invitee);
    vault
        .decline_shared_invitation(&proof(&vault, invitee), SHARED, &invitation.id)
        .expect("the invitee declines");
    assert!(
        vault
            .shared_invitations(&proof(&vault, invitee), SHARED)
            .expect("the invitee's invitations")
            .is_empty(),
        "nothing stays pending"
    );
}

/// Review of #9159: an invitation whose inviter was erased can no longer be
/// accepted, so it no longer blocks a live `add_member` holder from inviting
/// the same person again. On main the stale invitation stood until it
/// expired, and the new invitation was refused.
#[test]
fn a_live_owner_invites_again_a_person_whose_inviter_was_erased() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let admin = person(&vault);
    let invitee = person(&vault);
    share(&vault, owner, Some((admin, Role::Admin)));
    vault
        .add_shared_member(
            &admin_proof(&vault, admin),
            SHARED,
            invitee,
            Some(Role::Member),
        )
        .expect("the Admin invites a Member");
    let stale = pending_invitation(&vault, invitee);

    hard_erase(&vault, admin);

    vault
        .add_shared_member(&proof(&vault, owner), SHARED, invitee, Some(Role::Member))
        .expect("the Owner invites the same person again");
    let open = vault
        .shared_invitations(&proof(&vault, invitee), SHARED)
        .expect("the invitee's invitations");
    let fresh = open
        .iter()
        .find(|invitation| invitation.id != stale.id)
        .expect("the Owner's new invitation is listed");
    assert_eq!(
        fresh.inviter,
        owner.to_hex(),
        "the new invitation names its inviter"
    );
    vault
        .accept_shared_invitation(&proof(&vault, invitee), SHARED, &fresh.id)
        .expect("the invitee accepts the live Owner's invitation");
}
