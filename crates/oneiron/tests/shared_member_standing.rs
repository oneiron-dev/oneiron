//! A shared vault's owners and members come only from Grants the fold stands behind
//! (pass 28 R3, FIX SHARED-OWNER-SET-FROM-ROWS).
//!
//! A Grant row confers nothing by itself: a row no counted act gives, and a row put back
//! after a counted act ended its line, make no owner and no member. The vault's honest
//! owner and member, whose rows stand on their counted givings, keep their standing.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test shared_member_standing`.
#![cfg(all(feature = "sync", feature = "test-support", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, InitialSharedMember,
    decode_federation_grant_body, decode_federation_grant_body_keyed,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::{put_keyed_member_grant, put_unkeyed_member_grant};
use oneiron::test_doors::grant_standing::{grant_row, standing_member_grant_act};
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;

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

/// A fresh live person who holds nothing in the vault.
fn stranger(vault: &Vault) -> EntityId {
    let stranger = EntityId::now();
    person(vault, stranger);
    stranger
}

/// Puts `template`'s terms for `holder` at a fresh id, with no act: a forged row.
fn put_bare_copy(vault: &Vault, template: &FederationGrant, holder: EntityId) -> EntityId {
    let mut forged = template.clone();
    forged.member_ref = holder;
    let id = EntityId::now();
    put_unkeyed_member_grant(vault, id, &forged).expect("a bare row lands");
    assert_eq!(
        standing(vault, id),
        None,
        "FIXTURE: the bare row stands on no giving"
    );
    id
}

/// Catches a bare Owner row making an owner: the owner census read every live Owner row.
#[test]
fn a_bare_owner_row_makes_no_owner() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (_, owner) = provision_act_carrier(&vault);
    share(&vault, owner, &[]);
    let (owner_grant, owner_row) = member_row(&vault, owner).expect("the owner's grant");
    assert!(
        standing(&vault, owner_grant).is_some(),
        "FIXTURE: the owner's grant stands on its giving"
    );
    let forger = stranger(&vault);
    put_bare_copy(&vault, &owner_row, forger);

    assert!(
        !vault.is_live_owner_person(&forger).expect("owner read"),
        "a bare Owner row makes no owner"
    );
    assert!(
        vault.is_live_owner_person(&owner).expect("owner read"),
        "the owner whose row stands on its giving stays an owner"
    );
}

/// Catches an owner's row put back after its removal making them an owner again.
#[test]
fn a_removed_owners_put_back_row_makes_no_owner() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (issuer, owner) = provision_act_carrier(&vault);
    let o1 = EntityId::now();
    person(&vault, o1);
    share(&vault, owner, &[(o1, Role::Owner)]);
    accept(&vault, o1, Role::Owner);
    let (grant_id, _) = member_row(&vault, o1).expect("O1's grant");
    assert!(
        vault.is_live_owner_person(&o1).expect("owner read"),
        "FIXTURE: O1 owns the vault"
    );
    let old_body = grant_row(&vault, grant_id)
        .expect("row read")
        .expect("the live Owner row");

    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_remove_owner(&owner_proof, SHARED, o1, None, None, false)
        .expect("the owner starts remove_owner");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, Some(&issuer))
        .expect("remove_owner runs");
    assert!(
        member_row(&vault, o1).is_none(),
        "FIXTURE: the removal drops O1's row"
    );
    let (old_grant, old_key) = decode_federation_grant_body_keyed(&old_body).expect("old body");
    let old_key = old_key.expect("the Owner row was keyed by its giving");
    put_keyed_member_grant(&vault, grant_id, &old_grant, &old_key).expect("the old row put back");
    assert_eq!(
        standing(&vault, grant_id),
        None,
        "FIXTURE: the put-back row stands for nothing"
    );

    assert!(
        !vault.is_live_owner_person(&o1).expect("owner read"),
        "a removed owner's put-back row makes no owner"
    );
    assert!(
        vault.is_live_owner_person(&owner).expect("owner read"),
        "the remaining owner stays an owner"
    );
}

/// Catches a bare Member row giving membership: the member standing read every live row.
#[test]
fn a_bare_member_row_gives_no_membership() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (_, owner) = provision_act_carrier(&vault);
    let member = EntityId::now();
    person(&vault, member);
    share(&vault, owner, &[(member, Role::Member)]);
    accept(&vault, member, Role::Member);
    let (_, member_grant) = member_row(&vault, member).expect("the member's grant");
    assert!(
        vault.is_live_member_person(&member).expect("member read"),
        "FIXTURE: the member's grant gives membership"
    );
    let forger = stranger(&vault);
    put_bare_copy(&vault, &member_grant, forger);

    assert!(
        !vault.is_live_member_person(&forger).expect("member read"),
        "a bare Member row gives no membership"
    );
    assert!(
        vault.is_live_member_person(&member).expect("member read"),
        "the member whose row stands on its giving stays a member"
    );
}

/// Catches a removed member's row put back giving membership again.
#[test]
fn a_removed_members_put_back_row_gives_no_membership() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    let (issuer, owner) = provision_act_carrier(&vault);
    let member = EntityId::now();
    person(&vault, member);
    share(&vault, owner, &[(member, Role::Member)]);
    accept(&vault, member, Role::Member);
    let (grant_id, _) = member_row(&vault, member).expect("the member's grant");
    let old_body = grant_row(&vault, grant_id)
        .expect("row read")
        .expect("the live Member row");

    vault
        .remove_shared_member(&proof(&vault, owner), SHARED, member, Some(&issuer))
        .expect("the owner removes the member");
    assert!(
        member_row(&vault, member).is_none(),
        "FIXTURE: the removal drops the member's row"
    );
    let (old_grant, old_key) = decode_federation_grant_body_keyed(&old_body).expect("old body");
    let old_key = old_key.expect("the Member row was keyed by its giving");
    put_keyed_member_grant(&vault, grant_id, &old_grant, &old_key).expect("the old row put back");
    assert_eq!(
        standing(&vault, grant_id),
        None,
        "FIXTURE: the put-back row stands for nothing"
    );

    assert!(
        !vault.is_live_member_person(&member).expect("member read"),
        "a removed member's put-back row gives no membership"
    );
}
