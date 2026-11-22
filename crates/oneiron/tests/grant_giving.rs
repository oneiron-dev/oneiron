//! Pass 28 R2b: a membership writer's giving (`Vault::give_grant_in_txn`) refuses at an id whose
//! Grant a counted act already ended, and writes nothing. An end is forever, so a row given
//! again at that id would stand for nothing although its giving counted; a writer gives at a
//! fresh id instead.
//!
//! Runs on public paths and the test doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test grant_giving`.
#![cfg(all(oneiron_test_support, feature = "sync"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrant, FederationGrantRole as Role, FederationGrantScope, InitialSharedMember,
    decode_federation_grant_body,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::grant_act::give_member_grant_as_writer;
use oneiron::test_doors::grant_standing::{grant_line, grant_row, standing_member_grant_act};
use oneiron::test_support::{bind_host_actor, bind_host_owner, provision_engine_machines};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

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

#[test]
fn a_giving_at_an_ended_grants_id_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding");
    let member = EntityId::now();
    person(&vault, member);
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: member,
                    role: Some(Role::Member),
                },
            ],
            vault.now_recorded_at(),
        )
        .expect("a shared vault");
    let member_proof = proof(&vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Member)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
    let (id, grant) = member_row(&vault, member).expect("the member's grant");
    let given = standing_member_grant_act(&vault, id, vault.now_recorded_at())
        .expect("standing read")
        .expect("the member's grant stands");
    bind_host_actor(&vault, &issuer, member, "human").expect("the member's binding");
    vault
        .leave_shared_vault(&member_proof, SHARED, None)
        .expect("a leave is never refused");
    bind_host_owner(&vault, &issuer, owner).expect("the owner's binding again");
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        Some((Some(given), true)),
        "the leave's record ended the line"
    );

    let refused = give_member_grant_as_writer(&vault, id, &grant, owner);
    let error = refused.expect_err("a giving at the ended Grant's id refuses");
    assert!(
        error
            .to_string()
            .contains("already ended the Grant at this id"),
        "the refusal names the ended Grant, not another fault: {error}"
    );
    assert_eq!(
        grant_row(&vault, id).expect("row read"),
        None,
        "nothing is written at the ended id"
    );
    assert_eq!(
        grant_line(&vault, id).expect("line read"),
        Some((Some(given), true)),
        "the line holds no new giving"
    );
}
