//! A Steward's membership acts are asks (untangle 6.3d, ARCH-0043 Steward):
//! its add-member call writes an ask and changes no membership; a live Owner
//! applies it through the add door, and the receipt names both.
//!
//! Written by reading: the oneiron lib test target does not compile on main
//! (26 Oct decree).
use super::*;
use crate::federation::{InitialSharedMember, SharedVaultChange};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{TimeRange, VaultConfig};

const SHARED: u64 = 42;

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
        .unwrap();
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(
            person,
            &person.to_hex(),
            true,
            crate::store::GateDecisionId::now(),
        )
        .unwrap()
}

fn members(vault: &Vault) -> Vec<(EntityId, Role)> {
    let txn = vault.store.env.read_txn().unwrap();
    vault.shared_members_in_txn(&txn, SHARED).unwrap()
}

#[test]
fn a_stewards_add_member_call_becomes_an_ask_an_owner_applies() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let steward = person(&vault);
    let invitee = person(&vault);
    let (owner_proof, steward_proof, invitee_proof) = (
        proof(&vault, owner),
        proof(&vault, steward),
        proof(&vault, invitee),
    );
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: steward,
                    role: Some(Role::Steward),
                },
            ],
            1,
        )
        .unwrap();
    let roster = members(&vault);
    let add = MemberAskChange::Add {
        member: invitee.to_hex(),
        role: None,
    };

    // The add door itself refuses a Steward, as it did before 6.3d.
    assert!(
        vault
            .add_shared_member(&steward_proof, SHARED, invitee, None)
            .is_err()
    );

    // The Steward's add-member call becomes an ask: no invitation, no roster change.
    let SharedMemberChange::Asked(ask) = vault
        .shared_member_change(&steward_proof, SHARED, add.clone(), None)
        .unwrap()
    else {
        panic!("a Steward's add-member call is an ask");
    };
    assert_eq!(ask.steward, steward.to_hex());
    assert_eq!(ask.change, add);
    assert_eq!(ask.status, MemberAskStatus::Open);
    assert_eq!(members(&vault), roster);
    assert!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .unwrap()
            .is_empty()
    );

    // Asking again answers the open ask; the Steward sees its own ask.
    assert_eq!(
        vault
            .ask_shared_member_change(&steward_proof, SHARED, add.clone())
            .unwrap(),
        ask
    );
    assert_eq!(
        vault.shared_member_asks(&steward_proof, SHARED).unwrap(),
        vec![ask.clone()]
    );

    // A Steward never asks about its own membership, and never applies an ask.
    assert!(
        vault
            .ask_shared_member_change(
                &steward_proof,
                SHARED,
                MemberAskChange::AssignRole {
                    member: steward.to_hex(),
                    role: Role::Admin,
                },
            )
            .is_err()
    );
    assert!(
        vault
            .apply_shared_member_ask(&steward_proof, &ask.id, None)
            .is_err()
    );
    assert!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .unwrap()
            .is_empty()
    );

    // The Owner applies it through the add door: the receipt names the
    // Owner as actor and the Steward as proposer, and the ask closes.
    let receipt = vault
        .apply_shared_member_ask(&owner_proof, &ask.id, None)
        .unwrap();
    assert_eq!(receipt.actor, owner.to_hex());
    assert_eq!(receipt.proposer, Some(steward.to_hex()));
    assert!(matches!(
        &receipt.change,
        SharedVaultChange::MemberInvited { member, .. } if *member == invitee.to_hex()
    ));
    assert_eq!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .unwrap()
            .len(),
        1
    );
    let [closed] = vault
        .shared_member_asks(&owner_proof, SHARED)
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        closed.status,
        MemberAskStatus::Applied {
            by: owner.to_hex(),
            receipt: receipt.id.clone(),
        }
    );
    assert!(
        vault
            .apply_shared_member_ask(&owner_proof, &ask.id, None)
            .is_err()
    );

    // An Owner's own member change applies at once, with no proposer.
    let other = person(&vault);
    let SharedMemberChange::Applied(direct) = vault
        .shared_member_change(
            &owner_proof,
            SHARED,
            MemberAskChange::Add {
                member: other.to_hex(),
                role: None,
            },
            None,
        )
        .unwrap()
    else {
        panic!("an Owner's member change applies");
    };
    assert_eq!(direct.proposer, None);

    // A declined ask changes no membership.
    let later = person(&vault);
    let declined = vault
        .ask_shared_member_change(
            &steward_proof,
            SHARED,
            MemberAskChange::Add {
                member: later.to_hex(),
                role: None,
            },
        )
        .unwrap();
    let declined = vault
        .decline_shared_member_ask(&owner_proof, &declined.id)
        .unwrap();
    assert_eq!(
        declined.status,
        MemberAskStatus::Declined { by: owner.to_hex() }
    );
    assert!(
        vault
            .shared_invitations(&proof(&vault, later), SHARED)
            .unwrap()
            .is_empty()
    );
}
