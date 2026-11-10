//! A Steward's membership acts are asks (untangle 6.3d, S63-4 = A; ARCH-0043
//! Steward): its add-member call writes an ask and changes no membership; a
//! live Owner applies it through the add door, and the receipt names both.
//! A hard erase of a person deletes each ask that names them (review of
//! #6915, round 2: the ask table had no actor scrub).
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! steward_member_asks`.
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    FederationGrantRole as Role, InitialSharedMember, MemberAskChange, MemberAskStatus,
    SharedMemberChange, SharedVaultChange,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{DeleteReason, EntityId, Vault, VaultConfig};

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
        .expect("a live person");
    id
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

#[test]
fn a_stewards_add_member_call_becomes_an_ask_an_owner_applies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
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
        .expect("a shared vault with a Steward");
    // A founding member other than the creator joins by invitation (OF-531):
    // the Steward accepts its own before it acts as a member.
    let invitation = vault
        .shared_invitations(&steward_proof, SHARED)
        .expect("the Steward's invitations")
        .into_iter()
        .find(|open| open.role == Role::Steward)
        .expect("the Steward's founding invitation");
    vault
        .accept_shared_invitation(&steward_proof, SHARED, &invitation.id)
        .expect("the Steward accepts");
    let add = MemberAskChange::Add {
        member: invitee.to_hex(),
        role: None,
    };

    // The add door itself refuses a Steward.
    assert!(
        vault
            .add_shared_member(&steward_proof, SHARED, invitee, None)
            .is_err()
    );

    // The Steward's add-member call becomes an ask: no invitation is issued.
    let SharedMemberChange::Asked(ask) = vault
        .shared_member_change(&steward_proof, SHARED, add.clone(), None)
        .expect("the Steward's add-member call")
    else {
        panic!("a Steward's add-member call is an ask");
    };
    assert_eq!(ask.steward, steward.to_hex());
    assert_eq!(ask.change, add);
    assert_eq!(ask.status, MemberAskStatus::Open);
    assert!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .expect("invitations")
            .is_empty()
    );

    // Asking again answers the open ask; the Steward reads its own ask.
    assert_eq!(
        vault
            .ask_shared_member_change(&steward_proof, SHARED, add.clone())
            .expect("the same ask"),
        ask
    );
    assert_eq!(
        vault
            .shared_member_asks(&steward_proof, SHARED)
            .expect("asks"),
        vec![ask.clone()]
    );

    // A Steward never asks about its own membership, and never applies.
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
            .expect("invitations")
            .is_empty()
    );

    // The Owner applies it through the add door: the receipt names the
    // Owner as actor and the Steward as proposer, and the ask closes.
    let receipt = vault
        .apply_shared_member_ask(&owner_proof, &ask.id, None)
        .expect("the Owner applies the ask");
    assert_eq!(receipt.actor, owner.to_hex());
    assert_eq!(receipt.proposer, Some(steward.to_hex()));
    assert!(matches!(
        &receipt.change,
        SharedVaultChange::MemberInvited { member, .. } if *member == invitee.to_hex()
    ));
    assert_eq!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .expect("invitations")
            .len(),
        1
    );
    let asks = vault
        .shared_member_asks(&owner_proof, SHARED)
        .expect("asks");
    let [closed] = asks.as_slice() else {
        panic!("one ask, found {}", asks.len());
    };
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
        .expect("the Owner's member change")
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
        .expect("a second ask");
    let declined = vault
        .decline_shared_member_ask(&owner_proof, &declined.id)
        .expect("the Owner declines");
    assert_eq!(
        declined.status,
        MemberAskStatus::Declined { by: owner.to_hex() }
    );
    assert!(
        vault
            .shared_invitations(&proof(&vault, later), SHARED)
            .expect("invitations")
            .is_empty()
    );
}

/// Review of #6917: the ask door took an add the membership door refuses. A
/// person with an open invitation to the vault is no member yet, and the add
/// effect refuses a second invitation, so the Steward's ask is refused at
/// filing and nothing is stored.
#[test]
fn a_steward_cannot_ask_to_add_a_person_who_holds_an_open_invitation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
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
        .expect("a shared vault with a Steward");
    let invitation = vault
        .shared_invitations(&steward_proof, SHARED)
        .expect("the Steward's invitations")
        .into_iter()
        .find(|open| open.role == Role::Steward)
        .expect("the Steward's founding invitation");
    vault
        .accept_shared_invitation(&steward_proof, SHARED, &invitation.id)
        .expect("the Steward accepts");

    // The Owner invites the person: an open invitation, no membership yet.
    vault
        .add_shared_member(&owner_proof, SHARED, invitee, None)
        .expect("the Owner's invitation");
    assert_eq!(
        vault
            .shared_invitations(&invitee_proof, SHARED)
            .expect("invitations")
            .len(),
        1
    );
    // The add door refuses a second invitation while that one is open.
    assert!(
        vault
            .add_shared_member(&owner_proof, SHARED, invitee, None)
            .is_err()
    );

    // So the Steward's ask to add them is refused, by either door.
    let add = MemberAskChange::Add {
        member: invitee.to_hex(),
        role: None,
    };
    assert!(
        vault
            .ask_shared_member_change(&steward_proof, SHARED, add.clone())
            .is_err(),
        "an ask the add door cannot apply is refused at filing"
    );
    assert!(
        vault
            .shared_member_change(&steward_proof, SHARED, add, None)
            .is_err()
    );
    assert!(
        vault
            .shared_member_asks(&owner_proof, SHARED)
            .expect("asks")
            .is_empty(),
        "no ask is stored"
    );
}

/// A hard erase of a person takes them out of the asks: the ask table names
/// people (its Steward, the member a change is about, who closed it) and had
/// no actor scrub, so an ask to add M still showed M after M was erased.
#[test]
fn a_hard_erase_deletes_the_asks_that_name_the_erased_person() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let steward = person(&vault);
    let erased = person(&vault);
    let other = person(&vault);
    let (owner_proof, steward_proof) = (proof(&vault, owner), proof(&vault, steward));
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
        .expect("a shared vault with a Steward");
    let invitation = vault
        .shared_invitations(&steward_proof, SHARED)
        .expect("the Steward's invitations")
        .into_iter()
        .find(|open| open.role == Role::Steward)
        .expect("the Steward's founding invitation");
    vault
        .accept_shared_invitation(&steward_proof, SHARED, &invitation.id)
        .expect("the Steward accepts");

    // Two asks: one names the person who is erased, one names someone else.
    let names_erased = vault
        .ask_shared_member_change(
            &steward_proof,
            SHARED,
            MemberAskChange::Add {
                member: erased.to_hex(),
                role: None,
            },
        )
        .expect("the ask that names the erased person");
    let names_other = vault
        .ask_shared_member_change(
            &steward_proof,
            SHARED,
            MemberAskChange::Add {
                member: other.to_hex(),
                role: None,
            },
        )
        .expect("the ask that names someone else");
    assert_eq!(
        vault
            .shared_member_asks(&owner_proof, SHARED)
            .expect("asks")
            .len(),
        2,
        "two asks before the erase"
    );

    vault
        .delete_entity_with_reason(&erased, DeleteReason::UserHardDelete)
        .expect("hard erase");

    let left = vault
        .shared_member_asks(&owner_proof, SHARED)
        .expect("asks");
    let named = erased.to_hex();
    assert!(
        left.iter()
            .all(|ask| !serde_json::to_string(ask).expect("ask").contains(&named)),
        "no ask names the erased person: {left:?}"
    );
    assert_eq!(
        left.iter().map(|ask| ask.id.as_str()).collect::<Vec<_>>(),
        [names_other.id.as_str()],
        "the ask that names someone else stands"
    );
    assert!(
        vault
            .apply_shared_member_ask(&owner_proof, &names_erased.id, None)
            .is_err(),
        "an ask about an erased person is gone: nothing to apply"
    );
}
