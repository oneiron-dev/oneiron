//! A built-in act name whose plan does not decode is refused at the start,
//! before the store ([BUILTIN-ACT-PLAN-UNCHECKED-AT-START]): an Owner could
//! store an act that could never run, as its executor refuses it as an
//! invalid shared-vault act. A plan that decodes still starts, and any other
//! name keeps its opaque host payload.
//!
//! Runs on public paths: `cargo test -p oneiron --all-features --test
//! builtin_act_plan_unchecked_at_start`.
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    AddOwnerPlan, DeleteVaultPlan, FederationGrantRole as Role, InitialSharedMember,
    RemoveOwnerPlan, TransferOwnershipPlan,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EntityId, Vault, VaultConfig};

const SHARED: u64 = 42;
/// A payload no built-in plan decodes from.
const GARBAGE: &[u8] = b"not a plan";

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

/// A shared vault whose one Owner is its embedded owner.
fn shared(vault: &Vault) -> (AuthenticatedOwner, EntityId) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[InitialSharedMember {
                member_ref: owner,
                role: Some(Role::Owner),
            }],
            1,
        )
        .expect("a shared vault");
    (proof(vault, owner), owner)
}

#[test]
fn a_builtin_name_refuses_a_plan_that_does_not_decode() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (owner_proof, _) = shared(&vault);
    for act in [
        "add_owner",
        "transfer_ownership",
        "remove_owner",
        "delete_vault",
    ] {
        let refused = vault.start_authority_act(&owner_proof, SHARED, act, GARBAGE.to_vec());
        assert!(
            refused.is_err(),
            "a {act} act whose plan does not decode must be refused before the store: {refused:?}"
        );
    }
}

#[test]
fn a_builtin_name_starts_a_plan_that_decodes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (owner_proof, owner) = shared(&vault);
    let candidate = person(&vault);
    let plans = [
        (
            "add_owner",
            serde_json::to_vec(&AddOwnerPlan {
                v: 1,
                owner: candidate.to_hex(),
            })
            .expect("the add_owner plan encodes"),
        ),
        (
            "transfer_ownership",
            serde_json::to_vec(&TransferOwnershipPlan {
                v: 1,
                from: owner.to_hex(),
                to: candidate.to_hex(),
                from_keeps: None,
            })
            .expect("the transfer_ownership plan encodes"),
        ),
        (
            "remove_owner",
            serde_json::to_vec(&RemoveOwnerPlan {
                v: 1,
                target: owner.to_hex(),
                successor: None,
                target_keeps: None,
                export_first: false,
            })
            .expect("the remove_owner plan encodes"),
        ),
        (
            "delete_vault",
            serde_json::to_vec(&DeleteVaultPlan { v: 1 }).expect("the delete_vault plan encodes"),
        ),
    ];
    for (act, plan) in plans {
        let started = vault
            .start_authority_act(&owner_proof, SHARED, act, plan.clone())
            .expect("a plan that decodes still starts");
        let stored = vault
            .pending_authority_act(started.id.as_str())
            .expect("the read")
            .expect("the started act");
        assert_eq!(stored.payload, plan, "the {act} act stores its plan");
    }
}

#[test]
fn any_other_name_keeps_its_opaque_payload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (owner_proof, _) = shared(&vault);
    let custom = vault
        .start_authority_act(&owner_proof, SHARED, "custom_act", GARBAGE.to_vec())
        .expect("a host act keeps its opaque payload");
    assert_eq!(custom.act, "custom_act");
    vault
        .start_authority_act(&owner_proof, SHARED, "erase", vec![])
        .expect("a held erase names its record through its own door");
}
