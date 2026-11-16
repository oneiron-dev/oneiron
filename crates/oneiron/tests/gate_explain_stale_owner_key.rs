//! FIX GATE-EXPLAIN-STALE-OWNER-KEY: `Vault::explain_gate_receipt` read the
//! owner flag a read key stored when it was made
//! (`ScopedReadActorKey::reads_as_vault_owner`) and never judged it again. A
//! receipt that names no claim runs no scoped read, so an owner key kept past
//! its holder's demotion still read another actor's receipt: its writer,
//! outcome, reasons and notices. The owner widening now holds only while the
//! key's owner binding holds in the snapshot that reads the receipt.
//!
//! Public doors only: the policy-manifest door writes a receipt with no
//! claim, a shared vault seats a second Owner, and `remove_owner` makes that
//! Owner an Admin while its read key is kept.
//!
//! `cargo test --locked -p oneiron --all-features --test gate_explain_stale_owner_key`

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
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

/// The embedded owner writes the default policy manifest back unchanged:
/// the door records an allow receipt whose writer is the owner and which
/// names no claim. Returns the owner and the receipt id (`gate:<hex>`).
fn owner_policy_receipt(vault: &Vault) -> (EntityId, String) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_proof = proof(vault, owner);
    let policies = policy_manifests_as_owner(
        vault,
        &owner_proof,
        &PolicyManifestRead { manifest_ref: None },
    )
    .expect("the owner reads the default manifest");
    let default_ref = policies.default_manifest_ref;
    let default_view = policies
        .manifests
        .into_iter()
        .find(|view| view.manifest_ref == default_ref)
        .expect("the seeded default manifest");
    let receipt = put_policy_manifest_as_owner(
        vault,
        &owner_proof,
        PolicyManifestPut {
            manifest_ref: Some(default_ref),
            expected_body_hash: Some(default_view.body_hash),
            manifest: default_view.manifest,
        },
    )
    .expect("the owner writes the default manifest");
    assert!(receipt.receipt_ref.starts_with("gate:"));
    (owner, receipt.receipt_ref)
}

/// A shared vault whose roster holds the embedded owner and `co_owner` as
/// Owners, the co-owner having accepted its founding invitation.
fn seat_co_owner(vault: &Vault, owner: EntityId, co_owner: EntityId) {
    person(vault, co_owner);
    vault
        .initialize_shared_vault(
            &proof(vault, owner),
            SHARED,
            None,
            &[
                InitialSharedMember {
                    member_ref: owner,
                    role: Some(Role::Owner),
                },
                InitialSharedMember {
                    member_ref: co_owner,
                    role: Some(Role::Owner),
                },
            ],
            1,
        )
        .expect("a shared vault with a co-owner");
    let co_owner_proof = proof(vault, co_owner);
    let invitation = vault
        .shared_invitations(&co_owner_proof, SHARED)
        .expect("the co-owner's invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("an open invitation at Owner");
    vault
        .accept_shared_invitation(&co_owner_proof, SHARED, &invitation.id)
        .expect("the co-owner accepts");
    assert_eq!(role_of(vault, co_owner), Some(Role::Owner));
}

/// Control, green on main and on the fix: while the co-owner is an Owner,
/// its owner read key explains the other owner's receipt and names its
/// writer.
#[test]
fn a_live_co_owners_read_key_still_explains_the_other_owners_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (owner, receipt) = owner_policy_receipt(&vault);
    let co_owner = EntityId::now();
    seat_co_owner(&vault, owner, co_owner);

    let key = vault
        .owner_proof_read_key(&proof(&vault, co_owner))
        .expect("a live co-owner's read key");
    let read = vault.scoped_read(key);
    assert!(read.actor_key().reads_as_vault_owner());
    let explained = vault
        .explain_gate_receipt(&read, &receipt)
        .expect("a live owner's explanation")
        .expect("a live owner reads every receipt");
    assert_eq!(explained.receipt_id, receipt);
    assert_eq!(explained.actor_ref, Some(owner.to_hex()));
}

/// Red on main: the co-owner keeps its owner read key, the other owner makes
/// it an Admin through `remove_owner`, and the kept key still read the other
/// owner's receipt in full. With the fix the stale owner key widens nothing.
#[test]
fn a_demoted_owners_kept_read_key_explains_no_other_owners_receipt() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let (owner, receipt) = owner_policy_receipt(&vault);
    let co_owner = EntityId::now();
    seat_co_owner(&vault, owner, co_owner);

    let key = vault
        .owner_proof_read_key(&proof(&vault, co_owner))
        .expect("a live co-owner's read key");
    let kept = vault.scoped_read(key);
    let before = vault.explain_gate_receipt(&kept, &receipt);
    assert!(
        matches!(before, Ok(Some(_))),
        "the key reads the receipt while its holder is an Owner: {before:?}"
    );

    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_remove_owner(
            &owner_proof,
            SHARED,
            co_owner,
            None,
            Some(Role::Admin),
            false,
        )
        .expect("the other Owner starts remove_owner, the co-owner keeping Admin");
    vault
        .execute_completed_shared_act(&owner_proof, &act.id, None)
        .expect("remove_owner runs at once under its zero wait");
    assert_eq!(
        role_of(&vault, co_owner),
        Some(Role::Admin),
        "the co-owner is an Admin now"
    );

    let after = vault.explain_gate_receipt(&kept, &receipt);
    assert!(
        !matches!(after, Ok(Some(_))),
        "an owner key kept past its holder's demotion must not read another \
         owner's receipt: {after:?}"
    );
}
