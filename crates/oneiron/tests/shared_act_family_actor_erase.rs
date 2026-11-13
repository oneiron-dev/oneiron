//! A hard erase of a person keeps a shared vault's governance scaffold and
//! drops its attribution (SHARED-ACT-FAMILY-ACTOR-ERASE; Engine RULING
//! ROW4-SHARED-ACT-ERASE = B with the lead's condition, 13 Nov 21:09, and
//! RULING SHARED-ERASE-REFUSAL-RECEIPT = A, 21:23). On main no shared-act
//! table had an actor scrub: a receipt kept an erased Steward as its
//! proposer, a pending act kept an erased person as its operand, and an
//! erase ask kept its erased asker. Now:
//! - each slot that named the person holds the erased marker, and no
//!   shared-act row holds their id, except a record target that is their
//!   own person row, which resolves to nothing after the erase;
//! - their own outcome, started and matured notices are gone;
//! - a pending act whose operand they were is refused with its reason.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test shared_act_family_actor_erase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{
    AddOwnerPlan, FederationGrantRole as Role, InitialSharedMember, MemberAskChange,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::shared_act_family::rows_naming;
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

fn hard_erase(vault: &Vault, person: EntityId) {
    vault
        .delete_entity_with_reason(&person, DeleteReason::UserHardDelete)
        .expect("hard erase");
}

/// The lead's condition: after the erase the id is an orphaned key, with no
/// identity row, name or profile behind it.
fn assert_resolves_to_nothing(vault: &Vault, person: EntityId) {
    assert_eq!(
        vault.get(&person).expect("the lookup"),
        None,
        "the erased id resolves to nothing"
    );
}

#[test]
fn an_erased_stewards_receipt_keeps_its_scaffold_without_their_identity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let steward = person(&vault);
    let invitee = person(&vault);
    share(&vault, owner, Some((steward, Role::Steward)));
    let (owner_proof, steward_proof) = (proof(&vault, owner), proof(&vault, steward));
    let ask = vault
        .ask_shared_member_change(
            &steward_proof,
            SHARED,
            MemberAskChange::Add {
                member: invitee.to_hex(),
                role: None,
            },
        )
        .expect("the Steward's ask");
    let receipt = vault
        .apply_shared_member_ask(&owner_proof, &ask.id, None)
        .expect("the Owner applies it");
    assert_eq!(receipt.proposer, Some(steward.to_hex()));
    assert!(
        !rows_naming(&vault, steward).expect("rows").is_empty(),
        "before the erase the shared-act rows name the Steward"
    );

    hard_erase(&vault, steward);

    let read = vault
        .shared_act_receipt(&owner_proof, &receipt.id)
        .expect("the receipt stays");
    assert_eq!(
        read.proposer.as_deref(),
        Some(ERASED),
        "the erased Steward's slot holds the erased marker"
    );
    assert_eq!(
        (read.id, read.actor, read.completed_at),
        (receipt.id, owner.to_hex(), receipt.completed_at),
        "its id, the Owner's part and its clock stay"
    );
    assert_eq!(read.change, receipt.change, "the invitee's part stays");
    assert_eq!(
        rows_naming(&vault, steward).expect("rows"),
        Vec::<String>::new(),
        "a lookup by the erased id finds the erased marker only: no shared-act row holds the id"
    );
    assert_resolves_to_nothing(&vault, steward);
}

#[test]
fn a_pending_act_whose_operand_was_erased_is_refused_with_its_reason() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let candidate = person(&vault);
    share(&vault, owner, None);
    let owner_proof = proof(&vault, owner);
    let act = vault
        .propose_add_owner(&owner_proof, SHARED, candidate)
        .expect("the Owner starts add_owner");

    hard_erase(&vault, candidate);

    let refusal = vault
        .execute_completed_shared_act(&owner_proof, &act.id, None)
        .expect_err("an act whose operand was erased does not run");
    assert!(
        refusal.to_string().contains("identity was erased"),
        "the refusal says why: {refusal}"
    );
    let pending = vault
        .pending_authority_act(&act.id)
        .expect("the read")
        .expect("the act stays as scaffold");
    let plan: AddOwnerPlan = serde_json::from_slice(&pending.payload).expect("its plan");
    assert_eq!(plan.owner, ERASED, "its operand holds the erased marker");
    assert_eq!(pending.starter, owner.to_hex(), "its starter's part stays");
    assert_eq!(
        rows_naming(&vault, candidate).expect("rows"),
        Vec::<String>::new(),
        "no shared-act row holds the erased id"
    );
    assert_resolves_to_nothing(&vault, candidate);
}

#[test]
fn an_erased_askers_erase_ask_keeps_its_record_target_as_scaffold() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let admin = person(&vault);
    share(&vault, owner, Some((admin, Role::Admin)));
    // The Admin proposes to erase their own person row: the ask's record
    // target is the very id the hard erase removes.
    let ask = vault
        .ask_shared_erase(&proof(&vault, admin), SHARED, admin)
        .expect("the Admin's erase proposal");
    assert_eq!(ask.asker, admin.to_hex());

    hard_erase(&vault, admin);

    let asks = vault
        .shared_erase_asks(&proof(&vault, owner), SHARED)
        .expect("the Owner reads the asks");
    let [kept] = asks.as_slice() else {
        panic!("one ask, found {asks:?}");
    };
    assert_eq!(
        (kept.id.as_str(), kept.asker.as_str(), kept.record.as_str()),
        (ask.id.as_str(), ERASED, admin.to_hex().as_str()),
        "the asker holds the erased marker; the record target stays as scaffold"
    );
    assert_eq!(
        rows_naming(&vault, admin).expect("rows"),
        vec![format!("erase_ask:{}", ask.id)],
        "the one row that holds the id is the ask's record target"
    );
    assert_resolves_to_nothing(&vault, admin);
}

/// Review round 1 of #7759: `start_authority_act` checks a built-in act's
/// name, not its plan, so an Owner can store an `add_owner` act whose plan
/// does not decode. Every person's erase scans each pending act; at
/// f586cf806ad4 it failed on that one row, so no erase could finish. Now
/// the erase ends: an unreadable plan that named the erased person holds the
/// erased marker in their place, and one that named no one stays as stored.
#[test]
fn an_unreadable_plan_does_not_stop_a_hard_erase() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (vault, owner) = vault_and_owner(dir.path());
    let bystander = person(&vault);
    let candidate = person(&vault);
    share(&vault, owner, None);
    let owner_proof = proof(&vault, owner);
    let empty = vault
        .start_authority_act(&owner_proof, SHARED, "add_owner", b"{}".to_vec())
        .expect("the Owner stores an add_owner act with an empty plan");
    // The unknown field fails the plan's decode; the bytes still name the
    // candidate, in upper case.
    let unreadable = format!(
        r#"{{"v":1,"owner":"{}","note":1}}"#,
        candidate.to_hex().to_uppercase()
    );
    let naming = vault
        .start_authority_act(&owner_proof, SHARED, "add_owner", unreadable.into_bytes())
        .expect("the Owner stores an add_owner act with an unreadable plan");

    hard_erase(&vault, bystander);
    hard_erase(&vault, candidate);

    let payload = |act: &str| {
        vault
            .pending_authority_act(act)
            .expect("the read")
            .expect("the act stays as scaffold")
            .payload
    };
    assert_eq!(
        payload(empty.id.as_str()),
        b"{}",
        "the plan that named no one stays as stored"
    );
    assert_eq!(
        String::from_utf8(payload(naming.id.as_str())).expect("the plan's text"),
        r#"{"v":1,"owner":"erased","note":1}"#,
        "the unreadable plan holds the erased marker where it named the candidate"
    );
    assert_eq!(
        rows_naming(&vault, candidate).expect("rows"),
        Vec::<String>::new(),
        "no shared-act row holds the erased id"
    );
    assert_resolves_to_nothing(&vault, candidate);
}
