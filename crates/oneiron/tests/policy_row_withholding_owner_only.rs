//! A policy holder who is not the vault's Owner cannot turn a stored
//! withholding row off (FIX row CHECK-IN-POLICY-ROW-HOLDER-NO-JUDGE; Engine
//! rulings 20 Nov 23:56 = A and 21 Nov 00:30 = B). A holder's change inside
//! its named powers is its own proof and lands at once, in either direction
//! (ARCH-0082:113, DEC-0005:58). A C act moves only by the Owner's own row
//! (ARCH-0082:243): on the owner-policy table that is the Remove, or the Edit
//! to an action other than Block, of a stored Block or Reword row. An add, and
//! an edit that makes a row Block, still land at once.
//!
//! The shipped grant rows give the `policy.change` verb to no role, so the
//! owner first lets the Admin role carry it through the hidden door
//! `oneiron::test_doors::consent_graduation_demotion::admit_policy_verb`,
//! built only under `--cfg oneiron_test_support`; every assertion is here.
//! Without that cfg this target is empty. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test policy_row_withholding_owner_only`.
#![cfg(oneiron_test_support)]

use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember};
use oneiron::policy_model::{PolicyRowAction, PolicyRowChange, PolicyRowScope};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consent_graduation_demotion as doors;
use oneiron::{EntityId, Error, Vault, VaultConfig};

const SHARED: u64 = 42;
/// The typed reason the row change refuses a non-Owner holder with.
const WITHHOLDING_OWNER_ONLY: &str = "check_in.policy_row:withholding_owner_only";
const ROW: &str = "Protect information";

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("the person's proof")
}

/// The vault's embedded owner and an Admin who has accepted a founding
/// invitation into shared vault [`SHARED`], and who holds the policy power
/// over the owner-policy rows: the owner's grant rows let the Admin role
/// carry the `policy.change` verb, and the owner mints the Admin a
/// `policy.change` standing grant over `owner_policy_rows`.
struct Roster {
    owner: AuthenticatedOwner,
    admin: AuthenticatedOwner,
}

fn roster(vault: &Vault) -> Roster {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    doors::admit_policy_verb(vault, &proof(vault, owner), &[Role::Admin])
        .expect("the owner lets an Admin carry the policy verb");
    let admin = EntityId::now();
    vault
        .put_entity(
            &admin,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
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
                    member_ref: admin,
                    role: Some(Role::Admin),
                },
            ],
            1,
        )
        .expect("a shared vault with an Admin");
    let own = proof(vault, admin);
    let invitation = vault
        .shared_invitations(&own, SHARED)
        .expect("the Admin's invitations")
        .into_iter()
        .find(|open| open.role == Role::Admin)
        .expect("the Admin's founding invitation");
    vault
        .accept_shared_invitation(&own, SHARED, &invitation.id)
        .expect("the Admin accepts");
    let power = GrantBound::action(
        ActorBound::new(admin.to_hex())
            .and_then(|bound| bound.with_actor_class("human"))
            .expect("the Admin's bound"),
        ActionClass::new("policy.change").expect("the policy class"),
        ActionEnvelope::new(["owner_policy_rows".to_owned()]).expect("the policy envelope"),
    )
    .expect("the policy grant bound");
    vault
        .create_standing_grant(&proof(vault, owner), power)
        .expect("the owner mints the Admin the policy power");
    Roster {
        owner: proof(vault, owner),
        admin: proof(vault, admin),
    }
}

fn scope() -> PolicyRowScope {
    PolicyRowScope::World("w1".into())
}

fn add(action: PolicyRowAction) -> PolicyRowChange {
    PolicyRowChange::Add {
        row_ref: ROW.into(),
        text: "Keep this private".into(),
        action,
        scope: scope(),
    }
}

fn edit(action: PolicyRowAction) -> PolicyRowChange {
    PolicyRowChange::Edit {
        row_ref: ROW.into(),
        text: "Keep this private".into(),
        action,
        scope: scope(),
    }
}

fn remove() -> PolicyRowChange {
    PolicyRowChange::Remove {
        row_ref: ROW.into(),
        scope: scope(),
    }
}

/// A fresh vault whose Owner has stored the row [`ROW`] with `action`.
fn stored(action: PolicyRowAction) -> (tempfile::TempDir, Vault, Roster) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = roster(&vault);
    vault
        .change_policy_row(&roster.owner, add(action), 10)
        .expect("FIXTURE: the Owner stores the row");
    assert_eq!(vault.policy_row_change_log().expect("log").len(), 1);
    (dir, vault, roster)
}

fn assert_refused(vault: &Vault, result: oneiron::Result<oneiron::policy_model::PolicyRowReceipt>) {
    match result {
        Err(Error::InvalidConfig(reason)) => assert_eq!(reason, WITHHOLDING_OWNER_ONLY),
        other => panic!("expected the withholding refusal, got {other:?}"),
    }
    assert_eq!(
        vault.policy_row_change_log().expect("log").len(),
        1,
        "a refused change writes no receipt"
    );
}

#[test]
fn an_admin_holder_adds_a_warn_row_at_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let roster = roster(&vault);
    vault
        .change_policy_row(&roster.admin, add(PolicyRowAction::Warn), 11)
        .expect("an Admin holder's add lands at once");
    assert_eq!(vault.policy_row_change_log().expect("log").len(), 1);
}

#[test]
fn an_admin_holder_cannot_remove_a_stored_block_row() {
    let (_dir, vault, roster) = stored(PolicyRowAction::Block);
    let result = vault.change_policy_row(&roster.admin, remove(), 11);
    assert_refused(&vault, result);
}

#[test]
fn an_admin_holder_cannot_edit_a_stored_reword_row_down_to_warn() {
    let (_dir, vault, roster) = stored(PolicyRowAction::Reword);
    let result = vault.change_policy_row(&roster.admin, edit(PolicyRowAction::Warn), 11);
    assert_refused(&vault, result);
}

#[test]
fn an_admin_holder_edits_a_stored_reword_row_up_to_block() {
    let (_dir, vault, roster) = stored(PolicyRowAction::Reword);
    vault
        .change_policy_row(&roster.admin, edit(PolicyRowAction::Block), 11)
        .expect("an edit that makes a row Block lands at once");
    assert_eq!(vault.policy_row_change_log().expect("log").len(), 2);
}

#[test]
fn the_owner_removes_the_stored_block_row() {
    let (_dir, vault, roster) = stored(PolicyRowAction::Block);
    vault
        .change_policy_row(&roster.owner, remove(), 11)
        .expect("the Owner's own row turns the withholding off");
    assert_eq!(vault.policy_row_change_log().expect("log").len(), 2);
}
