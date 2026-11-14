//! ROLES-CHECKIN P2.5, row 2k11 (ARCH-0082 #act-table "an agent's widen of
//! a world (C)" and #owner-own-acts; Engine ruling P25-SHAPE Q1 = A, 14 Nov
//! 13:39): the world settings door, `vault.worlds.privacy.set`, on the
//! world_widen row.
//!
//! - The vault Owner's own change of a world's settings is never gated: its
//!   receipt records the Owner's own-proof decision, at the settings door
//!   (`set_world_privacy_by`) and at the receipt-only door
//!   (`set_world_privacy_as`), and the change log keeps it.
//! - With `check_in_ref` the Owner applies another asker's approved
//!   check-in for that exact change on their own proof: it is spent in the
//!   change's writer, the receipt names the asker as requester, and it
//!   applies once. A check-in for another change (here the same settings
//!   from another revision seen) lands nothing and stays unspent.
//! - The door's input reads an old body, with no `check_in_ref`, as before.
//!
//! The ask is opened here through the check-in test doors on a chain whose
//! Owner rung is the vault owner, as in `check_in_policy_row_effects`.
//!
//! On the base (60020f2632f) this file does not build: `set_world_privacy_by`
//! takes no `check_in_ref`, the world privacy receipt has no `check_in`, and
//! the world privacy set effect digest does not exist.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_world_widen_effects`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/owner_apply_fixture.rs"]
mod owner_apply_fixture;

use oneiron::authority::{ActAuthority, ActSurface, SealedCopies, WorldPrivacy};
use oneiron::check_in::{ActClass, world_privacy_set_effect_digest};
use oneiron::consent::AuthenticatedOwner;
use oneiron::policy_model::{WorldPrivacyOutcome, WorldPrivacyReceipt, WorldPrivacySetInput};
use oneiron::{EntityId, Vault};

use owner_apply_fixture::{approved, owner_decision, rooted, spent};

const WORLD_SET: &str = "vault.worlds.privacy.set";
const ACT: ActClass = ActClass::WorldWiden;

/// A new world's settings with its sealed copies kept off the cloud: a
/// tighten of the default, so the default after it is a widen. The world
/// stays readable everywhere, so no key work is needed.
fn kept_off_cloud() -> WorldPrivacy {
    WorldPrivacy {
        sealed: SealedCopies::MyMachines,
        ..WorldPrivacy::default()
    }
}

/// A new world of the owner's, its sealed copies kept off the cloud by the
/// owner's own change at the receipt-only door: that change's receipt.
fn tightened_world(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
) -> (EntityId, WorldPrivacyReceipt) {
    let world = vault
        .create_world(owner_proof, "Kept world", vault.now_recorded_at())
        .expect("the owner's world");
    let receipt = vault
        .set_world_privacy_as(
            owner_proof,
            ActSurface::ThisInstall,
            world,
            kept_off_cloud(),
            None,
        )
        .expect("the owner tightens the world");
    (world, receipt)
}

/// The owner's change of `world` to `settings` from `seen` at the settings
/// door, applying `check_in_ref` when given.
fn set_by(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    world: EntityId,
    settings: WorldPrivacy,
    seen: Option<oneiron::authority::PolicyRevision>,
    check_in_ref: Option<EntityId>,
) -> oneiron::Result<WorldPrivacyOutcome> {
    vault.set_world_privacy_by(
        &ActAuthority::Owner(owner_proof.clone(), ActSurface::ThisInstall),
        world,
        settings,
        seen,
        check_in_ref,
    )
}

fn applied(outcome: WorldPrivacyOutcome) -> WorldPrivacyReceipt {
    match outcome {
        WorldPrivacyOutcome::Applied(receipt) => receipt,
        other => panic!("the owner's change applies at once: {other:?}"),
    }
}

#[test]
fn the_owners_world_settings_change_records_their_own_decision() {
    let (_dir, vault, _owner, owner_proof) = rooted();

    let (world, tightened) = tightened_world(&vault, &owner_proof);
    assert_eq!(
        tightened.check_in,
        Some(owner_decision(ACT, None, None)),
        "the receipt-only door records the Owner's own proof"
    );

    let widened = applied(
        set_by(
            &vault,
            &owner_proof,
            world,
            WorldPrivacy::default(),
            None,
            None,
        )
        .expect("the Owner widens the world"),
    );
    assert_eq!(
        widened.check_in,
        Some(owner_decision(ACT, None, None)),
        "the Owner's own widen goes on their own proof"
    );
    let log = vault.world_privacy_change_log().expect("the change log");
    let kept: Vec<_> = log
        .iter()
        .rev()
        .take(2)
        .map(|kept| (&kept.receipt_id, &kept.check_in))
        .collect();
    assert_eq!(
        kept,
        vec![
            (&widened.receipt_id, &widened.check_in),
            (&tightened.receipt_id, &tightened.check_in)
        ],
        "the change log keeps each decision"
    );
}

#[test]
fn the_owner_applies_an_approved_world_widen_once() {
    let (_dir, vault, owner, owner_proof) = rooted();
    let (world, _tightened) = tightened_world(&vault, &owner_proof);
    let widen = WorldPrivacy::default();
    let digest = world_privacy_set_effect_digest(&world, &widen, None);
    let (ask, asker) = approved(&vault, owner, &owner_proof, WORLD_SET, ACT, &digest);

    let changes = || {
        vault
            .world_privacy_change_log()
            .expect("the change log")
            .len()
    };
    let before = changes();
    let seen = vault.world_privacy_revision(world).expect("the revision");
    assert!(
        set_by(
            &vault,
            &owner_proof,
            world,
            widen.clone(),
            Some(seen),
            Some(ask)
        )
        .is_err(),
        "the ask names the change from no revision seen, not from this one"
    );
    assert!(
        !spent(&vault, &ask),
        "a refused change leaves the ask unspent"
    );
    assert_eq!(changes(), before, "the refused change landed nothing");

    let receipt = applied(
        set_by(&vault, &owner_proof, world, widen.clone(), None, Some(ask))
            .expect("the Owner applies the approved ask"),
    );
    assert_eq!(
        receipt.check_in,
        Some(owner_decision(ACT, Some(ask), Some(asker))),
        "the receipt names the ask it spent and its asker"
    );
    assert_eq!(
        vault.world_privacy(world).expect("the settings").sealed,
        SealedCopies::CloudAndMyMachines,
        "the asked widen landed"
    );
    assert!(spent(&vault, &ask), "the change spent the ask");

    assert!(
        set_by(&vault, &owner_proof, world, widen, None, Some(ask)).is_err(),
        "a spent ask applies once"
    );
    assert_eq!(changes(), before + 1, "the replay landed nothing");
}

#[test]
fn the_settings_input_reads_an_old_body_and_names_a_check_in() {
    let old: WorldPrivacySetInput = serde_json::from_value(serde_json::json!({
        "world": EntityId::now().to_hex(),
        "read": { "kind": "everywhere" },
        "sealed": "my_machines",
    }))
    .expect("a body with no check_in_ref reads");
    assert_eq!(old.check_in_ref().expect("no check-in"), None);

    let ask = EntityId::now();
    let named: WorldPrivacySetInput = serde_json::from_value(serde_json::json!({
        "world": EntityId::now().to_hex(),
        "read": { "kind": "everywhere" },
        "sealed": "my_machines",
        "check_in_ref": ask.to_hex(),
    }))
    .expect("a body naming a check-in reads");
    assert_eq!(named.check_in_ref().expect("a check-in id"), Some(ask));

    let malformed = WorldPrivacySetInput {
        check_in_ref: Some("not hex".to_owned()),
        ..named
    };
    assert!(
        malformed.check_in_ref().is_err(),
        "a check_in_ref that is no id is refused"
    );
}
