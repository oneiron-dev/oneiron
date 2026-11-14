//! Two gaps #7834's ramp erase left (Engine TASK, Sun 15 Nov 08:32 JST):
//!
//! - RAMP-FLOOR-ORPHAN-ERASE: a streak floor dialed on a scope that has no
//!   stats, outcome, demotion or answer row goes when the scope's actor is
//!   hard-erased. Its key is a digest of the scope, and a digest of a person's
//!   id still links to that person, so the row and its key go; a floor another
//!   actor's scope holds stays.
//! - RAMP-SCOPE-ERASED-TOKEN-LIVE: a scope whose actor is
//!   `ERASED_CALL_IDENTITY` is refused, at `RampScope::new`, at
//!   `RampScope::validate`, and at the writer doors, before any row is
//!   written. The erase writes that token into the rows it keeps as acts, and
//!   the fold reads none of them, so a live scope keyed by it would be lost at
//!   the next rebuild.
//!
//! The ramp tables are read raw through the hidden door
//! `oneiron::test_doors::consent_graduation_ramp_rows`, built only under
//! `--cfg oneiron_test_support`; every assertion is here. Without that cfg
//! this target is empty. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test -p oneiron
//! --all-features --test ramp_floor_actor_erase`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::consent_graduation::RampScope;
use oneiron::error::GateError;
use oneiron::identity_topology::ProposalOutcome;
use oneiron::receipt::ERASED_CALL_IDENTITY;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consent_graduation_ramp_rows::{RampTableRows, ramp_rows_spelling};
use oneiron::{DeleteReason, EntityId, Error, Vault, VaultConfig};

const OP_KIND: &str = "send_email";
const TARGET_CLASS: &str = "client_followup";

/// The owner's proof on a fresh vault.
fn owner(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof")
}

/// A live PERSON the hard erase accepts.
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
        .expect("FIXTURE: a live person");
    id
}

/// Every ramp table, its row count, and how many of its rows spell `text`.
fn ramp_tables(vault: &Vault, text: &str) -> Vec<RampTableRows> {
    ramp_rows_spelling(vault, text).expect("ramp table read")
}

/// Each ramp table that holds a row, and how many it holds.
fn tables_with_rows(vault: &Vault) -> Vec<(&'static str, usize)> {
    ramp_tables(vault, "")
        .into_iter()
        .filter(|counted| counted.rows > 0)
        .map(|counted| (counted.table, counted.rows))
        .collect()
}

#[test]
fn a_hard_erase_removes_a_floor_dialed_on_a_scope_with_no_other_row() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    let actor = person(&vault);
    let hex = actor.to_hex();
    let scope = RampScope::new(OP_KIND, TARGET_CLASS, hex.clone()).expect("FIXTURE: the scope");
    // Another actor's scope with its own floor: the erase leaves it.
    let other = RampScope::new(OP_KIND, TARGET_CLASS, EntityId::now().to_hex())
        .expect("FIXTURE: another actor's scope");
    // A scope of the same op and class that no override names: the streak an
    // erased scope falls back to once its floor is gone.
    let untouched = RampScope::new(OP_KIND, TARGET_CLASS, EntityId::now().to_hex())
        .expect("FIXTURE: an untouched scope");
    let default_floor = vault.ramp_streak_floor(&untouched).expect("floor read");

    vault
        .set_ramp_streak_floor(&scope, 3)
        .expect("FIXTURE: the floor dialed on the actor's scope");
    vault
        .set_ramp_streak_floor(&other, 4)
        .expect("FIXTURE: the floor dialed on the other scope");
    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor read"),
        3,
        "FIXTURE: the actor's floor is in force"
    );
    assert_ne!(
        default_floor, 3,
        "FIXTURE: the floor differs from the default"
    );
    assert_eq!(
        tables_with_rows(&vault),
        vec![("ramp_floor", 2)],
        "FIXTURE: the two floors are the only ramp rows; no other row spells the actor's scope"
    );

    // Every delete signs as this install first.
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .delete_entity_with_reason(&actor, DeleteReason::UserHardDelete)
        .expect("FIXTURE: the scope's actor is hard-erased");

    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor read"),
        default_floor,
        "the floor dialed on the erased actor's scope is gone"
    );
    assert_eq!(
        tables_with_rows(&vault),
        vec![("ramp_floor", 1)],
        "the floor table keeps only the other actor's row: the erased scope's digest key went too"
    );
    assert_eq!(
        vault.ramp_streak_floor(&other).expect("floor read"),
        4,
        "the other actor's floor stays"
    );
    assert!(
        ramp_tables(&vault, &hex)
            .iter()
            .all(|counted| counted.spelling == 0),
        "no ramp row spells the erased actor's id"
    );
}

#[test]
fn a_scope_whose_actor_is_the_erased_token_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner = owner(&vault);
    let refused = |result: oneiron::Result<()>| {
        matches!(
            result,
            Err(Error::Gate(GateError::InvalidConsentBound(
                "ramp scope actor"
            )))
        )
    };

    assert!(
        refused(RampScope::new(OP_KIND, TARGET_CLASS, ERASED_CALL_IDENTITY).map(|_| ())),
        "RampScope::new refuses the erased token as a scope's actor"
    );
    // The fields are public, so a caller can assemble the tuple by hand.
    let erased = RampScope {
        op_kind: OP_KIND.to_owned(),
        target_class: TARGET_CLASS.to_owned(),
        actor: ERASED_CALL_IDENTITY.to_owned(),
    };
    assert!(
        refused(erased.validate()),
        "RampScope::validate refuses the erased token as a scope's actor"
    );
    assert!(
        refused(vault.set_ramp_streak_floor(&erased, 3)),
        "the floor door refuses a scope keyed by the erased token"
    );
    assert!(
        refused(
            vault
                .record_proposal_outcome_for_ramp(
                    &owner,
                    &erased,
                    ProposalOutcome::ApprovedUntouched
                )
                .map(|_| ())
        ),
        "the outcome door refuses a scope keyed by the erased token"
    );
    assert_eq!(
        tables_with_rows(&vault),
        Vec::new(),
        "no ramp row was written"
    );
}
