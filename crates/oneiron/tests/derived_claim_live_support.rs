//! A derived claim's typed TURN citations ride its write-envelope stamp, in
//! the writer's `candidate_evidence` (FIX
//! LIVE-SUPPORT-RULE-MISSES-CANDIDATE-EVIDENCE). The read-time live-support
//! test reads them there: a derived claim whose every cited TURN is deleted
//! has no live support, and one live cited TURN keeps it readable. The claim
//! itself stays stored.
//!
//! The vault loads this install's signing keys from a device keystore, as a
//! host's does: a delete signs its receipt with them, and the Dreamer's door
//! installs no keystore (FIX LIVE-SUPPORT-TEST-DELETE-NO-KEYSTORE: without
//! one, both tests stopped at the delete, red and green alike).
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test derived_claim_live_support`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::temporal::TimeRange;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::derive::{Claim, Named, claim_has_live_support, commit_claims};
use oneiron::test_doors::steward::dreamer;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const READER: &str = "reader";

/// The Dreamer's vault with this install's signing keys loaded, so a delete
/// can sign its receipt.
fn open_vault(dir: &tempfile::TempDir) -> Vault {
    let vault = open_dreamer_vault(dir.path(), READER).expect("vault");
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault
        .prepare_install_signing()
        .expect("load this install's signing keys");
    vault
}

fn put(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    let at = vault.now_recorded_at();
    vault
        .put_entity(&id, entity_type, TimeRange { start: at, end: at }, at, body)
        .expect("a row");
    id
}

fn turn(vault: &Vault) -> EntityId {
    let body = rmp_serde::to_vec_named(&std::collections::BTreeMap::from([("role", "user")]))
        .expect("a TURN body");
    put(vault, ENTITY_TYPE_TURN, &body)
}

/// The Dreamer's derivation lands one claim about a fresh person citing
/// `turns`, and returns its id.
fn derived_claim(vault: &Vault, turns: &[EntityId]) -> EntityId {
    let dreamer = dreamer(vault).expect("the Dreamer");
    let person = put(vault, ENTITY_TYPE_PERSON, b"someone");
    let committed = commit_claims(
        vault,
        dreamer,
        EdgeActorClass::System,
        "run-1",
        &[Claim {
            local: "coffee",
            predicate: "preference.coffee",
            subject: Named::Stored(person),
            value: json!("an oat milk flat white"),
            evidence: turns.iter().copied().map(Named::Stored).collect(),
        }],
    )
    .expect("the batch commits");
    let [item] = committed.items.as_slice() else {
        panic!("one item: {:?}", committed.items);
    };
    assert!(item.landed, "the derived claim lands: {item:?}");
    let [claim] = item.rows.as_slice() else {
        panic!("one row: {item:?}");
    };
    *claim
}

#[test]
fn a_derived_claim_whose_every_cited_turn_is_deleted_has_no_live_support() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let cited = turn(&vault);
    let claim = derived_claim(&vault, &[cited]);
    assert_eq!(
        claim_has_live_support(&vault, &claim).expect("read"),
        Some(true),
        "a claim whose cited TURN is live is readable"
    );

    assert!(
        vault.delete_entity(&cited).expect("delete"),
        "the TURN existed"
    );

    assert_eq!(
        claim_has_live_support(&vault, &claim).expect("read"),
        Some(false),
        "FAILBEFORE LIVE-SUPPORT-RULE-MISSES-CANDIDATE-EVIDENCE: a derived claim whose every \
         cited TURN is deleted has no live support"
    );
    assert!(
        vault.get_claim(&claim).expect("read").is_some(),
        "the claim stays in history"
    );
}

#[test]
fn one_live_cited_turn_keeps_a_derived_claim_readable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_vault(&dir);
    let deleted = turn(&vault);
    let kept = turn(&vault);
    let claim = derived_claim(&vault, &[deleted, kept]);

    assert!(
        vault.delete_entity(&deleted).expect("delete"),
        "the TURN existed"
    );

    assert_eq!(
        claim_has_live_support(&vault, &claim).expect("read"),
        Some(true),
        "one live cited TURN keeps the claim readable"
    );
}
