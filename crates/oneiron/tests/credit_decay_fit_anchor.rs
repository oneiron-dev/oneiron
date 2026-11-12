//! A matched ancestor check fits `credit_decay` whatever correctness anchor
//! credited its run (FIX-LIST CREDIT-DECAY-FIT-DROPS-OWNER-AND-WORLD-ANCHORS).
//! A contribution pair carries its credit's anchor: an owner verdict, a
//! world outcome, an audit or a held-out run. The fit records each matched
//! check on an adjacent used edge as a `learning.setting` check, which only
//! a fitting check, an audit or a held-out run feeds, so it records every
//! one as a fitting check, as the other two setting fitters do.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test credit_decay_fit_anchor`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::learning::Anchor;
use oneiron::learning_setting::{CREDIT_DECAY, global_setting_subject};
use oneiron::test_doors::credit_decay_fit::{
    credit_and_check_adjacent_edge, credit_decay_fit_runs,
};
use oneiron::{TimeRange, Vault, VaultConfig};
use serde_json::json;

const NOW: u64 = 10;

fn vault(dir: &std::path::Path) -> Vault {
    let vault = Vault::open(dir, VaultConfig::default()).expect("open vault");
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    // The fit's projected `learning.setting` head is a claim about the
    // knob's vault-wide ASSET (learning/project.rs). On main that head is
    // born in the ASSET's substrate facet, which no put stores, so the birth
    // gate refuses it InvalidFacet (#4389; #7205 gives it the vault default
    // facet), and the fit's capture drops the check with a WARN. The fixture
    // stores that facet, so the head lands on main and on #7205 alike; the
    // check's anchor is this file's subject, not the facet gate.
    let subject = global_setting_subject(CREDIT_DECAY.key).expect("the knob's subject");
    vault
        .put_entity(
            &oneiron::claim::substrate_facet_id(subject).expect("the subject's facet id"),
            oneiron::registry::ENTITY_TYPE_FACET,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
            &rmp_serde::to_vec_named(&json!({"name": "credit_decay fit facet"}))
                .expect("facet body"),
        )
        .expect("store the subject's facet");
    vault
}

/// Credits one run under `anchor`, records one matched check on the used
/// edge from its output (the ancestor helped: the fork with it passed, the
/// fork without it failed), and answers the fit's own runs after.
fn fit_runs_after_one_check(anchor: Anchor) -> Option<f64> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = vault(dir.path());
    assert_eq!(
        credit_decay_fit_runs(&vault).expect("read the fit"),
        None,
        "no check has fitted credit_decay yet"
    );
    credit_and_check_adjacent_edge(&vault, anchor, true, false, NOW).expect("credit and check");
    credit_decay_fit_runs(&vault).expect("read the fit")
}

#[test]
fn an_owner_verdicts_matched_ancestor_check_fits_credit_decay() {
    let runs = fit_runs_after_one_check(Anchor::OwnerVerdict)
        .expect("the check of a run the owner's verdict credited fits credit_decay");
    assert!(runs > 0.0, "one observation: {runs}");
}

#[test]
fn a_world_outcomes_matched_ancestor_check_fits_credit_decay() {
    let runs = fit_runs_after_one_check(Anchor::WorldOutcome)
        .expect("the check of a run a world outcome credited fits credit_decay");
    assert!(runs > 0.0, "one observation: {runs}");
}

#[test]
fn an_audited_runs_matched_ancestor_check_fits_credit_decay() {
    let runs = fit_runs_after_one_check(Anchor::Audit { rate: 0.5 })
        .expect("the check of a run an audit credited fits credit_decay");
    assert!(runs > 0.0, "one observation: {runs}");
}
