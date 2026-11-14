//! The engine ends every step of a seeded sequence where the reference model
//! does (F3.12 step 1; Fable's verdict 52, section 5 item 1).
//!
//! Each test draws eight seeded sequences of 40 steps from
//! `oneiron_testkit::model::generator`, applies each step to the reference
//! model and to a fresh vault, and checks three invariants after every step:
//! I1 counts conserve, I2 one live version per question, I3 no audience
//! widens. A failure names the seed, the step and the broken invariant;
//! `check_sequence` replays one seed.
//!
//! The universes keep the two defects this step must catch apart:
//! - MEMORY-01, an approved proposal left its former head standing (fixed by
//!   #6930): the settlement test has three persons, too few for a split;
//! - MEMORY-07, a split lost the claims a merged source brought (fixed by
//!   #6924): the topology test has no agents, so nothing is proposed;
//! - the third test draws from the whole mix.

use std::ops::Range;

use oneiron_testkit::model::Universe;
use oneiron_testkit::model::engine::{SeedReport, check_seeds};

const SEEDS: Range<u64> = 0..8;
const LENGTH: usize = 40;

/// Prints the report for the run log, then fails on any divergence.
fn assert_no_divergence(name: &str, report: &SeedReport) {
    let divergences = report.divergences.len();
    eprintln!(
        "## MODEL-SEQ {name} seeds {SEEDS:?} length {LENGTH} steps {:?} divergences {divergences}",
        report.steps
    );
    for divergence in &report.divergences {
        eprintln!("## MODEL-SEQ-DIVERGENCE {name} {divergence}");
    }
    assert!(
        report.divergences.is_empty(),
        "{divergences} of {} seeds diverged from the model:\n{}",
        SEEDS.end - SEEDS.start,
        report.divergences.join("\n")
    );
}

#[test]
fn an_approved_proposal_leaves_one_standing_head_in_every_seeded_sequence() {
    let universe = Universe {
        persons: 3,
        ..Universe::default()
    };
    let report = check_seeds(SEEDS, LENGTH, &universe);
    assert!(
        report.count("owner_approve") > 0,
        "the sequences approved no proposal: {:?}",
        report.steps
    );
    assert_no_divergence("settlement", &report);
}

#[test]
fn a_split_after_a_merge_keeps_every_claim_in_every_seeded_sequence() {
    // Ten persons: room for two merge-then-split shapes in one sequence.
    let universe = Universe {
        agents: 0,
        persons: 10,
        ..Universe::default()
    };
    let report = check_seeds(SEEDS, LENGTH, &universe);
    assert!(
        report.count("merge") > 0 && report.count("split") > 0,
        "the sequences merged or split nothing: {:?}",
        report.steps
    );
    assert_no_divergence("topology", &report);
}

#[test]
fn the_engine_matches_the_reference_model_in_every_seeded_sequence() {
    let report = check_seeds(SEEDS, LENGTH, &Universe::default());
    assert_no_divergence("mixed", &report);
}
