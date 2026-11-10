//! The Steward grant's rewrite of the Dreamer's policy rows holds on every
//! pack the policy decode accepts (review of #6913, untangle 6.3b). Once the
//! Dreamer holds its reach through a grant, each trusted pack is read with
//! the rows that name the Dreamer taken out and the grant's rows put back.
//!
//! Two packs broke that on the first head. A pack with a shorthand
//! source-trust row (`tool_output: false`) made the rewrite fail, so the
//! pack was read as written and its landing rows outlived a grant without
//! `derive`. A pack whose only actor ceiling was the Dreamer's lost its
//! required `actor_ceilings` entry, so the whole pack was dropped.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test steward_grant_policy_rewrite`.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::steward::{
    STEWARD_ARCHIVE_VERB, STEWARD_READ_VERB, STEWARD_VERBS, WeaveReach, dreamer,
    keep_only_the_dreamer_ceiling, stand_steward_grant, weave_reach,
    write_shorthand_tool_output_trust,
};

const READER: &str = "reader";

const READS_AND_LANDS: WeaveReach = WeaveReach {
    reads: true,
    lands_auto: true,
};
const READS_ONLY: WeaveReach = WeaveReach {
    reads: true,
    lands_auto: false,
};

#[test]
fn a_shorthand_source_trust_row_does_not_keep_the_written_landing_rows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    write_shorthand_tool_output_trust(&vault).expect("shorthand source trust");

    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("full grant");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_AND_LANDS,
        "the pack with the shorthand row is trusted and decodes"
    );

    stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])
        .expect("grant without derive");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_ONLY,
        "a grant without derive lands nothing, whatever rows the pack was written with"
    );
}

#[test]
fn taking_the_last_actor_ceiling_keeps_the_pack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_dreamer_vault(dir.path(), READER).expect("fixture vault");
    let dreamer = dreamer(&vault).expect("the Dreamer");
    keep_only_the_dreamer_ceiling(&vault).expect("one actor ceiling");

    stand_steward_grant(&vault, dreamer, &STEWARD_VERBS).expect("full grant");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_AND_LANDS,
        "the pack with one actor ceiling is trusted and decodes"
    );

    stand_steward_grant(&vault, dreamer, &[STEWARD_READ_VERB, STEWARD_ARCHIVE_VERB])
        .expect("grant without derive");
    assert_eq!(
        weave_reach(&vault).expect("reach"),
        READS_ONLY,
        "the pack still decodes with its ceiling list emptied: the read row is the pack's"
    );
}
