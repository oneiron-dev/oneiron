//! Every side table states a complete checkpoint row (fix list rows 22409-22423, 22346): a
//! payload family, a restore class and a storage tier that agree, so the payload preflight
//! holds no table out of the compartments and a capture logs no registry gap for one. A new
//! table that ships `[family: unregistered]`, or `[family: not_imaged]` on a canonical tier,
//! fails here.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::checkpoint_registry::side_table_registry_gaps;

#[test]
fn every_side_table_states_a_complete_checkpoint_row() {
    let gaps = side_table_registry_gaps();
    assert!(
        gaps.is_empty(),
        "{} side table registry gap(s):\n{}",
        gaps.len(),
        gaps.join("\n")
    );
}
