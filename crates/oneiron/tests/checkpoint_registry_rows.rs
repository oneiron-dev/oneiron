//! Every side table states a complete checkpoint row (fix list rows 22409-22423, 22346): a
//! payload family, a restore class and a storage tier that agree, so the payload preflight
//! holds no table out of the compartments and a capture logs no registry gap for one. A new
//! table that ships `[family: unregistered]`, or `[family: not_imaged]` on a canonical tier,
//! fails here.
#![cfg(oneiron_test_support)]

use oneiron::test_doors::checkpoint_registry::side_table_registry_gaps;

// FIX [PROVENANCE-BODY-OWNER-FAMILY-READ-BEFORE-LANDING]: the one known exception (Engine
// 14:3x, ASK CKPT-PROVENANCE-REFERENCES = B). Both tables name the owner's ProvenanceBody
// family, but the payload preflight lists them in REFERENCES, so they stay in the image.
// Remove this list in the PR that reclassifies them.
const KNOWN_REFERENCES_GAPS: [&str; 2] = ["PROVENANCE_BODY", "PROVENANCE_BODY_DIGEST"];
const REFERENCES_GAP_TEXT: &str =
    "an owner's, but a restore reads references from it before any compartment lands";

fn is_known_references_gap(gap: &str, table: &str) -> bool {
    gap.starts_with(&format!("family {table} (")) && gap.contains(REFERENCES_GAP_TEXT)
}

#[test]
fn every_side_table_states_a_complete_checkpoint_row() {
    let gaps = side_table_registry_gaps();
    let unexpected: Vec<&String> = gaps
        .iter()
        .filter(|gap| {
            !KNOWN_REFERENCES_GAPS
                .iter()
                .any(|table| is_known_references_gap(gap, table))
        })
        .collect();
    assert!(
        unexpected.is_empty(),
        "{} side table registry gap(s) beyond the known exception:\n{}",
        unexpected.len(),
        unexpected
            .iter()
            .map(|gap| gap.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    );
    for table in KNOWN_REFERENCES_GAPS {
        assert!(
            gaps.iter().any(|gap| is_known_references_gap(gap, table)),
            "{table} no longer reports its references gap: remove it from \
             KNOWN_REFERENCES_GAPS (FIX [PROVENANCE-BODY-OWNER-FAMILY-READ-BEFORE-LANDING])"
        );
    }
}
