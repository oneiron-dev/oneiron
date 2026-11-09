//! Regressions for ONE-1579 run provenance.
//!
//! Split out of `provenance.rs` so the module itself stays well under the
//! repository's giant-file bar; nothing here is reachable outside `cfg(test)`.

use super::*;

fn query_evidence() -> CorpusQueryEvidence {
    CorpusQueryEvidence {
        indexed_docs: 1,
        requested_queries: 1,
        emitted_queries: 1,
        distinct_anchors: 1,
        distinct_expected_documents: 1,
        anchors_distinct: true,
        rule: "test query-anchor evidence",
    }
}

fn marker_evidence() -> CorpusMarkerEvidence {
    CorpusMarkerEvidence {
        documents: 1,
        unique_markers: 1,
        collision_free: true,
        marker_prefix: "qzmk",
        base26_digits: 2 * std::mem::size_of::<usize>(),
        capacity_covers_full_usize_domain: true,
        rule: "test marker evidence",
    }
}

