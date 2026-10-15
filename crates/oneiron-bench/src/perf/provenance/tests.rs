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

#[test]
fn mount_lookup_prefers_the_longest_matching_mount_point() {
    // Only meaningful where a mount table exists; elsewhere the cell is
    // explicitly not-ready, which is itself the contract.
    let dir = tempfile::tempdir().expect("tempdir");
    match mount_facts(dir.path()) {
        Some(facts) => {
            assert!(!facts.mount_point.is_empty());
            assert!(!facts.filesystem_type.is_empty());
            assert!(facts.measured_path.starts_with(facts.mount_point.as_str()));
        }
        None => assert!(
            std::fs::metadata("/proc/self/mounts").is_err(),
            "a readable mount table must resolve a mount for a temp dir"
        ),
    }
}

/// The cache stream that produced the reported hit rates must be
/// identifiable by CONTENT: two different streams under the same pathname
/// must not share a provenance block.
#[test]
fn cache_event_bytes_are_hashed_into_provenance() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build = |events: &str| {
        Provenance::collect(ProvenanceInputs {
            plan_hash: "plan".to_owned(),
            corpus_hash: "corpus".to_owned(),
            corpus_marker_evidence: marker_evidence(),
            corpus_query_evidence: query_evidence(),
            cache_events: events.to_owned(),
            seed: 1579,
            sample_counts: BTreeMap::new(),
            evidence_kind: EvidenceKind::SyntheticSmoke,
            plan_source: "same/path/plan.json".to_owned(),
            cache_source: "same/path/cache.jsonl".to_owned(),
            measured_path: dir.path().to_path_buf(),
            node: NodeIdentity::collect(),
        })
    };
    let left = build(r#"{"rung":"embedding","outcome":"hit","source":"real_traffic"}"#);
    let right = build(r#"{"rung":"embedding","outcome":"miss","source":"real_traffic"}"#);

    assert_eq!(left.plan_hash, right.plan_hash);
    assert_eq!(left.cache_source, right.cache_source);
    assert!(left.cache_events_hash.is_measured());
    assert_ne!(
        left.cache_events_hash, right.cache_events_hash,
        "editing the cache stream must change provenance even under one pathname"
    );
    assert_eq!(
        left.cache_events_bytes,
        r#"{"rung":"embedding","outcome":"hit","source":"real_traffic"}"#.len(),
        "the byte count must describe the stream that was actually hashed"
    );

    let empty = build("");
    assert!(
        !empty.cache_events_hash.is_measured(),
        "no admitted bytes means no cache input to identify, not a hash of nothing"
    );
}
