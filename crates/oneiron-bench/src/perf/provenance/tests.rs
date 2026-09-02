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
fn target_triple_names_the_build_target() {
    let triple = target_triple();
    assert!(triple.starts_with(std::env::consts::ARCH), "{triple}");
    assert!(triple.contains(std::env::consts::OS), "{triple}");
    assert!(triple.split('-').count() >= 3, "{triple}");
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

#[test]
fn mount_fields_are_unescaped() {
    assert_eq!(unescape_mount_field("/mnt/my\\040disk"), "/mnt/my disk");
    assert_eq!(unescape_mount_field("/dev/nvme0n1p2"), "/dev/nvme0n1p2");
}

/// Node identity is captured for every run, and a host that did not
/// declare the designated node is NOT the designated node.
#[test]
fn node_identity_is_captured_and_designation_is_declared_not_assumed() {
    let identity = NodeIdentity::collect();
    assert_eq!(identity.designated_first_tokyo_node, "tokyo-1");
    assert_eq!(identity.designated_location, "tokyo");
    assert_eq!(identity.declared_node_source, NODE_ENV);
    assert_eq!(identity.declared_location_source, NODE_LOCATION_ENV);
    assert_eq!(
        identity.observed_identity_allowlist_source,
        TOKYO_NODE_ALLOWLIST_ENV
    );
    if identity.declared_node.value().map(String::as_str) != Some(DESIGNATED_FIRST_TOKYO_NODE) {
        assert!(
            !identity.is_designated_first_tokyo_node,
            "a host that did not declare the designated node cannot be it"
        );
        let detail = identity.publication_detail();
        assert!(detail.contains(NODE_ENV), "{detail}");
        assert!(detail.contains(DESIGNATED_FIRST_TOKYO_NODE), "{detail}");
    }
    let rendered = serde_json::to_string(&identity).expect("identity renders");
    assert!(
        rendered.contains("is_designated_first_tokyo_node"),
        "{rendered}"
    );
}

/// Designation must bind to the host identity this process OBSERVED, on an
/// allowlist compiled into the artifact. A free-form runtime claim is the
/// operator's assertion, not evidence: any host can export
/// `ONEIRON_BENCH_NODE=tokyo-1`, so a non-allowlisted host must stay
/// undesignated — and therefore unpublishable — however it labels itself.
#[test]
fn tokyo_designation_binds_to_an_allowlisted_observed_host_identity() {
    const ALLOWLIST: &str = "# the first Tokyo node\n\
         tokyo-1.oneiron.internal / 8f14e45fceea167a5a36dedd4bea2543\n\
         tokyo-1b.oneiron.internal/0cc175b9c0f1b6a831c399e269772661,\n\
         , malformed-without-machine-id, /only-a-machine-id, host-only/";
    let entries = allowlist_entries(Some(ALLOWLIST));
    assert_eq!(
        entries.len(),
        2,
        "comments, blanks and half-entries are dropped, never half-matched: {entries:?}"
    );
    assert!(entries.contains(&(
        "tokyo-1.oneiron.internal".to_owned(),
        "8f14e45fceea167a5a36dedd4bea2543".to_owned()
    )));
    assert!(allowlist_entries(None).is_empty());

    let host = || Some("tokyo-1.oneiron.internal".to_owned());
    let machine = || Some("8f14e45fceea167a5a36dedd4bea2543".to_owned());

    let listed = NodeIdentity::resolve(host(), machine(), Some(ALLOWLIST));
    assert!(
        listed.observed_identity_allowlisted,
        "the observed pair is on the artifact's allowlist"
    );
    assert_eq!(listed.observed_identity_allowlist_entries, 2);

    // Every way of NOT being the allowlisted host.
    for (label, hostname, machine_id, list) in [
        (
            "an impostor host",
            Some("laptop".to_owned()),
            machine(),
            Some(ALLOWLIST),
        ),
        (
            "a reused machine id",
            host(),
            Some("deadbeef".to_owned()),
            Some(ALLOWLIST),
        ),
        ("no readable hostname", None, machine(), Some(ALLOWLIST)),
        ("no readable machine id", host(), None, Some(ALLOWLIST)),
        ("an artifact with no allowlist", host(), machine(), None),
        (
            "an empty allowlist",
            host(),
            machine(),
            Some("  \n# nothing\n"),
        ),
    ] {
        let identity = NodeIdentity::resolve(hostname, machine_id, list);
        assert!(
            !identity.observed_identity_allowlisted,
            "{label} must not match the allowlist"
        );
        assert!(
            !identity.is_designated_first_tokyo_node,
            "{label} cannot be the designated first Tokyo node, whatever it declares"
        );
        let detail = identity.publication_detail();
        assert!(
            detail.contains(TOKYO_NODE_ALLOWLIST_ENV),
            "{label}: {detail}"
        );
        assert!(detail.contains("allowlisted=false"), "{label}: {detail}");
    }

    // The allowlist is necessary but not sufficient on its own: the
    // operator's declaration is still required, and the environment of
    // this test process decides which side of that we can observe.
    let declares_designated = declared(NODE_ENV).as_deref() == Some(DESIGNATED_FIRST_TOKYO_NODE)
        && declared(NODE_LOCATION_ENV).as_deref() == Some(DESIGNATED_NODE_LOCATION);
    assert_eq!(
        listed.is_designated_first_tokyo_node, declares_designated,
        "designation is allowlisted identity AND the declared node/location"
    );
    if !declares_designated {
        let detail = listed.publication_detail();
        assert!(detail.contains(NODE_ENV), "{detail}");
    }
}

/// Every report carries an immutable build revision even when no build-time
/// Git SHA was embedded. The mutable source-checkout HEAD is separate and
/// may never be the only artifact identity.
#[test]
fn provenance_identifies_the_running_build_independently_of_checkout_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provenance = Provenance::collect(ProvenanceInputs {
        plan_hash: "plan".to_owned(),
        corpus_hash: "corpus".to_owned(),
        corpus_marker_evidence: marker_evidence(),
        corpus_query_evidence: query_evidence(),
        cache_events: "event".to_owned(),
        seed: 1579,
        sample_counts: BTreeMap::new(),
        evidence_kind: EvidenceKind::SyntheticSmoke,
        plan_source: "fixture".to_owned(),
        cache_source: "fixture".to_owned(),
        measured_path: dir.path().to_path_buf(),
        node: NodeIdentity::collect(),
    });
    let digest = provenance
        .build_revision_blake3
        .value()
        .expect("the running test artifact hashes");
    assert_eq!(digest.len(), 64);
    assert!(provenance.build_revision_source.contains("BLAKE3"));
    assert!(
        provenance
            .source_checkout_git_sha_source
            .contains("build_manifest_dir")
            || !provenance.source_checkout_git_sha.is_measured()
    );

    // The artifact's own compile-time attribution rides beside the digest:
    // whether its sources were committed, and which profile built it. Both
    // are fail-closed cells, never assumptions, and neither is re-derived
    // from whatever checkout sits under the manifest path at report time.
    assert!(
        provenance
            .build_tree_dirty_source
            .contains("ONEIRON_BENCH_BUILD_GIT_DIRTY"),
        "{}",
        provenance.build_tree_dirty_source
    );
    assert_eq!(
        provenance.build_profile.debug_assertions,
        cfg!(debug_assertions)
    );
    let rendered = serde_json::to_string(&provenance).expect("provenance renders");
    for field in [
        "build_tree_dirty",
        "build_tree_dirty_source",
        "build_profile",
        "approved_for_publication",
    ] {
        assert!(rendered.contains(field), "provenance dropped `{field}`");
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
