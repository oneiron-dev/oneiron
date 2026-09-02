//! ONE-1961 regressions over the run certificate: the scope partition, the
//! trust manifest, the statistics block, and the hash definitions the external
//! verifier has to reproduce byte for byte.

use super::super::report::AXES;
use super::*;

/// The exact JCS bytes for a fixture that exercises every formatting rule the
/// two implementations could disagree on: key sorting, an unsorted nested
/// object, array order preservation, escapes, non-ASCII, an integral number and
/// a fractional one.
///
/// This constant is the cross-language contract. If `serde_json_canonicalizer`
/// ever stops producing it, `rfc8785` on the verifying side stops agreeing, and
/// every hash in the certificate silently becomes unverifiable.
const FIXTURE_JCS: &str = concat!(
    r#"{"a":{"y":null,"z":true},"b":[3,1,2],"escaped":"line\nquote\"backslash\\","#,
    r#""float":1.5,"int":42,"schema":"oneiron.bench.perf_report.v2","unicode":"café ☕"}"#
);

/// The same document, written with its keys in a deliberately different order.
const FIXTURE_SOURCE: &str = concat!(
    r#"{"unicode":"café ☕","int":42,"float":1.5,"#,
    r#""escaped":"line\nquote\"backslash\\","b":[3,1,2],"#,
    r#""a":{"z":true,"y":null},"schema":"oneiron.bench.perf_report.v2"}"#
);

fn fixture() -> serde_json::Value {
    serde_json::from_str(FIXTURE_SOURCE).expect("the fixture parses")
}

/// The canonical form is fixed BYTES, not merely "some deterministic string".
/// Pinning them is what lets a Python verifier recompute the digests.
#[test]
fn the_canonical_form_is_exactly_the_pinned_fixture_bytes() {
    let bytes = canonical_bytes("the fixture", &fixture()).expect("the fixture canonicalizes");
    let rendered = String::from_utf8(bytes.clone()).expect("JCS output is UTF-8");
    assert_eq!(rendered, FIXTURE_JCS);

    // Sorted keys, no STRUCTURAL whitespace, ES6 numbers: the three properties
    // raw-byte hashing of the emitted document would not give us. Whitespace
    // inside a string value is content and survives untouched.
    assert!(!rendered.contains(": "), "{rendered}");
    assert!(!rendered.contains(", "), "{rendered}");
    assert!(rendered.contains("café ☕"), "string content is untouched");
    assert!(
        rendered.contains(r#""b":[3,1,2]"#),
        "arrays keep their order"
    );
    assert!(
        rendered.contains(r#""int":42"#),
        "an integral number is bare"
    );
    assert!(rendered.contains(r#""float":1.5"#));

    // And the digest over those bytes is what the certificate reports.
    let expected = blake3::hash(FIXTURE_JCS.as_bytes()).to_hex().to_string();
    assert_eq!(
        canonical_blake3("the fixture", &fixture()).expect("the fixture hashes"),
        expected
    );
    assert_eq!(blake3::hash(&bytes).to_hex().to_string(), expected);
}

/// Whoever built the document must not be able to change its hash. This is the
/// property that makes the certificate reproducible at all, and it is not free:
/// this workspace builds `serde_json` with `preserve_order`, so a `Value` DOES
/// remember the order it was written in.
#[test]
fn key_order_cannot_change_a_hash() {
    let written_one_way = fixture();
    let written_another: serde_json::Value =
        serde_json::from_str(FIXTURE_JCS).expect("the canonical form parses back");

    assert_ne!(
        serde_json::to_string(&written_one_way).expect("renders"),
        serde_json::to_string(&written_another).expect("renders"),
        "the fixture must actually differ in key order, or this test proves nothing"
    );
    assert_eq!(
        canonical_blake3("a", &written_one_way).expect("hashes"),
        canonical_blake3("b", &written_another).expect("hashes"),
    );

    // A real content change still moves the hash.
    let mut changed = fixture();
    changed["int"] = serde_json::json!(43);
    assert_ne!(
        canonical_blake3("a", &fixture()).expect("hashes"),
        canonical_blake3("c", &changed).expect("hashes"),
    );
}

/// Values that cannot survive the round trip are REFUSED, not hashed into a
/// digest the verifier will disagree with.
#[test]
fn unrepresentable_values_are_refused_rather_than_hashed() {
    // JSON has no NaN or Infinity, so the canonicalizer errors and the run
    // refuses to emit rather than shipping a hash over `null`.
    #[derive(serde::Serialize)]
    struct NonFinite {
        latency_ms: f64,
    }
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let error = canonical_blake3("an axis", &NonFinite { latency_ms: value })
            .expect_err("a non-finite float has no canonical form");
        assert!(error.contains("canonical form"), "{error}");
    }

    // Past 2^53, ES6 number formatting is lossy, so two conforming
    // canonicalizers legitimately disagree. Refuse instead.
    let too_large = serde_json::json!({ "seed": MAX_EXACT_JSON_INTEGER + 1 });
    let error =
        canonical_blake3("provenance", &too_large).expect_err("an integer past 2^53 is refused");
    assert!(error.contains("2^53"), "{error}");
    assert!(
        error.contains(".seed"),
        "the refusal names the field: {error}"
    );

    // The boundary itself is representable and is admitted.
    let at_boundary = serde_json::json!({ "seed": MAX_EXACT_JSON_INTEGER });
    canonical_blake3("provenance", &at_boundary).expect("2^53 exactly is representable");
}

/// The publication scope is an EXACTLY-ONE partition of the emitted axes: every
/// axis is decided about, and nothing is decided about twice.
#[test]
fn the_publication_scope_partitions_every_emitted_axis() {
    assert_eq!(scope_partition_error(), None);
    assert_eq!(BLOCKING_AXES.len() + ADVISORY_AXES.len(), AXES.len());

    for axis in AXES {
        let blocking = BLOCKING_AXES.contains(&axis);
        let advisory = ADVISORY_AXES.contains(&axis);
        assert!(
            blocking ^ advisory,
            "`{axis}` must be in exactly one half of the partition"
        );
    }
    assert_eq!(
        ADVISORY_AXES,
        ["cache"],
        "cache is the operator-declared axis"
    );
    for blocking in BLOCKING_AXES {
        assert!(
            !ADVISORY_AXES.contains(&blocking),
            "`{blocking}` cannot be both"
        );
    }
}

/// Every trust input reaches the manifest with its class, its concrete origin
/// and the checks that rest on it.
#[test]
fn the_trust_manifest_carries_every_declared_input() {
    let manifest = trust_manifest();
    assert_eq!(manifest.len(), trust::INPUTS.len());

    for row in &manifest {
        let spec = trust::input_spec(row.name).expect("a manifest row is a declared input");
        assert_eq!(row.class, spec.class);
        assert_eq!(row.source, spec.source);
        assert!(
            !row.consumed_by.is_empty(),
            "`{}` must name the checks that rest on it",
            row.name
        );
    }

    let cache = manifest
        .iter()
        .find(|row| row.name == "cache_events")
        .expect("the cache stream is a declared input");
    assert_eq!(cache.class, TrustInput::OperatorDeclared);
    assert_eq!(cache.consumed_by, vec!["cache_rungs_complete"]);

    let child = manifest
        .iter()
        .find(|row| row.name == "child_program_blake3")
        .expect("ONE-1963 declares the child program digest");
    assert_eq!(child.class, TrustInput::Measured);
    assert_eq!(
        child.consumed_by,
        vec!["child_program_matches_build_revision"]
    );

    let rendered = serde_json::to_string(&manifest).expect("the manifest renders");
    assert!(
        rendered.contains(r#""class":"operator_declared""#),
        "{rendered}"
    );
    assert!(
        rendered.contains(r#""class":"compile_declared""#),
        "{rendered}"
    );
    assert!(rendered.contains(r#""class":"measured""#), "{rendered}");
    assert!(rendered.contains(r#""class":"derived""#), "{rendered}");
}

/// The statistics block exposes every axis's sample size and says out loud that
/// each one ran once. A missing count is an error, never a reported zero.
#[test]
fn the_statistics_block_exposes_every_axis_and_refuses_a_missing_count() {
    let mut counts: std::collections::BTreeMap<String, usize> = AXIS_SAMPLE_SOURCES
        .iter()
        .enumerate()
        .map(|(index, (_, key))| ((*key).to_owned(), index + 1))
        .collect();

    let exposed = statistics(&counts).expect("a complete count set produces statistics");
    assert_eq!(exposed.per_axis.len(), AXES.len());
    assert_eq!(exposed.repeats, 1);
    assert_eq!(
        exposed.single_trial_axes,
        ["wake", "resident_memory", "precision", "recall_latency"]
    );
    for axis in AXES {
        let row = exposed
            .per_axis
            .get(axis)
            .unwrap_or_else(|| panic!("`{axis}` must carry statistics"));
        assert_eq!(row.repeats, 1, "no axis is repeated in this round");
    }
    assert_eq!(
        exposed.per_axis.get("wake").map(|row| row.samples),
        counts.get("wake_probes").copied()
    );

    // Every single-trial axis is an axis the report actually emits.
    for axis in exposed.single_trial_axes {
        assert!(AXES.contains(&axis), "`{axis}` is not an emitted axis");
    }

    counts.remove("wake_probes");
    let error = statistics(&counts).expect_err("a missing count fails closed");
    assert!(error.contains("wake_probes"), "{error}");
    assert!(error.contains("not zero samples"), "{error}");
}

/// `certificate_blake3` is the digest of the certificate WITHOUT that field,
/// recomputed here exactly the way the verifier will.
#[test]
fn the_certificate_digest_covers_the_body_including_its_statistics() {
    let body = CertificateBody {
        contract_version: PERF_CANDIDATE_CONTRACT_VERSION,
        publication_scope: PublicationScope {
            blocking_axes: BLOCKING_AXES,
            advisory_axes: ADVISORY_AXES,
            rule: SCOPE_RULE,
        },
        trust_rule: trust::TRUST_RULE,
        trust_inputs: trust_manifest(),
        child_program_blake3: Cell::measured("f00d".to_owned()),
        statistics: statistics(
            &AXIS_SAMPLE_SOURCES
                .iter()
                .map(|(_, key)| ((*key).to_owned(), 7))
                .collect(),
        )
        .expect("statistics"),
        axes_blake3: "a".repeat(64),
        provenance_blake3: "b".repeat(64),
        hash_rule: HASH_RULE,
    };
    let digest = canonical_blake3("the run certificate", &body).expect("the body hashes");
    let sealed = RunCertificate {
        body: body.clone(),
        certificate_blake3: digest.clone(),
    };

    // The verifier's recomputation: render, drop the self-referential field,
    // canonicalize, hash.
    let mut rendered = serde_json::to_value(&sealed).expect("the certificate renders");
    let object = rendered.as_object_mut().expect("certificate object");
    let reported = object
        .remove("certificate_blake3")
        .expect("the certificate reports its own digest");
    assert_eq!(reported, serde_json::Value::String(digest.clone()));
    assert_eq!(
        canonical_blake3("recomputed", &rendered).expect("recomputes"),
        digest,
        "the emitted digest must be reproducible from the emitted document"
    );

    // The statistics are INSIDE the covered payload, so a caveat cannot be
    // edited out of a certificate without breaking its digest.
    let mut tampered = body;
    tampered.statistics.repeats = 2;
    assert_ne!(
        canonical_blake3("tampered", &tampered).expect("hashes"),
        digest
    );

    // The flattened body and its digest are one object, not two.
    let flat = serde_json::to_value(&sealed).expect("renders");
    let object = flat.as_object().expect("certificate object");
    for expected in [
        "contract_version",
        "publication_scope",
        "trust_inputs",
        "child_program_blake3",
        "statistics",
        "axes_blake3",
        "provenance_blake3",
        "certificate_blake3",
    ] {
        assert!(
            object.contains_key(expected),
            "certificate is missing {expected}"
        );
    }
}
