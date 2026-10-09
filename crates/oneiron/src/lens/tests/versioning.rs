//! Envelope-versioning and behavior-fingerprint tests: version stamps, canonical
//! fingerprints, and diffs.

use super::*;
use crate::Result;
use serde_json::json;

// ── ONE-1431 version pair, behavior fingerprint, and structured diff ─────────

#[test]
fn generated_lens_stamps_version_pair() -> Result<()> {
    assert_eq!(
        LensVersionStamp::current(),
        LensVersionStamp::new(LENS_ATOM_KIT_VERSION, LENS_APPS_CONTRACT_VERSION),
        "the live pair is the two running constants"
    );

    let v2 = GeneratedLens::new(v2_only_root())?;
    assert_eq!(
        v2.apps_contract_version(),
        LENS_APPS_CONTRACT_VERSION,
        "the apps-contract component records the shell contracts, so it is always live"
    );
    assert_eq!(
        v2.kit_version(),
        LENS_ATOM_KIT_VERSION,
        "the atom-kit component is the running constant, not this tree's contained minimum"
    );
    assert_eq!(
        v2.version_stamp(),
        LensVersionStamp::current(),
        "the constructor stamps the live pair, so its output is never born stale"
    );

    let v3 = GeneratedLens::new(standalone_result_set_root())?;
    assert_eq!(v3.kit_version(), LENS_ATOM_KIT_VERSION);
    assert_eq!(
        v3.version_stamp(),
        LensVersionStamp::current(),
        "a tree that needs the live kit stamps the live pair"
    );

    // Both stamp fields are body data, serialized in order before the tree.
    let encoded = serde_json::to_string(&v2).expect("lens serializes");
    let kit = encoded
        .find("\"kit_version\"")
        .expect("kit_version is on the wire");
    let apps = encoded
        .find("\"apps_contract_version\"")
        .expect("apps_contract_version is on the wire");
    let root = encoded.find("\"root\"").expect("root is on the wire");
    assert!(
        kit < apps && apps < root,
        "the wire order is kit_version, apps_contract_version, root: {encoded}"
    );

    Ok(())
}

#[test]
fn generated_lens_requires_both_version_fields_before_root() {
    let node = serde_json::to_value(v2_only_root()).expect("node encodes");

    // Either stamp field may come first as long as both precede the root.
    for envelope in [
        json!({
            "kit_version": 2,
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "root": &node,
        }),
        json!({
            "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
            "kit_version": 2,
            "root": &node,
        }),
    ] {
        assert!(
            serde_json::from_value::<GeneratedLens>(envelope).is_ok(),
            "either stamp order decodes when both precede root"
        );
    }

    // Missing either field is invalid; neither is defaulted or inferred.
    let missing_kit = serde_json::from_value::<GeneratedLens>(json!({
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
        "root": &node,
    }))
    .expect_err("kit_version is mandatory");
    assert!(
        missing_kit.to_string().contains("kit_version"),
        "{missing_kit}"
    );

    // Post-map check (b) — the missing apps field — is selected before check (c), the
    // root-precedence rule, even though this body also puts root before the pair.
    let missing_apps = serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": 2,
        "root": &node,
    }))
    .expect_err("apps_contract_version is mandatory");
    assert!(
        missing_apps.to_string().contains("apps_contract_version"),
        "the missing-field error wins over the precedence error: {missing_apps}"
    );

    // Both fields present but the root arrives before the pair completes: the body is
    // consumed as IgnoredAny, so the tree is never allocated.
    let root_in_the_middle = serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": 2,
        "root": &node,
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
    }))
    .expect_err("root must not precede the complete pair");
    assert!(
        root_in_the_middle
            .to_string()
            .contains("generated lens version fields must precede root"),
        "{root_in_the_middle}"
    );

    let missing_root = serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": 2,
        "apps_contract_version": LENS_APPS_CONTRACT_VERSION,
    }))
    .expect_err("root is mandatory");
    assert!(missing_root.to_string().contains("root"), "{missing_root}");
}
