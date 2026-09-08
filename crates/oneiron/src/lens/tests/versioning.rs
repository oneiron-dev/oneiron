//! Envelope-versioning and behavior-fingerprint tests: version stamps, canonical
//! fingerprints, and diffs.

use super::*;
use crate::{Error, Result};
use serde_json::json;
use std::collections::BTreeSet;

// ── ONE-1431 version pair, behavior fingerprint, and structured diff ─────────

fn throbber_node(name: &str) -> LensNode {
    LensNode::with_fallback_text(
        id(name),
        LensAtom::Throbber(ThrobberAtom { label: text(name) }),
        text(name),
    )
}

fn stamped_envelope(kit_version: u16, apps_contract_version: u16) -> Result<GeneratedLens> {
    serde_json::from_value::<GeneratedLens>(json!({
        "kit_version": kit_version,
        "apps_contract_version": apps_contract_version,
        "root": serde_json::to_value(v2_only_root()).expect("node encodes"),
    }))
    .map_err(|error| Error::InvalidConfig(error.to_string()))
}

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

#[test]
fn stale_but_decodable_lens_queues_regeneration() -> Result<()> {
    // Older on the apps-contract side, and newer than the running atom-kit constant:
    // "differs" is symmetric and both directions stay decodable.
    for stored in [
        LensVersionStamp::new(2, 0),
        LensVersionStamp::new(LENS_ATOM_KIT_VERSION + 1, LENS_APPS_CONTRACT_VERSION),
    ] {
        let decoded = stamped_envelope(stored.kit_version(), stored.apps_contract_version())?;
        assert_eq!(
            decoded.version_stamp(),
            stored,
            "the pair survives decoding"
        );
        assert_eq!(
            lens_load_action(decoded.version_stamp(), LensVersionStamp::current()),
            LensLoadAction::MountLastGoodAndQueueRegeneration {
                stored,
                live: LensVersionStamp::current(),
            },
            "a decodable stale body mounts as last-good and queues regeneration"
        );

        // A card wrapping that body reports the same decision to a shell loader.
        let card = GeneratedUiCard::new(render_id("card-1"), decoded)?;
        assert_eq!(
            card.load_action(),
            LensLoadAction::MountLastGoodAndQueueRegeneration {
                stored,
                live: LensVersionStamp::current(),
            },
            "a stale card cannot render without surfacing the regeneration decision"
        );
    }

    Ok(())
}

#[test]
fn matched_version_pair_mounts_current() -> Result<()> {
    let live = LensVersionStamp::current();
    assert_eq!(lens_load_action(live, live), LensLoadAction::MountCurrent);

    let body = stamped_envelope(LENS_ATOM_KIT_VERSION, LENS_APPS_CONTRACT_VERSION)?;
    assert_eq!(body.version_stamp(), live);
    let card = GeneratedUiCard::new(render_id("card-1"), body)?;
    assert_eq!(card.load_action(), LensLoadAction::MountCurrent);

    // The public constructor mints the other live body, and it must agree with the
    // decoded one: a freshly built pre-v3 tree mounts current instead of queueing a
    // regeneration it does not owe (and that regeneration could never satisfy, since
    // `regenerate_lens` only accepts a candidate stamped with the live target).
    let constructed = GeneratedLens::new(v2_only_root())?;
    assert_eq!(
        lens_load_action(constructed.version_stamp(), live),
        LensLoadAction::MountCurrent,
        "GeneratedLens::new output is current by construction"
    );
    let constructed_card = GeneratedUiCard::new(render_id("card-2"), constructed)?;
    assert_eq!(constructed_card.load_action(), LensLoadAction::MountCurrent);

    Ok(())
}

#[test]
fn fingerprint_is_canonical_across_input_and_binding_order() -> Result<()> {
    let mut first = card_root(vec![
        throbber_node("one"),
        LensNode::with_fallback_text(
            id("two"),
            LensAtom::MetaLine(MetaLineAtom {
                label: text("two"),
                value: text("two"),
            }),
            text("two"),
        ),
    ]);
    first.bindings = vec![
        binding("claims", LensHandleRole::ClaimSet),
        binding("people", LensHandleRole::EntitySet),
    ];

    // The same pairs, reversed and repeated: authority is a set, not a list.
    let mut second = first.clone();
    second.bindings = vec![
        binding("people", LensHandleRole::EntitySet),
        binding("claims", LensHandleRole::ClaimSet),
        binding("people", LensHandleRole::EntitySet),
    ];

    let first_lens = GeneratedLens::new(first.clone())?;
    let second_lens = GeneratedLens::new(second)?;

    let one = LensBehaviorFingerprint::from_golden_renders([
        ("alpha", &first_lens),
        ("beta", &second_lens),
    ])?;
    let two = LensBehaviorFingerprint::from_golden_renders([
        ("beta", &second_lens),
        ("alpha", &first_lens),
    ])?;
    assert_eq!(one, two, "input iteration order is not behavior");
    assert!(LensBehaviorDiff::between(&one, &two)?.is_identical());

    // Child order, however, is behavior: the ordered atom-kind shape changes.
    let mut reordered = first;
    reordered.children.reverse();
    let reordered_lens = GeneratedLens::new(reordered)?;
    let three = LensBehaviorFingerprint::from_golden_renders([
        ("alpha", &reordered_lens),
        ("beta", &second_lens),
    ])?;
    let diff = LensBehaviorDiff::between(&one, &three)?;
    assert_eq!(
        diff.structural_cases()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["alpha"],
        "only the reordered case is structural"
    );
    assert!(
        diff.inventory_changes().is_empty(),
        "reordering moves no atom counts"
    );
    assert!(
        !diff.has_data_read_change(),
        "reordering changes no bound data read"
    );

    Ok(())
}

#[test]
fn fingerprint_includes_answer_sheet_citation_bindings() -> Result<()> {
    let sheet = |role| {
        card_root(vec![LensNode::with_fallback_text(
            id("answer"),
            LensAtom::AnswerSheet(AnswerSheetAtom {
                question: text("who"),
                answer: text("them"),
                citations: vec![binding("cited", role)],
            }),
            text("answer"),
        )])
    };

    let before_lens = GeneratedLens::new(sheet(LensHandleRole::ClaimSet))?;
    let after_lens = GeneratedLens::new(sheet(LensHandleRole::QueryResult))?;
    let before = LensBehaviorFingerprint::from_golden_renders([("case", &before_lens)])?;
    let after = LensBehaviorFingerprint::from_golden_renders([("case", &after_lens)])?;

    let diff = LensBehaviorDiff::between(&before, &after)?;
    assert!(
        diff.has_data_read_change(),
        "a citation is a bound data read, not decoration"
    );
    assert!(
        diff.structural_cases().is_empty() && diff.inventory_changes().is_empty(),
        "the tree shape and inventory are untouched"
    );
    assert_eq!(diff.role_changes().len(), 1);
    let change = &diff.role_changes()[0];
    assert_eq!(change.name().as_str(), "cited");
    assert_eq!(change.before(), &BTreeSet::from([LensHandleRole::ClaimSet]));
    assert_eq!(
        change.after(),
        &BTreeSet::from([LensHandleRole::QueryResult])
    );

    Ok(())
}

#[test]
fn fingerprint_rejects_empty_duplicate_or_mismatched_corpora() -> Result<()> {
    let lens = GeneratedLens::new(v2_only_root())?;

    let empty =
        LensBehaviorFingerprint::from_golden_renders(std::iter::empty::<(&str, &GeneratedLens)>())
            .expect_err("an empty corpus is not a fingerprint");
    assert!(
        empty.to_string().contains("at least one fixture"),
        "{empty}"
    );

    let duplicate =
        LensBehaviorFingerprint::from_golden_renders([("case", &lens), ("case", &lens)])
            .expect_err("fixture ids identify cases, so they must be unique");
    assert!(
        duplicate.to_string().contains("duplicate fixture id case"),
        "{duplicate}"
    );

    let bad_token = LensBehaviorFingerprint::from_golden_renders([("not a token", &lens)])
        .expect_err("fixture ids are lens tokens");
    assert!(
        bad_token.to_string().contains("lens golden fixture id"),
        "{bad_token}"
    );

    let left = LensBehaviorFingerprint::from_golden_renders([("alpha", &lens)])?;
    let right = LensBehaviorFingerprint::from_golden_renders([("beta", &lens)])?;
    let mismatch = LensBehaviorDiff::between(&left, &right)
        .expect_err("unequal case-id sets are refused, never intersected");
    assert!(
        mismatch
            .to_string()
            .contains("cover different golden fixtures"),
        "{mismatch}"
    );

    Ok(())
}

#[test]
fn diff_reports_structure_inventory_and_role_changes_separately() -> Result<()> {
    let mut before_root = card_root(vec![throbber_node("one")]);
    before_root.bindings = vec![
        binding("people", LensHandleRole::EntitySet),
        binding("claims", LensHandleRole::ClaimSet),
    ];
    let before_lens = GeneratedLens::new(before_root)?;

    let mut after_root = card_root(vec![throbber_node("one"), throbber_node("two")]);
    after_root.bindings = vec![
        binding("people", LensHandleRole::QueryResult),
        binding("claims", LensHandleRole::Timeline),
    ];
    let after_lens = GeneratedLens::new(after_root)?;

    let before = LensBehaviorFingerprint::from_golden_renders([("case", &before_lens)])?;
    let after = LensBehaviorFingerprint::from_golden_renders([("case", &after_lens)])?;

    // A fingerprint diffed against itself is empty in every dimension.
    let identical = LensBehaviorDiff::between(&before, &before)?;
    assert!(identical.is_identical());
    assert!(
        identical.inventory_changes().is_empty(),
        "equal counts never produce change entries"
    );
    assert!(!identical.has_data_read_change());

    let diff = LensBehaviorDiff::between(&before, &after)?;
    assert_eq!(
        diff.structural_cases()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["case"]
    );

    let inventory = diff.inventory_changes().iter().collect::<Vec<_>>();
    assert_eq!(
        inventory.len(),
        1,
        "the unchanged sheet count is not reported: {inventory:?}"
    );
    assert_eq!(inventory[0].fixture_id(), "case");
    assert_eq!(inventory[0].primitive(), GeneratedUiPrimitive::Throbber);
    assert_eq!(inventory[0].before(), 1);
    assert_eq!(inventory[0].after(), 2);

    let removed = diff
        .removed_handles()
        .iter()
        .map(|entry| (entry.fixture_id(), entry.name().as_str(), entry.role()))
        .collect::<Vec<_>>();
    assert_eq!(
        removed,
        vec![
            ("case", "claims", LensHandleRole::ClaimSet),
            ("case", "people", LensHandleRole::EntitySet),
        ],
        "removed pairs are canonically ordered"
    );
    let added = diff
        .added_handles()
        .iter()
        .map(|entry| (entry.fixture_id(), entry.name().as_str(), entry.role()))
        .collect::<Vec<_>>();
    assert_eq!(
        added,
        vec![
            ("case", "claims", LensHandleRole::Timeline),
            ("case", "people", LensHandleRole::QueryResult),
        ],
        "added pairs are canonically ordered"
    );

    assert_eq!(
        diff.role_changes()
            .iter()
            .map(|change| (change.fixture_id(), change.name().as_str()))
            .collect::<Vec<_>>(),
        vec![("case", "claims"), ("case", "people")],
        "role changes are sorted by fixture id then handle name"
    );
    assert_eq!(
        diff.role_changes()[0].before(),
        &BTreeSet::from([LensHandleRole::ClaimSet])
    );
    assert_eq!(
        diff.role_changes()[0].after(),
        &BTreeSet::from([LensHandleRole::Timeline])
    );
    assert!(diff.has_data_read_change(), "role changes are data reads");
    assert!(!diff.is_identical());

    Ok(())
}
