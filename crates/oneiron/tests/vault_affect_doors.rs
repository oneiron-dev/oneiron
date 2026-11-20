//! The `vault.affect.*` doors keep the affect promises (ruling L4-23 = A:
//! each test proves a promise at its public door). Every call enters through
//! `oneiron_testkit::door::invoke`, the generated verb dispatch every
//! transport shares; the owner rows run on a vault opened with the process
//! writer lease (`TestVault::open_owned`), as an embedded host's are.
//!
//! - P1 `canon oneiron/affect-ei.md:30` "The turn write commits a tagging
//!   marker and never waits for the tagger": a turn lands on a vault with no
//!   tagger, and can be annotated at once.
//! - P2 `oneiron/affect-ei.md:67` "VAD numbers are canonical; words like
//!   dread or relief are deterministic projections, never model-authored
//!   labels": an annotation carrying a label is refused, and consolidation
//!   returns the floats as put, with no label anywhere.
//! - P3 the wellness action-mode policy is the owner's (the
//!   `vault.affect.wellness.policy.configure` row: "Configures or clears the
//!   existing action-mode policy as the owner"); another person or an agent
//!   configures nothing.
//! - P4 an out-of-range or mistyped VAD is refused at the door (the
//!   `QueryAffect` contract: valence in -1..=1, arousal and dominance in
//!   0..=1), as is an annotation on a row that is not a TURN.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_affect_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{base_world_id, default_project_id};
use oneiron::memory::Memory;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_testkit::{FAKE_EPOCH, FixtureVault, TestVault, door, fixture_cache};
use serde_json::{Value, json};

/// A time before the fixture clock's now.
const AT: u64 = FAKE_EPOCH - 600;

/// A private copy of the empty fixture, opened with the writer lease so the
/// owner-proof rows admit the embedded owner. The `TestVault` holds the
/// directory and must outlive the `Vault`.
fn owned_vault() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open_owned().expect("an owned open");
    (copy, vault)
}

/// The owner's default claim position: the base world, the default facet
/// and project, every relationship.
fn scope(vault: &Vault) -> Value {
    json!({
        "world_id": base_world_id().to_hex(),
        "scope_facet_id": vault.default_facet().expect("the default facet").to_hex(),
        "scope_relationship_id": "all",
        "scope_project_id": default_project_id().to_hex(),
    })
}

/// Lands one user turn through `vault.witness`; answers its short id.
fn witness(owner: &Memory<'_>, conversation: &str, text: &str) -> String {
    let receipt = door::invoke(
        owner,
        "vault.witness",
        json!({
            "conversation_ref": conversation,
            "turn_ref": null,
            "messages": [{
                "id": null,
                "author": "user",
                "message_type": "text",
                "content": text,
                "metadata": null,
                "is_visible": true,
                "order": 0,
            }],
            "occurred_at": AT,
        }),
    )
    .expect("the turn lands");
    receipt["turn_short_id"]
        .as_str()
        .expect("the receipt names the turn")
        .to_owned()
}

/// An annotation body for `turn` with the given floats.
fn annotation(vault: &Vault, turn: &str, valence: f64, arousal: f64, dominance: f64) -> Value {
    json!({
        "turn_ref": turn,
        "vad": {"valence": valence, "arousal": arousal, "dominance": dominance},
        "source": "user_self_report",
        "annotated_at": AT,
        "scope": scope(vault),
        "sensitivity": null,
    })
}

/// Every object key anywhere in `value`.
fn keys(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                keys(inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|inner| keys(inner, out)),
        _ => {}
    }
}

/// P1 (affect-ei.md:30). The fixture arms no tagger; two turns land, each
/// its own TURN, and the first takes an annotation at once.
/// Seeded fault: `crates/oneiron/src/tagging/marker.rs:302`, the unarmed
/// vault's `return Ok(());` in `mark_turn_in_txn`, made an error, so a turn
/// write depends on a tagger.
#[test]
fn a_turn_lands_without_waiting_for_a_tagger() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let conversation = EntityId::now().to_hex();

    let first = witness(&owner, &conversation, "the first turn");
    let second = witness(&owner, &conversation, "the second turn");
    assert_ne!(first, second, "each write lands its own TURN");

    let receipt = door::invoke(
        &owner,
        "vault.affect.annotations.put",
        annotation(&vault, &first, 0.25, 0.5, 0.75),
    )
    .expect("the landed turn takes an annotation");
    assert!(
        receipt["receipt_ref"]
            .as_str()
            .is_some_and(|reference| !reference.is_empty()),
        "{receipt}"
    );
}

/// P2 (affect-ei.md:67). A label rides on no annotation; the claim's
/// consolidation returns the turn's floats exactly, and no key of its
/// answer is a label.
/// Seeded fault: `crates/oneiron-verb-wire/src/memory/affect.rs:35`, the
/// `#[serde(deny_unknown_fields)]` on `AffectAnnotationPut`, deleted, so a
/// label is taken in silence.
#[test]
fn affect_is_floats_and_a_label_is_refused() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness(&owner, &EntityId::now().to_hex(), "a turn to annotate");

    let mut labelled = annotation(&vault, &turn, 0.25, 0.5, 0.75);
    labelled["label"] = json!("dread");
    door::invoke(&owner, "vault.affect.annotations.put", labelled)
        .expect_err("an annotation with a label is refused");

    let receipt = door::invoke(
        &owner,
        "vault.affect.annotations.put",
        annotation(&vault, &turn, 0.25, 0.5, 0.75),
    )
    .expect("the floats land");
    let claim = receipt["claim_short_id"]
        .as_str()
        .expect("the receipt names the claim");
    let consolidated = door::invoke(
        &owner,
        "vault.affect.claims.consolidate",
        json!({"claim_ref": claim}),
    )
    .expect("the owner consolidates the claim");
    let evidence = consolidated["evidence_turns"]
        .as_array()
        .expect("the evidence turns");
    assert!(!evidence.is_empty(), "{consolidated}");
    assert_eq!(
        evidence[0]["vad"],
        json!({"valence": 0.25, "arousal": 0.5, "dominance": 0.75}),
        "the floats come back as put"
    );
    let mut seen = Vec::new();
    keys(&consolidated, &mut seen);
    assert!(
        !seen
            .iter()
            .any(|key| key.contains("label") || key.contains("emotion")),
        "no label in the answer: {seen:?}"
    );
}

/// P3 (the `vault.affect.wellness.policy.configure` row). The owner sets
/// and clears the policy; another person and an agent are refused
/// FORBIDDEN and the stored policy is unchanged.
/// Seeded fault: `crates/oneiron/src/memory/owner_door.rs:77`, `if
/// self.actor != owner` made `if false`, so any human handle in the
/// process passes as the owner.
#[test]
fn only_the_owner_configures_the_wellness_policy() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let read = |caller: &Memory<'_>| {
        door::invoke(caller, "vault.affect.wellness.policy.get", json!({}))
            .expect("the owner reads the policy")
    };
    assert_eq!(read(&owner), Value::Null, "no policy until one is set");

    let policy = json!({
        "window": {"window_secs": 86_400, "expected_goal_completions": 1, "expected_engaged_days": 1},
        "rules": [
            {"mode": "steady", "min_index": 0.0, "max_index": 0.5},
            {"mode": "open", "min_index": 0.5, "max_index": 1.0},
        ],
    });
    let set = door::invoke(
        &owner,
        "vault.affect.wellness.policy.configure",
        json!({"policy": policy}),
    )
    .expect("the owner sets the policy");
    assert_eq!(read(&owner), set, "the policy reads back as set");

    let person = vault.memory(EntityId::now(), EdgeActorClass::Human);
    let agent = vault.memory(EntityId::now(), EdgeActorClass::Agent);
    for (name, caller) in [("another person", &person), ("an agent", &agent)] {
        let refused = door::invoke(
            caller,
            "vault.affect.wellness.policy.configure",
            json!({"policy": null}),
        )
        .expect_err(&format!("{name} configures nothing"));
        assert_eq!(refused.code, "FORBIDDEN", "{name}: {refused:?}");
    }
    assert_eq!(read(&owner), set, "the refused calls changed nothing");

    door::invoke(
        &owner,
        "vault.affect.wellness.policy.configure",
        json!({"policy": null}),
    )
    .expect("the owner clears the policy");
    assert_eq!(read(&owner), Value::Null, "a cleared policy stays absent");
}

/// P4 (the `QueryAffect` contract). Each row is refused at the door and
/// leaves the turn unannotated.
/// Seeded fault: `crates/oneiron-contracts/src/affect/vad.rs:34`, the
/// range check in `Vad::validate`, given `.filter(|_| false)`, so every
/// float passes.
#[test]
fn an_out_of_range_or_mistyped_annotation_is_refused() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let turn = witness(&owner, &EntityId::now().to_hex(), "a turn to mis-annotate");
    let not_a_turn = vault
        .ensure_embedded_owner_actor()
        .expect("the owner person")
        .to_hex();

    let mut mistyped = annotation(&vault, &turn, 0.1, 0.5, 0.5);
    mistyped["vad"]["valence"] = json!("high");
    let rows: [(&str, Value, Option<&str>); 6] = [
        (
            "valence above 1",
            annotation(&vault, &turn, 2.0, 0.5, 0.5),
            Some("BAD_REQUEST"),
        ),
        (
            "valence below -1",
            annotation(&vault, &turn, -1.5, 0.5, 0.5),
            Some("BAD_REQUEST"),
        ),
        (
            "arousal below 0",
            annotation(&vault, &turn, 0.1, -0.5, 0.5),
            Some("BAD_REQUEST"),
        ),
        (
            "dominance above 1",
            annotation(&vault, &turn, 0.1, 0.5, 1.5),
            Some("BAD_REQUEST"),
        ),
        ("a string for a float", mistyped, None),
        (
            "a PERSON for the turn",
            annotation(&vault, &not_a_turn, 0.1, 0.5, 0.5),
            Some("BAD_REQUEST"),
        ),
    ];
    for (name, body, code) in rows {
        let refused = door::invoke(&owner, "vault.affect.annotations.put", body)
            .expect_err(&format!("refused: {name}"));
        if let Some(code) = code {
            assert_eq!(refused.code, code, "{name}: {refused:?}");
        }
    }
}
