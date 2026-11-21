//! The coping lookup's tunables are the owner's manifest row (canon
//! `manifest:affect_lookup`: "the nearest-state metric (PAD distance over
//! the canonical VAD floats) and the outcome count below which the ledger
//! answers from generic regulation priors at low confidence ... These are
//! tunable starting values, not engine constants"). The owner reads them
//! with `vault.affect.lookup.get` and sets them with
//! `vault.affect.lookup.configure` against the default manifest's hash; the
//! lookup reads the row in its own snapshot. Every call enters through
//! `oneiron_testkit::door::invoke`; the fixtures follow
//! `tests/vault_coping_lookup.rs`.
//!
//! - P1 the starting values are read until the owner sets a floor, and the
//!   lookup then answers by the floor the owner set.
//! - P2 a stale manifest hash, an unknown metric, an unknown field and a
//!   missing floor each leave the row and the manifest unchanged.
//! - P3 only the owner reads or sets the row.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_coping_lookup_policy`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::claim::{base_world_id, default_project_id};
use oneiron::memory::{Memory, MemoryResult};
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

/// The owner PERSON's ref: the person every witnessed `user` turn names.
fn owner_person(vault: &Vault) -> String {
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner person")
        .to_hex()
}

/// A user turn the owner spoke, annotated with `vad`.
fn felt_turn(
    owner: &Memory<'_>,
    vault: &Vault,
    conversation: &str,
    text: &str,
    vad: (f64, f64, f64),
) -> String {
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
    let turn = receipt["turn_short_id"]
        .as_str()
        .expect("the receipt names the turn")
        .to_owned();
    door::invoke(
        owner,
        "vault.affect.annotations.put",
        json!({
            "turn_ref": turn,
            "vad": {"valence": vad.0, "arousal": vad.1, "dominance": vad.2},
            "source": "user_self_report",
            "annotated_at": AT,
            "scope": scope(vault),
            "sensitivity": null,
        }),
    )
    .expect("the turn takes its annotation");
    turn
}

/// One coping outcome that worked: `strategy` at `baseline`, measured at
/// `later`.
fn record_worked(owner: &Memory<'_>, vault: &Vault, baseline: &str, later: &str, strategy: &str) {
    let receipt = door::invoke(
        owner,
        "vault.affect.coping.record",
        json!({
            "affected_person_ref": owner_person(vault),
            "baseline_turn_ref": baseline,
            "later_turn_ref": later,
            "strategy": strategy,
            "confidence": 0.8,
            "scope": scope(vault),
            "sensitivity": null,
        }),
    )
    .expect("the owner records the outcome");
    assert_eq!(receipt["outcome"]["successful"], true, "{receipt}");
}

fn lookup(owner: &Memory<'_>, vault: &Vault, turn: &str) -> Value {
    door::invoke(
        owner,
        "vault.affect.coping.lookup",
        json!({
            "affected_person_ref": owner_person(vault),
            "current_turn_ref": turn,
            "scope": null,
        }),
    )
    .expect("the owner looks up coping")
}

fn get(caller: &Memory<'_>) -> MemoryResult<Value> {
    door::invoke(caller, "vault.affect.lookup.get", json!({}))
}

fn configure(
    caller: &Memory<'_>,
    expected_body_hash: &Value,
    policy: Value,
) -> MemoryResult<Value> {
    door::invoke(
        caller,
        "vault.affect.lookup.configure",
        json!({"expected_body_hash": expected_body_hash, "policy": policy}),
    )
}

fn floor(floor: u64) -> Value {
    json!({"nearest_state_metric": "pad_distance", "cold_start_min_outcomes": floor})
}

/// P1. The owner's default manifest has no `affect_lookup` row, so the row
/// reads as the starting values and one outcome is below the floor. The
/// owner sets a floor of 1: the same ledger now answers from its outcome.
/// A floor of 2 sends it back to the priors, and the answer names the
/// floor it used each time.
#[test]
fn the_lookup_answers_by_the_floor_the_owner_set() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let conversation = EntityId::now().to_hex();
    let before = felt_turn(&owner, &vault, &conversation, "tense", (-0.4, 0.8, 0.3));
    let after = felt_turn(&owner, &vault, &conversation, "eased", (0.2, 0.4, 0.5));
    let now = felt_turn(
        &owner,
        &vault,
        &conversation,
        "tense again",
        (-0.4, 0.7, 0.3),
    );
    record_worked(&owner, &vault, &before, &after, "SitMod");

    let start = get(&owner).expect("the owner reads the row");
    assert_eq!(start["policy"], floor(3), "the starting values: {start}");
    assert_eq!(
        start["manifest_ref"],
        oneiron_store::policy_record::default_policy_manifest_id()
            .expect("the default manifest id")
            .to_hex(),
        "{start}"
    );
    let thin = lookup(&owner, &vault, &now);
    assert_eq!(thin["basis"], "generic_priors", "{thin}");
    assert_eq!(thin["cold_start_min_outcomes"], 3, "{thin}");
    assert_eq!(thin["observed_n"], 1, "{thin}");

    let set = configure(&owner, &start["body_hash"], floor(1)).expect("the owner sets floor 1");
    assert_eq!(set["configuration"]["policy"], floor(1), "{set}");
    assert!(
        set["receipt_ref"]
            .as_str()
            .is_some_and(|receipt| receipt.starts_with("gate:")),
        "the edit is receipted: {set}"
    );
    assert_ne!(
        set["configuration"]["body_hash"], start["body_hash"],
        "the manifest body changed: {set}"
    );
    assert_eq!(
        get(&owner).expect("the owner reads the row")["policy"],
        floor(1)
    );
    let known = lookup(&owner, &vault, &now);
    assert_eq!(known["basis"], "outcomes", "{known}");
    assert_eq!(known["cold_start_min_outcomes"], 1, "{known}");
    assert_eq!(known["priors"], json!([]), "{known}");
    assert_eq!(
        known["outcomes"][0]["outcome"]["strategy"], "SitMod",
        "{known}"
    );

    let raised = configure(&owner, &set["configuration"]["body_hash"], floor(2))
        .expect("the owner sets floor 2");
    assert_eq!(raised["configuration"]["policy"], floor(2), "{raised}");
    let thin_again = lookup(&owner, &vault, &now);
    assert_eq!(thin_again["basis"], "generic_priors", "{thin_again}");
    assert_eq!(thin_again["cold_start_min_outcomes"], 2, "{thin_again}");
    assert_eq!(
        thin_again["priors"].as_array().map(Vec::len),
        Some(6),
        "{thin_again}"
    );
}

/// P2. A configure against a stale hash, one naming a metric other than
/// PAD distance, one with a field the row does not have, and one with no
/// floor are refused; each leaves the manifest hash and the row as they
/// were. The owner's well-formed configure then lands.
#[test]
fn a_stale_hash_or_an_unknown_metric_changes_nothing() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let start = get(&owner).expect("the owner reads the row");
    let hash = &start["body_hash"];
    assert!(
        hash.as_str().is_some_and(|hash| hash.len() == 64),
        "{start}"
    );

    let refused = [
        ("a stale hash", json!("0".repeat(64)), floor(1)),
        (
            "an unknown metric",
            hash.clone(),
            json!({"nearest_state_metric": "cosine", "cold_start_min_outcomes": 1}),
        ),
        (
            "an unknown field",
            hash.clone(),
            json!({
                "nearest_state_metric": "pad_distance",
                "cold_start_min_outcomes": 1,
                "prior_confidence": 0.9,
            }),
        ),
        (
            "a missing floor",
            hash.clone(),
            json!({"nearest_state_metric": "pad_distance"}),
        ),
    ];
    for (name, expected, policy) in refused {
        let error = configure(&owner, &expected, policy).expect_err(name);
        let after = get(&owner).expect("the owner reads the row");
        assert_eq!(after["body_hash"], *hash, "{name}: {error:?}");
        assert_eq!(after["policy"], floor(3), "{name}: {error:?}");
    }

    let set = configure(&owner, hash, floor(0)).expect("the owner turns the priors off");
    assert_eq!(set["configuration"]["policy"], floor(0), "{set}");
}

/// P3. Another person and an agent neither read nor set the row; the
/// owner's row is unchanged after their calls.
#[test]
fn only_the_owner_reads_or_sets_the_lookup_tunables() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let start = get(&owner).expect("the owner reads the row");

    let person = vault.memory(EntityId::now(), EdgeActorClass::Human);
    let agent = vault.memory(EntityId::now(), EdgeActorClass::Agent);
    for (name, caller) in [("another person", &person), ("an agent", &agent)] {
        let read = get(caller).expect_err(&format!("{name} reads nothing"));
        assert_eq!(read.code, "FORBIDDEN", "{name}: {read:?}");
        let set = configure(caller, &start["body_hash"], floor(1))
            .expect_err(&format!("{name} sets nothing"));
        assert_eq!(set.code, "FORBIDDEN", "{name}: {set:?}");
    }

    let after = get(&owner).expect("the owner reads the row");
    assert_eq!(after["body_hash"], start["body_hash"], "{after}");
    assert_eq!(after["policy"], floor(3), "{after}");
}
