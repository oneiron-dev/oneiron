//! `vault.affect.coping.lookup` keeps the coping-lookup promise at its
//! public door (canon oneiron/affect-ei.md: "Coping lookup is nearest-state.
//! Given the current turn-VAD, query `coping.outcome` for the nearest state
//! by PAD distance, rank by (worked, recency, confidence); below the
//! manifest's cold-start outcome floor the ledger falls back to generic
//! regulation priors at low confidence"). Every call enters through
//! `oneiron_testkit::door::invoke`; the owner rows run on a vault opened
//! with the process writer lease. The fixtures follow
//! `tests/vault_affect_doors.rs` (#8737).
//!
//! - L1 the nearest state's outcomes come first, and within one state a
//!   worked outcome comes before one that did not work.
//! - L2 below the cold-start floor (starting value 3 outcomes) the answer
//!   is the six generic regulation priors at Low confidence.
//! - L3 the current state is a turn the person spoke in, with a VAD.
//! - L4 the lookup is the owner's, like the coping aggregate.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test vault_coping_lookup`.
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

/// The owner PERSON's ref: the person every witnessed `user` turn names.
fn owner_person(vault: &Vault) -> String {
    vault
        .ensure_embedded_owner_actor()
        .expect("the owner person")
        .to_hex()
}

/// Lands one turn by `author` through `vault.witness`; answers its short id.
fn witness(owner: &Memory<'_>, conversation: &str, author: &str, text: &str) -> String {
    let receipt = door::invoke(
        owner,
        "vault.witness",
        json!({
            "conversation_ref": conversation,
            "turn_ref": null,
            "messages": [{
                "id": null,
                "author": author,
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

/// A user turn the owner spoke, annotated with `vad`.
fn felt_turn(
    owner: &Memory<'_>,
    vault: &Vault,
    conversation: &str,
    text: &str,
    vad: (f64, f64, f64),
) -> String {
    let turn = witness(owner, conversation, "user", text);
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

/// Records one coping outcome: `strategy` offered at `baseline`, measured
/// at `later`. Answers whether it worked.
fn record(owner: &Memory<'_>, vault: &Vault, baseline: &str, later: &str, strategy: &str) -> bool {
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
    receipt["outcome"]["successful"]
        .as_bool()
        .expect("the outcome says whether it worked")
}

fn lookup(caller: &Memory<'_>, vault: &Vault, turn: &str) -> oneiron::memory::MemoryResult<Value> {
    door::invoke(
        caller,
        "vault.affect.coping.lookup",
        json!({
            "affected_person_ref": owner_person(vault),
            "current_turn_ref": turn,
            "scope": null,
        }),
    )
}

fn number(value: &Value) -> f64 {
    value.as_f64().expect("a number")
}

/// L1. Two outcomes were used in a state near the current one (one worked,
/// one did not, the worked one recorded first), one in a far state (it
/// worked). The near state's outcomes come first, worked before not
/// worked; the far one comes last although it worked. Three outcomes reach
/// the floor, so no prior is listed, and the aggregate still counts all
/// three.
#[test]
fn the_nearest_state_comes_first_and_worked_before_not_worked() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let conversation = EntityId::now().to_hex();
    let near = felt_turn(
        &owner,
        &vault,
        &conversation,
        "a little low",
        (0.1, 0.5, 0.5),
    );
    let far = felt_turn(&owner, &vault, &conversation, "panicking", (-0.9, 0.9, 0.1));
    let calmer = felt_turn(&owner, &vault, &conversation, "calmer", (0.5, 0.3, 0.7));
    let worse = felt_turn(&owner, &vault, &conversation, "worse", (-0.3, 0.8, 0.3));
    let steady = felt_turn(&owner, &vault, &conversation, "steady", (0.0, 0.5, 0.5));
    let now = felt_turn(&owner, &vault, &conversation, "now", (0.0, 0.5, 0.5));

    assert!(
        record(&owner, &vault, &near, &calmer, "AttDep"),
        "valence rose"
    );
    assert!(
        !record(&owner, &vault, &near, &worse, "ResMod"),
        "every axis worsened"
    );
    assert!(
        record(&owner, &vault, &far, &steady, "CogChg"),
        "valence rose"
    );

    let answer = lookup(&owner, &vault, &now).expect("the owner looks up coping");
    assert_eq!(answer["basis"], "outcomes", "{answer}");
    assert_eq!(answer["observed_n"], 3, "{answer}");
    assert_eq!(answer["cold_start_min_outcomes"], 3, "{answer}");
    assert_eq!(answer["priors"], json!([]), "{answer}");
    assert!(
        (number(&answer["current_state"]["valence"]) - 0.0).abs() < 1e-6
            && (number(&answer["current_state"]["arousal"]) - 0.5).abs() < 1e-6,
        "the current state is the turn's VAD: {answer}"
    );

    let outcomes = answer["outcomes"].as_array().expect("ranked outcomes");
    let strategies: Vec<&str> = outcomes
        .iter()
        .map(|row| row["outcome"]["strategy"].as_str().expect("a strategy"))
        .collect();
    assert_eq!(strategies, ["AttDep", "ResMod", "CogChg"], "{answer}");
    let worked: Vec<bool> = outcomes
        .iter()
        .map(|row| row["outcome"]["successful"].as_bool().expect("worked"))
        .collect();
    assert_eq!(worked, [true, false, true], "{answer}");
    let distances: Vec<f64> = outcomes
        .iter()
        .map(|row| number(&row["pad_distance"]))
        .collect();
    assert!((distances[0] - 0.1).abs() < 1e-4, "{answer}");
    assert_eq!(
        distances[0], distances[1],
        "one state, one distance: {answer}"
    );
    assert!((distances[2] - 1.13_f64.sqrt()).abs() < 1e-4, "{answer}");
    assert!(
        (number(&outcomes[2]["state"]["valence"]) + 0.9).abs() < 1e-6,
        "each row carries the state it was used in: {answer}"
    );

    let aggregate = door::invoke(
        &owner,
        "vault.affect.coping.aggregate",
        json!({"affected_person_ref": owner_person(&vault), "scope": null}),
    )
    .expect("the owner reads the aggregate");
    assert_eq!(aggregate["observed_n"], 3, "{aggregate}");
    assert_eq!(
        aggregate["outcomes"].as_array().map(Vec::len),
        Some(3),
        "{aggregate}"
    );
}

/// L2. With no outcome, and then with one, the ledger is below the floor:
/// the answer is the six generic regulation priors, all at one Low
/// confidence (below the house band's 0.4), next to the one ledger row.
#[test]
fn a_thin_ledger_answers_generic_priors_at_low_confidence() {
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

    let priors = |answer: &Value| {
        assert_eq!(answer["basis"], "generic_priors", "{answer}");
        let priors = answer["priors"].as_array().expect("priors");
        let mut strategies: Vec<&str> = priors
            .iter()
            .map(|prior| prior["strategy"].as_str().expect("a strategy"))
            .collect();
        strategies.sort_unstable();
        assert_eq!(
            strategies,
            ["AttDep", "CogChg", "ERFlex", "ResMod", "SitMod", "SitSel"],
            "{answer}"
        );
        let confidence = number(&priors[0]["confidence"]);
        assert!(confidence > 0.0 && confidence < 0.4, "{answer}");
        assert!(
            priors
                .iter()
                .all(|prior| number(&prior["confidence"]) == confidence),
            "no strategy is ranked above another: {answer}"
        );
    };

    let empty = lookup(&owner, &vault, &now).expect("the owner looks up coping");
    priors(&empty);
    assert_eq!(empty["observed_n"], 0, "{empty}");
    assert_eq!(empty["outcomes"], json!([]), "{empty}");

    assert!(
        record(&owner, &vault, &before, &after, "SitMod"),
        "valence rose"
    );
    let thin = lookup(&owner, &vault, &now).expect("the owner looks up coping");
    priors(&thin);
    assert_eq!(thin["observed_n"], 1, "{thin}");
    assert_eq!(
        thin["outcomes"][0]["outcome"]["strategy"], "SitMod",
        "the one ledger row is still listed: {thin}"
    );
}

/// L3. A turn the person did not speak in, a turn with no VAD, and a row
/// that is no turn are each refused; the person's annotated turn answers.
#[test]
fn the_current_state_is_an_annotated_turn_the_person_spoke_in() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let conversation = EntityId::now().to_hex();
    let system = witness(&owner, &conversation, "system", "a system notice");
    let unannotated = witness(&owner, &conversation, "user", "no mood read yet");
    let felt = felt_turn(&owner, &vault, &conversation, "felt", (0.2, 0.4, 0.6));

    let rows = [
        ("a system turn", system, "spoke in"),
        ("a turn with no VAD", unannotated, "VAD"),
        ("a PERSON for the turn", owner_person(&vault), "spoke in"),
    ];
    for (name, turn, says) in rows {
        let refused = lookup(&owner, &vault, &turn).expect_err(&format!("refused: {name}"));
        assert_eq!(refused.code, "BAD_REQUEST", "{name}: {refused:?}");
        assert!(refused.message.contains(says), "{name}: {refused:?}");
    }

    let answer = lookup(&owner, &vault, &felt).expect("the annotated user turn answers");
    assert_eq!(answer["basis"], "generic_priors", "{answer}");
}

/// L4. Another person and an agent are refused as the aggregate refuses
/// them; the owner's call answers.
#[test]
fn only_the_owner_looks_up_coping() {
    let (_dir, vault) = owned_vault();
    let owner = door::owner(&vault).expect("the owner");
    let conversation = EntityId::now().to_hex();
    let now = felt_turn(&owner, &vault, &conversation, "now", (0.0, 0.5, 0.5));

    let person = vault.memory(EntityId::now(), EdgeActorClass::Human);
    let agent = vault.memory(EntityId::now(), EdgeActorClass::Agent);
    for (name, caller) in [("another person", &person), ("an agent", &agent)] {
        let refused = lookup(caller, &vault, &now).expect_err(&format!("{name} looks up nothing"));
        assert_eq!(refused.code, "FORBIDDEN", "{name}: {refused:?}");
    }
    lookup(&owner, &vault, &now).expect("the owner looks up coping");
}
