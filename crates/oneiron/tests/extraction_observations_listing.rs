//! One bound extraction observations page with its correction-listing facts.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test extraction_observations_listing`.
//! The engine worker owns the `listed` section with the candidate `correctable`
//! and `single_valued` facts and the prior `non_widening_candidates` facts. Every
//! assertion below reads the served page as plain JSON, so this file compiles
//! before the engine serves the new fields and fails on their absence. Common
//! vault, page and verdict helpers come from the shared verdict support module.
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict/support.rs"]
mod verdict_support;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_runner::DreamerAttemptBinding;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryResult};
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_single_valued::seed_extraction_single_valued_predicates;
use oneiron::test_doors::extraction_verdict::dreamer_extraction_verdict_source_version;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{EntityId, TimeRange, Vault};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use std::sync::Arc;
use verdict_support::{
    QUEUE_NOW, bind_extraction as bind_listing, extraction_attempt_hex as listing_attempt_hex,
    extraction_candidate as listing_candidate,
    extraction_verdict_request as listing_verdict_request, invoke_bound_verdict,
    open_extraction_verdict_vault as open_listing_vault, page_turns_with_versions,
    read_bound_extraction_page as read_bound_inputs_page,
};

/// Returns a fixture or assertion error without hiding its source.
type ListingTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The observations page an extraction attempt reads its operand facts through.
const OBSERVATIONS_PAGE_VERB: &str = "vault.consolidation.extraction.observations.page";

/// The host clock the observations requests here carry, in Unix milliseconds.
const OBSERVATION_NOW_MS: u64 = 21_000;

/// Asks one bound observations page through `binding` with `request` as plain JSON.
fn invoke_observations(binding: &DreamerAttemptBinding, request: Value) -> MemoryResult<Value> {
    binding.invoke(OBSERVATIONS_PAGE_VERB, request, None)
}

/// Lands one Active `preference.food` claim about `subject` with `value`, `source` and
/// `approval`, through the public claim write door.
fn land_food_claim(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
) -> ListingTestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = source;
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &id,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(id)
}

/// Returns the candidate row of `index` from an observations page.
fn page_candidate(page: &Value, index: u64) -> Value {
    page["candidates"]
        .as_array()
        .unwrap_or_else(|| panic!("candidates is an array"))
        .iter()
        .find(|row| row["index"] == json!(index))
        .unwrap_or_else(|| panic!("the candidate row is served"))
        .clone()
}

/// Returns the prior row of `claim` from an observations page.
fn page_prior(page: &Value, claim: &str) -> Value {
    page["priors"]
        .as_array()
        .unwrap_or_else(|| panic!("priors is an array"))
        .iter()
        .find(|row| row["claim"] == json!(claim))
        .unwrap_or_else(|| panic!("the prior row is served"))
        .clone()
}

/// Reads the index array of `field` from a page row as numbers.
fn row_indexes(row: &Value, field: &str) -> Vec<u64> {
    row[field]
        .as_array()
        .unwrap_or_else(|| panic!("the row names its {field}"))
        .iter()
        .map(|entry| {
            entry
                .as_u64()
                .unwrap_or_else(|| panic!("the {field} entry is a number"))
        })
        .collect()
}

/// Two correctable owen heads list in native order with live versions, drive their
/// candidates' correction pairs, and build a correction pack that passes the claim
/// pins; a proposed owen head lists nowhere.
#[test]
fn listed_rows_drive_a_correction_pack_past_the_claim_pins() -> ListingTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_listing_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let owen = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    let yuki = EntityId::now();
    seed_named_person(&vault, &yuki, "yuki", vault.now_recorded_at())?;
    let first = land_food_claim(
        &vault,
        owen,
        "green tea",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    let second = land_food_claim(
        &vault,
        owen,
        "black coffee",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    let proposed = land_food_claim(
        &vault,
        owen,
        "papaya custard",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Proposed,
    )?;
    let witnessed = witness_extraction_turns(
        &vault,
        &[
            "owen savors green tea",
            "owen cooks daily",
            "yuki walks daily",
        ],
    )?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_listing(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &listing_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 3, "all three witnessed turns are served");
    let owen_hex = owen.to_hex();
    let first_hex = first.to_hex();
    let second_hex = second.to_hex();
    let proposed_hex = proposed.to_hex();
    let owen_candidates = json!([
        listing_candidate(
            &owen_hex,
            "preference.food",
            json!("oolong"),
            &turns[0].0,
            turns[0].1.clone(),
        ),
        listing_candidate(
            &owen_hex,
            "preference.food",
            json!("jasmine"),
            &turns[1].0,
            turns[1].1.clone(),
        ),
    ]);
    let yuki_candidate = listing_candidate(
        &yuki.to_hex(),
        "preference.food",
        json!("green tea"),
        &turns[2].0,
        turns[2].1.clone(),
    );
    let observed = json!([
        owen_candidates[0].clone(),
        owen_candidates[1].clone(),
        yuki_candidate,
    ]);
    let served = invoke_observations(
        &binding,
        json!({
            "attempt": listing_attempt_hex(id),
            "now_ms": OBSERVATION_NOW_MS,
            "candidates": observed.clone(),
        }),
    )?["value"]
        .clone();
    let page = serde_json::to_value(&served)?;
    assert_eq!(
        page["listed"].as_array().map(Vec::len),
        Some(2),
        "the page serves two listed rows"
    );
    let listed = page["listed"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves its listed rows"))
        .clone();
    assert_eq!(listed.len(), 2, "exactly the two correctable heads list");
    let first_pin = serde_json::to_value(
        dreamer_extraction_verdict_source_version(&vault, first)?
            .unwrap_or_else(|| panic!("the Dreamer reads the first head")),
    )?;
    let second_pin = serde_json::to_value(
        dreamer_extraction_verdict_source_version(&vault, second)?
            .unwrap_or_else(|| panic!("the Dreamer reads the second head")),
    )?;
    let mut served: Vec<String> = Vec::new();
    for row in &listed {
        let claim = row["claim"]
            .as_str()
            .unwrap_or_else(|| panic!("the listed row names its claim"))
            .to_owned();
        assert_eq!(
            row["subject"],
            json!(owen_hex),
            "the listed row names its owen subject"
        );
        let expected = if claim == first_hex {
            &first_pin
        } else if claim == second_hex {
            &second_pin
        } else {
            panic!("the listed row names a correctable head");
        };
        assert_eq!(
            &row["version"], expected,
            "the listed row pins its live version"
        );
        served.push(claim);
    }
    served.sort();
    let mut correctable = vec![first_hex.clone(), second_hex.clone()];
    correctable.sort();
    assert_eq!(served, correctable, "both correctable heads list");
    assert!(
        !served.contains(&proposed_hex),
        "the proposed head lists nowhere"
    );
    assert_eq!(
        row_indexes(&page_candidate(&page, 0), "correctable"),
        vec![0, 1],
        "the first owen candidate corrects both listed rows"
    );
    assert_eq!(
        row_indexes(&page_candidate(&page, 1), "correctable"),
        vec![0, 1],
        "the second owen candidate corrects both listed rows"
    );
    assert!(
        row_indexes(&page_candidate(&page, 2), "correctable").is_empty(),
        "the yuki candidate corrects no listed row"
    );
    let pins: Vec<Value> = listed
        .iter()
        .map(|row| json!({"claim": row["claim"].clone(), "version": row["version"].clone()}))
        .collect();
    let head = listed[0]["claim"]
        .as_str()
        .unwrap_or_else(|| panic!("the first listed row names its claim"))
        .to_owned();
    let tail = listed[1]["claim"]
        .as_str()
        .unwrap_or_else(|| panic!("the second listed row names its claim"))
        .to_owned();
    let questions = json!([
        {"key": ["0", "0"], "options": ["none", head.clone(), tail.clone()]},
        {"key": ["1", "0"], "options": ["none", head.clone(), tail.clone()]},
    ]);
    let pack = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": observed.clone(),
        "listed": pins.clone(),
        "priors": [],
        "questions": questions,
        "earlier": [],
    });
    let contract = json!(["none", head.clone(), tail.clone()]);
    let Err(unlent) = invoke_bound_verdict(
        &binding,
        listing_verdict_request("correction", contract.clone(), pack),
    ) else {
        panic!("a checked correction pack without a loan answers model unavailable");
    };
    assert_eq!(unlent.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    let swapped = json!({
        "read": "correction",
        "part": {"kind": "whole"},
        "candidates": observed,
        "listed": [pins[1].clone(), pins[0].clone()],
        "priors": [],
        "questions": [
            {"key": ["0", "0"], "options": ["none", head.clone(), tail.clone()]},
            {"key": ["1", "0"], "options": ["none", head.clone(), tail.clone()]},
        ],
        "earlier": [],
    });
    let Err(order) = invoke_bound_verdict(
        &binding,
        listing_verdict_request("correction", contract.clone(), swapped),
    ) else {
        panic!("swapped listed pins are refused");
    };
    assert_eq!(order.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(
        order.message.as_str(),
        "the extraction pack claim pins differ from the engine's rebuilt order or versions",
        "the reversed pins refuse at the claim-pin recheck"
    );
    Ok(())
}

/// The page resolves single-valued predicates under the seeded policy, judges
/// replacement widening per prior with a missing stored source defaulting to
/// user-stated, and names per prior the operands whose identity subject and
/// predicate equal its stored ones.
#[test]
fn single_valued_and_non_widening_facts_match_the_native_policy() -> ListingTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_listing_vault(&dir)?);
    seed_extraction_single_valued_predicates(&vault, &["profile.name"])?;
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let owen = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    let stated = land_food_claim(
        &vault,
        owen,
        "green tea",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    let inferred = land_food_claim(
        &vault,
        owen,
        "black coffee",
        Some(ClaimSource::Inferred),
        ClaimApprovalStatus::Auto,
    )?;
    let imported = land_food_claim(
        &vault,
        owen,
        "oolong",
        Some(ClaimSource::Imported),
        ClaimApprovalStatus::Auto,
    )?;
    let missing = land_food_claim(&vault, owen, "jasmine", None, ClaimApprovalStatus::Auto)?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen savors green tea", "owen cooks daily"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_listing(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &listing_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 2, "both witnessed turns are served");
    let owen_hex = owen.to_hex();
    let served = invoke_observations(
        &binding,
        json!({
            "attempt": listing_attempt_hex(id),
            "now_ms": OBSERVATION_NOW_MS,
            "candidates": [
                listing_candidate(
                    &owen_hex,
                    "profile.name",
                    json!("owen"),
                    &turns[0].0,
                    turns[0].1.clone(),
                ),
                listing_candidate(
                    &owen_hex,
                    "preference.food",
                    json!("oolong"),
                    &turns[1].0,
                    turns[1].1.clone(),
                ),
            ],
        }),
    )?["value"]
        .clone();
    let page = serde_json::to_value(&served)?;
    let named = page_candidate(&page, 0);
    let food = page_candidate(&page, 1);
    assert_eq!(
        named["single_valued"],
        json!(true),
        "the seeded predicate reads single-valued"
    );
    assert_eq!(
        food["single_valued"],
        json!(false),
        "the unseeded predicate reads multi-valued"
    );
    for row in [&named, &food] {
        let meet = row["meet"]
            .as_str()
            .unwrap_or_else(|| panic!("the candidate names its meet"));
        assert_eq!(
            meet, "generated",
            "one user turn meets at the generated floor"
        );
    }
    assert_eq!(
        row_indexes(
            &page_prior(&page, &stated.to_hex()),
            "non_widening_candidates"
        ),
        Vec::<u64>::new(),
        "a user-stated prior widens beyond a generated meet"
    );
    assert_eq!(
        row_indexes(
            &page_prior(&page, &inferred.to_hex()),
            "non_widening_candidates"
        ),
        vec![0, 1],
        "an inferred prior meets both generated candidates"
    );
    assert_eq!(
        row_indexes(
            &page_prior(&page, &imported.to_hex()),
            "non_widening_candidates"
        ),
        vec![0, 1],
        "an imported prior meets both generated candidates"
    );
    assert_eq!(
        row_indexes(
            &page_prior(&page, &missing.to_hex()),
            "non_widening_candidates"
        ),
        Vec::<u64>::new(),
        "a missing source defaults to user-stated and widens"
    );
    for head in [&stated, &inferred, &imported, &missing] {
        assert_eq!(
            row_indexes(
                &page_prior(&page, &head.to_hex()),
                "subject_predicate_equal_candidates"
            ),
            vec![1],
            "only the food operand shares the food prior's subject and predicate"
        );
    }
    assert_eq!(
        page_prior(&page, &missing.to_hex())["source"],
        json!("imported"),
        "the served source falls back while the widening default stays user-stated"
    );
    Ok(())
}

/// The listed section carries claim and subject identifiers with live versions and
/// no words, and a newly landed correctable head moves the facts pin.
#[test]
fn listed_section_stays_word_free_and_pins_the_complete_facts() -> ListingTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(open_listing_vault(&dir)?);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let owen = EntityId::now();
    seed_named_person(&vault, &owen, "owen", vault.now_recorded_at())?;
    land_food_claim(
        &vault,
        owen,
        "papaya custard",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    land_food_claim(
        &vault,
        owen,
        "ginger broth",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    let witnessed =
        witness_extraction_turns(&vault, &["owen writes ginger broth to owen@example.com"])?;
    let (id, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let binding = bind_listing(&vault, &admitted)?;
    let inputs = read_bound_inputs_page(&binding, &listing_attempt_hex(id))?;
    let turns = page_turns_with_versions(&inputs);
    assert_eq!(turns.len(), 1, "the witnessed turn is served");
    let request = json!({
        "attempt": listing_attempt_hex(id),
        "now_ms": OBSERVATION_NOW_MS,
        "candidates": [
            listing_candidate(
                &owen.to_hex(),
                "profile.hobby",
                json!("ginger broth"),
                &turns[0].0,
                turns[0].1.clone(),
            ),
        ],
    });
    let served = invoke_observations(&binding, request.clone())?["value"].clone();
    let first = serde_json::to_value(&served)?;
    assert_eq!(
        first["listed"].as_array().map(Vec::len),
        Some(2),
        "the page serves two listed rows"
    );
    let listed = first["listed"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves its listed rows"))
        .clone();
    assert_eq!(listed.len(), 2, "both correctable heads list");
    for row in &listed {
        let mut keys: Vec<&str> = row
            .as_object()
            .unwrap_or_else(|| panic!("the listed row is an object"))
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys.as_slice(),
            ["claim", "subject", "version"],
            "the listed row carries identifiers with its version and no words"
        );
    }
    let serialized = serde_json::to_string(&serde_json::to_value(&first)?)?;
    for word in [
        "papaya",
        "custard",
        "ginger",
        "broth",
        "owen@example.com",
        "owen",
        "yuki",
        "preference.food",
    ] {
        assert!(
            !serialized.contains(word),
            "the serialized page carries no source word"
        );
    }
    land_food_claim(
        &vault,
        owen,
        "green tea",
        Some(ClaimSource::UserStated),
        ClaimApprovalStatus::Auto,
    )?;
    let second = invoke_observations(&binding, request)?["value"].clone();
    let relisted = second["listed"]
        .as_array()
        .unwrap_or_else(|| panic!("the page serves its listed rows"))
        .clone();
    assert_eq!(relisted.len(), 3, "the new correctable head lists");
    assert_ne!(
        first["facts_pin"], second["facts_pin"],
        "the new listed row moves the facts pin"
    );
    assert_eq!(
        first["policy_pin"], second["policy_pin"],
        "the unchanged policy keeps its pin"
    );
    Ok(())
}
