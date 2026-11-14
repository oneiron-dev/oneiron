//! Native versus crate extraction routing parity over real vaults.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test extraction_routing_parity`.
//! Four bound attempts compare `native_routes` to `observe_and_route` on the
//! same client, attempt, clock, operands and policy: exact prior attaches,
//! unequal prior judges, two siblings judge together, and a bound correction
//! exports its map while its singleton stays judged. Order preserved, no sort.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::dreamer_consolidation::selection::SelectionConfig;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_routing::native_routes;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{AttemptId, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_routing::{ExtractionRoutePlan, Route, observe_and_route};
use oneiron_dreamer::extraction_selection::{ExtractionSelectionConfig, ExtractionSelectionPlan};
use oneiron_remote::OneironClient;
use rmpv::Value as RmpValue;
use serde_json::{Value, json};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

const QUEUE_NOW: u64 = 1_000;
const INPUTS_PAGE_VERB: &str = "vault.consolidation.extraction.inputs.page";

/// Holds the live bound attempt and the policy both routers read under.
struct Fixture {
    _directory: tempfile::TempDir,
    vault: Arc<Vault>,
    client: OneironClient,
    attempt: String,
    now_ms: u64,
    operands: Vec<Value>,
    config: ExtractionSelectionConfig,
    policy_pin: String,
}

fn attempt_hex(attempt: AttemptId) -> String {
    attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn open_vault() -> TestResult<(tempfile::TempDir, Arc<Vault>)> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    vault.set_consolidation_selection(&SelectionConfig {
        soak_ms: 0,
        evidence_minimum: 1,
        ..vault.consolidation_selection()?
    })?;
    Ok((directory, vault))
}

fn land_head(
    vault: &Vault,
    subject: EntityId,
    value: &str,
    source: ClaimSource,
) -> TestResult<EntityId> {
    let head = EntityId::now();
    let mut body = ClaimBody::new(
        "preference.food",
        ClaimSubject::Entity(subject),
        RmpValue::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(source);
    body.scope_facet = vault.default_facet()?;
    let now = vault.now_recorded_at();
    vault.put_claim(
        &head,
        &body,
        TimeRange {
            start: now,
            end: now,
        },
        now,
    )?;
    Ok(head)
}

fn to_index(native: &Value) -> TestResult<BTreeMap<String, usize>> {
    let mut map = BTreeMap::new();
    for row in native["candidates"]
        .as_array()
        .ok_or("missing candidates")?
    {
        map.insert(
            row["claim"].as_str().ok_or("missing claim")?.to_owned(),
            row["index"].as_u64().ok_or("missing index")? as usize,
        );
    }
    Ok(map)
}

/// Maps native claim identifiers to original request indexes without reordering.
fn indexes(value: &Value, map: &BTreeMap<String, usize>) -> TestResult<Vec<usize>> {
    value
        .as_array()
        .ok_or("missing native claim list")?
        .iter()
        .map(|claim| {
            let claim = claim.as_str().ok_or("missing claim id")?;
            map.get(claim)
                .copied()
                .ok_or_else(|| "unknown native claim".into())
        })
        .collect()
}

/// Compares component, member and prior order and checks each route's exact set.
fn assert_sets(
    native: &Value,
    plan: &ExtractionRoutePlan,
    map: &BTreeMap<String, usize>,
) -> TestResult<BTreeSet<usize>> {
    let native_sets = native["judge_sets"]
        .as_array()
        .ok_or("missing judge sets")?;
    assert_eq!(
        native_sets.len(),
        plan.judge_sets.len(),
        "set count must match"
    );
    let mut judged = BTreeSet::new();
    for (set_index, (served, routed)) in native_sets.iter().zip(&plan.judge_sets).enumerate() {
        let members = indexes(&served["candidate_claims"], map)?;
        assert_eq!(members, routed.candidate_indexes, "member order must match");
        let heads: Vec<String> = serde_json::from_value(served["prior_heads"].clone())?;
        assert_eq!(heads, routed.prior_heads, "prior order must match");
        let head: Option<String> = serde_json::from_value(served["prior_head"].clone())?;
        assert_eq!(head, routed.prior_head, "single head must match");
        for index in &members {
            let route = plan
                .routes
                .iter()
                .find(|route| route.representative_index == *index)
                .ok_or("a judged member needs its route")?;
            assert!(
                matches!(route.choice, Route::Judge { set } if set == set_index),
                "a judged member must route to its exact set"
            );
        }
        judged.extend(members);
    }
    Ok(judged)
}

/// Compares every outside-set write choice and preserves its ready order.
fn assert_choices(
    native: &Value,
    plan: &ExtractionRoutePlan,
    map: &BTreeMap<String, usize>,
    judged: &BTreeSet<usize>,
) -> TestResult<()> {
    let choices = native["choices"].as_array().ok_or("missing choices")?;
    assert_eq!(
        choices.len() + judged.len(),
        plan.routes.len(),
        "every ready group has one native choice or set"
    );
    let claims = Value::Array(
        choices
            .iter()
            .map(|choice| choice["claim"].clone())
            .collect(),
    );
    let native_outside = indexes(&claims, map)?;
    let routed_outside: Vec<usize> = plan
        .routes
        .iter()
        .filter(|route| !matches!(route.choice, Route::Judge { .. }))
        .map(|route| route.representative_index)
        .collect();
    assert_eq!(
        native_outside, routed_outside,
        "outside write order must match"
    );
    for (choice, index) in choices.iter().zip(native_outside) {
        assert!(
            !judged.contains(&index),
            "a choice must be outside every set"
        );
        let route = plan
            .routes
            .iter()
            .find(|route| route.representative_index == index)
            .ok_or("a choice needs its route")?;
        match &route.choice {
            Route::Attach { head } => {
                assert_eq!(choice["kind"], json!("attach"));
                assert_eq!(choice["head"], json!(head));
            }
            Route::New => {
                assert_eq!(choice["kind"], json!("new"));
                assert_eq!(
                    choice["supersedes"],
                    Value::Null,
                    "native writes outside every set with no supersession"
                );
            }
            Route::AlreadyRepresented { .. } => {
                assert_eq!(choice["kind"], json!("already_represented"))
            }
            Route::Judge { .. } => return Err("an outside choice maps to a judge route".into()),
        }
    }
    Ok(())
}

/// Compares native JSON to crate plans without reordering either side.
fn assert_parity(
    native: &Value,
    selection: &ExtractionSelectionPlan,
    plan: &ExtractionRoutePlan,
) -> TestResult<()> {
    let map = to_index(native)?;
    assert_eq!(
        indexes(&native["ready"], &map)?,
        selection.ready,
        "ready order must match"
    );
    let crate_held: Vec<usize> = selection.held.iter().map(|(rep, _)| *rep).collect();
    assert_eq!(
        indexes(&native["held"], &map)?,
        crate_held,
        "held order must match"
    );
    assert_eq!(
        plan.routes.len(),
        selection.ready.len(),
        "one route per ready group"
    );
    let judged = assert_sets(native, plan, &map)?;
    let native_corrections: Vec<(usize, String)> = native["corrections"]
        .as_array()
        .ok_or("missing corrections")?
        .iter()
        .map(|row| {
            let claim = row["claim"].as_str().ok_or("missing correcting claim")?;
            let index = *map.get(claim).ok_or("unknown correcting claim")?;
            Ok((
                index,
                row["head"]
                    .as_str()
                    .ok_or("missing correction head")?
                    .to_owned(),
            ))
        })
        .collect::<TestResult<_>>()?;
    let crate_corrections: Vec<(usize, String)> = plan
        .corrections
        .iter()
        .map(|row| (row.representative_index, row.head.clone()))
        .collect();
    assert_eq!(
        native_corrections, crate_corrections,
        "corrections must match"
    );
    assert_choices(native, plan, &map, &judged)
}

fn both(fixture: &Fixture) -> TestResult<(Value, ExtractionSelectionPlan, ExtractionRoutePlan)> {
    let native = native_routes(
        &fixture.vault,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    let (selection, plan) = observe_and_route(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
        &fixture.config,
        &fixture.policy_pin,
    )?;
    assert_parity(&native, &selection, &plan)?;
    Ok((native, selection, plan))
}

#[test]
fn exact_prior_attaches() -> TestResult<()> {
    let (directory, vault) = open_vault()?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let head = land_head(&vault, subject, "green tea", ClaimSource::UserStated)?.to_hex();
    let witnessed = witness_extraction_turns(&vault, &["owen chooses green tea"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = attempt_hex(attempt_id);
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(INPUTS_PAGE_VERB, json!({"attempt": attempt}))?;
    let page = &inputs["value"];
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    let turn = witnessed.turns[0].to_hex();
    let version = page["turns"][0]["version"].clone();
    let operands = vec![json!({
        "subject": subject.to_hex(), "predicate": "preference.food",
        "value": "green tea", "evidence": [{"turn": turn, "version": version}],
    })];
    let observations = read_observations(&client, &attempt, now_ms, &operands)?;
    if !observations.priors.iter().any(|prior| prior.claim == head) {
        return Err("the prior head must be admitted before testing its route".into());
    }
    let fixture = Fixture {
        _directory: directory,
        vault,
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
    };
    let (native, _, _) = both(&fixture)?;
    assert_eq!(native["held"], json!([]), "ready, not held");
    assert_eq!(native["judge_sets"], json!([]), "no judge set");
    let choices = native["choices"].as_array().ok_or("missing choices")?;
    assert_eq!(choices.len(), 1, "one outside write");
    assert_eq!(choices[0]["kind"], json!("attach"));
    assert_eq!(choices[0]["head"], json!(head));
    Ok(())
}

#[test]
fn unequal_prior_judges_with_its_head() -> TestResult<()> {
    let (directory, vault) = open_vault()?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let head = land_head(&vault, subject, "green tea", ClaimSource::UserStated)?.to_hex();
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = attempt_hex(attempt_id);
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(INPUTS_PAGE_VERB, json!({"attempt": attempt}))?;
    let page = &inputs["value"];
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    let turn = witnessed.turns[0].to_hex();
    let version = page["turns"][0]["version"].clone();
    let operands = vec![json!({
        "subject": subject.to_hex(), "predicate": "preference.food",
        "value": "black coffee", "evidence": [{"turn": turn, "version": version}],
    })];
    let observations = read_observations(&client, &attempt, now_ms, &operands)?;
    if !observations.priors.iter().any(|prior| prior.claim == head) {
        return Err("the prior head must be admitted before testing its route".into());
    }
    let fixture = Fixture {
        _directory: directory,
        vault,
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
    };
    let (native, _, _) = both(&fixture)?;
    let sets = native["judge_sets"]
        .as_array()
        .ok_or("missing judge sets")?;
    assert_eq!(sets.len(), 1, "one conflict");
    assert_eq!(sets[0]["prior_heads"], json!([head]));
    assert_eq!(sets[0]["prior_head"], json!(head));
    assert_eq!(native["choices"], json!([]), "judged members write nothing");
    Ok(())
}

#[test]
fn two_conflicting_candidates_judge_together() -> TestResult<()> {
    let (directory, vault) = open_vault()?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(
        &vault,
        &["owen chooses green tea", "owen chooses black coffee"],
    )?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = attempt_hex(attempt_id);
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(INPUTS_PAGE_VERB, json!({"attempt": attempt}))?;
    let page = &inputs["value"];
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    let served = page["turns"].as_array().ok_or("missing turns")?;
    let subject = subject.to_hex();
    let operands = vec![
        json!({
            "subject": subject, "predicate": "preference.food", "value": "green tea",
            "evidence": [{"turn": served[0]["turn"], "version": served[0]["version"]}],
        }),
        json!({
            "subject": subject, "predicate": "preference.food", "value": "black coffee",
            "evidence": [{"turn": served[1]["turn"], "version": served[1]["version"]}],
        }),
    ];
    let fixture = Fixture {
        _directory: directory,
        vault,
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
    };
    let (native, _, _) = both(&fixture)?;
    let sets = native["judge_sets"]
        .as_array()
        .ok_or("missing judge sets")?;
    assert_eq!(sets.len(), 1, "siblings form one set");
    assert_eq!(sets[0]["prior_heads"], json!([]));
    assert_eq!(sets[0]["prior_head"], Value::Null);
    assert_eq!(native["choices"], json!([]), "judged members write nothing");
    Ok(())
}

#[test]
fn bound_correction_exports_its_map_while_judged() -> TestResult<()> {
    let (directory, vault) = open_vault()?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let head = land_head(&vault, subject, "green tea", ClaimSource::Generated)?.to_hex();
    let witnessed = witness_extraction_turns(&vault, &["owen chooses black coffee"])?;
    let (attempt_id, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, QUEUE_NOW)?;
    let attempt = attempt_hex(attempt_id);
    let client = OneironClient::for_dreamer_attempt(vault.bind_dreamer_attempt(&admitted)?);
    let now_ms = vault
        .now_recorded_at()
        .saturating_add(1)
        .saturating_mul(1_000);
    let inputs = client.agent_verb(INPUTS_PAGE_VERB, json!({"attempt": attempt}))?;
    let page = &inputs["value"];
    let policy_pin = page["policy_pin"]
        .as_str()
        .ok_or("missing policy pin")?
        .to_owned();
    let config = ExtractionSelectionConfig::from_selection(
        page["policy"]["selection"].clone(),
        &policy_pin,
    )?;
    let turn = witnessed.turns[0].to_hex();
    let version = page["turns"][0]["version"].clone();
    let operands = vec![json!({
        "subject": subject.to_hex(), "predicate": "preference.food",
        "value": "black coffee", "corrects": head,
        "evidence": [{"turn": turn, "version": version}],
    })];
    let observations = read_observations(&client, &attempt, now_ms, &operands)?;
    if !observations.priors.iter().any(|prior| prior.claim == head) {
        return Err("the generated head must be admitted before testing its correction".into());
    }
    let fixture = Fixture {
        _directory: directory,
        vault,
        client,
        attempt,
        now_ms,
        operands,
        config,
        policy_pin,
    };
    let (native, _, _) = both(&fixture)?;
    let corrections = native["corrections"]
        .as_array()
        .ok_or("missing corrections")?;
    assert_eq!(corrections.len(), 1, "the bound head is kept");
    assert_eq!(corrections[0]["head"], json!(head));
    let sets = native["judge_sets"]
        .as_array()
        .ok_or("missing judge sets")?;
    assert_eq!(
        sets.len(),
        1,
        "its singleton stays judged without executor skip"
    );
    assert_eq!(sets[0]["prior_head"], json!(head));
    assert_eq!(native["choices"], json!([]), "judged members write nothing");
    Ok(())
}
