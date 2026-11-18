//! Checks crate-routed observed preferences against the engine's bound verdict rebuild.
#![cfg(oneiron_test_support)]

#[path = "extraction_verdict_observed/support.rs"]
mod support;

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_routing::{ExtractionRoutePlan, Route, observe_and_route};
use serde_json::{Value, json};
use support::{Fixture, TestResult, fixture};

/// Checks qualification and ready order before using the crate's routed sets.
fn routes(fixture: &Fixture, observed: bool) -> TestResult<ExtractionRoutePlan> {
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    assert_eq!(observations.candidates.len(), 2);
    let coffee = observations
        .candidates
        .iter()
        .find(|candidate| candidate.index == 0)
        .ok_or("missing coffee observation")?;
    let juice = observations
        .candidates
        .iter()
        .find(|candidate| candidate.index == 1)
        .ok_or("missing juice observation")?;
    assert_eq!(coffee.observed, observed);
    assert!(!juice.observed, "one session cannot qualify juice");
    let (selection, plan) = observe_and_route(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
        &fixture.config,
        &fixture.policy_pin,
    )?;
    assert_eq!(selection.ready, vec![0, 1]);
    assert!(selection.held.is_empty());
    assert_eq!(selection.groups.len(), 2);
    Ok(plan)
}

/// Builds native whole-read questions with aliases into the unchanged operand universe.
fn whole_pack(
    fixture: &Fixture,
    members: &[usize],
    heads: &[String],
    selected: Option<&[usize]>,
) -> TestResult<Value> {
    let mut identities = vec!["none".to_owned()];
    identities.extend(members.iter().map(|index| format!("candidate:{index}")));
    let mut pack = json!({
        "read": "resolution",
        "part": {"kind": "whole"},
        "candidates": fixture.operands,
        "listed": [],
        "priors": fixture.prior_pins(heads)?,
        "questions": [
            {"key": ["resolution"], "options": ["merge", "supersede", "accumulate", "escalate"]},
            {"key": ["identity", "0"], "options": identities},
        ],
        "earlier": [],
    });
    if let Some(members) = selected {
        pack["set_members"] = json!(members);
    }
    Ok(pack)
}

/// Accepts the crate's B-only set while retaining observed A as nomination context.
#[test]
fn observed_member_beside_stated_head_rebuilds_the_crate_set() -> TestResult<()> {
    let fixture = fixture(true, false)?;
    let plan = routes(&fixture, true)?;
    assert_eq!(plan.judge_sets.len(), 1);
    let set = &plan.judge_sets[0];
    assert_eq!(set.candidate_indexes, vec![1]);
    assert_eq!(set.prior_heads, vec![fixture.stated.clone()]);
    assert_eq!(set.prior_head.as_deref(), Some(fixture.stated.as_str()));
    let coffee = plan
        .routes
        .iter()
        .find(|route| route.representative_index == 0)
        .ok_or("missing coffee route")?;
    assert_eq!(
        coffee.choice,
        Route::ObservedBeside {
            stated_heads: vec![fixture.stated.clone()],
        }
    );
    let pack = whole_pack(&fixture, &set.candidate_indexes, &set.prior_heads, None)?;
    let error = fixture
        .verdict(pack)
        .err()
        .ok_or("an unlent verdict must refuse after rebuilding the checked pack")?;
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{}",
        error.message
    );
    Ok(())
}

/// Keeps both ordinary members and refuses a contract that silently omits B's sibling.
#[test]
fn one_session_control_requires_both_conflict_members() -> TestResult<()> {
    let fixture = fixture(false, false)?;
    let plan = routes(&fixture, false)?;
    assert_eq!(plan.judge_sets.len(), 1);
    let set = &plan.judge_sets[0];
    assert_eq!(set.candidate_indexes, vec![0, 1]);
    assert_eq!(set.prior_heads, vec![fixture.stated.clone()]);
    let pack = whole_pack(&fixture, &set.candidate_indexes, &set.prior_heads, None)?;
    let error = fixture
        .verdict(pack)
        .err()
        .ok_or("an unlent verdict must refuse after rebuilding the checked pack")?;
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{}",
        error.message
    );
    let omitted = whole_pack(&fixture, &[1], &set.prior_heads, None)?;
    let error = fixture
        .verdict(omitted)
        .err()
        .ok_or("an incomplete identity contract must be refused")?;
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{}", error.message);
    Ok(())
}

/// Selects either set from one nomination component and refuses ambiguous omission.
#[test]
fn one_component_selects_its_shared_set_or_observed_singleton() -> TestResult<()> {
    let fixture = fixture(true, true)?;
    let plan = routes(&fixture, true)?;
    let generated = fixture.generated.as_ref().ok_or("missing generated head")?;
    let mut both_heads = vec![generated.clone(), fixture.stated.clone()];
    both_heads.sort();
    assert_eq!(plan.judge_sets.len(), 2);
    let shared = &plan.judge_sets[0];
    let singleton = &plan.judge_sets[1];
    assert_eq!(shared.candidate_indexes, vec![1]);
    assert_eq!(shared.prior_heads, both_heads);
    assert_eq!(shared.prior_head, None);
    assert_eq!(singleton.candidate_indexes, vec![0]);
    assert_eq!(singleton.prior_heads, vec![generated.clone()]);
    assert_eq!(singleton.prior_head.as_deref(), Some(generated.as_str()));
    assert_eq!(shared.identity_token, singleton.identity_token);
    let selected = whole_pack(&fixture, &[1], &shared.prior_heads, Some(&[1]))?;
    let error = fixture
        .verdict(selected)
        .err()
        .ok_or("the selected shared set must reach the absent lender")?;
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{}",
        error.message
    );
    let selected = whole_pack(&fixture, &[0], &singleton.prior_heads, Some(&[0]))?;
    let error = fixture
        .verdict(selected)
        .err()
        .ok_or("the selected singleton must reach the absent lender")?;
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{}",
        error.message
    );
    let ambiguous = whole_pack(&fixture, &[1], &shared.prior_heads, None)?;
    let error = fixture
        .verdict(ambiguous)
        .err()
        .ok_or("two routed sets require an explicit selector")?;
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{}", error.message);
    Ok(())
}
