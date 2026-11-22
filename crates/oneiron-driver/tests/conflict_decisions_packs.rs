//! Checks crate-built conflict packs against the bound verdict rebuild.
//!
//! No lender is lent: checked packs wait (`MODEL_UNAVAILABLE`), one mutated
//! option is refused (`BAD_REQUEST`). No answers or model runs.

#![cfg(oneiron_test_support)]

#[path = "extraction_verdict_observed/support.rs"]
mod observed_support;
#[path = "conflict_decisions_packs/support.rs"]
mod support;

use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_MODEL_UNAVAILABLE};
use oneiron_dreamer::conflict_decisions::{
    EarlierAnswer, ExtractionCorrectionPair, ExtractionLayout, ExtractionPack, ExtractionPart,
    IdentityRound, Input, ResolutionInput, Step, correction, correction_final, correction_pages,
    correction_step, identity_final, read_layout, resolution, resolution_final, resolution_pages,
    resolution_step,
};
use oneiron_dreamer::extraction_observations::{Observations, read_observations};
use oneiron_dreamer::extraction_routing::{ExtractionRoutePlan, JudgeSet, observe_and_route};
use oneiron_remote::OneironClient;
use support::TestResult;

/// Sends `pack` and expects the checked no-loan wait.
fn unlent(client: &OneironClient, pack: &ExtractionPack) -> TestResult<()> {
    // A checked pack without a loan parks until its host lends a read
    // (crates/oneiron/src/dreamer_runner/attempt_binding/extraction_execution.rs:156-163).
    let error = support::verdict_for_pack(client, pack)
        .err()
        .ok_or("a checked pack without a loan waits on it")?;
    assert_eq!(
        error.code, MEMORY_CODE_MODEL_UNAVAILABLE,
        "{}",
        error.message
    );
    Ok(())
}

/// Sends `pack` with its first option replaced and expects a rebuild refusal.
fn mutated_option_refused(client: &OneironClient, pack: &ExtractionPack) -> TestResult<()> {
    // Native compares each key and Choice contract in order and refuses drift
    // (crates/oneiron/src/dreamer_runner/attempt_binding/extraction_evidence.rs:114-143;
    // crates/oneiron/tests/extraction_verdict.rs:122-189).
    let mut bad = pack.clone();
    bad.questions[0].options[0] = "bogus".to_owned();
    let error = support::verdict_for_pack(client, &bad)
        .err()
        .ok_or("mutated options must be refused")?;
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{}", error.message);
    Ok(())
}

/// Reads observations and routes the observed fixture's ready groups.
fn observed_plan(
    fixture: &observed_support::Fixture,
) -> TestResult<(Observations, ExtractionRoutePlan)> {
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    let (_, plan) = observe_and_route(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
        &fixture.config,
        &fixture.policy_pin,
    )?;
    Ok((observations, plan))
}

/// Builds a resolution input over `set` within the observed operand universe.
fn resolution_input<'a>(
    fixture: &'a observed_support::Fixture,
    observations: &'a Observations,
    set: &'a JudgeSet,
) -> ResolutionInput<'a> {
    ResolutionInput {
        input: Input {
            candidates: &fixture.operands,
            observations,
        },
        set,
    }
}

/// Reads observations and routes the big resolution fixture's ready groups.
fn big_resolution_plan(
    fixture: &support::BigFixture,
) -> TestResult<(Observations, ExtractionRoutePlan)> {
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    let (_, plan) = observe_and_route(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
        &fixture.config,
        &fixture.policy_pin,
    )?;
    Ok((observations, plan))
}

/// Reads observations for the big correction fixture's single operand.
fn big_correction_observations(fixture: &support::BigFixture) -> TestResult<Observations> {
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    Ok(observations)
}

/// The observed singleton beside its stated head rebuilds its crate set.
#[test]
fn observed_singleton_beside_stated_crate_whole_reaches_lender() -> TestResult<()> {
    let fixture = observed_support::fixture(true, false)?;
    let (observations, plan) = observed_plan(&fixture)?;
    // Coffee over two sessions stands observed beside the stated tea head, so
    // only juice judges (crates/oneiron-driver/tests/extraction_verdict_observed.rs:78-94).
    assert_eq!(plan.judge_sets.len(), 1);
    let set = &plan.judge_sets[0];
    assert_eq!(set.candidate_indexes, vec![1]);
    assert_eq!(set.prior_heads, vec![fixture.stated.clone()]);
    let pack = resolution(resolution_input(&fixture, &observations, set), None)?;
    // Native selects the routed conflict by its explicit ordered members
    // (crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:244-266).
    assert_eq!(pack.set_members, Some(vec![1]));
    unlent(&fixture.client, &pack)
}

/// The one-session control keeps both members and reaches its loan wait.
#[test]
fn one_session_two_members_crate_whole_reaches_lender() -> TestResult<()> {
    let fixture = observed_support::fixture(false, false)?;
    let (observations, plan) = observed_plan(&fixture)?;
    // One session qualifies nothing, so both members judge the stated head
    // (crates/oneiron-driver/tests/extraction_verdict_observed.rs:112-117).
    assert_eq!(plan.judge_sets.len(), 1);
    let set = &plan.judge_sets[0];
    assert_eq!(set.candidate_indexes, vec![0, 1]);
    assert_eq!(set.prior_heads, vec![fixture.stated.clone()]);
    let pack = resolution(resolution_input(&fixture, &observations, set), None)?;
    assert_eq!(pack.set_members, Some(vec![0, 1])); // explicit members (crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:244-266)
    unlent(&fixture.client, &pack)?;
    mutated_option_refused(&fixture.client, &pack)
}

/// Each of the two routed sets selects explicitly and reaches its loan wait.
#[test]
fn two_sets_each_explicit_crate_whole_reaches_lender() -> TestResult<()> {
    let fixture = observed_support::fixture(true, true)?;
    let (observations, plan) = observed_plan(&fixture)?;
    // One nomination component selects its shared set or observed singleton
    // (crates/oneiron-driver/tests/extraction_verdict_observed.rs:140-153).
    assert_eq!(plan.judge_sets.len(), 2);
    let shared = &plan.judge_sets[0];
    let singleton = &plan.judge_sets[1];
    assert_eq!(shared.candidate_indexes, vec![1]);
    assert_eq!(singleton.candidate_indexes, vec![0]);
    for set in [shared, singleton] {
        let pack = resolution(resolution_input(&fixture, &observations, set), None)?;
        assert_eq!(pack.set_members, Some(set.candidate_indexes.clone())); // explicit members (crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:244-266)
        unlent(&fixture.client, &pack)?;
    }
    Ok(())
}

/// The correction Whole over one listed head rebuilds its groups.
#[test]
fn correction_whole_over_single_head_reaches_lender() -> TestResult<()> {
    let fixture = observed_support::fixture(false, false)?;
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    // The stated head about the same subject lists, and listed rows drive a
    // correction pack past its pins
    // (crates/oneiron/tests/extraction_observations_listing.rs:121-133,274-306;
    // crates/oneiron/tests/extraction_verdict.rs:81-115).
    assert!(
        observations
            .listed
            .iter()
            .any(|row| row.claim == fixture.stated)
    );
    let pack = correction(
        Input {
            candidates: &fixture.operands,
            observations: &observations,
        },
        None,
    )?;
    unlent(&fixture.client, &pack)?;
    mutated_option_refused(&fixture.client, &pack)
}

/// A resolution Whole over two 50k candidates refuses its layout, then each
/// crate page built from that layout waits on its loan.
#[test]
fn big_resolution_whole_layout_then_pages_reach_lender() -> TestResult<()> {
    let fixture = support::big_resolution_fixture()?;
    let (observations, plan) = big_resolution_plan(&fixture)?;
    // Same slice with same identity and topic but different values nominates
    // one conflict (crates/oneiron/src/dreamer_consolidation/routing.rs:145-157;
    // crates/oneiron-dreamer/src/extraction_routing.rs:422-432).
    assert_eq!(plan.judge_sets.len(), 1);
    let set = &plan.judge_sets[0];
    assert_eq!(set.candidate_indexes, vec![0, 1]);
    assert!(set.prior_heads.is_empty());
    let input = ResolutionInput {
        input: Input {
            candidates: &fixture.operands,
            observations: &observations,
        },
        set,
    };
    let whole = resolution(input, None)?;
    assert_eq!(whole.set_members, Some(vec![0, 1])); // explicit members (crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:244-266)
    // Whole first; a layout refusal resubmits as pages (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:593-641,648-698).
    let Step::Ask(first) = resolution_step(input, None, &[])? else {
        return Err("the first resolution step asks Whole".into());
    };
    assert_eq!(first.part, ExtractionPart::Whole);
    // Two 50,000-character candidates refuse Whole with [[0], [1]] before any
    // loan (crates/oneiron/tests/extraction_read_layout.rs:78-120;
    // crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:648-664).
    let refused = support::verdict_for_pack(&fixture.client, &whole)
        .err()
        .ok_or("a whole over two pages refuses")?;
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{}", refused.message);
    let layout = read_layout(&refused)?;
    let expected = ExtractionLayout::ResolutionPages {
        pages: vec![vec![0], vec![1]],
    };
    assert_eq!(layout, expected);
    let pages = resolution_pages(&layout)?;
    assert_eq!(pages.len(), 2); // two pages (crates/oneiron/tests/extraction_read_layout.rs:120)
    // Pages in engine layout order (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:555-586).
    let Step::Ask(next) = resolution_step(input, Some(&layout), &[])? else {
        return Err("the layout step asks the first page".into());
    };
    assert_eq!(next.part, ExtractionPart::Page { page: 0, pages: 2 });
    for page in &pages {
        let pack = resolution(input, Some(page))?;
        unlent(&fixture.client, &pack)?;
    }
    Ok(())
}

/// A correction Whole over two 50k candidates refuses its layout, then
/// each crate page built from that layout waits on its loan.
#[test]
fn big_correction_whole_layout_then_pages_reach_lender() -> TestResult<()> {
    let fixture = support::big_candidate_correction_fixture()?;
    let observations = big_correction_observations(&fixture)?;
    // Both candidates pair with the subject's listed head in request order
    // (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:164-187;
    // large candidate rows: crates/oneiron/tests/extraction_read_layout.rs:95-96).
    assert_eq!(observations.listed.len(), 1);
    let input = Input {
        candidates: &fixture.operands,
        observations: &observations,
    };
    let whole = correction(input, None)?;
    // Whole first; a layout refusal resubmits as pages (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:593-641,648-698).
    let Step::Ask(first) = correction_step(input, None, &[])? else {
        return Err("the first correction step asks Whole".into());
    };
    assert_eq!(first.part, ExtractionPart::Whole);
    // Two 50,000-character candidate rows split their pairs into two pages
    // (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:408-456;
    // crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:593-610).
    let refused = support::verdict_for_pack(&fixture.client, &whole)
        .err()
        .ok_or("a whole over two pairs refuses")?;
    assert_eq!(refused.code, MEMORY_CODE_BAD_REQUEST, "{}", refused.message);
    let layout = read_layout(&refused)?;
    let expected = ExtractionLayout::CorrectionPages {
        pages: vec![
            vec![ExtractionCorrectionPair {
                candidate: 0,
                listed: 0,
            }],
            vec![ExtractionCorrectionPair {
                candidate: 1,
                listed: 0,
            }],
        ],
    };
    assert_eq!(layout, expected);
    let pages = correction_pages(&layout)?;
    assert_eq!(pages.len(), 2); // two pages (crates/oneiron/tests/extraction_read_layout.rs:268-269)
    // Pages in engine layout order (crates/oneiron/src/dreamer_consolidation/extraction_pack/reads.rs:555-586).
    let Step::Ask(next) = correction_step(input, Some(&layout), &[])? else {
        return Err("the layout step asks the first page".into());
    };
    assert_eq!(next.part, ExtractionPart::Page { page: 0, pages: 2 });
    for page in &pages {
        let pack = correction(input, Some(page))?;
        unlent(&fixture.client, &pack)?;
    }
    Ok(())
}

/// The resolution final over two differing page answers waits on its loan.
#[test]
fn resolution_final_over_differing_pages_reaches_lender() -> TestResult<()> {
    let fixture = support::big_resolution_fixture()?;
    let (observations, plan) = big_resolution_plan(&fixture)?;
    assert_eq!(plan.judge_sets.len(), 1); // one conflict (crates/oneiron/src/dreamer_consolidation/routing.rs:145-157)
    let input = ResolutionInput {
        input: Input {
            candidates: &fixture.operands,
            observations: &observations,
        },
        set: &plan.judge_sets[0],
    };
    // One answer per rebuilt page in page order, distinct non-escalate
    // resolutions, or native asks no final
    // (crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:224-287;
    // crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:37-59).
    let earlier = [
        EarlierAnswer {
            key: vec!["resolution".to_owned(), "page".to_owned(), "0".to_owned()],
            answer: "merge".to_owned(),
        },
        EarlierAnswer {
            key: vec!["resolution".to_owned(), "page".to_owned(), "1".to_owned()],
            answer: "accumulate".to_owned(),
        },
    ];
    let pack = resolution_final(input, &earlier)?.ok_or("differing pages read a final")?;
    // The final asks [resolution, final] over the deduped first-seen answers
    // (crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:77-83,135-143).
    assert_eq!(
        pack.questions[0].key,
        vec!["resolution".to_owned(), "final".to_owned()]
    );
    assert_eq!(
        pack.questions[0].options,
        vec!["merge".to_owned(), "accumulate".to_owned()]
    );
    unlent(&fixture.client, &pack)?;
    mutated_option_refused(&fixture.client, &pack)
}

/// The identity final over groups naming two members waits on its loan.
#[test]
fn identity_final_over_differing_groups_reaches_lender() -> TestResult<()> {
    let fixture = support::big_resolution_fixture()?;
    let (observations, plan) = big_resolution_plan(&fixture)?;
    assert_eq!(plan.judge_sets.len(), 1); // one conflict (crates/oneiron/src/dreamer_consolidation/routing.rs:145-157)
    let input = ResolutionInput {
        input: Input {
            candidates: &fixture.operands,
            observations: &observations,
        },
        set: &plan.judge_sets[0],
    };
    // Each page group names a different member, so the shortlist holds two
    // ids (crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:294-349;
    // group keys crates/oneiron/src/dreamer_consolidation/executor/merge_resolution.rs:63-75;
    // aliases crates/oneiron/src/dreamer_consolidation/extraction_pack.rs:284-307).
    let earlier = [
        EarlierAnswer {
            key: vec![
                "identity".to_owned(),
                "0".to_owned(),
                "page".to_owned(),
                "0".to_owned(),
            ],
            answer: "candidate:0".to_owned(),
        },
        EarlierAnswer {
            key: vec![
                "identity".to_owned(),
                "0".to_owned(),
                "page".to_owned(),
                "1".to_owned(),
            ],
            answer: "candidate:1".to_owned(),
        },
    ];
    let shortlist = [0, 1];
    let pack = identity_final(
        input,
        IdentityRound {
            round: 1,
            shortlist: &shortlist,
            earlier: &earlier,
        },
    )?;
    // Round one asks [identity, final, 1, 0] over none plus both members
    // (crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:80-96;
    // none when members share one predicate, finals.rs:353-361).
    assert_eq!(
        pack.questions[0].key,
        vec![
            "identity".to_owned(),
            "final".to_owned(),
            "1".to_owned(),
            "0".to_owned(),
        ]
    );
    assert_eq!(
        pack.questions[0].options,
        vec![
            "none".to_owned(),
            "candidate:0".to_owned(),
            "candidate:1".to_owned(),
        ]
    );
    unlent(&fixture.client, &pack)?;
    mutated_option_refused(&fixture.client, &pack)
}

/// The correction final over groups naming two listed claims waits on its loan.
#[test]
fn correction_final_over_differing_groups_reaches_lender() -> TestResult<()> {
    let fixture = support::big_correction_fixture()?;
    let observations = big_correction_observations(&fixture)?;
    assert_eq!(observations.listed.len(), 2); // both heads list (crates/oneiron/tests/extraction_read_layout.rs:52-72)
    let listed: Vec<String> = observations
        .listed
        .iter()
        .map(|row| row.claim.clone())
        .collect();
    let input = Input {
        candidates: &fixture.operands,
        observations: &observations,
    };
    // Each page group names a different listed claim, so the round-one
    // shortlist holds two ids
    // (crates/oneiron/src/dreamer_consolidation/extraction_pack/finals.rs:127-216;
    // group keys crates/oneiron/src/dreamer_consolidation/executor/extraction/corrections.rs:36-49).
    let earlier = [
        EarlierAnswer {
            key: vec![
                "0".to_owned(),
                "0".to_owned(),
                "page".to_owned(),
                "0".to_owned(),
            ],
            answer: listed[0].clone(),
        },
        EarlierAnswer {
            key: vec![
                "0".to_owned(),
                "0".to_owned(),
                "page".to_owned(),
                "1".to_owned(),
            ],
            answer: listed[1].clone(),
        },
    ];
    let shortlist = [0, 1];
    let pack = correction_final(
        input,
        0,
        IdentityRound {
            round: 1,
            shortlist: &shortlist,
            earlier: &earlier,
        },
    )?;
    // Round one asks [0, final, 1, 0] over none plus both listed ids
    // (crates/oneiron/src/dreamer_consolidation/executor/decisions/identity_choice.rs:80-96;
    // every group offers none, corrections.rs:80-100).
    assert_eq!(
        pack.questions[0].key,
        vec![
            "0".to_owned(),
            "final".to_owned(),
            "1".to_owned(),
            "0".to_owned()
        ]
    );
    assert_eq!(
        pack.questions[0].options,
        vec!["none".to_owned(), listed[0].clone(), listed[1].clone()]
    );
    unlent(&fixture.client, &pack)?;
    mutated_option_refused(&fixture.client, &pack)
}
