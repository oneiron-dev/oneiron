//! Bound extraction decision orchestration over lent scripted verdicts.
//!
//! Cases 1-8 including 1b with key-based answers and call counts.

#![cfg(oneiron_test_support)]

#[path = "extraction_verdict_observed/support.rs"]
mod observed_support;
#[path = "extraction_decisions/support.rs"]
mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::Vault;
use oneiron::claim::ClaimSource;
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron_dreamer::conflict_decisions::Resolution;
use oneiron_dreamer::extraction_decisions::{Input, Outcome, SetOutcome, SkipRule, run};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_remote::OneironClient;
use serde_json::{Value, json};
use support::{Counts, KeyedReasoner, ParsedCall, RecordedCall, Script, TestResult};

/// Answers merge and the first shown candidate.
fn merge_script() -> Script {
    Arc::new(|call: &ParsedCall| {
        let mut out = HashMap::new();
        for asked in &call.questions {
            let pick = if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Answers none for corrections and merge plus the first candidate otherwise.
fn none_script() -> Script {
    Arc::new(|call: &ParsedCall| {
        let mut out = HashMap::new();
        let correction = call.state.get("listed").is_some();
        for asked in &call.questions {
            let pick = if correction {
                asked.labels.first().cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "merge") {
                "merge".to_owned()
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    })
}

/// Holds counted scripted answers and their recorded states.
fn keyed(
    script: Script,
) -> (
    Arc<Counts>,
    Arc<Mutex<Vec<RecordedCall>>>,
    Arc<KeyedReasoner>,
) {
    let counts = Arc::new(Counts::new());
    let recorded: Arc<Mutex<Vec<RecordedCall>>> = Arc::new(Mutex::new(Vec::new()));
    let reasoner = Arc::new(KeyedReasoner::new(
        script,
        Arc::clone(&counts),
        Arc::clone(&recorded),
    ));
    (counts, recorded, reasoner)
}

/// One lent run with its guards and counts.
struct Run {
    outcome: Outcome,
    counts: Arc<Counts>,
    recorded: Arc<Mutex<Vec<RecordedCall>>>,
    client: OneironClient,
    attempt: String,
    now_ms: u64,
    _dir: tempfile::TempDir,
    _vault: Arc<Vault>,
    _lent: Arc<ExtractionVerdictFixture>,
}

/// Runs one owen reply with Generated heads through the orchestration.
fn run_case(
    heads: &[(&str, &str)],
    words: &[&str],
    candidates: &[(&str, Value)],
    script: Script,
    single_valued: &[&str],
) -> TestResult<Run> {
    let (_dir, vault) = support::open_vault()?;
    if !single_valued.is_empty() {
        support::seed_single_valued(&vault, single_valued)?;
    }
    let subject = support::seed_person(&vault, "owen")?;
    for &(predicate, value) in heads {
        support::land_head(&vault, subject, predicate, value, ClaimSource::Generated)?;
    }
    let turns = support::witness_turns(&vault, words)?;
    let (counts, recorded, reasoner) = keyed(script);
    let (client, attempt, now_ms, page, config, policy_pin, lent) =
        support::bind_lent(&vault, &turns, reasoner)?;
    let served = support::page_turns(&page)?;
    let subject_hex = subject.to_hex();
    let mut built = Vec::with_capacity(candidates.len());
    for (n, (predicate, value)) in candidates.iter().enumerate() {
        let row = &served[n % served.len()];
        let evidence = [(row.0.clone(), row.1.clone(), 0, 4)];
        built.push(support::listed_candidate(
            n,
            &subject_hex,
            predicate,
            value.clone(),
            &evidence,
        ));
    }
    let reply = support::decode_reply(support::reply_json(built, vec![]))?;
    let outcome = run(Input {
        client: &client,
        attempt: &attempt,
        now_ms,
        reply: &reply,
        config: &config,
        policy_pin: &policy_pin,
    })?;
    Ok(Run {
        outcome,
        counts,
        recorded,
        client,
        attempt,
        now_ms,
        _dir,
        _vault: vault,
        _lent: lent,
    })
}

/// Case 1: correction applied, then bound-correction skip with zero conflict calls.
#[test]
fn correction_applied_then_bound_correction_skips() -> TestResult<()> {
    // Corrections precede routing (parallel.rs:437-472); lone corrected member skips (conflicts.rs:57-77; judge_context.rs:41-54).
    let run = run_case(
        &[("preference.food", "green tea")],
        &["owen chooses black coffee"],
        &[("preference.food", json!("black coffee"))],
        merge_script(),
        &[],
    )?;
    let outcome = &run.outcome;
    assert_eq!(outcome.operands.len(), 1);
    assert_eq!(outcome.candidate_indexes, vec![0]);
    assert_eq!(outcome.corrections.len(), 1);
    assert_eq!(outcome.route.corrections.len(), 1);
    assert_eq!(outcome.sets.len(), 1);
    assert!(
        matches!(&outcome.sets[0], SetOutcome::Skipped { prior_head, rule: SkipRule::BoundCorrection } if Some(prior_head) == outcome.route.judge_sets[0].prior_head.as_ref())
    );
    assert_eq!(
        outcome.corrections[0].corrects,
        outcome.route.judge_sets[0].prior_head
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    Ok(())
}

/// Case 1b: cross-predicate correction binds the head predicate and skips.
#[test]
fn cross_predicate_correction_binds_head_predicate() -> TestResult<()> {
    // Correcting inherits the head predicate (extraction.rs:505-536); set skips by bound correction (judge_context.rs:41-54).
    let run = run_case(
        &[("preference.food", "green tea")],
        &["owen chooses black coffee"],
        &[("preference.drink", json!("black coffee"))],
        merge_script(),
        &[],
    )?;
    let outcome = &run.outcome;
    assert_eq!(
        outcome.corrections[0].corrects,
        outcome.route.judge_sets[0].prior_head
    );
    let refreshed = read_observations(&run.client, &run.attempt, run.now_ms, &outcome.operands)?;
    assert_eq!(refreshed.candidates.len(), 1);
    assert_eq!(refreshed.candidates[0].predicate, "preference.food");
    assert!(
        matches!(&outcome.sets[0], SetOutcome::Skipped { prior_head, rule: SkipRule::BoundCorrection } if Some(prior_head) == outcome.route.judge_sets[0].prior_head.as_ref())
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    Ok(())
}

/// Case 2: two-member merge keeps first component member; two groups ask IdentityFinal.
#[test]
fn two_member_merge_and_identity_final() -> TestResult<()> {
    // Whole merge stands with kept identity (merge_resolution.rs:37-59); two ids ask IdentityFinal (finals.rs:294-349).
    let run = run_case(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_script(),
        &[],
    )?;
    let outcome = &run.outcome;
    assert_eq!(outcome.sets.len(), 1);
    let SetOutcome::Decided(decision) = &outcome.sets[0] else {
        panic!("the merge decides");
    };
    assert_eq!(decision.resolution, Resolution::Merge);
    assert_eq!(
        decision.identity,
        Some(outcome.route.judge_sets[0].component_indexes[0])
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 1));
    {
        let specs: Vec<(&str, Value)> = (0..64)
            .map(|n| ("preference.food", json!(format!("meal {n}"))))
            .collect();
        let run = run_case(&[], &["owen picks meals"], &specs, merge_script(), &[])?;
        let (outcome, counts, recorded) = (&run.outcome, &run.counts, &run.recorded);
        assert_eq!(outcome.sets.len(), 1);
        let SetOutcome::Decided(decision) = &outcome.sets[0] else {
            panic!("the merge decides");
        };
        assert_eq!(decision.resolution, Resolution::Merge);
        assert_eq!(
            decision.identity,
            Some(outcome.route.judge_sets[0].component_indexes[0])
        );
        assert!(
            decision
                .decisions
                .iter()
                .any(|entry| entry.key == ["identity", "final", "1", "0"].map(str::to_owned))
        );
        assert_eq!((counts.correction(), counts.resolution()), (0, 2));
        let states = recorded.lock().expect("record");
        assert!(
            states
                .iter()
                .any(|call| call.state.get("final_choice").is_some())
        );
    }
    Ok(())
}

/// Case 3: big values page, then differing pages ask both finals.
#[test]
fn big_paged_resolution_final_and_identity_final() -> TestResult<()> {
    // 50k values refuse Whole with [[0],[1]] (extraction_read_layout.rs:78-120); differing pages ask both finals (finals.rs:224-287,294-349).
    let script: Script = Arc::new(|call: &ParsedCall| {
        let mut out = HashMap::new();
        let state = &call.state;
        for asked in &call.questions {
            let pick = if state.get("page_answers").is_some() {
                asked.labels.first().cloned().unwrap_or_default()
            } else if state.get("final_choice").is_some() {
                asked.labels.get(1).cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "merge") {
                if state.get("page").and_then(|page| page.as_u64()) == Some(2) {
                    "accumulate".to_owned()
                } else {
                    "merge".to_owned()
                }
            } else {
                asked.labels.get(1).cloned().unwrap_or_default()
            };
            out.insert(asked.id.clone(), pick);
        }
        out
    });
    let run = run_case(
        &[],
        &["owen likes tea", "owen likes coffee"],
        &[
            ("profile.hobby", support::big_value("tea")),
            ("profile.hobby", support::big_value("coffee")),
        ],
        script,
        &[],
    )?;
    let outcome = &run.outcome;
    assert_eq!(outcome.sets.len(), 1);
    let SetOutcome::Decided(decision) = &outcome.sets[0] else {
        panic!("the pages decide");
    };
    assert_eq!(decision.resolution, Resolution::Merge);
    assert_eq!(
        decision.identity,
        Some(outcome.route.judge_sets[0].component_indexes[0])
    );
    assert!(
        decision
            .decisions
            .iter()
            .any(|entry| entry.key == ["resolution", "final"].map(str::to_owned))
    );
    assert!(
        decision
            .decisions
            .iter()
            .any(|entry| entry.key == ["identity", "final", "1", "0"].map(str::to_owned))
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 4));
    let states = run.recorded.lock().expect("record");
    assert!(
        states
            .iter()
            .any(|call| call.state.get("page_answers").is_some())
    );
    Ok(())
}

/// Case 4: fast-path set asks no resolution verdict.
#[test]
fn fast_path_asks_no_resolution() -> TestResult<()> {
    // One member, single-valued retained predicate, non-widening prior skips (judge_context.rs:9-26); head recorded where native sets supersedes (conflicts.rs:68-77).
    let run = run_case(
        &[("profile.name", "Owen")],
        &["owen is called Alex"],
        &[("profile.name", json!("Alex"))],
        none_script(),
        &["profile.name"],
    )?;
    let outcome = &run.outcome;
    let served = read_observations(&run.client, &run.attempt, run.now_ms, &outcome.operands)?;
    assert!(served.candidates.iter().all(|row| row.single_valued));
    assert_eq!(outcome.sets.len(), 1);
    assert!(
        matches!(&outcome.sets[0], SetOutcome::Skipped { prior_head, rule: SkipRule::FastPath } if Some(prior_head) == outcome.route.judge_sets[0].prior_head.as_ref())
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    Ok(())
}

/// Case 5: unlent run ends with MODEL_UNAVAILABLE and no partial result.
#[test]
fn unlent_returns_model_unavailable() -> TestResult<()> {
    // No loan parks the whole run (extraction_execution.rs:59-62,138-161).
    let fixture = observed_support::fixture(false, false)?;
    let observations = read_observations(
        &fixture.client,
        &fixture.attempt,
        fixture.now_ms,
        &fixture.operands,
    )?;
    assert!(
        observations
            .candidates
            .iter()
            .any(|row| !row.correctable.is_empty())
    );
    let mut candidates = Vec::with_capacity(fixture.operands.len());
    for (index, operand) in fixture.operands.iter().enumerate() {
        let subject = operand["subject"].as_str().ok_or("missing subject")?;
        let predicate = operand["predicate"].as_str().ok_or("missing predicate")?;
        let value = operand["value"].clone();
        let mut evidence = Vec::new();
        for cited in operand["evidence"].as_array().ok_or("missing evidence")? {
            evidence.push((
                cited["turn"].as_str().ok_or("missing turn")?.to_owned(),
                cited["version"].clone(),
                0,
                4,
            ));
        }
        candidates.push(support::listed_candidate(
            index, subject, predicate, value, &evidence,
        ));
    }
    let reply = support::decode_reply(support::reply_json(candidates, vec![]))?;
    let error = run(Input {
        client: &fixture.client,
        attempt: &fixture.attempt,
        now_ms: fixture.now_ms,
        reply: &reply,
        config: &fixture.config,
        policy_pin: &fixture.policy_pin,
    })
    .expect_err("no ladder");
    assert_eq!(error.code(), Some("MODEL_UNAVAILABLE"));
    Ok(())
}

/// Case 6: declared subject never becomes an operand and is never asked.
#[test]
fn declared_subject_never_operand() -> TestResult<()> {
    // Declared subjects stay pending, never operands (observe_groups; verdict_operands skips Declared).
    let (_dir, vault) = support::open_vault()?;
    let subject = support::seed_person(&vault, "owen")?;
    support::land_head(
        &vault,
        subject,
        "preference.food",
        "green tea",
        ClaimSource::Generated,
    )?;
    let turns = support::witness_turns(&vault, &["owen chooses black coffee", "yuki chooses tea"])?;
    let (counts, _recorded, reasoner) = keyed(merge_script());
    let (client, attempt, now_ms, page, config, policy_pin, lent) =
        support::bind_lent(&vault, &turns, reasoner)?;
    let _lent = lent;
    let served = support::page_turns(&page)?;
    let subject_hex = subject.to_hex();
    let first = [(served[0].0.clone(), served[0].1.clone(), 0, 4)];
    let second = [(served[1].0.clone(), served[1].1.clone(), 0, 4)];
    let listed = support::listed_candidate(
        0,
        &subject_hex,
        "preference.food",
        json!("black coffee"),
        &first,
    );
    let declared = support::declared_candidate(1, 1, "preference.food", json!("tea"), &second);
    let persons = vec![json!({"declared": 1, "name": "yuki", "turns": [served[1].0.clone()]})];
    let reply = support::decode_reply(support::reply_json(vec![listed, declared], persons))?;
    let outcome = run(Input {
        client: &client,
        attempt: &attempt,
        now_ms,
        reply: &reply,
        config: &config,
        policy_pin: &policy_pin,
    })?;
    assert_eq!(outcome.operands.len(), 1);
    assert_eq!(outcome.candidate_indexes, vec![0]);
    assert_eq!(outcome.corrections.len(), 1);
    assert!(
        matches!(&outcome.sets[0], SetOutcome::Skipped { prior_head, rule: SkipRule::BoundCorrection } if Some(prior_head) == outcome.route.judge_sets[0].prior_head.as_ref())
    );
    assert_eq!((counts.correction(), counts.resolution()), (1, 0));
    Ok(())
}

/// Case 7: two unrelated components each decide through their own exact array.
#[test]
fn two_components_each_decided() -> TestResult<()> {
    // Separate predicates nominate separately without vectors (routing.rs:147-170); each set reads its component or coverage refuses (reads.rs:469-499).
    let run = run_case(
        &[],
        &[
            "owen chooses green tea",
            "owen chooses black coffee",
            "owen drinks water",
            "owen drinks juice",
        ],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
            ("preference.drink", json!("water")),
            ("preference.drink", json!("juice")),
        ],
        merge_script(),
        &[],
    )?;
    let outcome = &run.outcome;
    assert_eq!(outcome.sets.len(), 2);
    for (position, set) in outcome.sets.iter().enumerate() {
        let SetOutcome::Decided(decision) = set else {
            panic!("each component decides");
        };
        assert_eq!(decision.resolution, Resolution::Merge);
        assert_eq!(
            decision.identity,
            Some(outcome.route.judge_sets[position].component_indexes[0])
        );
    }
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 2));
    let states = run.recorded.lock().expect("record");
    assert_eq!(states.len(), 2);
    for call in states.iter() {
        let members = call.state["candidates"]
            .as_array()
            .ok_or("missing candidates")?;
        assert_eq!(members.len(), 2);
    }
    Ok(())
}

/// Case 8: a folded duplicate pair before a fast-path candidate keeps request positions.
#[test]
fn union_read_keeps_fast_path_positions() -> TestResult<()> {
    // The union read names compact positions; remap_indexes restores request positions for the
    // prior's pair lists, so the lone member at position 2 still skips (judge_context.rs:9-26).
    // The shipped manifest has no single-valued predicate, so the fixture seeds one, as case 4 does.
    let run = run_case(
        &[("profile.name", "Owen")],
        &[
            "owen chooses green tea",
            "owen chooses green tea again",
            "owen is called Alex",
        ],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("green tea")),
            ("profile.name", json!("Alex")),
        ],
        none_script(),
        &["profile.name"],
    )?;
    let outcome = &run.outcome;
    assert_eq!(outcome.operands.len(), 3);
    assert_eq!(outcome.selection.groups.len(), 2);
    assert_eq!(outcome.selection.groups[0].member_indexes, vec![0, 1]);
    assert_eq!(outcome.selection.groups[1].member_indexes, vec![2]);
    assert_eq!(outcome.route.judge_sets.len(), 1);
    assert_eq!(outcome.route.judge_sets[0].candidate_indexes, vec![2]);
    assert_eq!(outcome.sets.len(), 1);
    assert!(
        matches!(&outcome.sets[0], SetOutcome::Skipped { prior_head, rule: SkipRule::FastPath } if Some(prior_head) == outcome.route.judge_sets[0].prior_head.as_ref())
    );
    assert_eq!(run.counts.resolution(), 0);
    Ok(())
}
