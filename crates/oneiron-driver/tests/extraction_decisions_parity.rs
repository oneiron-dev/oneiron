//! Native versus crate extraction decision parity over real vaults.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test extraction_decisions_parity`.
//! Eight bound attempts compare the native oracle to `run` on the same vault, attempt, fixture and operands: corrections, sets, skips, resolutions, identities, kept decisions, requests, reasoner calls and charges.
#![cfg(oneiron_test_support)]

#[path = "extraction_decisions/support.rs"]
mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::Vault;
use oneiron::claim::ClaimSource;
use oneiron::test_doors::extraction_decisions::{
    NativeExtractionDecisions, NativeSetOutcome, run_native_extraction_decisions,
};
use oneiron::test_doors::extraction_verdict::{
    ExtractionVerdictFixture, NativePackAnswer, fixture_charge_binding_count, fixture_charge_units,
    fixture_spent_observations,
};
use oneiron_dreamer::conflict_decisions::{DecisionEntry, Resolution};
use oneiron_dreamer::extraction_decisions::{Input, Outcome, SetOutcome, SkipRule, run};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_reply::decision_operands;
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

/// Answers paged merge versus accumulate with both finals for big values.
fn paged_script() -> Script {
    Arc::new(|call: &ParsedCall| {
        let mut out = HashMap::new();
        let state = &call.state;
        for asked in &call.questions {
            let pick = if state.get("page_answers").is_some() {
                asked.labels.first().cloned().unwrap_or_default()
            } else if state.get("final_choice").is_some() {
                asked.labels.get(1).cloned().unwrap_or_default()
            } else if asked.labels.iter().any(|label| label == "merge") {
                if state.get("page").and_then(Value::as_u64) == Some(2) {
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

/// Holds one shared parity run with both legs' outcomes.
struct ParityRun {
    /// Holds the native oracle outcome run first.
    native: NativeExtractionDecisions,
    /// Holds the crate outcome run second on the bound client.
    outcome: Outcome,
    /// Counts lent generations by family.
    counts: Arc<Counts>,
    /// Records served generation states.
    recorded: Arc<Mutex<Vec<RecordedCall>>>,
    /// Holds the bound client both observations and verdicts use.
    client: OneironClient,
    /// Names the shared admitted attempt.
    attempt: String,
    /// Holds the shared clock for observations and assembly.
    now_ms: u64,
    /// Keeps the vault alive for the bound client.
    _dir: tempfile::TempDir,
    /// Keeps the vault alive for the bound client.
    _vault: Arc<Vault>,
    /// Holds the shared fixture both legs spent through.
    lent: Arc<ExtractionVerdictFixture>,
}

/// Runs one owen reply through the native oracle first, then the crate on the same vault, attempt and fixture.
fn run_parity(
    heads: &[(&str, &str)],
    words: &[&str],
    candidates: &[(&str, Value)],
    script: Script,
    single_valued: &[&str],
) -> TestResult<ParityRun> {
    run_parity_with_values(heads, words, candidates, script, single_valued, &[])
}

/// Runs one parity case with big listed values for paging.
fn run_parity_with_values(
    heads: &[(&str, &str)],
    words: &[&str],
    candidates: &[(&str, Value)],
    script: Script,
    single_valued: &[&str],
    big_heads: &[(&str, Value)],
) -> TestResult<ParityRun> {
    let (_dir, vault) = support::open_vault()?;
    if !single_valued.is_empty() {
        support::seed_single_valued(&vault, single_valued)?;
    }
    let subject = support::seed_person(&vault, "owen")?;
    for &(predicate, value) in heads {
        support::land_head(&vault, subject, predicate, value, ClaimSource::Generated)?;
    }
    for &(predicate, value) in big_heads {
        let text = value.as_str().ok_or("a big head value is text")?;
        support::land_head(&vault, subject, predicate, text, ClaimSource::Generated)?;
    }
    let turns = support::witness_turns(&vault, words)?;
    let (counts, recorded, reasoner) = keyed(script);
    let bound = support::bind_lent_attempt(&vault, &turns, reasoner)?;
    let served = support::page_turns(&bound.page)?;
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
    let operands = decision_operands(&reply)?.operands;
    let native = run_native_extraction_decisions(
        &vault,
        &bound.admitted,
        &operands,
        bound.now_ms,
        &bound.lent,
    )?;
    let outcome = run(Input {
        client: &bound.client,
        attempt: &bound.attempt,
        now_ms: bound.now_ms,
        reply: &reply,
        config: &bound.config,
        policy_pin: &bound.policy_pin,
    })?;
    Ok(ParityRun {
        native,
        outcome,
        counts,
        recorded,
        client: bound.client,
        attempt: bound.attempt,
        now_ms: bound.now_ms,
        _dir,
        _vault: vault,
        lent: bound.lent,
    })
}

/// Maps a crate operand position to its served claim through the refreshed observations.
fn claim_of(
    observations: &oneiron_dreamer::extraction_observations::Observations,
    index: usize,
) -> TestResult<String> {
    observations
        .candidates
        .iter()
        .find(|row| row.index == index)
        .map(|row| row.claim.clone())
        .ok_or_else(|| "a crate position has no observation row".into())
}

/// Maps native resolution text to the crate resolution.
fn resolution_of(resolution: Option<&str>) -> Resolution {
    match resolution {
        Some("merge") => Resolution::Merge,
        Some("supersede") => Resolution::Supersede,
        Some("accumulate") => Resolution::Accumulate,
        Some("escalate") => Resolution::Escalate,
        _ => Resolution::NoStandingAnswer,
    }
}

/// Asserts native kept decisions equal the crate's entries in order: answer, probability, rung, question and the receipt with its measured time zeroed.
fn assert_kept(native: &[NativePackAnswer], kept: &[DecisionEntry]) -> TestResult<()> {
    assert_eq!(native.len(), kept.len());
    for (native_entry, crate_entry) in native.iter().zip(kept) {
        assert_eq!(
            native_entry.answer,
            serde_json::to_value(&crate_entry.answer)?
        );
        assert_eq!(native_entry.p, crate_entry.p);
        assert_eq!(native_entry.rung, json!(crate_entry.rung));
        assert_eq!(native_entry.question_id, crate_entry.question);
        let mut native_receipt = native_entry.receipt.clone();
        let mut crate_receipt = crate_entry.receipt.clone();
        for receipt in [&mut native_receipt, &mut crate_receipt] {
            if let Some(used) = receipt.pointer_mut("/time/used_ms") {
                *used = Value::from(0);
            }
        }
        assert!(native_receipt.pointer("/time/used_ms").is_some());
        assert_eq!(native_receipt, crate_receipt);
    }
    Ok(())
}

/// Asserts the same conflicts in the same order: member claims, prior heads, and per set the same skip rule or the same resolution, identity and kept decisions.
fn assert_sets(run: &ParityRun) -> TestResult<()> {
    let native = &run.native;
    let outcome = &run.outcome;
    let observations = read_observations(&run.client, &run.attempt, run.now_ms, &outcome.operands)?;
    assert_eq!(native.conflicts.len(), outcome.route.judge_sets.len());
    assert_eq!(native.conflicts.len(), outcome.sets.len());
    for (index, (native_set, routed)) in native
        .conflicts
        .iter()
        .zip(&outcome.route.judge_sets)
        .enumerate()
    {
        let mut members = Vec::with_capacity(routed.candidate_indexes.len());
        for position in &routed.candidate_indexes {
            members.push(claim_of(&observations, *position)?);
        }
        assert_eq!(native_set.members, members, "member claims must match");
        assert_eq!(native_set.prior_heads, routed.prior_heads);
        assert_eq!(native_set.prior_head, routed.prior_head);
        match (&native_set.outcome, &outcome.sets[index]) {
            (
                NativeSetOutcome::Skipped {
                    fast_path,
                    bound_correction,
                },
                SetOutcome::Skipped { prior_head, rule },
            ) => {
                assert_eq!(Some(prior_head), native_set.prior_head.as_ref());
                assert_eq!(*rule == SkipRule::FastPath, *fast_path);
                assert!(*fast_path || *bound_correction);
            }
            (
                NativeSetOutcome::Decided {
                    resolution,
                    identity,
                    decisions,
                },
                SetOutcome::Decided(decided),
            ) => {
                assert_eq!(resolution_of(resolution.as_deref()), decided.resolution);
                let expected_identity = match decided.identity {
                    Some(position) => Some(claim_of(&observations, position)?),
                    None => None,
                };
                assert_eq!(*identity, expected_identity);
                assert_kept(decisions, &decided.decisions)?;
            }
            _ => panic!("native skipped if and only if the crate skips"),
        }
    }
    Ok(())
}

/// Asserts the spend of both legs for `expected` native generations: native's entries first and not memoized, then the bound leg replaying each one from the memo with the same hashes in the same order, the reasoner called `expected` times in total, and the charges equal to native's tally.
fn assert_spend(run: &ParityRun, expected: usize) {
    let native = &run.native;
    assert_eq!(native.spent.len(), expected);
    for spent in &native.spent {
        assert!(!spent.memoized);
    }
    assert_eq!(native.tally_units, (expected as u64).saturating_mul(150));
    assert_eq!(native.tally_bindings, expected);
    let spent = fixture_spent_observations(&run.lent);
    assert_eq!(spent.len(), expected.saturating_mul(2));
    for (position, observation) in spent.iter().enumerate() {
        let native_entry = &native.spent[position % expected];
        assert_eq!(observation.request_hash_hex, native_entry.request_hash_hex);
        assert_eq!(observation.step_hash_hex, native_entry.step_hash_hex);
        assert!(observation.step_hash_hex.is_some());
        assert_eq!(observation.attempt_hex, native_entry.attempt_hex);
        assert_eq!(observation.input_total, 100);
        assert_eq!(observation.output_total, 50);
        if position < expected {
            assert!(!observation.memoized);
            assert_eq!(observation, native_entry);
        } else {
            assert!(observation.memoized);
        }
    }
    assert_eq!(
        run.counts
            .correction()
            .saturating_add(run.counts.resolution()),
        expected
    );
    assert_eq!(run.recorded.lock().expect("record").len(), expected);
    assert_eq!(fixture_charge_units(&run.lent), native.tally_units);
    assert_eq!(
        fixture_charge_binding_count(&run.lent),
        native.tally_bindings
    );
}

/// Asserts corrections, sets, kept decisions, requests, reasoner calls and charges for one shared run with `expected` native generations.
fn assert_parity(run: &ParityRun, expected: usize) -> TestResult<()> {
    let native = &run.native;
    let outcome = &run.outcome;
    assert_eq!(native.corrections.len(), outcome.corrections.len());
    for (left, right) in native.corrections.iter().zip(&outcome.corrections) {
        assert_eq!(left.position, right.candidate);
        assert_eq!(left.corrects, right.corrects);
        assert_kept(&left.decisions, &right.decisions)?;
    }
    assert_sets(run)?;
    assert_spend(run, expected);
    Ok(())
}

/// P1 a correction answered with the listed head, then the bound-correction skip.
#[test]
fn parity_correction_then_bound_correction_skip() -> TestResult<()> {
    let run = run_parity(
        &[("preference.food", "green tea")],
        &["owen chooses black coffee"],
        &[("preference.food", json!("black coffee"))],
        merge_script(),
        &[],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::BoundCorrection,
            ..
        }
    ));
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    assert_parity(&run, 1)
}

/// P2 a cross-predicate correction.
#[test]
fn parity_cross_predicate_correction() -> TestResult<()> {
    let run = run_parity(
        &[("preference.food", "green tea")],
        &["owen chooses black coffee"],
        &[("preference.drink", json!("black coffee"))],
        merge_script(),
        &[],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::BoundCorrection,
            ..
        }
    ));
    let refreshed =
        read_observations(&run.client, &run.attempt, run.now_ms, &run.outcome.operands)?;
    assert_eq!(refreshed.candidates[0].predicate, "preference.food");
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    assert_parity(&run, 1)
}

/// P3 two members, Merge, identity.
#[test]
fn parity_two_member_merge() -> TestResult<()> {
    let run = run_parity(
        &[],
        &["owen chooses green tea", "owen chooses black coffee"],
        &[
            ("preference.food", json!("green tea")),
            ("preference.food", json!("black coffee")),
        ],
        merge_script(),
        &[],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let SetOutcome::Decided(decided) = &run.outcome.sets[0] else {
        panic!("the merge decides");
    };
    assert_eq!(decided.resolution, Resolution::Merge);
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 1));
    assert_parity(&run, 1)
}

/// P4 64 identities: identity rounds and the identity final.
#[test]
fn parity_sixty_four_identities() -> TestResult<()> {
    let specs: Vec<(&str, Value)> = (0..64)
        .map(|n| ("preference.food", json!(format!("meal {n}"))))
        .collect();
    let run = run_parity(&[], &["owen picks meals"], &specs, merge_script(), &[])?;
    assert_eq!(run.outcome.sets.len(), 1);
    let SetOutcome::Decided(decided) = &run.outcome.sets[0] else {
        panic!("the merge decides");
    };
    assert_eq!(decided.resolution, Resolution::Merge);
    assert!(
        decided
            .decisions
            .iter()
            .any(|entry| entry.key == ["identity", "final", "1", "0"].map(str::to_owned))
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 2));
    assert_parity(&run, 2)
}

/// P5 two 50,000-character values: resolution pages, the resolution final, the identity final.
#[test]
fn parity_big_paged_resolution() -> TestResult<()> {
    let run = run_parity(
        &[],
        &["owen likes tea", "owen likes coffee"],
        &[
            ("profile.hobby", support::big_value("tea")),
            ("profile.hobby", support::big_value("coffee")),
        ],
        paged_script(),
        &[],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    let SetOutcome::Decided(decided) = &run.outcome.sets[0] else {
        panic!("the pages decide");
    };
    assert_eq!(decided.resolution, Resolution::Merge);
    assert!(
        decided
            .decisions
            .iter()
            .any(|entry| entry.key == ["resolution", "final"].map(str::to_owned))
    );
    assert!(
        decided
            .decisions
            .iter()
            .any(|entry| entry.key == ["identity", "final", "1", "0"].map(str::to_owned))
    );
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 4));
    assert_parity(&run, 4)
}

/// P6 the fast path over a seeded single-valued predicate.
#[test]
fn parity_fast_path() -> TestResult<()> {
    let run = run_parity(
        &[("profile.name", "Owen")],
        &["owen is called Alex"],
        &[("profile.name", json!("Alex"))],
        none_script(),
        &["profile.name"],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::FastPath,
            ..
        }
    ));
    assert_eq!((run.counts.correction(), run.counts.resolution()), (1, 0));
    assert_parity(&run, 1)
}

/// P7 two unrelated components.
#[test]
fn parity_two_components() -> TestResult<()> {
    let run = run_parity(
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
    assert_eq!(run.outcome.sets.len(), 2);
    for set in &run.outcome.sets {
        let SetOutcome::Decided(decided) = set else {
            panic!("each component decides");
        };
        assert_eq!(decided.resolution, Resolution::Merge);
    }
    assert_eq!((run.counts.correction(), run.counts.resolution()), (0, 2));
    assert_parity(&run, 2)
}

/// P8 correction pages and the correction final over two large heads of different predicates.
#[test]
fn parity_correction_pages_and_final() -> TestResult<()> {
    let run = run_parity_with_values(
        &[],
        &["owen chooses black coffee"],
        &[("preference.food", json!("black coffee"))],
        merge_script(),
        &[],
        &[
            ("preference.food", support::big_value("tea")),
            ("preference.drink", support::big_value("coffee")),
        ],
    )?;
    assert_eq!(run.outcome.sets.len(), 1);
    assert!(matches!(
        &run.outcome.sets[0],
        SetOutcome::Skipped {
            rule: SkipRule::BoundCorrection,
            ..
        }
    ));
    assert_eq!((run.counts.correction(), run.counts.resolution()), (3, 0));
    assert_parity(&run, 3)
}
