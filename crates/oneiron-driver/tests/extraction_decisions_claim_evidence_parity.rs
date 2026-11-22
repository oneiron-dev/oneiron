//! Native versus crate extraction correction parity for an operand that cites a listed claim
//! (FIX row LENT-CLAIM-EVIDENCE-NATIVE-ORACLE-PARITY-NO-TEST).
//!
//! #9851 taught the native decisions oracle door (`dreamer_consolidation/executor/extraction/
//! native_decisions_parity.rs`) to read an operand's `claim_evidence`: one claim locator per
//! distinct cited claim after the TURN ranges, the slice chosen as the first whose turns hold
//! every cited TURN and whose call labels every cited claim. No test called the door with claim
//! evidence. Here one reply about owen carries two operands over the same served turn: operand 0
//! restates the stated `green tea` head and cites it, and operand 1 proposes `black coffee`
//! without a citation. Native's correction read asks operand 1 alone whether it corrects the
//! head, as the step's own rule does (a candidate that cites a head and restates it is asked
//! nothing). The crate leg, the lent correction pack through the bound client, must ask the
//! same pair, list the same claim, choose the same correction with the same kept decisions, and
//! replay every native generation from the memo.
//!
//! The head is stated: a generated head cannot corroborate, and the bound check refuses a
//! citation of one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test extraction_decisions_claim_evidence_parity`.
#![cfg(oneiron_test_support)]

#[path = "extraction_decisions/support.rs"]
mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::claim::ClaimSource;
use oneiron::test_doors::extraction_decisions::run_native_extraction_decisions;
use oneiron::test_doors::extraction_verdict::{
    NativePackAnswer, dreamer_extraction_verdict_source_version, fixture_charge_binding_count,
    fixture_charge_units, fixture_spent_observations,
};
use oneiron_dreamer::conflict_decisions::DecisionEntry;
use oneiron_dreamer::extraction_decisions::{Input, run};
use oneiron_dreamer::extraction_observations::read_observations;
use oneiron_dreamer::extraction_reply::decision_operands;
use serde_json::{Value, json};
use support::{Counts, KeyedReasoner, ParsedCall, RecordedCall, Script, TestResult};

/// The predicate shared by the stored head and both operands.
const FOOD: &str = "preference.food";

/// The value of the stated head about owen, which operand 0 restates.
const HEAD_VALUE: &str = "green tea";

/// The value operand 1 proposes, which may correct the head.
const OTHER_VALUE: &str = "black coffee";

/// The words of the one witnessed turn, which name owen.
const WORDS: &str = "owen chooses black coffee";

/// Answers merge where it is offered, and otherwise the first shown candidate: a correction
/// question picks the listed head.
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

/// Asserts native kept decisions equal the crate's entries in order: answer, probability, rung,
/// question and the receipt with its measured time zeroed.
fn assert_kept(native: &[NativePackAnswer], kept: &[DecisionEntry]) -> TestResult<()> {
    assert_eq!(native.len(), kept.len(), "both legs keep as many decisions");
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
        assert_eq!(native_receipt, crate_receipt);
    }
    Ok(())
}

/// The restating operand that cites the head is asked no correction by either leg, the other
/// operand is asked about the head alone by both, and both choose the same correction.
#[test]
fn a_cited_restatement_is_asked_no_correction_by_native_or_the_lent_pack() -> TestResult<()> {
    let (_dir, vault) = support::open_vault()?;
    let subject = support::seed_person(&vault, "owen")?;
    let head = support::land_head(&vault, subject, FOOD, HEAD_VALUE, ClaimSource::UserStated)?;
    let head_hex = head.to_hex();
    let turns = support::witness_turns(&vault, &[WORDS])?;
    let counts = Arc::new(Counts::new());
    let recorded: Arc<Mutex<Vec<RecordedCall>>> = Arc::new(Mutex::new(Vec::new()));
    let reasoner = Arc::new(KeyedReasoner::new(
        merge_script(),
        Arc::clone(&counts),
        Arc::clone(&recorded),
    ));
    let bound = support::bind_lent_attempt(&vault, &turns, reasoner)?;
    let served = support::page_turns(&bound.page)?;
    let (turn, version) = served.first().ok_or("FIXTURE: the page serves the turn")?;
    let head_version = dreamer_extraction_verdict_source_version(&vault, head)?
        .ok_or("FIXTURE: the Dreamer reads the stated head")?;
    let subject_hex = subject.to_hex();
    let evidence = [(turn.clone(), version.clone(), 0, 4)];
    let mut restating =
        support::listed_candidate(0, &subject_hex, FOOD, json!(HEAD_VALUE), &evidence);
    restating["claim_evidence"] = json!([{
        "claim": head_hex,
        "version": serde_json::to_value(head_version)?,
    }]);
    let other = support::listed_candidate(1, &subject_hex, FOOD, json!(OTHER_VALUE), &evidence);
    let reply = support::decode_reply(support::reply_json(vec![restating, other], vec![]))?;
    let operands = decision_operands(&reply)?.operands;
    assert_eq!(operands.len(), 2, "FIXTURE: the reply gives two operands");
    assert_eq!(
        operands[0]["claim_evidence"][0]["claim"],
        json!(head_hex),
        "FIXTURE: operand 0 carries its claim citation"
    );
    assert!(
        operands[1].get("claim_evidence").is_none(),
        "FIXTURE: operand 1 cites no claim"
    );

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
        step: None,
        config: &bound.config,
        policy_pin: &bound.policy_pin,
    })?;

    // The listed claims and the asked pairs as the lent pack reads them.
    let observations = read_observations(&bound.client, &bound.attempt, bound.now_ms, &operands)?;
    let listed: Vec<&str> = observations
        .listed
        .iter()
        .map(|row| row.claim.as_str())
        .collect();
    assert_eq!(
        listed,
        vec![head_hex.as_str()],
        "the lent pack lists the head alone"
    );
    let correctable = |index: usize| {
        observations
            .candidates
            .iter()
            .find(|row| row.index == index)
            .map(|row| row.correctable.clone())
    };
    assert_eq!(
        correctable(0),
        Some(Vec::new()),
        "the lent pack asks the cited restatement about no head"
    );
    assert_eq!(
        correctable(1),
        Some(vec![0]),
        "the lent pack asks the other operand about the head"
    );

    // Native's correction read over the same operands.
    let native_at = |position: usize| {
        native
            .corrections
            .iter()
            .find(|row| row.position == position)
    };
    let restated = native_at(0).ok_or("native answers one row per operand")?;
    assert!(
        restated.corrects.is_none() && restated.decisions.is_empty(),
        "native asks no correction of operand 0, which cites the head and restates it, yet it \
         corrects {:?} with {} decisions",
        restated.corrects,
        restated.decisions.len()
    );
    let corrected = native_at(1).ok_or("native answers one row per operand")?;
    assert_eq!(
        corrected.corrects.as_deref(),
        Some(head_hex.as_str()),
        "native's correction read asks operand 1 about the head, and the script picks it"
    );

    // Both legs: the same correction per operand, with the same kept decisions.
    for position in 0..operands.len() {
        let native_row = native_at(position).ok_or("native answers one row per operand")?;
        match outcome
            .corrections
            .iter()
            .find(|row| row.candidate == position)
        {
            Some(crate_row) => {
                assert_eq!(
                    native_row.corrects, crate_row.corrects,
                    "operand {position}: both legs choose the same correction"
                );
                assert_kept(&native_row.decisions, &crate_row.decisions)?;
            }
            None => assert!(
                native_row.corrects.is_none() && native_row.decisions.is_empty(),
                "operand {position}: the crate asks no correction, so native asks none"
            ),
        }
    }

    // The crate leg replays each native generation from the memo, with the same hashes.
    let expected = native.spent.len();
    assert!(expected >= 1, "native asks at least the one correction");
    let spent = fixture_spent_observations(&bound.lent);
    assert_eq!(
        spent.len(),
        expected.saturating_mul(2),
        "the crate leg spends exactly the native generations again"
    );
    for (position, observation) in spent.iter().enumerate() {
        let native_entry = &native.spent[position % expected];
        assert_eq!(observation.request_hash_hex, native_entry.request_hash_hex);
        assert_eq!(observation.step_hash_hex, native_entry.step_hash_hex);
        assert_eq!(observation.memoized, position >= expected);
    }
    assert_eq!(
        counts.correction().saturating_add(counts.resolution()),
        expected,
        "the reasoner serves each native generation once"
    );
    assert_eq!(recorded.lock().map_or(0, |calls| calls.len()), expected);
    assert_eq!(fixture_charge_units(&bound.lent), native.tally_units);
    assert_eq!(
        fixture_charge_binding_count(&bound.lent),
        native.tally_bindings
    );
    Ok(())
}
