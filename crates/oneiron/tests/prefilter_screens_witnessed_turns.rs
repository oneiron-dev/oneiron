//! The Dreamer's prefilter screen scores a chat TURN on its MESSAGE words.
//!
//! A witnessed TURN stores no words of its own; the screen scores the words
//! extraction would read for it (its visible MESSAGE rows joined in order),
//! skips it under a threshold above zero, passes unscored a TURN the
//! Dreamer's read withholds, and still drops nothing under the default.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test prefilter_screens_witnessed_turns`.
#![cfg(oneiron_test_support)]

use oneiron::dreamer_consolidation::{
    ConsolidationWatermark, WorkingSetTurn, enqueue_partition_attempts,
};
use oneiron::dreamer_prefilter::{
    PREFILTER_DECISION_SKIP, PREFILTER_OUTCOME_SCREENED, PREFILTER_PHASE, PrefilterConfig,
    estimated_prompt_tokens,
};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{set_extraction_prefilter, witness_extraction_turns};
use oneiron::{
    DreamerConsolidationScope, EdgeActorClass, EntityId, TimeRange, Vault, plan_partitions,
    read_watermark, scan_dirty_turns, screen_turn_inputs,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Returns a fixture or assertion error without hiding its source.
type PrefilterWitnessedTurnsTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// The thin chat TURN's words: one filler word, so it scores far below the rich one.
const THIN_WORDS: &str = "ok";

/// The rich chat TURN's words: a long sentence of varied words naming people and places.
const RICH_WORDS: &str = "Mika and Owen signed the lease on the Shimokitazawa apartment near Kyoto \
    Station after Priya confirmed the Tuesday inspection";

/// The order-0 MESSAGE's words of the three-message TURN.
const ORDER_ZERO_WORDS: &str = "Yuki confirmed the Tuesday inspection with Priya";

/// The order-1 MESSAGE's words of the three-message TURN.
const ORDER_ONE_WORDS: &str = "Owen signed the Shimokitazawa lease after the inspection";

/// The hidden MESSAGE's words: many more than the two visible rows hold together.
const HIDDEN_WORDS: &str = "Priya mapped every shelved atlas in the Kyoto archive while Mika \
    photographed the Shimokitazawa timetables, and Owen catalogued Tuesday inspections across \
    twelve stations before the ferry timetables changed again at midnight";

/// The words of the TURN whose MESSAGE the Dreamer's read withholds.
const WITHHELD_WORDS: &str = "call me owen";

/// The prefilter receipt `fields` keys, as literals: the `FIELD_PREFILTER_*`
/// constants (`crates/oneiron/src/store/receipt_row.rs`) are crate-private.
const PHASE: &str = "phase";
/// What the screen ruled on the receipt's row: `skip`, or `screened` on a rollup.
const DECISION: &str = "decision";
/// The TURN's screening score, formatted `{:.6}`.
const SCORE: &str = "score";
/// The threshold the score was ruled against, formatted `{:.6}`.
const THRESHOLD: &str = "threshold";
/// The prompt tokens not spent, as a plain integer.
const TOKENS_SAVED: &str = "tokens_saved";
/// The screened TURN, lower hex; skip receipts only.
const TURN: &str = "turn";
/// How many TURNs the round screened, as a plain integer; rollups only.
const SCANNED: &str = "scanned";
/// How many TURNs the round kept, as a plain integer; rollups only.
const PASSED: &str = "passed";
/// How many TURNs the round screened out, as a plain integer; rollups only.
const SKIPPED: &str = "skipped";
/// The prefix of the per-axis feature keys, each formatted `{:.6}`.
const FEATURE_PREFIX: &str = "features.";

/// Opens the Dreamer fixture vault the consolidation door witnesses into.
fn open_prefilter_vault(dir: &tempfile::TempDir) -> PrefilterWitnessedTurnsTestResult<Vault> {
    Ok(open_dreamer_vault(dir.path(), "owen")?)
}

/// Scans the Micro dirty set the way the consolidation door does, and returns
/// the scan with the watermark it was read under.
fn scan_micro_turns(
    vault: &Vault,
) -> PrefilterWitnessedTurnsTestResult<(ConsolidationWatermark, Vec<WorkingSetTurn>)> {
    let watermark = read_watermark(vault, DreamerConsolidationScope::Micro)?;
    let scan = scan_dirty_turns(vault, DreamerConsolidationScope::Micro, &watermark, 10)?;
    Ok((watermark, scan))
}

/// Returns the TURN ids the committed-state preview keeps, in plan order.
fn planned_turn_ids(
    vault: &Vault,
    dirty: &[WorkingSetTurn],
    watermark: &ConsolidationWatermark,
) -> PrefilterWitnessedTurnsTestResult<Vec<EntityId>> {
    let plans = plan_partitions(vault, DreamerConsolidationScope::Micro, dirty, watermark)?;
    Ok(plans
        .iter()
        .flat_map(|plan| plan.turns.iter().map(|turn| turn.turn_id))
        .collect())
}

/// Returns the prefilter's Extraction receipts split into skips and rounds, by decision.
fn prefilter_receipts(
    vault: &Vault,
) -> PrefilterWitnessedTurnsTestResult<(Vec<ReceiptRecord>, Vec<ReceiptRecord>)> {
    let mut skips = Vec::new();
    let mut rounds = Vec::new();
    for receipt in vault.receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))? {
        match receipt.fields.get(DECISION).map(String::as_str) {
            Some(PREFILTER_DECISION_SKIP) => skips.push(receipt),
            Some(PREFILTER_OUTCOME_SCREENED) => rounds.push(receipt),
            other => panic!("a prefilter receipt decides skip or screened, found {other:?}"),
        }
    }
    Ok((skips, rounds))
}

/// A threshold between the thin and rich scores skips the thin chat TURN and
/// keeps the rich one, in the preview and in the enqueue alike, with one skip
/// receipt carrying the thin verdict and a rollup counting the round; fails
/// without the change because both TURNs pass unscored and no receipt exists.
#[test]
fn a_threshold_above_zero_skips_a_thin_chat_turn_and_keeps_a_rich_one()
-> PrefilterWitnessedTurnsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_prefilter_vault(&dir)?;
    let witnessed = witness_extraction_turns(&vault, &[THIN_WORDS, RICH_WORDS])?;
    let thin = witnessed.turns[0];
    let rich = witnessed.turns[1];
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 2, "the scan holds the thin and the rich TURN");
    let words = BTreeMap::from([(thin, THIN_WORDS), (rich, RICH_WORDS)]);
    let inputs: Vec<(WorkingSetTurn, Option<String>)> = scan
        .iter()
        .map(|turn| {
            let Some(text) = words.get(&turn.turn_id) else {
                panic!("the scan holds only the two witnessed TURNs");
            };
            (*turn, Some((*text).to_owned()))
        })
        .collect();
    let uncut = screen_turn_inputs(&PrefilterConfig::default(), &inputs, &BTreeSet::new());
    let Some(thin_scored) = uncut.verdicts.iter().find(|entry| entry.turn_id == thin) else {
        panic!("the default screen rules the thin TURN");
    };
    let Some(rich_scored) = uncut.verdicts.iter().find(|entry| entry.turn_id == rich) else {
        panic!("the default screen rules the rich TURN");
    };
    let thin_score = thin_scored.verdict.score;
    let rich_score = rich_scored.verdict.score;
    assert!(
        thin_score + 0.05 < rich_score,
        "the thin/rich fixture must separate by a clear margin: thin {thin_score} rich {rich_score}"
    );
    let threshold = f32::midpoint(thin_score, rich_score);
    set_extraction_prefilter(
        &vault,
        &PrefilterConfig {
            threshold,
            ..PrefilterConfig::default()
        },
    )?;
    let policy = vault.prefilter_config()?;
    assert_eq!(
        policy.threshold, threshold,
        "the door stores the threshold the planner reads"
    );
    assert!(policy.enabled, "the door leaves the screen enabled");
    let expected = screen_turn_inputs(&policy, &inputs, &BTreeSet::new());
    let Some(thin_expected) = expected.verdicts.iter().find(|entry| entry.turn_id == thin) else {
        panic!("the midpoint screen rules the thin TURN");
    };
    let Some(rich_expected) = expected.verdicts.iter().find(|entry| entry.turn_id == rich) else {
        panic!("the midpoint screen rules the rich TURN");
    };
    assert!(
        !thin_expected.verdict.pass,
        "the midpoint skips the thin TURN"
    );
    assert!(
        rich_expected.verdict.pass,
        "the midpoint keeps the rich TURN"
    );
    assert_eq!(
        planned_turn_ids(&vault, &scan, &watermark)?,
        vec![rich],
        "the preview plans the rich TURN and not the thin one"
    );
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert_eq!(skips.len(), 1, "one TURN is skipped");
    assert_eq!(rounds.len(), 1, "one round is rolled up");
    let thin_hex = thin.to_hex();
    let score = thin_expected.verdict.score;
    let score_text = format!("{score:.6}");
    let stored = policy.threshold;
    let threshold_text = format!("{stored:.6}");
    let tokens = thin_expected.verdict.estimated_tokens.to_string();
    let skip = &skips[0];
    assert_eq!(
        skip.fields.get(PHASE).map(String::as_str),
        Some(PREFILTER_PHASE),
        "the skip receipt names the prefilter phase"
    );
    assert_eq!(
        skip.fields.get(DECISION).map(String::as_str),
        Some(PREFILTER_DECISION_SKIP),
        "the skip receipt decides skip"
    );
    assert_eq!(
        skip.fields.get(TURN),
        Some(&thin_hex),
        "the skip receipt names the thin TURN"
    );
    assert_eq!(
        skip.fields.get(SCORE),
        Some(&score_text),
        "the skip receipt carries the thin score"
    );
    assert_eq!(
        skip.fields.get(THRESHOLD),
        Some(&threshold_text),
        "the skip receipt carries the midpoint threshold"
    );
    assert_eq!(
        skip.fields.get(TOKENS_SAVED),
        Some(&tokens),
        "the skip receipt carries the thin token estimate"
    );
    for (name, value) in &thin_expected.verdict.features {
        let axis = format!("{value:.6}");
        assert_eq!(
            skip.fields.get(&format!("{FEATURE_PREFIX}{name}")),
            Some(&axis),
            "the skip receipt carries the {name} axis"
        );
    }
    assert_eq!(
        skip.fields
            .keys()
            .filter(|key| key.starts_with(FEATURE_PREFIX))
            .count(),
        thin_expected.verdict.features.len(),
        "the skip receipt carries every axis and no other"
    );
    let round = &rounds[0];
    assert_eq!(
        round.fields.get(DECISION).map(String::as_str),
        Some(PREFILTER_OUTCOME_SCREENED),
        "the round receipt is a screening rollup"
    );
    let scanned = expected.scanned.to_string();
    let passed = expected.passed.to_string();
    let skipped = expected.skipped.to_string();
    let saved = expected.estimated_tokens_saved.to_string();
    assert_eq!(
        round.fields.get(SCANNED),
        Some(&scanned),
        "the round receipt counts the scanned TURNs"
    );
    assert_eq!(
        round.fields.get(PASSED),
        Some(&passed),
        "the round receipt counts the kept TURNs"
    );
    assert_eq!(
        round.fields.get(SKIPPED),
        Some(&skipped),
        "the round receipt counts the skipped TURNs"
    );
    assert_eq!(
        round.fields.get(TOKENS_SAVED),
        Some(&saved),
        "the round receipt carries the saved token estimate"
    );
    assert_eq!(
        round.fields.get(THRESHOLD),
        Some(&threshold_text),
        "the round receipt carries the midpoint threshold"
    );
    Ok(())
}

/// The screen scores one TURN on its visible MESSAGE rows joined by order with
/// `"\n"`, leaving the hidden row out: the skip receipt matches the scorer's
/// verdict over exactly that join; fails without the change, which scores no
/// chat TURN and writes no receipt.
#[test]
fn the_screen_scores_the_joined_words_of_a_turns_visible_messages()
-> PrefilterWitnessedTurnsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_prefilter_vault(&dir)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let conversation = EntityId::now();
    let turn = EntityId::now();
    let message = |order: u32, content: &str, is_visible: bool| WitnessMessage {
        id: Some(EntityId::now().to_hex()),
        author: WitnessAuthor::Companion,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        parts: None,
        metadata: None,
        is_visible,
        order,
        quote: None,
    };
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![
                message(1, ORDER_ONE_WORDS, true),
                message(0, ORDER_ZERO_WORDS, true),
                message(2, HIDDEN_WORDS, false),
            ],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })?;
    set_extraction_prefilter(
        &vault,
        &PrefilterConfig {
            threshold: 1.0,
            ..PrefilterConfig::default()
        },
    )?;
    let policy = vault.prefilter_config()?;
    assert_eq!(
        policy.threshold, 1.0,
        "the door stores the perfect threshold"
    );
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 1, "the scan holds the three-message TURN");
    let joined = format!("{ORDER_ZERO_WORDS}\n{ORDER_ONE_WORDS}");
    let inputs = vec![(scan[0], Some(joined.clone()))];
    let expected = screen_turn_inputs(&policy, &inputs, &BTreeSet::new());
    let [ruling] = expected.verdicts.as_slice() else {
        panic!("the joined screen rules the one TURN");
    };
    assert!(
        !ruling.verdict.pass,
        "a perfect threshold skips the scored TURN"
    );
    assert!(
        planned_turn_ids(&vault, &scan, &watermark)?.is_empty(),
        "the preview skips the three-message TURN"
    );
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert_eq!(skips.len(), 1, "one TURN is skipped");
    assert_eq!(rounds.len(), 1, "one round is rolled up");
    let turn_hex = turn.to_hex();
    let score = ruling.verdict.score;
    let score_text = format!("{score:.6}");
    let threshold = policy.threshold;
    let threshold_text = format!("{threshold:.6}");
    let tokens = ruling.verdict.estimated_tokens.to_string();
    let skip = &skips[0];
    assert_eq!(
        skip.fields.get(TURN),
        Some(&turn_hex),
        "the skip receipt names the three-message TURN"
    );
    assert_eq!(
        skip.fields.get(SCORE),
        Some(&score_text),
        "the skip receipt carries the joined score"
    );
    assert_eq!(
        skip.fields.get(THRESHOLD),
        Some(&threshold_text),
        "the skip receipt carries the perfect threshold"
    );
    assert_eq!(
        skip.fields.get(TOKENS_SAVED),
        Some(&tokens),
        "the skip receipt carries the joined token estimate"
    );
    for (name, value) in &ruling.verdict.features {
        let axis = format!("{value:.6}");
        assert_eq!(
            skip.fields.get(&format!("{FEATURE_PREFIX}{name}")),
            Some(&axis),
            "the skip receipt carries the {name} axis"
        );
    }
    let all_three = format!("{ORDER_ZERO_WORDS}\n{ORDER_ONE_WORDS}\n{HIDDEN_WORDS}");
    let joined_tokens = estimated_prompt_tokens(&joined);
    let three_tokens = estimated_prompt_tokens(&all_three);
    assert_ne!(
        joined_tokens, three_tokens,
        "the hidden row's words move the token estimate, so the receipt's count proves it out"
    );
    let round = &rounds[0];
    let scanned = expected.scanned.to_string();
    let passed = expected.passed.to_string();
    let skipped = expected.skipped.to_string();
    assert_eq!(
        round.fields.get(SCANNED),
        Some(&scanned),
        "the round receipt counts the scanned TURNs"
    );
    assert_eq!(
        round.fields.get(PASSED),
        Some(&passed),
        "the round receipt counts the kept TURNs"
    );
    assert_eq!(
        round.fields.get(SKIPPED),
        Some(&skipped),
        "the round receipt counts the skipped TURNs"
    );
    Ok(())
}

/// A chat TURN whose MESSAGE the Dreamer's read withholds passes unscored: the
/// preview plans it, the enqueue succeeds, and no skip receipt names it, while
/// an ordinary thin TURN beside it is skipped with its receipt; fails without
/// the change only through the thin TURN, which then passes unscored too.
#[test]
fn a_chat_turn_whose_message_the_dreamer_may_not_read_passes_unscored()
-> PrefilterWitnessedTurnsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_prefilter_vault(&dir)?;
    let relationship = EntityId::now();
    vault.put_entity(
        &relationship,
        ENTITY_TYPE_RELATIONSHIP,
        TimeRange { start: 1, end: 1 },
        1,
        b"relationship",
    )?;
    let speaker = EntityId::now();
    vault.put_entity(
        &speaker,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"witness",
    )?;
    let conversation = EntityId::now();
    let unreadable = EntityId::now();
    let related = relationship.to_hex();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: conversation.to_hex(),
            turn_ref: Some(unreadable.to_hex()),
            thread_audience: None,
            project: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: WITHHELD_WORDS.to_owned(),
                parts: None,
                metadata: Some(json!({"rel": related})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: 10,
            assertions: WitnessAssertions::default(),
        })?;
    let thin = witness_extraction_turns(&vault, &[THIN_WORDS])?.turns[0];
    set_extraction_prefilter(
        &vault,
        &PrefilterConfig {
            threshold: 1.0,
            ..PrefilterConfig::default()
        },
    )?;
    let policy = vault.prefilter_config()?;
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(
        scan.len(),
        2,
        "the scan holds the unreadable and the thin TURN"
    );
    let inputs: Vec<(WorkingSetTurn, Option<String>)> = scan
        .iter()
        .map(|turn| {
            if turn.turn_id == unreadable {
                (*turn, None)
            } else if turn.turn_id == thin {
                (*turn, Some(THIN_WORDS.to_owned()))
            } else {
                panic!("the scan holds only the two witnessed TURNs");
            }
        })
        .collect();
    let expected = screen_turn_inputs(&policy, &inputs, &BTreeSet::new());
    let Some(thin_expected) = expected.verdicts.iter().find(|entry| entry.turn_id == thin) else {
        panic!("the refusing screen rules the thin TURN");
    };
    assert!(
        !thin_expected.verdict.pass,
        "a perfect threshold skips the thin TURN"
    );
    assert_eq!(
        planned_turn_ids(&vault, &scan, &watermark)?,
        vec![unreadable],
        "the preview plans the unreadable TURN and not the thin one"
    );
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert_eq!(skips.len(), 1, "one TURN is skipped");
    assert_eq!(rounds.len(), 1, "one round is rolled up");
    let thin_hex = thin.to_hex();
    let unreadable_hex = unreadable.to_hex();
    let score = thin_expected.verdict.score;
    let score_text = format!("{score:.6}");
    let threshold = policy.threshold;
    let threshold_text = format!("{threshold:.6}");
    let tokens = thin_expected.verdict.estimated_tokens.to_string();
    let skip = &skips[0];
    assert_eq!(
        skip.fields.get(TURN),
        Some(&thin_hex),
        "the skip receipt names the thin TURN"
    );
    let names_unreadable = skips
        .iter()
        .any(|skip| skip.fields.get(TURN).map(String::as_str) == Some(unreadable_hex.as_str()));
    assert!(
        !names_unreadable,
        "no skip receipt names the unreadable TURN"
    );
    assert_eq!(
        skip.fields.get(SCORE),
        Some(&score_text),
        "the skip receipt carries the thin score"
    );
    assert_eq!(
        skip.fields.get(THRESHOLD),
        Some(&threshold_text),
        "the skip receipt carries the perfect threshold"
    );
    assert_eq!(
        skip.fields.get(TOKENS_SAVED),
        Some(&tokens),
        "the skip receipt carries the thin token estimate"
    );
    for (name, value) in &thin_expected.verdict.features {
        let axis = format!("{value:.6}");
        assert_eq!(
            skip.fields.get(&format!("{FEATURE_PREFIX}{name}")),
            Some(&axis),
            "the skip receipt carries the {name} axis"
        );
    }
    let round = &rounds[0];
    let scanned = expected.scanned.to_string();
    let passed = expected.passed.to_string();
    let skipped = expected.skipped.to_string();
    assert_eq!(
        round.fields.get(SCANNED),
        Some(&scanned),
        "the round receipt counts the scanned TURNs"
    );
    assert_eq!(
        round.fields.get(PASSED),
        Some(&passed),
        "the round receipt counts the kept TURNs"
    );
    assert_eq!(
        round.fields.get(SKIPPED),
        Some(&skipped),
        "the round receipt counts the skipped TURNs"
    );
    Ok(())
}

/// Under the vault's default policy both chat TURNs are planned, the enqueue
/// succeeds, and no prefilter receipt exists; green with and without the
/// change, the guard of "the default threshold stays 0.0".
#[test]
fn the_default_policy_skips_nothing_and_writes_no_prefilter_receipt()
-> PrefilterWitnessedTurnsTestResult<()> {
    let dir = tempfile::tempdir()?;
    let vault = open_prefilter_vault(&dir)?;
    assert_eq!(
        vault.prefilter_config()?,
        PrefilterConfig::default(),
        "the fixture policy is the shipped default"
    );
    let witnessed = witness_extraction_turns(&vault, &[THIN_WORDS, RICH_WORDS])?;
    let (watermark, scan) = scan_micro_turns(&vault)?;
    assert_eq!(scan.len(), 2, "the scan holds the thin and the rich TURN");
    let planned = planned_turn_ids(&vault, &scan, &watermark)?;
    let scanned: Vec<EntityId> = scan.iter().map(|turn| turn.turn_id).collect();
    assert_eq!(planned, scanned, "the default plans every scanned TURN");
    for turn in &witnessed.turns {
        assert!(
            planned.contains(turn),
            "the default plans the witnessed TURN {turn:?}"
        );
    }
    enqueue_partition_attempts(
        &vault,
        DreamerConsolidationScope::Micro,
        &scan,
        &watermark,
        "run-1",
        20,
    )?;
    let (skips, rounds) = prefilter_receipts(&vault)?;
    assert!(skips.is_empty(), "the default writes no skip receipt");
    assert!(rounds.is_empty(), "the default writes no round receipt");
    Ok(())
}
