use super::*;

mod repair_regressions;

use crate::config::VaultConfig;
use crate::dreamer_consolidation::{
    ConsolidationPartitionPlan, plan_partitions, read_watermark, scan_dirty_turns,
};
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CONVERSATION;
use crate::session_lifecycle::{SessionClosePredicate, SessionEndWake, SessionMintOutcome};
use crate::temporal::TimeRange;
use crate::test_util::open_test_vault_with;

const MESO: DreamerConsolidationScope = DreamerConsolidationScope::Meso;

fn open_vault() -> (tempfile::TempDir, Vault) {
    open_test_vault_with(VaultConfig::device())
}

fn at(second: u64) -> TimeRange {
    TimeRange {
        start: second,
        end: second,
    }
}

fn seed_conversation(vault: &Vault, seed: u8) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("conversation id");
    vault
        .put_entity(&id, ENTITY_TYPE_CONVERSATION, at(1), 1, b"\x80")
        .expect("seed conversation");
    id
}

/// One admissible dirty TURN: extraction-admissible speaker plus the
/// structural ChildOf edge the partition planner requires. The body is the
/// production `txt`/`spkr` MessagePack shape.
fn seed_turn(
    vault: &Vault,
    conversation: &EntityId,
    speaker: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    let turn = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (rmpv::Value::from("spkr"), rmpv::Value::from(speaker)),
            (rmpv::Value::from("txt"), rmpv::Value::from(text)),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(&turn, ENTITY_TYPE_TURN, at(learned_at), learned_at, &body)
        .edge(&turn, EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    turn
}

/// The production planning trio, exactly as the driver's close runs it.
fn meso_wake(vault: &Vault) -> SessionEndWake {
    let watermark = read_watermark(vault, MESO).expect("watermark");
    let dirty = scan_dirty_turns(vault, MESO, &watermark, usize::MAX).expect("scan");
    let advance_watermark_to = dirty.iter().map(|turn| turn.learned_at).max();
    let planned_turn_ids = dirty.iter().map(|turn| turn.turn_id).collect();
    let plans = plan_partitions(vault, MESO, &dirty, &watermark).expect("plan");
    SessionEndWake {
        plans,
        planned_watermark: watermark.last_learned_at,
        planned_turn_ids,
        advance_watermark_to,
    }
}

fn planned_turn_ids(plans: &[ConsolidationPartitionPlan]) -> Vec<EntityId> {
    plans
        .iter()
        .flat_map(|plan| plan.turns.iter().map(|turn| turn.turn_id))
        .collect()
}

fn plan_now(vault: &Vault) -> Vec<ConsolidationPartitionPlan> {
    let watermark = read_watermark(vault, MESO).expect("watermark");
    let dirty = scan_dirty_turns(vault, MESO, &watermark, usize::MAX).expect("scan");
    plan_partitions(vault, MESO, &dirty, &watermark).expect("plan")
}

fn minted(outcome: SessionMintOutcome) -> EntityId {
    match outcome {
        SessionMintOutcome::Minted(id) => id,
        SessionMintOutcome::AlreadyOpen(id) => panic!("expected a fresh mint, got open {id:?}"),
    }
}

/// Entity-dense, high-value turns beside filler, in one fixture corpus.
///
/// `true` = the turn a human would want extracted.
fn fixture_corpus() -> Vec<(&'static str, &'static str, bool)> {
    vec![
        (
            "user",
            "Yuki moved to Kyoto last March and started at Nintendo as a localization lead.",
            true,
        ),
        ("user", "ok", false),
        (
            "user",
            "My cardiologist Dr. Okafor scheduled the stress test for the fourteenth at Mercy General.",
            true,
        ),
        ("assistant", "Got it.", false),
        (
            "user",
            "We signed the lease on the Shimokitazawa apartment; rent is 148000 yen and Mika co-signed it.",
            true,
        ),
        ("user", "yeah sure", false),
        (
            "assistant",
            "I switched the deploy pipeline from Jenkins to GitHub Actions after the Tuesday outage.",
            true,
        ),
        ("user", "lol ok ok ok", false),
        (
            "user",
            "I keep putting off packing for the move because doing it makes the whole thing feel real.",
            true,
        ),
        ("assistant", "thanks!", false),
    ]
}

fn corpus_inputs(corpus: &[(&'static str, &'static str, bool)]) -> Vec<PrefilterScreenInput> {
    corpus
        .iter()
        .enumerate()
        .map(|(ordinal, (speaker, text, _))| {
            let mut bytes = [0_u8; 16];
            bytes[0] = 0xA0;
            bytes[1] = u8::try_from(ordinal).expect("corpus ordinal fits a byte");
            let turn = WorkingSetTurn {
                turn_id: EntityId::from_bytes(bytes).expect("fixture turn id"),
                role: dreamer_turn_role(Some(speaker), &[]),
                learned_at: 2_000 + ordinal as u64,
                carrier: None,
                conversation: None,
            };
            (turn, Some((*text).to_owned()))
        })
        .collect()
}

// ── the planner gate ────────────────────────────────────────────────────────

/// Seeds the fixture corpus into one conversation and returns
/// `(conversation, ids, high_value_ids)`.
fn seed_fixture_corpus(vault: &Vault) -> (EntityId, Vec<EntityId>, Vec<EntityId>) {
    let conversation = seed_conversation(vault, 0x11);
    let mut ids = Vec::new();
    let mut high_value = Vec::new();
    for (ordinal, (speaker, text, valuable)) in fixture_corpus().into_iter().enumerate() {
        let id = seed_turn(
            vault,
            &conversation,
            speaker,
            text,
            2_000 + ordinal as u64 + 1,
        );
        if valuable {
            high_value.push(id);
        }
        ids.push(id);
    }
    (conversation, ids, high_value)
}

/// The threshold that separates the fixture corpus, computed from the corpus
/// itself rather than pinned as a magic number.
fn separating_threshold() -> f32 {
    let corpus = fixture_corpus();
    let inputs = corpus_inputs(&corpus);
    let screen = screen_turn_inputs(&PrefilterConfig::default(), &inputs, &BTreeSet::new());
    let mut lowest_valuable = f32::MAX;
    let mut highest_filler = f32::MIN;
    for ((_, _, valuable), entry) in corpus.iter().zip(&screen.verdicts) {
        if *valuable {
            lowest_valuable = lowest_valuable.min(entry.verdict.score);
        } else {
            highest_filler = highest_filler.max(entry.verdict.score);
        }
    }
    assert!(
        lowest_valuable > highest_filler,
        "the corpus must be separable: lowest valuable {lowest_valuable} vs highest filler {highest_filler}"
    );
    f32::midpoint(lowest_valuable, highest_filler)
}

// ── receipts, watermark, and the rescan door ────────────────────────────────

fn extraction_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))
        .expect("receipt query")
}

#[test]
fn skipped_turns_advance_the_watermark_and_the_rescan_door_re_sweeps_them() {
    let (_dir, vault) = open_vault();
    let (_conversation, ids, _) = seed_fixture_corpus(&vault);
    vault
        .set_prefilter_config(PrefilterConfig {
            threshold: separating_threshold(),
            ..PrefilterConfig::default()
        })
        .expect("tighten");

    let session = minted(vault.mint_session(1_000).expect("mint"));
    let wake = meso_wake(&vault);
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 5_000, &wake)
        .expect("close")
        .expect("ended");

    // Make skipped turns visible to planning if the close failed to consume them.
    vault
        .set_prefilter_config(PrefilterConfig::default())
        .expect("restore lossless policy");
    assert!(
        plan_now(&vault).is_empty(),
        "skipped turns must not be re-scanned forever"
    );

    // I7: the explicit door re-opens them for a fresh sweep.
    reopen_prefilter_rescan(&vault, MESO, 0).expect("rescan door");
    assert_eq!(planned_turn_ids(&plan_now(&vault)), ids);
}
