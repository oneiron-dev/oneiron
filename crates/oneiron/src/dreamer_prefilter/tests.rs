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
        .put_entity(&id, ENTITY_TYPE_CONVERSATION, at(1), 1, b"conversation")
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
                conversation: None,
            };
            (turn, Some((*text).to_owned()))
        })
        .collect()
}

// ── the pure scorer ─────────────────────────────────────────────────────────

#[test]
fn score_is_bounded_and_the_default_threshold_keeps_everything() {
    let config = PrefilterConfig::default();
    assert!(config.enabled, "the screen ships on");
    assert_eq!(
        config.threshold, 0.0,
        "the shipped cut keeps everything: enabling the screen must not silently start dropping"
    );

    let window = NoveltyWindow::new();
    let known = BTreeSet::new();
    for (speaker, text, _) in fixture_corpus() {
        let verdict = prefilter_turn(
            &config,
            text,
            dreamer_turn_role(Some(speaker), &[]),
            &known,
            &window,
        );
        assert!(
            (0.0..=1.0).contains(&verdict.score),
            "score {} out of [0, 1] for {text:?}",
            verdict.score
        );
        assert!(verdict.pass, "the default threshold drops nothing");
        for (axis, value) in &verdict.features {
            assert!(
                (0.0..=1.0).contains(value),
                "axis {axis} out of [0, 1]: {value}"
            );
        }
    }
}

#[test]
fn a_repeated_turn_loses_its_novelty() {
    let config = PrefilterConfig::default();
    let known = BTreeSet::new();
    let text = "the deploy pipeline moved from Jenkins to GitHub Actions after the outage";

    let mut window = NoveltyWindow::new();
    let first = prefilter_turn(&config, text, DreamerTurnRole::User, &known, &window);
    window.observe(text);
    let repeat = prefilter_turn(&config, text, DreamerTurnRole::User, &known, &window);

    assert!(repeat.score < first.score);

    let config = PrefilterConfig {
        threshold: f32::midpoint(repeat.score, first.score),
        ..config
    };
    let first = prefilter_turn(
        &config,
        text,
        DreamerTurnRole::User,
        &known,
        &NoveltyWindow::new(),
    );
    let repeat = prefilter_turn(&config, text, DreamerTurnRole::User, &known, &window);
    assert!(first.pass);
    assert!(!repeat.pass);
}

#[test]
fn a_capitalized_span_is_one_mention_and_openers_are_not_mentions() {
    let config = PrefilterConfig {
        weights: PrefilterWeights {
            len: 0.0,
            ttr: 0.0,
            entity_density: 1.0,
            novelty: 0.0,
            role: 0.0,
        },
        ..PrefilterConfig::default()
    };
    let window = NoveltyWindow::new();
    let known = BTreeSet::new();
    let score = |text: &str, names: &BTreeSet<String>| {
        prefilter_turn(&config, text, DreamerTurnRole::User, names, &window).score
    };

    let single = score("Kyoto station", &known);
    let span = score("Kyoto Station", &known);
    let separated = score("Kyoto and Osaka", &known);
    assert!(single > 0.0);
    assert_eq!(span, single);
    assert!(separated > span);

    // "The" opens a sentence; it does not name anything.
    let unnamed = score("the train was late", &known);
    assert_eq!(score("The train was late", &known), unnamed);
    assert!(single > unnamed);

    let unknown = score("mika called", &known);
    let known = BTreeSet::from(["mika".to_owned()]);
    let named = score("mika called", &known);
    assert!(named > unknown);
    assert_eq!(named, single);
}

#[test]
fn an_unreadable_body_passes_unscored_rather_than_being_dropped() {
    // A screen that cannot read a turn does not get to discard it.
    let config = PrefilterConfig {
        threshold: 0.9,
        ..PrefilterConfig::default()
    };
    let turn = WorkingSetTurn {
        turn_id: EntityId::from_bytes([0xB1; 16]).expect("turn id"),
        role: DreamerTurnRole::User,
        learned_at: 10,
        conversation: None,
    };
    let screen = screen_turn_inputs(&config, &[(turn, None)], &BTreeSet::new());
    assert_eq!(screen.kept, vec![turn]);
    assert_eq!(screen.skipped, 0);
    assert!(screen.verdicts[0].verdict.pass);
    assert!(
        screen.verdicts[0].verdict.features.is_empty(),
        "an empty feature map means NOT screened, never screened-at-zero"
    );
}

#[test]
fn the_novelty_window_is_causal_and_bounded() {
    let config = PrefilterConfig::default();
    let known = BTreeSet::new();
    let expired_text = "amber birds circle distant mountains";
    let mut window = NoveltyWindow::new();
    let first = prefilter_turn(
        &config,
        expired_text,
        DreamerTurnRole::User,
        &known,
        &window,
    );
    window.observe(expired_text);
    let repeat = prefilter_turn(
        &config,
        expired_text,
        DreamerTurnRole::User,
        &known,
        &window,
    );
    assert!(repeat.score < first.score);

    for ordinal in 0..(NOVELTY_WINDOW_TURNS + 4) {
        window.observe(&format!(
            "distinct sentence number {ordinal} about something"
        ));
    }
    let expired = prefilter_turn(
        &config,
        expired_text,
        DreamerTurnRole::User,
        &known,
        &window,
    );
    assert_eq!(expired.score, first.score);

    let recent_text = format!(
        "distinct sentence number {} about something",
        NOVELTY_WINDOW_TURNS + 3,
    );
    let fresh = prefilter_turn(
        &config,
        &recent_text,
        DreamerTurnRole::User,
        &known,
        &NoveltyWindow::new(),
    );
    let recent = prefilter_turn(
        &config,
        &recent_text,
        DreamerTurnRole::User,
        &known,
        &window,
    );
    assert!(recent.score < fresh.score);
}

// ── config: durable, live, and validated ────────────────────────────────────

#[test]
fn absent_config_row_bootstraps_to_the_compiled_default() {
    let (_dir, vault) = open_vault();
    assert_eq!(
        vault.prefilter_config().expect("config"),
        PrefilterConfig::default()
    );
}

#[test]
fn config_round_trips_through_vault_meta() {
    let (_dir, vault) = open_vault();
    let config = PrefilterConfig {
        enabled: true,
        threshold: 0.42,
        weights: PrefilterWeights {
            len: 1.0,
            ttr: 2.0,
            entity_density: 3.0,
            novelty: 4.0,
            role: 0.0,
        },
    };
    vault.set_prefilter_config(config).expect("set config");
    assert_eq!(vault.prefilter_config().expect("config"), config);
}

#[test]
fn invalid_config_is_refused_typed_and_never_persisted() {
    let (_dir, vault) = open_vault();
    let landed = PrefilterConfig {
        enabled: true,
        threshold: 0.4,
        ..PrefilterConfig::default()
    };
    vault.set_prefilter_config(landed).expect("set config");

    let zero_mass = PrefilterWeights {
        len: 0.0,
        ttr: 0.0,
        entity_density: 0.0,
        novelty: 0.0,
        role: 0.0,
    };
    let refusals = [
        (
            "NaN threshold",
            PrefilterConfig {
                threshold: f32::NAN,
                ..landed
            },
        ),
        (
            "infinite threshold",
            PrefilterConfig {
                threshold: f32::INFINITY,
                ..landed
            },
        ),
        (
            "threshold above 1",
            PrefilterConfig {
                threshold: 1.5,
                ..landed
            },
        ),
        (
            "negative threshold",
            PrefilterConfig {
                threshold: -0.1,
                ..landed
            },
        ),
        (
            "NaN weight",
            PrefilterConfig {
                weights: PrefilterWeights {
                    novelty: f32::NAN,
                    ..PrefilterWeights::default()
                },
                ..landed
            },
        ),
        (
            "infinite weight",
            PrefilterConfig {
                weights: PrefilterWeights {
                    len: f32::NEG_INFINITY,
                    ..PrefilterWeights::default()
                },
                ..landed
            },
        ),
        (
            "negative weight",
            PrefilterConfig {
                weights: PrefilterWeights {
                    role: -1.0,
                    ..PrefilterWeights::default()
                },
                ..landed
            },
        ),
        (
            "zero-mass weights",
            PrefilterConfig {
                weights: zero_mass,
                ..landed
            },
        ),
    ];

    for (name, refused) in refusals {
        let error = vault
            .set_prefilter_config(refused)
            .expect_err("must be refused");
        assert!(
            matches!(error, Error::InvalidConfig(_)),
            "{name} must be a typed InvalidConfig refusal, got {error:?}"
        );
        assert_eq!(
            vault.prefilter_config().expect("config"),
            landed,
            "{name} must never reach the store"
        );
    }
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

#[test]
fn a_disabled_screen_plans_byte_identically() {
    let (_dir, vault) = open_vault();
    let (conversation, ids, high_value_ids) = seed_fixture_corpus(&vault);

    vault
        .set_prefilter_config(PrefilterConfig {
            enabled: false,
            threshold: 0.99,
            ..PrefilterConfig::default()
        })
        .expect("disable");
    let disabled = plan_now(&vault);
    assert_eq!(planned_turn_ids(&disabled), ids);
    for plan in &disabled {
        assert_eq!(plan.key.conversation_ref, conversation);
        assert!(plan.key.world_ref.is_none());
        assert!(plan.key.facet_ref.is_none());
    }

    // The shipped default is enabled — and equally lossless.
    vault
        .set_prefilter_config(PrefilterConfig::default())
        .expect("default");
    let default = plan_now(&vault);
    assert_eq!(planned_turn_ids(&default), ids);
    for plan in &default {
        assert_eq!(plan.key.conversation_ref, conversation);
        assert!(plan.key.world_ref.is_none());
        assert!(plan.key.facet_ref.is_none());
    }

    // The same config with a real cut is where planning diverges.
    vault
        .set_prefilter_config(PrefilterConfig {
            threshold: separating_threshold(),
            ..PrefilterConfig::default()
        })
        .expect("enable");
    let screened_ids = planned_turn_ids(&plan_now(&vault));
    assert_eq!(screened_ids, high_value_ids);
    assert_ne!(screened_ids, ids);
}

#[test]
fn a_threshold_change_flips_verdicts_without_a_recompile() {
    let (_dir, vault) = open_vault();
    let (_conversation, ids, high_value) = seed_fixture_corpus(&vault);
    let threshold = separating_threshold();

    vault
        .set_prefilter_config(PrefilterConfig {
            threshold,
            ..PrefilterConfig::default()
        })
        .expect("tighten");
    let kept: BTreeSet<EntityId> = planned_turn_ids(&plan_now(&vault)).into_iter().collect();
    assert_eq!(
        kept,
        high_value.iter().copied().collect::<BTreeSet<_>>(),
        "the tightened threshold keeps exactly the valuable turns"
    );

    // Nothing was recompiled; only the durable row changed.
    vault
        .set_prefilter_config(PrefilterConfig {
            threshold: 0.0,
            ..PrefilterConfig::default()
        })
        .expect("loosen");
    assert_eq!(
        planned_turn_ids(&plan_now(&vault)).len(),
        ids.len(),
        "loosening the same durable row restores every turn"
    );
}

#[test]
fn the_role_gate_still_rules_first() {
    let (_dir, vault) = open_vault();
    let conversation = seed_conversation(&vault, 0x22);
    // A SYSTEM turn that would score well if the screen ever saw it.
    seed_turn(
        &vault,
        &conversation,
        "system",
        "Yuki moved to Kyoto last March and started at Nintendo as a localization lead.",
        2_001,
    );
    let user = seed_turn(&vault, &conversation, "user", "ok", 2_002);

    vault
        .set_prefilter_config(PrefilterConfig::default())
        .expect("default");
    // GATE-10 refused the system turn in the SCAN; the screen never scored it,
    // and the permissive screen kept the low-value user turn. Eligibility
    // first, value second.
    assert_eq!(planned_turn_ids(&plan_now(&vault)), vec![user]);
}

// ── receipts, watermark, and the rescan door ────────────────────────────────

fn extraction_receipts(vault: &Vault) -> Vec<ReceiptRecord> {
    vault
        .receipts(ReceiptQuery::new(100).with_kind(ReceiptKind::Extraction))
        .expect("receipt query")
}

#[test]
fn a_screened_close_receipts_skips_per_turn_and_a_round_rollup() {
    let (_dir, vault) = open_vault();
    let (_conversation, ids, high_value) = seed_fixture_corpus(&vault);
    let threshold = separating_threshold();
    vault
        .set_prefilter_config(PrefilterConfig {
            threshold,
            ..PrefilterConfig::default()
        })
        .expect("tighten");

    let session = minted(vault.mint_session(1_000).expect("mint"));
    let wake = meso_wake(&vault);
    assert_eq!(
        wake.planned_turn_ids.len(),
        ids.len(),
        "the fence identity set is the PRE-screen scan, never the screen's output"
    );
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 5_000, &wake)
        .expect("close")
        .expect("session ended");

    let receipts = extraction_receipts(&vault);
    let skips: Vec<&ReceiptRecord> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == PREFILTER_DECISION_SKIP)
        .collect();
    let rollups: Vec<&ReceiptRecord> = receipts
        .iter()
        .filter(|receipt| receipt.outcome == PREFILTER_OUTCOME_SCREENED)
        .collect();

    let skipped_count = ids.len() - high_value.len();
    assert_eq!(skips.len(), skipped_count, "one receipt per skipped turn");
    assert_eq!(rollups.len(), 1, "one rollup per screened round");

    // Every skip is queryable BY TURN and carries the arithmetic behind it.
    for id in &ids {
        let trigger = format!("turn:{}", id.to_hex());
        let row = skips
            .iter()
            .find(|receipt| receipt.trigger_ref.as_deref() == Some(trigger.as_str()));
        if high_value.contains(id) {
            assert!(row.is_none(), "a kept turn writes no skip row");
            continue;
        }
        let row = row.expect("every skipped turn is queryable by its turn id");
        assert_eq!(row.receipt_kind, ReceiptKind::Extraction);
        assert_eq!(row.fields[FIELD_PREFILTER_PHASE], PREFILTER_PHASE);
        assert_eq!(
            row.fields[FIELD_PREFILTER_DECISION],
            PREFILTER_DECISION_SKIP
        );
        for axis in [
            PREFILTER_FEATURE_LEN,
            PREFILTER_FEATURE_TTR,
            PREFILTER_FEATURE_ENTITY_DENSITY,
            PREFILTER_FEATURE_NOVELTY,
            PREFILTER_FEATURE_ROLE,
        ] {
            assert!(
                row.fields
                    .contains_key(&format!("{FIELD_PREFILTER_FEATURE_PREFIX}{axis}")),
                "the {axis} axis travels with the ruling"
            );
        }
        let score: f32 = row.fields[FIELD_PREFILTER_SCORE].parse().expect("score");
        let ruled: f32 = row.fields[FIELD_PREFILTER_THRESHOLD]
            .parse()
            .expect("threshold");
        assert!(score < ruled, "a skip row must show why it was a skip");
    }

    // The rollup carries the counts and the savings claim.
    let rollup = rollups[0];
    assert_eq!(
        rollup.fields[FIELD_PREFILTER_SCANNED],
        ids.len().to_string()
    );
    assert_eq!(
        rollup.fields[FIELD_PREFILTER_PASSED],
        high_value.len().to_string()
    );
    assert_eq!(
        rollup.fields[FIELD_PREFILTER_SKIPPED],
        skipped_count.to_string()
    );
    let saved: u64 = rollup.fields[FIELD_PREFILTER_TOKENS_SAVED]
        .parse()
        .expect("tokens saved");
    assert!(saved > 0, "a round that skipped work saved budget");
    // Skip rows and the rollup join on the round hash.
    for skip in &skips {
        assert_eq!(
            skip.fields[FIELD_PREFILTER_ROUND],
            rollup.fields[FIELD_PREFILTER_ROUND]
        );
    }
}

/// Replays the exact fenced corpus after a tight close and checks the public
/// receipt projection against the new planner output, not the prior skips.
fn assert_same_batch_rescan_receipts(config: PrefilterConfig, expected_skipped: usize) {
    let (_dir, vault) = open_vault();
    let (_conversation, ids, high_value) = seed_fixture_corpus(&vault);
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

    let before = extraction_receipts(&vault);
    let prior_skipped = ids.len() - high_value.len();
    assert_eq!(
        before
            .iter()
            .filter(|row| row.outcome == PREFILTER_DECISION_SKIP)
            .count(),
        prior_skipped
    );
    assert_eq!(before.len(), prior_skipped + 1);
    let prior_rollup = before
        .iter()
        .find(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
        .expect("prior rollup");
    assert_eq!(
        prior_rollup.fields[FIELD_PREFILTER_SKIPPED],
        prior_skipped.to_string()
    );
    assert!(
        expected_skipped < prior_skipped,
        "the replay must rescue turns"
    );

    vault.set_prefilter_config(config).expect("change policy");
    reopen_prefilter_rescan(&vault, MESO, 0).expect("rescan door");
    let session = minted(vault.mint_session(5_001).expect("mint replay"));
    let replay = meso_wake(&vault);
    assert_eq!(
        replay.planned_turn_ids, wake.planned_turn_ids,
        "the replay must use the same pre-screen batch identity"
    );
    let kept: BTreeSet<_> = planned_turn_ids(&replay.plans).into_iter().collect();
    let expected_skips: BTreeSet<_> = ids
        .iter()
        .filter(|id| !kept.contains(*id))
        .map(EntityId::to_hex)
        .collect();
    assert_eq!(expected_skips.len(), expected_skipped);
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 6_000, &replay)
        .expect("close replay")
        .expect("replay ended");

    let after = extraction_receipts(&vault);
    let skips: Vec<_> = after
        .iter()
        .filter(|row| row.outcome == PREFILTER_DECISION_SKIP)
        .collect();
    assert_eq!(skips.len(), expected_skipped, "no stale skip rows");
    let actual_skips: BTreeSet<_> = skips
        .iter()
        .map(|row| row.fields[FIELD_PREFILTER_TURN].clone())
        .collect();
    assert_eq!(
        actual_skips, expected_skips,
        "only current skips are receipted"
    );
    if expected_skipped == 0 {
        assert!(
            after.is_empty(),
            "an all-pass replay removes the old rollup too"
        );
    } else {
        assert_eq!(after.len(), expected_skipped + 1, "one current rollup");
        let rollup = after
            .iter()
            .find(|row| row.outcome == PREFILTER_OUTCOME_SCREENED)
            .expect("current rollup");
        assert_eq!(
            rollup.fields[FIELD_PREFILTER_SKIPPED],
            skips.len().to_string()
        );
        assert_eq!(
            rollup.fields[FIELD_PREFILTER_PASSED],
            kept.len().to_string()
        );
        assert_eq!(
            rollup.fields[FIELD_PREFILTER_SCANNED],
            ids.len().to_string()
        );
        assert_eq!(
            rollup.fields[FIELD_PREFILTER_ROUND], prior_rollup.fields[FIELD_PREFILTER_ROUND],
            "replacement must not invent a new round identity"
        );
        for row in &after {
            assert_eq!(row.occurred_at, 6_000, "every receipt is from the replay");
            assert_eq!(
                row.fields[FIELD_PREFILTER_ROUND],
                rollup.fields[FIELD_PREFILTER_ROUND]
            );
        }
    }
    assert_eq!(
        read_watermark(&vault, MESO)
            .expect("watermark")
            .last_learned_at,
        wake.advance_watermark_to.expect("pre-screen watermark")
    );
    assert!(meso_wake(&vault).planned_turn_ids.is_empty());
}

#[test]
fn an_all_pass_rescan_removes_prior_skips_and_rollup_when_loosened_or_disabled() {
    for config in [
        PrefilterConfig::default(),
        PrefilterConfig {
            enabled: false,
            threshold: separating_threshold(),
            ..PrefilterConfig::default()
        },
    ] {
        assert_same_batch_rescan_receipts(config, 0);
    }
}

#[test]
fn a_partial_skip_rescan_replaces_receipts_with_current_verdicts() {
    let inputs = corpus_inputs(&fixture_corpus());
    let tight = PrefilterConfig {
        threshold: separating_threshold(),
        ..PrefilterConfig::default()
    };
    let before = screen_turn_inputs(&tight, &inputs, &BTreeSet::new());
    let mut skipped_scores: Vec<_> = before
        .verdicts
        .iter()
        .filter(|entry| !entry.verdict.pass)
        .map(|entry| entry.verdict.score)
        .collect();
    skipped_scores.sort_by(f32::total_cmp);
    let lowest = skipped_scores[0];
    let highest = *skipped_scores.last().expect("filler scores");
    assert!(lowest < highest, "the filler must admit a partial rescue");
    let loosened = PrefilterConfig {
        threshold: f32::midpoint(lowest, highest),
        ..tight
    };
    let after = screen_turn_inputs(&loosened, &inputs, &BTreeSet::new());
    assert!(after.skipped > 0 && after.skipped < before.skipped);
    assert_same_batch_rescan_receipts(loosened, after.skipped);
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

#[test]
fn a_round_that_skips_nothing_writes_no_receipt() {
    let (_dir, vault) = open_vault();
    seed_fixture_corpus(&vault);
    // The shipped default: the screen runs, scores, and drops nothing.
    vault
        .set_prefilter_config(PrefilterConfig::default())
        .expect("default");

    let session = minted(vault.mint_session(1_000).expect("mint"));
    let wake = meso_wake(&vault);
    vault
        .end_session_with_wake(&session, SessionClosePredicate::Explicit, 5_000, &wake)
        .expect("close")
        .expect("ended");

    assert!(
        extraction_receipts(&vault).is_empty(),
        "a screen that changed nothing leaves no trace"
    );
}

#[test]
fn receipt_kind_extraction_round_trips_and_is_not_emit_adjacent() {
    assert_eq!(ReceiptKind::Extraction.as_str(), "extraction");
    assert_eq!(
        ReceiptKind::parse("extraction"),
        Some(ReceiptKind::Extraction)
    );
    assert!(
        !ReceiptKind::Extraction.is_emit_adjacent(),
        "nothing leaves the vault when a turn is screened"
    );
}

// ── the savings table (PR body) and the import surface ──────────────────────

#[test]
fn fixture_corpus_savings_and_recall_table() {
    let corpus = fixture_corpus();
    let inputs = corpus_inputs(&corpus);
    let threshold = separating_threshold();
    let config = PrefilterConfig {
        threshold,
        ..PrefilterConfig::default()
    };
    let screen = screen_turn_inputs(&config, &inputs, &BTreeSet::new());

    let total_tokens: u64 = corpus
        .iter()
        .map(|(_, text, _)| estimated_prompt_tokens(text))
        .sum();
    let valuable = corpus.iter().filter(|(_, _, keep)| *keep).count();
    let mut kept_valuable = 0;
    let mut kept_filler = 0;

    println!("\n| turn | role | score | verdict | est. tokens |");
    println!("| --- | --- | --- | --- | --- |");
    for ((speaker, text, keep), entry) in corpus.iter().zip(&screen.verdicts) {
        let verdict = entry.verdict.decision();
        if entry.verdict.pass {
            if *keep {
                kept_valuable += 1;
            } else {
                kept_filler += 1;
            }
        }
        let excerpt: String = text.chars().take(56).collect();
        println!(
            "| {excerpt} | {speaker} | {:.3} | {verdict} | {} |",
            entry.verdict.score, entry.verdict.estimated_tokens
        );
    }
    let scanned = screen.scanned;
    let kept = screen.passed;
    let skipped = screen.skipped;
    let saved = screen.estimated_tokens_saved;
    let saved_pct = 100.0 * saved as f64 / total_tokens as f64;
    println!(
        "\nthreshold {threshold:.3} · scanned {scanned} · kept {kept} · skipped {skipped} · \
         est. tokens {saved} of {total_tokens} saved ({saved_pct:.0}%) · \
         recall {kept_valuable}/{valuable} · filler kept {kept_filler}"
    );

    assert_eq!(
        kept_valuable, valuable,
        "recall on the fixture corpus must be total: dropping a real memory is the failure that matters"
    );
    assert_eq!(kept_filler, 0, "every filler turn is screened out");
    assert!(screen.estimated_tokens_saved > 0);
    assert_eq!(screen.scanned, screen.passed + screen.skipped);
}

#[test]
fn the_screen_imports_no_model_surface() {
    // The whole premise is that this runs BEFORE tokens are spent. A single
    // model import here would make the cheap screen the expensive one.
    let source = concat!(
        include_str!("mod.rs"),
        include_str!("config.rs"),
        include_str!("score.rs"),
        include_str!("screen.rs"),
        include_str!("receipts.rs"),
        include_str!("supersession.rs"),
    );
    for needle in ["crate::llm", "use crate::llm", "LlmBackend", "LlmRequest"] {
        assert!(
            !source.contains(needle),
            "the pre-extraction screen must not reach the model surface ({needle})"
        );
    }
}
