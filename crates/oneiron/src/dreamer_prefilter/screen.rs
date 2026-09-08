//! The screen over planner input, and the rescan door that re-opens what it skipped.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::{WorkingSetTurn, decode_turn_body, reopen_watermark_from};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerTurnRole, dreamer_turn_role};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;

use super::config::PrefilterConfig;
use super::score::{NoveltyWindow, PrefilterVerdict, prefilter_turn};

// ---------------------------------------------------------------------------
// The screen over planner input
// ---------------------------------------------------------------------------

/// One scanned turn's verdict, in scan order.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefilterTurnVerdict {
    pub turn_id: EntityId,
    pub verdict: PrefilterVerdict,
}

/// The result of screening ONE planner input batch.
///
/// `kept` is the planner's new input; everything else is the accounting the
/// receipts project. `scanned == passed + skipped` always, and `kept.len() ==
/// passed`.
#[derive(Debug, Clone, PartialEq)]
pub struct PrefilterScreen {
    /// Whether the screen ran at all. `false` = the config disabled it and
    /// `kept` is the input verbatim.
    pub enabled: bool,
    /// The threshold the verdicts were ruled against.
    pub threshold: f32,
    /// Planner input after the screen, in the input's own order.
    pub kept: Vec<WorkingSetTurn>,
    /// Every scanned turn's verdict, in scan order. Empty when disabled.
    pub verdicts: Vec<PrefilterTurnVerdict>,
    pub scanned: usize,
    pub passed: usize,
    pub skipped: usize,
    /// Summed [`estimated_prompt_tokens`] of the SKIPPED turns — the budget
    /// this round did not spend.
    pub estimated_tokens_saved: u64,
}

impl PrefilterScreen {
    /// The pass-through screen: the input, unchanged and unjudged.
    fn disabled(turns: &[WorkingSetTurn], threshold: f32) -> Self {
        Self {
            enabled: false,
            threshold,
            kept: turns.to_vec(),
            verdicts: Vec::new(),
            scanned: turns.len(),
            passed: turns.len(),
            skipped: 0,
            estimated_tokens_saved: 0,
        }
    }
}

/// One screening input: the working-set row plus its body text, or `None` when
/// the body could not be read.
pub type PrefilterScreenInput = (WorkingSetTurn, Option<String>);

/// Screens a batch. Pure — every storage read happened in the caller.
///
/// Turns are scored in the batch's own order because the novelty window is
/// causal: turn *n* is judged against turns *0..n*, never against turns that
/// had not been said yet.
#[must_use]
pub fn screen_turn_inputs(
    config: &PrefilterConfig,
    inputs: &[PrefilterScreenInput],
    known_names: &BTreeSet<String>,
) -> PrefilterScreen {
    let mut screen = PrefilterScreen {
        enabled: true,
        threshold: config.threshold,
        kept: Vec::with_capacity(inputs.len()),
        verdicts: Vec::with_capacity(inputs.len()),
        scanned: inputs.len(),
        passed: 0,
        skipped: 0,
        estimated_tokens_saved: 0,
    };
    let mut window = NoveltyWindow::new();
    for (turn, text) in inputs {
        let verdict = match text {
            Some(text) => {
                let verdict = prefilter_turn(config, text, turn.role, known_names, &window);
                window.observe(text);
                verdict
            }
            None => PrefilterVerdict::unscored_pass(),
        };
        if verdict.pass {
            screen.passed += 1;
            screen.kept.push(*turn);
        } else {
            screen.skipped += 1;
            screen.estimated_tokens_saved = screen
                .estimated_tokens_saved
                .saturating_add(verdict.estimated_tokens);
        }
        screen.verdicts.push(PrefilterTurnVerdict {
            turn_id: turn.turn_id,
            verdict,
        });
    }
    screen
}

/// Turn body text for screening, or `None` when the row is absent or is not a
/// TURN.
///
/// The type check is the custody seal restated in the strongest available
/// form: the screen reads TURN bodies and nothing else, so a row of any other
/// type — a SECRET_CUSTODY carrier most of all — yields no text and the turn
/// passes unscored.
fn screen_text_from_raw(
    raw: &[u8],
    assistant_display_names: &[String],
) -> Option<(DreamerTurnRole, u64, Option<String>)> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return None;
    }
    let facts = decode_turn_body(&raw[ENTITY_METADATA_HEADER_LEN.min(raw.len())..]);
    Some((
        dreamer_turn_role(facts.speaker.as_deref(), assistant_display_names),
        header.learned_at,
        facts.text,
    ))
}

/// The POST-ROLE-GATE value screen over a partition planner's input.
///
/// Called at the top of [`crate::dreamer_consolidation::plan_partitions`]. The
/// input has already passed GATE-10; this decides which of it is worth
/// extracting. A disabled config short-circuits before any read, so the
/// disabled path is byte-identical planning at zero added cost.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn prefilter_partition_input(
    vault: &Vault,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let config = vault.prefilter_config()?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    for turn in turns {
        let text = match vault.get_raw(&turn.turn_id)? {
            Some(raw) => screen_text_from_raw(&raw, &vault.config.assistant_display_names)
                .and_then(|(_, _, text)| text),
            None => None,
        };
        inputs.push((*turn, text));
    }
    Ok(screen_turn_inputs(&config, &inputs, &BTreeSet::new()))
}

/// [`prefilter_partition_input`] through a caller-owned write transaction —
/// the ONE-1685 session close screens the rows it has staged but not yet
/// committed, under the same policy and the same arithmetic, so an
/// in-transaction screen and a committed-state screen of the same turns keep
/// the byte-identical-partition-keys claim on `plan_partitions_in_txn` true.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn prefilter_partition_input_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let config = vault.prefilter_config_in_txn(txn)?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    for turn in turns {
        let text = match vault.get_raw_in(txn, &turn.turn_id)? {
            Some(raw) => screen_text_from_raw(&raw, &vault.config.assistant_display_names)
                .and_then(|(_, _, text)| text),
            None => None,
        };
        inputs.push((*turn, text));
    }
    Ok(screen_turn_inputs(&config, &inputs, &BTreeSet::new()))
}

// ---------------------------------------------------------------------------
// The rescan door (I7)
// ---------------------------------------------------------------------------

/// Re-opens screened-out turns for a fresh sweep by REWINDING the scope
/// watermark to just before `from_learned_at`.
///
/// A skip costs a turn its extraction, not its place in the log: the round
/// that skipped it still advanced the cursor past it (invariant I2, which is
/// what stops a low-value turn from being re-scanned forever). The cost of
/// that guarantee is that a threshold change cannot retroactively rescue what
/// an earlier threshold dropped — this door is how an operator asks for that
/// re-sweep explicitly.
///
/// It writes an ABSOLUTE cursor position through the administrative rescan
/// path, including an explicit before-first position for zero. The normal
/// in-transaction settler `advance_watermark_in_txn` still fail-closes on
/// rewind so that a round cannot quietly re-plan consumed work.
/// `from_learned_at` is INCLUSIVE: the next round re-scans every admissible
/// turn at or after that second, and
/// `0` is a full re-sweep from the beginning of the log.
///
/// Re-planning is safe rather than duplicative because a consolidation attempt
/// is advisory identity — a re-swept batch that matches an earlier one exactly
/// coalesces on the `partition_round_hash` dedupe key.
///
/// # Errors
///
/// Storage errors.
pub fn reopen_prefilter_rescan(
    vault: &Vault,
    scope: DreamerConsolidationScope,
    from_learned_at: u64,
) -> Result<()> {
    reopen_watermark_from(vault, scope, from_learned_at)
}
