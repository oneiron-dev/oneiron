//! The screen over planner input, and the rescan door that re-opens what it skipped.

use std::collections::BTreeSet;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::dreamer_consolidation::{
    WorkingSetTurn, decode_turn_body, projected_turn_text_in, reopen_watermark_from,
};
use crate::dreamer_runner::{DreamerConsolidationScope, DreamerTurnRole, dreamer_turn_role};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
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
    /// Summed [`estimated_prompt_tokens`](crate::dreamer_prefilter::estimated_prompt_tokens) of the SKIPPED turns — the budget
    /// this round did not spend.
    pub estimated_tokens_saved: u64,
    /// Whether the screen asked for any scanned turn's words from its
    /// MESSAGE rows, whatever the ask gave: words, none (a turn with no
    /// MESSAGE row) or a refusal. The receipts of a round that did stand on
    /// rows they do not name: a turn's novelty is measured against the
    /// turns the round scored before it, and its own MESSAGE rows are read
    /// as the Dreamer. So `vault.receipts` serves them to the vault owner
    /// on this device alone
    /// ([`super::prefilter_receipt_read_message_rows`]).
    pub read_message_rows: bool,
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
            read_message_rows: false,
        }
    }
}

/// One screening input: the working-set row plus the words it is scored on
/// (its own body's, or its MESSAGE rows' for a TURN that stores none), or
/// `None` when it has none the screen may read.
pub type PrefilterScreenInput = (WorkingSetTurn, Option<String>);

/// Screens a batch. Pure — every storage read happened in the caller, and
/// the caller that read a turn's words from its MESSAGE rows says so on the
/// result ([`PrefilterScreen::read_message_rows`], `false` here).
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
        read_message_rows: false,
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
/// form: the screen takes words from a TURN's own body, or for a TURN that
/// stores none from that TURN's MESSAGE rows ([`screen_words_in_txn`]), and
/// from nothing else, so a row of any other type — a SECRET_CUSTODY carrier
/// most of all — yields no text and the turn passes unscored.
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

/// Whether `config` lets the screen read a witnessed TURN's MESSAGE rows: an
/// enabled policy at a threshold above zero, the only kind a score can skip
/// under.
fn screens_message_words(config: &PrefilterConfig) -> bool {
    config.enabled && config.threshold > 0.0
}

/// The words the screen scores one planned TURN on, and whether its MESSAGE
/// rows were read for them.
struct ScreenWords {
    /// `None` when the TURN has none the screen may read.
    words: Option<String>,
    /// Whether the TURN's MESSAGE rows were read, whatever they gave.
    read_message_rows: bool,
}

/// The words the screen scores one planned TURN on, or none when it has
/// none the screen may read.
///
/// A TURN that carries its own words (`txt|text`) is scored on them as
/// stored. A witnessed or imported chat TURN carries none: its words are its
/// MESSAGE rows. Once the policy can skip at all (a threshold above zero)
/// they are read by the projection a consolidation branch reads
/// ([`projected_turn_text_in`]): as the Dreamer, under the relationship gate,
/// the visible and final rows of the TURN's own author bucket, joined in
/// order, in the snapshot that read the TURN's row. So the screen scores the
/// words extraction would read, and no others. A TURN that projection refuses
/// (a row the Dreamer may not read, a MESSAGE that is away, a binding that
/// changed) passes unscored: the branch meets the same refusal and rules on
/// it. At a zero threshold no score can skip, so no MESSAGE row is read.
///
/// The Dreamer's grants on those rows are judged at the time `txn` judges
/// at, so every snapshot this runs in is opened, or moved, at a persisted
/// grant clock first, as a branch's read snapshot is: the committed screen
/// through [`committed_screen_snapshot`], a planning writer through
/// [`observe_grant_clock_for_message_screen_in_txn`], and each read of the
/// turn wake through `dreamer_wake::read_phase`'s
/// `read_then_write_at_grant_clock`, which observes the clock before every
/// one, a retry and the one-writer read too. A grant that expired since this
/// store last judged one lends the screen no words.
///
/// # Errors
///
/// Storage errors.
fn screen_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    config: &PrefilterConfig,
    turn: &EntityId,
    raw: Option<&[u8]>,
) -> Result<ScreenWords> {
    let Some((_, _, own_words)) =
        raw.and_then(|raw| screen_text_from_raw(raw, &vault.config.assistant_display_names))
    else {
        return Ok(ScreenWords {
            words: None,
            read_message_rows: false,
        });
    };
    if own_words.is_some() || !screens_message_words(config) {
        return Ok(ScreenWords {
            words: own_words,
            read_message_rows: false,
        });
    }
    let words = match projected_turn_text_in(vault, txn, turn) {
        Ok(words) => words,
        Err(Error::InvalidClaimBody(_)) => None,
        Err(error) => return Err(error),
    };
    Ok(ScreenWords {
        words,
        read_message_rows: true,
    })
}

/// The read snapshot one committed screen runs in, and the policy it holds.
///
/// A policy that screens MESSAGE words reads them under the Dreamer's grants,
/// so its snapshot opens after the grant clock is persisted, as a branch's
/// read snapshot does, and the policy is read again in it. A policy that
/// reads no MESSAGE row judges no grant: its snapshot opens with no clock
/// observation, so the default policy plans at no added cost.
///
/// # Errors
///
/// Storage errors, a vault a restore swap moved aside, or
/// [`Error::InvalidConfig`] when the landed config row is unusable.
fn committed_screen_snapshot(vault: &Vault) -> Result<(heed::RoTxn<'_>, PrefilterConfig)> {
    let txn = vault.store.env.read_txn()?;
    let config = vault.prefilter_config_in_txn(&txn)?;
    if !screens_message_words(&config) {
        return Ok((txn, config));
    }
    // The store gives a thread one read transaction at a time, and the
    // clock observation may open its own.
    drop(txn);
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let config = vault.prefilter_config_in_txn(&txn)?;
    Ok((txn, config))
}

/// Persists the grant clock in a planning writer before its screen runs.
///
/// A policy that screens MESSAGE words reads them under the Dreamer's grants
/// in the caller's transaction, and a grant is judged at a persisted clock
/// floor, as a branch's read snapshot judges it. Without the observation the
/// writer judges at the time of this store's last grant decision, and a
/// grant that expired since still lends the screen its MESSAGE's words. A
/// policy that reads no MESSAGE row judges no grant, and the writer's clock
/// floor stays where its own writes put it.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn observe_grant_clock_for_message_screen_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    if screens_message_words(&vault.prefilter_config_in_txn(txn)?) {
        crate::ports::observe_clock_floor_in_txn(&vault.store, txn)?;
    }
    Ok(())
}

/// The POST-ROLE-GATE value screen over a partition planner's input.
///
/// Called at the top of [`crate::dreamer_consolidation::plan_partitions`]. The
/// input has already passed GATE-10; this decides which of it is worth
/// extracting. A disabled config short-circuits before any read, so the
/// disabled path is byte-identical planning at zero added cost.
///
/// One snapshot ([`committed_screen_snapshot`]) holds the policy, every TURN
/// row as [`Vault::get_raw`] reads it, and the MESSAGE rows a witnessed
/// TURN's words are read from: the store gives a thread one read transaction
/// at a time.
///
/// # Errors
///
/// Storage errors, a vault a restore swap moved aside, or
/// [`Error::InvalidConfig`] when the landed config row is unusable.
pub(crate) fn prefilter_partition_input(
    vault: &Vault,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let (txn, config) = committed_screen_snapshot(vault)?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    let mut read_message_rows = false;
    for turn in turns {
        let raw = vault.get_raw_sealed_in_txn(&txn, &turn.turn_id)?;
        let read = screen_words_in_txn(vault, &txn, &config, &turn.turn_id, raw.as_deref())?;
        read_message_rows |= read.read_message_rows;
        inputs.push((*turn, read.words));
    }
    let mut screen = screen_turn_inputs(&config, &inputs, &BTreeSet::new());
    screen.read_message_rows = read_message_rows;
    Ok(screen)
}

/// [`prefilter_partition_input`] through a caller-owned write transaction —
/// the ONE-1685 session close screens the rows it has staged but not yet
/// committed, under the same policy and the same arithmetic, so an
/// in-transaction screen and a committed-state screen of the same turns keep
/// the byte-identical-partition-keys claim on `plan_partitions_in_txn` true.
///
/// A MESSAGE grant is judged at the time `txn` judges at: a writer calls
/// [`observe_grant_clock_for_message_screen_in_txn`] before this, and a read
/// snapshot is opened after the grant clock is persisted.
///
/// # Errors
///
/// Storage errors, or [`Error::InvalidConfig`] when the landed config row is
/// unusable.
pub(crate) fn prefilter_partition_input_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turns: &[WorkingSetTurn],
) -> Result<PrefilterScreen> {
    let config = vault.prefilter_config_in_txn(txn)?;
    if !config.enabled {
        return Ok(PrefilterScreen::disabled(turns, config.threshold));
    }
    let mut inputs = Vec::with_capacity(turns.len());
    let mut read_message_rows = false;
    for turn in turns {
        // A withdrawn TURN's words are gone, as `Vault::get_raw` reads them.
        let raw = match vault.get_raw_in(txn, &turn.turn_id)? {
            Some(raw)
                if crate::ports::raw_readable_in_txn(&vault.store, txn, &turn.turn_id, &raw)? =>
            {
                Some(raw)
            }
            _ => None,
        };
        let read = screen_words_in_txn(vault, txn, &config, &turn.turn_id, raw.as_deref())?;
        read_message_rows |= read.read_message_rows;
        inputs.push((*turn, read.words));
    }
    let mut screen = screen_turn_inputs(&config, &inputs, &BTreeSet::new());
    screen.read_message_rows = read_message_rows;
    Ok(screen)
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
