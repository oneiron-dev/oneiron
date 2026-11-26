//! One night's answer-schema check receipt (HOUSE-SCHEMA-CHECK): the drawn selection, written
//! before the first call so a retry names the same work, and, once finished, the pair scores,
//! the window and the action. Pair rows hold numbers only, never the turns or replies.

use serde::{Deserialize, Serialize};

use super::capture::{delete_captures_of_in_txn, delete_old_captures_in_txn};
use super::rule::WindowStats;
use super::{AnswerSchemaSuspension, suspend_answer_schema_in_txn};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::model_step_context::StepEffectBinding;
use crate::side_table::{self, Named, SideTable};

/// The night receipts, keyed by night.
const NIGHTS: SideTable<AttemptId, NightReceipt, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_NIGHT);

/// The scored pairs, keyed by night and index.
const PAIRS: SideTable<(AttemptId, u32), PairRow, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_PAIR);

/// How long a capture outlives its night when no check retires it: eight days, in seconds.
pub(crate) const CAPTURE_MAX_AGE_SECS: u64 = 8 * 86_400;

/// Why the check skipped a night.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SkipReason {
    /// The night's extraction ran past its budget.
    OverBudget,
    /// The switch read out of force when the check ran.
    NotInForce,
    /// No capture under the night's descendants still reads.
    NoCalls,
    /// The host lends no house rung at exactly its own server.
    NoHouseRung,
}

impl SkipReason {
    /// The stable name the receipt line carries.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OverBudget => "over_budget",
            Self::NotInForce => "not_in_force",
            Self::NoCalls => "no_calls",
            Self::NoHouseRung => "no_house_rung",
        }
    }
}

/// What a finished night came to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NightAction {
    /// The schema stays in force.
    Keep,
    /// The schema suspends; the receipt id the morning report carries. When another night's
    /// hold went live first, this night joins it and carries that hold's event: one pause,
    /// one receipt, never a second hold.
    Suspend { event: EntityId },
    /// The night scored nothing, with why.
    Skip { reason: SkipReason },
}

/// The finished half of a night receipt: scores, window and action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinishedReceipt {
    /// How many pairs the night scored.
    pub(crate) pairs: u32,
    /// How many schema replies came back whole.
    pub(crate) schema_whole: u32,
    /// How many shadow replies came back whole.
    pub(crate) shadow_whole: u32,
    /// The mean schema F1 over pairs with quality, if any.
    pub(crate) schema_f1_mean: Option<f64>,
    /// The mean shadow F1 over pairs with quality, if any.
    pub(crate) shadow_f1_mean: Option<f64>,
    /// The seven-night window, when thirty pairs with quality scored.
    pub(crate) window: Option<WindowStats>,
    /// What the night came to.
    pub(crate) action: NightAction,
    /// What the check's own calls spent.
    pub(crate) completed_units: u64,
    /// The terminal steps that spend charges for the first time.
    pub(crate) step_bindings: Vec<StepEffectBinding>,
}

/// One night's check receipt: the drawn selection, and the finished half once scored.
/// A receipt with no finished half is a started check a retry resumes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NightReceipt {
    /// The night, `YYYY-MM-DD` of the night attempt's start (UTC).
    pub(crate) night: String,
    /// The drawn capture keys, in draw order.
    pub(crate) selection: Vec<(AttemptId, [u8; 32])>,
    /// The finished half, once the night scored or skipped.
    pub(crate) finished: Option<FinishedReceipt>,
}

/// One scored pair: whole flags, candidate counts and F1 per arm. Numbers only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PairRow {
    /// The night, `YYYY-MM-DD`, for the seven-night window scan.
    pub(crate) night: String,
    /// Whether the schema reply came back whole.
    pub(crate) schema_whole: bool,
    /// Whether the shadow reply came back whole.
    pub(crate) shadow_whole: bool,
    /// How many candidates the schema reply decoded. The rules read the whole flags and
    /// F1; the check's landing log states the night's totals, and the test door reads these.
    pub(crate) schema_candidates: u32,
    /// How many candidates the shadow reply decoded. The rules read the whole flags and
    /// F1; the check's landing log states the night's totals, and the test door reads these.
    pub(crate) shadow_candidates: u32,
    /// The schema arm's F1 against the pooled gold, if the pair has quality.
    pub(crate) schema_f1: Option<f64>,
    /// The shadow arm's F1 against the pooled gold, if the pair has quality.
    pub(crate) shadow_f1: Option<f64>,
}

/// Reads the night's receipt, if any.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn receipt_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    night: AttemptId,
) -> Result<Option<NightReceipt>> {
    NIGHTS.get(&vault.store, txn, &night)
}

/// Writes the drawn selection into the receipt ledger before the first call, so a retry names
/// the same work. A receipt already there (a resumed check) keeps its selection.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn write_selection_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    night: AttemptId,
    date: &str,
    selection: &[(AttemptId, [u8; 32])],
) -> Result<()> {
    if NIGHTS.contains(&vault.store, &*txn, &night)? {
        return Ok(());
    }
    NIGHTS.put(
        &vault.store,
        txn,
        &night,
        &NightReceipt {
            night: date.to_owned(),
            selection: selection.to_vec(),
            finished: None,
        },
    )
}

/// The finished half's scores without the action: the suspension's event id is minted in
/// the landing transaction, so the action joins there.
#[derive(Debug, Clone)]
pub(crate) struct LandFinished {
    /// How many pairs the night scored.
    pub(crate) pairs: u32,
    /// How many schema replies came back whole.
    pub(crate) schema_whole: u32,
    /// How many shadow replies came back whole.
    pub(crate) shadow_whole: u32,
    /// The mean schema F1 over pairs with quality, if any.
    pub(crate) schema_f1_mean: Option<f64>,
    /// The mean shadow F1 over pairs with quality, if any.
    pub(crate) shadow_f1_mean: Option<f64>,
    /// The seven-night window, when thirty pairs with quality scored.
    pub(crate) window: Option<WindowStats>,
    /// What the check's own calls spent.
    pub(crate) completed_units: u64,
    /// The terminal steps that spend charges for the first time.
    pub(crate) step_bindings: Vec<StepEffectBinding>,
}

impl LandFinished {
    /// No pairs, no window, no spend: what a skip lands.
    pub(crate) fn empty() -> Self {
        Self {
            pairs: 0,
            schema_whole: 0,
            shadow_whole: 0,
            schema_f1_mean: None,
            shadow_f1_mean: None,
            window: None,
            completed_units: 0,
            step_bindings: Vec::new(),
        }
    }
}

/// What the landing night came to: the suspension carries its reason, and its event id joins
/// the receipt in the landing transaction.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ReceiptOutcome<'a> {
    /// The schema stays in force.
    Keep,
    /// The schema suspends for `0`.
    Suspend(&'a AnswerSchemaSuspension),
    /// The night scored nothing, with why.
    Skip(SkipReason),
}

/// Lands the night: the finished receipt, the pair rows, any suspension, and the retirement
/// of every capture under `descendants` (this night's sample, drawn or not), with captures
/// older than eight days anywhere, in one write transaction.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn land_receipt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    night: AttemptId,
    date: &str,
    selection: &[(AttemptId, [u8; 32])],
    pairs: &[PairRow],
    land: LandFinished,
    outcome: ReceiptOutcome<'_>,
    descendants: &[AttemptId],
    now: u64,
) -> Result<()> {
    let action = match outcome {
        ReceiptOutcome::Keep => NightAction::Keep,
        ReceiptOutcome::Suspend(suspension) => NightAction::Suspend {
            event: suspend_answer_schema_in_txn(vault, txn, suspension.clone(), now)?,
        },
        ReceiptOutcome::Skip(reason) => NightAction::Skip { reason },
    };
    for (index, pair) in pairs.iter().enumerate() {
        PAIRS.put(&vault.store, txn, &(night, index as u32), pair)?;
    }
    NIGHTS.put(
        &vault.store,
        txn,
        &night,
        &NightReceipt {
            night: date.to_owned(),
            selection: selection.to_vec(),
            finished: Some(FinishedReceipt {
                pairs: land.pairs,
                schema_whole: land.schema_whole,
                shadow_whole: land.shadow_whole,
                schema_f1_mean: land.schema_f1_mean,
                shadow_f1_mean: land.shadow_f1_mean,
                window: land.window,
                action,
                completed_units: land.completed_units,
                step_bindings: land.step_bindings,
            }),
        },
    )?;
    for descendant in descendants {
        delete_captures_of_in_txn(&vault.store, txn, *descendant)?;
    }
    delete_old_captures_in_txn(&vault.store, txn, now, CAPTURE_MAX_AGE_SECS)
}

/// Every decodable pair row of `night`, in index order, for
/// `test_doors::dreamer_answer_schema`.
///
/// # Errors
///
/// Storage faults.
#[cfg(oneiron_test_support)]
pub(crate) fn pairs_for_night_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    night: AttemptId,
) -> Result<Vec<(u32, PairRow)>> {
    let mut out = Vec::new();
    for row in PAIRS.iter_raw_from(&vault.store, txn, night.as_bytes())? {
        let (key, value) = row?;
        let (Some((_, index)), Ok(pair)) = (
            <(AttemptId, u32) as crate::side_table::SideKey>::decode_key(&key),
            PAIRS.decode_value(&value),
        ) else {
            continue;
        };
        out.push((index, pair));
    }
    out.sort_by_key(|(index, _)| *index);
    Ok(out)
}

/// Every decodable pair row, in key order: `(night, index, row)`. A row that does not decode
/// is no pair.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn all_pairs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(AttemptId, u32, PairRow)>> {
    let mut out = Vec::new();
    for row in PAIRS.iter_raw_from(&vault.store, txn, &[])? {
        let (key, value) = row?;
        let (Some((night, index)), Ok(pair)) = (
            <(AttemptId, u32) as crate::side_table::SideKey>::decode_key(&key),
            PAIRS.decode_value(&value),
        ) else {
            continue;
        };
        out.push((night, index, pair));
    }
    Ok(out)
}

/// Renders the plan's receipt line, e.g.
/// `answer_schema check night=2026-11-22 pairs=8 fault schema=0 shadow=1 quality schema=0.86
/// shadow=0.84 window d=+0.012 [-0.004,+0.029] n=40 action=keep`
/// (`action=suspend receipt=<event hex>` or `action=skip reason=<reason>`). The fault counts
/// are pairs minus whole replies per arm. It is not a digest line: the suspend and re-arm
/// report lines cover those.
pub(crate) fn receipt_line(receipt: &NightReceipt) -> String {
    let Some(finished) = receipt.finished.as_ref() else {
        return format!(
            "answer_schema check night={} pairs=0 action=pending",
            receipt.night,
        );
    };
    let fault = |whole: u32| finished.pairs.saturating_sub(whole);
    let quality = |mean: Option<f64>| match mean {
        Some(mean) => format!("{mean:.2}"),
        None => "-".to_owned(),
    };
    let window = match finished.window.as_ref() {
        Some(window) => format!(
            " window d={:+.3} [{:+.3},{:+.3}] n={}",
            window.d, window.lower, window.upper, window.n,
        ),
        None => String::new(),
    };
    let action = match &finished.action {
        NightAction::Keep => "keep".to_owned(),
        NightAction::Suspend { event } => format!("suspend receipt={}", event.to_hex()),
        NightAction::Skip { reason } => format!("skip reason={}", reason.as_str()),
    };
    format!(
        "answer_schema check night={} pairs={} fault schema={} shadow={} quality schema={} \
         shadow={}{window} action={action}",
        receipt.night,
        finished.pairs,
        fault(finished.schema_whole),
        fault(finished.shadow_whole),
        quality(finished.schema_f1_mean),
        quality(finished.shadow_f1_mean),
    )
}
