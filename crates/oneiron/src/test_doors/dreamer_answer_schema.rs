//! Door for `tests/dreamer_answer_schema_switch.rs` (HOUSE-SCHEMA-SWITCH): the
//! answer-schema switch in force, the owner's setting alone, suspensions, the live hold,
//! the events, and the params a TURN extraction request carries while in force and those
//! a NOTE review request carries (never the schema).
//!
//! Door for `tests/dreamer_answer_schema_check.rs` (HOUSE-SCHEMA-CHECK) below: planting
//! nights, children, turns and captures, the capture hook as the callers run it, the draw,
//! the shadow arms, the rules, the judged F1, and running the check on a scripted house.

use std::collections::BTreeMap;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::answer_schema::{
    AnswerSchemaSuspension, answer_schema_in_force_in_txn, capture, check, draw, events_for_test,
    hold_event_for_test, overrun, pair, receipt, request_over_params_for_test, rule,
    suspend_answer_schema_in_txn,
};
use crate::dreamer_consolidation::extraction_request_params_for_test;
use crate::dreamer_runner::{
    DREAMER_RECIPE_WAKE_ATTEMPT_KIND, DreamerAttemptPayload, DreamerConsolidationScope,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use oneiron_model::llm::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId, ModelLocality, ModelTierRef, ResponseFormat, Scope, TierPrecedence,
};

mod check_run;
pub use check_run::{
    check_replies_kept, run_check, run_check_no_house, run_check_outcome, run_check_toward,
};

/// One answer-schema event as `(id, kind, at)`: `kind` is `suspended_window`,
/// `suspended_grammar` or `rearmed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerSchemaEventView {
    pub id: EntityId,
    pub kind: String,
    pub at: u64,
}

/// Whether the answer schema is in force on `vault`: the setting reads `true` and no live
/// engine hold.
///
/// # Errors
///
/// Storage faults.
pub fn in_force(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    answer_schema_in_force_in_txn(vault, &txn)
}

/// The owner's setting alone on `vault`, without the hold: `true` unless the owner turned
/// it off or an unreadable deciding row fell back to `false`.
///
/// # Errors
///
/// Storage faults.
pub fn setting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::dreamer_consolidation::setting_keys::ANSWER_SCHEMA
        .read_in_txn(vault, &txn, &[], None)?
        .value)
}

/// Pauses the answer schema for a 7-night window suspension. Returns the event id, the
/// receipt id the report line carries; while a hold is live returns the live hold's id.
///
/// # Errors
///
/// Storage faults.
pub fn suspend_window(
    vault: &Vault,
    d: f64,
    lower: f64,
    upper: f64,
    pairs: u32,
    nights: u32,
    now: u64,
) -> Result<EntityId> {
    let suspension = AnswerSchemaSuspension::Window {
        d,
        lower,
        upper,
        pairs,
        nights,
    };
    vault.with_write_txn_grouped(|txn| suspend_answer_schema_in_txn(vault, txn, suspension, now))
}

/// Pauses the answer schema for a grammar-faults suspension on `night` (YYYY-MM-DD).
/// Returns the event id, or the live hold's id while a hold is live.
///
/// # Errors
///
/// Storage faults.
pub fn suspend_grammar_faults(
    vault: &Vault,
    night: &str,
    faults: u32,
    now: u64,
) -> Result<EntityId> {
    let suspension = AnswerSchemaSuspension::GrammarFaults {
        night: night.to_owned(),
        faults,
    };
    vault.with_write_txn_grouped(|txn| suspend_answer_schema_in_txn(vault, txn, suspension, now))
}

/// The live hold's event id, if any.
///
/// # Errors
///
/// Storage faults.
pub fn hold(vault: &Vault) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    hold_event_for_test(vault, &txn)
}

/// Every decodable event, oldest first.
///
/// # Errors
///
/// Storage faults.
pub fn events(vault: &Vault) -> Result<Vec<AnswerSchemaEventView>> {
    let txn = vault.store.env.read_txn()?;
    Ok(events_for_test(vault, &txn)?
        .into_iter()
        .map(|(id, kind, at)| AnswerSchemaEventView { id, kind, at })
        .collect())
}

/// The params a TURN extraction request carries on `vault`: with the answer schema while
/// the switch is in force, without it otherwise. Reads in-force in a short read txn, as
/// the callers do, then builds them as `request_over` does for a TURN call.
///
/// # Errors
///
/// Storage faults; the shipped schema file does not parse.
pub fn turn_params(vault: &Vault) -> Result<BTreeMap<String, serde_json::Value>> {
    let in_force = {
        let txn = vault.store.env.read_txn()?;
        answer_schema_in_force_in_txn(vault, &txn)?
    };
    request_over_params_for_test(false, in_force)
}

/// The params a NOTE review request carries, built as `request_over` builds them for a NOTE
/// review whose caller passed `answer_schema`: never the schema.
///
/// # Errors
///
/// `answer_schema` asked for on a NOTE review: refused.
pub fn note_params(answer_schema: bool) -> Result<BTreeMap<String, serde_json::Value>> {
    request_over_params_for_test(true, answer_schema)
}

/// When the door plants nights and children (Unix seconds).
const DOOR_NOW: u64 = 1_790_000_000;

/// Plants one night: a recipe receipt attempt, the check's parent.
///
/// # Errors
///
/// Storage faults.
pub fn plant_night(vault: &Vault) -> Result<AttemptId> {
    plant_attempt(
        vault,
        DREAMER_RECIPE_WAKE_ATTEMPT_KIND,
        DREAMER_RECIPE_WAKE_ATTEMPT_KIND,
        None,
    )
}

/// Plants one child of `night`, standing in for a consolidation child: on the Micro lane,
/// so the door admits and completes children without a home election and the gate stands
/// open. The run tree, not the lane, makes them the night's descendants.
///
/// # Errors
///
/// Storage faults.
pub fn plant_child(vault: &Vault, night: AttemptId) -> Result<AttemptId> {
    plant_attempt(
        vault,
        DreamerConsolidationScope::Micro.attempt_kind(),
        "test.child",
        Some(night),
    )
}

/// Plants one queued child of `night` that the check's runs never settle: a Meso attempt,
/// which keeps the gate shut while it stays open, as a budget-parked extraction does.
///
/// # Errors
///
/// Storage faults.
pub fn plant_open_child(vault: &Vault, night: AttemptId) -> Result<AttemptId> {
    plant_attempt(
        vault,
        DreamerConsolidationScope::Meso.attempt_kind(),
        "test.open_child",
        Some(night),
    )
}

/// Plants one attempt of `kind` and `attempt_type` under `parent`, with a fresh dedupe key.
///
/// # Errors
///
/// Storage faults.
fn plant_attempt(
    vault: &Vault,
    kind: &str,
    attempt_type: &str,
    parent: Option<AttemptId>,
) -> Result<AttemptId> {
    let store = DreamerRunnerStore::new(vault);
    let outcome = vault.with_write_txn_grouped(|txn| {
        store.enqueue_kind_in_txn(
            txn,
            kind,
            DreamerAttemptPayload {
                attempt_type: attempt_type.to_owned(),
                input: rmpv::Value::Nil,
                parent_attempt: parent,
            },
            Some(format!("test-answer-schema:{}", EntityId::now().to_hex())),
            None,
            DOOR_NOW,
        )
    })?;
    Ok(match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
    })
}

/// Witnesses `words` as one user turn of a fresh conversation.
///
/// # Errors
///
/// The witness door's.
pub fn plant_turn(vault: &Vault, words: &str) -> Result<EntityId> {
    let conversation = EntityId::now();
    Ok(super::nightly::witness_turn(vault, conversation, words, DOOR_NOW)?.0)
}

/// One TURN extraction request as the callers build it with the schema: the shipped params
/// with the answer schema over `text` as the last user message.
///
/// # Errors
///
/// The test model id; the shipped schema file does not parse.
fn sample_request(text: &str) -> Result<LlmRequest> {
    let model = ModelId::new("test/house@1")
        .map_err(|_| crate::error::Error::InvalidConfig("the test house model".into()))?;
    Ok(LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
            purpose: CallPurpose::Extraction,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Extraction,
                ModelTierRef("consolidation".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        }
        .with_purpose_defaults(),
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::System,
                content: vec![ContentPart::Text {
                    text: "test extraction".to_owned(),
                    signature: None,
                }],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: text.to_owned(),
                    signature: None,
                }],
            },
        ],
        tools: Vec::new(),
        params: extraction_request_params_for_test(true)?,
        provider_options: BTreeMap::new(),
        host_segments: None,
    })
}

/// Plants one capture of `child` over `text` from `sources`, kept at `captured_at` (Unix
/// seconds). Returns the capture's step hash.
///
/// # Errors
///
/// The test request does not hash; storage faults.
pub fn plant_capture(
    vault: &Vault,
    child: AttemptId,
    sources: &[EntityId],
    text: &str,
    captured_at: u64,
) -> Result<[u8; 32]> {
    let request = sample_request(text)?;
    let step = request
        .canonical_hash()
        .map_err(|_| crate::error::Error::InvalidConfig("the test request did not hash".into()))?;
    capture::capture_turn_call(vault, child, &request, sources, captured_at)?;
    Ok(step)
}

/// Captures one TURN call as the callers do: reads in-force in a short read transaction,
/// then keeps the call through the same capture. Returns whether this call wrote a new row:
/// a call out of force, or a memo hit, writes nothing.
///
/// # Errors
///
/// The test request does not hash; storage faults.
pub fn capture_if_in_force(
    vault: &Vault,
    attempt: AttemptId,
    text: &str,
    sources: &[EntityId],
    now: u64,
) -> Result<bool> {
    let in_force = {
        let txn = vault.store.env.read_txn()?;
        answer_schema_in_force_in_txn(vault, &txn)?
    };
    if !in_force {
        return Ok(false);
    }
    let request = sample_request(text)?;
    let step = request
        .canonical_hash()
        .map_err(|_| crate::error::Error::InvalidConfig("the test request did not hash".into()))?;
    let key = (attempt, step);
    {
        let txn = vault.store.env.read_txn()?;
        if capture::capture_in_txn(&vault.store, &txn, &key)?.is_some() {
            return Ok(false);
        }
    }
    capture::capture_turn_call(vault, attempt, &request, sources, now)?;
    Ok(true)
}

/// How many capture rows the vault holds, decodable or not.
///
/// # Errors
///
/// Storage faults.
pub fn capture_count(vault: &Vault) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    capture::capture_count_in_txn(&vault.store, &txn)
}

/// How many decodable captures the night's descendants hold.
///
/// # Errors
///
/// Storage faults.
pub fn captures_for_night(vault: &Vault, night: AttemptId) -> Result<usize> {
    let txn = vault.store.env.read_txn()?;
    let descendants = check::descendants_in_txn(vault, &txn, night, false)?;
    let mut count = 0;
    for descendant in descendants {
        count += capture::captures_of_in_txn(&vault.store, &txn, descendant)?.len();
    }
    Ok(count)
}

/// One scored pair, as the test reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct PairRowView {
    pub index: u32,
    pub schema_whole: bool,
    pub shadow_whole: bool,
    pub schema_candidates: u32,
    pub shadow_candidates: u32,
    pub schema_f1: Option<f64>,
    pub shadow_f1: Option<f64>,
}

/// Every scored pair row of `night`, in index order.
///
/// # Errors
///
/// Storage faults.
pub fn pairs(vault: &Vault, night: AttemptId) -> Result<Vec<PairRowView>> {
    let txn = vault.store.env.read_txn()?;
    Ok(receipt::pairs_for_night_in_txn(vault, &txn, night)?
        .into_iter()
        .map(|(index, pair)| PairRowView {
            index,
            schema_whole: pair.schema_whole,
            shadow_whole: pair.shadow_whole,
            schema_candidates: pair.schema_candidates,
            shadow_candidates: pair.shadow_candidates,
            schema_f1: pair.schema_f1,
            shadow_f1: pair.shadow_f1,
        })
        .collect())
}

/// Latches the night over budget, as an extraction child's budget-stop settlement does.
///
/// # Errors
///
/// Storage faults.
pub fn plant_overrun(vault: &Vault, night: AttemptId) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        overrun::latch_overrun_in_txn(
            vault,
            txn,
            night,
            overrun::AnswerSchemaOverrun::BudgetRefusal,
        )
    })
}

/// The night's draw: the drawn capture keys, in draw order.
///
/// # Errors
///
/// Storage faults.
pub fn draw(vault: &Vault, night: AttemptId) -> Result<Vec<(AttemptId, [u8; 32])>> {
    draw::draw_for_test(vault, night)
}

/// The pair's two arms' params from one captured call over `text` with `seed`: the schema
/// arm's, then the shadow arm's.
///
/// # Errors
///
/// The test model id; the shipped schema file does not parse.
pub fn pair_arms(
    text: &str,
    seed: u64,
) -> Result<(
    BTreeMap<String, serde_json::Value>,
    BTreeMap<String, serde_json::Value>,
)> {
    let request = sample_request(text)?;
    let model = ModelId::new("test/house@1")
        .map_err(|_| crate::error::Error::InvalidConfig("the test house model".into()))?;
    Ok(pair::arm_params_for_test(&request, &model, seed))
}

/// Whether `wholes`, `(schema_whole, shadow_whole)` per pair, suspends the night at once:
/// the night and its fault count, or `None` to keep.
#[must_use]
pub fn grammar_suspends(wholes: &[(bool, bool)], night: &str) -> Option<(String, u32)> {
    let faults = rule::grammar_faults(wholes);
    rule::grammar_suspends(faults).then(|| (night.to_owned(), faults))
}

/// The window's paired quality difference, as the receipt carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowView {
    pub d: f64,
    pub lower: f64,
    pub upper: f64,
    pub n: u32,
    pub nights: u32,
}

/// Evaluates the window over `diffs`, `(schema F1, shadow F1)` per pair with quality from
/// `nights` nights: `None` while fewer than thirty pairs.
#[must_use]
pub fn window_stats(diffs: &[(f64, f64)], night: AttemptId, nights: u32) -> Option<WindowView> {
    let diffs: Vec<f64> = diffs
        .iter()
        .map(|(schema, shadow)| schema - shadow)
        .collect();
    rule::evaluate_window(&diffs, night.as_bytes(), nights).map(|stats| WindowView {
        d: stats.d,
        lower: stats.lower,
        upper: stats.upper,
        n: stats.n,
        nights: stats.nights,
    })
}

/// Whether the window suspends: its mean below zero with its upper bound below zero.
#[must_use]
pub fn window_suspends(stats: &WindowView) -> bool {
    rule::window_suspends(&rule::WindowStats {
        d: stats.d,
        lower: stats.lower,
        upper: stats.upper,
        n: stats.n,
        nights: stats.nights,
    })
}

/// Each arm's F1 against the pooled gold from the judge's two answers: `schema` and
/// `shadow` are the arms' candidate lists, `seed` the pair's seed, and each order's answer
/// is its two lists' flags. `None` for both when the gold is empty.
#[must_use]
pub fn f1(
    schema: &[serde_json::Value],
    shadow: &[serde_json::Value],
    seed: u64,
    order1: (&[bool], &[bool]),
    order2: (&[bool], &[bool]),
) -> (Option<f64>, Option<f64>) {
    let (schema_flags, shadow_flags) = pair::supported_flags(
        seed,
        schema.len(),
        shadow.len(),
        (order1.0.to_vec(), order1.1.to_vec()),
        (order2.0.to_vec(), order2.1.to_vec()),
    );
    pair::f1_against_gold(schema, &schema_flags, shadow, &shadow_flags)
}

/// One night's check receipt, as the test reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceiptView {
    pub night: String,
    pub pairs: u32,
    pub schema_whole: u32,
    pub shadow_whole: u32,
    pub schema_f1: Option<f64>,
    pub shadow_f1: Option<f64>,
    pub window: Option<WindowView>,
    /// `keep`, `suspend` or `skip`.
    pub action: String,
    /// The suspension's event id, for `suspend`.
    pub event: Option<EntityId>,
    /// The skip reason, for `skip`.
    pub reason: Option<String>,
    /// How many captures the receipt's selection holds.
    pub selection: usize,
    /// The plan's receipt line.
    pub line: String,
}

/// Reads the night's receipt view, which the run wrote.
///
/// # Errors
///
/// No receipt; storage faults.
pub fn receipt(vault: &Vault, night: AttemptId) -> Result<ReceiptView> {
    let txn = vault.store.env.read_txn()?;
    let receipt = receipt::receipt_in_txn(vault, &txn, night)?
        .ok_or_else(|| crate::error::Error::InvalidConfig("the check wrote no receipt".into()))?;
    Ok(receipt_view(&receipt))
}

/// `receipt` as its view.
fn receipt_view(receipt: &receipt::NightReceipt) -> ReceiptView {
    let finished = receipt.finished.as_ref();
    let (action, event, reason) = match finished.map(|finished| &finished.action) {
        Some(receipt::NightAction::Keep) => ("keep".to_owned(), None, None),
        Some(receipt::NightAction::Suspend { event }) => ("suspend".to_owned(), Some(*event), None),
        Some(receipt::NightAction::Skip { reason }) => {
            ("skip".to_owned(), None, Some(reason.as_str().to_owned()))
        }
        None => ("pending".to_owned(), None, None),
    };
    ReceiptView {
        night: receipt.night.clone(),
        pairs: finished.map_or(0, |finished| finished.pairs),
        schema_whole: finished.map_or(0, |finished| finished.schema_whole),
        shadow_whole: finished.map_or(0, |finished| finished.shadow_whole),
        schema_f1: finished.and_then(|finished| finished.schema_f1_mean),
        shadow_f1: finished.and_then(|finished| finished.shadow_f1_mean),
        window: finished
            .and_then(|finished| finished.window.as_ref())
            .map(|window| WindowView {
                d: window.d,
                lower: window.lower,
                upper: window.upper,
                n: window.n,
                nights: window.nights,
            }),
        action,
        event,
        reason,
        selection: receipt.selection.len(),
        line: receipt::receipt_line(receipt),
    }
}
