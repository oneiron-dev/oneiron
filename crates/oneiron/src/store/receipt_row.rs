//! Core half of `store::receipt_row`: its store-layer items live in `oneiron_store::receipt_row` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::receipt_row::*;

// Engine-only receipt keys: core is their only writer and reader, so they
// stay here, crate-private, rather than in the store layer.

/// ARCH-0055 r7 proposal-outcome receipt fields (ONE-1747).
///
/// The three ramp-scope keys are `pub(crate)` because ONE-1748's demotion
/// receipt names the SAME scope tuple: two spellings of one key would make the
/// ramp's own receipts unjoinable with the outcome receipts they answer.
pub(crate) const FIELD_PROPOSAL_REF: &str = "proposal_ref";
pub(crate) const FIELD_OP_KIND: &str = "op_kind";
pub(crate) const FIELD_TARGET_CLASS: &str = "target_class";
pub(crate) const FIELD_SCOPE_ACTOR: &str = "actor";
/// Why a consent-graduation scope was demoted back to the propose lane
/// (ONE-1748); the wire strings are `consent_graduation::DemotionReason`.
pub(crate) const FIELD_DEMOTION_REASON: &str = "demotion_reason";
/// Who demoted a consent-graduation scope, as an entity id in lower hex: the
/// owner's or a policy holder's person, the spawning parent agent, the scope's
/// own actor, or the person whose ruling caused it. Absent on a demotion
/// recorded before the field existed. The receipt's `actor` stays the scope's.
pub(crate) const FIELD_DEMOTED_BY: &str = "demoted_by";
/// The resolution event's claim-source axis. Deliberately NOT `"source"`:
/// that key is reserved as one of the six ARCH-0056 Δ field names this
/// receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
pub(crate) const FIELD_CLAIM_SOURCE: &str = "claim_source";
/// The amended op body verbatim (lower hex) — the PRODUCER artifact.
pub(crate) const FIELD_AMENDED_BODY: &str = "amended_body";
/// The ARCH-0056 Δ slot. Minted reserved by ONE-1747; ED-01 (ONE-1757) fills
/// it from the Δ side-ledger as receipts project
/// (`edit_distance::delta::attach_amendment_deltas`), which is why the key is
/// `pub(crate)` rather than private to this module.
pub(crate) const FIELD_AMENDMENT_DELTA: &str = "amendment_delta";
/// Companion marker to [`FIELD_AMENDMENT_DELTA`]: the Δ for this amendment was
/// measured and the measurement FAILED. It exists so the two states a reader
/// would otherwise confuse stay apart — capture failure is non-fatal, but it
/// is receipted, never silent.
pub(crate) const FIELD_AMENDMENT_DELTA_UNCAPTURED: &str = "amendment_delta_uncaptured";
/// The ARCH-0056 §7 ESCALATION field class (ONE-1762, ED-06).
///
/// An escalation is a gate decision a human made, so it projects into the
/// existing `Gate` kind rather than minting one — which means the kind alone no
/// longer says which projector wrote a record. These keys are that
/// discriminator: a receipt carrying them is an escalation ruling or the
/// standing policy one earned, and `edit_distance::escalation` is the only
/// writer. They are `pub(crate)` for the same reason [`FIELD_AMENDMENT_DELTA`]
/// is — the projector lives in another module, and a second spelling of one key
/// would make the two families unjoinable.
pub(crate) const FIELD_ESCALATION_SCOPE: &str = "escalation_scope";
/// Which of the three closed triggers fired (`escalation::EscalationTrigger`).
pub(crate) const FIELD_ESCALATION_TRIGGER: &str = "escalation_trigger";
/// What was ruled (`escalation::EscalationRuling`). Also the ledger receipt's
/// `outcome`; on a standing-policy receipt the outcome is the row's STATUS, so
/// this field is what keeps one key answering "what was ruled" across the whole
/// class.
pub(crate) const FIELD_ESCALATION_RULING: &str = "escalation_ruling";
/// What the engine asked when it stopped.
pub(crate) const FIELD_ESCALATION_QUESTION: &str = "escalation_question";
/// Why the human ruled as they did.
pub(crate) const FIELD_ESCALATION_RATIONALE: &str = "escalation_rationale";
/// The ask's magnitude band. Budget-triggered escalations only.
pub(crate) const FIELD_ESCALATION_BUDGET_BAND: &str = "escalation_budget_band";
/// The band ceiling a standing policy covers — distinct from
/// [`FIELD_ESCALATION_BUDGET_BAND`], which is one ask's magnitude rather than a
/// row's reach.
pub(crate) const FIELD_ESCALATION_BAND_CEILING: &str = "escalation_band_ceiling";
/// Comma-joined receipt ids of the rulings a standing policy was learned from.
pub(crate) const FIELD_ESCALATION_CITED_RECEIPTS: &str = "escalation_cited_receipts";
/// The ONE-1449 SKILL-EDIT GATE field class (SKILL-OPT-2).
///
/// A held-out score-gate verdict is a gate decision the engine made, so it
/// projects into the existing `Gate` kind rather than minting one — the
/// [`FIELD_ESCALATION_SCOPE`] precedent, and these keys are the discriminator
/// that says which projector wrote a record. `crate::skill_optimize` is the
/// only writer, and they are `pub(crate)` for the reason that class is: a
/// second spelling of one key would make the family unjoinable with itself.
pub(crate) const FIELD_SKILL_EDIT_PROPOSAL: &str = "skill_edit_proposal";
/// The ACTIVE skill entity the gated proposal revises.
pub(crate) const FIELD_SKILL_EDIT_SKILL: &str = "skill_edit_skill";
/// Held-out replay score of the CURRENT instructions, as a decimal numeral.
///
/// Deliberately a numeral rather than prose or a digest: the whole point of the
/// pair is that a reader can compare it, and the receipt family's field ABI is
/// string-valued. The same two numbers are served already-typed by
/// `crate::skill_optimize::skill_edit_verdicts`.
pub(crate) const FIELD_SKILL_EDIT_SCORE_BEFORE: &str = "skill_edit_score_before";
/// Held-out replay score of the PROPOSED instructions, as a decimal numeral.
pub(crate) const FIELD_SKILL_EDIT_SCORE_AFTER: &str = "skill_edit_score_after";
/// JSON measurement of the two DecoEvo audits and per-axis world agreement.
pub(crate) const FIELD_SKILL_EDIT_MEASUREMENTS: &str = "skill_edit_measurements";
/// The scored goal vector, including axis classes.
pub(crate) const FIELD_SKILL_EDIT_GOAL_AXES: &str = "skill_edit_goal_axes";
/// Bound human decision evidence for a scored tradeoff.
pub(crate) const FIELD_SKILL_EDIT_TRADEOFF_RESOLUTION: &str = "skill_edit_tradeoff_resolution";
/// The Dreamer cycle the verdict counted against, for the per-cycle accept cap.
pub(crate) const FIELD_SKILL_EDIT_CYCLE: &str = "skill_edit_cycle";
/// Comma-joined reserved receipt ids the score pair was computed over.
///
/// A bounded DISPLAY list. The complete basis is
/// [`FIELD_SKILL_EDIT_HELD_OUT_COUNT`] plus
/// [`FIELD_SKILL_EDIT_HELD_OUT_DIGEST`], and
/// [`FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED`] says when this list is a prefix of
/// the truth rather than the whole of it.
pub(crate) const FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS: &str = "skill_edit_held_out_receipts";
/// How many reserved receipts the score pair was ACTUALLY computed over.
///
/// The count is the completeness check the display list cannot make: a reader
/// comparing it against `skill_edit_held_out_receipts` learns whether it is
/// looking at the whole basis or a window on it.
pub(crate) const FIELD_SKILL_EDIT_HELD_OUT_COUNT: &str = "skill_edit_held_out_count";
/// Canonical digest of the EXACT scored evidence set, in scored order.
///
/// What makes an acceptance auditable after the ledger has moved on: the set
/// itself cannot be reconstructed from a later read once more outcomes land,
/// but it can be recomputed and compared against this.
pub(crate) const FIELD_SKILL_EDIT_HELD_OUT_DIGEST: &str = "skill_edit_held_out_digest";
/// `"true"` when the display list is a bounded window on a larger basis.
/// Absent otherwise — hidden truncation is the failure this key exists to end.
pub(crate) const FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED: &str = "skill_edit_held_out_truncated";
/// Canonical content digest of the candidate body the scores were computed on.
pub(crate) const FIELD_SKILL_EDIT_PROPOSAL_DIGEST: &str = "skill_edit_proposal_digest";
/// Canonical content digest of the predecessor body the scores were computed
/// against.
pub(crate) const FIELD_SKILL_EDIT_TARGET_DIGEST: &str = "skill_edit_target_digest";
/// The accepted verdict row a post-score admission refusal answers.
///
/// A refusal reached THROUGH a standing acceptance carries that acceptance's
/// real score pair and evidence basis, so this key names the ruling it
/// supersedes rather than leaving a reader to guess which one it was.
pub(crate) const FIELD_SKILL_EDIT_ACCEPTED_VERDICT: &str = "skill_edit_accepted_verdict";
/// What the gate ruled (`skill_optimize::SkillEditDisposition`). Also the
/// receipt's `outcome`; this key keeps one name answering "what was ruled".
pub(crate) const FIELD_SKILL_EDIT_DISPOSITION: &str = "skill_edit_disposition";
/// Comma-joined cited `source_messages` ids that no longer resolve, on a
/// source-liveness refusal.
pub(crate) const FIELD_SKILL_EDIT_MISSING_SOURCES: &str = "skill_edit_missing_sources";
/// The OF-361 PRE-EXTRACTION field class (ONE-1525, ORF-2).
///
/// Unlike the escalation and skill-edit classes above, these keys do NOT need
/// a projector discriminator: they ride [`ReceiptKind::Extraction`], which
/// this class mints and `crate::dreamer_prefilter` is the only writer of. The
/// names are therefore the plain ones — a reader of an extraction receipt is
/// already in one family. They are `pub(crate)` for the same reason the
/// classes above are: the projector lives in another module, and a second
/// spelling of one key would make the family unjoinable with itself.
///
/// Which pre-extraction stage ruled (`dreamer_prefilter::PREFILTER_PHASE`).
/// Reserved as the discriminator for a SECOND extraction-phase writer, so the
/// kind never has to be split when one lands.
pub(crate) const FIELD_PREFILTER_PHASE: &str = "phase";
/// What the screen ruled: `pass` or `skip` on a turn row, `screened` on a
/// round rollup. Also the receipt's `outcome`; this key keeps one name
/// answering "what was ruled" across the whole class.
pub(crate) const FIELD_PREFILTER_DECISION: &str = "decision";
/// The turn's screening score, as a decimal numeral.
///
/// A numeral rather than a band: the whole point of a score is that a reader
/// can compare it against the threshold that rejected it, and the receipt
/// family's field ABI is string-valued.
pub(crate) const FIELD_PREFILTER_SCORE: &str = "score";
/// The threshold the score was ruled against — without it the score is a
/// number with no verdict in it.
pub(crate) const FIELD_PREFILTER_THRESHOLD: &str = "threshold";
/// Prefix of the per-axis feature keys (`features.len`, `features.novelty`,
/// …). Every input to the score travels with it, so a ruling can be
/// recomputed rather than trusted.
pub(crate) const FIELD_PREFILTER_FEATURE_PREFIX: &str = "features.";
/// The planning round's `partition_round_hash`, lower hex — the join key
/// between a skip row and the rollup that counted it.
pub(crate) const FIELD_PREFILTER_ROUND: &str = "round";
/// The screened TURN, lower hex.
pub(crate) const FIELD_PREFILTER_TURN: &str = "turn";
/// Rollup: how many turns the round screened.
pub(crate) const FIELD_PREFILTER_SCANNED: &str = "scanned";
/// Rollup: how many were kept for extraction.
pub(crate) const FIELD_PREFILTER_PASSED: &str = "passed";
/// Rollup: how many were screened out.
pub(crate) const FIELD_PREFILTER_SKIPPED: &str = "skipped";
/// Estimated prompt tokens NOT spent — per turn on a skip row, summed over the
/// round on a rollup. The savings claim is on the receipt because a budget
/// filter that could not show its savings would be asking to be believed.
pub(crate) const FIELD_PREFILTER_TOKENS_SAVED: &str = "tokens_saved";

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Query filters for the unified receipt family.
///
/// Empty `kinds` means all supported receipt kinds. `start_at` and `end_at`
/// are inclusive Unix-second bounds over the receipt event time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptQuery {
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub kinds: BTreeSet<ReceiptKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_at: Option<u64>,
    /// Only receipts naming this ASSET (lower hex) in their `asset_ref`
    /// field: the served-form receipts of one asset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    /// Exclusive cursor: only receipts after this position in newest-first
    /// order, the last row of the page before (FIX 11297). A walk pages by it,
    /// so no number of receipts sharing one second stops the walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<ReceiptScanPosition>,
    #[serde(default = "default_receipt_query_limit")]
    pub limit: usize,
}

impl Default for ReceiptQuery {
    fn default() -> Self {
        Self {
            kinds: BTreeSet::new(),
            actor: None,
            outcome: None,
            job_ref: None,
            start_at: None,
            end_at: None,
            asset_ref: None,
            after: None,
            limit: DEFAULT_RECEIPT_QUERY_LIMIT,
        }
    }
}

impl ReceiptQuery {
    /// Builds an all-kind query with an explicit result limit.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit,
            ..Self::default()
        }
    }

    /// Adds one kind filter.
    #[must_use]
    pub fn with_kind(mut self, kind: ReceiptKind) -> Self {
        self.kinds.insert(kind);
        self
    }

    /// Adds an actor filter.
    #[must_use]
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Adds an outcome filter.
    #[must_use]
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.outcome = Some(outcome.into());
        self
    }

    /// Adds a brief/attempt filter for brief-rooted receipt projections.
    #[must_use]
    pub fn with_job_ref(mut self, job_ref: impl Into<String>) -> Self {
        self.job_ref = Some(job_ref.into());
        self
    }

    /// Adds an asset filter: receipts whose `asset_ref` field names
    /// `asset_ref`, such as the served-form receipts of one ASSET.
    #[must_use]
    pub fn with_asset_ref(mut self, asset_ref: impl Into<String>) -> Self {
        self.asset_ref = Some(asset_ref.into());
        self
    }

    /// Starts the query after `position`, the last receipt of the page
    /// before, in newest-first order (FIX 11297).
    #[must_use]
    pub fn with_after(mut self, position: ReceiptScanPosition) -> Self {
        self.after = Some(position);
        self
    }

    /// Adds inclusive Unix-second time bounds.
    #[must_use]
    pub const fn with_time_bounds(mut self, start_at: Option<u64>, end_at: Option<u64>) -> Self {
        self.start_at = start_at;
        self.end_at = end_at;
        self
    }

    pub(crate) fn includes_kind(&self, kind: ReceiptKind) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&kind)
    }

    pub(crate) fn matches(&self, receipt: &ReceiptRecord) -> bool {
        if !self.includes_kind(receipt.receipt_kind) {
            return false;
        }
        if let Some(actor) = self.actor.as_deref()
            && receipt.actor.as_deref() != Some(actor)
            && receipt.on_behalf_of.as_deref() != Some(actor)
        {
            return false;
        }
        if let Some(outcome) = self.outcome.as_deref()
            && receipt.outcome != outcome
        {
            return false;
        }
        if let Some(start_at) = self.start_at
            && receipt.occurred_at < start_at
        {
            return false;
        }
        if let Some(end_at) = self.end_at
            && receipt.occurred_at > end_at
        {
            return false;
        }
        if let Some(asset_ref) = self.asset_ref.as_deref()
            && receipt.fields.get(FIELD_ASSET_REF).map(String::as_str) != Some(asset_ref)
        {
            return false;
        }
        if let Some(after) = &self.after
            && !after.precedes(receipt)
        {
            return false;
        }
        true
    }
}

/// One projected receipt-family row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptRecord {
    pub receipt_id: String,
    pub receipt_kind: ReceiptKind,
    pub occurred_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_trace: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

impl ReceiptRecord {
    /// This receipt's free text as the side-row wall keeps it (OF-067), read in
    /// the caller's transaction for the row at `at` (its place and key); `true`
    /// when the wall placed a handle.
    ///
    /// Free text is the open `fields` map, names and values, but for the names
    /// in `except` that the row's own identity or evidence reads. The kind,
    /// outcome, ids, refs, stamps and policy trace are engine-authored and stay
    /// as written.
    pub(crate) fn admit_free_text(
        &mut self,
        dbs: &impl crate::side_table::SideTableDbs,
        wtxn: &mut heed::RwTxn<'_>,
        at: (&str, &[u8]),
        except: &[&str],
    ) -> crate::Result<bool> {
        let mut free: BTreeMap<String, String> = self
            .fields
            .iter()
            .filter(|(name, _)| !except.contains(&name.as_str()))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        if free.is_empty() {
            return Ok(false);
        }
        let names: BTreeSet<String> = free.keys().cloned().collect();
        if !crate::batch::secret_scan::admit_typed(dbs, wtxn, at, &mut free)? {
            return Ok(false);
        }
        self.fields.retain(|name, _| !names.contains(name));
        self.fields.extend(free);
        Ok(true)
    }
}

/// A receipt-family result with explicit source and result-limit completeness.
///
/// Only `complete` proves that `records` contains every matching receipt.
/// Incomplete records are not a safe candidate set for ranking or lifecycle folds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScan {
    pub records: Vec<ReceiptRecord>,
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<ReceiptScanContinuation>,
    /// Send receipt rows skipped as undecodable (FIX 12044): counted, never
    /// read as receipts. A diagnostic of the scan.
    pub undecodable: u32,
}

/// Boundaries of omitted data, not a snapshot or a globally ordered page token.
///
/// Source and result truncation are independent: both boundaries can be present.
/// A source boundary is retained even when every scanned row is filtered out.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScanContinuation {
    /// Exclusive raw ledger key for continuing the reverse attempt-pack walk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_pack_before: Option<Vec<u8>>,
    /// First matching record omitted by the result limit, in receipt sort order.
    /// This does not describe rows omitted by a source work cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_record: Option<ReceiptScanPosition>,
}

/// Inclusive position in newest-first receipt order (time descending, kind/id ascending).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptScanPosition {
    pub occurred_at: u64,
    pub receipt_kind: ReceiptKind,
    pub receipt_id: String,
}

impl ReceiptScanPosition {
    /// The position of `receipt` in newest-first receipt order.
    #[must_use]
    pub fn of(receipt: &ReceiptRecord) -> Self {
        Self {
            occurred_at: receipt.occurred_at,
            receipt_kind: receipt.receipt_kind,
            receipt_id: receipt.receipt_id.clone(),
        }
    }

    /// Whether `receipt` comes after this position in newest-first order:
    /// older, or as old and after it by kind, then id.
    #[must_use]
    pub fn precedes(&self, receipt: &ReceiptRecord) -> bool {
        receipt
            .occurred_at
            .cmp(&self.occurred_at)
            .then_with(|| self.receipt_kind.cmp(&receipt.receipt_kind))
            .then_with(|| self.receipt_id.as_str().cmp(receipt.receipt_id.as_str()))
            .is_lt()
    }
}

impl ReceiptScan {
    pub(crate) fn from_complete_records(records: Vec<ReceiptRecord>) -> Self {
        Self {
            records,
            complete: true,
            continuation: None,
            undecodable: 0,
        }
    }

    pub(crate) fn mark_incomplete(&mut self) -> &mut ReceiptScanContinuation {
        self.complete = false;
        self.continuation
            .get_or_insert_with(ReceiptScanContinuation::default)
    }
}

/// Minimal OF-367/RCPT-3 seam for consumers that render receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptView {
    pub component: String,
    pub receipt: ReceiptRecord,
}

impl ReceiptView {
    #[must_use]
    pub fn new(receipt: ReceiptRecord) -> Self {
        Self {
            component: RECEIPT_VIEW_COMPONENT.to_owned(),
            receipt,
        }
    }
}

pub(crate) fn projection_scan_query(mut query: ReceiptQuery) -> ReceiptQuery {
    query.limit = MAX_RECEIPT_QUERY_SCAN;
    query
}

pub(crate) fn lineage_scan_query() -> ReceiptQuery {
    ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN)
}

pub(crate) fn receipt_newest_first_order(
    left: &ReceiptRecord,
    right: &ReceiptRecord,
) -> std::cmp::Ordering {
    right
        .occurred_at
        .cmp(&left.occurred_at)
        .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
        .then_with(|| left.receipt_id.cmp(&right.receipt_id))
}

/// Keeps at most `limit` records, evicting the oldest under
/// [`receipt_newest_first_order`] — the SAME order
/// [`finalize_receipt_query_records`] finally sorts by, which is what makes a
/// bounded projector buffer lossless with respect to the public answer.
pub(crate) fn retain_newest_receipt(
    receipts: &mut Vec<ReceiptRecord>,
    receipt: ReceiptRecord,
    limit: usize,
) {
    if receipts.len() < limit {
        receipts.push(receipt);
        return;
    }
    let Some((oldest_index, oldest)) = receipts
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| receipt_newest_first_order(left, right))
    else {
        return;
    };
    if receipt_newest_first_order(&receipt, oldest).is_lt() {
        receipts[oldest_index] = receipt;
    }
}
