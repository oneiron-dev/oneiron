use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub(super) const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
pub(crate) const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;

#[cfg(test)]
thread_local! {
    pub(super) static GATE_RECEIPT_PAGES_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static GATE_RECEIPT_MAX_BUFFERED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(super) static ATTEMPT_PACK_SCAN_CAPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn reset_gate_receipt_pages_scanned() {
    GATE_RECEIPT_PAGES_SCANNED.set(0);
    GATE_RECEIPT_MAX_BUFFERED.set(0);
}

#[cfg(test)]
pub(super) fn gate_receipt_pages_scanned() -> usize {
    GATE_RECEIPT_PAGES_SCANNED.get()
}

#[cfg(test)]
pub(super) fn gate_receipt_max_buffered() -> usize {
    GATE_RECEIPT_MAX_BUFFERED.get()
}

#[cfg(test)]
pub(super) fn attempt_pack_scan_capped() -> usize {
    ATTEMPT_PACK_SCAN_CAPPED.get()
}

#[cfg(test)]
pub(super) fn reset_attempt_pack_scan_capped() {
    ATTEMPT_PACK_SCAN_CAPPED.set(0);
}
pub(super) const RECEIPT_VIEW_COMPONENT: &str = "receipt_view";
pub(super) const FIELD_JOB_REF: &str = "job_ref";
pub(super) const FIELD_BRIEF_REF: &str = "brief_ref";
pub(super) const FIELD_RUN_REF: &str = "run_ref";
pub(super) const FIELD_INTENT_REF: &str = "intent_ref";
/// Originating connector-send TASK carried by durable outbound receipts.
pub const FIELD_TASK_REF: &str = "task_ref";
/// Durable proof that the connector execution sink was reached successfully.
pub const FIELD_TRANSPORT_DISPATCHED: &str = "transport_dispatched";
/// ARCH-0053 §2 pack manifest: the `skill_id@version` rows the attempt loaded,
/// as a canonical JSON array string.
pub const FIELD_MANIFEST_SKILLS: &str = "manifest.skills";
/// ARCH-0053 §2 pack manifest: the `actor.*` claim rows the attempt loaded, as
/// a canonical JSON array string.
pub const FIELD_MANIFEST_ACTOR_CLAIMS: &str = "manifest.actor_claims";

pub(super) const FIELD_PARENT_REF: &str = "parent_ref";
pub(super) const FIELD_COUNTERPARTY_REF: &str = "counterparty_ref";
pub(super) const FIELD_IDENTITY_REF: &str = "identity_ref";
pub(super) const FIELD_CHANNEL_IDENTITY_REF: &str = "channel_identity_ref";
pub(super) const FIELD_RECEIVING_IDENTITY_REF: &str = "receiving_identity_ref";
pub(crate) const FIELD_GRANT_REF: &str = "grant_ref";
pub(super) const FIELD_BUNDLE_REF: &str = "bundle_ref";
pub(super) const FIELD_BUDGET_DEBIT: &str = "budget_debit";
pub(super) const FIELD_BUDGET: &str = "budget";
pub(super) const FIELD_FIRST_TOUCH: &str = "first_touch";
pub(super) const FIELD_OPT_OUT: &str = "opt_out";
pub(super) const FIELD_PROMO_CONSENT: &str = "promo_consent";
pub(super) const FIELD_PERSONA_COMPILE_STAMP: &str = "persona_compile_stamp";
pub(super) const FIELD_ACTIVATED_MEMORY_IDS: &str = "activated_memory_ids";
pub(super) const FIELD_BOARD_STATE_REF: &str = "board_state_ref";
pub(super) const FIELD_SUBSTRATE_REF: &str = "substrate_ref";
pub(super) const FIELD_MODEL: &str = "model";
pub(super) const FIELD_REASONING_EFFORT: &str = "reasoning_effort";
pub(super) const FIELD_PROMPT_INPUT_REF: &str = "prompt_input_ref";
pub(super) const FIELD_DISCLOSURE_STAMP: &str = "disclosure_stamp";

/// ARCH-0055 r7 proposal-outcome receipt fields (ONE-1747).
///
/// The three ramp-scope keys are `pub(crate)` because ONE-1748's demotion
/// receipt names the SAME scope tuple: two spellings of one key would make the
/// ramp's own receipts unjoinable with the outcome receipts they answer.
pub(super) const FIELD_PROPOSAL_REF: &str = "proposal_ref";
pub(crate) const FIELD_OP_KIND: &str = "op_kind";
pub(crate) const FIELD_TARGET_CLASS: &str = "target_class";
pub(crate) const FIELD_SCOPE_ACTOR: &str = "actor";
/// Why a consent-graduation scope was demoted back to the propose lane
/// (ONE-1748); the wire strings are `consent_graduation::DemotionReason`.
pub(crate) const FIELD_DEMOTION_REASON: &str = "demotion_reason";
/// The resolution event's claim-source axis. Deliberately NOT `"source"`:
/// that key is reserved as one of the six ARCH-0056 Δ field names this
/// receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
pub(super) const FIELD_CLAIM_SOURCE: &str = "claim_source";
/// The amended op body verbatim (lower hex) — the PRODUCER artifact.
pub(super) const FIELD_AMENDED_BODY: &str = "amended_body";
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
pub(super) const FIELD_RECEIPT_SCHEMA: &str = "receipt_schema";
pub(super) const FIELD_ENGINE_REGISTER: &str = "engine_register";
pub(super) const FIELD_CARE_REGISTER: &str = "care_register";
pub(super) const FIELD_AUDIT_REGISTER: &str = "audit_register";

const fn default_receipt_query_limit() -> usize {
    DEFAULT_RECEIPT_QUERY_LIMIT
}

/// Receipt family discriminator pinned by OF-367 RS1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReceiptKind {
    /// Outbound effect receipt.
    Outbound,
    /// Gate decision/stamp receipt.
    Gate,
    /// Companion/persona identity lifecycle receipt.
    IdentityLifecycle,
    /// Scoped read/access receipt.
    ScopedRead,
    /// Share/federation receipt.
    Share,
    /// Retained-output settle receipt: an [`EditProposal`] was selected into a
    /// new artifact version or discarded (OF-368 D6, ARTL-4). Projects from the
    /// blob-artifact settlement substrate, so it is a floor receipt (persists
    /// through its own store, never rides the session-local emit log).
    ///
    /// [`EditProposal`]: crate::edit_roundtrip::EditProposal
    ArtifactSettle,
    /// Outcome receipt of a resolved identity-topology proposal (ARCH-0055
    /// r7, ONE-1747): what was proposed, what the decider ruled, and — on an
    /// amended approval — the amended op body verbatim. Projects from the
    /// type-76 resolution ledger event; there is no separate receipt store.
    ProposalOutcome,
}

impl ReceiptKind {
    /// Returns the stable query string for this receipt kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Gate => "gate",
            Self::IdentityLifecycle => "identity_lifecycle",
            Self::ScopedRead => "scoped_read",
            Self::Share => "share",
            Self::ArtifactSettle => "artifact_settle",
            Self::ProposalOutcome => "proposal_outcome",
        }
    }

    /// Parses a stable receipt kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "outbound" => Some(Self::Outbound),
            "gate" => Some(Self::Gate),
            "identity_lifecycle" => Some(Self::IdentityLifecycle),
            "scoped_read" => Some(Self::ScopedRead),
            "share" => Some(Self::Share),
            "artifact_settle" => Some(Self::ArtifactSettle),
            "proposal_outcome" => Some(Self::ProposalOutcome),
            _ => None,
        }
    }

    /// Returns true when this receipt kind is stamped on an agent emit
    /// (OF-369/RS9: chat turn, voice utterance, outbound send, artifact
    /// write). Only emit-adjacent receipts carry the context receipt
    /// field-set; today the outbound send receipt is the only emit path
    /// with a receipt, and future emit receipt kinds extend this match.
    #[must_use]
    pub const fn is_emit_adjacent(self) -> bool {
        matches!(self, Self::Outbound)
    }
}

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

    /// Adds inclusive Unix-second time bounds.
    #[must_use]
    pub const fn with_time_bounds(mut self, start_at: Option<u64>, end_at: Option<u64>) -> Self {
        self.start_at = start_at;
        self.end_at = end_at;
        self
    }

    pub(super) fn includes_kind(&self, kind: ReceiptKind) -> bool {
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
        true
    }
}

/// One projected receipt-family row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Minimal OF-367/RCPT-3 seam for consumers that render receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub(super) fn projection_scan_query(mut query: ReceiptQuery) -> ReceiptQuery {
    query.limit = MAX_RECEIPT_QUERY_SCAN;
    query
}

pub(super) fn lineage_scan_query() -> ReceiptQuery {
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

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
