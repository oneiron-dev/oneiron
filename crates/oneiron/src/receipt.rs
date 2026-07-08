//! Unified receipt-family query surface over existing receipt emitters.
//!
//! RS1 is intentionally a projection over existing event substrates. This
//! module does not mint a new receipt store and does not change emitter schema.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantScope, decode_access_grant_body};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::outbound::OutboundIntent;
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, decode_standing_outbound_grant_body,
};
use crate::persona_snapshot::{PersonaSnapshotExportRecord, decode_persona_snapshot_export_body};
use crate::prompt::PromptRecompileStamp;
use crate::store::{
    ChannelIdentityLifecycleReceiptRecord, GateDecisionRecord, GateSystemNoticeRecord,
    PendingGateConsentRecord,
};
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_COMPANION_REGISTER,
    ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
    EiriMemoryBoard, EntityId,
    companion::{
        CompanionLifecycleEvent, CompanionRecord, CompanionScope, CompanionSubject,
        decode_companion_record_body,
    },
};

const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
pub(crate) const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;
const RECEIPT_VIEW_COMPONENT: &str = "receipt_view";
const FIELD_JOB_REF: &str = "job_ref";
const FIELD_BRIEF_REF: &str = "brief_ref";
const FIELD_RUN_REF: &str = "run_ref";
const FIELD_INTENT_REF: &str = "intent_ref";
const FIELD_PARENT_REF: &str = "parent_ref";
const FIELD_COUNTERPARTY_REF: &str = "counterparty_ref";
const FIELD_IDENTITY_REF: &str = "identity_ref";
const FIELD_CHANNEL_IDENTITY_REF: &str = "channel_identity_ref";
const FIELD_RECEIVING_IDENTITY_REF: &str = "receiving_identity_ref";
const FIELD_GRANT_REF: &str = "grant_ref";
const FIELD_BUNDLE_REF: &str = "bundle_ref";
const FIELD_BUDGET_DEBIT: &str = "budget_debit";
const FIELD_BUDGET: &str = "budget";
const FIELD_FIRST_TOUCH: &str = "first_touch";
const FIELD_OPT_OUT: &str = "opt_out";
const FIELD_PROMO_CONSENT: &str = "promo_consent";
const FIELD_PERSONA_COMPILE_STAMP: &str = "persona_compile_stamp";
const FIELD_ACTIVATED_MEMORY_IDS: &str = "activated_memory_ids";
const FIELD_BOARD_STATE_REF: &str = "board_state_ref";
const FIELD_SUBSTRATE_REF: &str = "substrate_ref";
const FIELD_MODEL: &str = "model";
const FIELD_REASONING_EFFORT: &str = "reasoning_effort";
const FIELD_PROMPT_INPUT_REF: &str = "prompt_input_ref";
const BOARD_STATE_REF_PREFIX: &str = "board:";
const ACTIVATED_MEMORY_IDS_SEPARATOR: char = ',';
const FIELD_RECEIPT_SCHEMA: &str = "receipt_schema";
const FIELD_ENGINE_REGISTER: &str = "engine_register";
const FIELD_CARE_REGISTER: &str = "care_register";
const FIELD_AUDIT_REGISTER: &str = "audit_register";
const SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY: &str = "third_party";
const SYSTEM_NOTICE_AUDIENCE_ALL: &str = "all";
const OUTBOUND_RECEIPT_SCHEMA: &str = "outbound_receipt.v1";
const OUTBOUND_ENGINE_REGISTER: &str = "neutral";
const OUTBOUND_CARE_REGISTER: &str = "eirispec_care_register";
const OUTBOUND_AUDIT_REGISTER: &str = "dashboard_atom_kit_audit";

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

    /// Adds a brief/job filter for brief-rooted receipt projections.
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

    fn includes_kind(&self, kind: ReceiptKind) -> bool {
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

/// OF-369/RS9 context receipt field-set on emit-adjacent receipts.
///
/// Every agent emit is stamped with the exact assembled context that
/// produced it, so "why did she say that" is answered by READING a receipt,
/// never by re-deriving. Record-not-replay law: the LEDGER/bitemporal
/// substrate replays facts-at-T, but derived views (retrieval output, the
/// board as shown) drift with embedder/index/ranker versions, so they are
/// RECORDED here at emit time and never recomputed.
///
/// This is a field-set on the RS1 shared spine, NOT a new receipt kind: it
/// rides the `fields` map of receipts whose kind is
/// [`ReceiptKind::is_emit_adjacent`].
///
/// The provenance joins (`substrate_ref`, `model`, `reasoning_effort`)
/// mirror the ratified provenance ABI, where `substrate_ref` and
/// `reasoning_effort` are themselves optional fields: they are recorded
/// when the emit's provenance carries them, absent otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextReceiptFields {
    /// The OF-217 B9 standing-block compile id in effect for this emit.
    pub persona_compile_stamp: String,
    /// The claim/summary entity ids actually placed in context this emit,
    /// in board row order.
    pub activated_memory_ids: Vec<String>,
    /// Content-hash ref of the assembled context board at emit.
    pub board_state_ref: String,
    /// Provenance join: ref of the MODEL substrate entity in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substrate_ref: Option<String>,
    /// Provenance join: model identifier in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Provenance join: reasoning-effort scalar in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<String>,
    /// When OF-236 pre-compression ran, the post-compression input hash
    /// (r-knob auditability).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_input_ref: Option<String>,
}

impl ContextReceiptFields {
    /// Captures the field-set at the context-assembly seam — the one hook
    /// where the activation set is finalized (OF-369/RS9 emission point).
    ///
    /// `persona_compile_stamp` records the compile id of the resolved
    /// standing-block prompt in effect; `activated_memory_ids` and
    /// `board_state_ref` record the assembled memory board as shown.
    pub fn from_assembly(persona: &PromptRecompileStamp, board: &EiriMemoryBoard) -> Result<Self> {
        Ok(Self {
            persona_compile_stamp: format!(
                "{}:{}",
                persona.schema_version, persona.resolved_fingerprint
            ),
            activated_memory_ids: board.rows.iter().map(|row| row.id.clone()).collect(),
            board_state_ref: eiri_memory_board_state_ref(board)?,
            substrate_ref: None,
            model: None,
            reasoning_effort: None,
            prompt_input_ref: None,
        })
    }

    /// Joins the provenance `substrate_ref` (MODEL entity ref) to the stamp.
    #[must_use]
    pub fn substrate_ref(mut self, substrate_ref: impl Into<String>) -> Self {
        self.substrate_ref = Some(substrate_ref.into());
        self
    }

    /// Joins the provenance model identifier to the stamp.
    #[must_use]
    pub fn model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Joins the provenance reasoning-effort scalar to the stamp.
    #[must_use]
    pub fn reasoning_effort(mut self, reasoning_effort: impl Into<String>) -> Self {
        self.reasoning_effort = Some(reasoning_effort.into());
        self
    }

    /// Records the OF-236 post-compression prompt input hash.
    #[must_use]
    pub fn prompt_input_ref(mut self, prompt_input_ref: impl Into<String>) -> Self {
        self.prompt_input_ref = Some(prompt_input_ref.into());
        self
    }

    pub(crate) fn append_to_fields(&self, fields: &mut BTreeMap<String, String>) {
        fields.insert(
            FIELD_PERSONA_COMPILE_STAMP.to_owned(),
            self.persona_compile_stamp.clone(),
        );
        fields.insert(
            FIELD_ACTIVATED_MEMORY_IDS.to_owned(),
            self.activated_memory_ids
                .join(&ACTIVATED_MEMORY_IDS_SEPARATOR.to_string()),
        );
        fields.insert(
            FIELD_BOARD_STATE_REF.to_owned(),
            self.board_state_ref.clone(),
        );
        if let Some(substrate_ref) = self.substrate_ref.as_ref() {
            fields.insert(FIELD_SUBSTRATE_REF.to_owned(), substrate_ref.clone());
        }
        if let Some(model) = self.model.as_ref() {
            fields.insert(FIELD_MODEL.to_owned(), model.clone());
        }
        if let Some(reasoning_effort) = self.reasoning_effort.as_ref() {
            fields.insert(FIELD_REASONING_EFFORT.to_owned(), reasoning_effort.clone());
        }
        if let Some(prompt_input_ref) = self.prompt_input_ref.as_ref() {
            fields.insert(FIELD_PROMPT_INPUT_REF.to_owned(), prompt_input_ref.clone());
        }
    }
}

/// Computes the content-hash ref of an assembled context board.
///
/// The ref covers the board as shown (rows, scores, budget, companion), so
/// any drift in retrieval output produces a different ref while already
/// recorded receipts keep the ref captured at their emit.
pub fn eiri_memory_board_state_ref(board: &EiriMemoryBoard) -> Result<String> {
    let bytes = rmp_serde::to_vec_named(board)
        .map_err(|_| Error::InvariantViolation("memory board state ref encode failed"))?;
    Ok(format!(
        "{BOARD_STATE_REF_PREFIX}{}",
        hex_lower(blake3::hash(&bytes).as_bytes())
    ))
}

/// Attaches the OF-369 context field-set to an emit-adjacent receipt.
///
/// Non-emit receipts never carry emit context; attaching to one is rejected
/// without modifying the receipt.
pub fn append_context_receipt_fields(
    receipt: &mut ReceiptRecord,
    context: &ContextReceiptFields,
) -> Result<()> {
    if !receipt.receipt_kind.is_emit_adjacent() {
        return Err(Error::EmitAdjacentReceiptRequired {
            surface: "context receipt field-set",
            kind: receipt.receipt_kind.as_str(),
        });
    }
    context.append_to_fields(&mut receipt.fields);
    Ok(())
}

impl ReceiptRecord {
    /// Reads the OF-369 context field-set recorded on this receipt.
    ///
    /// Returns `None` on non-emit receipt kinds and on emit receipts that
    /// were stamped before the field-set existed. The values are read from
    /// the recorded fields alone — never recomputed from live index state.
    #[must_use]
    pub fn context_receipt_fields(&self) -> Option<ContextReceiptFields> {
        if !self.receipt_kind.is_emit_adjacent() {
            return None;
        }
        let persona_compile_stamp = self.fields.get(FIELD_PERSONA_COMPILE_STAMP)?;
        let activated_memory_ids = self.fields.get(FIELD_ACTIVATED_MEMORY_IDS)?;
        let board_state_ref = self.fields.get(FIELD_BOARD_STATE_REF)?;
        Some(ContextReceiptFields {
            persona_compile_stamp: persona_compile_stamp.clone(),
            activated_memory_ids: activated_memory_ids
                .split(ACTIVATED_MEMORY_IDS_SEPARATOR)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect(),
            board_state_ref: board_state_ref.clone(),
            substrate_ref: self.fields.get(FIELD_SUBSTRATE_REF).cloned(),
            model: self.fields.get(FIELD_MODEL).cloned(),
            reasoning_effort: self.fields.get(FIELD_REASONING_EFFORT).cloned(),
            prompt_input_ref: self.fields.get(FIELD_PROMPT_INPUT_REF).cloned(),
        })
    }
}

/// Session-local holder for emit-adjacent receipts (OF-326 interaction).
///
/// Emit-adjacent receipts follow the transcript: in an off-record session
/// they are session-local and deleted with the transcript at session close
/// (the context field-set — `activated_memory_ids` above all — would betray
/// what the room was about). Floor receipts never ride this log: they
/// project from their own stored substrates and persist regardless of
/// session mode, which is exactly the OF-326 "only floor receipts persist"
/// split.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLocalReceiptLog {
    session_ref: String,
    off_record: bool,
    receipts: Vec<ReceiptRecord>,
}

impl SessionLocalReceiptLog {
    /// Opens the emit receipt log for an on-record session: receipts are
    /// retained at close.
    #[must_use]
    pub fn on_record(session_ref: impl Into<String>) -> Self {
        Self {
            session_ref: session_ref.into(),
            off_record: false,
            receipts: Vec::new(),
        }
    }

    /// Opens the emit receipt log for an off-record session: receipts are
    /// deleted with the transcript at close.
    #[must_use]
    pub fn off_record(session_ref: impl Into<String>) -> Self {
        Self {
            session_ref: session_ref.into(),
            off_record: true,
            receipts: Vec::new(),
        }
    }

    #[must_use]
    pub fn session_ref(&self) -> &str {
        &self.session_ref
    }

    #[must_use]
    pub const fn is_off_record(&self) -> bool {
        self.off_record
    }

    /// Records one emit-adjacent receipt into the session-local log.
    ///
    /// Non-emit receipts are rejected: they persist through their own
    /// substrates and must never become deletable via session close.
    pub fn record(&mut self, receipt: ReceiptRecord) -> Result<()> {
        if !receipt.receipt_kind.is_emit_adjacent() {
            return Err(Error::EmitAdjacentReceiptRequired {
                surface: "session-local receipt log",
                kind: receipt.receipt_kind.as_str(),
            });
        }
        self.receipts.push(receipt);
        Ok(())
    }

    /// The receipts visible while the session lives, regardless of mode.
    #[must_use]
    pub fn receipts(&self) -> &[ReceiptRecord] {
        &self.receipts
    }

    /// Closes the session log. On-record sessions retain their emit
    /// receipts; off-record sessions delete them with the transcript.
    #[must_use]
    pub fn close(self) -> SessionReceiptClose {
        let (retained, deleted) = if self.off_record {
            (Vec::new(), self.receipts.len())
        } else {
            (self.receipts, 0)
        };
        SessionReceiptClose {
            session_ref: self.session_ref,
            off_record: self.off_record,
            retained,
            deleted,
        }
    }
}

/// Outcome of closing a [`SessionLocalReceiptLog`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionReceiptClose {
    pub session_ref: String,
    pub off_record: bool,
    /// Emit receipts that survive the close (empty for off-record sessions).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retained: Vec<ReceiptRecord>,
    /// Count of emit receipts deleted with the transcript.
    pub deleted: usize,
}

/// Query for the EF-055 pending tray lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayQuery {
    pub now: u64,
    pub limit: usize,
}

impl PendingTrayQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: crate::unix_seconds_now(),
            limit,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self { now, limit }
    }
}

/// One current pending ask for the logbook tray lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTrayAsk {
    pub claim_id: String,
    pub created_at: u64,
    pub age_secs: u64,
    pub hold_reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hold_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dreamer_run_id: Option<String>,
    pub receipt_view: ReceiptView,
}

/// Brief-rooted receipt projection for the B2 RS4 project view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefReceiptProjection {
    pub brief_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runs: Vec<ReceiptProjectionRun>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consent_grants: Vec<ReceiptRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One run under a brief-rooted receipt projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionRun {
    pub run_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intents: Vec<ReceiptProjectionIntent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// One outbound intent under a projected run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptProjectionIntent {
    pub intent_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-counterparty receipt projection for "who have you contacted on my behalf".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterpartyReceiptProjection {
    pub counterparty_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_touch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_out: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promo_consent: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Per-grant receipt projection for "this grant produced N sends".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantReceiptProjection {
    pub grant_ref: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipts: Vec<ReceiptRecord>,
    pub budget_debit_total: u64,
}

/// Query for the OF-367 RS6.5 standing outbound-grants lens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantsLensQuery {
    pub limit: usize,
    pub receipt_limit_per_grant: usize,
}

impl StandingOutboundGrantsLensQuery {
    #[must_use]
    pub const fn new(limit: usize, receipt_limit_per_grant: usize) -> Self {
        Self {
            limit,
            receipt_limit_per_grant,
        }
    }
}

/// Grants-page projection over active, stale, and revoked standing grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantsLens {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<StandingOutboundGrantLensRow>,
}

/// One standing outbound-grant row for the grants page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantLensRow {
    pub grant_ref: String,
    pub origin_component_id: String,
    pub origin_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_receipt_ref: Option<String>,
    pub scope_dial: String,
    pub status: String,
    pub stale: bool,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<u64>,
    pub receipt_join: GrantReceiptProjection,
    pub revoke_action: StandingOutboundGrantRevokeAction,
}

/// Host-interpreted one-tap revoke command for a grants lens row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantRevokeAction {
    pub command: String,
    pub grant_ref: String,
}

impl Vault {
    /// Queries the unified receipt family across existing receipt emitters.
    pub fn receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        receipt_family_query(self, &query)
    }

    /// Alias for callers that prefer verb-first query naming.
    pub fn query_receipts(&self, query: ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
        self.receipts(query)
    }

    /// Returns the current pending tray lane rows backed by Pending-state Gate receipts.
    pub fn pending_tray(&self, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
        pending_tray_query(self, query)
    }

    /// Resolves a stale pending ask by emitting a `let_go` receipt and removing it from the tray.
    pub fn let_go_pending_ask(&self, claim_id: &EntityId) -> Result<Option<ReceiptRecord>> {
        self.let_go_pending_ask_at(claim_id, crate::unix_seconds_now())
    }

    /// Testable variant of [`Vault::let_go_pending_ask`] with an explicit event time.
    pub fn let_go_pending_ask_at(
        &self,
        claim_id: &EntityId,
        now: u64,
    ) -> Result<Option<ReceiptRecord>> {
        let emitted = self.with_write_txn(|wtxn| {
            self.store
                .let_go_pending_gate_consent_in_txn(wtxn, claim_id, now)
        })?;
        Ok(emitted.as_ref().map(gate_decision_receipt))
    }

    /// Computes the brief-rooted receipt projection from the unified family.
    pub fn receipt_projection_by_brief(
        &self,
        brief_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<BriefReceiptProjection> {
        Ok(project_receipts_by_brief(brief_ref, self.receipts(query)?))
    }

    /// Computes per-counterparty receipt projections from the unified family.
    pub fn receipt_projections_by_counterparty(
        &self,
        query: ReceiptQuery,
    ) -> Result<Vec<CounterpartyReceiptProjection>> {
        if query.limit == 0 {
            return Ok(Vec::new());
        }
        let receipts = self.receipts(projection_scan_query(query))?;
        let contact_records = counterparty_contact_records_for_receipts(self, &receipts)?;
        Ok(project_receipts_by_counterparty_with_contacts(
            receipts,
            &contact_records,
        ))
    }

    /// Computes the per-grant receipt projection from the unified family.
    pub fn receipt_projection_by_grant(
        &self,
        grant_ref: impl Into<String>,
        query: ReceiptQuery,
    ) -> Result<GrantReceiptProjection> {
        let limit = query.limit;
        if limit == 0 {
            return Ok(project_receipts_by_grant_limited(
                grant_ref,
                Vec::new(),
                limit,
            ));
        }
        Ok(project_receipts_by_grant_limited(
            grant_ref,
            self.receipts(projection_scan_query(query))?,
            limit,
        ))
    }

    /// Computes the standing outbound-grants lens behind the logbook.
    pub fn standing_outbound_grants_lens(
        &self,
        query: StandingOutboundGrantsLensQuery,
    ) -> Result<StandingOutboundGrantsLens> {
        standing_outbound_grants_lens(self, query)
    }
}

/// Builds an outbound receipt row from the OF-327 intent spine.
///
/// The helper keeps `job_ref` propagation explicit for brief-rooted runs while
/// preserving legacy compatibility: callers that pass an older intent without a
/// job ref still emit a receipt with `job_ref: None`.
#[must_use]
pub fn outbound_intent_receipt(
    receipt_id: impl Into<String>,
    intent_ref: impl Into<String>,
    intent: &OutboundIntent,
    occurred_at: u64,
    outcome: impl Into<String>,
) -> ReceiptRecord {
    let receipt_id = receipt_id.into();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_INTENT_REF.to_owned(), intent_ref.into());
    fields.insert("verb".to_owned(), intent.verb.clone());
    fields.insert("channel".to_owned(), intent.channel.clone());
    fields.insert("target".to_owned(), intent.target.clone());
    fields.insert("intent_source".to_owned(), intent.intent_source.clone());
    fields.insert(
        FIELD_RECEIPT_SCHEMA.to_owned(),
        OUTBOUND_RECEIPT_SCHEMA.to_owned(),
    );
    fields.insert(
        FIELD_ENGINE_REGISTER.to_owned(),
        OUTBOUND_ENGINE_REGISTER.to_owned(),
    );
    fields.insert(
        FIELD_CARE_REGISTER.to_owned(),
        OUTBOUND_CARE_REGISTER.to_owned(),
    );
    fields.insert(
        FIELD_AUDIT_REGISTER.to_owned(),
        OUTBOUND_AUDIT_REGISTER.to_owned(),
    );
    if let Some(content_ref) = intent.content_ref.as_ref() {
        fields.insert("content_ref".to_owned(), content_ref.clone());
    }
    if let Some(idempotency_key) = intent.idempotency_key.as_ref() {
        fields.insert("idempotency_key".to_owned(), idempotency_key.clone());
    }
    if let Some(dedupe_key) = intent.dedupe_key.as_ref() {
        fields.insert("dedupe_key".to_owned(), dedupe_key.clone());
    }

    ReceiptRecord {
        receipt_id,
        receipt_kind: ReceiptKind::Outbound,
        occurred_at,
        actor: Some(intent.actor.clone()),
        on_behalf_of: intent.on_behalf_of.clone(),
        outcome: outcome.into(),
        job_ref: intent.job_ref.clone(),
        trigger_ref: Some(intent.trigger_ref.clone()),
        policy_trace: Vec::new(),
        fields,
    }
}

/// Computes the brief/project receipt projection over supplied receipt rows.
///
/// This is a pure projection: it does not write grouping state. Direct
/// `job_ref`/`brief_ref` matches win, and older rows can still join the brief
/// through `trigger_ref` plus `run_ref`/`intent_ref`/`parent_ref` chain fields.
#[must_use]
pub fn project_receipts_by_brief(
    brief_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> BriefReceiptProjection {
    let brief_ref = brief_ref.into();
    let receipts = receipts.into_iter().collect::<Vec<_>>();
    let index = ReceiptProjectionIndex::new(&receipts);
    let mut builder = BriefProjectionBuilder::new(brief_ref.clone());

    for receipt in receipts {
        if index.receipt_matches_brief(&receipt, &brief_ref) {
            builder.push(receipt, &index);
        }
    }

    builder.finish()
}

/// Computes one projection per counterparty over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_counterparty(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> Vec<CounterpartyReceiptProjection> {
    project_receipts_by_counterparty_with_contacts(receipts, &BTreeMap::new())
}

fn project_receipts_by_counterparty_with_contacts(
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    contact_records: &BTreeMap<String, CounterpartyContactProjection>,
) -> Vec<CounterpartyReceiptProjection> {
    let mut projections = BTreeMap::<String, CounterpartyProjectionBuilder>::new();
    let mut receipts = receipts.into_iter().collect::<Vec<_>>();
    sort_receipts_newest_first(&mut receipts);

    for receipt in receipts {
        let Some(counterparty_ref) = receipt_counterparty_ref(&receipt) else {
            continue;
        };
        projections
            .entry(counterparty_ref.clone())
            .or_insert_with(|| CounterpartyProjectionBuilder::new(counterparty_ref))
            .push(receipt);
    }

    for (counterparty_ref, contact) in contact_records {
        if let Some(builder) = projections.get_mut(counterparty_ref) {
            builder.apply_contact(contact);
        }
    }

    projections
        .into_values()
        .map(CounterpartyProjectionBuilder::finish)
        .collect()
}

/// Computes the grant receipt projection over supplied receipt rows.
#[must_use]
pub fn project_receipts_by_grant(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
) -> GrantReceiptProjection {
    project_receipts_by_grant_limited(grant_ref, receipts, usize::MAX)
}

fn project_receipts_by_grant_limited(
    grant_ref: impl Into<String>,
    receipts: impl IntoIterator<Item = ReceiptRecord>,
    limit: usize,
) -> GrantReceiptProjection {
    let grant_ref = grant_ref.into();
    let mut projection = GrantReceiptProjection {
        grant_ref: grant_ref.clone(),
        receipts: Vec::new(),
        budget_debit_total: 0,
    };

    for receipt in receipts {
        if receipt_matches_grant(&receipt, &grant_ref) {
            projection.budget_debit_total = projection
                .budget_debit_total
                .saturating_add(receipt_budget_debit(&receipt));
            projection.receipts.push(receipt);
        }
    }
    projection.receipts.truncate(limit);

    projection
}

fn standing_outbound_grants_lens(
    vault: &Vault,
    query: StandingOutboundGrantsLensQuery,
) -> Result<StandingOutboundGrantsLens> {
    if query.limit == 0 {
        return Ok(StandingOutboundGrantsLens { grants: Vec::new() });
    }

    let policy_floor = {
        let rtxn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    let receipt_records = if query.receipt_limit_per_grant == 0 {
        Vec::new()
    } else {
        vault.receipts(projection_scan_query(
            ReceiptQuery::new(query.receipt_limit_per_grant)
                .with_kind(ReceiptKind::Gate)
                .with_kind(ReceiptKind::ScopedRead),
        ))?
    };

    let rtxn = vault.store.env.read_txn()?;
    let mut rows = Vec::new();
    scan_entities_by_type(
        vault,
        &rtxn,
        ENTITY_TYPE_OUTBOUND_GRANT,
        "outbound grant type index",
        |id, _header, body| {
            let grant = decode_standing_outbound_grant_body(body)?;
            rows.push(standing_outbound_grant_lens_row(
                id,
                &grant,
                &policy_floor,
                &receipt_records,
                query.receipt_limit_per_grant,
            ));
            Ok(())
        },
    )?;
    rows.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| left.grant_ref.cmp(&right.grant_ref))
    });
    rows.truncate(query.limit);
    Ok(StandingOutboundGrantsLens { grants: rows })
}

fn standing_outbound_grant_lens_row(
    id: EntityId,
    grant: &StandingOutboundGrant,
    policy_floor: &[u8; 32],
    receipt_records: &[ReceiptRecord],
    receipt_limit: usize,
) -> StandingOutboundGrantLensRow {
    let grant_ref = format!("grant:{}", id.to_hex());
    let stale = !grant.is_active_under_policy(policy_floor) && grant.revoked_at.is_none();
    StandingOutboundGrantLensRow {
        grant_ref: grant_ref.clone(),
        origin_component_id: grant.origin_component_id.clone(),
        origin_action_id: grant.origin_action_id.clone(),
        origin_receipt_ref: grant.origin_receipt_ref.clone(),
        scope_dial: grant.scope.dial_label().to_owned(),
        status: grant.status.as_str().to_owned(),
        stale,
        created_at: grant.created_at,
        last_used_at: grant.last_used_at,
        revoked_at: grant.revoked_at,
        receipt_join: project_receipts_by_grant_limited(
            grant_ref.clone(),
            receipt_records.iter().cloned(),
            receipt_limit,
        ),
        revoke_action: StandingOutboundGrantRevokeAction {
            command: "revoke_standing_outbound_grant".to_owned(),
            grant_ref,
        },
    }
}

#[derive(Debug, Default)]
struct ReceiptProjectionIndex {
    run_to_brief: BTreeMap<String, String>,
    run_to_parent_run: BTreeMap<String, String>,
    intent_to_run: BTreeMap<String, String>,
    intent_to_brief: BTreeMap<String, String>,
}

impl ReceiptProjectionIndex {
    fn new(receipts: &[ReceiptRecord]) -> Self {
        let mut index = Self::default();
        for receipt in receipts {
            let brief_ref = direct_brief_ref(receipt);
            let run_ref = direct_run_ref(receipt);
            let intent_ref = direct_intent_ref(receipt);

            if let (Some(run_ref), Some(brief_ref)) = (run_ref.as_deref(), brief_ref.as_deref()) {
                index
                    .run_to_brief
                    .entry(run_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(brief_ref)) =
                (intent_ref.as_deref(), brief_ref.as_deref())
            {
                index
                    .intent_to_brief
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| brief_ref.to_owned());
            }
            if let (Some(intent_ref), Some(run_ref)) = (intent_ref.as_deref(), run_ref.as_deref()) {
                index
                    .intent_to_run
                    .entry(intent_ref.to_owned())
                    .or_insert_with(|| run_ref.to_owned());
            }

            if let Some(parent_ref) = field_ref(receipt, FIELD_PARENT_REF) {
                if parent_ref.starts_with("brief:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_brief
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_brief
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                } else if parent_ref.starts_with("run:") {
                    if let Some(run_ref) = run_ref.as_deref() {
                        index
                            .run_to_parent_run
                            .entry(run_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                    if let Some(intent_ref) = intent_ref.as_deref() {
                        index
                            .intent_to_run
                            .entry(intent_ref.to_owned())
                            .or_insert_with(|| parent_ref.to_owned());
                    }
                }
            }
        }

        loop {
            let mut changed = false;
            for run_ref in index.run_to_parent_run.keys().cloned().collect::<Vec<_>>() {
                let Some(parent_run_ref) = index.run_to_parent_run.get(&run_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(parent_run_ref).cloned()
                    && !index.run_to_brief.contains_key(&run_ref)
                {
                    index.run_to_brief.insert(run_ref, brief_ref);
                    changed = true;
                }
            }
            for intent_ref in index.intent_to_run.keys().cloned().collect::<Vec<_>>() {
                let Some(run_ref) = index.intent_to_run.get(&intent_ref) else {
                    continue;
                };
                if let Some(brief_ref) = index.run_to_brief.get(run_ref).cloned()
                    && !index.intent_to_brief.contains_key(&intent_ref)
                {
                    index.intent_to_brief.insert(intent_ref, brief_ref);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }

        index
    }

    fn receipt_matches_brief(&self, receipt: &ReceiptRecord, brief_ref: &str) -> bool {
        if direct_brief_ref(receipt).is_some_and(|value| refs_match(&value, brief_ref)) {
            return true;
        }
        if let Some(run_ref) = direct_run_ref(receipt)
            && self
                .run_to_brief
                .get(&run_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
        {
            return true;
        }
        if let Some(intent_ref) = direct_intent_ref(receipt) {
            if self
                .intent_to_brief
                .get(&intent_ref)
                .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
            if let Some(run_ref) = self.intent_to_run.get(&intent_ref)
                && self
                    .run_to_brief
                    .get(run_ref)
                    .is_some_and(|value| refs_match(value, brief_ref))
            {
                return true;
            }
        }
        false
    }

    fn receipt_run_ref(&self, receipt: &ReceiptRecord) -> Option<String> {
        direct_run_ref(receipt).or_else(|| {
            direct_intent_ref(receipt)
                .and_then(|intent_ref| self.intent_to_run.get(&intent_ref).cloned())
        })
    }
}

#[derive(Debug)]
struct BriefProjectionBuilder {
    brief_ref: String,
    runs: BTreeMap<String, ReceiptProjectionRunBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    consent_grants: Vec<ReceiptRecord>,
    bundles: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl BriefProjectionBuilder {
    fn new(brief_ref: String) -> Self {
        Self {
            brief_ref,
            runs: BTreeMap::new(),
            direct_receipts: Vec::new(),
            consent_grants: Vec::new(),
            bundles: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, index: &ReceiptProjectionIndex) {
        let budget = receipt_budget_debit(&receipt);
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);

        if receipt_is_consent_grant(&receipt) {
            self.consent_grants.push(receipt.clone());
        }
        if receipt_is_bundle_event(&receipt) {
            self.bundles.push(receipt.clone());
        }

        let intent_ref = direct_intent_ref(&receipt);
        if let Some(run_ref) = index.receipt_run_ref(&receipt) {
            self.runs
                .entry(run_ref.clone())
                .or_insert_with(|| ReceiptProjectionRunBuilder::new(run_ref))
                .push(receipt, intent_ref, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> BriefReceiptProjection {
        BriefReceiptProjection {
            brief_ref: self.brief_ref,
            runs: self
                .runs
                .into_values()
                .map(ReceiptProjectionRunBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            consent_grants: self.consent_grants,
            bundles: self.bundles,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionRunBuilder {
    run_ref: String,
    intents: BTreeMap<String, ReceiptProjectionIntentBuilder>,
    direct_receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionRunBuilder {
    fn new(run_ref: String) -> Self {
        Self {
            run_ref,
            intents: BTreeMap::new(),
            direct_receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, intent_ref: Option<String>, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        if let Some(intent_ref) = intent_ref {
            self.intents
                .entry(intent_ref.clone())
                .or_insert_with(|| ReceiptProjectionIntentBuilder::new(intent_ref))
                .push(receipt, budget);
        } else {
            self.direct_receipts.push(receipt);
        }
    }

    fn finish(self) -> ReceiptProjectionRun {
        ReceiptProjectionRun {
            run_ref: self.run_ref,
            intents: self
                .intents
                .into_values()
                .map(ReceiptProjectionIntentBuilder::finish)
                .collect(),
            direct_receipts: self.direct_receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct ReceiptProjectionIntentBuilder {
    intent_ref: String,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl ReceiptProjectionIntentBuilder {
    fn new(intent_ref: String) -> Self {
        Self {
            intent_ref,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord, budget: u64) {
        self.budget_debit_total = self.budget_debit_total.saturating_add(budget);
        self.receipts.push(receipt);
    }

    fn finish(self) -> ReceiptProjectionIntent {
        ReceiptProjectionIntent {
            intent_ref: self.intent_ref,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

#[derive(Debug)]
struct CounterpartyProjectionBuilder {
    counterparty_ref: String,
    first_touch: Option<String>,
    opt_out: Option<bool>,
    promo_consent: Option<bool>,
    receipts: Vec<ReceiptRecord>,
    budget_debit_total: u64,
}

impl CounterpartyProjectionBuilder {
    fn new(counterparty_ref: String) -> Self {
        Self {
            counterparty_ref,
            first_touch: None,
            opt_out: None,
            promo_consent: None,
            receipts: Vec::new(),
            budget_debit_total: 0,
        }
    }

    fn push(&mut self, receipt: ReceiptRecord) {
        if self.first_touch.is_none()
            && let Some(first_touch) = field_ref(&receipt, FIELD_FIRST_TOUCH)
        {
            self.first_touch = Some(first_touch.to_owned());
        }
        if let Some(opt_out) = bool_field(&receipt, FIELD_OPT_OUT) {
            self.opt_out.get_or_insert(opt_out);
        }
        if let Some(promo_consent) = bool_field(&receipt, FIELD_PROMO_CONSENT) {
            self.promo_consent.get_or_insert(promo_consent);
        }
        self.budget_debit_total = self
            .budget_debit_total
            .saturating_add(receipt_budget_debit(&receipt));
        self.receipts.push(receipt);
    }

    fn apply_contact(&mut self, contact: &CounterpartyContactProjection) {
        self.first_touch = contact.first_touch.clone();
        self.opt_out = Some(contact.opt_out);
        self.promo_consent = Some(contact.promo_consent);
    }

    fn finish(self) -> CounterpartyReceiptProjection {
        CounterpartyReceiptProjection {
            counterparty_ref: self.counterparty_ref,
            first_touch: self.first_touch,
            opt_out: self.opt_out,
            promo_consent: self.promo_consent,
            receipts: self.receipts,
            budget_debit_total: self.budget_debit_total,
        }
    }
}

fn direct_brief_ref(receipt: &ReceiptRecord) -> Option<String> {
    receipt
        .job_ref
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| field_ref(receipt, FIELD_JOB_REF).map(str::to_owned))
        .or_else(|| field_ref(receipt, FIELD_BRIEF_REF).map(str::to_owned))
        .or_else(|| trigger_ref_with_prefix(receipt, "brief:"))
}

fn direct_run_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_RUN_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "run:"))
}

fn direct_intent_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_INTENT_REF)
        .map(str::to_owned)
        .or_else(|| trigger_ref_with_prefix(receipt, "intent:"))
}

fn receipt_counterparty_ref(receipt: &ReceiptRecord) -> Option<String> {
    field_ref(receipt, FIELD_COUNTERPARTY_REF)
        .or_else(|| field_ref(receipt, "target"))
        .map(str::to_owned)
}

fn receipt_identity_ref(receipt: &ReceiptRecord) -> Option<EntityId> {
    [
        FIELD_CHANNEL_IDENTITY_REF,
        FIELD_RECEIVING_IDENTITY_REF,
        FIELD_IDENTITY_REF,
    ]
    .iter()
    .find_map(|key| field_ref(receipt, key).and_then(entity_ref_from_str))
}

fn receipt_matches_grant(receipt: &ReceiptRecord, grant_ref: &str) -> bool {
    field_ref(receipt, FIELD_GRANT_REF).is_some_and(|value| refs_match(value, grant_ref))
        || receipt
            .trigger_ref
            .as_deref()
            .filter(|value| value.starts_with("access_grant:") || value.starts_with("grant:"))
            .is_some_and(|value| refs_match(value, grant_ref))
}

fn receipt_is_consent_grant(receipt: &ReceiptRecord) -> bool {
    receipt.receipt_kind == ReceiptKind::ScopedRead
}

fn receipt_is_bundle_event(receipt: &ReceiptRecord) -> bool {
    field_ref(receipt, FIELD_BUNDLE_REF).is_some()
        || receipt
            .trigger_ref
            .as_deref()
            .is_some_and(|value| value.starts_with("bundle:"))
        || field_ref(receipt, "event").is_some_and(|value| value == "bundle")
}

fn receipt_budget_debit(receipt: &ReceiptRecord) -> u64 {
    field_ref(receipt, FIELD_BUDGET_DEBIT)
        .or_else(|| field_ref(receipt, FIELD_BUDGET))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn bool_field(receipt: &ReceiptRecord, key: &str) -> Option<bool> {
    match field_ref(receipt, key)? {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn field_ref<'a>(receipt: &'a ReceiptRecord, key: &str) -> Option<&'a str> {
    receipt
        .fields
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

fn trigger_ref_with_prefix(receipt: &ReceiptRecord, prefix: &str) -> Option<String> {
    receipt
        .trigger_ref
        .as_deref()
        .filter(|value| value.starts_with(prefix))
        .map(str::to_owned)
}

fn refs_match(candidate: &str, target: &str) -> bool {
    candidate == target || strip_ref_prefix(candidate) == strip_ref_prefix(target)
}

fn strip_ref_prefix(value: &str) -> &str {
    value
        .split_once(':')
        .map_or(value, |(_prefix, suffix)| suffix)
}

fn entity_ref_from_str(value: &str) -> Option<EntityId> {
    EntityId::from_hex(strip_ref_prefix(value)).ok()
}

fn projection_scan_query(mut query: ReceiptQuery) -> ReceiptQuery {
    query.limit = MAX_RECEIPT_QUERY_SCAN;
    query
}

fn lineage_scan_query() -> ReceiptQuery {
    ReceiptQuery::new(MAX_RECEIPT_QUERY_SCAN)
}

fn sort_receipts_newest_first(records: &mut [ReceiptRecord]) {
    records.sort_by(|left, right| {
        right
            .occurred_at
            .cmp(&left.occurred_at)
            .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
            .then_with(|| left.receipt_id.cmp(&right.receipt_id))
    });
}

fn finalize_receipt_query_records(
    mut records: Vec<ReceiptRecord>,
    query: &ReceiptQuery,
    lineage_records: Option<&[ReceiptRecord]>,
) -> Vec<ReceiptRecord> {
    sort_receipts_newest_first(&mut records);
    if let Some(job_ref) = query.job_ref.as_deref() {
        let index = ReceiptProjectionIndex::new(lineage_records.unwrap_or(&records));
        records.retain(|receipt| index.receipt_matches_brief(receipt, job_ref));
    }
    records.truncate(query.limit);
    records
}

#[derive(Debug, Clone)]
struct CounterpartyContactProjection {
    first_touch: Option<String>,
    first_touch_created_at: u64,
    opt_out: bool,
    promo_consent: bool,
}

impl CounterpartyContactProjection {
    fn new(contact: &CounterpartyContactRecord) -> Self {
        Self {
            first_touch: Some(contact.first_touch.as_str().to_owned()),
            first_touch_created_at: contact.created_at,
            opt_out: contact.is_opted_out(),
            promo_consent: contact.promo_consent,
        }
    }

    fn merge(&mut self, contact: &CounterpartyContactRecord) {
        if contact.created_at < self.first_touch_created_at {
            self.first_touch = Some(contact.first_touch.as_str().to_owned());
            self.first_touch_created_at = contact.created_at;
        }
        self.opt_out |= contact.is_opted_out();
        self.promo_consent &= contact.promo_consent;
    }
}

fn counterparty_contact_records_for_receipts(
    vault: &Vault,
    receipts: &[ReceiptRecord],
) -> Result<BTreeMap<String, CounterpartyContactProjection>> {
    let mut wanted_by_identity = BTreeMap::<EntityId, BTreeMap<String, BTreeSet<String>>>::new();
    for receipt in receipts {
        let (Some(counterparty_ref), Some(identity_ref)) = (
            receipt_counterparty_ref(receipt),
            receipt_identity_ref(receipt),
        ) else {
            continue;
        };
        wanted_by_identity
            .entry(identity_ref)
            .or_default()
            .entry(counterparty_ref.trim().to_owned())
            .or_default()
            .insert(counterparty_ref);
    }

    let mut contacts = BTreeMap::<String, CounterpartyContactProjection>::new();
    for (identity_ref, wanted_counterparties) in wanted_by_identity {
        for (_contact_id, contact) in vault.counterparty_contacts_for_identity(&identity_ref)? {
            let Some(counterparty_refs) = wanted_counterparties.get(&contact.counterparty) else {
                continue;
            };
            for counterparty_ref in counterparty_refs {
                contacts
                    .entry(counterparty_ref.clone())
                    .and_modify(|projection| projection.merge(&contact))
                    .or_insert_with(|| CounterpartyContactProjection::new(&contact));
            }
        }
    }
    Ok(contacts)
}

fn receipt_family_query(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let records = collect_receipt_records(vault, query)?;
    let lineage_records = if query.job_ref.is_some() {
        Some(collect_receipt_records(vault, &lineage_scan_query())?)
    } else {
        None
    };
    Ok(finalize_receipt_query_records(
        records,
        query,
        lineage_records.as_deref(),
    ))
}

fn collect_receipt_records(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut records = Vec::new();
    if query.includes_kind(ReceiptKind::Gate) {
        records.extend(gate_receipts(vault, query)?);
    }

    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(channel_identity_lifecycle_receipts(vault, query)?);
    }

    // The settle projection opens its own read txn, so it runs before the shared
    // `rtxn` below to avoid a nested read transaction on this thread. It applies
    // the query filter itself (the settlement key is not time-ordered).
    if query.includes_kind(ReceiptKind::ArtifactSettle) {
        records.extend(crate::edit_settle::settle_receipts(vault, query)?);
    }

    let rtxn = vault.store.env.read_txn()?;
    if query.includes_kind(ReceiptKind::IdentityLifecycle) {
        records.extend(companion_lifecycle_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::ScopedRead) {
        records.extend(access_grant_receipts(vault, &rtxn, query)?);
        records.extend(outbound_grant_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::Share) {
        records.extend(federation_share_receipts(vault, &rtxn, query)?);
        records.extend(persona_snapshot_export_receipts(vault, &rtxn, query)?);
    }

    Ok(records)
}

fn gate_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for decision in vault.store.gate_decisions(MAX_RECEIPT_QUERY_SCAN)? {
        let receipt = gate_decision_receipt(&decision);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

pub(crate) fn gate_decision_receipt(record: &GateDecisionRecord) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("content_kind".to_owned(), record.content_kind.clone());
    fields.insert(
        "policy_manifest_version".to_owned(),
        record.policy_manifest_version.clone(),
    );
    fields.insert("diff_handle".to_owned(), hex_lower(&record.diff_handle));
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&record.read_frontier_hash),
    );
    if let Some(receipt_reason) = record.receipt_reasons.first() {
        fields.insert("receipt_reason".to_owned(), receipt_reason.clone());
    }
    if record.receipt_reasons.len() > 1 {
        fields.insert(
            "receipt_reasons".to_owned(),
            record.receipt_reasons.join(","),
        );
    }
    if let Some(grant_ref) = record.grant_ref.as_ref() {
        fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
        // OF-234 bundle-consent rows reference their bundle through the grant
        // ref; surfacing it as `bundle_ref` joins them into the RS4 bundle lane.
        if grant_ref.starts_with("bundle:") {
            fields.insert(FIELD_BUNDLE_REF.to_owned(), grant_ref.clone());
        }
    }
    if let Some(notice) = select_gate_system_notice_for_receipt(&record.system_notices) {
        fields.insert("system_notice_type".to_owned(), notice.notice_type.clone());
        fields.insert("system_notice_channel".to_owned(), notice.channel.clone());
        fields.insert("system_notice_voice".to_owned(), notice.voice.clone());
        fields.insert("system_notice_audience".to_owned(), notice.audience.clone());
        fields.insert("system_notice".to_owned(), notice.body.clone());
    }

    let mut policy_trace = record.reason_codes.clone();
    policy_trace.extend(record.receipt_reasons.clone());
    policy_trace.extend(
        record
            .system_notices
            .iter()
            .map(|notice| format!("gate.system_notice.{}", notice.notice_type)),
    );

    ReceiptRecord {
        receipt_id: format!("gate:{}", record.decision_id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: record
            .claim_id
            .map(|id| format!("claim:{}", hex_lower(&id)))
            .or_else(|| {
                // A bundle-level row (no claim id) opens its dreamer run: the
                // RS3 door on the bundle receipt reopens the inbox group.
                record
                    .grant_ref
                    .as_deref()
                    .and_then(|grant_ref| grant_ref.strip_prefix("bundle:"))
                    .map(str::to_owned)
            }),
        policy_trace,
        fields,
    }
}

fn select_gate_system_notice_for_receipt(
    notices: &[GateSystemNoticeRecord],
) -> Option<&GateSystemNoticeRecord> {
    notices
        .iter()
        .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_THIRD_PARTY)
        .or_else(|| {
            notices
                .iter()
                .find(|notice| notice.audience == SYSTEM_NOTICE_AUDIENCE_ALL)
        })
        .or_else(|| notices.first())
}

fn pending_tray_query(vault: &Vault, query: PendingTrayQuery) -> Result<Vec<PendingTrayAsk>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let rtxn = vault.store.env.read_txn()?;
    let mut asks = Vec::new();
    for pending in vault
        .store
        .pending_gate_consents_in_txn(&rtxn, query.limit)?
    {
        let Some(decision) = vault
            .store
            .gate_decision_in_txn(&rtxn, pending.decision_id)?
        else {
            return Err(Error::CorruptedIndex("pending gate consent"));
        };
        if decision.outcome != "pending" {
            return Err(Error::CorruptedIndex("pending gate consent"));
        }
        asks.push(pending_tray_ask(&pending, &decision, query.now));
    }
    Ok(asks)
}

fn pending_tray_ask(
    pending: &PendingGateConsentRecord,
    decision: &GateDecisionRecord,
    now: u64,
) -> PendingTrayAsk {
    let receipt = gate_decision_receipt(decision);
    let hold_reasons = pending.reason_codes.clone();
    let hold_reason = hold_reasons
        .first()
        .cloned()
        .unwrap_or_else(|| "gate.pending".to_owned());
    PendingTrayAsk {
        claim_id: hex_lower(&pending.claim_id),
        created_at: pending.created_at,
        age_secs: now.saturating_sub(pending.created_at),
        hold_reason,
        hold_reasons,
        dreamer_run_id: pending.dreamer_run_id.clone(),
        receipt_view: ReceiptView::new(receipt),
    }
}

fn companion_lifecycle_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_COMPANION_REGISTER,
        "companion register type index",
        |id, header, body| {
            let record = decode_companion_record_body(body)?;
            for (index, event) in record.lifecycle_events.iter().enumerate() {
                let receipt =
                    companion_lifecycle_receipt(id, &record, *event, index, header.learned_at);
                if query.matches(&receipt) {
                    receipts.push(receipt);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn companion_lifecycle_receipt(
    id: EntityId,
    record: &CompanionRecord,
    event: CompanionLifecycleEvent,
    event_index: usize,
    learned_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        "actor_class".to_owned(),
        record.provenance.actor_class.gate_actor_class().to_owned(),
    );
    fields.insert(
        "source".to_owned(),
        record.provenance.source.as_str().to_owned(),
    );
    fields.insert(
        "approval".to_owned(),
        record.provenance.approval.as_str().to_owned(),
    );
    fields.insert("record_kind".to_owned(), record.kind().as_str().to_owned());
    fields.insert(
        "record_lifecycle".to_owned(),
        record.lifecycle.as_str().to_owned(),
    );
    fields.insert("learned_at".to_owned(), learned_at.to_string());
    append_companion_scope_fields(&mut fields, &record.scope);
    append_companion_subject_fields(&mut fields, &record.subject);

    ReceiptRecord {
        receipt_id: format!(
            "identity_lifecycle:{}:{}:{}",
            id.to_hex(),
            event.kind.as_str(),
            event_index
        ),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: event.at,
        actor: Some(record.provenance.actor_ref.to_hex()),
        on_behalf_of: None,
        outcome: event.kind.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn channel_identity_lifecycle_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    for record in vault
        .store
        .channel_identity_lifecycle_receipts(MAX_RECEIPT_QUERY_SCAN)?
    {
        let receipt = channel_identity_lifecycle_receipt(&record);
        if query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn channel_identity_lifecycle_receipt(
    record: &ChannelIdentityLifecycleReceiptRecord,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("actor_class".to_owned(), record.actor_class.clone());
    fields.insert("verb".to_owned(), record.verb.clone());
    fields.insert("intent_kind".to_owned(), record.intent_kind.clone());
    fields.insert("channel".to_owned(), record.channel.clone());
    fields.insert(
        "address_or_handle".to_owned(),
        record.address_or_handle.clone(),
    );
    fields.insert("state".to_owned(), record.state.clone());
    fields.insert(
        "owner_visible_state".to_owned(),
        record.owner_visible_state.clone(),
    );
    fields.insert(
        "outbound_closed".to_owned(),
        record.outbound_closed.to_string(),
    );
    fields.insert(
        "identity_retiring".to_owned(),
        record.identity_retiring.to_string(),
    );
    if let Some(mode) = record.fulfillment_mode.as_ref() {
        fields.insert("fulfillment_mode".to_owned(), mode.clone());
    }
    if let Some(until) = record.quarantine_until {
        fields.insert("quarantine_until".to_owned(), until.to_string());
    }
    if let Some(decision_id) = record.gate_decision_id {
        fields.insert(
            "gate_decision_ref".to_owned(),
            format!("gate:{}", decision_id.to_hex()),
        );
    }

    ReceiptRecord {
        receipt_id: crate::channel_identity_lifecycle::lifecycle_receipt_ref(record.receipt_id),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: record.created_at,
        actor: record
            .actor_ref
            .clone()
            .or_else(|| Some(record.actor_class.clone())),
        on_behalf_of: None,
        outcome: record.outcome.clone(),
        job_ref: None,
        trigger_ref: Some(format!("entity:{}", hex_lower(&record.identity_id))),
        policy_trace: Vec::new(),
        fields,
    }
}

fn access_grant_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_ACCESS_GRANT,
        "access grant type index",
        |id, _header, body| {
            let grant = decode_access_grant_body(body)?;
            let created = access_grant_receipt(id, &grant, grant.created_at, "active", "created");
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = grant.revoked_at {
                let revoked = access_grant_receipt(id, &grant, revoked_at, "revoked", "revoked");
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn access_grant_receipt(
    id: EntityId,
    grant: &AccessGrant,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert(
        "capability".to_owned(),
        grant.capability.as_str().to_owned(),
    );
    append_access_grant_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:{}:{event_name}", id.to_hex()),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.to_hex()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("access_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn outbound_grant_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_OUTBOUND_GRANT,
        "outbound grant type index",
        |id, _header, body| {
            let grant = decode_standing_outbound_grant_body(body)?;
            let created = outbound_grant_receipt(id, &grant, grant.created_at, "active", "created");
            if query.matches(&created) {
                receipts.push(created);
            }
            if let Some(revoked_at) = grant.revoked_at {
                let revoked = outbound_grant_receipt(id, &grant, revoked_at, "revoked", "revoked");
                if query.matches(&revoked) {
                    receipts.push(revoked);
                }
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn outbound_grant_receipt(
    id: EntityId,
    grant: &StandingOutboundGrant,
    occurred_at: u64,
    outcome: &str,
    event_name: &str,
) -> ReceiptRecord {
    let grant_ref = format!("grant:{}", id.to_hex());
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_GRANT_REF.to_owned(), grant_ref.clone());
    fields.insert("status".to_owned(), grant.status.as_str().to_owned());
    fields.insert("scope_dial".to_owned(), grant.scope.dial_label().to_owned());
    fields.insert(
        "origin_component_id".to_owned(),
        grant.origin_component_id.clone(),
    );
    fields.insert(
        "origin_action_id".to_owned(),
        grant.origin_action_id.clone(),
    );
    fields.insert(
        "binding_diff_handle".to_owned(),
        hex_lower(&grant.binding_diff_handle),
    );
    fields.insert(
        "read_frontier_hash".to_owned(),
        hex_lower(&grant.read_frontier_hash),
    );
    if let Some(origin_receipt_ref) = grant.origin_receipt_ref.as_ref() {
        fields.insert("origin_receipt_ref".to_owned(), origin_receipt_ref.clone());
    }
    if let Some(last_used_at) = grant.last_used_at {
        fields.insert("last_used_at".to_owned(), last_used_at.to_string());
    }
    append_outbound_grant_scope_fields(&mut fields, &grant.scope);

    ReceiptRecord {
        receipt_id: format!("scoped_read:{}:{event_name}", grant_ref),
        receipt_kind: ReceiptKind::ScopedRead,
        occurred_at,
        actor: Some(grant.principal_ref.clone()),
        on_behalf_of: None,
        outcome: outcome.to_owned(),
        job_ref: outbound_grant_job_ref(&grant.scope),
        trigger_ref: Some(grant_ref),
        policy_trace: Vec::new(),
        fields,
    }
}

fn federation_share_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        "federation grant type index",
        |id, header, body| {
            let grant = decode_federation_grant_body(body)?;
            let receipt = federation_share_receipt(id, &grant, header.occurred_start);
            if query.matches(&receipt) {
                receipts.push(receipt);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn federation_share_receipt(
    id: EntityId,
    grant: &FederationGrant,
    occurred_at: u64,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert("role".to_owned(), grant.role.as_str().to_owned());
    fields.insert("preset".to_owned(), grant.preset.as_str().to_owned());
    append_federation_scope_fields(&mut fields, grant.scope);

    ReceiptRecord {
        receipt_id: format!("share:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at,
        actor: Some(grant.member_ref.to_hex()),
        on_behalf_of: None,
        outcome: "granted".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("federation_grant:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn persona_snapshot_export_receipts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    scan_entities_by_type(
        vault,
        txn,
        ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
        "persona snapshot export type index",
        |id, _header, body| {
            let record = decode_persona_snapshot_export_body(body)?;
            let receipt = persona_snapshot_export_receipt(id, &record);
            if query.matches(&receipt) {
                receipts.push(receipt);
            }
            Ok(())
        },
    )?;
    Ok(receipts)
}

fn persona_snapshot_export_receipt(
    id: EntityId,
    record: &PersonaSnapshotExportRecord,
) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    fields.insert(
        FIELD_PERSONA_COMPILE_STAMP.to_owned(),
        record.compile_stamp_identity(),
    );
    fields.insert("subject_ref".to_owned(), record.subject_ref.to_hex());
    if let Some(audience_ref) = record.audience_ref.as_deref() {
        fields.insert("audience_ref".to_owned(), audience_ref.to_owned());
    }
    fields.insert(
        "compiled_at_secs".to_owned(),
        record.compiled_at_secs.to_string(),
    );
    fields.insert(
        "stale_after_secs".to_owned(),
        record.stale_after_secs.to_string(),
    );
    fields.insert(
        "included_rows".to_owned(),
        record.included_row_ids.len().to_string(),
    );
    fields.insert(
        "struck_rows".to_owned(),
        record.struck_row_ids.len().to_string(),
    );
    fields.insert(
        "takes_included".to_owned(),
        record.takes_included.to_string(),
    );
    fields.insert(
        "artifact_fingerprint".to_owned(),
        record.artifact_fingerprint.clone(),
    );

    ReceiptRecord {
        receipt_id: format!("share:persona_snapshot:{}", id.to_hex()),
        receipt_kind: ReceiptKind::Share,
        occurred_at: record.exported_at_secs,
        actor: Some(record.granted_by.clone()),
        on_behalf_of: None,
        outcome: "exported".to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("persona_snapshot_export:{}", id.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

fn scan_entities_by_type(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity_type: u8,
    context: &'static str,
    mut visit: impl FnMut(EntityId, EntityMetadataHeader, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut scanned = 0_usize;
    for entry in vault.store.type_index.prefix_iter(txn, &[entity_type])? {
        let (key, _) = entry?;
        if key.first().copied() != Some(entity_type) {
            return Err(Error::CorruptedIndex(context));
        }
        let id = entity_id_from_type_index_key(key, context)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex(context));
        };
        let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex(context))?;
        if header.entity_type != entity_type {
            return Err(Error::CorruptedIndex(context));
        }
        visit(id, header, &raw[ENTITY_METADATA_HEADER_LEN..])?;
        scanned = scanned.saturating_add(1);
        if scanned >= MAX_RECEIPT_QUERY_SCAN {
            break;
        }
    }
    Ok(())
}

fn entity_id_from_type_index_key(key: &[u8], context: &'static str) -> Result<EntityId> {
    if key.len() != 1 + ENTITY_ID_LEN {
        return Err(Error::CorruptedIndex(context));
    }
    EntityId::from_bytes(
        key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex(context))?,
    )
    .map_err(|_| Error::CorruptedIndex(context))
}

fn append_companion_scope_fields(fields: &mut BTreeMap<String, String>, scope: &CompanionScope) {
    match scope {
        CompanionScope::Neutral => {
            fields.insert("scope".to_owned(), "neutral".to_owned());
        }
        CompanionScope::Personal { person_ref } => {
            fields.insert("scope".to_owned(), "personal".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
        }
        CompanionScope::SharedVault { vault_id } => {
            fields.insert("scope".to_owned(), "shared_vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
    }
}

fn append_companion_subject_fields(
    fields: &mut BTreeMap<String, String>,
    subject: &CompanionSubject,
) {
    match subject {
        CompanionSubject::Persona { persona_ref } => {
            fields.insert("subject".to_owned(), "persona".to_owned());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => {
            fields.insert("subject".to_owned(), "relationship".to_owned());
            fields.insert("source_ref".to_owned(), source_ref.to_hex());
            fields.insert("target_ref".to_owned(), target_ref.to_hex());
        }
    }
}

fn append_access_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: AccessGrantScope,
) {
    match scope {
        AccessGrantScope::CompanionProfile {
            person_ref,
            persona_ref,
        } => {
            fields.insert("scope".to_owned(), "companion_profile".to_owned());
            fields.insert("person_ref".to_owned(), person_ref.to_hex());
            fields.insert("persona_ref".to_owned(), persona_ref.to_hex());
        }
    }
}

fn append_outbound_grant_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: &StandingOutboundGrantScope,
) {
    match scope {
        StandingOutboundGrantScope::Contact { contact_ref } => {
            fields.insert("scope".to_owned(), "contact".to_owned());
            fields.insert("contact_ref".to_owned(), contact_ref.clone());
        }
        StandingOutboundGrantScope::VerbClass { verb_class } => {
            fields.insert("scope".to_owned(), "verb_class".to_owned());
            fields.insert("verb_class".to_owned(), verb_class.clone());
        }
        StandingOutboundGrantScope::Channel { channel } => {
            fields.insert("scope".to_owned(), "channel".to_owned());
            fields.insert("channel".to_owned(), channel.clone());
        }
        StandingOutboundGrantScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            fields.insert("scope".to_owned(), "brief_verb_class".to_owned());
            fields.insert(FIELD_BRIEF_REF.to_owned(), brief_ref.clone());
            fields.insert("verb_class".to_owned(), verb_class.clone());
        }
    }
}

fn outbound_grant_job_ref(scope: &StandingOutboundGrantScope) -> Option<String> {
    match scope {
        StandingOutboundGrantScope::BriefVerbClass { brief_ref, .. } => Some(brief_ref.clone()),
        _ => None,
    }
}

fn append_federation_scope_fields(
    fields: &mut BTreeMap<String, String>,
    scope: FederationGrantScope,
) {
    match scope {
        FederationGrantScope::Vault { vault_id } => {
            fields.insert("scope".to_owned(), "vault".to_owned());
            fields.insert("vault_id".to_owned(), vault_id.to_string());
        }
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

#[cfg(test)]
mod tests;
