//! Unified receipt-family query surface over existing receipt emitters.
//!
//! RS1 is intentionally a projection over existing event substrates. This
//! module does not mint a new receipt store and does not change emitter schema.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::access_grant::{AccessGrant, AccessGrantScope, decode_access_grant_body};
use crate::attempt_queue::{AttemptId, AttemptRecord, ManifestEntry, ManifestKind};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::companion::{
    ENTITY_TYPE_COMPANION_REGISTER,
    {
        CompanionLifecycleEvent, CompanionRecord, CompanionScope, CompanionSubject,
        decode_companion_record_body,
    },
};
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::eiri::EiriMemoryBoard;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::federation::{FederationGrant, FederationGrantScope, decode_federation_grant_body};
use crate::outbound::OutboundIntent;
use crate::outbound_grant::{
    StandingOutboundGrant, StandingOutboundGrantScope, decode_standing_outbound_grant_body,
};
use crate::persona_snapshot::{PersonaSnapshotExportRecord, decode_persona_snapshot_export_body};
use crate::prompt::PromptRecompileStamp;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT,
};
use crate::store::{
    ChannelIdentityLifecycleReceiptRecord, GateDecisionRecord, GateSystemNoticeRecord,
    PendingGateConsentRecord, SEND_RECEIPT_RECORD_VERSION, Store,
};

const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
pub(crate) const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;

#[cfg(test)]
thread_local! {
    static GATE_RECEIPT_PAGES_SCANNED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static GATE_RECEIPT_MAX_BUFFERED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static ATTEMPT_PACK_SCAN_CAPPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_gate_receipt_pages_scanned() {
    GATE_RECEIPT_PAGES_SCANNED.set(0);
    GATE_RECEIPT_MAX_BUFFERED.set(0);
}

#[cfg(test)]
fn gate_receipt_pages_scanned() -> usize {
    GATE_RECEIPT_PAGES_SCANNED.get()
}

#[cfg(test)]
fn gate_receipt_max_buffered() -> usize {
    GATE_RECEIPT_MAX_BUFFERED.get()
}

#[cfg(test)]
fn attempt_pack_scan_capped() -> usize {
    ATTEMPT_PACK_SCAN_CAPPED.get()
}

#[cfg(test)]
fn reset_attempt_pack_scan_capped() {
    ATTEMPT_PACK_SCAN_CAPPED.set(0);
}
const RECEIPT_VIEW_COMPONENT: &str = "receipt_view";
const FIELD_JOB_REF: &str = "job_ref";
const FIELD_BRIEF_REF: &str = "brief_ref";
const FIELD_RUN_REF: &str = "run_ref";
const FIELD_INTENT_REF: &str = "intent_ref";
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
/// `vault_meta` keyspace of the attempt PACK RECEIPT ledger. The suffix is the
/// receipt id itself, so a cited `receipt_ref` point-reads its row.
const ATTEMPT_PACK_RECEIPT_KEY_PREFIX: &[u8] = b"attempt_receipt:v1:";
/// `receipt_id` namespace of the same ledger.
const ATTEMPT_PACK_RECEIPT_ID_PREFIX: &str = "attempt:";
const FIELD_PARENT_REF: &str = "parent_ref";
const FIELD_COUNTERPARTY_REF: &str = "counterparty_ref";
const FIELD_IDENTITY_REF: &str = "identity_ref";
const FIELD_CHANNEL_IDENTITY_REF: &str = "channel_identity_ref";
const FIELD_RECEIVING_IDENTITY_REF: &str = "receiving_identity_ref";
pub(crate) const FIELD_GRANT_REF: &str = "grant_ref";
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
const FIELD_DISCLOSURE_STAMP: &str = "disclosure_stamp";
const BOARD_STATE_REF_PREFIX: &str = "board:";
const ACTIVATED_MEMORY_IDS_SEPARATOR: char = ',';
/// ARCH-0055 r7 proposal-outcome receipt fields (ONE-1747).
///
/// The three ramp-scope keys are `pub(crate)` because ONE-1748's demotion
/// receipt names the SAME scope tuple: two spellings of one key would make the
/// ramp's own receipts unjoinable with the outcome receipts they answer.
const FIELD_PROPOSAL_REF: &str = "proposal_ref";
pub(crate) const FIELD_OP_KIND: &str = "op_kind";
pub(crate) const FIELD_TARGET_CLASS: &str = "target_class";
pub(crate) const FIELD_SCOPE_ACTOR: &str = "actor";
/// Why a consent-graduation scope was demoted back to the propose lane
/// (ONE-1748); the wire strings are `consent_graduation::DemotionReason`.
pub(crate) const FIELD_DEMOTION_REASON: &str = "demotion_reason";
/// The resolution event's claim-source axis. Deliberately NOT `"source"`:
/// that key is reserved as one of the six ARCH-0056 Δ field names this
/// receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
const FIELD_CLAIM_SOURCE: &str = "claim_source";
/// The amended op body verbatim (lower hex) — the PRODUCER artifact.
const FIELD_AMENDED_BODY: &str = "amended_body";
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableSendReceipt {
    version: u8,
    task_ref: String,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    receipt: ReceiptRecord,
}

// ONE-1690 closes the known interim double-authority window: ledger rows are
// the resend authority; send receipts are required-outcome audit narrative.

/// Delivery state carried by the additive connector-send receipt ledger.
/// Failed transport audit rows remain visible but are not idempotency tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SendReceiptOutcome {
    Delivered,
    Failed,
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
    /// Content-hash ref of the Eiri activated-memories board
    /// ([`EiriMemoryBoard`]) at emit — a distinct surface from the
    /// `[CONTEXT_BOARD]` render block, which is never hashed here.
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
    /// OF-365 disclosure stamp for the assembly that produced this emit:
    /// `"mode=<mode>;interlocutors=<class>:<label>[,...]"`. Absent on
    /// receipts stamped before the disclosure clamp existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_stamp: Option<String>,
}

impl ContextReceiptFields {
    /// Captures the field-set at the context-assembly seam — the one hook
    /// where the activation set is finalized (OF-369/RS9 emission point).
    ///
    /// `persona_compile_stamp` records the compile id of the resolved
    /// standing-block prompt in effect; `activated_memory_ids` and
    /// `board_state_ref` record the Eiri activated-memories board
    /// ([`EiriMemoryBoard`]) as shown — not the `[CONTEXT_BOARD]` render
    /// block, which is a distinct surface.
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
            disclosure_stamp: None,
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

    /// Records the OF-365 disclosure stamp
    /// (`DisclosureContext::receipt_stamp`) for this emit's assembly.
    #[must_use]
    pub fn disclosure_stamp(mut self, disclosure_stamp: impl Into<String>) -> Self {
        self.disclosure_stamp = Some(disclosure_stamp.into());
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
        if let Some(disclosure_stamp) = self.disclosure_stamp.as_ref() {
            fields.insert(FIELD_DISCLOSURE_STAMP.to_owned(), disclosure_stamp.clone());
        }
    }
}

/// Computes the content-hash ref of the Eiri activated-memories board
/// ([`EiriMemoryBoard`]) — a distinct surface from the `[CONTEXT_BOARD]`
/// render block, which is never hashed here.
///
/// The ref covers the board as shown (rows, scores, budget, companion), so
/// any drift in retrieval output produces a different ref while already
/// recorded receipts keep the ref captured at their emit.
pub fn eiri_memory_board_state_ref(board: &EiriMemoryBoard) -> Result<String> {
    let bytes = rmp_serde::to_vec_named(board)
        .map_err(|_| Error::InvariantViolation("context board state ref encode failed"))?;
    Ok(format!(
        "{BOARD_STATE_REF_PREFIX}{}",
        hex_lower(blake3::hash(&bytes).as_bytes())
    ))
}

/// Projects an attempt's accumulated PACK MANIFEST into receipt fields
/// (ARCH-0053 §2 — the manifest is the attribution hinge).
///
/// This is a field-set on the RS1 shared spine, NOT a new receipt kind and
/// NOT a new store: the terminal receipt of an attempt carries what the pack
/// actually loaded, so an outcome can be attributed to a skill or an actor
/// without re-deriving the pack. Both keys are always stamped, so an absent
/// key means "this receipt predates the manifest" while an empty array means
/// "the pack loaded nothing of that kind".
///
/// Order is the manifest's append order — never sorted, never deduped: the
/// append-only sequence IS the evidence.
pub fn append_pack_manifest_fields(
    receipt: &mut ReceiptRecord,
    manifest: &[ManifestEntry],
) -> Result<()> {
    let skills = manifest_wire_forms(manifest, ManifestKind::Skill);
    let actor_claims = manifest_wire_forms(manifest, ManifestKind::ActorClaim);
    receipt.fields.insert(
        FIELD_MANIFEST_SKILLS.to_owned(),
        encode_wire_forms(&skills)?,
    );
    receipt.fields.insert(
        FIELD_MANIFEST_ACTOR_CLAIMS.to_owned(),
        encode_wire_forms(&actor_claims)?,
    );
    Ok(())
}

fn manifest_wire_forms(manifest: &[ManifestEntry], kind: ManifestKind) -> Vec<String> {
    manifest
        .iter()
        .filter(|entry| entry.kind == kind)
        .map(ManifestEntry::wire_form)
        .collect()
}

fn encode_wire_forms(entries: &[String]) -> Result<String> {
    serde_json::to_string(entries)
        .map_err(|_| Error::InvariantViolation("pack manifest field encode failed"))
}

fn decode_wire_forms(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str(raw).ok()
}

/// The stable `receipt_id` of one attempt's terminal PACK RECEIPT.
///
/// Attribution evidence cites this string, and the ledger is keyed by it, so
/// a cited `receipt_ref` resolves with a point-read rather than a scan.
#[must_use]
pub fn attempt_pack_receipt_id(attempt_id: &AttemptId) -> String {
    format!(
        "{ATTEMPT_PACK_RECEIPT_ID_PREFIX}{}",
        hex_lower(attempt_id.as_bytes())
    )
}

fn attempt_pack_receipt_key(receipt_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ATTEMPT_PACK_RECEIPT_KEY_PREFIX.len() + receipt_id.len());
    key.extend_from_slice(ATTEMPT_PACK_RECEIPT_KEY_PREFIX);
    key.extend_from_slice(receipt_id.as_bytes());
    key
}

/// Stamps the terminal pack receipt for an attempt that ran underneath a
/// skill pack, inside the terminal transition's OWN write transaction.
///
/// This is the production call path for [`append_pack_manifest_fields`]:
/// [`AttemptQueue::complete`] and [`AttemptQueue::fail`] are the two doors
/// every execute leaves through, so stamping there cannot be forgotten by a
/// caller and cannot drift per lane. An attempt whose pack loaded nothing
/// mints no row — the manifest IS the reason this receipt exists.
///
/// Atomic with the state seal: a terminal attempt with a manifest and no
/// receipt (or the reverse) is not a reachable state. The row is written
/// once, at the transition, and never rewritten — which is what makes
/// "a closed attempt's manifest is the evidence its receipt already
/// projected" true rather than aspirational.
///
/// [`AttemptQueue::complete`]: crate::attempt_queue::AttemptQueue::complete
/// [`AttemptQueue::fail`]: crate::attempt_queue::AttemptQueue::fail
pub(crate) fn stamp_attempt_pack_receipt_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    actor: &str,
) -> Result<()> {
    if record.manifest().is_empty() {
        return Ok(());
    }
    let mut receipt = ReceiptRecord {
        receipt_id: attempt_pack_receipt_id(&record.id),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: record.updated_at,
        actor: Some(actor.to_owned()),
        on_behalf_of: None,
        outcome: record.state.as_str().to_owned(),
        job_ref: record.run_id.clone(),
        trigger_ref: record.task_ref.clone(),
        policy_trace: Vec::new(),
        fields: BTreeMap::new(),
    };
    append_pack_manifest_fields(&mut receipt, record.manifest())?;
    let encoded = rmp_serde::to_vec_named(&receipt)
        .map_err(|_| Error::InvariantViolation("attempt pack receipt encode failed"))?;
    store.vault_meta.put(
        wtxn,
        &attempt_pack_receipt_key(&receipt.receipt_id),
        &encoded,
    )?;
    Ok(())
}

/// Point-reads the attempt pack receipt named by `receipt_id`.
///
/// `Ok(None)` means "no such receipt on the ledger" — the answer attribution
/// needs to reject a fabricated `receipt_ref`, and the reason this is a
/// point-read: it runs once per recorded outcome.
pub fn attempt_pack_receipt(vault: &Vault, receipt_id: &str) -> Result<Option<ReceiptRecord>> {
    if !receipt_id.starts_with(ATTEMPT_PACK_RECEIPT_ID_PREFIX) {
        return Ok(None);
    }
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &attempt_pack_receipt_key(receipt_id))?
    else {
        return Ok(None);
    };
    decode_attempt_pack_receipt(&raw).map(Some)
}

/// Overwrites one row of the pack receipt ledger.
///
/// Test-only by construction: production stamps exactly once, at the terminal
/// transition, and never rewrites. Tests use it to synthesize rows the current
/// stamper cannot produce (a receipt predating the manifest field-set).
#[cfg(test)]
pub(crate) fn overwrite_attempt_pack_receipt_for_test(
    vault: &Vault,
    receipt: &ReceiptRecord,
) -> Result<()> {
    vault.with_write_txn(|wtxn| put_attempt_pack_receipt_for_test(&vault.store, wtxn, receipt))
}

/// The transaction-scoped half of [`overwrite_attempt_pack_receipt_for_test`],
/// so a test that synthesizes a large ledger pays one write transaction rather
/// than one per row.
#[cfg(test)]
pub(crate) fn put_attempt_pack_receipt_for_test(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &ReceiptRecord,
) -> Result<()> {
    let encoded = rmp_serde::to_vec_named(receipt)
        .map_err(|_| Error::InvariantViolation("attempt pack receipt encode failed"))?;
    store.vault_meta.put(
        wtxn,
        &attempt_pack_receipt_key(&receipt.receipt_id),
        &encoded,
    )?;
    Ok(())
}

/// Names the first key past the attempt pack receipt family.
///
/// The reverse walk needs an explicit half-open range because `OverlayDb`
/// exposes no reverse prefix iterator. The prefix is an ASCII literal, so its
/// final byte is nowhere near `0xFF` and bumping it is the exclusive bound.
fn attempt_pack_receipt_key_range_end() -> Vec<u8> {
    let mut end = ATTEMPT_PACK_RECEIPT_KEY_PREFIX.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Collects the attempt pack receipt ledger under the family DoS guard.
///
/// Walks the key range NEWEST-FIRST — the key embeds the UUIDv7 attempt id, so
/// key order IS mint order — and caps the walk at [`MAX_RECEIPT_QUERY_SCAN`].
/// Direction is the whole point of the cap: these rows persist for the life of
/// the vault (unlike the attempt events they project from, which drain), so an
/// oldest-first cap would permanently hide every RECENT receipt behind an
/// attacker-grown backlog, and the family query is newest-first by contract.
/// Callers sort and truncate downstream, so below the cap this returns the
/// same set the unbounded walk did.
///
/// Above the cap the answer is a bounded PREFIX, not the family — which
/// [`note_attempt_pack_scan_capped`] says out loud rather than truncating in
/// silence.
fn attempt_pack_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let end = attempt_pack_receipt_key_range_end();
    let bounds = (
        std::ops::Bound::Included(ATTEMPT_PACK_RECEIPT_KEY_PREFIX),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut receipts = Vec::new();
    // One row PAST the cap is read and never decoded: it is what separates a
    // ledger holding exactly the cap from one the cap truncated.
    for row in vault
        .store
        .vault_meta
        .rev_range(&rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN + 1)
    {
        let (_, raw) = row?;
        if receipts.len() == MAX_RECEIPT_QUERY_SCAN {
            note_attempt_pack_scan_capped();
            break;
        }
        receipts.push(decode_attempt_pack_receipt(&raw)?);
    }
    Ok(receipts)
}

/// Surfaces an attempt pack receipt scan that stopped at the work cap.
///
/// The discarded remainder is unbounded by construction, so it is never
/// counted — the signal is that the cap FIRED, which is the fact an operator
/// (or a test) needs to know the query answered from a prefix.
fn note_attempt_pack_scan_capped() {
    tracing::warn!(
        scan_cap = MAX_RECEIPT_QUERY_SCAN,
        "attempt pack receipt scan hit the receipt-family work cap; older rows were not projected"
    );
    #[cfg(test)]
    ATTEMPT_PACK_SCAN_CAPPED.with(|fired| fired.set(fired.get() + 1));
}

fn decode_attempt_pack_receipt(raw: &[u8]) -> Result<ReceiptRecord> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("attempt pack receipt row"))
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
    /// Reads the ARCH-0053 §2 pack manifest recorded on this receipt: the
    /// `skill_id@version` rows the attempt's pack loaded, in append order.
    ///
    /// Returns `None` on receipts stamped before the field-set existed —
    /// distinct from `Some(vec![])`, which records a pack that loaded no
    /// skills. The values are read from the recorded field alone, never
    /// recomputed from the live attempt row (record-not-replay).
    #[must_use]
    pub fn pack_manifest_skills(&self) -> Option<Vec<String>> {
        decode_wire_forms(self.fields.get(FIELD_MANIFEST_SKILLS)?)
    }

    /// Reads the ARCH-0053 §2 pack manifest's `actor.*` claim rows. Same
    /// absent-versus-empty contract as [`Self::pack_manifest_skills`].
    #[must_use]
    pub fn pack_manifest_actor_claims(&self) -> Option<Vec<String>> {
        decode_wire_forms(self.fields.get(FIELD_MANIFEST_ACTOR_CLAIMS)?)
    }

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
            disclosure_stamp: self.fields.get(FIELD_DISCLOSURE_STAMP).cloned(),
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

    /// DEC-0006 surface (b): the unified consent registry, projected here so
    /// review and one-tap revoke reach it through the receipt family like
    /// every other lens.
    ///
    /// This is a re-export of [`Vault::consent_registry`], not a second
    /// registry — invariant 9 allows exactly two human surfaces, so a lens
    /// that recomputed its own view would BE the forbidden third one.
    /// [`Vault::standing_outbound_grants_lens`] above is likewise a
    /// COMPATIBILITY projection over the outbound grant family, kept for its
    /// existing callers rather than promoted to a separate consent surface.
    pub fn consent_registry_lens(
        &self,
        query: crate::consent::ConsentRegistryQuery,
    ) -> Result<crate::consent::ConsentRegistry> {
        self.consent_registry(query)
    }
}

/// Persists the outbound pipeline receipt as the sole durable record of a
/// connector send. A delivered row atomically installs the actor-scoped client
/// idempotency index; a failed row remains audit-only and may be replaced by a
/// later delivered retry for the same TASK.
pub(crate) fn persist_send_receipt(
    vault: &Vault,
    task_ref: EntityId,
    mut receipt: ReceiptRecord,
    outcome: SendReceiptOutcome,
    transport_dispatched: bool,
    delivered_idempotency: Option<(EntityId, &str)>,
) -> Result<bool> {
    receipt
        .fields
        .insert(FIELD_TASK_REF.to_owned(), task_ref.to_hex());
    receipt.fields.insert(
        FIELD_TRANSPORT_DISPATCHED.to_owned(),
        transport_dispatched.to_string(),
    );
    let durable = DurableSendReceipt {
        version: SEND_RECEIPT_RECORD_VERSION,
        task_ref: task_ref.to_hex(),
        outcome,
        transport_dispatched,
        receipt,
    };
    let encoded = rmp_serde::to_vec_named(&durable)
        .map_err(|_| Error::InvariantViolation("send receipt encode failed"))?;
    vault.with_write_txn(|wtxn| {
        let existing = vault
            .store
            .get_send_receipt_by_task_in_txn(&*wtxn, &task_ref)?;
        if let Some(raw) = existing.as_deref() {
            let existing = decode_durable_send_receipt(task_ref.as_bytes(), raw)?;
            if existing.outcome == SendReceiptOutcome::Delivered {
                return Ok(false);
            }
        }
        if existing.is_some() {
            vault
                .store
                .set_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
        } else {
            vault
                .store
                .put_send_receipt_in_txn(wtxn, &task_ref, &encoded)?;
        }
        if outcome == SendReceiptOutcome::Delivered
            && let Some((actor_ref, idempotency_key)) = delivered_idempotency
        {
            vault.store.put_delivered_send_idempotency_in_txn(
                wtxn,
                &actor_ref,
                idempotency_key,
                &task_ref,
            )?;
        }
        Ok(true)
    })
}

/// Point-reads a delivered receipt for executor and schedule idempotency.
/// Failed audit rows intentionally project as absent from this seam.
pub(crate) fn delivered_send_receipt_for_task(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<ReceiptRecord>> {
    let Some(raw) = vault.store.get_send_receipt_by_task(&task_ref)? else {
        return Ok(None);
    };
    let durable = decode_durable_send_receipt(task_ref.as_bytes(), &raw)?;
    Ok((durable.outcome == SendReceiptOutcome::Delivered).then_some(durable.receipt))
}

fn decode_durable_send_receipt(task_id: &[u8; 16], raw: &[u8]) -> Result<DurableSendReceipt> {
    let durable: DurableSendReceipt =
        rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("send receipt ledger"))?;
    let expected_receipt_outcome = match durable.outcome {
        SendReceiptOutcome::Delivered => "delivered_to_channel",
        SendReceiptOutcome::Failed => "failed",
    };
    if durable.version != SEND_RECEIPT_RECORD_VERSION
        || durable.task_ref != crate::entity_id::bytes_to_hex_lower(task_id)
        || durable.receipt.receipt_kind != ReceiptKind::Outbound
        || durable.receipt.outcome != expected_receipt_outcome
        || durable.receipt.fields.get(FIELD_TASK_REF) != Some(&durable.task_ref)
        || durable
            .receipt
            .fields
            .get(FIELD_TRANSPORT_DISPATCHED)
            .and_then(|value| value.parse::<bool>().ok())
            != Some(durable.transport_dispatched)
    {
        return Err(Error::CorruptedIndex("send receipt ledger"));
    }
    Ok(durable)
}

fn durable_send_receipts(vault: &Vault) -> Result<Vec<ReceiptRecord>> {
    vault
        .store
        .send_receipt_rows()?
        .into_iter()
        .map(|(task_id, raw)| {
            decode_durable_send_receipt(&task_id, &raw).map(|durable| durable.receipt)
        })
        .collect()
}

/// Builds an outbound receipt row from the OF-327 intent spine.
///
/// The helper keeps `job_ref` propagation explicit for brief-rooted runs while
/// preserving legacy compatibility: callers that pass an older intent without a
/// attempt ref still emit a receipt with `job_ref: None`.
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
            for run_ref in index.run_to_parent_run.keys().cloned() {
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
            for intent_ref in index.intent_to_run.keys().cloned() {
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
    records.sort_by(receipt_newest_first_order);
}

fn receipt_newest_first_order(left: &ReceiptRecord, right: &ReceiptRecord) -> std::cmp::Ordering {
    right
        .occurred_at
        .cmp(&left.occurred_at)
        .then_with(|| left.receipt_kind.cmp(&right.receipt_kind))
        .then_with(|| left.receipt_id.cmp(&right.receipt_id))
}

fn retain_newest_receipt(receipts: &mut Vec<ReceiptRecord>, receipt: ReceiptRecord, limit: usize) {
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
    if query.includes_kind(ReceiptKind::Outbound) {
        records.extend(
            durable_send_receipts(vault)?
                .into_iter()
                .filter(|receipt| query.matches(receipt)),
        );
        records.extend(
            attempt_pack_receipts(vault)?
                .into_iter()
                .filter(|receipt| query.matches(receipt)),
        );
    }
    if query.includes_kind(ReceiptKind::Gate) {
        records.extend(gate_receipts(vault, query)?);
        // The SECOND Gate projector (ONE-1748): consent-graduation
        // self-demotions and door-recorded ramp outcomes. They share the kind
        // but not the store — a ramp bookkeeping row has no business in the
        // gate-decision ledger, which ONE-1637 made the erasure chain's H0
        // index. Both projectors open their own read txn, so they run before
        // the shared `rtxn` below.
        records.extend(crate::consent_graduation::ramp_receipts(vault, query)?);
        // The THIRD Gate projector (ONE-1762): escalation rulings and the
        // standing policies they earn. Same kind, own store, own field class —
        // an escalation is a gate decision a human made, so it mints no kind of
        // its own. Opens its own read txn, as the ramp projector does.
        records.extend(crate::edit_distance::escalation::escalation_receipts(
            vault, query,
        )?);
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
    // ONE type-76 scan serves both kinds it projects; the projector-level
    // kind gate keeps a single-kind query from returning the other's rows.
    if query.includes_kind(ReceiptKind::IdentityLifecycle)
        || query.includes_kind(ReceiptKind::ProposalOutcome)
    {
        records.extend(identity_topology_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::ScopedRead) {
        records.extend(access_grant_receipts(vault, &rtxn, query)?);
        records.extend(outbound_grant_receipts(vault, &rtxn, query)?);
    }
    if query.includes_kind(ReceiptKind::Share) {
        records.extend(federation_share_receipts(vault, &rtxn, query)?);
        records.extend(persona_snapshot_export_receipts(vault, &rtxn, query)?);
    }

    // ED-01 (ONE-1757): the reserved Δ slot is filled from its own side-ledger
    // once, HERE, rather than by every projector that can emit an amended
    // outcome. Receipts are projections, so a Δ has nowhere else to be
    // stamped; one pass over the collected records keeps the family
    // projectors ignorant of edit distance.
    crate::edit_distance::delta::attach_amendment_deltas(vault, &rtxn, &mut records)?;

    Ok(records)
}

fn gate_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let mut receipts = Vec::new();
    let mut before = None;
    loop {
        #[cfg(test)]
        GATE_RECEIPT_PAGES_SCANNED.with(|count| count.set(count.get() + 1));
        let decisions = vault
            .store
            .gate_decisions_page(before, MAX_RECEIPT_QUERY_SCAN)?;
        let page_len = decisions.len();
        before = decisions.last().map(|decision| decision.decision_id);
        for decision in decisions {
            let receipt = gate_decision_receipt(&decision);
            if query.matches(&receipt) {
                if query.job_ref.is_none() {
                    // Decision ids define ledger traversal, but connector-key
                    // rows may carry caller-supplied, non-monotonic event
                    // times. Scan every page while retaining only the exact
                    // public newest-first top-N. `job_ref` stays exhaustive
                    // because its lineage join runs after collection.
                    retain_newest_receipt(&mut receipts, receipt, query.limit);
                } else {
                    receipts.push(receipt);
                }
                #[cfg(test)]
                GATE_RECEIPT_MAX_BUFFERED.with(|max| max.set(max.get().max(receipts.len())));
            }
        }
        if page_len < MAX_RECEIPT_QUERY_SCAN {
            break;
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

/// Projects ARCH-0055 identity-topology ledger events (merge / split / undo
/// counter-events, effective AND parked) into `IdentityLifecycle` receipts.
///
/// Scans the type-76 record family NEWEST-FIRST (reverse type-index walk;
/// UUIDv7 ids order by mint time) and caps EVERY visited row, including rows
/// outside the query's `[start_at, end_at]` window. This is a bound on query
/// work, not merely on returned candidates: an attacker-controlled backlog
/// cannot force an unbounded ledger walk. Because mint order is not `at`
/// order, this bounded scan can starve an older-minted in-window receipt;
/// avoiding that requires an `at`-ordered index or cursor pagination. The
/// family is engine-authored and door-validated: an undecodable row is
/// corruption, never skipped.
fn identity_topology_receipts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let start = [crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT];
    let end = [crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT + 1];
    let bounds = (
        std::ops::Bound::Included(&start[..]),
        std::ops::Bound::Excluded(&end[..]),
    );
    let mut receipts = Vec::new();
    for entry in vault
        .store
        .type_index
        .rev_range(rtxn, &bounds)?
        .take(MAX_RECEIPT_QUERY_SCAN)
    {
        let (key, _) = entry?;
        let event_id = crate::vault::entity_id_from_type_index_key(&key)?;
        let record = vault
            .identity_topology_event_in_txn(rtxn, &event_id)?
            .ok_or(Error::CorruptedIndex("identity topology event index"))?;
        if query.end_at.is_some_and(|end_at| record.at > end_at)
            || query.start_at.is_some_and(|start_at| record.at < start_at)
        {
            continue;
        }
        // Per-kind dispatch: a resolution row NAMED by the fold as a
        // duplicate (the proposal already retired by an EARLIER ruling)
        // projects nothing — an outcome receipt for it would read as a
        // second, contradictory decision about one review. Rejection sets
        // arrive from the fold the log itself maintains, so a replay that
        // double-rules converges to the same single receipt everywhere.
        let action_is_resolution = matches!(
            record.action,
            crate::identity_topology::StoredIdentityOpAction::ProposalResolution { .. }
        );
        if action_is_resolution {
            let fold = crate::identity_topology::fold_identity_topology_log(
                &vault.fold_effective_identity_topology_events_in_txn(rtxn)?,
            );
            if fold
                .rejections
                .iter()
                .any(|(rejected, reason)| {
                    *rejected == event_id
                        && matches!(
                            reason,
                            crate::identity_topology::IdentityTopologyRejection::ProposalAlreadyResolved { .. }
                        )
                })
            {
                continue;
            }
        }
        let receipt = if action_is_resolution {
            proposal_outcome_receipt(&event_id, &record)
        } else {
            identity_topology_receipt(&event_id, &record)
        };
        if query.includes_kind(receipt.receipt_kind) && query.matches(&receipt) {
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

/// Projects the ARCH-0055 r7 proposal-outcome receipt from a resolution
/// ledger event (ONE-1747).
///
/// The three ramp-scope fields (`op_kind`, `target_class`, `actor`) are
/// stamped on ALL THREE outcomes so MS-06 (ONE-1748) can rebuild per-scope
/// ramp statistics from receipts alone, with no ledger dereference.
///
/// `amended_body` carries the amended op bytes as lower hex, present ONLY on
/// `approved_amended` — the producer artifact ED-01 (ONE-1757) diffs
/// against the proposal, never overwritten. It is DISTINCT from
/// [`FIELD_AMENDMENT_DELTA`], the reserved slot ED-01 fills with the encoded
/// Δ schema: two fields, two meanings. This ticket never writes the latter.
fn proposal_outcome_receipt(
    event_id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> ReceiptRecord {
    use crate::identity_topology::StoredIdentityOpAction;

    let StoredIdentityOpAction::ProposalResolution {
        proposal,
        outcome,
        scope,
        amended_body,
    } = &record.action
    else {
        unreachable!("proposal outcome receipt projects only resolution events")
    };

    let mut fields = BTreeMap::new();
    fields.insert(FIELD_PROPOSAL_REF.to_owned(), proposal.to_hex());
    fields.insert(FIELD_OP_KIND.to_owned(), scope.op_kind.to_owned());
    fields.insert(FIELD_TARGET_CLASS.to_owned(), scope.target_class.clone());
    fields.insert(FIELD_SCOPE_ACTOR.to_owned(), scope.actor.clone());
    // NOT `source`: that key is one of the six ARCH-0056 Δ field names this
    // receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
    // The claim-source axis is real and unrelated, so it keeps its own
    // unambiguous key rather than squatting on the reserved one.
    fields.insert(
        FIELD_CLAIM_SOURCE.to_owned(),
        record.source.as_str().to_owned(),
    );
    fields.insert("seq".to_owned(), record.seq.to_string());
    if let Some(amended_body) = amended_body {
        fields.insert(FIELD_AMENDED_BODY.to_owned(), hex_lower(amended_body));
    }

    ReceiptRecord {
        receipt_id: format!("proposal_outcome:{}", event_id.to_hex()),
        receipt_kind: ReceiptKind::ProposalOutcome,
        occurred_at: record.at,
        actor: record.actor.map(|actor| actor.entity_ref().to_hex()),
        on_behalf_of: None,
        outcome: outcome.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("event:{}", proposal.to_hex())),
        policy_trace: Vec::new(),
        fields,
    }
}

/// The amended op body a proposal-outcome receipt carries — the raw bytes
/// the decider approved, byte-identical to what was applied. `None` on
/// `approved_untouched` / `rejected` (nothing was amended) and on any other
/// receipt kind.
#[must_use]
pub fn proposal_outcome_amended_body(record: &ReceiptRecord) -> Option<Vec<u8>> {
    receipt_hex_field(record, FIELD_AMENDED_BODY)
}

/// The reserved ARCH-0056 amendment-delta slot (ONE-1747 mints it EMPTY;
/// ED-01 / ONE-1757 fills it with the encoded Δ schema).
///
/// Always `None` today — deliberately, not incidentally: the Δ schema is the
/// ED epic's surface, and building it here would over-build it. Distinct
/// from [`proposal_outcome_amended_body`], which is the producer artifact
/// the Δ is computed FROM.
#[must_use]
pub fn proposal_outcome_delta(record: &ReceiptRecord) -> Option<Vec<u8>> {
    receipt_hex_field(record, FIELD_AMENDMENT_DELTA)
}

/// Decodes an opaque payload field carried as lower hex. A malformed value
/// reads as absent: the field is engine-written through
/// [`hex_lower`], so unparseable content is not a payload the caller can
/// meaningfully act on.
fn receipt_hex_field(record: &ReceiptRecord, field: &str) -> Option<Vec<u8>> {
    let hex = record.fields.get(field)?;
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(hex.get(index..index + 2)?, 16).ok())
        .collect()
}

fn identity_topology_receipt(
    event_id: &EntityId,
    record: &crate::identity_topology::StoredIdentityOpEvent,
) -> ReceiptRecord {
    use crate::identity_topology::StoredIdentityOpAction;

    let mut fields = BTreeMap::new();
    fields.insert("approval".to_owned(), record.approval.as_str().to_owned());
    fields.insert("source".to_owned(), record.source.as_str().to_owned());
    fields.insert("seq".to_owned(), record.seq.to_string());
    if let Some(actor) = record.actor {
        fields.insert(
            "actor_class".to_owned(),
            actor.actor_class().gate_actor_class().to_owned(),
        );
    }
    // DECLARED vs APPLIED (ONE-1745), for every action that carries a
    // reassignment map. The gap is the point: it means the decision named
    // items this vault holds no claim for. Both halves read the STORED
    // record alone, so the projector stays pure — no vault, no txn.
    if let Some(map) = record.action.reassignment_map() {
        let (assigned, residue) = map.assigned_and_residue_counts();
        fields.insert("assigned".to_owned(), assigned.to_string());
        fields.insert("residue".to_owned(), residue.to_string());
    }
    if let Some(applied) = record.action.applied_reassignment_stats() {
        fields.insert("applied_assigned".to_owned(), applied.assigned.to_string());
        fields.insert("applied_residue".to_owned(), applied.residue.to_string());
    }
    let trigger_ref = match &record.action {
        StoredIdentityOpAction::Merge { sources, survivor } => {
            fields.insert("survivor".to_owned(), survivor.to_hex());
            fields.insert("source_count".to_owned(), sources.len().to_string());
            Some(format!("entity:{}", survivor.to_hex()))
        }
        StoredIdentityOpAction::Split { entity, heads, .. } => {
            fields.insert("entity".to_owned(), entity.to_hex());
            fields.insert("head_count".to_owned(), heads.len().to_string());
            Some(format!("entity:{}", entity.to_hex()))
        }
        StoredIdentityOpAction::Facet { entity, facets, .. } => {
            fields.insert("entity".to_owned(), entity.to_hex());
            fields.insert("facet_count".to_owned(), facets.len().to_string());
            Some(format!("entity:{}", entity.to_hex()))
        }
        // ONE-1746: the pair is the decision, and the claim is where it
        // lives — both projected so a reader can audit the assertion without
        // dereferencing the ledger event.
        StoredIdentityOpAction::AssertDistinct { a, b, claim } => {
            fields.insert("pair_a".to_owned(), a.to_hex());
            fields.insert("pair_b".to_owned(), b.to_hex());
            fields.insert("claim".to_owned(), claim.to_hex());
            Some(format!("claim:{}", claim.to_hex()))
        }
        StoredIdentityOpAction::Undo { target } => {
            fields.insert("undo_of".to_owned(), target.to_hex());
            Some(format!("event:{}", target.to_hex()))
        }
        // Resolution rows project the ProposalOutcome receipt instead; the
        // caller dispatches on the action before reaching this projector.
        StoredIdentityOpAction::ProposalResolution { proposal, .. } => {
            Some(format!("event:{}", proposal.to_hex()))
        }
    };

    ReceiptRecord {
        receipt_id: format!("identity_topology:{}", event_id.to_hex()),
        receipt_kind: ReceiptKind::IdentityLifecycle,
        occurred_at: record.at,
        actor: record.actor.map(|actor| actor.entity_ref().to_hex()),
        on_behalf_of: None,
        outcome: record.action.kind_str().to_owned(),
        job_ref: None,
        trigger_ref,
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
        receipt_id: format!("scoped_read:{grant_ref}:{event_name}"),
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
        let id = entity_id_from_type_index_key(&key, context)?;
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex(context));
        };
        let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex(context))?;
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
        AccessGrantScope::Calendar { calendar_ref, rung } => {
            fields.insert("scope".to_owned(), "calendar".to_owned());
            fields.insert("calendar_ref".to_owned(), calendar_ref.to_hex());
            fields.insert("rung".to_owned(), rung.as_str().to_owned());
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
        StandingOutboundGrantScope::ScopedMcp {
            server,
            tool,
            data_class_ceiling,
            endpoint_allowlist,
        } => {
            fields.insert("scope".to_owned(), "scoped_mcp".to_owned());
            fields.insert("server".to_owned(), server.clone());
            fields.insert("tool".to_owned(), tool.clone());
            fields.insert(
                "data_class_ceiling".to_owned(),
                data_class_ceiling.as_str().to_owned(),
            );
            fields.insert(
                "endpoint_allowlist".to_owned(),
                endpoint_allowlist.join("\n"),
            );
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
