//! Receipt row fields, query values, and deterministic ordering.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const DEFAULT_RECEIPT_QUERY_LIMIT: usize = 100;
pub const MAX_RECEIPT_QUERY_SCAN: usize = 100_000;

pub const RECEIPT_VIEW_COMPONENT: &str = "receipt_view";
pub const FIELD_JOB_REF: &str = "job_ref";
pub const FIELD_BRIEF_REF: &str = "brief_ref";
pub const FIELD_RUN_REF: &str = "run_ref";
pub const FIELD_INTENT_REF: &str = "intent_ref";
/// Originating connector-send TASK carried by durable outbound receipts.
pub const FIELD_TASK_REF: &str = "task_ref";
/// Durable proof that the connector execution sink was reached successfully.
pub const FIELD_TRANSPORT_DISPATCHED: &str = "transport_dispatched";
/// OF-543 ONE TASK TYPE: the placed type-tree node of a spawn/task receipt.
pub const FIELD_TYPE_REF_NODE: &str = "type_ref.node_id";
/// OF-543 ONE TASK TYPE: the tree version that placement was read from.
pub const FIELD_TYPE_REF_TREE_VERSION: &str = "type_ref.tree_version";
/// ARCH-0053 §2 pack manifest: the `skill_id@version` rows the attempt loaded,
/// as a canonical JSON array string.
pub const FIELD_MANIFEST_SKILLS: &str = "manifest.skills";
/// ARCH-0053 §2 pack manifest: the `actor.*` claim rows the attempt loaded, as
/// a canonical JSON array string.
pub const FIELD_MANIFEST_ACTOR_CLAIMS: &str = "manifest.actor_claims";

pub const FIELD_PARENT_REF: &str = "parent_ref";
pub const FIELD_COUNTERPARTY_REF: &str = "counterparty_ref";
pub const FIELD_IDENTITY_REF: &str = "identity_ref";
pub const FIELD_CHANNEL_IDENTITY_REF: &str = "channel_identity_ref";
pub const FIELD_RECEIVING_IDENTITY_REF: &str = "receiving_identity_ref";
pub const FIELD_GRANT_REF: &str = "grant_ref";
pub const FIELD_BUNDLE_REF: &str = "bundle_ref";
pub const FIELD_BUDGET_DEBIT: &str = "budget_debit";
pub const FIELD_BUDGET: &str = "budget";
pub const FIELD_FIRST_TOUCH: &str = "first_touch";
pub const FIELD_OPT_OUT: &str = "opt_out";
pub const FIELD_PROMO_CONSENT: &str = "promo_consent";
pub const FIELD_PERSONA_COMPILE_STAMP: &str = "persona_compile_stamp";
pub const FIELD_ACTIVATED_MEMORY_IDS: &str = "activated_memory_ids";
pub const FIELD_BOARD_STATE_REF: &str = "board_state_ref";
pub const FIELD_SUBSTRATE_REF: &str = "substrate_ref";
pub const FIELD_MODEL: &str = "model";
pub const FIELD_REASONING_EFFORT: &str = "reasoning_effort";
pub const FIELD_PROMPT_INPUT_REF: &str = "prompt_input_ref";
pub const FIELD_DISCLOSURE_STAMP: &str = "disclosure_stamp";
/// The ASSET a served-form receipt names, lower hex: what
/// [`ReceiptQuery::with_asset_ref`] matches.
pub const FIELD_ASSET_REF: &str = "asset_ref";

/// ARCH-0055 r7 proposal-outcome receipt fields (ONE-1747).
///
/// The three ramp-scope keys are `pub(crate)` because ONE-1748's demotion
/// receipt names the SAME scope tuple: two spellings of one key would make the
/// ramp's own receipts unjoinable with the outcome receipts they answer.
pub const FIELD_PROPOSAL_REF: &str = "proposal_ref";
pub const FIELD_OP_KIND: &str = "op_kind";
pub const FIELD_TARGET_CLASS: &str = "target_class";
pub const FIELD_SCOPE_ACTOR: &str = "actor";
/// Why a consent-graduation scope was demoted back to the propose lane
/// (ONE-1748); the wire strings are `consent_graduation::DemotionReason`.
pub const FIELD_DEMOTION_REASON: &str = "demotion_reason";
/// The resolution event's claim-source axis. Deliberately NOT `"source"`:
/// that key is reserved as one of the six ARCH-0056 Δ field names this
/// receipt must not project until ED-01 (ONE-1757) builds the Δ schema.
pub const FIELD_CLAIM_SOURCE: &str = "claim_source";
/// The amended op body verbatim (lower hex) — the PRODUCER artifact.
pub const FIELD_AMENDED_BODY: &str = "amended_body";
/// The ARCH-0056 Δ slot. Minted reserved by ONE-1747; ED-01 (ONE-1757) fills
/// it from the Δ side-ledger as receipts project
/// (`edit_distance::delta::attach_amendment_deltas`), which is why the key is
/// `pub(crate)` rather than private to this module.
pub const FIELD_AMENDMENT_DELTA: &str = "amendment_delta";
/// Companion marker to [`FIELD_AMENDMENT_DELTA`]: the Δ for this amendment was
/// measured and the measurement FAILED. It exists so the two states a reader
/// would otherwise confuse stay apart — capture failure is non-fatal, but it
/// is receipted, never silent.
pub const FIELD_AMENDMENT_DELTA_UNCAPTURED: &str = "amendment_delta_uncaptured";
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
pub const FIELD_ESCALATION_SCOPE: &str = "escalation_scope";
/// Which of the three closed triggers fired (`escalation::EscalationTrigger`).
pub const FIELD_ESCALATION_TRIGGER: &str = "escalation_trigger";
/// What was ruled (`escalation::EscalationRuling`). Also the ledger receipt's
/// `outcome`; on a standing-policy receipt the outcome is the row's STATUS, so
/// this field is what keeps one key answering "what was ruled" across the whole
/// class.
pub const FIELD_ESCALATION_RULING: &str = "escalation_ruling";
/// What the engine asked when it stopped.
pub const FIELD_ESCALATION_QUESTION: &str = "escalation_question";
/// Why the human ruled as they did.
pub const FIELD_ESCALATION_RATIONALE: &str = "escalation_rationale";
/// The ask's magnitude band. Budget-triggered escalations only.
pub const FIELD_ESCALATION_BUDGET_BAND: &str = "escalation_budget_band";
/// The band ceiling a standing policy covers — distinct from
/// [`FIELD_ESCALATION_BUDGET_BAND`], which is one ask's magnitude rather than a
/// row's reach.
pub const FIELD_ESCALATION_BAND_CEILING: &str = "escalation_band_ceiling";
/// Comma-joined receipt ids of the rulings a standing policy was learned from.
pub const FIELD_ESCALATION_CITED_RECEIPTS: &str = "escalation_cited_receipts";
/// The ONE-1449 SKILL-EDIT GATE field class (SKILL-OPT-2).
///
/// A held-out score-gate verdict is a gate decision the engine made, so it
/// projects into the existing `Gate` kind rather than minting one — the
/// [`FIELD_ESCALATION_SCOPE`] precedent, and these keys are the discriminator
/// that says which projector wrote a record. `crate::skill_optimize` is the
/// only writer, and they are `pub(crate)` for the reason that class is: a
/// second spelling of one key would make the family unjoinable with itself.
pub const FIELD_SKILL_EDIT_PROPOSAL: &str = "skill_edit_proposal";
/// The ACTIVE skill entity the gated proposal revises.
pub const FIELD_SKILL_EDIT_SKILL: &str = "skill_edit_skill";
/// Held-out replay score of the CURRENT instructions, as a decimal numeral.
///
/// Deliberately a numeral rather than prose or a digest: the whole point of the
/// pair is that a reader can compare it, and the receipt family's field ABI is
/// string-valued. The same two numbers are served already-typed by
/// `crate::skill_optimize::skill_edit_verdicts`.
pub const FIELD_SKILL_EDIT_SCORE_BEFORE: &str = "skill_edit_score_before";
/// Held-out replay score of the PROPOSED instructions, as a decimal numeral.
pub const FIELD_SKILL_EDIT_SCORE_AFTER: &str = "skill_edit_score_after";
/// JSON measurement of the two DecoEvo audits and per-axis world agreement.
pub const FIELD_SKILL_EDIT_MEASUREMENTS: &str = "skill_edit_measurements";
/// The scored goal vector, including axis classes.
pub const FIELD_SKILL_EDIT_GOAL_AXES: &str = "skill_edit_goal_axes";
/// Bound human decision evidence for a scored tradeoff.
pub const FIELD_SKILL_EDIT_TRADEOFF_RESOLUTION: &str = "skill_edit_tradeoff_resolution";
/// The Dreamer cycle the verdict counted against, for the per-cycle accept cap.
pub const FIELD_SKILL_EDIT_CYCLE: &str = "skill_edit_cycle";
/// Comma-joined reserved receipt ids the score pair was computed over.
///
/// A bounded DISPLAY list. The complete basis is
/// [`FIELD_SKILL_EDIT_HELD_OUT_COUNT`] plus
/// [`FIELD_SKILL_EDIT_HELD_OUT_DIGEST`], and
/// [`FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED`] says when this list is a prefix of
/// the truth rather than the whole of it.
pub const FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS: &str = "skill_edit_held_out_receipts";
/// How many reserved receipts the score pair was ACTUALLY computed over.
///
/// The count is the completeness check the display list cannot make: a reader
/// comparing it against `skill_edit_held_out_receipts` learns whether it is
/// looking at the whole basis or a window on it.
pub const FIELD_SKILL_EDIT_HELD_OUT_COUNT: &str = "skill_edit_held_out_count";
/// Canonical digest of the EXACT scored evidence set, in scored order.
///
/// What makes an acceptance auditable after the ledger has moved on: the set
/// itself cannot be reconstructed from a later read once more outcomes land,
/// but it can be recomputed and compared against this.
pub const FIELD_SKILL_EDIT_HELD_OUT_DIGEST: &str = "skill_edit_held_out_digest";
/// `"true"` when the display list is a bounded window on a larger basis.
/// Absent otherwise — hidden truncation is the failure this key exists to end.
pub const FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED: &str = "skill_edit_held_out_truncated";
/// Canonical content digest of the candidate body the scores were computed on.
pub const FIELD_SKILL_EDIT_PROPOSAL_DIGEST: &str = "skill_edit_proposal_digest";
/// Canonical content digest of the predecessor body the scores were computed
/// against.
pub const FIELD_SKILL_EDIT_TARGET_DIGEST: &str = "skill_edit_target_digest";
/// The accepted verdict row a post-score admission refusal answers.
///
/// A refusal reached THROUGH a standing acceptance carries that acceptance's
/// real score pair and evidence basis, so this key names the ruling it
/// supersedes rather than leaving a reader to guess which one it was.
pub const FIELD_SKILL_EDIT_ACCEPTED_VERDICT: &str = "skill_edit_accepted_verdict";
/// What the gate ruled (`skill_optimize::SkillEditDisposition`). Also the
/// receipt's `outcome`; this key keeps one name answering "what was ruled".
pub const FIELD_SKILL_EDIT_DISPOSITION: &str = "skill_edit_disposition";
/// Comma-joined cited `source_messages` ids that no longer resolve, on a
/// source-liveness refusal.
pub const FIELD_SKILL_EDIT_MISSING_SOURCES: &str = "skill_edit_missing_sources";
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
pub const FIELD_PREFILTER_PHASE: &str = "phase";
/// What the screen ruled: `pass` or `skip` on a turn row, `screened` on a
/// round rollup. Also the receipt's `outcome`; this key keeps one name
/// answering "what was ruled" across the whole class.
pub const FIELD_PREFILTER_DECISION: &str = "decision";
/// The turn's screening score, as a decimal numeral.
///
/// A numeral rather than a band: the whole point of a score is that a reader
/// can compare it against the threshold that rejected it, and the receipt
/// family's field ABI is string-valued.
pub const FIELD_PREFILTER_SCORE: &str = "score";
/// The threshold the score was ruled against — without it the score is a
/// number with no verdict in it.
pub const FIELD_PREFILTER_THRESHOLD: &str = "threshold";
/// Prefix of the per-axis feature keys (`features.len`, `features.novelty`,
/// …). Every input to the score travels with it, so a ruling can be
/// recomputed rather than trusted.
pub const FIELD_PREFILTER_FEATURE_PREFIX: &str = "features.";
/// The planning round's `partition_round_hash`, lower hex — the join key
/// between a skip row and the rollup that counted it.
pub const FIELD_PREFILTER_ROUND: &str = "round";
/// The screened TURN, lower hex.
pub const FIELD_PREFILTER_TURN: &str = "turn";
/// Rollup: how many turns the round screened.
pub const FIELD_PREFILTER_SCANNED: &str = "scanned";
/// Rollup: how many were kept for extraction.
pub const FIELD_PREFILTER_PASSED: &str = "passed";
/// Rollup: how many were screened out.
pub const FIELD_PREFILTER_SKIPPED: &str = "skipped";
/// Estimated prompt tokens NOT spent — per turn on a skip row, summed over the
/// round on a rollup. The savings claim is on the receipt because a budget
/// filter that could not show its savings would be asking to be believed.
pub const FIELD_PREFILTER_TOKENS_SAVED: &str = "tokens_saved";
pub const FIELD_RECEIPT_SCHEMA: &str = "receipt_schema";
pub const FIELD_ENGINE_REGISTER: &str = "engine_register";
pub const FIELD_CARE_REGISTER: &str = "care_register";
pub const FIELD_AUDIT_REGISTER: &str = "audit_register";

pub const fn default_receipt_query_limit() -> usize {
    DEFAULT_RECEIPT_QUERY_LIMIT
}

/// Receipt family discriminator pinned by OF-367 RS1.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
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
    /// Commitment lifecycle receipt (CMT-4, ONE-1541): a `commitment.record`
    /// CLAIM reached a terminal status — kept, waived, or let go. Projected
    /// from the claim row itself; there is no lifecycle ledger, so the
    /// invariant it carries is bounded by `MAX_RECEIPT_QUERY_SCAN` exactly
    /// like every other projected kind.
    CommitmentLifecycle,
    /// Pre-extraction screening receipt (OF-361, ONE-1525): what the Dreamer
    /// declined to spend extraction budget on, why, and what that saved.
    ///
    /// It mints a kind rather than joining `Gate` — the precedent ONE-1762's
    /// escalations and ONE-1449's skill-edit verdicts both took — because it
    /// is not a gate decision. A gate rules on whether something MAY happen
    /// and is answerable to policy; this rules on whether something is WORTH
    /// doing and is answerable to a budget. Filing a budget estimate in the
    /// gate ledger would make "what did the gate refuse" un-askable.
    ///
    /// Not emit-adjacent: nothing leaves the vault when a turn is screened.
    Extraction,
    /// Served-form receipt (OF-329): which form of an ASSET one read served,
    /// its image bytes or its text in place of its body, and to which
    /// holder. The read writes it before it answers, as its own
    /// RECEIPT_RECORD, so it is a floor receipt.
    ///
    /// Not emit-adjacent: the read answers its own caller.
    ServedForm,
    /// One fact-hook run (ARCH-0080 §6): the hook, its CODE id and body hash,
    /// the duration, the outcome, `now` and the rows it read. Written by the
    /// runner in the run's own transaction, to its own store.
    Hook,
    /// One record ref a write named that its writer cannot resolve (OF-063):
    /// the actor, the verb row, the field pointer and the time. `refused`
    /// when a typed slot named it and the write never ran; `unlinked` when
    /// AI-written prose linked it and the text landed with the link shown as
    /// plain label. Written where it is found, on its own write, as its own
    /// RECEIPT_RECORD; it never holds the ref or any other content of the
    /// attempt.
    ReferenceRefusal,
    /// One mutating task-highway call (OF-220, ARCH-0079): post, accept or
    /// report, what it asked and resolved, and why. The highway assembles
    /// the call's `TaskLifecycleRecord`; the call's own write transaction
    /// keeps it, projected once, in its own store under a stable receipt id
    /// its `receipt_ref` names. A status read keeps none.
    TaskLifecycle,
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
            Self::CommitmentLifecycle => "commitment_lifecycle",
            Self::Extraction => "extraction",
            Self::ServedForm => "served_form",
            Self::Hook => "hook",
            Self::ReferenceRefusal => "reference_refusal",
            Self::TaskLifecycle => "task_lifecycle",
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
            "commitment_lifecycle" => Some(Self::CommitmentLifecycle),
            "extraction" => Some(Self::Extraction),
            "served_form" => Some(Self::ServedForm),
            "hook" => Some(Self::Hook),
            "reference_refusal" => Some(Self::ReferenceRefusal),
            "task_lifecycle" => Some(Self::TaskLifecycle),
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

    /// OF-543: spawn and task receipts require a `typeRef`. The attempt pack
    /// receipt projects on the `Outbound` kind, and a task-highway call's
    /// lifecycle on `TaskLifecycle`; each stamps the type its brief placed.
    #[must_use]
    pub const fn is_spawn_or_task_receipt(self) -> bool {
        matches!(self, Self::Outbound | Self::TaskLifecycle)
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
