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
    /// One override of an engine hold on a run (Fable 5.2 item 2, Engine
    /// call S65-B-R3): a generic Resume released a budget, fan-out, hook or
    /// annotation hold that its own signal had not released. It names the
    /// hold, the run, the actor and the time, written in the override's own
    /// transaction to its own store; the vault owner's override and the
    /// engine's internal resumes alike.
    RunHoldOverride,
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
            Self::RunHoldOverride => "run_hold_override",
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
            "run_hold_override" => Some(Self::RunHoldOverride),
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
