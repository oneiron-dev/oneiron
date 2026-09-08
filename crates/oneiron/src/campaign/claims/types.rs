//! CRM-pack claim predicates, value types, token enums, and descriptor table.

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;

use super::codec::EVIDENCE_HASH_LEN;

/// Cohort membership for one PERSON in one CAMPAIGN.
pub const PREDICATE_CAMPAIGN_MEMBER: &str = "campaign.member";

/// ICP-scoped fit verdict for one PERSON. Restrictive: `not_fit` wins.
pub const PREDICATE_CRM_FIT: &str = "crm.fit";

/// Projector-written stage of one PERSON inside one campaign.
pub const PREDICATE_CRM_STAGE: &str = "crm.stage";

/// Campaign-independent do-not-contact standing state for one PERSON.
pub const PREDICATE_COMM_DO_NOT_CONTACT: &str = "comm.do_not_contact";

/// Projector-written bounce fact for one PERSON on one channel.
pub const PREDICATE_COMM_BOUNCE: &str = "comm.bounce";

/// Projector-written jurisdiction observation for one PERSON.
pub const PREDICATE_COMM_JURISDICTION: &str = "comm.jurisdiction";

/// Complete CRM-pack claim family minted at this layer.
///
/// Membership is an exact table, never a `campaign.` / `crm.` / `comm.` prefix
/// match: a prefix catch-all here would swallow SPINE-COMM's `comm.opt_out`
/// family and silently reinterpret unknown future predicates.
pub const CAMPAIGN_PACK_CLAIM_PREDICATES: [&str; 6] = [
    PREDICATE_CAMPAIGN_MEMBER,
    PREDICATE_CRM_FIT,
    PREDICATE_CRM_STAGE,
    PREDICATE_COMM_DO_NOT_CONTACT,
    PREDICATE_COMM_BOUNCE,
    PREDICATE_COMM_JURISDICTION,
];

/// `comm.do_not_contact` scope token matching every external-effect scope.
pub const DO_NOT_CONTACT_SCOPE_ALL: &str = "all";

/// Write class for claims an engine projector records rather than a human asserts.
const WRITE_CLASS_RECORDED: &str = "recorded";

/// Write class for claims a human ruling establishes.
const WRITE_CLASS_HUMAN_RULED: &str = "human_ruled";

/// Write class for ordinary claims.
const WRITE_CLASS_ORDINARY: &str = "ordinary";

/// Membership state of one PERSON in one campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CampaignMemberState {
    /// Live in the cohort.
    Enrolled,
    /// Paused until a wake condition fires. At least one option is present;
    /// both present means "at the deadline OR on a new trigger, whichever
    /// comes first".
    Paused {
        /// Wake at or after this instant.
        until: Option<u64>,
        /// Wake when a new trigger arrives.
        new_trigger: Option<bool>,
    },
    /// Left the cohort. Re-entry mints a new epoch, never a resurrection.
    Exited,
    /// Held out of the cohort by hygiene or compliance.
    Suppressed,
}

impl CampaignMemberState {
    /// Wire tag for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enrolled => "enrolled",
            Self::Paused { .. } => "paused",
            Self::Exited => "exited",
            Self::Suppressed => "suppressed",
        }
    }
}

/// One channel row of a `campaign.member` value.
///
/// Every row carries its own consent basis and its sticky sender: a cohort row
/// with no basis is an unauthorized send waiting to happen, and a row with no
/// sticky sender re-randomizes the sender identity on every touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignMemberChannel {
    /// Normalized channel token.
    pub channel: String,
    /// Evidence entity authorizing contact on this channel.
    pub basis_evidence: EntityId,
    /// Sticky sender identity for this channel.
    pub sender_ref: EntityId,
}

/// Provenance of a machine-derived membership row.
///
/// Absent for manual membership. ONE-1773 populates it and compare-and-sets the
/// monotonic per-`(query, entity)` `epoch` watermark inside its commit txn, so
/// a stale `Entered` plan replayed after exit/re-entry is REJECTED rather than
/// reported as already-applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignMemberDerivation {
    /// SAVED_QUERY this membership was derived from.
    pub source_query: EntityId,
    /// Hash of the evidence the derivation ran over.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
    /// Monotonic per-`(query, entity)` watermark.
    pub epoch: u64,
}

/// Value of a `campaign.member` claim. The claim is ON the PERSON; a CAMPAIGN
/// never stores or owns a member list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignMemberValue {
    /// The CAMPAIGN this membership is scoped to.
    pub campaign: EntityId,
    /// Membership state.
    pub state: CampaignMemberState,
    /// Non-empty set of channel rows, unique by normalized channel.
    pub channels: Vec<CampaignMemberChannel>,
    /// Derivation provenance; absent for manual membership.
    pub derivation: Option<CampaignMemberDerivation>,
}

/// ICP fit verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrmFitVerdict {
    /// The person fits the ICP.
    Fit,
    /// The person does not fit the ICP. Restrictive: this wins the fold.
    NotFit,
}

impl CrmFitVerdict {
    /// Wire token for this verdict.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fit => "fit",
            Self::NotFit => "not_fit",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fit" => Some(Self::Fit),
            "not_fit" => Some(Self::NotFit),
            _ => None,
        }
    }
}

/// Value of a `crm.fit` claim, scoped to exactly one ICP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrmFitValue {
    /// The ICP this verdict is scoped to.
    pub icp_scope: EntityId,
    /// Fit verdict.
    pub verdict: CrmFitVerdict,
}

/// Opaque stage token. The ladder's shape is ONE-1775's; this layer stores it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StageKey(pub String);

/// What established a stage: a machine derivation or an owner's attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBasis {
    /// Derived by the engine from evidence it can re-read.
    Machine,
    /// Attested by the owner.
    OwnerAttested,
}

impl EvidenceBasis {
    /// Wire token for this basis. Pinned equal to the serde representation by
    /// `crm_stage_wire_tokens_match_serde`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Machine => "machine",
            Self::OwnerAttested => "owner_attested",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "machine" => Some(Self::Machine),
            "owner_attested" => Some(Self::OwnerAttested),
            _ => None,
        }
    }
}

/// The closed set of evidence classes a stage write may cite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageEvidenceClass {
    /// A substantive counterparty reply.
    MeaningfulReply,
    /// A calendar event exists.
    CalendarEvent,
    /// A calendar event resolved to an outcome.
    CalendarEventOutcome,
    /// A document artifact plus the receipt proving it was sent.
    DocumentArtifactAndSendReceipt,
    /// The counterparty's own ledger.
    CounterpartyLedger,
    /// Progress on a task list.
    TaskListProgress,
    /// A recurring commitment.
    RecurringCommitment,
}

impl StageEvidenceClass {
    /// Every evidence class, in wire order.
    pub const ALL: [Self; 7] = [
        Self::MeaningfulReply,
        Self::CalendarEvent,
        Self::CalendarEventOutcome,
        Self::DocumentArtifactAndSendReceipt,
        Self::CounterpartyLedger,
        Self::TaskListProgress,
        Self::RecurringCommitment,
    ];

    /// Wire token for this class. Pinned equal to the serde representation by
    /// `crm_stage_wire_tokens_match_serde`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MeaningfulReply => "meaningful_reply",
            Self::CalendarEvent => "calendar_event",
            Self::CalendarEventOutcome => "calendar_event_outcome",
            Self::DocumentArtifactAndSendReceipt => "document_artifact_and_send_receipt",
            Self::CounterpartyLedger => "counterparty_ledger",
            Self::TaskListProgress => "task_list_progress",
            Self::RecurringCommitment => "recurring_commitment",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.as_str() == value)
    }
}

/// The one CA-owned `crm.stage` wire type.
///
/// ONE-1775 imports this rather than defining a second stage shape, and routes
/// its `apply_coded_reply` / `apply_external_stage_evidence` operations through
/// the projector write path instead of direct claim puts.
///
/// The struct itself is not serde-derived: [`EntityId`] has no serde impl and
/// `entity_id.rs` is a CA non-claim, so entity references cross the wire as
/// canonical hex through `decode_crm_stage_value`. The three token types it
/// composes ([`StageKey`], [`StageEvidenceClass`], [`EvidenceBasis`]) DO derive
/// serde, so a surface layer serializes them without re-spelling the tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrmStageValue {
    /// The campaign this stage is scoped to.
    pub campaign_ref: EntityId,
    /// Stage token.
    pub stage: StageKey,
    /// Which class of evidence established the stage.
    pub evidence_class: StageEvidenceClass,
    /// Non-empty evidence references. A stage with no evidence is a guess.
    pub evidence_refs: Vec<EntityId>,
    /// Machine derivation or owner attestation.
    pub basis: EvidenceBasis,
    /// When the stage was recorded.
    pub recorded_at: u64,
}

/// Value of a `comm.do_not_contact` claim.
///
/// Campaign-independent by construction: there is no campaign field, so a
/// suppression can never be scoped away by moving the person to another
/// campaign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommDoNotContactValue {
    /// Absent means every channel; present matches exactly after normalization.
    pub channel: Option<String>,
    /// [`DO_NOT_CONTACT_SCOPE_ALL`] means every external-effect scope; any
    /// other non-empty token matches exactly after normalization.
    pub scope: String,
}

/// Bounce severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BounceKind {
    /// Permanent failure.
    Hard,
    /// Transient failure.
    Soft,
}

impl BounceKind {
    /// Wire token for this bounce kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hard => "hard",
            Self::Soft => "soft",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "hard" => Some(Self::Hard),
            "soft" => Some(Self::Soft),
            _ => None,
        }
    }
}

/// Value of a `comm.bounce` claim. ONE-1776 owns webhook projection and the
/// bounce-to-suppression consequences; this layer validates and describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommBounceValue {
    /// Normalized channel the bounce occurred on.
    pub channel: String,
    /// Bounce severity.
    pub bounce: BounceKind,
    /// The sender identity that observed the bounce.
    pub sender_ref: EntityId,
    /// When the bounce occurred.
    pub occurred_at: u64,
}

/// Value of a `comm.jurisdiction` claim.
///
/// Confidence stays in [`ClaimBody::confidence`] and provenance stays in
/// [`ClaimBody::evidence`] — neither is duplicated into the value. ONE-1777
/// owns compliance-row evaluation over these facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommJurisdictionValue {
    /// Stable jurisdiction token.
    pub jurisdiction: String,
    /// When the jurisdiction was observed.
    pub observed_at: u64,
}

/// One pure-data descriptor row, mirroring ARCH-0057 §4 fields.
///
/// No descriptor runtime exists in engine Rust yet; this table is ready to
/// register when the registry lands and is authoritative documentation until
/// then. It has no persistence side effect and mints no entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimClassDescriptorRow {
    /// The predicate this row describes.
    pub predicate: &'static str,
    /// Exactly one of `"recorded"`, `"human_ruled"`, or `"ordinary"`.
    pub write_class: &'static str,
    /// Whether the class is read by an enforcement path.
    pub enforcement: bool,
    /// Whether the class is restrictive (the restrictive value wins the fold).
    pub restrictive: bool,
    /// Whether only an engine projector may write the class.
    pub projector_only: bool,
}

/// Descriptor rows for the whole CRM-pack family, one per predicate.
///
/// The rows are spelled out rather than derived: each family's axes differ, and
/// a derivation rule would hide the one row that matters — enforcement-gated,
/// restrictive `comm.do_not_contact`.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    vec![
        ClaimClassDescriptorRow {
            predicate: PREDICATE_CAMPAIGN_MEMBER,
            write_class: WRITE_CLASS_ORDINARY,
            enforcement: false,
            restrictive: true,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_CRM_FIT,
            write_class: WRITE_CLASS_HUMAN_RULED,
            enforcement: false,
            restrictive: true,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_CRM_STAGE,
            write_class: WRITE_CLASS_RECORDED,
            enforcement: false,
            restrictive: false,
            projector_only: true,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_DO_NOT_CONTACT,
            write_class: WRITE_CLASS_ORDINARY,
            enforcement: true,
            restrictive: true,
            projector_only: false,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_BOUNCE,
            write_class: WRITE_CLASS_RECORDED,
            enforcement: false,
            restrictive: false,
            projector_only: true,
        },
        ClaimClassDescriptorRow {
            predicate: PREDICATE_COMM_JURISDICTION,
            write_class: WRITE_CLASS_RECORDED,
            enforcement: true,
            restrictive: false,
            projector_only: true,
        },
    ]
}

/// Returns whether `predicate` belongs to the CRM-pack claim family.
///
/// Exact-table membership. `comm.do_not_contact.extra` and `comm.opt_out` both
/// answer `false`.
#[must_use]
pub fn is_campaign_pack_claim_predicate(predicate: &str) -> bool {
    CAMPAIGN_PACK_CLAIM_PREDICATES.contains(&predicate)
}
