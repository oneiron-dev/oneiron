//! The CRM pack's claim families (CA-01).
//!
//! Six exact predicates live here — `campaign.member`, `crm.fit`, `crm.stage`,
//! `comm.do_not_contact`, `comm.bounce`, and `comm.jurisdiction`. The last three
//! carry a `comm.` prefix but are CA-owned: `comm.rs` stays SPINE-COMM's
//! projector hot zone, so the authoritative comm-residence seam puts their
//! constants, codecs, and validators here and routes them through the
//! `claim.rs` family chain by EXACT predicate match, which is more specific
//! than the `comm.` prefix family. No entity type byte, `EdgeKind`, or
//! serialization profile is minted at this layer.
//!
//! Two halves, mirroring `calendar::claims`:
//!
//! * `validate_campaign_pack_claim_structure` is the byte-level half wired
//!   into the write-only validator chain in `crate::claim`. It sees a decoded
//!   `ClaimBody` and no storage, so it enforces subject *shape* plus exact
//!   value shapes.
//! * `matching_do_not_contact_in_txn` is the store-aware half: the
//!   enforcement read the external-effect gate folds into
//!   `counterparty_opted_out`.
//!
//! Descriptor-gap posture: ARCH-0057's descriptor runtime does not exist in
//! engine Rust. Rather than block on it, every family here ships an interim
//! exact-predicate validator plus a pure-data `claim_class_descriptors` table
//! that is ready to register when the registry lands. Building that registry is
//! explicitly NOT this ticket's job.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::vault::{edge_kind_prefix, parse_edge_record};

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

const KEY_CAMPAIGN: &str = "campaign";
const KEY_STATE: &str = "state";
const KEY_CHANNELS: &str = "channels";
const KEY_DERIVATION: &str = "derivation";
const KEY_KIND: &str = "kind";
const KEY_UNTIL: &str = "until";
const KEY_NEW_TRIGGER: &str = "new_trigger";
const KEY_CHANNEL: &str = "channel";
const KEY_BASIS_EVIDENCE: &str = "basis_evidence";
const KEY_SENDER_REF: &str = "sender_ref";
const KEY_SOURCE_QUERY: &str = "source_query";
const KEY_EVIDENCE_HASH: &str = "evidence_hash";
const KEY_EPOCH: &str = "epoch";
const KEY_ICP_SCOPE: &str = "icp_scope";
const KEY_VERDICT: &str = "verdict";
const KEY_CAMPAIGN_REF: &str = "campaign_ref";
const KEY_STAGE: &str = "stage";
const KEY_EVIDENCE_CLASS: &str = "evidence_class";
const KEY_EVIDENCE_REFS: &str = "evidence_refs";
const KEY_BASIS: &str = "basis";
const KEY_RECORDED_AT: &str = "recorded_at";
const KEY_SCOPE: &str = "scope";
const KEY_BOUNCE: &str = "bounce";
const KEY_OCCURRED_AT: &str = "occurred_at";
const KEY_JURISDICTION: &str = "jurisdiction";
const KEY_OBSERVED_AT: &str = "observed_at";

/// Upper bound for every bounded text field in these families.
const MAX_TEXT_BYTES: usize = 512;
/// Cohort derivation hashes are SHA-256 sized.
const EVIDENCE_HASH_LEN: usize = 32;

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

/// Validates one CRM-pack claim subject and value shape.
///
/// Structural only: campaign/ICP/evidence references are shape-checked, never
/// resolved. Every value is an exact key set with no extras and no back-compat
/// defaults — these families are greenfield, so there is no legacy shape to
/// admit.
pub(crate) fn validate_campaign_pack_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim(
            "campaign pack claim subject must be an entity",
        ));
    }
    match body.predicate.as_str() {
        PREDICATE_CAMPAIGN_MEMBER => decode_campaign_member_value(&body.value).map(|_| ()),
        PREDICATE_CRM_FIT => decode_crm_fit_value(&body.value).map(|_| ()),
        PREDICATE_CRM_STAGE => decode_crm_stage_value(&body.value).map(|_| ()),
        PREDICATE_COMM_DO_NOT_CONTACT => decode_do_not_contact_value(&body.value).map(|_| ()),
        PREDICATE_COMM_BOUNCE => decode_comm_bounce_value(&body.value).map(|_| ()),
        PREDICATE_COMM_JURISDICTION => {
            // Provenance for a projector-written external fact is not optional:
            // a jurisdiction with no evidence cannot be re-derived or disputed.
            if body.evidence.is_none() {
                return Err(invalid_claim("comm.jurisdiction requires claim evidence"));
            }
            decode_comm_jurisdiction_value(&body.value).map(|_| ())
        }
        _ => Err(invalid_claim("unknown campaign pack claim predicate")),
    }
}

/// Encodes a [`CampaignMemberValue`] into the exact wire map
/// `decode_campaign_member_value` accepts.
///
/// The CA-owned write half of the codec. ONE-1773's saved-query writer composes
/// its membership value from the typed struct through this door instead of
/// re-spelling this module's private MessagePack key literals — a second
/// spelling of one schema is drift with a delay fuse.
///
/// Deliberately infallible. Shape law (a paused row needs a wake condition, a
/// membership needs at least one channel) is enforced once, at the write door,
/// by `validate_campaign_pack_claim_structure`; re-checking it here would be
/// a second authority that can disagree with the first.
#[must_use]
pub fn encode_campaign_member_value(value: &CampaignMemberValue) -> Value {
    let mut entries = vec![
        (Value::from(KEY_CAMPAIGN), entity_ref_value(&value.campaign)),
        (Value::from(KEY_STATE), encode_member_state(value.state)),
        (
            Value::from(KEY_CHANNELS),
            Value::Array(value.channels.iter().map(encode_member_channel).collect()),
        ),
    ];
    if let Some(derivation) = &value.derivation {
        entries.push((
            Value::from(KEY_DERIVATION),
            encode_member_derivation(derivation),
        ));
    }
    Value::Map(entries)
}

fn encode_member_state(state: CampaignMemberState) -> Value {
    let mut entries = vec![(Value::from(KEY_KIND), Value::from(state.as_str()))];
    if let CampaignMemberState::Paused { until, new_trigger } = state {
        if let Some(until) = until {
            entries.push((Value::from(KEY_UNTIL), Value::from(until)));
        }
        if let Some(new_trigger) = new_trigger {
            entries.push((Value::from(KEY_NEW_TRIGGER), Value::from(new_trigger)));
        }
    }
    Value::Map(entries)
}

fn encode_member_channel(channel: &CampaignMemberChannel) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CHANNEL),
            Value::from(channel.channel.as_str()),
        ),
        (
            Value::from(KEY_BASIS_EVIDENCE),
            entity_ref_value(&channel.basis_evidence),
        ),
        (
            Value::from(KEY_SENDER_REF),
            entity_ref_value(&channel.sender_ref),
        ),
    ])
}

fn encode_member_derivation(derivation: &CampaignMemberDerivation) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SOURCE_QUERY),
            entity_ref_value(&derivation.source_query),
        ),
        (
            Value::from(KEY_EVIDENCE_HASH),
            Value::Binary(derivation.evidence_hash.to_vec()),
        ),
        (Value::from(KEY_EPOCH), Value::from(derivation.epoch)),
    ])
}

/// Decodes a `campaign.member` value.
pub(crate) fn decode_campaign_member_value(value: &Value) -> Result<CampaignMemberValue> {
    let entries = value_map(value)?;
    validate_keys(
        entries,
        &[KEY_CAMPAIGN, KEY_STATE, KEY_CHANNELS, KEY_DERIVATION],
        &[KEY_CAMPAIGN, KEY_STATE, KEY_CHANNELS],
    )?;
    Ok(CampaignMemberValue {
        campaign: required_entity_ref(entries, KEY_CAMPAIGN)?,
        state: decode_member_state(required_value(entries, KEY_STATE)?)?,
        channels: decode_member_channels(required_value(entries, KEY_CHANNELS)?)?,
        derivation: optional_value(entries, KEY_DERIVATION)?
            .map(decode_member_derivation)
            .transpose()?,
    })
}

fn decode_member_state(value: &Value) -> Result<CampaignMemberState> {
    let entries = value_map(value)?;
    match required_string(entries, KEY_KIND)? {
        "enrolled" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Enrolled)
        }
        "exited" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Exited)
        }
        "suppressed" => {
            validate_keys(entries, &[KEY_KIND], &[KEY_KIND])?;
            Ok(CampaignMemberState::Suppressed)
        }
        "paused" => {
            validate_keys(
                entries,
                &[KEY_KIND, KEY_UNTIL, KEY_NEW_TRIGGER],
                &[KEY_KIND],
            )?;
            let until = optional_value(entries, KEY_UNTIL)?
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| invalid_claim("campaign.member until must be an integer"))
                })
                .transpose()?;
            let new_trigger = optional_value(entries, KEY_NEW_TRIGGER)?
                .map(|value| {
                    value.as_bool().ok_or_else(|| {
                        invalid_claim("campaign.member new_trigger must be a boolean")
                    })
                })
                .transpose()?;
            // A paused row with neither wake condition never wakes: it is an
            // exit that still counts as membership.
            if until.is_none() && new_trigger.is_none() {
                return Err(invalid_claim(
                    "campaign.member paused requires until or new_trigger",
                ));
            }
            Ok(CampaignMemberState::Paused { until, new_trigger })
        }
        _ => Err(invalid_claim("campaign.member state kind is invalid")),
    }
}

fn decode_member_channels(value: &Value) -> Result<Vec<CampaignMemberChannel>> {
    let Value::Array(rows) = value else {
        return Err(invalid_claim("campaign.member channels must be an array"));
    };
    // A membership with no channel is a cohort row nothing can act on.
    if rows.is_empty() {
        return Err(invalid_claim("campaign.member channels must be non-empty"));
    }
    let mut channels = Vec::with_capacity(rows.len());
    for row in rows {
        let entries = value_map(row)?;
        let keys = [KEY_CHANNEL, KEY_BASIS_EVIDENCE, KEY_SENDER_REF];
        validate_keys(entries, &keys, &keys)?;
        let channel = required_string(entries, KEY_CHANNEL)?;
        validate_channel(channel)?;
        // The collection is a SET: two rows for one channel would make the
        // consent basis and the sticky sender ambiguous.
        if channels
            .iter()
            .any(|existing: &CampaignMemberChannel| existing.channel == channel)
        {
            return Err(invalid_claim("campaign.member channels must be unique"));
        }
        channels.push(CampaignMemberChannel {
            channel: channel.to_owned(),
            basis_evidence: required_entity_ref(entries, KEY_BASIS_EVIDENCE)?,
            sender_ref: required_entity_ref(entries, KEY_SENDER_REF)?,
        });
    }
    Ok(channels)
}

fn decode_member_derivation(value: &Value) -> Result<CampaignMemberDerivation> {
    let entries = value_map(value)?;
    let keys = [KEY_SOURCE_QUERY, KEY_EVIDENCE_HASH, KEY_EPOCH];
    validate_keys(entries, &keys, &keys)?;
    Ok(CampaignMemberDerivation {
        source_query: required_entity_ref(entries, KEY_SOURCE_QUERY)?,
        evidence_hash: required_evidence_hash(entries, KEY_EVIDENCE_HASH)?,
        epoch: required_u64(entries, KEY_EPOCH)?,
    })
}

/// Decodes a `crm.fit` value.
pub(crate) fn decode_crm_fit_value(value: &Value) -> Result<CrmFitValue> {
    let entries = value_map(value)?;
    let keys = [KEY_ICP_SCOPE, KEY_VERDICT];
    validate_keys(entries, &keys, &keys)?;
    Ok(CrmFitValue {
        icp_scope: required_entity_ref(entries, KEY_ICP_SCOPE)?,
        verdict: CrmFitVerdict::parse(required_string(entries, KEY_VERDICT)?)
            .ok_or_else(|| invalid_claim("crm.fit verdict is invalid"))?,
    })
}

/// Encodes a [`CrmStageValue`] into the exact wire map
/// `decode_crm_stage_value` accepts.
///
/// The CA-owned write half of the codec, and the only way ONE-1775's stage
/// projector builds a `crm.stage` value: `CrmStageValue` is not serde-derived
/// ([`EntityId`] has no serde impl), so without this door a stage writer would
/// have to re-spell this module's private key literals and the canonical-hex
/// entity-reference rule.
///
/// Deliberately infallible, for the same reason as
/// [`encode_campaign_member_value`]: the non-empty-evidence law lives at the
/// write door, not in a second place that can drift from it.
#[must_use]
pub fn encode_crm_stage_value(value: &CrmStageValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CAMPAIGN_REF),
            entity_ref_value(&value.campaign_ref),
        ),
        (Value::from(KEY_STAGE), Value::from(value.stage.0.as_str())),
        (
            Value::from(KEY_EVIDENCE_CLASS),
            Value::from(value.evidence_class.as_str()),
        ),
        (
            Value::from(KEY_EVIDENCE_REFS),
            Value::Array(value.evidence_refs.iter().map(entity_ref_value).collect()),
        ),
        (Value::from(KEY_BASIS), Value::from(value.basis.as_str())),
        (Value::from(KEY_RECORDED_AT), Value::from(value.recorded_at)),
    ])
}

/// Decodes a `crm.stage` value.
pub(crate) fn decode_crm_stage_value(value: &Value) -> Result<CrmStageValue> {
    let entries = value_map(value)?;
    let keys = [
        KEY_CAMPAIGN_REF,
        KEY_STAGE,
        KEY_EVIDENCE_CLASS,
        KEY_EVIDENCE_REFS,
        KEY_BASIS,
        KEY_RECORDED_AT,
    ];
    validate_keys(entries, &keys, &keys)?;
    let stage = required_string(entries, KEY_STAGE)?;
    validate_bounded_text(stage)?;
    let Value::Array(refs) = required_value(entries, KEY_EVIDENCE_REFS)? else {
        return Err(invalid_claim("crm.stage evidence_refs must be an array"));
    };
    // A stage transition with no evidence is a guess wearing a fact's clothes.
    if refs.is_empty() {
        return Err(invalid_claim("crm.stage evidence_refs must be non-empty"));
    }
    let evidence_refs = refs
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("crm.stage evidence ref must be a string"))
                .and_then(parse_entity_ref)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(CrmStageValue {
        campaign_ref: required_entity_ref(entries, KEY_CAMPAIGN_REF)?,
        stage: StageKey(stage.to_owned()),
        evidence_class: StageEvidenceClass::parse(required_string(entries, KEY_EVIDENCE_CLASS)?)
            .ok_or_else(|| invalid_claim("crm.stage evidence_class is invalid"))?,
        evidence_refs,
        basis: EvidenceBasis::parse(required_string(entries, KEY_BASIS)?)
            .ok_or_else(|| invalid_claim("crm.stage basis is invalid"))?,
        recorded_at: required_u64(entries, KEY_RECORDED_AT)?,
    })
}

/// Encodes a [`CommDoNotContactValue`] into the exact wire map
/// `decode_do_not_contact_value` accepts.
///
/// The CA-owned write half of the codec, for the same reason
/// [`encode_campaign_member_value`] exists: ONE-1776's suppression writer would
/// otherwise re-spell this module's private key literals, and a second spelling
/// of one schema is drift with a delay fuse. `channel: None` ELIDES the key
/// rather than writing a null — absent is what "every channel" means here.
///
/// Deliberately infallible: normalization law lives at the write door in
/// `validate_campaign_pack_claim_structure`, not in a second authority.
#[must_use]
pub fn encode_do_not_contact_value(value: &CommDoNotContactValue) -> Value {
    let mut entries = Vec::with_capacity(2);
    if let Some(channel) = &value.channel {
        entries.push((Value::from(KEY_CHANNEL), Value::from(channel.as_str())));
    }
    entries.push((Value::from(KEY_SCOPE), Value::from(value.scope.as_str())));
    Value::Map(entries)
}

/// Decodes a `comm.do_not_contact` value.
pub(crate) fn decode_do_not_contact_value(value: &Value) -> Result<CommDoNotContactValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_CHANNEL, KEY_SCOPE], &[KEY_SCOPE])?;
    let channel = optional_string(entries, KEY_CHANNEL)?;
    if let Some(channel) = channel {
        validate_channel(channel)?;
    }
    let scope = required_string(entries, KEY_SCOPE)?;
    validate_scope(scope)?;
    Ok(CommDoNotContactValue {
        channel: channel.map(str::to_owned),
        scope: scope.to_owned(),
    })
}

/// Encodes a [`CommBounceValue`] into the exact wire map
/// `decode_comm_bounce_value` accepts.
///
/// The CA-owned write half of the codec. ONE-1776's webhook projector composes
/// the bounce fact through this door instead of re-spelling the key literals.
#[must_use]
pub fn encode_comm_bounce_value(value: &CommBounceValue) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_CHANNEL),
            Value::from(value.channel.as_str()),
        ),
        (Value::from(KEY_BOUNCE), Value::from(value.bounce.as_str())),
        (
            Value::from(KEY_SENDER_REF),
            entity_ref_value(&value.sender_ref),
        ),
        (Value::from(KEY_OCCURRED_AT), Value::from(value.occurred_at)),
    ])
}

/// Decodes a `comm.bounce` value.
pub(crate) fn decode_comm_bounce_value(value: &Value) -> Result<CommBounceValue> {
    let entries = value_map(value)?;
    let keys = [KEY_CHANNEL, KEY_BOUNCE, KEY_SENDER_REF, KEY_OCCURRED_AT];
    validate_keys(entries, &keys, &keys)?;
    let channel = required_string(entries, KEY_CHANNEL)?;
    validate_channel(channel)?;
    Ok(CommBounceValue {
        channel: channel.to_owned(),
        bounce: BounceKind::parse(required_string(entries, KEY_BOUNCE)?)
            .ok_or_else(|| invalid_claim("comm.bounce bounce is invalid"))?,
        sender_ref: required_entity_ref(entries, KEY_SENDER_REF)?,
        occurred_at: required_u64(entries, KEY_OCCURRED_AT)?,
    })
}

/// Decodes a `comm.jurisdiction` value.
pub(crate) fn decode_comm_jurisdiction_value(value: &Value) -> Result<CommJurisdictionValue> {
    let entries = value_map(value)?;
    let keys = [KEY_JURISDICTION, KEY_OBSERVED_AT];
    validate_keys(entries, &keys, &keys)?;
    let jurisdiction = required_string(entries, KEY_JURISDICTION)?;
    validate_bounded_text(jurisdiction)?;
    Ok(CommJurisdictionValue {
        jurisdiction: jurisdiction.to_owned(),
        observed_at: required_u64(entries, KEY_OBSERVED_AT)?,
    })
}

/// Restrictive fold over one person's live `crm.fit` claims: `NotFit` wins.
///
/// `icp_scope` is a parameter rather than a caller-side filter so scope
/// isolation is a property of this chokepoint — a caller that hands over a
/// person's whole `crm.fit` set cannot accidentally let one ICP's rejection
/// contaminate another's verdict. Returns `None` when no claim is scoped here.
#[must_use]
pub fn resolve_crm_fit(icp_scope: &EntityId, claims: &[CrmFitValue]) -> Option<CrmFitVerdict> {
    claims
        .iter()
        .filter(|claim| claim.icp_scope == *icp_scope)
        .fold(None, |resolved, claim| match (resolved, claim.verdict) {
            (Some(CrmFitVerdict::NotFit), _) | (_, CrmFitVerdict::NotFit) => {
                Some(CrmFitVerdict::NotFit)
            }
            _ => Some(CrmFitVerdict::Fit),
        })
}

/// Compare-and-swaps the `crm.stage` head INSIDE the caller's write txn.
///
/// This is THE stage-transition door: it takes the caller's `wtxn` rather than
/// opening its own, so the projector that writes the replacement head and the
/// supersession of the prior head are ONE atomic unit. A self-transaction
/// variant would force a writer to put the new head in one txn and supersede in
/// another, and two projectors planning from the same head could then leave two
/// live heads behind — the exact torn state the head check exists to prevent.
///
/// `expected_current_head_id` is the compare half of the CAS:
///
/// * `Some(id)` — `id` must be the ONLY other live head for this
///   `(subject, campaign_ref)`, and both claims must agree on predicate, PERSON
///   subject, and campaign scope. It is then superseded.
/// * `None` — the FIRST stage head for this `(subject, campaign_ref)`. The
///   compare is against the ABSENCE of a head, so a head another writer already
///   landed loses instead of silently becoming a second live head. There is
///   nothing to supersede, so the call only validates.
///
/// Every rejection happens before the first write of this call, and a rejection
/// aborts the caller's whole txn — so the replacement head the caller wrote
/// rolls back with it.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] with a distinct static reason per rejection:
/// either id is not a live `crm.stage` claim, subject or campaign scope
/// disagree, the expected head is not the current one, or a `None` (first-head)
/// CAS found a head already live. Supersession errors propagate unchanged from
/// [`Vault::supersede_claim`].
pub fn supersede_crm_stage_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    new_claim_id: &EntityId,
    expected_current_head_id: Option<&EntityId>,
    now: u64,
) -> Result<()> {
    let (new_subject, new_value) = read_crm_stage_claim_in_txn(&vault.store, wtxn, new_claim_id)?;
    let Some(expected_current_head_id) = expected_current_head_id else {
        let heads = other_live_crm_stage_heads_in_txn(
            &vault.store,
            wtxn,
            new_subject,
            &new_value.campaign_ref,
            new_claim_id,
        )?;
        if !heads.is_empty() {
            return Err(invalid_claim("crm.stage first head is not the only head"));
        }
        return Ok(());
    };
    let (old_subject, old_value) =
        read_crm_stage_claim_in_txn(&vault.store, wtxn, expected_current_head_id)?;
    if new_subject != old_subject {
        return Err(invalid_claim("crm.stage supersession subject mismatch"));
    }
    if new_value.campaign_ref != old_value.campaign_ref {
        return Err(invalid_claim("crm.stage supersession campaign mismatch"));
    }
    let heads = other_live_crm_stage_heads_in_txn(
        &vault.store,
        wtxn,
        new_subject,
        &new_value.campaign_ref,
        new_claim_id,
    )?;
    if heads.as_slice() != [*expected_current_head_id] {
        return Err(invalid_claim("crm.stage expected head is not current"));
    }
    vault.supersede_claim_in_txn(wtxn, new_claim_id, expected_current_head_id, now)
}

/// Reads one live `crm.stage` claim, returning its subject and decoded value.
fn read_crm_stage_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<(EntityId, CrmStageValue)> {
    let body =
        claim_body_in_txn(store, txn, id)?.ok_or(invalid_claim("crm.stage claim is missing"))?;
    if body.predicate != PREDICATE_CRM_STAGE {
        return Err(invalid_claim("claim is not crm.stage"));
    }
    if body.lifecycle != ClaimLifecycleStatus::Active {
        return Err(invalid_claim("crm.stage claim is not live"));
    }
    let ClaimSubject::Entity(subject) = body.subject else {
        return Err(invalid_claim("crm.stage subject must be an entity"));
    };
    Ok((subject, decode_crm_stage_value(&body.value)?))
}

/// Live `crm.stage` claim ids on `subject` scoped to `campaign_ref`, excluding
/// `replacement` — the head the caller already wrote into this same txn, which
/// is never its own competition.
fn other_live_crm_stage_heads_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    campaign_ref: &EntityId,
    replacement: &EntityId,
) -> Result<Vec<EntityId>> {
    let mut heads = Vec::new();
    for id in subject_claim_ids_in_txn(store, txn, &subject)? {
        if id == *replacement {
            continue;
        }
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CRM_STAGE || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        if decode_crm_stage_value(&body.value)?.campaign_ref == *campaign_ref {
            heads.push(id);
        }
    }
    Ok(heads)
}

/// Returns whether `value` suppresses contact on `channel` within `scope`.
///
/// Matching is restrictive in both directions of uncertainty:
///
/// * a stored `channel` of `None` covers every channel;
/// * a stored `scope` of [`DO_NOT_CONTACT_SCOPE_ALL`] covers every scope;
/// * a caller that does not know the channel (`channel = None`) cannot prove
///   the suppression is irrelevant, so it matches.
///
/// Everything else compares exactly after normalization.
#[must_use]
pub fn do_not_contact_applies(
    value: &CommDoNotContactValue,
    channel: Option<&str>,
    scope: &str,
) -> bool {
    let channel_matches = match (value.channel.as_deref(), channel) {
        (None, _) | (Some(_), None) => true,
        (Some(stored), Some(queried)) => stored == normalize_token(queried),
    };
    let scope_matches =
        value.scope == DO_NOT_CONTACT_SCOPE_ALL || value.scope == normalize_token(scope);
    channel_matches && scope_matches
}

/// Whether `person_ref` carries a live `comm.do_not_contact` head matching
/// `(channel, scope)`.
///
/// A matching head applies at ANY approval state — including `Proposed` — and
/// regardless of staleness or validity window: this is the restrictive-wins
/// law, and a suppression that expires on its own is a suppression that leaks.
/// Only superseding or retracting the head (an authorized clear stamp) removes
/// it from the fold.
pub(crate) fn matching_do_not_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person_ref: EntityId,
    channel: Option<&str>,
    scope: &str,
) -> Result<bool> {
    for id in subject_claim_ids_in_txn(store, txn, &person_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_COMM_DO_NOT_CONTACT
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        if do_not_contact_applies(&decode_do_not_contact_value(&body.value)?, channel, scope) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The live `campaign.member` head on `person_ref` scoped to `campaign_ref`.
///
/// The membership counterpart of [`other_live_crm_stage_heads_in_txn`], and the
/// single door ONE-1776's suppression and sticky-sender writers read through:
/// both must supersede exactly the head they read, in the same txn, or leave two
/// live memberships behind.
///
/// Two live heads for one `(person, campaign)` is a TORN cohort, not a merge
/// problem — the two rows can disagree about state, channels, and derivation,
/// and picking one would silently discard the other's provenance. It is rejected
/// for the same reason `crm.stage` rejects a second head.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when more than one live head exists; storage and
/// decode errors propagate.
pub(crate) fn live_campaign_member_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    person_ref: EntityId,
    campaign_ref: EntityId,
) -> Result<Option<(EntityId, CampaignMemberValue)>> {
    let mut head = None;
    for id in subject_claim_ids_in_txn(store, txn, &person_ref)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = decode_campaign_member_value(&body.value)?;
        if value.campaign != campaign_ref {
            continue;
        }
        if head.is_some() {
            return Err(invalid_claim("campaign.member has more than one live head"));
        }
        head = Some((id, value));
    }
    Ok(head)
}

/// The live CRM-pack claim head on `subject` carrying exactly `predicate` and
/// `value`.
///
/// The replay door. Provider webhooks and unsubscribe callbacks redeliver, so a
/// writer that always appends would grow one suppression head per redelivery of
/// the same fact. Equality is on the ENCODED value, so it is the same identity
/// test the decoder enforces, not a hand-written field comparison that can drift
/// from the schema.
pub(crate) fn identical_live_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: EntityId,
    predicate: &str,
    value: &Value,
) -> Result<Option<EntityId>> {
    for id in subject_claim_ids_in_txn(store, txn, &subject)? {
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate == predicate
            && body.lifecycle == ClaimLifecycleStatus::Active
            && body.value == *value
        {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Resolves the PERSON a `comm.do_not_contact` claim would be written against
/// for the external-effect gate's `counterparty` string.
///
/// INTERIM and deliberately narrow. `ExternalEffectGateInput::counterparty` is
/// a bare address at HEAD and no existing engine call turns one into an
/// `EntityId`, so this reads SPINE-COMM's node-local party shortcut (whose
/// writer stays in `comm.rs` — CA never edits that file) and then re-validates
/// the hit against synced truth: the row must still be a PERSON carrying
/// exactly this `party_key`. A stale shortcut therefore resolves to NOTHING
/// rather than to the wrong person.
///
/// `Ok(None)` means the leg contributes nothing — it never clears an opt-out
/// another source established. ONE-1868 owns the complete resolution (all
/// contact records matched by `(party_ref, channel_class)`, index repair, and
/// the full-scan fallback) so no shipping path can answer a false "no".
fn resolve_do_not_contact_subject_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
) -> Result<Option<EntityId>> {
    let party_key = counterparty.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let Some(raw_id) = store
        .vault_meta
        .get(txn, &comm_party_index_key(party_key))?
    else {
        return Ok(None);
    };
    let Ok(bytes) = <[u8; crate::entity_id::ENTITY_ID_LEN]>::try_from(raw_id.as_ref()) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_bytes(bytes) else {
        return Ok(None);
    };
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Value::Map(entries) = body else {
        return Ok(None);
    };
    let carries_party_key = entries.iter().any(|(key, value)| {
        key.as_str() == Some(COMM_PARTY_KEY_FIELD) && value.as_str() == Some(party_key)
    });
    Ok(carries_party_key.then_some(id))
}

/// The external-effect gate's do-not-contact leg.
///
/// Called from `gate::hydrate_external_effect_contact` so every external effect
/// that names a counterparty folds `comm.do_not_contact` at ONE chokepoint. The
/// result is OR-ed into `counterparty_opted_out`: this leg can only ever ADD
/// suppression, never clear truth a COUNTERPARTY_CONTACT contact record supplied.
pub(crate) fn counterparty_do_not_contact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
    channel: Option<&str>,
    scope: &str,
) -> Result<bool> {
    match resolve_do_not_contact_subject_in_txn(store, txn, counterparty)? {
        Some(person_ref) => matching_do_not_contact_in_txn(store, txn, person_ref, channel, scope),
        None => Ok(false),
    }
}

/// Synced-truth field naming a comm-owned PERSON's party. Mirrors the private
/// `comm.rs` constant; CA reads it and never writes it.
const COMM_PARTY_KEY_FIELD: &str = "party_key";
/// Node-local party shortcut prefix owned by `comm.rs`. Read-only mirror.
const COMM_PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";

fn comm_party_index_key(party_key: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(party_key.as_bytes());
    let mut key = Vec::with_capacity(COMM_PARTY_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(COMM_PARTY_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

/// CLAIM ids attached to `subject` through inbound `claim_of` edges.
fn subject_claim_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Vec<EntityId>> {
    let prefix = edge_kind_prefix(subject, EdgeKind::ClaimOf);
    let mut ids = Vec::new();
    for entry in store.edges_in.prefix_iter(txn, &prefix)? {
        let (key, value) = entry?;
        ids.push(parse_edge_record(&key, &value)?.target);
    }
    Ok(ids)
}

/// Decodes the CLAIM body stored at `id`, or `None` when the row is absent or
/// is not a type-0 CLAIM.
fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("campaign pack claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("campaign pack claim value must be a map")),
    }
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("campaign pack value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("campaign pack value contains duplicate key"));
    }
    Ok(value)
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches.next();
    if matches.next().is_some() {
        return Err(invalid_claim("campaign pack value contains duplicate key"));
    }
    Ok(value)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    required_value(entries, key)?
        .as_str()
        .ok_or_else(|| invalid_claim("campaign pack value string invalid"))
}

fn optional_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_claim("campaign pack value string invalid"))
        })
        .transpose()
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("campaign pack value integer invalid"))
}

fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    parse_entity_ref(required_string(entries, key)?)
}

/// The write counterpart of [`parse_entity_ref`]: canonical hex, the one wire
/// form an identity has.
fn entity_ref_value(id: &EntityId) -> Value {
    Value::from(id.to_hex())
}

fn parse_entity_ref(hex: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(hex)
        .map_err(|_| invalid_claim("campaign pack entity reference invalid"))?;
    // Reject non-canonical spellings so one identity has one wire form.
    if id.to_hex() != hex {
        return Err(invalid_claim("campaign pack entity reference invalid"));
    }
    Ok(id)
}

fn required_evidence_hash(
    entries: &[(Value, Value)],
    key: &str,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let Value::Binary(bytes) = required_value(entries, key)? else {
        return Err(invalid_claim("campaign pack evidence_hash must be binary"));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_claim("campaign pack evidence_hash must be 32 bytes"))
}

/// Rejects extra keys, missing required keys, non-string keys, and duplicates.
///
/// `allowed` is the full key set; `required` is the subset that must be
/// present. These families are greenfield, so the two differ only where the
/// field is genuinely optional (`derivation`, paused wake fields, DNC channel).
fn validate_keys(entries: &[(Value, Value)], allowed: &[&str], required: &[&str]) -> Result<()> {
    if entries.len() > allowed.len() {
        return Err(invalid_claim("campaign pack value key set invalid"));
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !allowed.contains(&key)))
    {
        return Err(invalid_claim("campaign pack value key set invalid"));
    }
    for key in required {
        required_value(entries, key)?;
    }
    Ok(())
}

/// Bounded, non-empty, control-character-free text.
fn validate_bounded_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("campaign pack text field length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim(
            "campaign pack text field has control characters",
        ));
    }
    Ok(())
}

/// Channel tokens are stored already-normalized, mirroring the `comm.*`
/// `channel_class` rule. Normalizing at the write door is what lets matching
/// compare bytes instead of guessing at equivalence.
fn validate_channel(value: &str) -> Result<()> {
    validate_bounded_text(value)?;
    if value != normalize_token(value) {
        return Err(invalid_claim("campaign pack channel must be normalized"));
    }
    Ok(())
}

/// Scope tokens follow the channel rule; [`DO_NOT_CONTACT_SCOPE_ALL`] is just
/// the wildcard member of the same normalized space.
fn validate_scope(value: &str) -> Result<()> {
    validate_bounded_text(value)?;
    if value != normalize_token(value) {
        return Err(invalid_claim("campaign pack scope must be normalized"));
    }
    Ok(())
}

/// Normalizes a channel or scope token to the one spelling these families
/// store.
///
/// Exported so a CA writer normalizes through the SAME rule the validator
/// enforces. A writer that re-spelled `trim().to_ascii_lowercase()` locally
/// would keep working until this rule changed, and then write tokens the write
/// door rejects.
#[must_use]
pub fn normalize_campaign_pack_token(value: &str) -> String {
    normalize_token(value)
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests;
