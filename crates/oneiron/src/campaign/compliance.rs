//! CA-06's compliance pack: versioned, vault-resident legal rule rows and the
//! dispatch gate that enforces them.
//!
//! Three properties decide this module's shape.
//!
//! * **Law is data.** The seeded rule rows live in `compliance/seed_v1.json`,
//!   not in jurisdiction-specific `if` statements. Rust parses, validates,
//!   selects, and applies rows; it never spells a country's rule. Adding
//!   Ireland, retuning the verification-age dial, or taking a counsel-reviewed
//!   correction is a data revision, not a code change. The two machine checks a
//!   conditional exemption can demand ([`ComplianceExemptionEvidence`]) are
//!   mechanical primitives; which jurisdiction demands which is a pack row.
//! * **Evidence is hydrated, never presence-checked.** The evaluator accepts
//!   only [`HydratedListProvenance`] / [`HydratedJpPublicationFacts`], both of
//!   which exist only after the referenced record was resolved from the vault,
//!   bound to this counterparty, and class-validated. A dangling reference is
//!   not weaker evidence, it is no evidence, and the strict path applies.
//! * **This is enforcement, not a new approval surface.** A blocking verdict
//!   maps to a hard gate deny in `gate.rs`. Nothing here asks a human to
//!   approve a compliant send, and an unknown jurisdiction is NOT an automatic
//!   deny — it routes to the pack's strictest seeded pole, where satisfying
//!   facts still allow.
//!
//! Storage mirrors `gate.rs`'s `PolicyPack`/`PolicyRule` carrier shape and
//! `connector_key.rs`'s propose-versus-stamp amendment posture. Neither is
//! reused: connector-charter storage stays connector-local, and this module
//! shares no storage or code with BK-06's `booking/anti_abuse.rs`, which
//! imitates the row/amendment SHAPE only. Convergence onto one rule-row
//! substrate is a later integrator's concern.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::campaign::claims::{
    PREDICATE_CAMPAIGN_MEMBER, PREDICATE_COMM_JURISDICTION, decode_comm_jurisdiction_value,
};
use crate::claim::{ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::gate::ExternalEffectGateInput;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::vault::{edge_kind_prefix, parse_edge_record};

/// Stable id of the compliance pack this module governs.
pub const CAMPAIGN_COMPLIANCE_PACK_ID: &str = "crm.compliance.v1";
/// `vault_meta` key holding the ACTIVE pack.
pub const CAMPAIGN_COMPLIANCE_META_KEY: &[u8] = b"campaign:compliance:active:v1";
/// `vault_meta` key holding the one staged proposal awaiting an owner stamp.
const CAMPAIGN_COMPLIANCE_PENDING_META_KEY: &[u8] = b"campaign:compliance:pending:v1";
/// `vault_meta` prefix of the durable activation-notice log, keyed by the
/// activated pack version so one version can never write two notices.
const CAMPAIGN_COMPLIANCE_NOTICE_META_PREFIX: &[u8] = b"campaign:compliance:notice:v1:";
/// The bootstrap seed. It is the active pack only while the vault holds none.
pub const CAMPAIGN_COMPLIANCE_SEED_JSON: &str = include_str!("compliance/seed_v1.json");

/// Predicate of the CA-owned dispatch-evidence claim, written on the PERSON.
///
/// It carries the recipient's legal form and the REFERENCES to the provenance
/// records below; it never carries the provenance itself, so the gate cannot be
/// satisfied by an assertion that names no record.
pub const PREDICATE_CRM_COMPLIANCE_EVIDENCE: &str = "crm.compliance.evidence";
/// Predicate of a list-provenance record. Its value states the provenance
/// class, which must equal the class the evidence claim claimed for it.
pub const PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE: &str = "crm.compliance.list_provenance";
/// Predicate of a publication-context record carrying the three Art. 3(1)(iv)
/// facts.
pub const PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION: &str = "crm.compliance.jp_publication";
/// Predicate of the sending identity's message-element configuration.
pub const PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS: &str = "crm.compliance.message_elements";

/// Jurisdiction token of the explicit unknown-jurisdiction disposition row.
const JURISDICTION_NONE: &str = "none";
/// Channel token matching every channel.
const CHANNEL_WILDCARD: &str = "*";
/// Domain tag separating this hash space from every other one in the engine.
const PROPOSAL_HASH_DOMAIN: &[u8] = b"oneiron.campaign.compliance.proposal.v1";
/// Confidence is stored as a fraction; the pack's floor is in thousandths.
const CONFIDENCE_MILLIS_SCALE: f32 = 1000.0;

// ---------------------------------------------------------------------------
// Pack data
// ---------------------------------------------------------------------------

/// The ARCH-0059 §8 `rule_kind` axis.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceRuleKind {
    /// What lawful basis the send needs, and whether a B2B exemption exists.
    ConsentClass,
    /// The sender's identity must be present and never concealed.
    SenderId,
    /// A postal address must appear in the message.
    PhysicalAddress,
    /// A working opt-out mechanism must appear in the message.
    OptoutMechanism,
    /// How fast an opt-out must be honored. A POST-SEND obligation: no
    /// dispatch-time fact can witness it, so it never blocks a dispatch.
    OptoutDeadline,
    /// The commercial nature of the message must be identifiable.
    ContentMarking,
    /// What evidence must be retained. A POST-SEND obligation; see
    /// [`ComplianceRuleKind::OptoutDeadline`].
    Records,
    /// How the address entered the list.
    SourceHygiene,
}

impl ComplianceRuleKind {
    /// Whether a dispatch-time fact can witness this row.
    ///
    /// Retention and opt-out deadlines are obligations that begin AFTER the
    /// send; blocking a dispatch on them would deny every send forever while
    /// enforcing nothing. They ship as data because they are real law the
    /// surface and suppression paths read.
    const fn is_dispatch_enforced(self) -> bool {
        !matches!(self, Self::OptoutDeadline | Self::Records)
    }
}

/// Whether a row's requirement admits a business-recipient exemption.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum B2bExemption {
    /// The exemption applies unconditionally.
    Yes,
    /// No exemption exists.
    No,
    /// The exemption exists but depends on evidence the pack names.
    Conditional,
}

/// The primary source a row was verified against.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComplianceSource {
    /// Human-readable citation, e.g. the article or regulation number.
    pub citation: String,
    /// Stable URL of the primary source.
    pub url: String,
}

/// One ARCH-0059 §8 rule row. Identity is `(jurisdiction, channel, rule_kind)`.
///
/// `jurisdiction` is hierarchical: `EU/DE` selects the German rows AND the EU
/// floor rows above them, which is how a directive floor composes with a
/// national pole without either being duplicated into the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ComplianceRuleRow {
    /// Hierarchical jurisdiction token, e.g. `UK`, `JP`, `EU`, `EU/DE`.
    pub jurisdiction: String,
    /// Normalized channel token, or `*` for every channel.
    pub channel: String,
    /// Which mechanical axis this row governs.
    pub rule_kind: ComplianceRuleKind,
    /// The requirement in the source's own terms. Read by humans and compared
    /// byte-wise by the amendment classifier; never parsed for meaning.
    pub requirement: String,
    /// Whether a business recipient is exempt.
    pub b2b_exemption: B2bExemption,
    /// Where the requirement was read from.
    pub source: ComplianceSource,
    /// When a human last verified the row against its source (Unix seconds).
    pub verified_at: u64,
    /// Row revision, advanced whenever the requirement changes.
    pub version: u32,
    /// What getting this wrong costs.
    pub penalty_note: String,
}

impl ComplianceRuleRow {
    fn key(&self) -> (&str, &str, ComplianceRuleKind) {
        (&self.jurisdiction, &self.channel, self.rule_kind)
    }

    fn semantics(&self) -> (&str, B2bExemption) {
        (&self.requirement, self.b2b_exemption)
    }
}

/// What to do when the dispatch carries no trusted jurisdiction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownJurisdictionDefault {
    /// Evaluate under the pack's strictest seeded pole. Never an automatic
    /// deny: facts that satisfy the pole still allow.
    StrictPole,
}

/// The machine check a conditional exemption demands.
///
/// Two mechanical primitives, not two jurisdictions. Which jurisdiction demands
/// which is [`CompliancePack::conditional_exemption_evidence`] — a data row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceExemptionEvidence {
    /// The recipient's legal form must be known.
    LegalForm,
    /// A publication-context record must prove all three of its facts.
    PublicationContext,
}

/// Binds one jurisdiction's conditional rows to the evidence they demand.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConditionalExemptionEvidence {
    /// The jurisdiction token this binding governs.
    pub jurisdiction: String,
    /// What a `conditional` row in that jurisdiction demands.
    pub evidence: ComplianceExemptionEvidence,
}

/// A versioned set of rule rows plus the pack-level dials that apply them.
///
/// Every dial exists so a policy decision stays DATA. Hard-coding the strict
/// pole, the confidence floor, the prohibited provenance classes, or the
/// conditional-evidence bindings would each re-introduce exactly the
/// jurisdiction-specific branch this module exists to avoid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompliancePack {
    /// Stable pack id; an amendment may never change it.
    pub pack_id: String,
    /// Monotonic pack revision. Every activation advances it.
    pub pack_version: u32,
    /// Lowest engine version that understands these rows.
    pub min_engine_version: String,
    /// How long a row's `verified_at` stays trustworthy. Exceeded ⇒ block.
    pub verified_at_max_age_secs: u64,
    /// Disposition for a dispatch with no trusted jurisdiction.
    pub unknown_jurisdiction_default: UnknownJurisdictionDefault,
    /// The jurisdiction the unknown disposition routes to.
    pub strict_pole_jurisdiction: String,
    /// Minimum jurisdiction-claim confidence, in thousandths, below which the
    /// observation is not trusted and the unknown disposition applies.
    pub jurisdiction_confidence_floor_millis: u16,
    /// List-provenance classes that are themselves a violation.
    pub prohibited_list_provenance_classes: Vec<String>,
    /// Which evidence each jurisdiction's conditional rows demand.
    pub conditional_exemption_evidence: Vec<ConditionalExemptionEvidence>,
    /// The pack's standing caveat. Carried, never suppressed.
    pub warning: String,
    /// The rows themselves.
    pub rows: Vec<ComplianceRuleRow>,
}

impl CompliancePack {
    fn exemption_evidence(&self, jurisdiction: &str) -> Option<ComplianceExemptionEvidence> {
        self.conditional_exemption_evidence
            .iter()
            .find(|binding| binding.jurisdiction == jurisdiction)
            .map(|binding| binding.evidence)
    }

    fn is_stale(&self, row: &ComplianceRuleRow, now_utc: u64) -> bool {
        now_utc
            > row
                .verified_at
                .saturating_add(self.verified_at_max_age_secs)
    }
}

// ---------------------------------------------------------------------------
// Hydrated dispatch facts
// ---------------------------------------------------------------------------

/// A list-provenance record that RESOLVED and matched its claimed class.
///
/// Constructed only by [`hydrate_dispatch_compliance_facts`]. There is no
/// public constructor by design: the type's existence IS the evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HydratedListProvenance {
    /// The provenance record that was resolved.
    pub record_ref: EntityId,
    /// The class the evidence claimed and the record confirmed.
    pub claimed_class: String,
}

/// A publication-context record that RESOLVED, carrying its three facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HydratedJpPublicationFacts {
    /// The publication record that was resolved.
    pub record_ref: EntityId,
    /// The address was published by the recipient.
    pub published_by_recipient: bool,
    /// It was published in the course of business.
    pub in_course_of_business: bool,
    /// No statement refusing marketing was attached to it.
    pub no_marketing_statement_attached: bool,
}

impl HydratedJpPublicationFacts {
    /// All three Art. 3(1)(iv) facts hold.
    const fn exemption_holds(&self) -> bool {
        self.published_by_recipient
            && self.in_course_of_business
            && self.no_marketing_statement_attached
    }
}

/// Everything the evaluator is allowed to see, all of it already resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchComplianceFacts {
    /// The PERSON this dispatch addresses.
    pub counterparty: EntityId,
    /// The observed jurisdiction token, absent when none was recorded.
    pub jurisdiction: Option<String>,
    /// Confidence of that observation, in thousandths.
    pub jurisdiction_confidence_millis: Option<u16>,
    /// Normalized dispatch channel.
    pub channel: String,
    /// The recipient's legal form, absent when unknown.
    pub legal_form: Option<String>,
    /// Resolved list provenance, absent when unresolved or class-mismatched.
    pub list_provenance: Option<HydratedListProvenance>,
    /// Resolved publication context, absent when unresolved.
    pub jp_publication: Option<HydratedJpPublicationFacts>,
    /// The message carries an unconcealed sender identity.
    pub sender_identity_present: bool,
    /// The message carries a postal address.
    pub physical_address_present: bool,
    /// The message carries a working opt-out mechanism.
    pub optout_mechanism_present: bool,
    /// The message is identifiable as commercial.
    pub commercial_marking_present: bool,
    /// The engine clock this evaluation runs against.
    pub now_utc: u64,
}

/// Why a dispatch was blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplianceBlockReason {
    /// A conditional exemption needs the recipient's legal form.
    UnknownLegalForm,
    /// A source-hygiene row needs resolved, class-matched list provenance.
    UnknownListProvenance,
    /// A conditional exemption needs a resolved publication-context record.
    MissingPublicationContext,
    /// A mandatory message element is absent.
    MissingRequiredMessageElement,
    /// The governing row is older than the pack's verification-age dial.
    StaleRule,
    /// The row is violated on its own terms, or the pack cannot apply it.
    RuleViolation,
}

impl ComplianceBlockReason {
    /// The receipt reason the gate records alongside the deny.
    ///
    /// `store.rs` owns a CLOSED receipt-reason vocabulary and admits only the
    /// `counterparty_` / `connector_key_` / `effector_budget_` / `charter_`
    /// families. These walls are counterparty-scoped legal facts — what may
    /// lawfully be sent to THIS recipient — so they ride the `counterparty_`
    /// family rather than minting a fifth one in a file this lane does not own.
    #[must_use]
    pub const fn receipt_reason(self) -> &'static str {
        match self {
            Self::UnknownLegalForm => "counterparty_compliance_unknown_legal_form",
            Self::UnknownListProvenance => "counterparty_compliance_unknown_list_provenance",
            Self::MissingPublicationContext => {
                "counterparty_compliance_missing_publication_context"
            }
            Self::MissingRequiredMessageElement => {
                "counterparty_compliance_missing_message_element"
            }
            Self::StaleRule => "counterparty_compliance_stale_rule",
            Self::RuleViolation => "counterparty_compliance_rule_violation",
        }
    }
}

/// The evaluator's answer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceVerdict {
    /// No matching row is violated. The dispatch proceeds to the next gate.
    Allow,
    /// A matching row blocks the dispatch.
    Block {
        /// Which wall was hit.
        reason: ComplianceBlockReason,
        /// The governing jurisdiction, when a row named one.
        jurisdiction: Option<String>,
        /// The governing row kind, when a row named one.
        rule_kind: Option<ComplianceRuleKind>,
    },
}

fn block(reason: ComplianceBlockReason, row: &ComplianceRuleRow) -> ComplianceVerdict {
    ComplianceVerdict::Block {
        reason,
        jurisdiction: Some(row.jurisdiction.clone()),
        rule_kind: Some(row.rule_kind),
    }
}

// ---------------------------------------------------------------------------
// Pack loading and validation
// ---------------------------------------------------------------------------

/// Parses and validates the embedded bootstrap seed.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the shipped JSON is unparseable, and the
/// [`Error::InvalidConfig`] shape errors of [`validate_compliance_pack`]
/// otherwise. Both are build-time defects, not runtime conditions.
pub fn embedded_seed_pack() -> Result<CompliancePack> {
    let pack: CompliancePack =
        serde_json::from_str(CAMPAIGN_COMPLIANCE_SEED_JSON).map_err(|_| {
            Error::InvariantViolation("campaign compliance seed pack is not valid JSON")
        })?;
    validate_compliance_pack(&pack)?;
    Ok(pack)
}

/// Rejects a pack that cannot be applied deterministically.
///
/// Runs before EVERY activation, seed or amendment, so a pack that would
/// evaluate ambiguously never becomes active in the first place.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the first defect found.
pub fn validate_compliance_pack(pack: &CompliancePack) -> Result<()> {
    if pack.pack_id.trim().is_empty() || pack.warning.trim().is_empty() || pack.rows.is_empty() {
        return Err(invalid_pack(
            "pack id, warning, and rows must all be present",
        ));
    }
    if pack.strict_pole_jurisdiction.trim().is_empty()
        || pack.strict_pole_jurisdiction == JURISDICTION_NONE
    {
        return Err(invalid_pack("strict pole must name a seeded jurisdiction"));
    }
    let mut keys: Vec<(&str, &str, ComplianceRuleKind)> = Vec::with_capacity(pack.rows.len());
    for row in &pack.rows {
        validate_compliance_row(row)?;
        keys.push(row.key());
    }
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid_pack(
            "duplicate (jurisdiction, channel, rule_kind) row key",
        ));
    }
    validate_pack_coverage(pack)
}

fn validate_compliance_row(row: &ComplianceRuleRow) -> Result<()> {
    let blank = row.jurisdiction.trim().is_empty()
        || row.channel.trim().is_empty()
        || row.requirement.trim().is_empty()
        || row.penalty_note.trim().is_empty()
        || row.source.citation.trim().is_empty()
        || row.source.url.trim().is_empty();
    if blank {
        return Err(invalid_pack("rule row has a blank required field"));
    }
    if row.verified_at == 0 || row.version == 0 {
        return Err(invalid_pack("rule row needs a verified_at and a version"));
    }
    Ok(())
}

/// Every disposition the evaluator relies on must be seeded.
fn validate_pack_coverage(pack: &CompliancePack) -> Result<()> {
    if !pack
        .rows
        .iter()
        .any(|row| row.jurisdiction == JURISDICTION_NONE)
    {
        return Err(invalid_pack(
            "pack needs an explicit unknown-jurisdiction disposition row",
        ));
    }
    if !pack
        .rows
        .iter()
        .any(|row| row.jurisdiction == pack.strict_pole_jurisdiction)
    {
        return Err(invalid_pack("strict pole has no rows"));
    }
    let unbound = pack.rows.iter().find(|row| {
        row.b2b_exemption == B2bExemption::Conditional
            && row.rule_kind == ComplianceRuleKind::ConsentClass
            && row.jurisdiction != JURISDICTION_NONE
            && pack.exemption_evidence(&row.jurisdiction).is_none()
    });
    if unbound.is_some() {
        return Err(invalid_pack(
            "conditional consent-class row has no declared exemption evidence",
        ));
    }
    Ok(())
}

fn invalid_pack(message: &str) -> Error {
    Error::InvalidConfig(format!("campaign compliance pack: {message}"))
}

/// The ACTIVE pack, or the embedded seed when the vault holds none.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] when the stored row cannot be
/// decoded.
pub fn load_active_compliance_pack(vault: &Vault) -> Result<CompliancePack> {
    let rtxn = vault.store.env.read_txn()?;
    active_compliance_pack_in_txn(&vault.store, &rtxn)
}

pub(crate) fn active_compliance_pack_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<CompliancePack> {
    match store.vault_meta.get(txn, CAMPAIGN_COMPLIANCE_META_KEY)? {
        Some(raw) => decode_pack(&raw, "campaign compliance active pack"),
        None => embedded_seed_pack(),
    }
}

/// The ONLY writer of the active pack, and deliberately private: the public
/// path is the versioned amendment transaction, which cannot be bypassed.
fn store_active_compliance_pack(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pack: &CompliancePack,
) -> Result<()> {
    validate_compliance_pack(pack)?;
    let encoded = encode_pack(pack)?;
    store
        .vault_meta
        .put(wtxn, CAMPAIGN_COMPLIANCE_META_KEY, &encoded)?;
    Ok(())
}

fn encode_pack(pack: &CompliancePack) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(pack)
        .map_err(|_| Error::InvariantViolation("campaign compliance pack encode failed"))
}

fn decode_pack(raw: &[u8], label: &'static str) -> Result<CompliancePack> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex(label))
}

// ---------------------------------------------------------------------------
// Row selection and evaluation
// ---------------------------------------------------------------------------

/// Applies `pack` to `facts`. Pure: same inputs, same verdict, no storage.
///
/// Selection is exact jurisdiction first, then the configured strict pole. A
/// hierarchical token composes with its ancestors (`EU/DE` selects the German
/// rows AND the EU floor), every matching row is evaluated, and the strictest
/// outcome wins — a permissive row can never erase a stricter one because no
/// row can produce an allow, only the absence of a block.
#[must_use]
pub fn evaluate_dispatch_compliance(
    pack: &CompliancePack,
    facts: &DispatchComplianceFacts,
) -> ComplianceVerdict {
    let jurisdiction = effective_jurisdiction(pack, facts);
    let rows = matching_rows(pack, &jurisdiction, &facts.channel);
    if let Some(stale) = rows.iter().find(|row| pack.is_stale(row, facts.now_utc)) {
        return block(ComplianceBlockReason::StaleRule, stale);
    }
    if let Some(uncovered) = consent_class_coverage_gap(&rows) {
        return uncovered;
    }
    rows.iter()
        .find_map(|row| evaluate_row(pack, row, facts))
        .unwrap_or(ComplianceVerdict::Allow)
}

/// The jurisdiction the rows are selected for.
///
/// An absent token, a token below the pack's confidence floor, and a token the
/// pack does not seed all take the same road: the unknown disposition, which
/// routes to the strict pole rather than denying.
fn effective_jurisdiction(pack: &CompliancePack, facts: &DispatchComplianceFacts) -> String {
    trusted_jurisdiction(pack, facts).unwrap_or_else(|| match pack.unknown_jurisdiction_default {
        UnknownJurisdictionDefault::StrictPole => pack.strict_pole_jurisdiction.clone(),
    })
}

fn trusted_jurisdiction(pack: &CompliancePack, facts: &DispatchComplianceFacts) -> Option<String> {
    let observed = normalize_jurisdiction(facts.jurisdiction.as_deref()?);
    if observed.is_empty() || observed.eq_ignore_ascii_case(JURISDICTION_NONE) {
        return None;
    }
    if facts
        .jurisdiction_confidence_millis
        .is_some_and(|millis| millis < pack.jurisdiction_confidence_floor_millis)
    {
        return None;
    }
    pack.rows
        .iter()
        .any(|row| row.jurisdiction == observed)
        .then_some(observed)
}

/// Rows governing `(jurisdiction chain, channel)`, in a deterministic order.
///
/// The unknown-jurisdiction row is excluded on purpose: it states a
/// disposition, not a requirement, and [`effective_jurisdiction`] has already
/// applied it.
fn matching_rows<'a>(
    pack: &'a CompliancePack,
    jurisdiction: &str,
    channel: &str,
) -> Vec<&'a ComplianceRuleRow> {
    let chain = jurisdiction_chain(jurisdiction);
    let channel = normalize_token(channel);
    let mut rows: Vec<&ComplianceRuleRow> = pack
        .rows
        .iter()
        .filter(|row| row.jurisdiction != JURISDICTION_NONE)
        .filter(|row| chain.contains(&row.jurisdiction))
        .filter(|row| row.channel == CHANNEL_WILDCARD || row.channel == channel)
        .collect();
    rows.sort_unstable_by(|left, right| left.key().cmp(&right.key()));
    rows
}

/// `EU/DE` ⇒ `["EU", "EU/DE"]`; `UK` ⇒ `["UK"]`.
fn jurisdiction_chain(jurisdiction: &str) -> Vec<String> {
    let mut chain = Vec::new();
    let mut token = String::new();
    for segment in jurisdiction.split('/') {
        if !token.is_empty() {
            token.push('/');
        }
        token.push_str(segment);
        chain.push(token.clone());
    }
    chain
}

/// A jurisdiction that seeds no consent-class row for this channel cannot be
/// evaluated, so it fails closed rather than allowing on an empty axis.
///
/// The no-rows-at-all case fails closed for the same reason and reports no
/// governing row, because there is none: a pack that governs nothing here
/// cannot vouch for the send.
fn consent_class_coverage_gap(rows: &[&ComplianceRuleRow]) -> Option<ComplianceVerdict> {
    if rows
        .iter()
        .any(|row| row.rule_kind == ComplianceRuleKind::ConsentClass)
    {
        return None;
    }
    Some(rows.first().map_or(
        ComplianceVerdict::Block {
            reason: ComplianceBlockReason::RuleViolation,
            jurisdiction: None,
            rule_kind: None,
        },
        |anchor| block(ComplianceBlockReason::RuleViolation, anchor),
    ))
}

fn evaluate_row(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    if !row.rule_kind.is_dispatch_enforced() {
        return None;
    }
    let element_present = match row.rule_kind {
        ComplianceRuleKind::SenderId => facts.sender_identity_present,
        ComplianceRuleKind::PhysicalAddress => facts.physical_address_present,
        ComplianceRuleKind::OptoutMechanism => facts.optout_mechanism_present,
        ComplianceRuleKind::ContentMarking => facts.commercial_marking_present,
        ComplianceRuleKind::SourceHygiene => return evaluate_source_hygiene(pack, row, facts),
        ComplianceRuleKind::ConsentClass => return evaluate_consent_class(pack, row, facts),
        ComplianceRuleKind::OptoutDeadline | ComplianceRuleKind::Records => return None,
    };
    (!element_present).then(|| block(ComplianceBlockReason::MissingRequiredMessageElement, row))
}

fn evaluate_consent_class(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    if row.b2b_exemption != B2bExemption::Conditional {
        return None;
    }
    let Some(evidence) = pack.exemption_evidence(&row.jurisdiction) else {
        // A stored pack that skipped validation cannot apply its own
        // conditional row. Fail closed rather than guess which branch was meant.
        return Some(block(ComplianceBlockReason::RuleViolation, row));
    };
    match evidence {
        ComplianceExemptionEvidence::LegalForm => facts
            .legal_form
            .is_none()
            .then(|| block(ComplianceBlockReason::UnknownLegalForm, row)),
        ComplianceExemptionEvidence::PublicationContext => (!facts
            .jp_publication
            .is_some_and(|publication| publication.exemption_holds()))
        .then(|| block(ComplianceBlockReason::MissingPublicationContext, row)),
    }
}

fn evaluate_source_hygiene(
    pack: &CompliancePack,
    row: &ComplianceRuleRow,
    facts: &DispatchComplianceFacts,
) -> Option<ComplianceVerdict> {
    let Some(provenance) = facts.list_provenance.as_ref() else {
        return Some(block(ComplianceBlockReason::UnknownListProvenance, row));
    };
    pack.prohibited_list_provenance_classes
        .contains(&provenance.claimed_class)
        .then(|| block(ComplianceBlockReason::RuleViolation, row))
}

fn normalize_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

/// Jurisdiction tokens are case-folded to upper for the country segments while
/// keeping the `/` hierarchy, so `eu/de` and `EU/DE` name the same rows.
fn normalize_jurisdiction(value: &str) -> String {
    value.trim().to_ascii_uppercase()
}

// ---------------------------------------------------------------------------
// Hydration
// ---------------------------------------------------------------------------

/// The external-effect gate's campaign-compliance leg.
///
/// Returns `None` when compliance does not govern the effect at all: no
/// counterparty, no comm-owned PERSON behind the address, or a PERSON carrying
/// no campaign membership. Membership IS the campaign scope — the CRM pack's
/// ratified law is that a cohort is claims — so a booking confirmation or a
/// support reply never enters this stage.
pub(crate) fn campaign_compliance_gate(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    now_utc: u64,
) -> Result<Option<ComplianceVerdict>> {
    let Some(counterparty) = effect.counterparty.as_deref() else {
        return Ok(None);
    };
    let Some(subject) = resolve_comm_party_in_txn(store, txn, counterparty)? else {
        return Ok(None);
    };
    if !has_active_claim_in_txn(store, txn, &subject, PREDICATE_CAMPAIGN_MEMBER)? {
        return Ok(None);
    }
    let pack = active_compliance_pack_in_txn(store, txn)?;
    let facts = hydrate_dispatch_compliance_facts(store, txn, effect, subject, now_utc)?;
    Ok(Some(evaluate_dispatch_compliance(&pack, &facts)))
}

/// Resolves every fact the evaluator is allowed to see.
///
/// Each evidence reference is RESOLVED from the vault, bound to this
/// counterparty, and class-validated here. A reference that fails any of those
/// yields `None`, so the evaluator sees "no evidence" rather than "an assertion
/// that a record exists" — presence of a ref is never sufficient.
pub(crate) fn hydrate_dispatch_compliance_facts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
    counterparty: EntityId,
    now_utc: u64,
) -> Result<DispatchComplianceFacts> {
    let observation = jurisdiction_observation_in_txn(store, txn, &counterparty)?;
    let evidence = dispatch_evidence_in_txn(store, txn, &counterparty)?;
    let elements = message_elements_in_txn(store, txn, effect.channel_identity_ref)?;
    Ok(DispatchComplianceFacts {
        counterparty,
        jurisdiction: observation.as_ref().map(|(token, _)| token.clone()),
        jurisdiction_confidence_millis: observation.and_then(|(_, confidence)| confidence),
        channel: normalize_token(&effect.channel),
        legal_form: evidence.legal_form,
        list_provenance: evidence.list_provenance,
        jp_publication: evidence.jp_publication,
        // A send with no bound sending identity has no identity to disclose,
        // whatever a configuration row claims.
        sender_identity_present: elements.sender_identity && effect.channel_identity_ref.is_some(),
        physical_address_present: elements.physical_address,
        optout_mechanism_present: elements.optout_mechanism,
        commercial_marking_present: elements.commercial_marking,
        now_utc,
    })
}

/// The newest ACTIVE `comm.jurisdiction` observation, with its confidence.
///
/// Two live heads at the same `observed_at` are a real possibility (an
/// offline-minted twin, a re-import), and edge-iteration order is not a tie
/// break a gate may depend on — so ties resolve on the token itself. Same
/// vault, same answer, every run.
fn jurisdiction_observation_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<Option<(String, Option<u16>)>> {
    let mut observations = Vec::new();
    for body in active_claim_bodies_in_txn(store, txn, subject, PREDICATE_COMM_JURISDICTION)? {
        let value = decode_comm_jurisdiction_value(&body.value)?;
        observations.push((
            value.observed_at,
            normalize_jurisdiction(&value.jurisdiction),
            confidence_millis(body.confidence),
        ));
    }
    observations
        .sort_unstable_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    Ok(observations
        .into_iter()
        .next()
        .map(|(_, token, confidence)| (token, confidence)))
}

/// `ClaimBody::confidence` is a fraction in `[0, 1]`; the pack's floor is in
/// thousandths. A non-finite or out-of-range value is not a confidence.
fn confidence_millis(confidence: f32) -> Option<u16> {
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return None;
    }
    Some((confidence * CONFIDENCE_MILLIS_SCALE).round() as u16)
}

#[derive(Debug, Default)]
struct DispatchEvidence {
    legal_form: Option<String>,
    list_provenance: Option<HydratedListProvenance>,
    jp_publication: Option<HydratedJpPublicationFacts>,
}

fn dispatch_evidence_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
) -> Result<DispatchEvidence> {
    let Some(body) =
        active_claim_bodies_in_txn(store, txn, subject, PREDICATE_CRM_COMPLIANCE_EVIDENCE)?
            .into_iter()
            .next()
    else {
        return Ok(DispatchEvidence::default());
    };
    let entries = map_entries(&body.value);
    Ok(DispatchEvidence {
        legal_form: nested_text(entries, "legal_form"),
        list_provenance: hydrate_list_provenance(store, txn, subject, entries)?,
        jp_publication: hydrate_jp_publication(store, txn, subject, entries)?,
    })
}

/// Resolves the list-provenance reference and confirms its class.
///
/// Three ways this yields `None`, and all three are the same answer to the
/// evaluator: the reference is absent, it resolves to nothing or to a record of
/// another kind, or the record's own class contradicts the claimed one.
fn hydrate_list_provenance(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    entries: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<HydratedListProvenance>> {
    let Some(nested) = nested_map(entries, "list_provenance") else {
        return Ok(None);
    };
    let (Some(record_ref), Some(claimed_class)) = (
        nested_entity_ref(nested, "ref"),
        nested_text(nested, "class"),
    ) else {
        return Ok(None);
    };
    let Some(record) = evidence_record_in_txn(
        store,
        txn,
        subject,
        &record_ref,
        PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
    )?
    else {
        return Ok(None);
    };
    let stored_class = nested_text(map_entries(&record.value), "class");
    Ok(
        (stored_class.as_ref() == Some(&claimed_class)).then_some(HydratedListProvenance {
            record_ref,
            claimed_class,
        }),
    )
}

fn hydrate_jp_publication(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    entries: &[(rmpv::Value, rmpv::Value)],
) -> Result<Option<HydratedJpPublicationFacts>> {
    let Some(record_ref) =
        nested_map(entries, "jp_publication").and_then(|nested| nested_entity_ref(nested, "ref"))
    else {
        return Ok(None);
    };
    let Some(record) = evidence_record_in_txn(
        store,
        txn,
        subject,
        &record_ref,
        PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
    )?
    else {
        return Ok(None);
    };
    let facts = map_entries(&record.value);
    Ok(Some(HydratedJpPublicationFacts {
        record_ref,
        published_by_recipient: nested_flag(facts, "published_by_recipient"),
        in_course_of_business: nested_flag(facts, "in_course_of_business"),
        no_marketing_statement_attached: nested_flag(facts, "no_marketing_statement_attached"),
    }))
}

/// A cited record counts only when it is an ACTIVE CLAIM of the expected
/// predicate whose subject is THIS counterparty. The subject binding is what
/// stops one contact's evidence from authorizing another's dispatch.
fn evidence_record_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    record_ref: &EntityId,
    predicate: &str,
) -> Result<Option<ClaimBody>> {
    let Some(body) = claim_body_in_txn(store, txn, record_ref)? else {
        return Ok(None);
    };
    let bound = body.predicate == predicate
        && body.lifecycle == ClaimLifecycleStatus::Active
        && body.subject == ClaimSubject::Entity(*subject);
    Ok(bound.then_some(body))
}

#[derive(Debug, Default)]
struct MessageElements {
    sender_identity: bool,
    physical_address: bool,
    optout_mechanism: bool,
    commercial_marking: bool,
}

/// Message elements are a property of the SENDING identity's template, so they
/// are read from the channel identity the effect is bound to. No identity, or
/// no configuration row, means no element is established.
fn message_elements_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    channel_identity_ref: Option<EntityId>,
) -> Result<MessageElements> {
    let Some(identity) = channel_identity_ref else {
        return Ok(MessageElements::default());
    };
    let Some(body) = active_claim_bodies_in_txn(
        store,
        txn,
        &identity,
        PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
    )?
    .into_iter()
    .next() else {
        return Ok(MessageElements::default());
    };
    let entries = map_entries(&body.value);
    Ok(MessageElements {
        sender_identity: nested_flag(entries, "sender_identity"),
        physical_address: nested_flag(entries, "physical_address"),
        optout_mechanism: nested_flag(entries, "optout_mechanism"),
        commercial_marking: nested_flag(entries, "commercial_marking"),
    })
}

// ---------------------------------------------------------------------------
// Claim substrate reads
// ---------------------------------------------------------------------------

fn has_active_claim_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<bool> {
    Ok(!active_claim_bodies_in_txn(store, txn, subject, predicate)?.is_empty())
}

/// Live claim heads of `predicate` on `subject`.
///
/// Lifecycle is the filter; approval status deliberately is NOT. Requiring an
/// APPROVED evidence claim would put a human approval in front of every
/// compliant send — precisely the blanket review step this gate exists to
/// avoid — and it would do so on the permissive side only, which is where a
/// stall is most expensive and least protective. This matches CA-01's stated
/// posture for the enforcement-read families. Superseding or retracting a head
/// is the way to withdraw it.
fn active_claim_bodies_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<ClaimBody>> {
    let mut bodies = Vec::new();
    for entry in store
        .edges_in
        .prefix_iter(txn, &edge_kind_prefix(subject, EdgeKind::ClaimOf))?
    {
        let (key, value) = entry?;
        let id = parse_edge_record(&key, &value)?.target;
        let Some(body) = claim_body_in_txn(store, txn, &id)? else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            bodies.push(body);
        }
    }
    Ok(bodies)
}

fn claim_body_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<ClaimBody>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("campaign compliance claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true).map(Some)
}

/// Node-local party shortcut owned by `comm.rs`, re-validated against synced
/// truth. Read-only mirror; CA never writes this index.
const COMM_PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";
/// Synced-truth field naming a comm-owned PERSON's party.
const COMM_PARTY_KEY_FIELD: &str = "party_key";

/// Resolves the PERSON behind an external-effect `counterparty` address.
///
/// A stale shortcut resolves to NOTHING rather than to the wrong person: the
/// row must still be a PERSON carrying exactly this `party_key`. Answering
/// `None` withdraws compliance from the effect, which is why the re-validation
/// is not optional — it is the difference between "not a campaign send" and
/// "someone else's compliance facts".
fn resolve_comm_party_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    counterparty: &str,
) -> Result<Option<EntityId>> {
    let party_key = counterparty.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let mut key = Vec::with_capacity(COMM_PARTY_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(COMM_PARTY_INDEX_PREFIX);
    key.extend_from_slice(&Sha256::digest(party_key.as_bytes()));
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let Ok(bytes) = <[u8; ENTITY_ID_LEN]>::try_from(raw_id.as_ref()) else {
        return Ok(None);
    };
    let Ok(id) = EntityId::from_bytes(bytes) else {
        return Ok(None);
    };
    Ok(person_with_party_key_in_txn(store, txn, &id, party_key)?.then_some(id))
}

fn person_with_party_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    party_key: &str,
) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(false);
    }
    let mut cursor = std::io::Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(body) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(false);
    };
    Ok(map_entries(&body).iter().any(|(key, value)| {
        key.as_str() == Some(COMM_PARTY_KEY_FIELD) && value.as_str() == Some(party_key)
    }))
}

// ---------------------------------------------------------------------------
// MessagePack value helpers
// ---------------------------------------------------------------------------

fn map_entries(value: &rmpv::Value) -> &[(rmpv::Value, rmpv::Value)] {
    match value {
        rmpv::Value::Map(entries) => entries,
        _ => &[],
    }
}

fn lookup<'a>(entries: &'a [(rmpv::Value, rmpv::Value)], key: &str) -> Option<&'a rmpv::Value> {
    entries
        .iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn nested_map<'a>(
    entries: &'a [(rmpv::Value, rmpv::Value)],
    key: &str,
) -> Option<&'a [(rmpv::Value, rmpv::Value)]> {
    match lookup(entries, key)? {
        rmpv::Value::Map(nested) => Some(nested),
        _ => None,
    }
}

fn nested_text(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<String> {
    let text = lookup(entries, key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn nested_flag(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> bool {
    lookup(entries, key).and_then(rmpv::Value::as_bool) == Some(true)
}

/// Entity references cross the CA-pack wire as CANONICAL lowercase hex — the
/// one spelling `campaign/claims.rs` established, because [`EntityId`] has no
/// serde impl. A non-canonical spelling is not a reference.
fn nested_entity_ref(entries: &[(rmpv::Value, rmpv::Value)], key: &str) -> Option<EntityId> {
    let hex = lookup(entries, key)?.as_str()?;
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex).then_some(id)
}

// ---------------------------------------------------------------------------
// Amendment: tighten auto, loosen or ambiguous waits for the owner stamp
// ---------------------------------------------------------------------------

/// What an amendment does to the pack's strictness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentClass {
    /// Provably stricter: rows added, dials tightened, nothing relaxed.
    Tightening,
    /// Policy semantics unchanged; only citations, verification dates, penalty
    /// notes, or the engine-version floor moved.
    MetadataRefresh,
    /// Anything that relaxes the pack, and anything the comparator cannot
    /// order. Free-text requirement edits live here: an unorderable change is
    /// not guessed safe.
    LooseningOrAmbiguous,
}

/// What a proposal did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComplianceAmendmentOutcome {
    /// Activated immediately, with a durable notice.
    Applied {
        /// The now-active pack version.
        pack_version: u32,
        /// The notice persisted alongside the activation.
        notice: String,
    },
    /// Staged. Nothing changed until an owner stamps this exact hash.
    PendingOwnerStamp {
        /// Canonical hash binding the exact proposed rows and version.
        proposal_hash: [u8; 32],
    },
}

/// Orders `proposed` against `current`.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the proposal is malformed, renames the pack,
/// or fails to advance the pack version.
pub fn classify_compliance_amendment(
    current: &CompliancePack,
    proposed: &CompliancePack,
) -> Result<ComplianceAmendmentClass> {
    validate_compliance_pack(proposed)?;
    if proposed.pack_id != current.pack_id {
        return Err(invalid_pack("an amendment may not rename the pack"));
    }
    if proposed.pack_version <= current.pack_version {
        return Err(invalid_pack("an amendment must advance the pack version"));
    }
    let rows = classify_row_delta(current, proposed);
    let dials = classify_dial_delta(current, proposed);
    Ok(
        match (
            rows.loosened || dials.loosened,
            rows.tightened || dials.tightened,
        ) {
            (true, _) => ComplianceAmendmentClass::LooseningOrAmbiguous,
            (false, true) => ComplianceAmendmentClass::Tightening,
            (false, false) => ComplianceAmendmentClass::MetadataRefresh,
        },
    )
}

#[derive(Debug, Default)]
struct AmendmentDelta {
    loosened: bool,
    tightened: bool,
}

/// A row set is stricter only when every current row survives byte-identically
/// on its semantic axes and the rows added are provably additive. A deleted
/// row, a widened exemption, and any requirement-text edit are all unorderable.
///
/// Adding a row is additive only under a jurisdiction the pack ALREADY seeds.
/// Seeding a NEW one is not: [`trusted_jurisdiction`] trusts any token the pack
/// holds a row for, so the addition takes that token OUT of the unknown
/// disposition and hands it to exactly the rows the proposal supplied — which
/// may be thinner than the strict pole it used to route to. Row addition is
/// therefore not monotone in the selected requirement set, and the case the
/// comparator cannot order waits for the stamp like every other one.
fn classify_row_delta(current: &CompliancePack, proposed: &CompliancePack) -> AmendmentDelta {
    let mut delta = AmendmentDelta::default();
    for row in &current.rows {
        match proposed
            .rows
            .iter()
            .find(|candidate| candidate.key() == row.key())
        {
            Some(candidate) if candidate.semantics() == row.semantics() => {}
            _ => delta.loosened = true,
        }
    }
    for added in proposed
        .rows
        .iter()
        .filter(|row| !current.rows.iter().any(|held| held.key() == row.key()))
    {
        if current
            .rows
            .iter()
            .any(|held| held.jurisdiction == added.jurisdiction)
        {
            delta.tightened = true;
        } else {
            delta.loosened = true;
        }
    }
    delta
}

fn classify_dial_delta(current: &CompliancePack, proposed: &CompliancePack) -> AmendmentDelta {
    let mut delta = AmendmentDelta::default();
    // A longer trust window and a lower confidence floor both admit sends the
    // current pack refuses.
    delta.loosened |= proposed.verified_at_max_age_secs > current.verified_at_max_age_secs;
    delta.loosened |= proposed.jurisdiction_confidence_floor_millis
        < current.jurisdiction_confidence_floor_millis;
    delta.loosened |= proposed.strict_pole_jurisdiction != current.strict_pole_jurisdiction;
    delta.loosened |= current
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !proposed.prohibited_list_provenance_classes.contains(class));
    delta.loosened |= current
        .conditional_exemption_evidence
        .iter()
        .any(|binding| !proposed.conditional_exemption_evidence.contains(binding));
    delta.tightened |= proposed.verified_at_max_age_secs < current.verified_at_max_age_secs;
    delta.tightened |= proposed.jurisdiction_confidence_floor_millis
        > current.jurisdiction_confidence_floor_millis;
    delta.tightened |= proposed
        .prohibited_list_provenance_classes
        .iter()
        .any(|class| !current.prohibited_list_provenance_classes.contains(class));
    delta
}

/// The only public activation path.
///
/// A provable tightening or a provenance-only refresh activates immediately
/// with a durable notice; anything else is staged behind an owner stamp bound
/// to the exact proposed rows and version.
///
/// # Errors
///
/// The classifier's rejections, plus storage errors.
pub fn propose_compliance_amendment(
    vault: &Vault,
    proposer: EntityId,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    apply_compliance_amendment(vault, &proposer.to_hex(), proposed)
}

/// OF-401's narrow ingestion hook.
///
/// It runs the SAME classifier as every other proposal, so a published update
/// cannot loosen the pack without an owner stamp. This mints no publisher
/// runtime, scheduler, or transport.
///
/// # Errors
///
/// As [`propose_compliance_amendment`].
pub fn ingest_published_compliance_update(
    vault: &Vault,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    apply_compliance_amendment(vault, "publisher-loop", proposed)
}

fn apply_compliance_amendment(
    vault: &Vault,
    proposer: &str,
    proposed: CompliancePack,
) -> Result<ComplianceAmendmentOutcome> {
    let mut wtxn = vault.store.env.write_txn()?;
    let current = active_compliance_pack_in_txn(&vault.store, &wtxn)?;
    let class = classify_compliance_amendment(&current, &proposed)?;
    let outcome = match class {
        ComplianceAmendmentClass::LooseningOrAmbiguous => {
            let encoded = encode_pack(&proposed)?;
            vault.store.vault_meta.put(
                &mut wtxn,
                CAMPAIGN_COMPLIANCE_PENDING_META_KEY,
                &encoded,
            )?;
            ComplianceAmendmentOutcome::PendingOwnerStamp {
                proposal_hash: compliance_proposal_hash(&proposed)?,
            }
        }
        ComplianceAmendmentClass::Tightening | ComplianceAmendmentClass::MetadataRefresh => {
            activate_compliance_pack(&vault.store, &mut wtxn, &proposed, class, proposer)?
        }
    };
    wtxn.commit()?;
    Ok(outcome)
}

/// The owner gate: activates the staged proposal iff the stamp binds the exact
/// rows and version that were staged.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when nothing is staged, when the hash names
/// different rows or a different version, or when the staged proposal no longer
/// advances the active version.
pub fn stamp_compliance_amendment(
    vault: &Vault,
    owner: EntityId,
    proposal_hash: [u8; 32],
) -> Result<CompliancePack> {
    let mut wtxn = vault.store.env.write_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&wtxn, CAMPAIGN_COMPLIANCE_PENDING_META_KEY)?
    else {
        return Err(invalid_pack("no amendment is awaiting an owner stamp"));
    };
    let pending = decode_pack(&raw, "campaign compliance pending amendment")?;
    if compliance_proposal_hash(&pending)? != proposal_hash {
        return Err(invalid_pack(
            "owner stamp does not bind the staged rows and version",
        ));
    }
    let current = active_compliance_pack_in_txn(&vault.store, &wtxn)?;
    if pending.pack_version <= current.pack_version {
        return Err(invalid_pack("staged amendment no longer advances the pack"));
    }
    activate_compliance_pack(
        &vault.store,
        &mut wtxn,
        &pending,
        ComplianceAmendmentClass::LooseningOrAmbiguous,
        &owner.to_hex(),
    )?;
    vault
        .store
        .vault_meta
        .delete(&mut wtxn, CAMPAIGN_COMPLIANCE_PENDING_META_KEY)?;
    wtxn.commit()?;
    Ok(pending)
}

fn activate_compliance_pack(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    pack: &CompliancePack,
    class: ComplianceAmendmentClass,
    actor: &str,
) -> Result<ComplianceAmendmentOutcome> {
    store_active_compliance_pack(store, wtxn, pack)?;
    let notice = format!(
        "campaign compliance pack {} activated at version {} ({}) by {}; {} rows",
        pack.pack_id,
        pack.pack_version,
        amendment_class_token(class),
        actor,
        pack.rows.len(),
    );
    let mut key = Vec::with_capacity(CAMPAIGN_COMPLIANCE_NOTICE_META_PREFIX.len() + 4);
    key.extend_from_slice(CAMPAIGN_COMPLIANCE_NOTICE_META_PREFIX);
    key.extend_from_slice(&pack.pack_version.to_be_bytes());
    store.vault_meta.put(wtxn, &key, notice.as_bytes())?;
    Ok(ComplianceAmendmentOutcome::Applied {
        pack_version: pack.pack_version,
        notice,
    })
}

const fn amendment_class_token(class: ComplianceAmendmentClass) -> &'static str {
    match class {
        ComplianceAmendmentClass::Tightening => "tightening",
        ComplianceAmendmentClass::MetadataRefresh => "metadata refresh",
        ComplianceAmendmentClass::LooseningOrAmbiguous => "owner stamped",
    }
}

/// Every durable activation notice, oldest version first.
///
/// # Errors
///
/// Storage errors, and [`Error::CorruptedIndex`] when a notice is not UTF-8.
pub fn compliance_amendment_notices(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut notices = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, CAMPAIGN_COMPLIANCE_NOTICE_META_PREFIX)?
    {
        let (_, raw) = entry?;
        let notice = std::str::from_utf8(&raw)
            .map_err(|_| Error::CorruptedIndex("campaign compliance activation notice"))?;
        notices.push(notice.to_owned());
    }
    Ok(notices)
}

/// Canonical hash of a proposal: the exact rows, in a canonical order, plus the
/// pack version and every dial that decides how those rows apply.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the canonical form cannot be encoded.
pub fn compliance_proposal_hash(pack: &CompliancePack) -> Result<[u8; 32]> {
    let mut canonical = pack.clone();
    canonical.rows.sort_by(|left, right| {
        (&left.jurisdiction, &left.channel, left.rule_kind).cmp(&(
            &right.jurisdiction,
            &right.channel,
            right.rule_kind,
        ))
    });
    canonical.prohibited_list_provenance_classes.sort_unstable();
    canonical
        .conditional_exemption_evidence
        .sort_by(|left, right| left.jurisdiction.cmp(&right.jurisdiction));
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_HASH_DOMAIN);
    hasher.update(encode_pack(&canonical)?);
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rmpv::Value;

    use crate::claim::ClaimApprovalStatus;
    use crate::config::VaultConfig;
    use crate::gate::{ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor};
    use crate::temporal::TimeRange;
    use crate::test_util::entity;

    /// The counterparty PERSON every vault-backed arm addresses.
    const SUBJECT_SEED: u8 = 0xC1;
    /// A second PERSON, for the cross-subject evidence-binding arm.
    const OTHER_SUBJECT_SEED: u8 = 0xC2;
    /// The dispatch-evidence claim.
    const EVIDENCE_SEED: u8 = 0xC3;
    /// The list-provenance record.
    const PROVENANCE_SEED: u8 = 0xC4;
    /// The publication-context record.
    const PUBLICATION_SEED: u8 = 0xC5;
    /// The sending channel identity.
    const IDENTITY_SEED: u8 = 0xC6;
    /// The message-element configuration claim.
    const ELEMENTS_SEED: u8 = 0xC7;
    /// A record of the wrong kind, cited on purpose.
    const WRONG_KIND_SEED: u8 = 0xC8;
    /// A provenance record whose stored class contradicts the claim.
    const WRONG_CLASS_SEED: u8 = 0xC9;
    /// A provenance record bound to the other subject.
    const FOREIGN_SEED: u8 = 0xCA;
    /// The amendment proposer / owner.
    const ACTOR_SEED: u8 = 0xCB;

    /// The seed's verification date; every row shares it.
    const SEED_VERIFIED_AT: u64 = 1_784_505_600;
    /// A clock comfortably inside the seed's freshness window.
    const FRESH_NOW: u64 = SEED_VERIFIED_AT + 1_000;

    fn pack() -> CompliancePack {
        embedded_seed_pack().expect("seed pack parses")
    }

    /// Facts that satisfy every seeded pole. Each arm below spoils exactly one
    /// axis, so a block can only come from the axis under test.
    fn facts(jurisdiction: Option<&str>, channel: &str) -> DispatchComplianceFacts {
        DispatchComplianceFacts {
            counterparty: entity(SUBJECT_SEED),
            jurisdiction: jurisdiction.map(str::to_owned),
            jurisdiction_confidence_millis: Some(1_000),
            channel: channel.to_owned(),
            legal_form: Some("corporate".to_owned()),
            list_provenance: Some(HydratedListProvenance {
                record_ref: entity(PROVENANCE_SEED),
                claimed_class: "double_opt_in".to_owned(),
            }),
            jp_publication: Some(HydratedJpPublicationFacts {
                record_ref: entity(PUBLICATION_SEED),
                published_by_recipient: true,
                in_course_of_business: true,
                no_marketing_statement_attached: true,
            }),
            sender_identity_present: true,
            physical_address_present: true,
            optout_mechanism_present: true,
            commercial_marking_present: true,
            now_utc: FRESH_NOW,
        }
    }

    fn reason(verdict: &ComplianceVerdict) -> Option<ComplianceBlockReason> {
        match verdict {
            ComplianceVerdict::Allow => None,
            ComplianceVerdict::Block { reason, .. } => Some(*reason),
        }
    }

    fn verdict(facts: &DispatchComplianceFacts) -> ComplianceVerdict {
        evaluate_dispatch_compliance(&pack(), facts)
    }

    // -- seed integrity ----------------------------------------------------

    #[test]
    fn campaign_compliance_seed_rows_match_arch_0059() {
        let pack = pack();
        assert_eq!(pack.pack_id, CAMPAIGN_COMPLIANCE_PACK_ID);
        assert!(
            !pack.warning.trim().is_empty(),
            "the caveat ships with the pack"
        );
        for jurisdiction in ["UK", "JP", "EU", "EU/DE", "EU/FR", "US", JURISDICTION_NONE] {
            assert!(
                pack.rows.iter().any(|row| row.jurisdiction == jurisdiction),
                "{jurisdiction} has no seeded rows"
            );
        }
        // The four headline consent-class rows carry their primary source.
        for jurisdiction in ["UK", "JP", "EU", "US"] {
            let row = pack
                .rows
                .iter()
                .find(|row| {
                    row.jurisdiction == jurisdiction
                        && row.rule_kind == ComplianceRuleKind::ConsentClass
                        && row.channel == "email"
                })
                .expect("headline consent-class row");
            assert!(!row.requirement.trim().is_empty());
            assert!(!row.source.citation.trim().is_empty());
            assert!(!row.source.url.trim().is_empty());
            assert!(!row.penalty_note.trim().is_empty());
            assert_eq!(row.verified_at, SEED_VERIFIED_AT);
            assert_eq!(row.version, 1);
        }
        // JP's publication exemption is bound to the three-fact check, and US
        // seeds the source-hygiene refusal.
        assert_eq!(
            pack.exemption_evidence("JP"),
            Some(ComplianceExemptionEvidence::PublicationContext)
        );
        assert!(pack.rows.iter().any(|row| {
            row.jurisdiction == "US" && row.rule_kind == ComplianceRuleKind::SourceHygiene
        }));
    }

    #[test]
    fn campaign_compliance_pack_validation_rejects_malformed_packs() {
        let mut duplicated = pack();
        let first = duplicated.rows[0].clone();
        duplicated.rows.push(first);
        assert!(
            validate_compliance_pack(&duplicated).is_err(),
            "a duplicate (jurisdiction, channel, rule_kind) key must be rejected"
        );

        let mut no_disposition = pack();
        no_disposition
            .rows
            .retain(|row| row.jurisdiction != JURISDICTION_NONE);
        assert!(validate_compliance_pack(&no_disposition).is_err());

        let mut unbound = pack();
        unbound
            .conditional_exemption_evidence
            .retain(|binding| binding.jurisdiction != "JP");
        assert!(
            validate_compliance_pack(&unbound).is_err(),
            "a conditional row with no declared evidence cannot be applied"
        );
    }

    // -- selection and composition ----------------------------------------

    #[test]
    fn campaign_compliance_strictest_matching_rows_win() {
        // Germany seeds no content-marking row of its own; the EU floor's row
        // still governs, so the absence of a national row cannot relax it.
        let mut german = facts(Some("EU/DE"), "email");
        german.commercial_marking_present = false;
        assert_eq!(
            verdict(&german),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::MissingRequiredMessageElement,
                jurisdiction: Some("EU".to_owned()),
                rule_kind: Some(ComplianceRuleKind::ContentMarking),
            }
        );

        // The same spoiled axis under the UK, which composes no EU floor,
        // still blocks on the UK's own row — composition is per-chain.
        let mut uk = facts(Some("UK"), "email");
        uk.commercial_marking_present = false;
        assert_eq!(
            verdict(&uk),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::MissingRequiredMessageElement,
                jurisdiction: Some("UK".to_owned()),
                rule_kind: Some(ComplianceRuleKind::ContentMarking),
            }
        );

        // A jurisdiction that seeds no postal-address row does not inherit
        // one: rows are the only source of requirements.
        let mut no_address = facts(Some("UK"), "email");
        no_address.physical_address_present = false;
        assert_eq!(verdict(&no_address), ComplianceVerdict::Allow);
    }

    #[test]
    fn campaign_compliance_unknown_jurisdiction_uses_strict_pole() {
        // Absent jurisdiction is NOT an automatic deny: facts that satisfy the
        // pole allow.
        assert_eq!(verdict(&facts(None, "email")), ComplianceVerdict::Allow);

        // A requirement the pole states still blocks, and names the pole's row.
        let mut spoiled = facts(None, "email");
        spoiled.optout_mechanism_present = false;
        assert_eq!(
            verdict(&spoiled),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::MissingRequiredMessageElement,
                jurisdiction: Some("EU".to_owned()),
                rule_kind: Some(ComplianceRuleKind::OptoutMechanism),
            }
        );

        // An unseeded token and a below-floor confidence take the same road.
        assert_eq!(
            verdict(&facts(Some("ZZ"), "email")),
            ComplianceVerdict::Allow
        );
        let mut low_confidence = facts(Some("US"), "email");
        low_confidence.jurisdiction_confidence_millis = Some(100);
        low_confidence.list_provenance = None;
        assert_eq!(
            verdict(&low_confidence),
            ComplianceVerdict::Allow,
            "a distrusted US observation must not apply the US source-hygiene row"
        );
    }

    #[test]
    fn campaign_compliance_platform_dm_scope_is_row_local() {
        // Japan: the publication exemption exists on email and not on the
        // platform lane, so the same missing context decides differently.
        let mut jp_email = facts(Some("JP"), "email");
        jp_email.jp_publication = None;
        assert_eq!(
            reason(&verdict(&jp_email)),
            Some(ComplianceBlockReason::MissingPublicationContext)
        );
        let mut jp_dm = facts(Some("JP"), "linkedin");
        jp_dm.jp_publication = None;
        assert_eq!(verdict(&jp_dm), ComplianceVerdict::Allow);

        // The UK carries its subscriber-class question onto the platform lane;
        // the US does not carry its opt-out regime's consent question anywhere.
        let mut uk_dm = facts(Some("UK"), "linkedin");
        uk_dm.legal_form = None;
        assert_eq!(
            reason(&verdict(&uk_dm)),
            Some(ComplianceBlockReason::UnknownLegalForm)
        );
        let mut us_dm = facts(Some("US"), "linkedin");
        us_dm.legal_form = None;
        assert_eq!(verdict(&us_dm), ComplianceVerdict::Allow);

        // Germany's platform row is its own, not a global DM rule.
        let mut de_dm = facts(Some("EU/DE"), "linkedin");
        de_dm.legal_form = None;
        assert_eq!(
            reason(&verdict(&de_dm)),
            Some(ComplianceBlockReason::UnknownLegalForm)
        );

        // A channel no row covers cannot be evaluated, so it fails closed.
        assert_eq!(
            reason(&verdict(&facts(Some("JP"), "whatsapp"))),
            Some(ComplianceBlockReason::RuleViolation)
        );
    }

    // -- per-axis walls ----------------------------------------------------

    #[test]
    fn campaign_compliance_unknown_legal_form_blocks_exemption() {
        let mut unknown = facts(Some("UK"), "email");
        unknown.legal_form = None;
        assert_eq!(
            verdict(&unknown),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::UnknownLegalForm,
                jurisdiction: Some("UK".to_owned()),
                rule_kind: Some(ComplianceRuleKind::ConsentClass),
            }
        );
        assert_eq!(
            verdict(&facts(Some("UK"), "email")),
            ComplianceVerdict::Allow
        );
    }

    #[test]
    fn campaign_compliance_jp_publication_exemption_requires_context() {
        assert_eq!(
            verdict(&facts(Some("JP"), "email")),
            ComplianceVerdict::Allow
        );
        for spoil in 0..3usize {
            let mut partial = facts(Some("JP"), "email");
            let publication = partial.jp_publication.as_mut().expect("seeded publication");
            match spoil {
                0 => publication.published_by_recipient = false,
                1 => publication.in_course_of_business = false,
                _ => publication.no_marketing_statement_attached = false,
            }
            assert_eq!(
                reason(&verdict(&partial)),
                Some(ComplianceBlockReason::MissingPublicationContext),
                "each of the three Art. 3(1)(iv) facts is load-bearing"
            );
        }
    }

    #[test]
    fn campaign_compliance_us_unknown_list_provenance_blocks() {
        let mut unknown = facts(Some("US"), "email");
        unknown.list_provenance = None;
        assert_eq!(
            verdict(&unknown),
            ComplianceVerdict::Block {
                reason: ComplianceBlockReason::UnknownListProvenance,
                jurisdiction: Some("US".to_owned()),
                rule_kind: Some(ComplianceRuleKind::SourceHygiene),
            }
        );

        // A KNOWN-bad provenance is a violation, not an unknown.
        let mut harvested = facts(Some("US"), "email");
        harvested.list_provenance = Some(HydratedListProvenance {
            record_ref: entity(PROVENANCE_SEED),
            claimed_class: "harvested".to_owned(),
        });
        assert_eq!(
            reason(&verdict(&harvested)),
            Some(ComplianceBlockReason::RuleViolation)
        );
    }

    #[test]
    fn campaign_compliance_required_message_elements_block() {
        type SpoilOneAxis = fn(&mut DispatchComplianceFacts);
        let axes: [(SpoilOneAxis, ComplianceRuleKind); 4] = [
            (
                |facts| facts.sender_identity_present = false,
                ComplianceRuleKind::SenderId,
            ),
            (
                |facts| facts.physical_address_present = false,
                ComplianceRuleKind::PhysicalAddress,
            ),
            (
                |facts| facts.optout_mechanism_present = false,
                ComplianceRuleKind::OptoutMechanism,
            ),
            (
                |facts| facts.commercial_marking_present = false,
                ComplianceRuleKind::ContentMarking,
            ),
        ];
        for (spoil, rule_kind) in axes {
            let mut spoiled = facts(Some("US"), "email");
            spoil(&mut spoiled);
            assert_eq!(
                verdict(&spoiled),
                ComplianceVerdict::Block {
                    reason: ComplianceBlockReason::MissingRequiredMessageElement,
                    jurisdiction: Some("US".to_owned()),
                    rule_kind: Some(rule_kind),
                }
            );
        }
    }

    #[test]
    fn campaign_compliance_stale_verified_at_blocks_dispatch() {
        let pack = pack();
        let mut stale = facts(Some("US"), "email");
        stale.now_utc = SEED_VERIFIED_AT + pack.verified_at_max_age_secs + 1;
        assert_eq!(
            reason(&evaluate_dispatch_compliance(&pack, &stale)),
            Some(ComplianceBlockReason::StaleRule),
            "staleness blocks; it never degrades to warn-and-send"
        );

        // One second earlier the same row is still fresh.
        let mut fresh = stale;
        fresh.now_utc = SEED_VERIFIED_AT + pack.verified_at_max_age_secs;
        assert_eq!(
            evaluate_dispatch_compliance(&pack, &fresh),
            ComplianceVerdict::Allow
        );
    }

    #[test]
    fn campaign_compliance_post_send_rows_never_block_dispatch() {
        // Opt-out deadlines and retention are obligations that begin after the
        // send. They ship as data and are never a dispatch wall.
        assert!(!ComplianceRuleKind::OptoutDeadline.is_dispatch_enforced());
        assert!(!ComplianceRuleKind::Records.is_dispatch_enforced());
        assert_eq!(
            verdict(&facts(Some("US"), "email")),
            ComplianceVerdict::Allow
        );
        assert_eq!(
            verdict(&facts(Some("EU/DE"), "email")),
            ComplianceVerdict::Allow
        );
    }

    // -- hydration ---------------------------------------------------------

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault =
            Vault::open_unseeded_for_test(dir.path(), VaultConfig::device()).expect("open vault");
        (dir, vault)
    }

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(*key), value.clone()))
                .collect(),
        )
    }

    fn put_person(vault: &Vault, seed: u8) -> EntityId {
        let id = entity(seed);
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"compliance fixture",
            )
            .expect("person");
        id
    }

    fn put_claim(vault: &Vault, seed: u8, predicate: &str, subject: EntityId, value: Value) {
        let body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        vault
            .put_claim(&entity(seed), &body, TimeRange { start: 1, end: 1 }, 1)
            .expect("claim write");
    }

    fn gate_effect(channel_identity_ref: Option<EntityId>) -> ExternalEffectGateInput {
        ExternalEffectGateInput {
            actor: GateActor {
                actor_class: "first_party".to_owned(),
                actor_ref: None,
            },
            provenance: crate::gate::GateProvenanceHandles::default(),
            verb: "send".to_owned(),
            channel: "email".to_owned(),
            channel_identity_ref,
            counterparty: Some("kenji@example.com".to_owned()),
            brief_ref: None,
            send_ref: None,
            standing_grant_ref: None,
            scoped_mcp_call: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: true,
            has_permission: true,
            policy_risk: ExternalEffectPolicyRisk::Normal,
        }
    }

    fn hydrate(vault: &Vault, subject: EntityId) -> DispatchComplianceFacts {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        hydrate_dispatch_compliance_facts(
            &vault.store,
            &rtxn,
            &gate_effect(Some(entity(IDENTITY_SEED))),
            subject,
            FRESH_NOW,
        )
        .expect("hydration")
    }

    /// Writes the evidence claim citing `provenance_ref` as `class`.
    fn put_evidence(vault: &Vault, subject: EntityId, provenance_ref: EntityId, class: &str) {
        put_claim(
            vault,
            EVIDENCE_SEED,
            PREDICATE_CRM_COMPLIANCE_EVIDENCE,
            subject,
            map(&[
                ("legal_form", Value::from("corporate")),
                (
                    "list_provenance",
                    map(&[
                        ("ref", Value::from(provenance_ref.to_hex())),
                        ("class", Value::from(class)),
                    ]),
                ),
            ]),
        );
    }

    #[test]
    fn campaign_compliance_evidence_refs_are_hydrated_and_class_validated() {
        let (_dir, vault) = test_vault();
        let subject = put_person(&vault, SUBJECT_SEED);
        let other = put_person(&vault, OTHER_SUBJECT_SEED);

        // 1. A reference that resolves to nothing is not evidence.
        put_evidence(&vault, subject, entity(PROVENANCE_SEED), "double_opt_in");
        assert!(hydrate(&vault, subject).list_provenance.is_none());

        // 2. A reference to an unrelated record is not evidence either.
        put_claim(
            &vault,
            WRONG_KIND_SEED,
            PREDICATE_CRM_COMPLIANCE_JP_PUBLICATION,
            subject,
            map(&[("published_by_recipient", Value::from(true))]),
        );
        put_evidence(&vault, subject, entity(WRONG_KIND_SEED), "double_opt_in");
        assert!(hydrate(&vault, subject).list_provenance.is_none());

        // 3. A provenance record whose own class contradicts the claimed one
        //    is rejected: the claim cannot name the class it likes.
        put_claim(
            &vault,
            WRONG_CLASS_SEED,
            PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
            subject,
            map(&[("class", Value::from("harvested"))]),
        );
        put_evidence(&vault, subject, entity(WRONG_CLASS_SEED), "double_opt_in");
        assert!(hydrate(&vault, subject).list_provenance.is_none());

        // 4. A record bound to ANOTHER counterparty cannot authorize this one.
        put_claim(
            &vault,
            FOREIGN_SEED,
            PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
            other,
            map(&[("class", Value::from("double_opt_in"))]),
        );
        put_evidence(&vault, subject, entity(FOREIGN_SEED), "double_opt_in");
        assert!(hydrate(&vault, subject).list_provenance.is_none());

        // 5. The matching record on this subject hydrates.
        put_claim(
            &vault,
            PROVENANCE_SEED,
            PREDICATE_CRM_COMPLIANCE_LIST_PROVENANCE,
            subject,
            map(&[("class", Value::from("double_opt_in"))]),
        );
        put_evidence(&vault, subject, entity(PROVENANCE_SEED), "double_opt_in");
        let hydrated = hydrate(&vault, subject);
        assert_eq!(
            hydrated.list_provenance,
            Some(HydratedListProvenance {
                record_ref: entity(PROVENANCE_SEED),
                claimed_class: "double_opt_in".to_owned(),
            })
        );
        assert_eq!(hydrated.legal_form.as_deref(), Some("corporate"));
    }

    #[test]
    fn campaign_compliance_message_elements_come_from_the_sending_identity() {
        let (_dir, vault) = test_vault();
        let subject = put_person(&vault, SUBJECT_SEED);
        let identity = put_person(&vault, IDENTITY_SEED);

        // With no configuration row, no element is established.
        let bare = hydrate(&vault, subject);
        assert!(!bare.sender_identity_present);
        assert!(!bare.optout_mechanism_present);

        put_claim(
            &vault,
            ELEMENTS_SEED,
            PREDICATE_CRM_COMPLIANCE_MESSAGE_ELEMENTS,
            identity,
            map(&[
                ("sender_identity", Value::from(true)),
                ("physical_address", Value::from(true)),
                ("optout_mechanism", Value::from(true)),
                ("commercial_marking", Value::from(true)),
            ]),
        );
        let configured = hydrate(&vault, subject);
        assert!(configured.sender_identity_present);
        assert!(configured.physical_address_present);
        assert!(configured.optout_mechanism_present);
        assert!(configured.commercial_marking_present);

        // A send with no bound identity discloses nothing, whatever a row says.
        let rtxn = vault.store.env.read_txn().expect("read txn");
        let unbound = hydrate_dispatch_compliance_facts(
            &vault.store,
            &rtxn,
            &gate_effect(None),
            subject,
            FRESH_NOW,
        )
        .expect("hydration");
        assert!(!unbound.sender_identity_present);
    }

    // -- amendment ---------------------------------------------------------

    fn tightened(base: &CompliancePack) -> CompliancePack {
        let mut proposed = base.clone();
        proposed.pack_version = base.pack_version + 1;
        let mut added = base
            .rows
            .iter()
            .find(|row| row.rule_kind == ComplianceRuleKind::SourceHygiene)
            .expect("a source-hygiene row to copy")
            .clone();
        added.jurisdiction = "UK".to_owned();
        proposed.rows.push(added);
        proposed
    }

    #[test]
    fn campaign_compliance_tightening_auto_applies_with_notice() {
        let (_dir, vault) = test_vault();
        let base = load_active_compliance_pack(&vault).expect("seed bootstraps the active pack");
        assert_eq!(base, pack(), "an empty vault reads the embedded seed");

        let proposed = tightened(&base);
        assert_eq!(
            classify_compliance_amendment(&base, &proposed).expect("classified"),
            ComplianceAmendmentClass::Tightening
        );
        let outcome = propose_compliance_amendment(&vault, entity(ACTOR_SEED), proposed.clone())
            .expect("tightening applies");
        assert_eq!(
            outcome,
            ComplianceAmendmentOutcome::Applied {
                pack_version: 2,
                notice: match &outcome {
                    ComplianceAmendmentOutcome::Applied { notice, .. } => notice.clone(),
                    ComplianceAmendmentOutcome::PendingOwnerStamp { .. } => String::new(),
                },
            }
        );
        assert_eq!(
            load_active_compliance_pack(&vault)
                .expect("active")
                .pack_version,
            2
        );
        let notices = compliance_amendment_notices(&vault).expect("notices");
        assert_eq!(notices.len(), 1, "the activation left a durable notice");
        assert!(notices[0].contains("tightening"));

        // A citation-and-date-only revision is a metadata refresh.
        let mut refreshed = proposed;
        refreshed.pack_version = 3;
        for row in &mut refreshed.rows {
            row.verified_at += 1;
        }
        assert_eq!(
            classify_compliance_amendment(
                &load_active_compliance_pack(&vault).expect("active"),
                &refreshed
            )
            .expect("classified"),
            ComplianceAmendmentClass::MetadataRefresh
        );
    }

    #[test]
    fn campaign_compliance_loosening_waits_for_owner_stamp() {
        let (_dir, vault) = test_vault();
        let base = load_active_compliance_pack(&vault).expect("active");
        let mut relaxed = base.clone();
        relaxed.pack_version = 2;
        relaxed
            .rows
            .retain(|row| row.rule_kind != ComplianceRuleKind::SourceHygiene);
        assert_eq!(
            classify_compliance_amendment(&base, &relaxed).expect("classified"),
            ComplianceAmendmentClass::LooseningOrAmbiguous
        );

        let outcome = propose_compliance_amendment(&vault, entity(ACTOR_SEED), relaxed.clone())
            .expect("staged");
        let ComplianceAmendmentOutcome::PendingOwnerStamp { proposal_hash } = outcome else {
            panic!("a row deletion must not auto-apply");
        };
        assert_eq!(
            load_active_compliance_pack(&vault)
                .expect("active")
                .pack_version,
            1,
            "nothing activates before the stamp"
        );

        // A hash over different rows does not bind this proposal.
        let other_rows = compliance_proposal_hash(&tightened(&base)).expect("hash");
        assert!(stamp_compliance_amendment(&vault, entity(ACTOR_SEED), other_rows).is_err());
        // Nor does the same rows at a different version.
        let mut other_version = relaxed.clone();
        other_version.pack_version = 3;
        let other_version_hash = compliance_proposal_hash(&other_version).expect("hash");
        assert_ne!(other_version_hash, proposal_hash);
        assert!(
            stamp_compliance_amendment(&vault, entity(ACTOR_SEED), other_version_hash).is_err()
        );
        assert_eq!(
            load_active_compliance_pack(&vault)
                .expect("active")
                .pack_version,
            1
        );

        let stamped =
            stamp_compliance_amendment(&vault, entity(ACTOR_SEED), proposal_hash).expect("stamped");
        assert_eq!(stamped.pack_version, 2);
        assert_eq!(
            load_active_compliance_pack(&vault).expect("active"),
            relaxed,
            "the stamped version activates"
        );
        // The staged slot is consumed, so one stamp cannot activate twice.
        assert!(stamp_compliance_amendment(&vault, entity(ACTOR_SEED), proposal_hash).is_err());
    }

    #[test]
    fn campaign_compliance_ambiguous_change_is_not_auto_applied() {
        let (_dir, vault) = test_vault();
        let base = load_active_compliance_pack(&vault).expect("active");

        // Free-text requirement edits cannot be ordered, so they are not
        // guessed safe — even one that reads stricter to a human.
        let mut reworded = base.clone();
        reworded.pack_version = 2;
        reworded.rows[0]
            .requirement
            .push_str(" This is now mandatory.");
        assert_eq!(
            classify_compliance_amendment(&base, &reworded).expect("classified"),
            ComplianceAmendmentClass::LooseningOrAmbiguous
        );
        assert!(matches!(
            ingest_published_compliance_update(&vault, reworded).expect("staged"),
            ComplianceAmendmentOutcome::PendingOwnerStamp { .. }
        ));
        assert_eq!(
            load_active_compliance_pack(&vault)
                .expect("active")
                .pack_version,
            1
        );

        // So is a widened trust window, and so is moving the strict pole.
        let mut widened = base.clone();
        widened.pack_version = 2;
        widened.verified_at_max_age_secs += 1;
        assert_eq!(
            classify_compliance_amendment(&base, &widened).expect("classified"),
            ComplianceAmendmentClass::LooseningOrAmbiguous
        );
        let mut moved_pole = base.clone();
        moved_pole.pack_version = 2;
        moved_pole.strict_pole_jurisdiction = "UK".to_owned();
        assert_eq!(
            classify_compliance_amendment(&base, &moved_pole).expect("classified"),
            ComplianceAmendmentClass::LooseningOrAmbiguous
        );

        // A proposal that does not advance the version is rejected outright.
        let mut stale_version = base.clone();
        stale_version.verified_at_max_age_secs -= 1;
        assert!(classify_compliance_amendment(&base, &stale_version).is_err());
    }

    #[test]
    fn campaign_compliance_new_jurisdiction_rows_wait_for_owner_stamp() {
        let base = pack();
        let mut seeded_zz = base.clone();
        seeded_zz.pack_version = 2;
        let mut added = base
            .rows
            .iter()
            .find(|row| {
                row.jurisdiction == "US" && row.rule_kind == ComplianceRuleKind::ConsentClass
            })
            .expect("a consent-class row to copy")
            .clone();
        added.jurisdiction = "ZZ".to_owned();
        seeded_zz.rows.push(added);

        // Every current row survives byte-identically and one row is added, so
        // the row set reads additive. It is not: seeding a jurisdiction the
        // pack did not hold REMOVES that token from the unknown disposition.
        assert_eq!(
            classify_compliance_amendment(&base, &seeded_zz).expect("classified"),
            ComplianceAmendmentClass::LooseningOrAmbiguous,
            "a row that seeds a NEW jurisdiction is not provably additive"
        );

        // The escape it would otherwise auto-activate, spelled out: the same
        // facts the strict pole refuses sail through the newly seeded token,
        // which now governs itself with exactly the one row the proposal wrote.
        let mut spoiled = facts(Some("ZZ"), "email");
        spoiled.optout_mechanism_present = false;
        assert_eq!(
            reason(&evaluate_dispatch_compliance(&base, &spoiled)),
            Some(ComplianceBlockReason::MissingRequiredMessageElement),
            "an unseeded token takes the strict pole"
        );
        assert_eq!(
            evaluate_dispatch_compliance(&seeded_zz, &spoiled),
            ComplianceVerdict::Allow,
            "a seeded token governs itself — which is why this needs the stamp"
        );

        // Adding a row under an ALREADY-seeded jurisdiction stays additive, so
        // the ordinary tightening path is not collateral damage.
        assert_eq!(
            classify_compliance_amendment(&base, &tightened(&base)).expect("classified"),
            ComplianceAmendmentClass::Tightening
        );
    }
}
