//! Pack identity consts, predicates, rule-row types, and the CompliancePack container.

use serde::{Deserialize, Serialize};

/// Stable id of the compliance pack this module governs.
pub const CAMPAIGN_COMPLIANCE_PACK_ID: &str = "crm.compliance.v1";

/// `vault_meta` key holding the ACTIVE pack.
pub const CAMPAIGN_COMPLIANCE_META_KEY: &[u8] = b"campaign:compliance:active:v1";

/// `vault_meta` key holding the one staged proposal awaiting an owner stamp.
pub(super) const CAMPAIGN_COMPLIANCE_PENDING_META_KEY: &[u8] = b"campaign:compliance:pending:v1";

/// `vault_meta` prefix of the durable activation-notice log, keyed by the
/// activated pack version so one version can never write two notices.
pub(super) const CAMPAIGN_COMPLIANCE_NOTICE_META_PREFIX: &[u8] = b"campaign:compliance:notice:v1:";

/// The bootstrap seed. It is the active pack only while the vault holds none.
pub const CAMPAIGN_COMPLIANCE_SEED_JSON: &str = include_str!("seed_v1.json");

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
pub(super) const JURISDICTION_NONE: &str = "none";

/// Channel token matching every channel.
pub(super) const CHANNEL_WILDCARD: &str = "*";

/// Domain tag separating this hash space from every other one in the engine.
pub(super) const PROPOSAL_HASH_DOMAIN: &[u8] = b"oneiron.campaign.compliance.proposal.v1";

/// Confidence is stored as a fraction; the pack's floor is in thousandths.
pub(super) const CONFIDENCE_MILLIS_SCALE: f32 = 1000.0;

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
    pub(super) const fn is_dispatch_enforced(self) -> bool {
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
    pub(super) fn key(&self) -> (&str, &str, ComplianceRuleKind) {
        (&self.jurisdiction, &self.channel, self.rule_kind)
    }

    pub(super) fn semantics(&self) -> (&str, B2bExemption) {
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
    pub(super) fn exemption_evidence(
        &self,
        jurisdiction: &str,
    ) -> Option<ComplianceExemptionEvidence> {
        self.conditional_exemption_evidence
            .iter()
            .find(|binding| binding.jurisdiction == jurisdiction)
            .map(|binding| binding.evidence)
    }

    /// A row is trustworthy only inside the window that OPENS when a human
    /// verified it and closes one dial-width later.
    ///
    /// The forward half of that test is load-bearing, not decoration: nothing
    /// verifies a row after now, and `verified_at` widens the effective trust
    /// window exactly as [`Self::verified_at_max_age_secs`] does — but moving
    /// it is provenance, so the amendment classifier reads it as a metadata
    /// refresh and auto-activates. Without this half, one forward-dated field
    /// (a millisecond mistype is enough) saturates the window open forever and
    /// disables the stale-row wall with no owner stamp anywhere.
    pub(super) fn is_stale(&self, row: &ComplianceRuleRow, now_utc: u64) -> bool {
        row.verified_at > now_utc
            || now_utc
                > row
                    .verified_at
                    .saturating_add(self.verified_at_max_age_secs)
    }
}
