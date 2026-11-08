//! The per-class verdicts a brief shows (FIX 20734, Engine ruling 11:16):
//! one line for each class the actor's standing outbound and consent grants,
//! its effector policy rows, governing connector keys and act-policy rows
//! name, and one for each of DEC-0006 invariant 1's default rules. Each line
//! gives the word an act inside its bound gets (allow, deny or would-ask)
//! with that bound shown,
//! and names each administrative hold as a hold, never as one of those three
//! words (C2:207, B67:148).
//!
//! The words are classed as `can(effect)` classes them, from the checks the
//! actor meets for any target. A line's `allow` is no admission:
//! the line names the checks every act inside its bound still meets, and
//! execution rechecks every act. Nothing here is read back as authority.
//!
//! The lines are read beside the class ceilings in one snapshot, dated with
//! the same instant and policy frontier
//! ([`crate::Vault::self_brief_class_reads`]). The read writes nothing.

use crate::entity_id::EntityId;
use crate::memory::CanEffectVerdict;
use crate::outbound_consent::DataClass;
use crate::outbound_consent::tool_call::ToolGrantDataClass;
use crate::outbound_grant::StandingOutboundGrantScope;
use crate::policy_manifest_doors::PolicyGrantValue;

use super::ceilings::BriefCeiling;

/// The class reads of one brief, from one snapshot: the concrete class
/// ceilings and the per-class verdicts beside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefClassReads {
    pub ceilings: Vec<BriefCeiling>,
    pub class_verdicts: BriefClassVerdicts,
}

/// The per-class verdicts, dated as the class ceilings beside them are.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefClassVerdicts {
    /// The vault's authority instant the read observed, in Unix seconds.
    pub as_of_secs: u64,
    /// The resolved policy's frontier hash in the same read, lowercase hex:
    /// it names the policy state the lines were read beside.
    pub policy_frontier: String,
    /// The lines, by class, then by source kind, then by grant.
    pub verdicts: Vec<BriefClassVerdict>,
}

/// One class's verdict, with the bound it holds inside. It is no verdict
/// on any one act: an act inside the bound still meets every check
/// `per_act` names, and execution rechecks it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefClassVerdict {
    /// The class as its source names it.
    pub class: String,
    /// Where the line comes from, with its bound.
    pub source: BriefClassSource,
    /// The word an act inside the bound gets: `held` when an administrative
    /// hold holds it, each hold named in `holds`.
    pub inside: CanEffectVerdict,
    /// The Gate's reason codes behind `inside`, `GateReasonCode::as_str`
    /// tokens, or the connector driver's own token for its administrative
    /// stop; none for `allow`, and none for an act-policy row's `deny`, which
    /// no reason code names.
    pub reasons: Vec<String>,
    /// Each administrative hold among `reasons`, its token without its
    /// `gate.pending.` prefix (for example `actor_ceiling`).
    pub holds: Vec<String>,
    /// The word an act beyond the bound gets; `null` when the line has no
    /// bound to go beyond.
    pub outside: Option<CanEffectVerdict>,
    /// The checks every act inside the bound still meets, which only the act
    /// itself answers.
    pub per_act: Vec<BriefPerActCheck>,
}

/// A consent grant's action envelope as its bound states it. An act's
/// selectors must all be among `selectors`; its target must be `target` when
/// one is set; its draw must stay within `budget`. `receipt_required` is an
/// obligation, never an authorization.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct BriefActionEnvelope {
    pub selectors: Vec<String>,
    pub target: Option<String>,
    pub budget: Option<u64>,
    pub receipt_required: bool,
}

/// Where a class line comes from, with the bound its source states.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefClassSource {
    /// A standing outbound grant the actor holds, active under the policy
    /// the read resolved: the grant and its scope dial.
    OutboundGrant {
        grant: EntityId,
        scope: BriefOutboundScope,
    },
    /// An active standing consent grant whose actor subject contains this
    /// actor: its reference and action envelope. `external_effects` is false
    /// when the subject pins an actor class: an external effect's consent
    /// requirement names no actor class, so such a grant never covers it.
    ConsentGrant {
        grant: String,
        envelope: BriefActionEnvelope,
        external_effects: bool,
    },
    /// The governing key the actor's calls to `server` run under, when it is
    /// not Active. `status` is `ConnectorKeyStatus::as_str()`.
    ConnectorKey {
        key: EntityId,
        server: String,
        status: String,
    },
    /// A stamped charter whose text or compiled policy no longer matches its
    /// stamp. `catalog_charter` is true for a derived key's catalog charter,
    /// false for the key's own.
    CharterDrift {
        key: EntityId,
        server: String,
        catalog_charter: bool,
    },
    /// One compiled never-list entry, exactly as stored. `catalog_charter`
    /// distinguishes the derived key's catalog charter from its own.
    NeverListEntry {
        key: EntityId,
        server: String,
        entry: String,
        catalog_charter: bool,
    },
    /// The governing connector slate's setting for one tool.
    SlateTool {
        key: EntityId,
        server: String,
        tool: String,
        setting: crate::connector_key::SlateDisposition,
    },
    /// A scoped policy grant row that admits the actor and an external
    /// effect, with no budget row: the effector it covers as the row names
    /// it, its purpose-specific selectors as the manifest gives them, and
    /// whether an act under it needs a receipt.
    Effector {
        effector: String,
        selectors: Option<PolicyGrantValue>,
        receipt_required: bool,
    },
    /// An act-policy pairing whose posture resolves to deny for the actor,
    /// from the vault row and the actor's own holder rows.
    Act {
        act_class: String,
        subject_class: String,
    },
    /// A default rule of DEC-0006 invariant 1, which holds with no grant.
    Default { rule: BriefDefaultRule },
}

/// A standing outbound grant's scope dial, field for field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BriefOutboundScope {
    /// Matching sends to one contact or counterparty.
    Contact { contact_ref: String },
    /// Every verb in one outbound verb class.
    VerbClass { verb_class: String },
    /// Matching sends on one channel.
    Channel { channel: String },
    /// Every verb in one verb class, inside one brief.
    BriefVerbClass {
        brief_ref: String,
        verb_class: String,
    },
    /// Publish updates to one artifact.
    ArtifactPublish { artifact: String },
    /// One external tool on one server: the highest payload data class, the
    /// argument and header classes, and every endpoint it may reach.
    ScopedMcp {
        server: String,
        tool: String,
        data_class_ceiling: DataClass,
        tool_data_classes: Vec<ToolGrantDataClass>,
        endpoint_allowlist: Vec<String>,
    },
    /// `calendar.invite` for the bookings confirmed on one booking page.
    BookingPageInvites { page_ref: EntityId },
}

impl BriefOutboundScope {
    /// The dial a standing outbound grant's scope `scope` states.
    pub(crate) fn of_grant_scope(scope: &StandingOutboundGrantScope) -> Self {
        match scope {
            StandingOutboundGrantScope::Contact { contact_ref } => Self::Contact {
                contact_ref: contact_ref.clone(),
            },
            StandingOutboundGrantScope::VerbClass { verb_class } => Self::VerbClass {
                verb_class: verb_class.clone(),
            },
            StandingOutboundGrantScope::Channel { channel } => Self::Channel {
                channel: channel.clone(),
            },
            StandingOutboundGrantScope::BriefVerbClass {
                brief_ref,
                verb_class,
            } => Self::BriefVerbClass {
                brief_ref: brief_ref.clone(),
                verb_class: verb_class.clone(),
            },
            StandingOutboundGrantScope::ArtifactPublish { artifact } => Self::ArtifactPublish {
                artifact: artifact.clone(),
            },
            StandingOutboundGrantScope::ScopedMcp {
                server,
                tool,
                data_class_ceiling,
                tool_data_classes,
                endpoint_allowlist,
            } => Self::ScopedMcp {
                server: server.clone(),
                tool: tool.clone(),
                data_class_ceiling: *data_class_ceiling,
                tool_data_classes: tool_data_classes.clone(),
                endpoint_allowlist: endpoint_allowlist.clone(),
            },
            StandingOutboundGrantScope::BookingPageInvites { page_ref } => {
                Self::BookingPageInvites {
                    page_ref: *page_ref,
                }
            }
        }
    }
}

/// A default rule of DEC-0006 invariant 1, as C2:201 states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefDefaultRule {
    /// "Reversible vault effects proceed."
    ReversibleVaultEffect,
    /// "Destructive, outbound and critical effects become durable consent
    /// waits, unless a standing grant covers them."
    DestructiveOutboundOrCritical,
    /// "The catastrophe floor still asks. Only an owner's scoped bypass
    /// passes it, and no bypass covers erase."
    CatastropheFloor,
}

impl BriefDefaultRule {
    /// Every rule, in the order C2:201 states them.
    pub(crate) const ALL: [Self; 3] = [
        Self::ReversibleVaultEffect,
        Self::DestructiveOutboundOrCritical,
        Self::CatastropheFloor,
    ];

    /// The rule's name, as identity spells it: the class its line names.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ReversibleVaultEffect => "reversible_vault_effect",
            Self::DestructiveOutboundOrCritical => "destructive_outbound_or_critical",
            Self::CatastropheFloor => "catastrophe_floor",
        }
    }
}

/// A check every act inside a line's bound still meets, which only the act
/// itself answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BriefPerActCheck {
    /// The counterparty has not opted out, or an override passes it.
    CounterpartyOptOut,
    /// The counterparty's campaign membership and its law rows.
    CampaignCompliance,
    /// The sender's envelope window has room for the act now.
    EnvelopeWindow,
    /// The governing key's budgets have room for the act.
    Budget,
    /// The counterparty's permission and opt-in facts.
    Permission,
    /// The act carries its own external-effect authority.
    ExternalAuthority,
    /// The act's own selectors, target and draw fit inside the bound.
    BoundContainment,
    /// The prepared call binds the approved manifest.
    ManifestBinding,
    /// The payload's data class and the resolved endpoint fit the grant.
    DataClassAndEndpoint,
    /// The connector slate's setting for the tool.
    ToolSetting,
}
