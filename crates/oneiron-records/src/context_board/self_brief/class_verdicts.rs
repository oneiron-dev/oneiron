//! Moved from `crates/oneiron/src/context_board/self_brief/class_verdicts.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;

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

/// A default rule of DEC-0006 invariant 1, as C2:201 states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Register)]
#[serde(rename_all = "snake_case")]
#[register("brief.default.rule")]
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
    pub const ALL: [Self; 3] = [
        Self::ReversibleVaultEffect,
        Self::DestructiveOutboundOrCritical,
        Self::CatastropheFloor,
    ];
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
