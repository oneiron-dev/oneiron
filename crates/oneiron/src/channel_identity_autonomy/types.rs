//! Schema version, vault-meta predicates, the autonomy rung, envelope/candidate/mode/request/state shapes and the graduation shapes.

use crate::access_grant::AccessGrant;
use crate::channel_identity_selection::RelationshipContext;
use crate::entity_id::EntityId;
use crate::outbound_grant::StandingOutboundGrant;

pub const CHANNEL_IDENTITY_AUTONOMY_SCHEMA_VERSION: u64 = 1;
pub const DEFAULT_GRADUATION_UNCHANGED_STREAK: u32 = 12;
pub const PREDICATE_MAILBOX_READ_ENVELOPE: &str = "channel_identity.mailbox_read_envelope";
pub const PREDICATE_ACTION_ENVELOPE: &str = "channel_identity.action_envelope";
pub const PREDICATE_AUTONOMY_MODE: &str = "channel_identity.autonomy_mode";
pub const PREDICATE_GRADUATION_EVIDENCE: &str = "channel_identity.graduation_evidence";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelIdentityAutonomyRung {
    ScopedRead,
    DraftOnly,
    SendWithApproval,
    AutonomousWithinEnvelope,
}

impl ChannelIdentityAutonomyRung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScopedRead => "scoped_read",
            Self::DraftOnly => "draft_only",
            Self::SendWithApproval => "send_with_approval",
            Self::AutonomousWithinEnvelope => "autonomous_within_envelope",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "scoped_read" => Some(Self::ScopedRead),
            "draft_only" => Some(Self::DraftOnly),
            "send_with_approval" => Some(Self::SendWithApproval),
            "autonomous_within_envelope" => Some(Self::AutonomousWithinEnvelope),
            _ => None,
        }
    }

    pub(super) fn verb(self) -> Option<&'static str> {
        match self {
            Self::ScopedRead => None,
            Self::DraftOnly | Self::SendWithApproval => Some("mail.draft"),
            Self::AutonomousWithinEnvelope => Some("mail.send"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxReadEnvelope {
    pub identity_ref: EntityId,
    pub label_allowlist: Vec<String>,
    pub thread_allowlist: Vec<String>,
    /// Inclusive lower bound on mailbox item time, not a volume-window clock.
    pub not_before: Option<u64>,
    /// Inclusive upper bound on mailbox item time.
    pub not_after: Option<u64>,
}

/// One already-resolved mailbox item to check against read-side authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxReadCandidate {
    pub identity_ref: EntityId,
    pub label: Option<String>,
    pub thread_ref: Option<String>,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityActionEnvelope {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    /// None matches only an unclassified counterparty, not every class.
    pub counterparty_class: Option<String>,
    pub max_actions: u32,
    pub window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityEffectCandidate {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub verb_class: String,
    pub counterparty_class: Option<String>,
    /// Engine effect identity. Reuse reserves no second slot or delivery.
    pub effect_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelIdentityGrantWindowUsage {
    pub window_started_at: u64,
    pub used_actions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyMode {
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub rung: ChannelIdentityAutonomyRung,
    pub read_grant_ref: Option<EntityId>,
    pub action_grant_ref: Option<EntityId>,
}

/// Exact desired configuration. Apply refuses to replace a different posture;
/// intentional changes use the authenticated mode door after minting bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyRequest {
    pub actor_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub rung: ChannelIdentityAutonomyRung,
    pub read_envelope: MailboxReadEnvelope,
    pub action_envelope: Option<ChannelIdentityActionEnvelope>,
}

impl ChannelIdentityAutonomyRequest {
    /// Starting posture for a newly delegated mailbox. Applying it still needs
    /// owner consent and creates separate read and draft grants, never send.
    #[must_use]
    pub fn draft_only(
        actor_ref: EntityId,
        read_envelope: MailboxReadEnvelope,
        action_envelope: ChannelIdentityActionEnvelope,
    ) -> Self {
        Self {
            actor_ref,
            relationship_context: action_envelope.relationship_context,
            rung: ChannelIdentityAutonomyRung::DraftOnly,
            read_envelope,
            action_envelope: Some(action_envelope),
        }
    }
}

/// Read-back proof includes the actual persisted grants, not just a mode label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelIdentityAutonomyState {
    pub mode: ChannelIdentityAutonomyMode,
    pub read_envelope: MailboxReadEnvelope,
    pub action_envelope: Option<ChannelIdentityActionEnvelope>,
    pub read_grant: AccessGrant,
    pub action_grant: Option<StandingOutboundGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GraduationScopeKey {
    pub actor_ref: EntityId,
    pub identity_ref: EntityId,
    pub relationship_context: RelationshipContext,
    pub verb_class: String,
    pub counterparty_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftReviewOutcome {
    ApprovedUntouched,
    ApprovedAmended { edit_distance_millis: u32 },
    Rejected,
    Undone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraduationEvidence {
    pub scope: GraduationScopeKey,
    pub outcome: DraftReviewOutcome,
    pub receipt_ref: String,
    pub occurred_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraduationOffer {
    pub scope: GraduationScopeKey,
    pub evidence_refs: Vec<String>,
    pub proposed_envelope: ChannelIdentityActionEnvelope,
    pub unchanged_streak: u32,
    pub offered_at: u64,
}
