//! AccessGrant record and scope, capability, and status enums.

use std::collections::BTreeSet;

use crate::booking::DisclosureRung;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::invalid_grant;

/// Scope addressed by an AccessGrant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantScope {
    /// Access to one companion persona profile in one person scope.
    CompanionProfile {
        /// Person scope the companion profile belongs to.
        person_ref: EntityId,
        /// Persona/profile record being addressed.
        persona_ref: EntityId,
    },
    /// Calendar disclosure at one rung (ARCH-0062 R1).
    ///
    /// DEC-0006 binds calendar disclosure per `(calendar × audience)`. The
    /// audience is the record's own `principal_ref` — the same field
    /// [`crate::consent::disclosure_grant_from_access_grant`] already lifts
    /// into the unified registry's singleton audience bound — so the scope
    /// carries the calendar and the rung and nothing that could disagree with
    /// it.
    Calendar {
        /// Calendar whose events may be projected.
        calendar_ref: EntityId,
        /// Highest rung the audience may read, before any surface ceiling.
        rung: DisclosureRung,
    },
    /// Read one identity through an immutable mailbox envelope.
    ChannelIdentity {
        identity_ref: EntityId,
        envelope_ref: EntityId,
    },
    /// Read one opaque brief through a render-time redaction maximum.
    SharedBrief {
        /// Rendering-layer document handle, not a document copy.
        brief_ref: String,
        /// Maximum explicitly permitted WORLD refs.
        world_refs: BTreeSet<EntityId>,
        /// Maximum explicitly permitted FACET refs.
        facet_refs: BTreeSet<EntityId>,
        /// Whether unscoped dimensions may pass.
        include_unscoped: bool,
    },
}

impl AccessGrantScope {
    /// Constructs a companion profile scope.
    #[must_use]
    pub const fn companion_profile(person_ref: EntityId, persona_ref: EntityId) -> Self {
        Self::CompanionProfile {
            person_ref,
            persona_ref,
        }
    }

    /// Constructs a calendar disclosure scope.
    #[must_use]
    pub const fn calendar(calendar_ref: EntityId, rung: DisclosureRung) -> Self {
        Self::Calendar { calendar_ref, rung }
    }

    /// Returns whether this scope exactly names the supplied companion profile.
    #[must_use]
    pub fn matches_companion_profile(&self, person_ref: &EntityId, persona_ref: &EntityId) -> bool {
        match self {
            Self::CompanionProfile {
                person_ref: grant_person_ref,
                persona_ref: grant_persona_ref,
            } => {
                grant_person_ref.as_bytes() == person_ref.as_bytes()
                    && grant_persona_ref.as_bytes() == persona_ref.as_bytes()
            }
            Self::Calendar { .. } | Self::SharedBrief { .. } | Self::ChannelIdentity { .. } => {
                false
            }
        }
    }

    /// Returns companion profile refs when this scope uses that shape.
    #[must_use]
    pub const fn companion_profile_refs(&self) -> Option<(EntityId, EntityId)> {
        match self {
            Self::CompanionProfile {
                person_ref,
                persona_ref,
            } => Some((*person_ref, *persona_ref)),
            Self::Calendar { .. } | Self::SharedBrief { .. } | Self::ChannelIdentity { .. } => None,
        }
    }

    /// Returns the one capability this scope shape can authorize.
    ///
    /// Scope and capability are a matched pair, not two free axes: a calendar
    /// scope authorizes a rung read and nothing else, a companion-profile
    /// scope a profile read and nothing else. [`AccessGrant::validate`] is the
    /// door that enforces it, so a mispaired grant can never encode, decode,
    /// or persist.
    #[must_use]
    pub const fn required_capability(&self) -> AccessGrantCapability {
        match self {
            Self::CompanionProfile { .. } => AccessGrantCapability::CompanionProfileRead,
            Self::Calendar { .. } => AccessGrantCapability::CalendarDisclosureRead,
            Self::SharedBrief { .. } => AccessGrantCapability::SharedBriefRead,
            Self::ChannelIdentity { .. } => AccessGrantCapability::ChannelIdentityScopedRead,
        }
    }

    /// Returns the granted rung when this scope names the supplied calendar.
    #[must_use]
    pub fn calendar_rung(&self, calendar_ref: &EntityId) -> Option<DisclosureRung> {
        match self {
            Self::Calendar {
                calendar_ref: grant_calendar_ref,
                rung,
            } if grant_calendar_ref.as_bytes() == calendar_ref.as_bytes() => Some(*rung),
            Self::Calendar { .. }
            | Self::CompanionProfile { .. }
            | Self::SharedBrief { .. }
            | Self::ChannelIdentity { .. } => None,
        }
    }
}

/// Capability authorized by an AccessGrant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantCapability {
    /// Read one companion profile.
    CompanionProfileRead,
    /// Read one calendar as a rung projection, never as raw event rows.
    CalendarDisclosureRead,
    /// Read a shared brief after live scope redaction.
    SharedBriefRead,
    /// Read only the named ChannelIdentity mailbox envelope.
    ChannelIdentityScopedRead,
}

impl AccessGrantCapability {
    /// Returns the pinned on-disk string for this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SharedBriefRead => "brief.share.read",
            Self::ChannelIdentityScopedRead => "channel_identity.scoped_read",
            Self::CompanionProfileRead => "companion_profile.read",
            Self::CalendarDisclosureRead => "calendar.disclosure_read",
        }
    }

    /// Parses a pinned on-disk capability string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "brief.share.read" => Some(Self::SharedBriefRead),
            "channel_identity.scoped_read" => Some(Self::ChannelIdentityScopedRead),
            "companion_profile.read" => Some(Self::CompanionProfileRead),
            "calendar.disclosure_read" => Some(Self::CalendarDisclosureRead),
            _ => None,
        }
    }
}

/// AccessGrant lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessGrantStatus {
    /// Grant is live and can authorize a matching access.
    Active,
    /// Grant has been revoked and must fail closed.
    Revoked,
}

impl AccessGrantStatus {
    /// Returns the pinned on-disk string for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// Parses a pinned on-disk status string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "revoked" => Some(Self::Revoked),
            _ => None,
        }
    }
}

/// Vault-resident access grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccessGrant {
    /// Principal receiving access.
    pub principal_ref: EntityId,
    /// Exact resource scope.
    pub scope: AccessGrantScope,
    /// Authorized capability.
    pub capability: AccessGrantCapability,
    /// Grant lifecycle status.
    pub status: AccessGrantStatus,
    /// Creation time in Unix seconds.
    pub created_at: u64,
    /// Revocation time in Unix seconds.
    pub revoked_at: Option<u64>,
}

impl AccessGrant {
    /// Constructs an active companion-profile read grant.
    #[must_use]
    pub const fn companion_profile_read(
        principal_ref: EntityId,
        person_ref: EntityId,
        persona_ref: EntityId,
        created_at: u64,
    ) -> Self {
        Self {
            principal_ref,
            scope: AccessGrantScope::companion_profile(person_ref, persona_ref),
            capability: AccessGrantCapability::CompanionProfileRead,
            status: AccessGrantStatus::Active,
            created_at,
            revoked_at: None,
        }
    }

    /// Constructs an active calendar-disclosure grant.
    ///
    /// `principal_ref` is the audience: DEC-0006 binds one standing grant per
    /// `(calendar × audience)`, and this record is that binding.
    #[must_use]
    pub const fn calendar_disclosure(
        principal_ref: EntityId,
        calendar_ref: EntityId,
        rung: DisclosureRung,
        created_at: u64,
    ) -> Self {
        Self {
            principal_ref,
            scope: AccessGrantScope::calendar(calendar_ref, rung),
            capability: AccessGrantCapability::CalendarDisclosureRead,
            status: AccessGrantStatus::Active,
            created_at,
            revoked_at: None,
        }
    }

    /// Returns a revoked version of this grant.
    pub fn revoked(&self, revoked_at: u64) -> Result<Self> {
        let grant = Self {
            status: AccessGrantStatus::Revoked,
            revoked_at: Some(revoked_at),
            ..self.clone()
        };
        grant.validate()?;
        Ok(grant)
    }

    /// Validates the scope/capability pairing and the revocation invariants.
    ///
    /// A grant whose capability does not match its scope shape is a nonsensical
    /// control-plane state — every reader would answer a different question
    /// about it — so it is rejected here, at the one door every codec, mint,
    /// and revoke path already passes through.
    pub fn validate(&self) -> Result<()> {
        if matches!(self.scope, AccessGrantScope::SharedBrief { .. }) {
            crate::share::validate_shared_brief_grant(self)?;
        }
        if self.capability != self.scope.required_capability() {
            return Err(Error::InvalidAccessGrantBody(
                "scope and capability are not a matched pair",
            ));
        }
        match (self.status, self.revoked_at) {
            (AccessGrantStatus::Active, None) => Ok(()),
            (AccessGrantStatus::Active, Some(_)) => Err(invalid_grant()),
            (AccessGrantStatus::Revoked, Some(revoked_at)) if revoked_at >= self.created_at => {
                Ok(())
            }
            (AccessGrantStatus::Revoked, Some(_)) | (AccessGrantStatus::Revoked, None) => {
                Err(invalid_grant())
            }
        }
    }

    /// Returns whether this grant authorizes the supplied companion profile.
    #[must_use]
    pub fn allows_companion_profile_read(
        &self,
        principal_ref: &EntityId,
        person_ref: &EntityId,
        persona_ref: &EntityId,
    ) -> bool {
        self.status == AccessGrantStatus::Active
            && self.capability == AccessGrantCapability::CompanionProfileRead
            && self.principal_ref.as_bytes() == principal_ref.as_bytes()
            && self
                .scope
                .matches_companion_profile(person_ref, persona_ref)
    }

    /// Returns the rung this grant discloses of `calendar_ref` to
    /// `principal_ref`, or `None` when it authorizes no such read.
    ///
    /// Revoked grants, other principals, other calendars, and non-calendar
    /// capabilities all return `None` — the caller's fail-safe is
    /// [`DisclosureRung::Nothing`].
    #[must_use]
    pub fn calendar_disclosure_rung(
        &self,
        principal_ref: &EntityId,
        calendar_ref: &EntityId,
    ) -> Option<DisclosureRung> {
        if self.status != AccessGrantStatus::Active
            || self.capability != AccessGrantCapability::CalendarDisclosureRead
            || self.principal_ref.as_bytes() != principal_ref.as_bytes()
        {
            return None;
        }
        self.scope.calendar_rung(calendar_ref)
    }
}

/// One row of the calendar-grant registry view.
///
/// The pair, not the bare grant: `grant_ref` is the handle
/// [`Vault::revoke_calendar_access_grant`] takes, so a listed row is directly
/// revocable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CalendarAccessGrantRow {
    /// Entity id of the grant record.
    pub grant_ref: EntityId,
    /// The grant itself.
    pub grant: AccessGrant,
}
