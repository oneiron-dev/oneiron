//! ChannelIdentity binding and fulfillment values with scope strings.

use crate::entity_id::EntityId;

use crate::error::Result;

use super::codec::invalid_identity;

/// Scope at which an identity is bound (OF-347 R2, ARCH-0063 R7).
///
/// [`Self::Actor`] names an AUTHORITY-BEARING ENTITY, not a new entity kind:
/// a named agent is normally an `AGENT_DEF`, and a connector/plumbing actor
/// keeps whatever reference it already had. Whether a someone stands behind
/// that actor is a SEPARATE question answered by an `actor.subject_ref`
/// anchor (see [`crate::subject_model`]) — never by the binding, and never by
/// forking the entity kind.
///
/// `facet_ref` is owned HERE rather than on the connector key record because
/// the facet is the mask worn ON THIS CHANNEL: one actor speaks through many
/// identities and may wear a different face on each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityBinding {
    Actor {
        actor_ref: EntityId,
        /// Type-13 FACET mask worn on this channel; `None` speaks unmasked.
        facet_ref: Option<EntityId>,
    },
    Vault {
        vault_id: u64,
    },
}

impl ChannelIdentityBinding {
    /// Binds an unmasked actor.
    #[must_use]
    pub const fn actor(actor_ref: EntityId) -> Self {
        Self::Actor {
            actor_ref,
            facet_ref: None,
        }
    }

    /// Binds an actor wearing `facet_ref` on this channel.
    #[must_use]
    pub const fn actor_with_facet(actor_ref: EntityId, facet_ref: EntityId) -> Self {
        Self::Actor {
            actor_ref,
            facet_ref: Some(facet_ref),
        }
    }

    /// Pre-INB-06 spelling of [`Self::actor`], kept because "the agent bound
    /// to this identity" is exactly an unmasked actor — the rename did not
    /// change what any existing caller meant.
    #[must_use]
    pub const fn agent(agent_ref: EntityId) -> Self {
        Self::actor(agent_ref)
    }

    #[must_use]
    pub const fn vault(vault_id: u64) -> Self {
        Self::Vault { vault_id }
    }

    /// Actor this identity speaks for, when it is actor-bound.
    #[must_use]
    pub const fn actor_ref(self) -> Option<EntityId> {
        match self {
            Self::Actor { actor_ref, .. } => Some(actor_ref),
            Self::Vault { .. } => None,
        }
    }

    /// Facet mask worn on this channel, when one is bound.
    #[must_use]
    pub const fn facet_ref(self) -> Option<EntityId> {
        match self {
            Self::Actor { facet_ref, .. } => facet_ref,
            Self::Vault { .. } => None,
        }
    }

    #[must_use]
    pub const fn scope_str(self) -> &'static str {
        match self {
            Self::Actor { .. } => "actor",
            Self::Vault { .. } => "vault",
        }
    }

    pub(super) fn validate(self) -> Result<()> {
        match self {
            Self::Actor { .. } => Ok(()),
            Self::Vault { vault_id: 0 } => Err(invalid_identity()),
            Self::Vault { .. } => Ok(()),
        }
    }
}

/// Async fulfillment lane for PENDING_FULFILLMENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ChannelIdentityFulfillment {
    Api,
    Manual,
    Review,
}

impl ChannelIdentityFulfillment {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Manual => "manual",
            Self::Review => "review",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "api" => Some(Self::Api),
            "manual" => Some(Self::Manual),
            "review" => Some(Self::Review),
            _ => None,
        }
    }
}
