//! Typed companion task domain: scopes, PERSON/relationship subjects, and task keys.

use super::codec::invalid_companion;
use crate::claim::{
    COMPANION_EXPRESSION_PROFESSIONAL, COMPANION_EXPRESSION_UNRESTRICTED, COMPANION_EXPRESSION_WARM,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Companion task subject kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionSubjectKind {
    /// One PERSON identity.
    Person,
    /// A relationship between two entities in a companion scope.
    Relationship,
}

impl CompanionSubjectKind {
    /// Returns the pinned payload string for this subject kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Relationship => "relationship",
        }
    }

    /// Parses a pinned payload subject kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "person" => Some(Self::Person),
            "relationship" => Some(Self::Relationship),
            _ => None,
        }
    }
}

/// Companion visibility boundary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionScope {
    /// Neutral @Oneiron scope, not bound to a person or shared vault.
    Neutral,
    /// Per-person companion scope.
    Personal { person_ref: EntityId },
    /// Shared-vault companion scope.
    SharedVault { vault_id: u64 },
}

impl CompanionScope {
    /// Constructs the neutral @Oneiron scope.
    #[must_use]
    pub const fn neutral() -> Self {
        Self::Neutral
    }

    /// Constructs a per-person companion scope.
    #[must_use]
    pub const fn personal(person_ref: EntityId) -> Self {
        Self::Personal { person_ref }
    }

    /// Constructs a shared-vault companion scope.
    #[must_use]
    pub const fn shared_vault(vault_id: u64) -> Self {
        Self::SharedVault { vault_id }
    }

    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::SharedVault { vault_id: 0 } => Err(invalid_companion(
                "shared-vault companion scope requires nonzero vault_id",
            )),
            Self::Neutral | Self::Personal { .. } | Self::SharedVault { .. } => Ok(()),
        }
    }

    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Neutral => "neutral",
            Self::Personal { .. } => "personal",
            Self::SharedVault { .. } => "shared_vault",
        }
    }
}

/// PERSON or relationship subject addressed by a companion task key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionSubject {
    /// One PERSON identity; admission requires it to be a live PERSON.
    Person { person_ref: EntityId },
    /// Relationship subject.
    Relationship {
        source_ref: EntityId,
        target_ref: EntityId,
    },
}

impl CompanionSubject {
    /// Constructs a PERSON subject.
    #[must_use]
    pub const fn person(person_ref: EntityId) -> Self {
        Self::Person { person_ref }
    }

    /// Constructs a relationship subject.
    #[must_use]
    pub const fn relationship(source_ref: EntityId, target_ref: EntityId) -> Self {
        Self::Relationship {
            source_ref,
            target_ref,
        }
    }

    /// Returns this subject's kind.
    #[must_use]
    pub const fn kind(&self) -> CompanionSubjectKind {
        match self {
            Self::Person { .. } => CompanionSubjectKind::Person,
            Self::Relationship { .. } => CompanionSubjectKind::Relationship,
        }
    }
}

/// Companion expression mode for persona/relationship state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionExpression {
    /// Professional, bounded interaction style.
    Professional,
    /// Warm companion style.
    Warm,
    /// Unrestricted style selected by policy or user intent.
    Unrestricted,
}

impl CompanionExpression {
    /// Returns the pinned on-disk string for this expression mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Professional => COMPANION_EXPRESSION_PROFESSIONAL,
            Self::Warm => COMPANION_EXPRESSION_WARM,
            Self::Unrestricted => COMPANION_EXPRESSION_UNRESTRICTED,
        }
    }

    /// Parses a pinned expression mode string. Unknown future values fail closed.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            COMPANION_EXPRESSION_PROFESSIONAL => Some(Self::Professional),
            COMPANION_EXPRESSION_WARM => Some(Self::Warm),
            COMPANION_EXPRESSION_UNRESTRICTED => Some(Self::Unrestricted),
            _ => None,
        }
    }

    /// Parses a pinned expression mode string into a typed error.
    pub fn parse_closed(value: &str) -> Result<Self> {
        Self::parse(value).ok_or(invalid_companion(
            "expression must be professional|warm|unrestricted",
        ))
    }
}

/// Stable target of a companion task: a scope and a PERSON or relationship.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompanionTaskKey {
    /// Scope boundary.
    pub scope: CompanionScope,
    /// PERSON or relationship target.
    pub subject: CompanionSubject,
}

impl CompanionTaskKey {
    /// Constructs a PERSON-targeted task key.
    #[must_use]
    pub const fn person(scope: CompanionScope, person_ref: EntityId) -> Self {
        Self {
            scope,
            subject: CompanionSubject::person(person_ref),
        }
    }

    /// Constructs a relationship task key.
    #[must_use]
    pub const fn relationship(
        scope: CompanionScope,
        source_ref: EntityId,
        target_ref: EntityId,
    ) -> Self {
        Self {
            scope,
            subject: CompanionSubject::relationship(source_ref, target_ref),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.scope.validate()
    }
}
