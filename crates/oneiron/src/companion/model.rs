//! Typed companion record domain: kinds, scopes, subjects, provenance, and records.

use super::codec::invalid_companion;
use crate::claim::{
    COMPANION_EXPRESSION_PROFESSIONAL, COMPANION_EXPRESSION_UNRESTRICTED, COMPANION_EXPRESSION_WARM,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Companion record kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionRecordKind {
    /// PERSON-targeted expression/task key; not a companion record body.
    Persona,
    /// A relationship record between two entities in a companion scope.
    Relationship,
}

impl CompanionRecordKind {
    /// Returns the pinned on-disk string for this record kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persona => "persona",
            Self::Relationship => "relationship",
        }
    }

    /// Parses a pinned on-disk record kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "persona" => Some(Self::Persona),
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

/// PERSON or relationship subject addressed by an expression or task key.
/// Companion record bodies admit relationship subjects only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionSubject {
    /// PERSON identity target for expression and task keys.
    Persona { persona_ref: EntityId },
    /// Relationship record subject.
    Relationship {
        source_ref: EntityId,
        target_ref: EntityId,
    },
}

impl CompanionSubject {
    /// Constructs a persona record subject.
    #[must_use]
    pub const fn persona(persona_ref: EntityId) -> Self {
        Self::Persona { persona_ref }
    }

    /// Constructs a relationship record subject.
    #[must_use]
    pub const fn relationship(source_ref: EntityId, target_ref: EntityId) -> Self {
        Self::Relationship {
            source_ref,
            target_ref,
        }
    }

    /// Returns this subject's record kind.
    #[must_use]
    pub const fn kind(&self) -> CompanionRecordKind {
        match self {
            Self::Persona { .. } => CompanionRecordKind::Persona,
            Self::Relationship { .. } => CompanionRecordKind::Relationship,
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

/// Stable lookup key for companion records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompanionRecordKey {
    /// Scope boundary.
    pub scope: CompanionScope,
    /// Relationship or PERSON target.
    pub subject: CompanionSubject,
}

impl CompanionRecordKey {
    /// Constructs a PERSON-targeted expression or task key.
    #[must_use]
    pub const fn persona(scope: CompanionScope, persona_ref: EntityId) -> Self {
        Self {
            scope,
            subject: CompanionSubject::persona(persona_ref),
        }
    }

    /// Constructs a relationship lookup key.
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
