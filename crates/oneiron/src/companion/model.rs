//! Typed companion record domain: kinds, scopes, subjects, provenance, and records.

use super::codec::invalid_companion;
use crate::claim::{
    COMPANION_EXPRESSION_PROFESSIONAL, COMPANION_EXPRESSION_UNRESTRICTED,
    COMPANION_EXPRESSION_WARM, ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::write_envelope::WriteEnvelope;
use rmpv::Value;

/// Companion record kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionRecordKind {
    /// A persona record for neutral @Oneiron or a scoped companion.
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

/// Persona or relationship subject addressed by a companion record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionSubject {
    /// Persona record subject.
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

/// Typed lifecycle event carried by companion persona/relationship records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionLifecycleEventKind {
    /// Record was created as active.
    Created,
    /// Record was superseded by a later active record.
    Superseded,
    /// Record was explicitly retired/retracted.
    Retired,
    /// Record was explicitly revived as active.
    Revived,
}

impl CompanionLifecycleEventKind {
    /// Returns the pinned on-disk string for this lifecycle event kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Superseded => "superseded",
            Self::Retired => "retired",
            Self::Revived => "revived",
        }
    }

    /// Parses a pinned on-disk lifecycle event kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "superseded" => Some(Self::Superseded),
            "retired" => Some(Self::Retired),
            "revived" => Some(Self::Revived),
            _ => None,
        }
    }

    /// Returns the record lifecycle status produced by this event.
    #[must_use]
    pub const fn lifecycle_status(self) -> ClaimLifecycleStatus {
        match self {
            Self::Created | Self::Revived => ClaimLifecycleStatus::Active,
            Self::Superseded => ClaimLifecycleStatus::Superseded,
            Self::Retired => ClaimLifecycleStatus::Retracted,
        }
    }
}

/// One auditable companion lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompanionLifecycleEvent {
    /// Event discriminator.
    pub kind: CompanionLifecycleEventKind,
    /// Event timestamp in Unix seconds.
    pub at: u64,
}

impl CompanionLifecycleEvent {
    /// Constructs a created lifecycle event.
    #[must_use]
    pub const fn created(at: u64) -> Self {
        Self {
            kind: CompanionLifecycleEventKind::Created,
            at,
        }
    }

    /// Constructs a superseded lifecycle event.
    #[must_use]
    pub const fn superseded(at: u64) -> Self {
        Self {
            kind: CompanionLifecycleEventKind::Superseded,
            at,
        }
    }

    /// Constructs a retired lifecycle event.
    #[must_use]
    pub const fn retired(at: u64) -> Self {
        Self {
            kind: CompanionLifecycleEventKind::Retired,
            at,
        }
    }

    /// Constructs a revived lifecycle event.
    #[must_use]
    pub const fn revived(at: u64) -> Self {
        Self {
            kind: CompanionLifecycleEventKind::Revived,
            at,
        }
    }

    /// Returns the record lifecycle status produced by this event.
    #[must_use]
    pub const fn lifecycle_status(self) -> ClaimLifecycleStatus {
        self.kind.lifecycle_status()
    }
}

/// Export policy carried by a companion record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CompanionExportClassification {
    /// Kept local to this vault unless a later policy explicitly rewrites it.
    LocalOnly,
    /// Safe for user-directed portable export.
    Portable,
    /// Scoped to shared-vault replication/export surfaces.
    SharedVault,
}

impl CompanionExportClassification {
    /// Returns the pinned on-disk string for this export classification.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::Portable => "portable",
            Self::SharedVault => "shared_vault",
        }
    }

    /// Parses a pinned on-disk export classification string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local_only" => Some(Self::LocalOnly),
            "portable" => Some(Self::Portable),
            "shared_vault" => Some(Self::SharedVault),
            _ => None,
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

/// Provenance stamp carried by companion records.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CompanionProvenance {
    /// Actor responsible for the record.
    pub actor_ref: EntityId,
    /// Actor class asserted at write time.
    pub actor_class: EdgeActorClass,
    /// Provenance source.
    pub source: ClaimSource,
    /// Approval status of the write that created this record.
    pub approval: ClaimApprovalStatus,
    /// Opaque provenance payload.
    pub value: Value,
}

impl CompanionProvenance {
    /// Constructs a provenance stamp.
    #[must_use]
    pub fn new(
        actor_ref: EntityId,
        actor_class: EdgeActorClass,
        source: ClaimSource,
        approval: ClaimApprovalStatus,
        value: Value,
    ) -> Self {
        Self {
            actor_ref,
            actor_class,
            source,
            approval,
            value,
        }
    }

    /// Constructs a companion provenance stamp from a write envelope.
    #[must_use]
    pub fn from_envelope(envelope: &WriteEnvelope) -> Self {
        let actor = envelope.actor();
        Self::new(
            actor.entity_ref(),
            actor.actor_class(),
            envelope.source(),
            envelope.approval(),
            envelope.provenance().value().clone(),
        )
    }

    pub(super) fn validate(&self) -> Result<()> {
        if matches!(self.value, Value::Nil) {
            return Err(invalid_companion(
                "companion provenance value must not be nil",
            ));
        }
        Ok(())
    }
}

/// First-class companion relationship/persona record.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CompanionRecord {
    /// Scope boundary for this record.
    pub scope: CompanionScope,
    /// Persona or relationship subject.
    pub subject: CompanionSubject,
    /// Opaque record payload.
    pub value: Value,
    /// Provenance stamp for this record.
    pub provenance: CompanionProvenance,
    /// Lifecycle state.
    pub lifecycle: ClaimLifecycleStatus,
    /// Auditable lifecycle transitions applied to this record.
    pub lifecycle_events: Vec<CompanionLifecycleEvent>,
    /// Export classification.
    pub export_classification: CompanionExportClassification,
}

impl CompanionRecord {
    /// Constructs a persona record with active lifecycle.
    #[must_use]
    pub fn persona(
        scope: CompanionScope,
        persona_ref: EntityId,
        value: Value,
        provenance: CompanionProvenance,
        export_classification: CompanionExportClassification,
    ) -> Self {
        Self::new(
            scope,
            CompanionSubject::persona(persona_ref),
            value,
            provenance,
            ClaimLifecycleStatus::Active,
            export_classification,
        )
    }

    /// Constructs a relationship record with active lifecycle.
    #[must_use]
    pub fn relationship(
        scope: CompanionScope,
        source_ref: EntityId,
        target_ref: EntityId,
        value: Value,
        provenance: CompanionProvenance,
        export_classification: CompanionExportClassification,
    ) -> Self {
        Self::new(
            scope,
            CompanionSubject::relationship(source_ref, target_ref),
            value,
            provenance,
            ClaimLifecycleStatus::Active,
            export_classification,
        )
    }

    /// Constructs a record from already-typed fields.
    #[must_use]
    pub fn new(
        scope: CompanionScope,
        subject: CompanionSubject,
        value: Value,
        provenance: CompanionProvenance,
        lifecycle: ClaimLifecycleStatus,
        export_classification: CompanionExportClassification,
    ) -> Self {
        Self {
            scope,
            subject,
            value,
            provenance,
            lifecycle,
            lifecycle_events: Vec::new(),
            export_classification,
        }
    }

    /// Returns this record's kind.
    #[must_use]
    pub const fn kind(&self) -> CompanionRecordKind {
        self.subject.kind()
    }

    /// Returns this record's lookup key.
    #[must_use]
    pub fn key(&self) -> CompanionRecordKey {
        CompanionRecordKey {
            scope: self.scope.clone(),
            subject: self.subject.clone(),
        }
    }

    /// Validates the typed record before encoding/registering.
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        self.provenance.validate()?;
        if matches!(self.value, Value::Nil) {
            return Err(invalid_companion("companion record value must not be nil"));
        }
        if let Some(event) = self.lifecycle_events.last()
            && event.lifecycle_status() != self.lifecycle
        {
            return Err(invalid_companion(
                "companion lifecycle event does not match record lifecycle",
            ));
        }
        Ok(())
    }

    /// Validates lifecycle evidence required for current-schema persisted bodies.
    pub fn validate_current_schema_lifecycle_events(&self) -> Result<()> {
        self.validate()?;
        if self.lifecycle_events.is_empty() {
            return Err(invalid_companion(
                "companion lifecycle events required for current schema",
            ));
        }
        Ok(())
    }

    /// Returns the terminal lifecycle event kind, if present.
    #[must_use]
    pub fn terminal_lifecycle_event_kind(&self) -> Option<CompanionLifecycleEventKind> {
        self.lifecycle_events.last().map(|event| event.kind)
    }

    /// Returns a copy of this active record with canonical created history.
    pub fn created_at(&self, created_at: u64) -> Result<Self> {
        if self.lifecycle != ClaimLifecycleStatus::Active {
            return Err(invalid_companion(
                "companion record create requires active record",
            ));
        }
        let mut record = self.clone();
        record.lifecycle_events = vec![CompanionLifecycleEvent::created(created_at)];
        record.validate_current_schema_lifecycle_events()?;
        Ok(record)
    }

    /// Returns a copy of this record with the lifecycle retired/retracted
    /// without stamping a lifecycle event.
    ///
    /// Use [`Self::retired_at`] for auditable retire transitions.
    pub fn retired(&self) -> Result<Self> {
        if self.lifecycle != ClaimLifecycleStatus::Active {
            return Err(invalid_companion(
                "companion record retire requires active record",
            ));
        }
        if !self.lifecycle_events.is_empty() {
            return Err(invalid_companion(
                "companion record retire requires explicit timestamp",
            ));
        }
        let mut record = self.clone();
        record.lifecycle = ClaimLifecycleStatus::Retracted;
        record.validate()?;
        Ok(record)
    }

    /// Returns a copy of this record with a stamped retired lifecycle event.
    pub fn retired_at(&self, retired_at: u64) -> Result<Self> {
        if self.lifecycle != ClaimLifecycleStatus::Active {
            return Err(invalid_companion(
                "companion record retire requires active record",
            ));
        }
        let mut record = self.clone();
        record.lifecycle = ClaimLifecycleStatus::Retracted;
        record
            .lifecycle_events
            .push(CompanionLifecycleEvent::retired(retired_at));
        record.validate()?;
        Ok(record)
    }

    /// Returns a copy of this record revived to active lifecycle.
    pub fn revived_at(&self, revived_at: u64) -> Result<Self> {
        if self.lifecycle != ClaimLifecycleStatus::Retracted {
            return Err(invalid_companion(
                "companion record revive requires retired record",
            ));
        }
        let mut record = self.clone();
        record.lifecycle = ClaimLifecycleStatus::Active;
        record
            .lifecycle_events
            .push(CompanionLifecycleEvent::revived(revived_at));
        record.validate()?;
        Ok(record)
    }
}

/// Stable lookup key for companion records.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompanionRecordKey {
    /// Scope boundary.
    pub scope: CompanionScope,
    /// Persona or relationship subject.
    pub subject: CompanionSubject,
}

impl CompanionRecordKey {
    /// Constructs a persona lookup key.
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
