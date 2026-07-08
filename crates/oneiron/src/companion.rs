//! Companion relationship/persona record substrate.
//!
//! This module is intentionally storage-agnostic: it defines the typed record
//! shape, canonical MessagePack body encoding, and a small register used by
//! callers/tests before later API or vault wiring.

use std::collections::BTreeMap;
use std::io::Cursor;

use rmpv::Value;
use serde_json::Value as JsonValue;

use crate::Vault;
use crate::claim::{
    COMPANION_EXPRESSION_PROFESSIONAL, COMPANION_EXPRESSION_UNRESTRICTED,
    COMPANION_EXPRESSION_WARM, ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource,
};
use crate::error::{Error, Result};
use crate::job_queue::{
    ClaimJob, ClaimOutcome, CompleteJob, CompleteOutcome, EnqueueJob, EnqueueOutcome, FailJob,
    FailOutcome, JobId, JobQueue, JobRecord, RetryJob, RetryOutcome,
};

use crate::types::{EdgeActorClass, EntityId, WriteEnvelope};

/// Dedicated companion-register structural kind byte.
///
/// The companion pack owns bytes 64..=79; this API pins the register substrate
/// to the first byte in that band and registers it lazily per vault.
pub const ENTITY_TYPE_COMPANION_REGISTER: u8 = crate::types::TYPE_BYTE_BAND_COMPANION_START;
/// Short-id prefix for companion-register rows.
pub const COMPANION_REGISTER_SHORT_ID_PREFIX: &str = "cr";
/// Pack id recorded in the vault-scoped structural-kind registry.
pub const COMPANION_REGISTER_PACK_ID: &str = "oneiron-companion-register";
/// Current companion record body schema version.
pub const COMPANION_RECORD_SCHEMA_VERSION: u64 = 2;
const COMPANION_RECORD_SCHEMA_VERSION_V1: u64 = 1;

/// Pinned on-disk MessagePack key set for companion record bodies.
pub const COMPANION_RECORD_BODY_KEYS: [&str; 9] = [
    "schema_version",
    "kind",
    "scope",
    "subject",
    "value",
    "provenance",
    "lifecycle",
    "export",
    "lifecycle_events",
];

const KEY_SCHEMA_VERSION: &str = COMPANION_RECORD_BODY_KEYS[0];
const KEY_KIND: &str = COMPANION_RECORD_BODY_KEYS[1];
const KEY_SCOPE: &str = COMPANION_RECORD_BODY_KEYS[2];
const KEY_SUBJECT: &str = COMPANION_RECORD_BODY_KEYS[3];
const KEY_VALUE: &str = COMPANION_RECORD_BODY_KEYS[4];
const KEY_PROVENANCE: &str = COMPANION_RECORD_BODY_KEYS[5];
const KEY_LIFECYCLE: &str = COMPANION_RECORD_BODY_KEYS[6];
const KEY_EXPORT: &str = COMPANION_RECORD_BODY_KEYS[7];
const KEY_LIFECYCLE_EVENTS: &str = COMPANION_RECORD_BODY_KEYS[8];

const SCOPE_KEYS: [&str; 3] = ["kind", "person_ref", "vault_id"];
const SUBJECT_KEYS: [&str; 3] = ["kind", "persona_ref", "relationship_ref"];
const RELATIONSHIP_REF_KEYS: [&str; 2] = ["source_ref", "target_ref"];
const PROVENANCE_KEYS: [&str; 5] = ["actor_ref", "actor_class", "source", "approval", "value"];
const LIFECYCLE_EVENT_KEYS: [&str; 2] = ["kind", "at"];

/// Generic JobQueue kind used by all durable companion background tasks.
pub const COMPANION_TASK_JOB_KIND: &str = "companion_task";
/// Current companion task payload schema version.
pub const COMPANION_TASK_PAYLOAD_SCHEMA_VERSION: u64 = 1;
/// Pinned on-disk MessagePack key set for companion task payloads.
pub const COMPANION_TASK_PAYLOAD_KEYS: [&str; 4] = ["schema_version", "task", "scope", "subject"];
const ERR_INVALID_COMPANION_TASK_PAYLOAD: &str = "invalid companion task payload";

const KEY_TASK_SCHEMA_VERSION: &str = COMPANION_TASK_PAYLOAD_KEYS[0];
const KEY_TASK: &str = COMPANION_TASK_PAYLOAD_KEYS[1];
const KEY_TASK_SCOPE: &str = COMPANION_TASK_PAYLOAD_KEYS[2];
const KEY_TASK_SUBJECT: &str = COMPANION_TASK_PAYLOAD_KEYS[3];

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

    fn validate(&self) -> Result<()> {
        match self {
            Self::SharedVault { vault_id: 0 } => Err(invalid_companion(
                "shared-vault companion scope requires nonzero vault_id",
            )),
            Self::Neutral | Self::Personal { .. } | Self::SharedVault { .. } => Ok(()),
        }
    }

    fn as_str(&self) -> &'static str {
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

    fn validate(&self) -> Result<()> {
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

/// Source evidence used to resolve an effective companion scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionScopeResolutionSource {
    /// No active companion record matched; neutral @Oneiron remains in effect.
    NeutralDefault,
    /// An active persona record selected the scope.
    PersonaRecord,
    /// An active relationship record selected the scope.
    RelationshipRecord,
    /// Active persona and relationship records both selected the same scope.
    PersonaAndRelationshipRecords,
}

impl CompanionScopeResolutionSource {
    /// Returns the stable wire/debug string for this resolution source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeutralDefault => "neutral_default",
            Self::PersonaRecord => "persona_record",
            Self::RelationshipRecord => "relationship_record",
            Self::PersonaAndRelationshipRecords => "persona_and_relationship_records",
        }
    }
}

/// Effective companion scope and expression boundary resolved from records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionScopeResolution {
    /// Effective scope boundary for this companion assembly.
    pub scope: CompanionScope,
    /// Active persona record key that selected or contributes to this scope.
    pub persona_key: Option<CompanionRecordKey>,
    /// Active relationship record key that selected or contributes to this scope.
    pub relationship_key: Option<CompanionRecordKey>,
    /// Effective expression register value for the resolved boundary.
    pub expression: CompanionExpression,
    /// Evidence class used for the scope decision.
    pub source: CompanionScopeResolutionSource,
}

/// In-memory companion record register keyed by `(scope, subject)`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CompanionRegister {
    records: BTreeMap<CompanionRecordKey, CompanionRecord>,
}

impl CompanionRegister {
    /// Creates an empty register.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: BTreeMap::new(),
        }
    }

    /// Registers a record, returning the previous record for the same key.
    pub fn register(&mut self, record: CompanionRecord) -> Result<Option<CompanionRecord>> {
        record.validate()?;
        Ok(self.records.insert(record.key(), record))
    }

    /// Looks up a record by key.
    #[must_use]
    pub fn lookup(&self, key: &CompanionRecordKey) -> Option<&CompanionRecord> {
        self.records.get(key)
    }

    /// Looks up an active record by key.
    #[must_use]
    pub fn lookup_active(&self, key: &CompanionRecordKey) -> Option<&CompanionRecord> {
        self.lookup(key)
            .filter(|record| record.lifecycle == ClaimLifecycleStatus::Active)
    }

    /// Looks up a persona record in a specific scope.
    #[must_use]
    pub fn lookup_persona(
        &self,
        scope: &CompanionScope,
        persona_ref: EntityId,
    ) -> Option<&CompanionRecord> {
        self.lookup(&CompanionRecordKey::persona(scope.clone(), persona_ref))
    }

    /// Looks up a relationship record in a specific scope.
    #[must_use]
    pub fn lookup_relationship(
        &self,
        scope: &CompanionScope,
        source_ref: EntityId,
        target_ref: EntityId,
    ) -> Option<&CompanionRecord> {
        self.lookup(&CompanionRecordKey::relationship(
            scope.clone(),
            source_ref,
            target_ref,
        ))
    }

    /// Iterates over records in a specific scope.
    pub fn records_in_scope<'a>(
        &'a self,
        scope: &'a CompanionScope,
    ) -> impl Iterator<Item = &'a CompanionRecord> + 'a {
        self.records
            .iter()
            .filter(move |(key, _)| &key.scope == scope)
            .map(|(_, record)| record)
    }

    /// Iterates over all records in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&CompanionRecordKey, &CompanionRecord)> {
        self.records.iter()
    }

    /// Resolves the effective neutral/personal companion scope from active
    /// persona and relationship records.
    ///
    /// Personal scope takes precedence only when an active record exists for
    /// the requested person. Expression values are read only from the active
    /// record keys that contributed to the resolved scope, so orphan or
    /// cross-scope expression entries cannot widen the boundary.
    #[must_use]
    pub fn resolve_companion_scope(
        &self,
        expressions: &CompanionExpressionRegister,
        person_ref: Option<EntityId>,
        persona_ref: Option<EntityId>,
        relationship_ref: Option<(EntityId, EntityId)>,
    ) -> CompanionScopeResolution {
        let neutral = CompanionScope::neutral();
        if let Some(person_ref) = person_ref {
            let personal = CompanionScope::personal(person_ref);
            if let Some(resolution) = self.resolve_companion_scope_in(
                &personal,
                expressions,
                persona_ref,
                relationship_ref,
            ) {
                return resolution;
            }
        }

        self.resolve_companion_scope_in(&neutral, expressions, persona_ref, relationship_ref)
            .unwrap_or(CompanionScopeResolution {
                scope: neutral,
                persona_key: None,
                relationship_key: None,
                expression: CompanionExpression::Professional,
                source: CompanionScopeResolutionSource::NeutralDefault,
            })
    }

    fn resolve_companion_scope_in(
        &self,
        scope: &CompanionScope,
        expressions: &CompanionExpressionRegister,
        persona_ref: Option<EntityId>,
        relationship_ref: Option<(EntityId, EntityId)>,
    ) -> Option<CompanionScopeResolution> {
        let persona_key = persona_ref
            .map(|persona_ref| CompanionRecordKey::persona(scope.clone(), persona_ref))
            .filter(|key| self.lookup_active(key).is_some());
        let relationship_key = relationship_ref
            .map(|(source_ref, target_ref)| {
                CompanionRecordKey::relationship(scope.clone(), source_ref, target_ref)
            })
            .filter(|key| self.lookup_active(key).is_some());

        let source = match (persona_key.is_some(), relationship_key.is_some()) {
            (true, true) => CompanionScopeResolutionSource::PersonaAndRelationshipRecords,
            (true, false) => CompanionScopeResolutionSource::PersonaRecord,
            (false, true) => CompanionScopeResolutionSource::RelationshipRecord,
            (false, false) => return None,
        };
        let expression = relationship_key
            .as_ref()
            .and_then(|key| expressions.lookup(key))
            .or_else(|| persona_key.as_ref().and_then(|key| expressions.lookup(key)))
            .unwrap_or(CompanionExpression::Professional);

        Some(CompanionScopeResolution {
            scope: scope.clone(),
            persona_key,
            relationship_key,
            expression,
            source,
        })
    }

    /// Returns the number of records in the register.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns whether the register is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// In-memory expression register keyed by companion persona/relationship.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CompanionExpressionRegister {
    expressions: BTreeMap<CompanionRecordKey, CompanionExpression>,
}

impl CompanionExpressionRegister {
    /// Creates an empty expression register.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expressions: BTreeMap::new(),
        }
    }

    /// Updates the expression for a companion persona/relationship key.
    pub fn update(
        &mut self,
        key: CompanionRecordKey,
        expression: CompanionExpression,
    ) -> Result<Option<CompanionExpression>> {
        key.validate()?;
        Ok(self.expressions.insert(key, expression))
    }

    /// Looks up an expression by key.
    #[must_use]
    pub fn lookup(&self, key: &CompanionRecordKey) -> Option<CompanionExpression> {
        self.expressions.get(key).copied()
    }

    /// Looks up a persona expression in a specific scope.
    #[must_use]
    pub fn lookup_persona(
        &self,
        scope: &CompanionScope,
        persona_ref: EntityId,
    ) -> Option<CompanionExpression> {
        self.lookup(&CompanionRecordKey::persona(scope.clone(), persona_ref))
    }

    /// Looks up a relationship expression in a specific scope.
    #[must_use]
    pub fn lookup_relationship(
        &self,
        scope: &CompanionScope,
        source_ref: EntityId,
        target_ref: EntityId,
    ) -> Option<CompanionExpression> {
        self.lookup(&CompanionRecordKey::relationship(
            scope.clone(),
            source_ref,
            target_ref,
        ))
    }

    /// Iterates over expression entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&CompanionRecordKey, CompanionExpression)> {
        self.expressions
            .iter()
            .map(|(key, expression)| (key, *expression))
    }

    /// Returns the number of expression entries in the register.
    #[must_use]
    pub fn len(&self) -> usize {
        self.expressions.len()
    }

    /// Returns whether the register is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.expressions.is_empty()
    }
}

/// Companion background task family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CompanionTaskKind {
    /// Rebuild or refresh context assembly state for a companion record.
    Context,
    /// Refresh derived profile/persona state for a companion record.
    Profile,
    /// Consolidate companion memory material for a companion record.
    Memory,
    /// Generate a goodbye artifact after an amicable relationship ending.
    GoodbyeArtifact,
}

impl CompanionTaskKind {
    /// Returns the pinned payload string for this companion task kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::Profile => "profile",
            Self::Memory => "memory",
            Self::GoodbyeArtifact => "goodbye_artifact",
        }
    }

    /// Parses a pinned companion task kind string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "context" => Some(Self::Context),
            "profile" => Some(Self::Profile),
            "memory" => Some(Self::Memory),
            "goodbye_artifact" => Some(Self::GoodbyeArtifact),
            _ => None,
        }
    }
}

/// Inputs controlling relationship-ending teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndCompanionRelationship {
    pub ended_at: u64,
    pub ended_badly: bool,
    pub run_id: Option<String>,
}

/// Result of relationship-ending teardown.
#[derive(Debug, Clone, PartialEq)]
pub struct EndCompanionRelationshipOutcome {
    pub record: CompanionRecord,
    pub goodbye_artifact: Option<EnqueueCompanionTaskOutcome>,
    pub already_ended: bool,
}

/// Typed payload stored on durable companion task job rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTask {
    pub kind: CompanionTaskKind,
    pub key: CompanionRecordKey,
}

impl CompanionTask {
    /// Constructs a companion task, validating the referenced companion key.
    pub fn new(kind: CompanionTaskKind, key: CompanionRecordKey) -> Result<Self> {
        key.validate()?;
        Ok(Self { kind, key })
    }

    /// Stable advisory dedupe key for this task target.
    #[must_use]
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.kind.as_str(),
            companion_scope_dedupe_key(&self.key.scope),
            companion_subject_dedupe_key(&self.key.subject)
        )
    }
}

/// Decoded companion task plus its backing durable JobQueue row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionTaskStatus {
    pub job: JobRecord,
    pub task: CompanionTask,
}

/// Input for enqueuing a companion task through the generic JobQueue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueueCompanionTask {
    pub task: CompanionTask,
    pub run_id: Option<String>,
    pub now: u64,
}

/// Typed companion enqueue outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnqueueCompanionTaskOutcome {
    Enqueued(CompanionTaskStatus),
    Existing(CompanionTaskStatus),
}

/// Input for claiming the next queued companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimCompanionTask {
    pub lease_owner: String,
    pub now: u64,
}

/// Typed companion claim outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimCompanionTaskOutcome {
    Empty,
    Claimed(Box<CompanionTaskStatus>),
}

/// Input for completing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteCompanionTask {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub now: u64,
}

/// Typed companion complete outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteCompanionTaskOutcome {
    Completed(CompanionTaskStatus),
    AlreadyCompleted(CompanionTaskStatus),
}

/// Input for terminally failing a leased companion task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailCompanionTask {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub reason: String,
    pub now: u64,
}

/// Typed companion fail outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailCompanionTaskOutcome {
    Failed(CompanionTaskStatus),
    AlreadyFailed(CompanionTaskStatus),
}

/// Input for requeuing a leased companion task after a retryable failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryCompanionTask {
    pub id: JobId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub backoff_until: u64,
    pub last_error: Option<String>,
    pub now: u64,
}

/// Typed companion retry outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryCompanionTaskOutcome {
    Retried(CompanionTaskStatus),
}

/// Companion-specific facade over the generic durable JobQueue.
pub struct CompanionQueue<'a> {
    jobs: JobQueue<'a>,
}

impl<'a> CompanionQueue<'a> {
    /// Opens a companion queue handle over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            jobs: JobQueue::new(vault),
        }
    }

    /// Enqueues a companion task as a generic durable job row.
    pub fn enqueue(&self, input: EnqueueCompanionTask) -> Result<EnqueueCompanionTaskOutcome> {
        let payload = encode_companion_task_payload(&input.task)?;
        let outcome = self.jobs.enqueue(EnqueueJob {
            kind: COMPANION_TASK_JOB_KIND.to_owned(),
            payload,
            dedupe_key: Some(input.task.dedupe_key()),
            run_id: input.run_id,
            now: input.now,
        })?;
        match outcome {
            EnqueueOutcome::Enqueued(record) => {
                decode_companion_task_status(record).map(EnqueueCompanionTaskOutcome::Enqueued)
            }
            EnqueueOutcome::Existing(record) => {
                decode_companion_task_status(record).map(EnqueueCompanionTaskOutcome::Existing)
            }
        }
    }

    /// Claims the oldest queued companion task without leasing unrelated jobs.
    pub fn claim(&self, input: ClaimCompanionTask) -> Result<ClaimCompanionTaskOutcome> {
        loop {
            match self.jobs.claim_kind(
                COMPANION_TASK_JOB_KIND,
                ClaimJob {
                    lease_owner: input.lease_owner.clone(),
                    now: input.now,
                },
            )? {
                ClaimOutcome::Empty => return Ok(ClaimCompanionTaskOutcome::Empty),
                ClaimOutcome::Claimed(record) => match decode_companion_task_status(record.clone())
                {
                    Ok(status) => return Ok(ClaimCompanionTaskOutcome::Claimed(Box::new(status))),
                    Err(_) => {
                        self.fail_undecodable_claimed_task(&record, &input.lease_owner, input.now)?;
                    }
                },
            }
        }
    }

    /// Completes a leased companion task through the generic JobQueue.
    pub fn complete(&self, input: CompleteCompanionTask) -> Result<CompleteCompanionTaskOutcome> {
        self.ensure_companion_job_id(input.id)?;
        let outcome = self.jobs.complete(CompleteJob {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            now: input.now,
        })?;
        match outcome {
            CompleteOutcome::Completed(record) => {
                decode_companion_task_status(record).map(CompleteCompanionTaskOutcome::Completed)
            }
            CompleteOutcome::AlreadyCompleted(record) => decode_companion_task_status(record)
                .map(CompleteCompanionTaskOutcome::AlreadyCompleted),
        }
    }

    /// Terminally fails a leased companion task through the generic JobQueue.
    pub fn fail(&self, input: FailCompanionTask) -> Result<FailCompanionTaskOutcome> {
        self.ensure_companion_job_id(input.id)?;
        let outcome = self.jobs.fail(FailJob {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            reason: input.reason,
            now: input.now,
        })?;
        match outcome {
            FailOutcome::Failed(record) => {
                decode_companion_task_status(record).map(FailCompanionTaskOutcome::Failed)
            }
            FailOutcome::AlreadyFailed(record) => {
                decode_companion_task_status(record).map(FailCompanionTaskOutcome::AlreadyFailed)
            }
        }
    }

    /// Requeues a leased companion task after a retryable failure.
    pub fn retry(&self, input: RetryCompanionTask) -> Result<RetryCompanionTaskOutcome> {
        self.ensure_companion_job_id(input.id)?;
        let outcome = self.jobs.retry(RetryJob {
            id: input.id,
            lease_owner: input.lease_owner,
            attempt_count: input.attempt_count,
            backoff_until: input.backoff_until,
            last_error: input.last_error,
            now: input.now,
        })?;
        match outcome {
            RetryOutcome::Retried(record) => {
                decode_companion_task_status(record).map(RetryCompanionTaskOutcome::Retried)
            }
        }
    }

    /// Reads and decodes companion task status by durable job id.
    pub fn status(&self, id: JobId) -> Result<Option<CompanionTaskStatus>> {
        self.jobs
            .get(id)?
            .map(decode_companion_task_status)
            .transpose()
    }

    fn ensure_companion_job_id(&self, id: JobId) -> Result<()> {
        let _ = self.status(id)?;
        Ok(())
    }

    fn fail_undecodable_claimed_task(
        &self,
        record: &JobRecord,
        lease_owner: &str,
        now: u64,
    ) -> Result<()> {
        match self.jobs.fail(FailJob {
            id: record.id,
            lease_owner: lease_owner.to_owned(),
            attempt_count: record.attempt_count,
            reason: ERR_INVALID_COMPANION_TASK_PAYLOAD.to_owned(),
            now,
        })? {
            FailOutcome::Failed(_) | FailOutcome::AlreadyFailed(_) => Ok(()),
        }
    }
}

/// Encodes a companion task payload in canonical MessagePack field order.
pub fn encode_companion_task_payload(task: &CompanionTask) -> Result<Vec<u8>> {
    task.key.validate()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_TASK_SCHEMA_VERSION),
            Value::from(COMPANION_TASK_PAYLOAD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TASK), Value::from(task.kind.as_str())),
        (Value::from(KEY_TASK_SCOPE), encode_scope(&task.key.scope)),
        (
            Value::from(KEY_TASK_SUBJECT),
            encode_subject(&task.key.subject),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("companion task MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a companion task payload.
pub fn decode_companion_task_payload(bytes: &[u8]) -> Result<CompanionTask> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion_task("companion task payload is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_companion_task(
            "trailing bytes after companion task payload",
        ));
    }

    decode_companion_task_payload_value(&value)
}

fn decode_companion_task_status(record: JobRecord) -> Result<CompanionTaskStatus> {
    if record.kind != COMPANION_TASK_JOB_KIND {
        return Err(invalid_companion_task("job is not a companion task"));
    }
    let task = decode_companion_task_payload(&record.payload)?;
    Ok(CompanionTaskStatus { job: record, task })
}

fn decode_companion_task_payload_value(value: &Value) -> Result<CompanionTask> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion_task(
            "companion task payload must be a MessagePack map",
        ));
    };

    let mut schema_version: Option<u64> = None;
    let mut task_kind: Option<CompanionTaskKind> = None;
    let mut scope: Option<CompanionScope> = None;
    let mut subject: Option<CompanionSubject> = None;
    let mut seen = [false; COMPANION_TASK_PAYLOAD_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion_task(
                "companion task payload keys must be strings",
            ));
        };
        let Some(index) = COMPANION_TASK_PAYLOAD_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_companion_task(
                "companion task payload key is not in the pinned set",
            ));
        };
        if seen[index] {
            return Err(invalid_companion_task(
                "duplicate companion task payload key",
            ));
        }
        seen[index] = true;

        match COMPANION_TASK_PAYLOAD_KEYS[index] {
            KEY_TASK_SCHEMA_VERSION => {
                schema_version = Some(value.as_u64().ok_or(invalid_companion_task(
                    "companion task schema_version must be an integer",
                ))?);
            }
            KEY_TASK => {
                task_kind = Some(value.as_str().and_then(CompanionTaskKind::parse).ok_or(
                    invalid_companion_task(
                        "companion task must be context|profile|memory|goodbye_artifact",
                    ),
                )?);
            }
            KEY_TASK_SCOPE => scope = Some(decode_scope(value)?),
            KEY_TASK_SUBJECT => subject = Some(decode_subject(value)?),
            _ => unreachable!("index resolved from COMPANION_TASK_PAYLOAD_KEYS"),
        }
    }

    let schema_version = schema_version.ok_or(invalid_companion_task(
        "missing required companion task field schema_version",
    ))?;
    if schema_version != COMPANION_TASK_PAYLOAD_SCHEMA_VERSION {
        return Err(invalid_companion_task(
            "unsupported companion task schema_version",
        ));
    }
    let key = CompanionRecordKey {
        scope: scope.ok_or(invalid_companion_task(
            "missing required companion task field scope",
        ))?,
        subject: subject.ok_or(invalid_companion_task(
            "missing required companion task field subject",
        ))?,
    };
    CompanionTask::new(
        task_kind.ok_or(invalid_companion_task(
            "missing required companion task field task",
        ))?,
        key,
    )
}

fn companion_scope_dedupe_key(scope: &CompanionScope) -> String {
    match scope {
        CompanionScope::Neutral => "neutral".to_owned(),
        CompanionScope::Personal { person_ref } => format!("personal:{}", person_ref.to_hex()),
        CompanionScope::SharedVault { vault_id } => format!("shared_vault:{vault_id}"),
    }
}

fn companion_subject_dedupe_key(subject: &CompanionSubject) -> String {
    match subject {
        CompanionSubject::Persona { persona_ref } => format!("persona:{}", persona_ref.to_hex()),
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => format!(
            "relationship:{}:{}",
            source_ref.to_hex(),
            target_ref.to_hex()
        ),
    }
}

/// Encodes a companion record body in canonical MessagePack field order.
pub fn encode_companion_record_body(record: &CompanionRecord) -> Result<Vec<u8>> {
    record.validate_current_schema_lifecycle_events()?;
    let value = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMPANION_RECORD_SCHEMA_VERSION),
        ),
        (Value::from(KEY_KIND), Value::from(record.kind().as_str())),
        (Value::from(KEY_SCOPE), encode_scope(&record.scope)),
        (Value::from(KEY_SUBJECT), encode_subject(&record.subject)),
        (Value::from(KEY_VALUE), record.value.clone()),
        (
            Value::from(KEY_PROVENANCE),
            encode_provenance(&record.provenance),
        ),
        (
            Value::from(KEY_LIFECYCLE),
            Value::from(record.lifecycle.as_str()),
        ),
        (
            Value::from(KEY_EXPORT),
            Value::from(record.export_classification.as_str()),
        ),
        (
            Value::from(KEY_LIFECYCLE_EVENTS),
            encode_lifecycle_events(&record.lifecycle_events),
        ),
    ]);

    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("companion record MessagePack encode failed"))?;
    Ok(out)
}

/// Decodes and validates a companion record body.
pub fn decode_companion_record_body(bytes: &[u8]) -> Result<CompanionRecord> {
    let mut cursor = Cursor::new(bytes);
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("body is not valid MessagePack"))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(invalid_companion("trailing bytes after body map"));
    }

    decode_companion_record_value(&value)
}

/// Converts JSON accepted by public APIs into the opaque MessagePack value
/// carried by a companion record.
pub fn companion_value_from_json(value: &JsonValue) -> Result<Value> {
    let encoded = rmp_serde::to_vec_named(value)
        .map_err(|_| invalid_companion("companion record value must be msgpack-encodable JSON"))?;
    let mut cursor = Cursor::new(encoded.as_slice());
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| invalid_companion("companion record value is not valid MessagePack"))?;
    if cursor.position() != encoded.len() as u64 {
        return Err(invalid_companion(
            "trailing bytes after companion record value",
        ));
    }
    Ok(value)
}

/// Converts the opaque companion MessagePack value back to JSON for typed API
/// envelopes. MessagePack binary/ext values are redacted because they are not
/// JSON-shaped public API values.
#[must_use]
pub fn companion_value_to_json(value: &Value) -> JsonValue {
    match value {
        Value::Nil => JsonValue::Null,
        Value::Boolean(value) => JsonValue::Bool(*value),
        Value::Integer(value) => {
            if let Some(value) = value.as_i64() {
                serde_json::json!(value)
            } else if let Some(value) = value.as_u64() {
                serde_json::json!(value)
            } else {
                JsonValue::Null
            }
        }
        Value::F32(value) => serde_json::json!(value),
        Value::F64(value) => serde_json::json!(value),
        Value::String(value) => match value.as_str() {
            Some(value) => JsonValue::String(value.to_owned()),
            None => serde_json::json!({ "redacted": "invalid_utf8_string" }),
        },
        Value::Binary(_) | Value::Ext(_, _) => JsonValue::Null,
        Value::Array(values) => {
            JsonValue::Array(values.iter().map(companion_value_to_json).collect())
        }
        Value::Map(entries) => {
            let mut object = serde_json::Map::new();
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    continue;
                };
                object.insert(key.to_owned(), companion_value_to_json(value));
            }
            JsonValue::Object(object)
        }
    }
}

fn decode_companion_record_value(value: &Value) -> Result<CompanionRecord> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("body must be a MessagePack map"));
    };

    let mut schema_version: Option<u64> = None;
    let mut kind: Option<CompanionRecordKind> = None;
    let mut scope: Option<CompanionScope> = None;
    let mut subject: Option<CompanionSubject> = None;
    let mut record_value: Option<Value> = None;
    let mut provenance: Option<CompanionProvenance> = None;
    let mut lifecycle: Option<ClaimLifecycleStatus> = None;
    let mut export_classification: Option<CompanionExportClassification> = None;
    let mut lifecycle_events: Option<Vec<CompanionLifecycleEvent>> = None;
    let mut seen = [false; COMPANION_RECORD_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("body keys must be strings"));
        };
        let Some(index) = COMPANION_RECORD_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(invalid_companion(
                "body key is not in the pinned COMPANION_RECORD_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate body key"));
        }
        seen[index] = true;

        match COMPANION_RECORD_BODY_KEYS[index] {
            KEY_SCHEMA_VERSION => {
                schema_version = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("schema_version must be an integer"))?,
                );
            }
            KEY_KIND => {
                let parsed = value
                    .as_str()
                    .and_then(CompanionRecordKind::parse)
                    .ok_or(invalid_companion("kind must be persona|relationship"))?;
                kind = Some(parsed);
            }
            KEY_SCOPE => scope = Some(decode_scope(value)?),
            KEY_SUBJECT => subject = Some(decode_subject(value)?),
            KEY_VALUE => record_value = Some(value.clone()),
            KEY_PROVENANCE => provenance = Some(decode_provenance(value)?),
            KEY_LIFECYCLE => {
                let parsed = value.as_str().and_then(ClaimLifecycleStatus::parse).ok_or(
                    invalid_companion("lifecycle must be active|superseded|retracted"),
                )?;
                lifecycle = Some(parsed);
            }
            KEY_EXPORT => {
                let parsed = value
                    .as_str()
                    .and_then(CompanionExportClassification::parse)
                    .ok_or(invalid_companion(
                        "export must be local_only|portable|shared_vault",
                    ))?;
                export_classification = Some(parsed);
            }
            KEY_LIFECYCLE_EVENTS => {
                lifecycle_events = Some(decode_lifecycle_events(value)?);
            }
            _ => unreachable!("index resolved from COMPANION_RECORD_BODY_KEYS"),
        }
    }

    let schema_version =
        schema_version.ok_or(invalid_companion("missing required field schema_version"))?;
    if !matches!(
        Some(schema_version),
        Some(COMPANION_RECORD_SCHEMA_VERSION_V1 | COMPANION_RECORD_SCHEMA_VERSION)
    ) {
        return Err(invalid_companion(
            "unsupported companion record schema_version",
        ));
    }

    let record = CompanionRecord::new(
        scope.ok_or(invalid_companion("missing required field scope"))?,
        subject.ok_or(invalid_companion("missing required field subject"))?,
        record_value.ok_or(invalid_companion("missing required field value"))?,
        provenance.ok_or(invalid_companion("missing required field provenance"))?,
        lifecycle.ok_or(invalid_companion("missing required field lifecycle"))?,
        export_classification.ok_or(invalid_companion("missing required field export"))?,
    );
    let mut record = record;
    record.lifecycle_events = match (schema_version, lifecycle_events) {
        (COMPANION_RECORD_SCHEMA_VERSION, Some(events)) => events,
        (COMPANION_RECORD_SCHEMA_VERSION, None) => {
            return Err(invalid_companion("missing required field lifecycle_events"));
        }
        (_, events) => events.unwrap_or_default(),
    };
    let expected_kind = kind.ok_or(invalid_companion("missing required field kind"))?;
    if record.kind() != expected_kind {
        return Err(invalid_companion("kind does not match subject shape"));
    }
    record.validate()?;
    if schema_version == COMPANION_RECORD_SCHEMA_VERSION {
        record.validate_current_schema_lifecycle_events()?;
    }
    Ok(record)
}

fn encode_lifecycle_events(events: &[CompanionLifecycleEvent]) -> Value {
    Value::Array(events.iter().map(encode_lifecycle_event).collect())
}

fn encode_lifecycle_event(event: &CompanionLifecycleEvent) -> Value {
    Value::Map(vec![
        (
            Value::from(LIFECYCLE_EVENT_KEYS[0]),
            Value::from(event.kind.as_str()),
        ),
        (Value::from(LIFECYCLE_EVENT_KEYS[1]), Value::from(event.at)),
    ])
}

fn decode_lifecycle_events(value: &Value) -> Result<Vec<CompanionLifecycleEvent>> {
    let Value::Array(events) = value else {
        return Err(invalid_companion("lifecycle_events must be an array"));
    };
    events.iter().map(decode_lifecycle_event).collect()
}

fn decode_lifecycle_event(value: &Value) -> Result<CompanionLifecycleEvent> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("lifecycle event must be a map"));
    };

    let mut kind: Option<CompanionLifecycleEventKind> = None;
    let mut at: Option<u64> = None;
    let mut seen = [false; LIFECYCLE_EVENT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("lifecycle event keys must be strings"));
        };
        let Some(index) = LIFECYCLE_EVENT_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion("lifecycle event key is not kind|at"));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate lifecycle event key"));
        }
        seen[index] = true;

        match LIFECYCLE_EVENT_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .and_then(CompanionLifecycleEventKind::parse)
                        .ok_or(invalid_companion(
                            "lifecycle event kind must be created|superseded|retired|revived",
                        ))?,
                );
            }
            "at" => {
                at = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("lifecycle event at must be an integer"))?,
                );
            }
            _ => unreachable!("index resolved from LIFECYCLE_EVENT_KEYS"),
        }
    }

    Ok(CompanionLifecycleEvent {
        kind: kind.ok_or(invalid_companion("lifecycle event missing kind"))?,
        at: at.ok_or(invalid_companion("lifecycle event missing at"))?,
    })
}

fn encode_scope(scope: &CompanionScope) -> Value {
    let mut entries = vec![(Value::from(SCOPE_KEYS[0]), Value::from(scope.as_str()))];
    match scope {
        CompanionScope::Neutral => {}
        CompanionScope::Personal { person_ref } => {
            entries.push((Value::from(SCOPE_KEYS[1]), entity_value(person_ref)));
        }
        CompanionScope::SharedVault { vault_id } => {
            entries.push((Value::from(SCOPE_KEYS[2]), Value::from(*vault_id)));
        }
    }
    Value::Map(entries)
}

fn decode_scope(value: &Value) -> Result<CompanionScope> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("scope must be a map"));
    };

    let mut kind: Option<&str> = None;
    let mut person_ref: Option<EntityId> = None;
    let mut vault_id: Option<u64> = None;
    let mut seen = [false; SCOPE_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("scope keys must be strings"));
        };
        let Some(index) = SCOPE_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "scope key is not kind|person_ref|vault_id",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate scope key"));
        }
        seen[index] = true;

        match SCOPE_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .ok_or(invalid_companion("scope.kind must be a string"))?,
                );
            }
            "person_ref" => {
                person_ref = Some(entity_from_value(
                    value,
                    "scope.person_ref must be entity id",
                )?);
            }
            "vault_id" => {
                vault_id = Some(
                    value
                        .as_u64()
                        .ok_or(invalid_companion("scope.vault_id must be an integer"))?,
                );
            }
            _ => unreachable!("index resolved from SCOPE_KEYS"),
        }
    }

    let scope = match kind.ok_or(invalid_companion("scope missing kind"))? {
        "neutral" if person_ref.is_none() && vault_id.is_none() => CompanionScope::Neutral,
        "personal" if vault_id.is_none() => CompanionScope::Personal {
            person_ref: person_ref.ok_or(invalid_companion(
                "personal companion scope requires person_ref",
            ))?,
        },
        "shared_vault" if person_ref.is_none() => CompanionScope::SharedVault {
            vault_id: vault_id.ok_or(invalid_companion(
                "shared-vault companion scope requires vault_id",
            ))?,
        },
        _ => return Err(invalid_companion("scope shape does not match scope.kind")),
    };
    scope.validate()?;
    Ok(scope)
}

fn encode_subject(subject: &CompanionSubject) -> Value {
    match subject {
        CompanionSubject::Persona { persona_ref } => Value::Map(vec![
            (Value::from(SUBJECT_KEYS[0]), Value::from("persona")),
            (Value::from(SUBJECT_KEYS[1]), entity_value(persona_ref)),
        ]),
        CompanionSubject::Relationship {
            source_ref,
            target_ref,
        } => Value::Map(vec![
            (Value::from(SUBJECT_KEYS[0]), Value::from("relationship")),
            (
                Value::from(SUBJECT_KEYS[2]),
                Value::Map(vec![
                    (
                        Value::from(RELATIONSHIP_REF_KEYS[0]),
                        entity_value(source_ref),
                    ),
                    (
                        Value::from(RELATIONSHIP_REF_KEYS[1]),
                        entity_value(target_ref),
                    ),
                ]),
            ),
        ]),
    }
}

fn decode_subject(value: &Value) -> Result<CompanionSubject> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("subject must be a map"));
    };

    let mut kind: Option<&str> = None;
    let mut persona_ref: Option<EntityId> = None;
    let mut relationship_ref: Option<(EntityId, EntityId)> = None;
    let mut seen = [false; SUBJECT_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("subject keys must be strings"));
        };
        let Some(index) = SUBJECT_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "subject key is not kind|persona_ref|relationship_ref",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate subject key"));
        }
        seen[index] = true;

        match SUBJECT_KEYS[index] {
            "kind" => {
                kind = Some(
                    value
                        .as_str()
                        .ok_or(invalid_companion("subject.kind must be a string"))?,
                );
            }
            "persona_ref" => {
                persona_ref = Some(entity_from_value(
                    value,
                    "subject.persona_ref must be entity id",
                )?);
            }
            "relationship_ref" => relationship_ref = Some(decode_relationship_ref(value)?),
            _ => unreachable!("index resolved from SUBJECT_KEYS"),
        }
    }

    match kind.ok_or(invalid_companion("subject missing kind"))? {
        "persona" if relationship_ref.is_none() => Ok(CompanionSubject::Persona {
            persona_ref: persona_ref
                .ok_or(invalid_companion("persona subject requires persona_ref"))?,
        }),
        "relationship" if persona_ref.is_none() => {
            let (source_ref, target_ref) = relationship_ref.ok_or(invalid_companion(
                "relationship subject requires relationship_ref",
            ))?;
            Ok(CompanionSubject::Relationship {
                source_ref,
                target_ref,
            })
        }
        _ => Err(invalid_companion(
            "subject shape does not match subject.kind",
        )),
    }
}

fn decode_relationship_ref(value: &Value) -> Result<(EntityId, EntityId)> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("relationship_ref must be a map"));
    };

    let mut source_ref: Option<EntityId> = None;
    let mut target_ref: Option<EntityId> = None;
    let mut seen = [false; RELATIONSHIP_REF_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("relationship_ref keys must be strings"));
        };
        let Some(index) = RELATIONSHIP_REF_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "relationship_ref key is not source_ref|target_ref",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate relationship_ref key"));
        }
        seen[index] = true;

        match RELATIONSHIP_REF_KEYS[index] {
            "source_ref" => {
                source_ref = Some(entity_from_value(
                    value,
                    "relationship_ref.source_ref must be entity id",
                )?);
            }
            "target_ref" => {
                target_ref = Some(entity_from_value(
                    value,
                    "relationship_ref.target_ref must be entity id",
                )?);
            }
            _ => unreachable!("index resolved from RELATIONSHIP_REF_KEYS"),
        }
    }

    Ok((
        source_ref.ok_or(invalid_companion("relationship_ref missing source_ref"))?,
        target_ref.ok_or(invalid_companion("relationship_ref missing target_ref"))?,
    ))
}

fn encode_provenance(provenance: &CompanionProvenance) -> Value {
    Value::Map(vec![
        (
            Value::from(PROVENANCE_KEYS[0]),
            entity_value(&provenance.actor_ref),
        ),
        (
            Value::from(PROVENANCE_KEYS[1]),
            Value::from(provenance.actor_class as u8),
        ),
        (
            Value::from(PROVENANCE_KEYS[2]),
            Value::from(provenance.source.as_str()),
        ),
        (
            Value::from(PROVENANCE_KEYS[3]),
            Value::from(provenance.approval.as_str()),
        ),
        (Value::from(PROVENANCE_KEYS[4]), provenance.value.clone()),
    ])
}

fn decode_provenance(value: &Value) -> Result<CompanionProvenance> {
    let Value::Map(entries) = value else {
        return Err(invalid_companion("provenance must be a map"));
    };

    let mut actor_ref: Option<EntityId> = None;
    let mut actor_class: Option<EdgeActorClass> = None;
    let mut source: Option<ClaimSource> = None;
    let mut approval: Option<ClaimApprovalStatus> = None;
    let mut provenance_value: Option<Value> = None;
    let mut seen = [false; PROVENANCE_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_companion("provenance keys must be strings"));
        };
        let Some(index) = PROVENANCE_KEYS.iter().position(|known| *known == key) else {
            return Err(invalid_companion(
                "provenance key is not actor_ref|actor_class|source|approval|value",
            ));
        };
        if seen[index] {
            return Err(invalid_companion("duplicate provenance key"));
        }
        seen[index] = true;

        match PROVENANCE_KEYS[index] {
            "actor_ref" => {
                actor_ref = Some(entity_from_value(
                    value,
                    "provenance.actor_ref must be entity id",
                )?);
            }
            "actor_class" => {
                let raw = value
                    .as_u64()
                    .and_then(|raw| u8::try_from(raw).ok())
                    .ok_or(invalid_companion("provenance.actor_class must be a u8"))?;
                actor_class = Some(EdgeActorClass::try_from_u8(raw).ok_or(invalid_companion(
                    "provenance.actor_class must be human|agent|system",
                ))?);
            }
            "source" => {
                source = Some(
                    value
                        .as_str()
                        .and_then(ClaimSource::parse)
                        .ok_or(invalid_companion("provenance.source is not recognized"))?,
                );
            }
            "approval" => {
                approval = Some(
                    value
                        .as_str()
                        .and_then(ClaimApprovalStatus::parse)
                        .ok_or(invalid_companion("provenance.approval is not recognized"))?,
                );
            }
            "value" => provenance_value = Some(value.clone()),
            _ => unreachable!("index resolved from PROVENANCE_KEYS"),
        }
    }

    let provenance = CompanionProvenance::new(
        actor_ref.ok_or(invalid_companion("provenance missing actor_ref"))?,
        actor_class.ok_or(invalid_companion("provenance missing actor_class"))?,
        source.ok_or(invalid_companion("provenance missing source"))?,
        approval.ok_or(invalid_companion("provenance missing approval"))?,
        provenance_value.ok_or(invalid_companion("provenance missing value"))?,
    );
    provenance.validate()?;
    Ok(provenance)
}

fn entity_value(id: &EntityId) -> Value {
    Value::Binary(id.as_bytes().to_vec())
}

fn entity_from_value(value: &Value, context: &'static str) -> Result<EntityId> {
    let Value::Binary(bytes) = value else {
        return Err(invalid_companion(context));
    };
    if bytes.len() != crate::types::ENTITY_ID_LEN {
        return Err(invalid_companion(context));
    }
    let mut arr = [0_u8; crate::types::ENTITY_ID_LEN];
    arr.copy_from_slice(bytes);
    EntityId::from_bytes(arr).map_err(|_| invalid_companion(context))
}

fn invalid_companion(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

fn invalid_companion_task(reason: &'static str) -> Error {
    Error::InvalidJobQueueRecord(reason)
}

#[cfg(test)]
mod tests;
