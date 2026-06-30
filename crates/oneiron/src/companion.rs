//! Companion relationship/persona record substrate.
//!
//! This module is intentionally storage-agnostic: it defines the typed record
//! shape, canonical MessagePack body encoding, and a small register used by
//! callers/tests before later API or vault wiring.

use std::collections::BTreeMap;
use std::io::Cursor;

use rmpv::Value;

use crate::claim::{
    COMPANION_EXPRESSION_PROFESSIONAL, COMPANION_EXPRESSION_UNRESTRICTED,
    COMPANION_EXPRESSION_WARM, ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource,
};
use crate::error::{Error, Result};

use super::{EdgeActorClass, EntityId, WriteEnvelope};

/// Current companion record body schema version.
pub const COMPANION_RECORD_SCHEMA_VERSION: u64 = 1;

/// Pinned on-disk MessagePack key set for companion record bodies.
pub const COMPANION_RECORD_BODY_KEYS: [&str; 8] = [
    "schema_version",
    "kind",
    "scope",
    "subject",
    "value",
    "provenance",
    "lifecycle",
    "export",
];

const KEY_SCHEMA_VERSION: &str = COMPANION_RECORD_BODY_KEYS[0];
const KEY_KIND: &str = COMPANION_RECORD_BODY_KEYS[1];
const KEY_SCOPE: &str = COMPANION_RECORD_BODY_KEYS[2];
const KEY_SUBJECT: &str = COMPANION_RECORD_BODY_KEYS[3];
const KEY_VALUE: &str = COMPANION_RECORD_BODY_KEYS[4];
const KEY_PROVENANCE: &str = COMPANION_RECORD_BODY_KEYS[5];
const KEY_LIFECYCLE: &str = COMPANION_RECORD_BODY_KEYS[6];
const KEY_EXPORT: &str = COMPANION_RECORD_BODY_KEYS[7];

const SCOPE_KEYS: [&str; 3] = ["kind", "person_ref", "vault_id"];
const SUBJECT_KEYS: [&str; 3] = ["kind", "persona_ref", "relationship_ref"];
const RELATIONSHIP_REF_KEYS: [&str; 2] = ["source_ref", "target_ref"];
const PROVENANCE_KEYS: [&str; 5] = ["actor_ref", "actor_class", "source", "approval", "value"];

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
        Ok(())
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

    fn validate(&self) -> Result<()> {
        self.scope.validate()
    }
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

/// Encodes a companion record body in canonical MessagePack field order.
pub fn encode_companion_record_body(record: &CompanionRecord) -> Result<Vec<u8>> {
    record.validate()?;
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
            _ => unreachable!("index resolved from COMPANION_RECORD_BODY_KEYS"),
        }
    }

    if schema_version != Some(COMPANION_RECORD_SCHEMA_VERSION) {
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
    let expected_kind = kind.ok_or(invalid_companion("missing required field kind"))?;
    if record.kind() != expected_kind {
        return Err(invalid_companion("kind does not match subject shape"));
    }
    record.validate()?;
    Ok(record)
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
    if bytes.len() != super::ENTITY_ID_LEN {
        return Err(invalid_companion(context));
    }
    let mut arr = [0_u8; super::ENTITY_ID_LEN];
    arr.copy_from_slice(bytes);
    EntityId::from_bytes(arr).map_err(|_| invalid_companion(context))
}

fn invalid_companion(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::ClaimSource;
    use crate::types::{WriteActor, WriteProvenance};

    fn entity(seed: u8) -> EntityId {
        let mut bytes = [seed; 16];
        bytes[0] = seed.max(1);
        EntityId::from_bytes(bytes).expect("test entity id")
    }

    fn provenance(seed: u8) -> CompanionProvenance {
        let envelope = WriteEnvelope::new(
            WriteActor::new(entity(seed), EdgeActorClass::Agent),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from(format!("fixture-{seed}"))).unwrap(),
            ClaimApprovalStatus::Approved,
        );
        CompanionProvenance::from_envelope(&envelope)
    }

    #[test]
    fn companion_register_creates_and_looks_up_persona_and_relationship() -> Result<()> {
        let neutral = CompanionScope::neutral();
        let persona_ref = entity(0x11);
        let source_ref = entity(0x12);
        let target_ref = entity(0x13);

        let persona = CompanionRecord::persona(
            neutral.clone(),
            persona_ref,
            Value::from("neutral persona"),
            provenance(0xA1),
            CompanionExportClassification::Portable,
        );
        let relationship = CompanionRecord::relationship(
            neutral.clone(),
            source_ref,
            target_ref,
            Value::from("neutral relationship"),
            provenance(0xA2),
            CompanionExportClassification::LocalOnly,
        );

        let mut register = CompanionRegister::new();
        assert!(register.register(persona.clone())?.is_none());
        assert!(register.register(relationship.clone())?.is_none());

        assert_eq!(
            register.lookup_persona(&neutral, persona_ref),
            Some(&persona)
        );
        assert_eq!(
            register.lookup_relationship(&neutral, source_ref, target_ref),
            Some(&relationship)
        );
        assert_eq!(register.len(), 2);
        Ok(())
    }

    #[test]
    fn companion_register_keeps_neutral_personal_and_shared_vault_scopes_separate() -> Result<()> {
        let persona_ref = entity(0x21);
        let person_owner = entity(0x22);
        let neutral = CompanionScope::neutral();
        let personal = CompanionScope::personal(person_owner);
        let shared = CompanionScope::shared_vault(7);

        let mut register = CompanionRegister::new();
        register.register(CompanionRecord::persona(
            neutral.clone(),
            persona_ref,
            Value::from("neutral"),
            provenance(0xB1),
            CompanionExportClassification::Portable,
        ))?;
        register.register(CompanionRecord::persona(
            personal.clone(),
            persona_ref,
            Value::from("personal"),
            provenance(0xB2),
            CompanionExportClassification::LocalOnly,
        ))?;
        register.register(CompanionRecord::persona(
            shared.clone(),
            persona_ref,
            Value::from("shared"),
            provenance(0xB3),
            CompanionExportClassification::SharedVault,
        ))?;

        assert_eq!(
            register
                .lookup_persona(&neutral, persona_ref)
                .map(|r| &r.value),
            Some(&Value::from("neutral"))
        );
        assert_eq!(
            register
                .lookup_persona(&personal, persona_ref)
                .map(|r| &r.value),
            Some(&Value::from("personal"))
        );
        assert_eq!(
            register
                .lookup_persona(&shared, persona_ref)
                .map(|r| &r.value),
            Some(&Value::from("shared"))
        );
        assert_eq!(register.records_in_scope(&neutral).count(), 1);
        assert_eq!(register.records_in_scope(&personal).count(), 1);
        assert_eq!(register.records_in_scope(&shared).count(), 1);
        Ok(())
    }

    #[test]
    fn companion_register_body_round_trip_carries_provenance_lifecycle_and_export() -> Result<()> {
        let mut record = CompanionRecord::relationship(
            CompanionScope::shared_vault(42),
            entity(0x31),
            entity(0x32),
            Value::Map(vec![(Value::from("affinity"), Value::from("trusted"))]),
            CompanionProvenance::new(
                entity(0x33),
                EdgeActorClass::Human,
                ClaimSource::Observed,
                ClaimApprovalStatus::Proposed,
                Value::Map(vec![(Value::from("source"), Value::from("test"))]),
            ),
            CompanionExportClassification::SharedVault,
        );
        record.lifecycle = ClaimLifecycleStatus::Superseded;

        let encoded = encode_companion_record_body(&record)?;
        let decoded = decode_companion_record_body(&encoded)?;

        assert_eq!(decoded, record);
        assert_eq!(decoded.lifecycle, ClaimLifecycleStatus::Superseded);
        assert_eq!(
            decoded.export_classification,
            CompanionExportClassification::SharedVault
        );
        assert_eq!(decoded.provenance.actor_class, EdgeActorClass::Human);
        Ok(())
    }

    #[test]
    fn companion_export_expression_register_updates_and_fails_closed_on_future_values() -> Result<()>
    {
        assert_eq!(
            CompanionExpression::parse("professional"),
            Some(CompanionExpression::Professional)
        );
        assert_eq!(
            CompanionExpression::parse("warm"),
            Some(CompanionExpression::Warm)
        );
        assert_eq!(
            CompanionExpression::parse("unrestricted"),
            Some(CompanionExpression::Unrestricted)
        );
        for expression in [
            CompanionExpression::Professional,
            CompanionExpression::Warm,
            CompanionExpression::Unrestricted,
        ] {
            assert_eq!(
                CompanionExpression::parse(expression.as_str()),
                Some(expression)
            );
        }
        assert!(CompanionExpression::parse("future_closed").is_none());
        assert!(matches!(
            CompanionExpression::parse_closed("future_closed"),
            Err(Error::InvalidClaimBody(
                "expression must be professional|warm|unrestricted"
            ))
        ));

        let neutral = CompanionScope::neutral();
        let persona_ref = entity(0x41);
        let key = CompanionRecordKey::persona(neutral.clone(), persona_ref);
        let mut register = CompanionExpressionRegister::new();

        assert!(
            register
                .update(key.clone(), CompanionExpression::Professional)?
                .is_none()
        );
        assert_eq!(
            register.lookup_persona(&neutral, persona_ref),
            Some(CompanionExpression::Professional)
        );
        assert_eq!(
            register.update(key, CompanionExpression::Warm)?,
            Some(CompanionExpression::Professional)
        );
        assert_eq!(
            register.lookup_persona(&neutral, persona_ref),
            Some(CompanionExpression::Warm)
        );

        let err = register
            .update(
                CompanionRecordKey::persona(CompanionScope::shared_vault(0), persona_ref),
                CompanionExpression::Unrestricted,
            )
            .expect_err("invalid shared-vault expression scope must fail closed");
        assert!(matches!(
            err,
            Error::InvalidClaimBody("shared-vault companion scope requires nonzero vault_id")
        ));
        Ok(())
    }
}
