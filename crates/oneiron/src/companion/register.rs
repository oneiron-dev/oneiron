//! In-memory companion registers with scope and expression resolution.

use super::model::{CompanionExpression, CompanionRecord, CompanionRecordKey, CompanionScope};
use crate::claim::ClaimLifecycleStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use std::collections::BTreeMap;

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
