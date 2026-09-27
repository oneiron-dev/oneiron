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
    /// An active relationship record selected the scope.
    RelationshipRecord,
}

impl CompanionScopeResolutionSource {
    /// Returns the stable wire/debug string for this resolution source.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeutralDefault => "neutral_default",
            Self::RelationshipRecord => "relationship_record",
        }
    }
}

/// Effective companion scope and expression boundary resolved from records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompanionScopeResolution {
    /// Effective scope boundary for this companion assembly.
    pub scope: CompanionScope,
    /// Active relationship record key that selected or contributes to this scope.
    pub relationship_key: Option<CompanionRecordKey>,
    /// Effective expression register value for the resolved boundary.
    pub expression: CompanionExpression,
    /// Evidence class used for the scope decision.
    pub source: CompanionScopeResolutionSource,
}

/// In-memory relationship record register keyed by `(scope, subject)`.
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
    /// relationship records. PERSON identity is not a companion register record.
    /// Personal scope takes precedence only when an active relationship record
    /// exists; orphan expressions cannot select a scope.
    #[must_use]
    pub fn resolve_companion_scope(
        &self,
        expressions: &CompanionExpressionRegister,
        person_ref: Option<EntityId>,
        relationship_ref: Option<(EntityId, EntityId)>,
    ) -> CompanionScopeResolution {
        let neutral = CompanionScope::neutral();
        if let Some(person_ref) = person_ref {
            let personal = CompanionScope::personal(person_ref);
            if let Some(resolution) =
                self.resolve_companion_scope_in(&personal, expressions, relationship_ref)
            {
                return resolution;
            }
        }

        self.resolve_companion_scope_in(&neutral, expressions, relationship_ref)
            .unwrap_or(CompanionScopeResolution {
                scope: neutral,
                relationship_key: None,
                expression: CompanionExpression::Professional,
                source: CompanionScopeResolutionSource::NeutralDefault,
            })
    }

    fn resolve_companion_scope_in(
        &self,
        scope: &CompanionScope,
        expressions: &CompanionExpressionRegister,
        relationship_ref: Option<(EntityId, EntityId)>,
    ) -> Option<CompanionScopeResolution> {
        let relationship_key = relationship_ref
            .map(|(source_ref, target_ref)| {
                CompanionRecordKey::relationship(scope.clone(), source_ref, target_ref)
            })
            .filter(|key| self.lookup_active(key).is_some());

        let relationship_key = relationship_key?;
        let expression = expressions
            .lookup(&relationship_key)
            .unwrap_or(CompanionExpression::Professional);

        Some(CompanionScopeResolution {
            scope: scope.clone(),
            relationship_key: Some(relationship_key),
            expression,
            source: CompanionScopeResolutionSource::RelationshipRecord,
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

/// In-memory expression register keyed by PERSON or relationship target.
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
