//! Companion-layer export filtering.
use crate::claim::ClaimLifecycleStatus;
use crate::companion::{
    CompanionExportClassification, CompanionExpression, CompanionExpressionRegister,
    CompanionRecord, CompanionRecordKey, CompanionRecordKind, CompanionRegister, CompanionScope,
};

pub const COMPANION_EXPORT_LAYER_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportLayer {
    layer_version: u16,
    personas: Vec<CompanionExportRecord>,
    relationships: Vec<CompanionExportRecord>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionExportRecord {
    key: CompanionRecordKey,
    record: CompanionRecord,
    expression: Option<CompanionExpression>,
}

pub fn companion_export_layer(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
) -> CompanionExportLayer {
    let mut personas = Vec::new();
    let mut relationships = Vec::new();

    for (key, record) in records.iter() {
        if !companion_record_exportable(record) {
            continue;
        }

        let exported = CompanionExportRecord {
            key: key.clone(),
            record: record.clone(),
            expression: expressions.lookup(key),
        };

        match record.kind() {
            CompanionRecordKind::Persona => personas.push(exported),
            CompanionRecordKind::Relationship => relationships.push(exported),
        }
    }

    CompanionExportLayer {
        layer_version: COMPANION_EXPORT_LAYER_VERSION,
        personas,
        relationships,
    }
}

fn companion_record_exportable(record: &CompanionRecord) -> bool {
    record.lifecycle == ClaimLifecycleStatus::Active
        && record.export_classification == CompanionExportClassification::Portable
        && !matches!(&record.scope, CompanionScope::SharedVault { .. })
}

impl CompanionExportLayer {
    #[must_use]
    pub const fn layer_version(&self) -> u16 {
        self.layer_version
    }

    #[must_use]
    pub fn personas(&self) -> &[CompanionExportRecord] {
        &self.personas
    }

    #[must_use]
    pub fn relationships(&self) -> &[CompanionExportRecord] {
        &self.relationships
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.personas.len() + self.relationships.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.personas.is_empty() && self.relationships.is_empty()
    }
}

impl CompanionExportRecord {
    #[must_use]
    pub const fn key(&self) -> &CompanionRecordKey {
        &self.key
    }

    #[must_use]
    pub const fn record(&self) -> &CompanionRecord {
        &self.record
    }

    #[must_use]
    pub const fn expression(&self) -> Option<CompanionExpression> {
        self.expression
    }
}
