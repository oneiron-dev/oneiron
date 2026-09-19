//! Companion-layer export filtering.
use crate::channel_identity::ChannelIdentity;
use crate::claim::ClaimLifecycleStatus;
use crate::companion::{
    CompanionExpression, CompanionExpressionRegister, CompanionRecord, CompanionRecordKey,
    CompanionRecordKind, CompanionRegister, CompanionScope,
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

/// Portable export without a destination identity excludes shared-vault content.
pub fn companion_export_layer(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
    channel: &crate::federation::Scope,
) -> CompanionExportLayer {
    export_layer(records, expressions, channel, None)
}

/// Filters an export for a channel identity's vault binding and sensitivity ceiling.
/// This is a content filter, not an outbound authorization or effector-gate bypass.
/// Invalid, inactive, and read-only identities yield an empty layer.
pub fn companion_export_layer_for_channel(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
    channel: &crate::federation::Scope,
    identity: &ChannelIdentity,
) -> CompanionExportLayer {
    export_layer(records, expressions, channel, Some(identity))
}

fn export_layer(
    records: &CompanionRegister,
    expressions: &CompanionExpressionRegister,
    channel: &crate::federation::Scope,
    identity: Option<&ChannelIdentity>,
) -> CompanionExportLayer {
    let mut personas = Vec::new();
    let mut relationships = Vec::new();

    for (key, record) in records.iter() {
        if !companion_record_exportable(record, channel.sensitivity, identity) {
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

fn companion_record_exportable(
    record: &CompanionRecord,
    ceiling: crate::federation::SensitivityCeiling,
    identity: Option<&ChannelIdentity>,
) -> bool {
    record.lifecycle == ClaimLifecycleStatus::Active
        && ceiling.permits(record.sensitivity)
        && match identity {
            Some(identity) => identity.permits_companion_export_scope(&record.scope),
            None => !matches!(record.scope, CompanionScope::SharedVault { .. }),
        }
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
