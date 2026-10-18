//! Scoped exports carry the caller's verified ceiling, never a caller-authored grant.
use super::{Memory, MemoryError, MemoryResult};
use crate::federation::Scope;
use serde::{Deserialize, Serialize};

/// A position may select rows but cannot be supplied as a permission ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "scope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RecordPosition {
    Position(Scope),
}

/// This value is projected only from the authenticated credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "scope",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CredentialCeiling {
    Ceiling(Scope),
}

/// Requested read axes: empty lists add no narrowing, unlike an empty grant axis.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RecordSelector {
    pub worlds: Option<super::RecallWorlds>,
    pub facet_refs: Vec<String>,
    pub kinds: Vec<String>,
    pub project_refs: Vec<String>,
}

/// The channel's wire axes are ceilings: omitted or empty axes grant nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "values",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScopeAxisInput<T> {
    Bottom,
    All,
    Some(Vec<T>),
}
impl<T> Default for ScopeAxisInput<T> {
    fn default() -> Self {
        Self::Bottom
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSensitivityBand {
    Public,
    Private,
    Sensitive,
    Restricted,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ScopeSensitivityInput {
    #[default]
    Bottom,
    AtMost(ScopeSensitivityBand),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelCeiling {
    pub worlds: ScopeAxisInput<String>,
    pub facets: ScopeAxisInput<String>,
    pub bands: ScopeAxisInput<u8>,
    pub audience: ScopeAxisInput<String>,
    pub verbs: ScopeAxisInput<String>,
    pub sensitivity: ScopeSensitivityInput,
}

impl<T: Ord + Clone> ScopeAxisInput<T> {
    fn axis(&self) -> crate::federation::ScopeAxis<T> {
        match self {
            Self::Bottom => crate::federation::ScopeAxis::Bottom,
            Self::All => crate::federation::ScopeAxis::All,
            Self::Some(values) => values.iter().cloned().collect(),
        }
    }
}

/// A destination selection meets the credential; it never replaces it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportChannel {
    pub channel_ref: String,
    pub scope: ChannelCeiling,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopedExportRequest {
    pub selector: RecordSelector,
    pub channel: ExportChannel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopedExportRecord {
    pub record: crate::lens::RecordRef,
    pub position: RecordPosition,
    /// Complete metadata header and body, as returned by the engine's scoped export.
    pub bytes: Vec<u8>,
    pub birth: Option<crate::provenance::birth::RowBirth>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScopedExport {
    pub selector: RecordSelector,
    pub credential: CredentialCeiling,
    pub channel: ExportChannel,
    pub applied: Scope,
    pub records: Vec<ScopedExportRecord>,
}

impl Memory<'_> {
    fn export_selector(&self, input: &RecordSelector) -> MemoryResult<Scope> {
        use crate::federation::{ScopeAxis, ScopeId};
        let mut scope = Scope::top();
        let worlds = self.selected_worlds(&super::RecallScope {
            worlds: Some(input.worlds.clone().unwrap_or(super::RecallWorlds::All)),
            ..Default::default()
        })?;
        if let Some(worlds) = worlds {
            scope.worlds = worlds.scope_axis();
        }
        let ids = |refs: &[String]| -> MemoryResult<ScopeAxis<ScopeId>> {
            if refs.is_empty() {
                return Ok(ScopeAxis::All);
            }
            Ok(refs
                .iter()
                .map(|reference| self.resolve_ref(reference).map(ScopeId))
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .collect())
        };
        scope.facets = ids(&input.facet_refs)?;
        scope.audience = ids(&input.project_refs)?;
        if !input.kinds.is_empty() {
            scope.bands = input
                .kinds
                .iter()
                .map(|kind| super::structural::type_byte_for_kind(kind))
                .collect::<MemoryResult<Vec<_>>>()?
                .into_iter()
                .collect();
        }
        Ok(scope)
    }

    fn export_channel_scope(&self, input: &ChannelCeiling) -> MemoryResult<Scope> {
        use crate::federation::{ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
        let ids = |axis: &ScopeAxisInput<String>| -> MemoryResult<ScopeAxis<ScopeId>> {
            match axis {
                ScopeAxisInput::Bottom => Ok(ScopeAxis::Bottom),
                ScopeAxisInput::All => Ok(ScopeAxis::All),
                ScopeAxisInput::Some(values) => Ok(values
                    .iter()
                    .map(|reference| self.resolve_ref(reference).map(ScopeId))
                    .collect::<MemoryResult<Vec<_>>>()?
                    .into_iter()
                    .collect()),
            }
        };
        Ok(Scope {
            worlds: ids(&input.worlds)?,
            facets: ids(&input.facets)?,
            audience: ids(&input.audience)?,
            bands: input.bands.axis(),
            verbs: input.verbs.axis(),
            sensitivity: match input.sensitivity {
                ScopeSensitivityInput::Bottom => SensitivityCeiling::Bottom,
                ScopeSensitivityInput::AtMost(band) => SensitivityCeiling::AtMost(match band {
                    ScopeSensitivityBand::Public => Sensitivity::Public,
                    ScopeSensitivityBand::Private => Sensitivity::Private,
                    ScopeSensitivityBand::Sensitive => Sensitivity::Sensitive,
                    ScopeSensitivityBand::Restricted => Sensitivity::Restricted,
                }),
            },
        })
    }

    /// The verified credential's actual ceiling, not a requested read selector.
    pub fn credential_ceiling(&self) -> MemoryResult<CredentialCeiling> {
        let proof = self.presented_credential().ok_or_else(|| {
            MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "this door requires the caller's verified credential",
                &[],
            )
        })?;
        if proof.claims().holder_ref != self.actor.to_hex()
            || !self.vault.capability_slip_is_live(proof)?
        {
            return Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "the caller credential is not live",
                &[],
            ));
        }
        Ok(CredentialCeiling::Ceiling(proof.scope().clone()))
    }

    /// Delegates row admission, epoch/text fences and withholding to the engine's scoped export.
    pub fn export_scoped(&self, input: &ScopedExportRequest) -> MemoryResult<ScopedExport> {
        let credential = self.credential_ceiling()?;
        let proof = self
            .presented_credential()
            .expect("credential_ceiling verified this proof");
        if !proof.allows_verb("export")
            || input.channel.channel_ref.is_empty()
            || (!proof.claims().channels.is_empty()
                && !proof.claims().channels.contains(&input.channel.channel_ref))
        {
            return Err(MemoryError::new(
                super::MEMORY_CODE_FORBIDDEN,
                "the credential does not grant export on this channel",
                &[],
            ));
        }
        let selector = self.export_selector(&input.selector)?;
        let channel = self.export_channel_scope(&input.channel.scope)?;
        let rows = self
            .vault
            .export_records_in_scope(&selector, proof.scope(), &channel)?;
        let ids: Vec<_> = rows.iter().map(|row| row.id).collect();
        // The export evaluator does not replace relationship grants, NOTE privacy,
        // device locality or record caveats; the credential's own read lane also binds.
        let admitted = self
            .read_lane(crate::claim::ClaimReadStatus::Recorded)?
            .through_channel(&input.channel.channel_ref)
            .read(
                &ids.iter()
                    .copied()
                    .map(crate::claim::PointRead::id)
                    .collect::<Vec<_>>(),
                None,
            )?;
        let shipped: std::collections::BTreeSet<_> = admitted
            .value
            .into_iter()
            .flatten()
            .filter(|row| row.body.is_some())
            .map(|row| row.id)
            .collect();
        let key = crate::provenance::birth::WithheldKey::for_export();
        let mut records = Vec::new();
        for row in rows.into_iter().filter(|row| shipped.contains(&row.id)) {
            let header = crate::batch::EntityMetadataHeader::parse(&row.bytes)
                .ok_or(crate::Error::CorruptedIndex("scoped export header"))?;
            let Some(position) = row.scope else { continue };
            records.push(ScopedExportRecord {
                record: crate::lens::RecordRef::from_id(header.entity_type, &row.id, None),
                position: RecordPosition::Position(position),
                bytes: row.bytes,
                birth: row
                    .birth
                    .map(|birth| birth.masked(|id| shipped.contains(id), &key)),
            });
        }
        self.produced_from(shipped);
        Ok(ScopedExport {
            selector: input.selector.clone(),
            credential,
            channel: input.channel.clone(),
            applied: selector.meet(proof.scope()).meet(&channel),
            records,
        })
    }
}
