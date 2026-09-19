//! Validate source identities, facet/body agreement and explicit archive-only omissions.
use super::*;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    ENTITY_TYPE_SKILL_HUB,
};
use crate::serialize::ExportBody;
use std::collections::{BTreeMap, BTreeSet};

impl WholeVaultDocument {
    pub(crate) fn refresh_omissions(&mut self) -> Result<()> {
        let (imports, bundles) = self.expected_omissions();
        self.manifest.import_refusals = self.expected_refusals()?;
        self.manifest.import_omissions = imports;
        self.manifest.bundle_omissions = bundles;
        Ok(())
    }

    pub(super) fn validate_bundles(&self) -> Result<()> {
        for bundle in &self.skills {
            if bundle.source_tree.is_some() != bundle.source_format.is_some() {
                return Err(invalid(
                    "skill source format and tree must be present together",
                ));
            }
            if let Some(tree) = &bundle.source_tree {
                tree.validate()?;
                if let Some(hash) = &tree.content_hash {
                    let body = crate::skill::decode_skill_record(&bundle.entity.body.to_bytes()?)?;
                    if body.content_hash.map(|h| h.to_hex()).as_ref() != Some(hash) {
                        return Err(invalid("skill source hash disagrees with its native row"));
                    }
                    crate::skill_hub::package_from_source(
                        &body,
                        tree.import_files()?,
                        bundle
                            .source_format
                            .ok_or_else(|| invalid("skill source format missing"))?,
                    )?;
                }
            }
        }
        let mut bindings = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for bundle in &self.agent_packs {
            let id = document_import::parse_id(&bundle.entity_id)?;
            if !ids.insert(id) {
                return Err(invalid("duplicate agent source bundle"));
            }
            if let Some(hash) = &bundle.fork_hash {
                crate::skill::SkillContentHash::parse_hex(hash)?;
                bindings.insert(id, hash.clone());
            }
            if let Some(tree) = &bundle.source_tree {
                tree.validate()?;
            }
        }
        // Recompute every typed facet from the native AGENT_DEF and selected
        // knowledge/skill records. A caller cannot replace policy.md or add code.
        let mut expected = self.clone();
        crate::serialize::populate_agent_bundles(&mut expected, &bindings)?;
        if self.agent_packs != expected.agent_packs {
            return Err(invalid("agent facets disagree with native rows"));
        }
        let (imports, bundles) = self.expected_omissions();
        if self.manifest.import_omissions != imports
            || self.manifest.import_refusals != self.expected_refusals()?
            || self.manifest.bundle_omissions != bundles
        {
            return Err(invalid(
                "manifest omission declaration disagrees with document",
            ));
        }
        Ok(())
    }

    fn expected_refusals(&self) -> Result<Vec<ExportImportRefusal>> {
        let mut rows: Vec<_> = self.entities().collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        let mut refusals = Vec::new();
        for row in rows {
            if archive_only_reason(row).is_some() {
                continue;
            }
            let reason = if matches!(row.body, ExportBody::Nulled)
                || matches!(&row.body, ExportBody::Pack(value) if matches!(value.payload, ExportBody::Nulled))
            {
                Some(ImportRefusalReason::RedactedBody)
            } else if crate::registry::zone_of(row.entity_type)
                != crate::registry::TypeByteZone::PackHandle
                && crate::registry::validate_public_entity_type(row.entity_type).is_err()
            {
                Some(ImportRefusalReason::OwningEntityAdapterRequired)
            } else if row.entity_type == ENTITY_TYPE_CLAIM
                && crate::claim::decode_claim_body(&row.body.to_bytes()?, false).is_err()
            {
                Some(ImportRefusalReason::OwningClaimAdapterRequired)
            } else {
                None
            };
            if let Some(reason) = reason {
                refusals.push(ExportImportRefusal::Entity {
                    entity_id: row.id.clone(),
                    reason,
                });
            }
        }
        let mut bundles: Vec<_> = self.skills.iter().collect();
        bundles.sort_by(|a, b| a.entity.id.cmp(&b.entity.id));
        for bundle in bundles {
            if bundle
                .source_tree
                .as_ref()
                .is_some_and(|tree| tree.content_hash.is_none())
            {
                refusals.push(ExportImportRefusal::Entity {
                    entity_id: bundle.entity.id.clone(),
                    reason: ImportRefusalReason::RedactedSource,
                });
            }
        }
        let omitted: BTreeSet<_> = self
            .entities()
            .filter_map(|row| archive_only_reason(row).map(|_| row.id.as_str()))
            .collect();
        let mut edges: Vec<_> = self.evidence_ledger.edges.iter().collect();
        edges.sort_by(|a, b| (&a.source, a.kind, &a.target).cmp(&(&b.source, b.kind, &b.target)));
        for edge in edges {
            if edge.provenance.is_some()
                && !omitted.contains(edge.source.as_str())
                && !omitted.contains(edge.target.as_str())
            {
                refusals.push(ExportImportRefusal::ProvenancedEdge {
                    source: edge.source.clone(),
                    edge_kind: edge.kind,
                    target: edge.target.clone(),
                });
            }
        }
        Ok(refusals)
    }

    fn expected_omissions(&self) -> (Vec<ExportImportOmission>, Vec<ExportBundleOmission>) {
        let mut imports = Vec::new();
        for row in self.entities() {
            if let Some(reason) = archive_only_reason(row) {
                imports.push(ExportImportOmission {
                    entity_id: row.id.clone(),
                    reason,
                });
            }
        }
        imports.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        let mut bundles = Vec::new();
        for bundle in &self.skills {
            let reason = match &bundle.source_tree {
                None => Some(BundleOmissionReason::SkillSourceUnavailable),
                Some(tree) if tree.content_hash.is_none() => {
                    Some(BundleOmissionReason::SkillSourceRedacted)
                }
                Some(_) => None,
            };
            if let Some(reason) = reason {
                bundles.push(ExportBundleOmission {
                    entity_id: bundle.entity.id.clone(),
                    reason,
                });
            }
        }
        for bundle in &self.agent_packs {
            if let Some(omission) = bundle.omission {
                let reason = match omission {
                    AgentBundleOmission::ForkBindingUnavailable => {
                        BundleOmissionReason::AgentForkBindingUnavailable
                    }
                    AgentBundleOmission::UnresolvedSkill => {
                        BundleOmissionReason::AgentUnresolvedSkill
                    }
                    AgentBundleOmission::CredentialRedaction => {
                        BundleOmissionReason::AgentCredentialRedaction
                    }
                };
                bundles.push(ExportBundleOmission {
                    entity_id: bundle.entity_id.clone(),
                    reason,
                });
            }
        }
        bundles.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        (imports, bundles)
    }
}

/// This is a closed list of archive-only families, not a reserved-claim import
/// bypass. Other reserved claims still fail their ordinary import door.
fn archive_only_reason(row: &ExportEntity) -> Option<ImportOmissionReason> {
    match row.entity_type {
        ENTITY_TYPE_SKILL_CONTENT_ANCHOR => Some(ImportOmissionReason::SkillAnchorRecomputed),
        ENTITY_TYPE_SKILL_HUB => Some(ImportOmissionReason::HubConfigurationNotRestored),
        ENTITY_TYPE_POLICY_MANIFEST => Some(ImportOmissionReason::PolicyAuthorityNotRestored),
        ENTITY_TYPE_CLAIM => {
            // Decode a reserved claim only for classification; NEVER store it.
            let predicate = match &row.body {
                ExportBody::MessagePack(crate::serialize::ExportValue::Map(entries)) => {
                    entries.iter().find_map(|(k, v)| match (k, v) {
                        (
                            crate::serialize::ExportValue::String(k),
                            crate::serialize::ExportValue::String(v),
                        ) if k == "pred" => Some(v.as_str()),
                        _ => None,
                    })
                }
                _ => None,
            };
            if matches!(
                predicate,
                Some(
                    crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE
                        | crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT
                )
            ) {
                Some(ImportOmissionReason::ForeignSkillSignalNotRestored)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault bundle: {reason}"))
}
