//! Validate source identities, facet/body agreement and explicit archive-only omissions.
use super::*;
use crate::agent_def::KnowledgeFormat;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL_CONTENT_ANCHOR,
    ENTITY_TYPE_SKILL_HUB,
};
use crate::serialize::ExportBody;
use std::collections::{BTreeMap, BTreeSet};

impl WholeVaultDocument {
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
        crate::serialize::populate_agent_bundles(
            &mut expected,
            &bindings,
            KnowledgeFormat::CURRENT,
        )?;
        if self.agent_packs != expected.agent_packs {
            // An archive an older engine wrote carries the first knowledge form.
            crate::serialize::populate_agent_bundles(
                &mut expected,
                &bindings,
                KnowledgeFormat::V1,
            )?;
            if self.agent_packs != expected.agent_packs {
                return Err(invalid("agent facets disagree with native rows"));
            }
        }
        let (refusals, imports, bundles) = self.omission_ledger()?.finish();
        if self.manifest.import_omissions != imports
            || self.manifest.import_refusals != refusals
            || self.manifest.bundle_omissions != bundles
        {
            return Err(invalid(
                "manifest omission declaration disagrees with document",
            ));
        }
        Ok(())
    }

    /// The omission and refusal lists this document's rows declare, gathered
    /// as an export gathers them one row at a time.
    fn omission_ledger(&self) -> Result<OmissionLedger> {
        let mut ledger = OmissionLedger::default();
        for row in self.entities() {
            ledger.entity(row)?;
        }
        for bundle in &self.skills {
            ledger.skill(bundle);
        }
        for edge in &self.evidence_ledger.edges {
            ledger.edge(edge);
        }
        let assets: BTreeMap<&str, &ExportBody> = self
            .entities()
            .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_ASSET)
            .map(|row| (row.id.as_str(), &row.body))
            .collect();
        for bundle in &self.agent_packs {
            ledger.agent(bundle, |carrier| {
                assets.get(carrier.to_hex().as_str()).copied()
            });
        }
        Ok(ledger)
    }
}

/// The manifest's import refusals, import omissions and bundle omissions,
/// gathered one row at a time (FIX 2766): an export streams its rows past
/// this ledger, and an import's validation feeds it the same rows again.
#[derive(Default)]
pub(crate) struct OmissionLedger {
    entity_refusals: Vec<(String, ImportRefusalReason)>,
    source_refusals: Vec<String>,
    archive_only: BTreeMap<String, ImportOmissionReason>,
    provenance_subjects: BTreeSet<(String, u8, String)>,
    provenanced_edges: Vec<(String, u8, String)>,
    bundle_omissions: Vec<ExportBundleOmission>,
}

impl OmissionLedger {
    /// One entity row, before the document's second credential pass.
    pub(crate) fn entity(&mut self, row: &ExportEntity) -> Result<()> {
        if row.entity_type == ENTITY_TYPE_CLAIM
            && super::provenance_import::is_provenance(row)
            && let Some(crate::claim::ClaimSubject::Edge {
                source,
                kind,
                target,
            }) = row
                .body
                .to_bytes()
                .ok()
                .and_then(|bytes| crate::claim::decode_claim_body(&bytes, true).ok())
                .map(|claim| claim.subject)
        {
            self.provenance_subjects
                .insert((source.to_hex(), kind as u8, target.to_hex()));
        }
        if let Some(reason) = archive_only_reason(row) {
            self.archive_only.insert(row.id.clone(), reason);
            return Ok(());
        }
        let reason = if matches!(&row.body,ExportBody::HubSource(source) if source.redacted())
            || matches!(row.body, ExportBody::Nulled)
            || matches!(&row.body, ExportBody::Pack(value) if matches!(value.payload, ExportBody::Nulled))
        {
            Some(ImportRefusalReason::RedactedBody)
        } else if row.entity_type == crate::registry::ENTITY_TYPE_MODEL
            || super::provenance_import::is_provenance(row)
        {
            None
        } else if crate::registry::zone_of(row.entity_type)
            != crate::registry::TypeByteZone::PackHandle
            && crate::registry::validate_public_entity_type(row.entity_type).is_err()
        {
            Some(ImportRefusalReason::OwningEntityAdapterRequired)
        } else if super::expression_import::is_expression(row) {
            Some(ImportRefusalReason::LocalExpressionWriterRequired)
        } else if row.entity_type == ENTITY_TYPE_CLAIM
            && crate::claim::decode_claim_body(&row.body.to_bytes()?, false).is_err()
            && !crate::claim::decode_claim_body(&row.body.to_bytes()?, true).is_ok_and(|body| {
                crate::subject_model::imported_subject_body(&body).is_ok()
                    || crate::actor_claims::imported_actor_body(&body).is_ok()
                    || crate::skill_reliability::imported_reliability_body(&body).is_ok()
                    || crate::edit_distance::attribution::imported_skill_cost_body(&body)
                        .is_ok()
            })
        {
            Some(ImportRefusalReason::OwningClaimAdapterRequired)
        } else {
            None
        };
        if let Some(reason) = reason {
            self.entity_refusals.push((row.id.clone(), reason));
        }
        Ok(())
    }

    /// One skill's source bundle.
    pub(crate) fn skill(&mut self, bundle: &ExportSkillBundle) {
        let reason = match &bundle.source_tree {
            None => Some(BundleOmissionReason::SkillSourceUnavailable),
            Some(tree) if tree.content_hash.is_none() => {
                self.source_refusals.push(bundle.entity.id.clone());
                Some(BundleOmissionReason::SkillSourceRedacted)
            }
            Some(_) => None,
        };
        if let Some(reason) = reason {
            self.bundle_omissions.push(ExportBundleOmission {
                entity_id: bundle.entity.id.clone(),
                reason,
            });
        }
    }

    /// One graph edge: a provenanced edge needs its owning claim adapter.
    pub(crate) fn edge(&mut self, edge: &ExportEdge) {
        if edge.provenance.is_some() {
            self.provenanced_edges
                .push((edge.source.clone(), edge.kind, edge.target.clone()));
        }
    }

    /// One agent's bundle; `asset` lends the body of an ASSET row the
    /// document holds under an id.
    pub(crate) fn agent<'a>(
        &mut self,
        bundle: &ExportAgentBundle,
        asset: impl Fn(&crate::entity_id::EntityId) -> Option<&'a ExportBody>,
    ) {
        if let Some(hash) = &bundle.fork_hash {
            let available = document_import::parse_id(&bundle.entity_id)
                .ok()
                .is_some_and(|child| {
                    crate::agent_def::birth_source_id(&child)
                        .ok()
                        .and_then(|carrier| asset(&carrier))
                        .and_then(|body| body.to_bytes().ok())
                        .is_some_and(|bytes| {
                            crate::agent_def::archived_birth_source_matches(&child, hash, &bytes)
                        })
                });
            if !available {
                self.bundle_omissions.push(ExportBundleOmission {
                    entity_id: bundle.entity_id.clone(),
                    reason: BundleOmissionReason::AgentBirthSourceUnavailable,
                });
            }
        }
        if let Some(omission) = bundle.omission {
            let reason = match omission {
                AgentBundleOmission::ForkBindingUnavailable => {
                    BundleOmissionReason::AgentForkBindingUnavailable
                }
                AgentBundleOmission::UnresolvedSkill => BundleOmissionReason::AgentUnresolvedSkill,
                AgentBundleOmission::CredentialRedaction => {
                    BundleOmissionReason::AgentCredentialRedaction
                }
            };
            self.bundle_omissions.push(ExportBundleOmission {
                entity_id: bundle.entity_id.clone(),
                reason,
            });
        }
    }

    /// Forgets rows that left the archive after the snapshot (OF-490: a
    /// diary whose read could not be logged).
    pub(crate) fn forget(&mut self, ids: &BTreeSet<String>) {
        self.archive_only.retain(|id, _| !ids.contains(id));
        self.entity_refusals.retain(|(id, _)| !ids.contains(id));
    }

    /// The import refusals, import omissions and bundle omissions, each in
    /// the manifest's order.
    pub(crate) fn finish(
        mut self,
    ) -> (
        Vec<ExportImportRefusal>,
        Vec<ExportImportOmission>,
        Vec<ExportBundleOmission>,
    ) {
        self.entity_refusals.sort_by(|a, b| a.0.cmp(&b.0));
        self.source_refusals.sort();
        self.provenanced_edges.sort();
        let mut refusals: Vec<_> = self
            .entity_refusals
            .into_iter()
            .map(|(entity_id, reason)| ExportImportRefusal::Entity { entity_id, reason })
            .collect();
        refusals.extend(
            self.source_refusals
                .into_iter()
                .map(|entity_id| ExportImportRefusal::Entity {
                    entity_id,
                    reason: ImportRefusalReason::RedactedSource,
                }),
        );
        for (source, edge_kind, target) in self.provenanced_edges {
            if !self
                .provenance_subjects
                .contains(&(source.clone(), edge_kind, target.clone()))
                && !self.archive_only.contains_key(&source)
                && !self.archive_only.contains_key(&target)
            {
                refusals.push(ExportImportRefusal::ProvenancedEdge {
                    source,
                    edge_kind,
                    target,
                });
            }
        }
        let imports = self
            .archive_only
            .into_iter()
            .map(|(entity_id, reason)| ExportImportOmission { entity_id, reason })
            .collect();
        self.bundle_omissions
            .sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        (refusals, imports, self.bundle_omissions)
    }
}

/// This is a closed list of archive-only families, not a reserved-claim import
/// bypass. Other reserved claims still fail their ordinary import door.
fn archive_only_reason(row: &ExportEntity) -> Option<ImportOmissionReason> {
    match row.entity_type {
        ENTITY_TYPE_SKILL_CONTENT_ANCHOR => Some(ImportOmissionReason::SkillAnchorRecomputed),
        ENTITY_TYPE_SKILL_HUB => Some(ImportOmissionReason::HubConfigurationNotRestored),
        ENTITY_TYPE_POLICY_MANIFEST => Some(ImportOmissionReason::PolicyAuthorityNotRestored),
        crate::registry::ENTITY_TYPE_AUTHORITY_LOG
        | crate::registry::ENTITY_TYPE_FEDERATION_GRANT
        | crate::registry::ENTITY_TYPE_ACCESS_GRANT
        | crate::registry::ENTITY_TYPE_CONNECTOR_KEY
        | crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY
        | crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT
        | crate::registry::ENTITY_TYPE_OUTBOUND_GRANT => {
            Some(ImportOmissionReason::LocalAuthorityNotRestored)
        }
        crate::registry::ENTITY_TYPE_DIAGNOSTIC
        | crate::registry::ENTITY_TYPE_REDACTION_AUDIT
        | crate::registry::ENTITY_TYPE_PERSONA_SNAPSHOT_EXPORT
        | crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
        | crate::registry::ENTITY_TYPE_COMM_RECORD => {
            Some(ImportOmissionReason::LocalHistoryNotRestored)
        }
        crate::registry::ENTITY_TYPE_PSYCH_PROFILE => {
            Some(ImportOmissionReason::LocalProjectionNotRestored)
        }
        crate::registry::ENTITY_TYPE_MESSAGE => {
            Some(ImportOmissionReason::WitnessAuthorizationNotRestored)
        }
        crate::registry::ENTITY_TYPE_NOTE => Some(ImportOmissionReason::NoteAuthorshipNotRestored),
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
            } else if matches!(
                predicate,
                Some("actor.peer_binding" | "actor.confidence_prior")
            ) {
                Some(ImportOmissionReason::LocalActorConfigurationNotRestored)
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
