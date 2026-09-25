//! Build portable facets after every native body has passed credential nulling.
use super::{ExportBody, export_source_tree};
use crate::batch::export::{AgentBundleOmission, ExportAgentBundle, WholeVaultDocument};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use std::collections::BTreeMap;

pub(crate) fn populate_agent_bundles(
    document: &mut WholeVaultDocument,
    bindings: &BTreeMap<EntityId, String>,
) -> Result<()> {
    let skills = document
        .skills
        .iter()
        .filter_map(|bundle| {
            let id = EntityId::from_hex(&bundle.entity.id).ok()?;
            let body = bundle.entity.body.to_bytes().ok()?;
            let record = crate::skill::decode_skill_record(&body).ok()?;
            Some((id, record))
        })
        .collect::<Vec<_>>();
    let mut bundles = Vec::new();
    for row in &document.evidence_ledger.entities {
        if row.entity_type != ENTITY_TYPE_AGENT_DEF {
            continue;
        }
        let id = EntityId::from_hex(&row.id)?;
        let mut bundle = ExportAgentBundle {
            entity_id: row.id.clone(),
            fork_hash: bindings.get(&id).cloned(),
            source_tree: None,
            omission: None,
        };
        let definition = row
            .body
            .to_bytes()
            .ok()
            .and_then(|b| crate::agent_def::decode_agent_definition(&b).ok());
        if let Some(definition) = definition {
            if let Some(refs) = crate::agent_def::resolve_agent_skill_refs(&definition, &skills) {
                let knowledge = crate::agent_def::select_agent_knowledge(&id, &document.claims);
                let files =
                    crate::agent_def::agent_pack_files(&id, &definition, &refs, &knowledge)?;
                let tree = export_source_tree(&files)?;
                bundle.omission = if tree.content_hash.is_none() {
                    Some(AgentBundleOmission::CredentialRedaction)
                } else if bundle.fork_hash.is_none() {
                    Some(AgentBundleOmission::ForkBindingUnavailable)
                } else {
                    None
                };
                bundle.source_tree = Some(tree);
            } else {
                bundle.omission = Some(AgentBundleOmission::UnresolvedSkill);
            }
        } else {
            // Redacted definition fields cannot be reinterpreted as an empty agent.
            bundle.omission = Some(AgentBundleOmission::CredentialRedaction);
        }
        if matches!(row.body, ExportBody::Nulled) {
            bundle.fork_hash = None;
        }
        bundles.push(bundle);
    }
    document.agent_packs = bundles;
    Ok(())
}
