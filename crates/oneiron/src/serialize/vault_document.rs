//! Whole-vault export uses the ContextPack format writers without retrieval
//! projection, timestamp normalization, truncation, or token budgets.
use serde_json::Value;

use super::credential_nulling::null_credentials;
use super::export_value::{ExportBody, ExportValue};
use super::markdown_plaintext_format::{write_markdown_groups, write_plaintext_groups};
use super::pack_entry::{PreparedEntity, PreparedEntitySource};
use super::toon_format::encode_toon_section;
use super::types::GroupKey;
use super::yaml_format::write_yaml_groups;
use crate::batch::export::ExportSnapshot;
use crate::batch::export::{
    ExportDerivationEnvelope, ExportEntity, ExportLedger, ExportSourceVault,
    WHOLE_VAULT_DOCUMENT_VERSION, WholeVaultDocument, WholeVaultDocumentManifest, WholeVaultExport,
};
use crate::context_pack::PackFormat;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};

pub(crate) fn serialize_vault_snapshot(
    mut snapshot: ExportSnapshot,
    format: PackFormat,
) -> Result<WholeVaultExport> {
    let storage = snapshot.storage.with_serializer_nulling();
    let manifest = WholeVaultDocumentManifest {
        manifest_version: WHOLE_VAULT_DOCUMENT_VERSION,
        format: format_name(format).to_owned(),
        serializer: storage.serializer().clone(),
        secrets_nulled: true,
        source_vault: ExportSourceVault {
            vault_id: storage.authority().map(|a| a.vault_id().to_owned()),
            exported_at: snapshot.exported_at,
        },
        storage,
        import_omissions: Vec::new(),
        import_refusals: Vec::new(),
        bundle_omissions: Vec::new(),
        source_boundaries: vec![
            crate::batch::export::ExportSourceBoundary::BuiltinAdapterCodeNotStored,
        ],
    };
    let mut document = WholeVaultDocument {
        manifest,
        evidence_ledger: ExportLedger {
            entities: Vec::new(),
            edges: snapshot.edges,
        },
        claims: Vec::new(),
        packs: snapshot
            .adapters
            .into_iter()
            .map(crate::batch::export::ExportPack::BuiltinAdapter)
            .collect(),
        skills: Vec::new(),
        agent_packs: Vec::new(),
        derivation_envelopes: Vec::new(),
    };
    for raw in snapshot.entities {
        let body = if raw.tainted {
            ExportBody::Nulled
        } else {
            ExportBody::from_bytes(&raw.body, raw.header.entity_type)
        };
        if raw.header.entity_type == ENTITY_TYPE_CLAIM
            && let ExportBody::MessagePack(ExportValue::Map(entries)) = &body
            && let Some((_, evidence)) = entries
                .iter()
                .find(|(key, _)| matches!(key, ExportValue::String(key) if key == "evid"))
        {
            document
                .derivation_envelopes
                .push(ExportDerivationEnvelope {
                    id: raw.id.to_hex(),
                    evidence: evidence.clone(),
                    receipts: crate::batch::export::receipt_sources_for_body(
                        &body,
                        &snapshot.task_receipts,
                        snapshot.archived_receipts.get(&raw.id),
                    )?,
                });
        }
        let entity = ExportEntity {
            id: raw.id.to_hex(),
            short_ref: raw.short_ref,
            entity_type: raw.header.entity_type,
            occurred_start: raw.header.occurred_start,
            occurred_end: raw.header.occurred_end,
            learned_at: raw.header.learned_at,
            body,
        };
        if let Some(source) = snapshot.pack_sources.remove(&raw.id) {
            let mut tree = super::export_source_tree(source.files())?;
            if raw.tainted {
                tree.content_hash = None;
                for file in &mut tree.files {
                    file.content = None;
                    file.sha256 = None;
                }
            }
            document
                .packs
                .push(crate::batch::export::ExportPack::Source(
                    crate::batch::export::ExportPackSource {
                        entity_id: raw.id.to_hex(),
                        source_tree: tree,
                    },
                ));
        }
        match entity.entity_type {
            ENTITY_TYPE_CLAIM => document.claims.push(entity),
            ENTITY_TYPE_SKILL => {
                let package = snapshot.skill_packages.remove(&raw.id);
                let source_format = package.as_ref().map(|package| package.format);
                let source_tree = package
                    .map(|package| super::export_source_tree(&package.files))
                    .transpose()?;
                let source_tree = source_tree.map(|mut tree| {
                    if raw.tainted {
                        tree.content_hash = None;
                        for file in &mut tree.files {
                            file.content = None;
                            file.sha256 = None;
                        }
                    }
                    tree
                });
                document
                    .skills
                    .push(crate::batch::export::ExportSkillBundle {
                        entity,
                        source_tree,
                        source_format,
                    });
            }
            _ => document.evidence_ledger.entities.push(entity),
        }
    }
    super::vault_bundles::populate_agent_bundles(&mut document, &snapshot.agent_fork_hashes)?;
    document.refresh_omissions()?;
    let bytes = encode_document(&document, format)?;
    Ok(WholeVaultExport {
        bytes,
        manifest: document.manifest,
    })
}

fn format_name(format: PackFormat) -> &'static str {
    match format {
        PackFormat::Json => "json",
        PackFormat::Yaml => "yaml",
        PackFormat::Toon => "toon",
        PackFormat::Markdown => "markdown",
        PackFormat::Plaintext => "plaintext",
        PackFormat::OpenaiCompat => "openai-compat",
        PackFormat::AnthropicMessages => "anthropic-messages",
        PackFormat::Gemini => "gemini",
    }
}

fn encode_document(document: &WholeVaultDocument, format: PackFormat) -> Result<Vec<u8>> {
    let value = serde_json::to_value(document)
        .map_err(|_| Error::InvariantViolation("whole-vault document serialization failed"))?;
    // This second pass covers descriptors and manifest strings too. Body keys
    // and binary values were already inspected before the typed-tree encoding.
    let value = null_credentials("", &value);
    if format == PackFormat::Json {
        return serde_json::to_vec(&value)
            .map_err(|_| Error::InvariantViolation("whole-vault JSON serialization failed"));
    }
    let mut groups = Vec::new();
    for name in [
        "manifest",
        "evidence_ledger",
        "claims",
        "packs",
        "skills",
        "agent_packs",
        "derivation_envelopes",
    ] {
        let content = value.get(name).cloned().unwrap_or(Value::Null);
        // One document-section row preserves empty sections in every format.
        // Nested values go through the same established writers as ContextPack.
        let row = PreparedEntity {
            entity_type: 0,
            score: 0.0,
            critical: false,
            source: PreparedEntitySource::Result,
            source_id: [0; 16],
            id: name.to_owned(),
            fields: vec![("entries".to_owned(), content)],
        };
        groups.push((GroupKey::ExportSection(name), vec![row]));
    }
    // Provider wire formats have no whole-vault document shape; the export
    // manifest pins one of the five document formats above.
    if matches!(
        format,
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini
    ) {
        return Err(Error::InvalidConfig(
            "whole-vault export does not support provider wire formats".to_owned(),
        ));
    }
    let mut out = String::new();
    match format {
        PackFormat::Json => unreachable!(),
        PackFormat::Yaml => write_yaml_groups(&mut out, &groups, 0),
        PackFormat::Toon => {
            out = encode_toon_section(&groups, &mut super::handles::Handles::default());
        }
        PackFormat::Markdown => write_markdown_groups(&mut out, &groups, "##"),
        PackFormat::Plaintext => write_plaintext_groups(&mut out, &groups),
        PackFormat::OpenaiCompat | PackFormat::AnthropicMessages | PackFormat::Gemini => {
            unreachable!("provider formats refused above");
        }
    }
    Ok(out.into_bytes())
}
