//! Whole-vault export: the snapshot becomes the typed document, the document
//! passes the credential-nulling transform, and the nulled value is cut into
//! the archive (OF-222). No retrieval projection, truncation or token budget.
use super::credential_nulling::null_document_credentials;
use super::export_value::{ExportBody, ExportValue};
use crate::batch::export::{ExportCut, ExportSnapshot, VAULT_OKF_FORMAT};
use crate::batch::export::{
    ExportDerivationEnvelope, ExportEntity, ExportLedger, ExportResultBody, ExportRun,
    ExportRunOutput, ExportRunResults, ExportSourceVault, VAULT_ARCHIVE_FORMAT,
    WHOLE_VAULT_DOCUMENT_VERSION, WholeVaultDocument, WholeVaultDocumentManifest, WholeVaultExport,
};
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};

pub(crate) fn serialize_vault_snapshot(
    mut snapshot: ExportSnapshot,
    cut: ExportCut,
) -> Result<WholeVaultExport> {
    let storage = snapshot.storage.with_serializer_nulling();
    let manifest = WholeVaultDocumentManifest {
        manifest_version: WHOLE_VAULT_DOCUMENT_VERSION,
        format: match cut {
            ExportCut::Archive => VAULT_ARCHIVE_FORMAT,
            ExportCut::Okf => VAULT_OKF_FORMAT,
        }
        .to_owned(),
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
        records: Vec::new(),
        files: Vec::new(),
        diary_holds: snapshot.diary_holds,
        secrets_included: snapshot.secrets_included,
    };
    let (run_results, binary_bodies) =
        export_run_results(snapshot.run_results, snapshot.result_bodies);
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
        run_results,
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
    super::vault_bundles::populate_agent_bundles(
        &mut document,
        &snapshot.agent_fork_hashes,
        crate::agent_def::KnowledgeFormat::CURRENT,
    )?;
    document.refresh_omissions()?;
    let value = serde_json::to_value(&document)
        .map_err(|_| Error::InvariantViolation("whole-vault document serialization failed"))?;
    // This second pass covers descriptors and manifest strings too. Body keys
    // and binary values were already inspected before the typed-tree encoding.
    let value = null_document_credentials(&value);
    let (bytes, manifest) = match cut {
        ExportCut::Archive => {
            super::vault_archive::write_vault_archive(value, &snapshot.secrets, binary_bodies)?
        }
        ExportCut::Okf => (
            super::okf_bundle::write_okf_bundle(&value, snapshot.exported_at)?,
            document.manifest,
        ),
    };
    Ok(WholeVaultExport {
        bytes,
        manifest,
        diary_reads: snapshot.diary_reads,
    })
}

/// The run results section: each body through the release door's scan, or
/// why it is withheld. A text body rides in the document; a body that is no
/// UTF-8 text (Docs Q20) is returned beside it, by BLAKE3, for the archive's
/// `files/`: it is never base64-encoded into the text around that scan.
fn export_run_results(
    runs: Vec<crate::batch::export::ExportSnapshotRun>,
    bodies: std::collections::BTreeMap<[u8; 32], crate::batch::export::ExportSnapshotBody>,
) -> (
    ExportRunResults,
    std::collections::BTreeMap<String, Vec<u8>>,
) {
    let hex = crate::entity_id::bytes_to_hex_lower;
    let mut binary = std::collections::BTreeMap::new();
    let results = ExportRunResults {
        runs: runs
            .into_iter()
            .map(|run| ExportRun {
                run_id: run.run_id.to_hex(),
                outputs: run
                    .outputs
                    .into_iter()
                    .map(|output| ExportRunOutput {
                        blake3: hex(&output.raw_blake3),
                        bytes: output.raw_len,
                        kind: match output.kind {
                            crate::code_run::CodeRunOutputKind::Text => "text",
                            crate::code_run::CodeRunOutputKind::Binary => "binary",
                        }
                        .to_owned(),
                        lines: output.lines,
                        complete: output.complete,
                        path: output.path,
                    })
                    .collect(),
            })
            .collect(),
        bodies: bodies
            .into_iter()
            .map(|(digest, body)| {
                let (content, withheld) = match body.body {
                    Err(reason) => (None, Some(reason)),
                    Ok(bytes) => match String::from_utf8(bytes) {
                        Err(error) => {
                            let bytes = error.into_bytes();
                            match crate::batch::secret_scan::scan_file_content("", &bytes) {
                                Some(_) => (None, Some("credential")),
                                None => {
                                    binary.insert(hex(&digest), bytes);
                                    (None, None)
                                }
                            }
                        }
                        Ok(text) => {
                            match crate::batch::secret_scan::scan_file_content("", text.as_bytes())
                            {
                                Some(_) => (None, Some("credential")),
                                None => (Some(text), None),
                            }
                        }
                    },
                };
                ExportResultBody {
                    blake3: hex(&digest),
                    bytes: body.bytes,
                    content,
                    withheld: withheld.map(str::to_owned),
                }
            })
            .collect(),
    };
    (results, binary)
}
