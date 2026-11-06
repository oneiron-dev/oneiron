//! The run results of a whole-vault archive import, put in the import's one
//! write transaction: each released occurrence's body, the replay record its
//! run's restored outputs and bindings rebuild, and the run's fold receipts.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use super::archive_index::{IndexedArchive, Tag};
use super::document_import::{invalid, parse_id};
use super::{ArchiveRecordKind, ExportRun};
use crate::Vault;
use crate::error::Result;

/// Writes each run's results whose bodies came back as that run's
/// occurrences; a result the export withheld stays a manifest in the
/// archive. Returns the counts of both. Each body is staged from the archive
/// as its occurrence goes in, checked against its digest and length, so the
/// manifests and line indexes are rebuilt from the bytes; the secret scan
/// reads them again as they go in. No body is held between two occurrences
/// (FIX 3678): a later occurrence of the same bytes stages them again. Each
/// newly staged archive digest is pushed before the staging calls can fail;
/// each final digest is retained immediately after staging, before occurrence
/// validation, for the import's post-error cleanup (FIX 588).
///
/// FIX 6648: `known` holds one instance, reserved before this writer opened,
/// for each occurrence staged here. So a masked copy goes in even when the
/// scan makes it longer than the inline bound. A body with a secret the wall
/// cannot place still keeps its archived bytes (CALLS C5718-22).
pub(super) fn put_run_results_in_txn<R: Read + Seek>(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    archive: &mut IndexedArchive<'_, R>,
    known: crate::store::result_manifest::StagedSinks,
    staged: &mut Vec<[u8; 32]>,
) -> Result<(usize, usize, usize, usize, usize, usize, usize)> {
    let (mut imported, mut withheld) = (0, 0);
    let (mut bindings_bound, mut bindings_unresolved, mut bindings_withheld) = (0, 0, 0);
    let (mut records_rebuilt, mut records_skipped) = (0, 0);
    // Manifests only: bodies are streamed above and never retained between
    // occurrences. These outputs rebuild each run's replay record below.
    let mut restored_outputs = BTreeMap::new();
    // The values custody knows, read in this writer and kept no longer
    // (KS-3), shared with the write's other passes (FIX 12210, 12229): each
    // body's sweep replaces them with their handles.
    let swept = crate::store::known_value_index::KnownValues::shared_in_writer(&vault.store, wtxn)?;
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        let run_id = parse_id(&run.run_id)?;
        let mut manifests = Vec::with_capacity(run.outputs.len());
        for output in &run.outputs {
            let Some(blake3) = &output.blake3 else {
                withheld += 1;
                continue;
            };
            let digest = parse_digest(blake3)?;
            let Some(listed) = archive.files.file_len(blake3) else {
                withheld += 1;
                continue;
            };
            if !archive.index.contains(Tag::Released, blake3.as_bytes())? {
                withheld += 1;
                continue;
            }
            // Only a body's first occurrence is held to its manifest's length.
            // A newly staged digest is tracked before the length check and
            // the read/admit/stage calls below, so even a partial stage or
            // the digest-length error is covered; later occurrences of the
            // same bytes push nothing again.
            let fresh = archive.index.insert(Tag::Staged, &digest, &[])?;
            if fresh {
                staged.push(digest);
            }
            if fresh && listed != output.bytes {
                return Err(invalid("run result body does not match its digest"));
            }
            // The manifest path is validated with from_facts' own
            // predicate before staging publishes the spill: from_facts
            // rejects an empty/overlong path only after publication, when
            // cleanup would know just the archive digest (FIX 588).
            crate::store::result_manifest::validate_text(
                &output.path,
                crate::store::result_manifest::CODE_RUN_REPLAY_MAX_OUTPUT_PATH_BYTES,
                "raw output path",
            )?;
            // Masked at write as a run's reply body is (FIX 5718 part 3).
            // FIX 6648: this occurrence has its own reserved instance, so
            // the masked copy may spill even when the scan makes it longer.
            let body = archive.files.read_file(blake3)?;
            let body = vault.admit_imported_result_in_txn(
                wtxn,
                run_id,
                &output.path,
                body,
                swept.as_ref(),
                true,
            )?;
            let finished = vault.stage_code_run_output_from(
                output.path.clone(),
                vault.code_run_output_sink_knowing(known.clone(), swept.clone())?,
                std::io::Cursor::new(body),
            )?;
            staged.push(finished.output.raw_blake3);
            let occurrence = finished.at(output.path.clone(), output.complete)?;
            vault.put_code_run_output_in_txn(wtxn, &finished, &occurrence, Some(run_id))?;
            // Custody admission may have masked the bytes, so the restored
            // manifest's own handle can differ from the archived one the
            // bindings name. The canonical handle of the archived digest is
            // kept beside the restored occurrence, in memory only, so the
            // rebind below resolves through it.
            manifests.push(RestoredRunOutput {
                source_handle: format!(
                    "{}{}",
                    crate::store::result_manifest::CODE_RUN_OUTPUT_HANDLE_PREFIX,
                    crate::entity_id::bytes_to_hex_lower(&digest)
                ),
                output: occurrence,
            });
            imported += 1;
        }
        if !manifests.is_empty() {
            restored_outputs.insert(run_id, manifests);
        }
    }
    // The occurrences are in before their names, exactly as they are for the
    // receipts below. Rebuild only the approved outputs + bindings record;
    // bridge calls, checkpoints and other full-replay inputs stay unknown.
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        let run_id = parse_id(&run.run_id)?;
        let outputs = restored_outputs
            .get(&run_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let (bindings, unresolved, withheld_names) = rebind_run_results(outputs, &run.bindings)?;
        bindings_bound += bindings.len();
        bindings_unresolved += unresolved;
        bindings_withheld += withheld_names;
        let determinism = run
            .determinism
            .as_ref()
            .map(|determinism| {
                parse_digest(&determinism.rng_seed).map(|seed| {
                    crate::code_run::CodeRunDeterminism::new(determinism.frozen_unix_ms, seed)
                })
            })
            .transpose()?;
        if outputs.is_empty() {
            continue;
        }
        let mut record =
            crate::code_run::CodeRunReplayRecord::with_determinism(run_id, determinism);
        record.outputs = outputs
            .iter()
            .map(|restored| restored.output.clone())
            .collect();
        record.bindings = bindings;
        record.callable_rows = None;
        let existing = {
            let rtxn: &heed::RoTxn<'_> = wtxn;
            vault.get_code_run_replay_record_in_txn(rtxn, &run_id)?
        };
        let same = existing.as_ref().is_some_and(|current| {
            current.determinism == record.determinism
                && current
                    .outputs
                    .iter()
                    .map(|output| (&output.handle, &output.path, output.complete))
                    .eq(record
                        .outputs
                        .iter()
                        .map(|output| (&output.handle, &output.path, output.complete)))
                && current
                    .bindings
                    .iter()
                    .map(|binding| (&binding.name, &binding.handle, &binding.path))
                    .eq(record
                        .bindings
                        .iter()
                        .map(|binding| (&binding.name, &binding.handle, &binding.path)))
        });
        match existing {
            None => {
                vault.put_code_run_replay_record_in_txn(wtxn, &record)?;
                records_rebuilt += 1;
            }
            Some(_) if same => records_skipped += 1,
            Some(_) => return Err(invalid("run replay record collision")),
        }
    }
    // A receipt comes back with the occurrence it describes, and only whole:
    // a withheld one's refs stay in the archive. Every run's outputs are in
    // first, so a ref to another run's output resolves; one that resolves to
    // nothing (not in the archive, nor in this vault) is named unresolved.
    let mut runs = archive.spool.rows(ArchiveRecordKind::Run);
    while let Some((_, run)) = runs.next_parsed::<ExportRun>(&archive.spool)? {
        let run_id = parse_id(&run.run_id)?;
        for fold in run.receipts.iter().filter(|fold| fold.withheld.is_none()) {
            let mut came_back = false;
            for output in run.outputs.iter().filter(|output| output.path == fold.path) {
                if let Some(digest) = output
                    .blake3
                    .as_deref()
                    .and_then(|blake3| parse_digest(blake3).ok())
                {
                    came_back |= archive.index.contains(Tag::Staged, &digest)?;
                }
            }
            if !came_back {
                continue;
            }
            let mut receipt: crate::store::reader_fold_receipt::ReaderFoldReceipt =
                serde_json::from_value(fold.receipt.clone())
                    .map_err(|_| invalid("run fold receipt"))?;
            if receipt.folded.owner != run_id || receipt.folded.path != fold.path {
                return Err(invalid("run fold receipt names another occurrence"));
            }
            let rtxn: &heed::RoTxn<'_> = wtxn;
            receipt.mark_unresolved(|named| {
                Ok(crate::store::owned_body::owned_body_in_txn(
                    &vault.store,
                    rtxn,
                    &named.owner,
                    &named.occurrence,
                )?
                .is_some())
            })?;
            vault.put_code_run_reader_fold_in_txn(wtxn, &receipt)?;
        }
    }
    Ok((
        imported,
        withheld,
        bindings_bound,
        bindings_unresolved,
        bindings_withheld,
        records_rebuilt,
        records_skipped,
    ))
}

/// One restored result occurrence with the archived handle that named it.
/// Custody admission can mask the bytes as they go in, so the restored
/// manifest's own handle may differ from the archived one; the rebind
/// matches archived names through this association, never the two
/// handle namespaces against each other.
struct RestoredRunOutput {
    source_handle: String,
    output: crate::code_run::CodeRunRawOutput,
}

/// Rebinds archived names to the outputs restored in this writer. A name or
/// handle with the wrong shape is malformed archive data; a well-formed
/// archived occurrence no restored output matches is merely unresolved.
fn rebind_run_results(
    outputs: &[RestoredRunOutput],
    bindings: &[super::ExportRunBinding],
) -> Result<(Vec<crate::code_run::CodeRunResultBinding>, usize, usize)> {
    let mut bound = Vec::new();
    let (mut unresolved, mut withheld) = (0, 0);
    for binding in bindings {
        if !crate::code_run::CodeRunResultBinding::is_valid_name(&binding.name) {
            return Err(invalid("run result binding name"));
        }
        match (&binding.handle, &binding.withheld) {
            (None, Some(_)) => withheld += 1,
            (Some(handle), None) => {
                let hex = handle
                    .strip_prefix(crate::store::result_manifest::CODE_RUN_OUTPUT_HANDLE_PREFIX)
                    .ok_or_else(|| invalid("run result binding handle"))?;
                let digest = parse_digest(hex)?;
                if crate::entity_id::bytes_to_hex_lower(&digest) != hex {
                    return Err(invalid("run result binding handle"));
                }
                if let Some(restored) = outputs.iter().find(|restored| {
                    restored.source_handle == handle.as_str()
                        && restored.output.path == binding.path
                }) {
                    bound.push(crate::code_run::CodeRunResultBinding::new(
                        binding.name.clone(),
                        restored.output.handle.clone(),
                        restored.output.path.clone(),
                    ));
                } else {
                    unresolved += 1;
                }
            }
            _ => return Err(invalid("run result binding handle")),
        }
    }
    Ok((bound, unresolved, withheld))
}

fn parse_digest(text: &str) -> Result<[u8; 32]> {
    let mut digest = [0; 32];
    if text.len() != 64 {
        return Err(invalid("run result digest"));
    }
    for (byte, pair) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *byte = std::str::from_utf8(pair)
            .ok()
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(|| invalid("run result digest"))?;
    }
    Ok(digest)
}
