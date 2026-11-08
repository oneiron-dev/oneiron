//! Exact-field transforms for CLAIM revision artifacts (BIZ-LEGAL-0004 A9).
//!
//! The courtesy-answer writer supplies owner/copy authority. The transform
//! preserves operation history and installs its exact bindings with a local
//! typed body edit and fresh indexes. It is not peer/export erasure proof:
//! replacing a local snapshot alone is not replicated redaction.

use std::collections::BTreeSet;

use loro::{
    ContainerID, ContainerType, EncodedBlobMode, ExportMode, Frontiers, JsonMapOp, JsonOpContent,
    LoroDoc, LoroValue, VersionVector,
};

use super::{DOC, FRONTIER, IDENTITY, doc_raw, put_state, reference, state};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, short_id_content_hash};
use crate::claim::decode_claim_body;
use crate::error::{Error, Result};
use crate::store::checkpoint_payload::loro::prove_loro_equivalent;
use crate::vault::entity_revision::RevisionRef;
use crate::{EntityId, registry::ENTITY_TYPE_CLAIM};

/// Exact top-level keys of a CLAIM's value map selected by its owner.
/// No dotted paths, inferred identifying fields, or other claim columns.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimValueFieldRedaction {
    fields: BTreeSet<String>,
}

impl ClaimValueFieldRedaction {
    /// Selects exact keys, each once. An empty key is a literal map key,
    /// not a wildcard; an empty selection is invalid.
    fn new(fields: impl IntoIterator<Item = String>) -> Result<Self> {
        let fields: BTreeSet<_> = fields.into_iter().collect();
        if fields.is_empty() {
            return Err(invalid("no claim value fields selected"));
        }
        Ok(Self { fields })
    }

    /// Removes only selected keys from one raw CLAIM row's value map.
    /// A missing key or a non-map value has no such field and is unchanged.
    /// Header, source, evidence, subject, scope and all other columns stay.
    /// This alone does not scrub the row's retained history or copies.
    fn redact_row(&self, raw: &[u8]) -> Result<Vec<u8>> {
        let header =
            EntityMetadataHeader::parse(raw).ok_or_else(|| invalid("claim redaction header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            return Err(invalid("claim redaction needs a CLAIM row"));
        }
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            return Ok(raw.to_vec());
        }
        decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
        let (count, start) = map_header(bytes).ok_or_else(|| invalid("claim body map"))?;
        let mut cursor = std::io::Cursor::new(bytes);
        cursor.set_position(start as u64);
        for _ in 0..count {
            let key = read_value(&mut cursor)?;
            let start = cursor.position() as usize;
            read_value(&mut cursor)?;
            let end = cursor.position() as usize;
            if key.as_str() == Some("val") {
                let Some(value) = self.redact_value_map(&bytes[start..end])? else {
                    return Ok(raw.to_vec());
                };
                let mut rewritten = raw[..ENTITY_METADATA_HEADER_LEN + start].to_vec();
                rewritten.extend_from_slice(&value);
                rewritten.extend_from_slice(&bytes[end..]);
                decode_claim_body(&rewritten[ENTITY_METADATA_HEADER_LEN..], true)?;
                return Ok(rewritten);
            }
        }
        Err(invalid("claim value absent"))
    }

    fn redact_value_map(&self, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some((count, start)) = map_header(bytes) else {
            return Ok(None);
        };
        let mut cursor = std::io::Cursor::new(bytes);
        cursor.set_position(start as u64);
        let mut kept = Vec::new();
        for _ in 0..count {
            let start = cursor.position() as usize;
            let key = read_value(&mut cursor)?;
            read_value(&mut cursor)?;
            let end = cursor.position() as usize;
            if !key.as_str().is_some_and(|key| self.fields.contains(key)) {
                kept.push(&bytes[start..end]);
            }
        }
        if kept.len() == count {
            return Ok(None);
        }
        let mut encoded = map_prefix(kept.len())?;
        for entry in kept {
            encoded.extend_from_slice(entry);
        }
        Ok(Some(encoded))
    }

    /// Rewrites every raw-register insertion in a full revision snapshot,
    /// including overwritten values. All operations, their identities,
    /// dependencies, timestamps, messages and retained frontiers survive.
    /// Only the selected CLAIM value-map fields change.
    ///
    /// `bindings` must include every retained `(revision, encoded frontier)`
    /// the eventual writer installs. This pure function cannot prove that a
    /// caller enumerated a live ledger completely. Raw-derived references
    /// are rehashed over the rewritten row; frontier-derived refs stay.
    /// Existing content-bound citations are not relabelled or re-signed.
    fn redact_history(
        &self,
        entity: EntityId,
        snapshot: &[u8],
        bindings: &[(RevisionRef, Vec<u8>)],
    ) -> Result<RedactedClaimRevisionHistory> {
        let source = full_doc(snapshot)?;
        let mut expected = source.export_json_updates_without_peer_compression(
            &VersionVector::default(),
            &source.oplog_vv(),
        );
        let mut recorded_rows = 0;
        let mut changed_rows = 0;
        for change in &mut expected.changes {
            for op in &mut change.ops {
                if !record_container(&op.container) {
                    continue;
                }
                let JsonOpContent::Map(JsonMapOp::Insert { key, value }) = &mut op.content else {
                    return Err(invalid("claim revision record operation"));
                };
                if key.as_str() != "raw" {
                    return Err(invalid("claim revision record key"));
                }
                let LoroValue::Binary(raw) = value else {
                    return Err(invalid("claim revision raw register"));
                };
                let rewritten = self.redact_row(raw)?;
                recorded_rows += 1;
                if rewritten.as_slice() != raw.as_slice() {
                    *value = LoroValue::from(rewritten);
                    changed_rows += 1;
                }
            }
        }
        if recorded_rows == 0 {
            return Err(invalid("claim revision history has no raw rows"));
        }
        let rebuilt = LoroDoc::new();
        let status = rebuilt
            .import_json_updates(expected.clone())
            .map_err(|_| invalid("claim revision history import"))?;
        if status.pending.is_some()
            || source.oplog_frontiers() != rebuilt.oplog_frontiers()
            || source.oplog_vv() != rebuilt.oplog_vv()
        {
            return Err(invalid("claim revision history frontier changed"));
        }
        let next = rebuilt
            .export(ExportMode::Snapshot)
            .map_err(|_| invalid("claim revision history export"))?;
        // Verify the exported artifact, not just the scratch document.
        let carried = full_doc(&next)?;
        let actual = carried.export_json_updates_without_peer_compression(
            &VersionVector::default(),
            &carried.oplog_vv(),
        );
        prove_loro_equivalent(&expected.changes, &actual.changes)?;
        if carried.oplog_frontiers() != source.oplog_frontiers()
            || carried.get_deep_value() != rebuilt.get_deep_value()
            || doc_raw(&carried)? != self.redact_row(&doc_raw(&source)?)?
        {
            return Err(invalid("claim revision history round trip"));
        }
        let mut seen = BTreeSet::new();
        let mut rewritten_bindings = Vec::with_capacity(bindings.len());
        for (revision, encoded) in bindings {
            if !seen.insert(*revision) {
                return Err(invalid("duplicate claim revision binding"));
            }
            rewritten_bindings.push(rebind(entity, &source, &carried, *revision, encoded)?);
        }
        Ok(RedactedClaimRevisionHistory {
            snapshot: next,
            bindings: rewritten_bindings,
            changed_rows,
        })
    }
}

/// The prepared artifact and all supplied bindings, not authority to put it.
/// No live table, index, family proof, signature or replay marker is changed.
#[derive(Debug)]
struct RedactedClaimRevisionHistory {
    pub snapshot: Vec<u8>,
    pub bindings: Vec<ClaimValueRedactionBinding>,
    /// Insertions whose selected map fields were present and removed.
    pub changed_rows: usize,
}

/// One retained frontier's exact old/new reference and citation status.
/// An old content hash is never silently assigned to different bytes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimValueRedactionBinding {
    pub previous_revision: RevisionRef,
    pub revision: RevisionRef,
    pub frontier: Vec<u8>,
    pub body_changed: bool,
    /// A saved `short:hh@rev` needs a new hash byte when this is true.
    /// False does not prove content equality: an 8-bit hash can collide.
    pub short_hash_changed: bool,
}

fn record_container(container: &ContainerID) -> bool {
    matches!(container, ContainerID::Root { name, container_type: ContainerType::Map }
        if name.as_str() == "record")
}

fn full_doc(bytes: &[u8]) -> Result<LoroDoc> {
    let metadata = LoroDoc::decode_import_blob_meta(bytes, true)
        .map_err(|_| invalid("claim revision snapshot"))?;
    if metadata.mode != EncodedBlobMode::Snapshot {
        return Err(invalid("claim redaction needs full revision history"));
    }
    let doc = LoroDoc::new();
    let status = doc
        .import(bytes)
        .map_err(|_| invalid("claim revision snapshot import"))?;
    if status.pending.is_some()
        || doc.is_shallow()
        || doc.state_frontiers() != doc.oplog_frontiers()
    {
        return Err(invalid("claim redaction needs complete head history"));
    }
    Ok(doc)
}

fn rebind(
    entity: EntityId,
    source: &LoroDoc,
    rewritten: &LoroDoc,
    previous_revision: RevisionRef,
    encoded: &[u8],
) -> Result<ClaimValueRedactionBinding> {
    let document_frontier = super::frontier::FrontierEntry::decode(encoded)?.document()?;
    let frontier =
        Frontiers::decode(document_frontier).map_err(|_| invalid("claim revision frontier"))?;
    let before = source
        .fork_at(&frontier)
        .map_err(|_| invalid("claim revision binding"))?;
    let after = rewritten
        .fork_at(&frontier)
        .map_err(|_| invalid("redacted claim revision binding"))?;
    let before = doc_raw(&before)?;
    let after = doc_raw(&after)?;
    let revision = if reference(&entity, document_frontier) == previous_revision {
        previous_revision
    } else if reference(&entity, &before) == previous_revision {
        reference(&entity, &after)
    } else {
        return Err(invalid("claim revision reference mismatch"));
    };
    let before = &before[ENTITY_METADATA_HEADER_LEN..];
    let after = &after[ENTITY_METADATA_HEADER_LEN..];
    Ok(ClaimValueRedactionBinding {
        previous_revision,
        revision,
        frontier: encoded.to_vec(),
        body_changed: before != after,
        short_hash_changed: short_id_content_hash(before) != short_id_content_hash(after),
    })
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// Content-free local result, not peer convergence or an export receipt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalClaimValueRedaction {
    pub record: EntityId,
    pub value_fields: Vec<String>,
    pub changed_history_rows: usize,
    pub bindings: Vec<ClaimValueRedactionBinding>,
}

/// The courtesy-answer writer has re-proved owner and actual copy scope.
/// This composes its selected local edit, full history scrub and derived
/// index publication in that SAME writer. No new authority or raw-Put door.
pub(crate) fn redact_claim_value_fields_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    keys: &[String],
    actor: EntityId,
) -> Result<LocalClaimValueRedaction> {
    use crate::ports::EntityStoreRead;
    let selection = ClaimValueFieldRedaction::new(keys.iter().cloned())?;
    if crate::entity_doc::has_record_head(&vault.store, txn, &id)? {
        return Err(invalid("record-headed redaction needs its document door"));
    }
    let raw = vault
        .store
        .port_entity_raw(txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let rewritten = selection.redact_row(&raw)?;
    let body = crate::claim::validate_claim_body_and_decode_in_txn(
        &vault.store,
        txn,
        &rewritten[ENTITY_METADATA_HEADER_LEN..],
        false,
    )?;
    check_family(&body)?;
    let live_changed = rewritten != raw;
    if live_changed {
        vault.store.reject_legal_holds_in_txn(
            txn,
            &[id],
            &crate::store::legal_hold::HoldActor::owner(actor),
        )?;
        vault.put_claim_value_redaction_in_txn(txn, &id, &ClaimValueRedactionRow(rewritten))?;
        drop_room_copies(vault, txn, &id);
    }
    let mut receipt = LocalClaimValueRedaction {
        record: id,
        value_fields: selection.fields.iter().cloned().collect(),
        changed_history_rows: 0,
        bindings: Vec::new(),
    };
    let Some(mut current) = state(&vault.store, txn, &id)? else {
        return Ok(receipt);
    };
    if !current.has_doc {
        return Ok(receipt);
    }
    let snapshot = DOC
        .get(&vault.store, txn, &id)?
        .ok_or_else(|| invalid("claim revision document absent"))?;
    let bindings: Vec<_> = FRONTIER
        .scan_from(&vault.store, txn, id.as_bytes())?
        .into_iter()
        .map(|((_, revision), frontier)| (RevisionRef(revision), frontier))
        .collect();
    let prepared = selection.redact_history(id, &snapshot, &bindings)?;
    if prepared.changed_rows == 0 {
        return Ok(receipt);
    }
    if !live_changed {
        vault.store.reject_legal_holds_in_txn(
            txn,
            &[id],
            &crate::store::legal_hold::HoldActor::owner(actor),
        )?;
        drop_room_copies(vault, txn, &id);
    }
    // Every rewritten historical row keeps its ordinary family/source-trust
    // admission too; a retained reserved proof is not made into a raw edit.
    let source = full_doc(&snapshot)?;
    let history = source.export_json_updates_without_peer_compression(
        &VersionVector::default(),
        &source.oplog_vv(),
    );
    for change in &history.changes {
        for op in &change.ops {
            if !record_container(&op.container) {
                continue;
            }
            let JsonOpContent::Map(JsonMapOp::Insert {
                value: LoroValue::Binary(raw),
                ..
            }) = &op.content
            else {
                return Err(invalid("claim revision raw register"));
            };
            let next = selection.redact_row(raw)?;
            if next.as_slice() != raw.as_slice() {
                let body = crate::claim::validate_claim_body_and_decode_in_txn(
                    &vault.store,
                    txn,
                    &next[ENTITY_METADATA_HEADER_LEN..],
                    false,
                )?;
                check_family(&body)?;
            }
        }
    }
    let mapped = |revision| -> Result<RevisionRef> {
        prepared
            .bindings
            .iter()
            .find(|binding| binding.previous_revision == revision)
            .map(|binding| binding.revision)
            .ok_or_else(|| invalid("claim state names an unretained revision"))
    };
    current.live = mapped(current.live)?;
    current.indexed = mapped(current.indexed)?;
    // Check the complete new set before deleting any old reverse row.
    let mut destinations = std::collections::BTreeMap::new();
    for binding in &prepared.bindings {
        if let Some(other) = IDENTITY.get(&vault.store, txn, &binding.revision.0)?
            && other != id
        {
            return Err(invalid("redacted revision belongs to another entity"));
        }
        if let Some(other) = destinations.insert(binding.revision, &binding.frontier)
            && other != &binding.frontier
        {
            return Err(invalid("redacted revision binding collision"));
        }
    }
    for binding in &prepared.bindings {
        if binding.previous_revision != binding.revision {
            FRONTIER.delete(&vault.store, txn, &(id, binding.previous_revision.0))?;
            IDENTITY.delete(&vault.store, txn, &binding.previous_revision.0)?;
        }
    }
    for binding in &prepared.bindings {
        FRONTIER.put(
            &vault.store,
            txn,
            &(id, binding.revision.0),
            &binding.frontier,
        )?;
        IDENTITY.put(&vault.store, txn, &binding.revision.0, &id)?;
    }
    DOC.put(&vault.store, txn, &id, &prepared.snapshot)?;
    // Old staged inputs and vectors describe the pre-redaction bytes even
    // when their causal frontier did not change. Publish fresh text now.
    super::super::pending_index::clear(&vault.store, txn, &id)?;
    super::super::phonetic::clear_phonetic(&vault.store, txn, &id)?;
    super::super::vector_refill::clear(&vault.store, txn, &id)?;
    crate::vault::entity_revision::drop_vector_state(vault, txn, &id)?;
    current.indexed = current.live;
    put_state(&vault.store, txn, &id, &current)?;
    let live = vault
        .store
        .port_entity_raw(txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let body_bytes = &live[ENTITY_METADATA_HEADER_LEN..];
    let body = decode_claim_body(body_bytes, false)?;
    let text = crate::store::claim_lineage::claim_value_index_text(&body.value);
    let fields = if crate::claim::claim_surfaceable(&body) && !text.is_empty() {
        vec![("val".to_owned(), text)]
    } else {
        Vec::new()
    };
    let codes = super::super::phonetic::take_phonetic(
        &vault.store,
        txn,
        &id,
        current.live,
        ENTITY_TYPE_CLAIM,
        body_bytes,
    )?;
    crate::batch::delete_from_phonetic_postings(&vault.store, txn, &id)?;
    crate::batch::apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![
            crate::batch::BatchOp::Text { id, fields },
            crate::batch::BatchOp::Phonetic { id, codes },
        ],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        false,
    )?;
    if crate::claim::claim_surfaceable(&body) {
        vault.store.mark_pending_embedding(txn, &id, body_bytes)?;
        #[cfg(feature = "sync")]
        if vault.config.embedding_model.is_some() {
            vault.store.sync_hooks.push_embed_job_in_txn(
                &vault.store,
                txn,
                &id,
                crate::store::embedding::EMBED_PRIORITY_DEVICE,
            )?;
        }
    }
    receipt.changed_history_rows = prepared.changed_rows;
    receipt.bindings = prepared.bindings;
    Ok(receipt)
}

/// Drops every room's copies of claim `id` the redaction rewrites in base:
/// its text index rows, vector and phonetic codes, its media vectors and its
/// revision rows (FIX 19487). A room that staged and promoted the claim keeps
/// them byte-equal to base's pre-redaction rows, so without this it would
/// serve the redacted value until it closes. A room with no entity row of
/// the claim then reads base's redacted rows; a room that stages its own row
/// of the claim keeps it, as on a delete. It runs in this writer, before it
/// commits ([`crate::embed::drop_room_media_copies_in_txn`]).
fn drop_room_copies(vault: &crate::Vault, txn: &heed::RwTxn<'_>, id: &EntityId) {
    crate::embed::drop_room_media_copies_in_txn(&vault.store, txn, id);
}

fn check_family(body: &crate::claim::ClaimBody) -> Result<()> {
    if crate::claim::is_expression_preference_predicate(&body.predicate)
        || matches!(
            body.predicate.as_str(),
            "comm.last_touch" | "comm.thread_member" | "comm.opt_out"
        )
    {
        return Err(invalid(
            "this claim redaction needs its family's typed door",
        ));
    }
    Ok(())
}

/// Only the selected-field transform can construct this exact body edit.
/// It is not a general raw-Put allowance.
pub(crate) struct ClaimValueRedactionRow(Vec<u8>);

impl ClaimValueRedactionRow {
    pub(crate) fn raw(&self) -> &[u8] {
        &self.0
    }
}

fn read_value(cursor: &mut std::io::Cursor<&[u8]>) -> Result<rmpv::Value> {
    rmpv::decode::read_value(cursor).map_err(|_| invalid("claim redaction MessagePack"))
}

fn map_header(bytes: &[u8]) -> Option<(usize, usize)> {
    match *bytes.first()? {
        tag @ 0x80..=0x8f => Some(((tag & 0x0f) as usize, 1)),
        0xde => Some((
            u16::from_be_bytes(bytes.get(1..3)?.try_into().ok()?) as usize,
            3,
        )),
        0xdf => Some((
            u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?) as usize,
            5,
        )),
        _ => None,
    }
}

fn map_prefix(count: usize) -> Result<Vec<u8>> {
    let count = u32::try_from(count).map_err(|_| invalid("claim value map length"))?;
    Ok(if count < 16 {
        vec![0x80 | count as u8]
    } else if count <= u16::MAX as u32 {
        let mut bytes = vec![0xde];
        bytes.extend_from_slice(&(count as u16).to_be_bytes());
        bytes
    } else {
        let mut bytes = vec![0xdf];
        bytes.extend_from_slice(&count.to_be_bytes());
        bytes
    })
}
