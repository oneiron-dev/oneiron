//! Rebuild mechanical projections and reset leased attempt ownership.
use super::codec_error;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::{
    EntityId, Error, Result, Vault,
    attempt_queue::AttemptState,
    batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader},
    temporal::TimeRange,
};

/// Canonical caller-supplied text fields backing one document's bm25 index.
/// Key: id16.
const INDEX_SOURCE_TEXT: SideTable<EntityId, Vec<(String, String)>, Named> =
    SideTable::new(&side_table::INDEX_SOURCE_TEXT);
/// Caller-supplied phonetic codes retained to recompute an entity's phonetic
/// postings. Key: id16.
const INDEX_SOURCE_PHONETIC: SideTable<EntityId, Vec<String>, Named> =
    SideTable::new(&side_table::BATCH_PHONETIC_INDEX_SOURCE);
/// A sync window needs a full resync (`fr:w:{key}`). Marker byte `[1]`.
/// Bound locally rather than reused from `crate::sync::window_rows` because
/// that module lives behind `feature = "sync"` and this rebuild runs without
/// it; the declaration itself (`side_table::WINDOW_FULL_RESYNC_MARKER`) is
/// unconditional, so both bindings share one declared table.
const WINDOW_FULL_RESYNC_MARKER: SideTable<String, [u8; 1], Raw> =
    SideTable::new(&side_table::WINDOW_FULL_RESYNC_MARKER);
pub(super) fn unlease_attempt(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    let (&version, _) = bytes.split_first().ok_or_else(codec_error)?;
    let mut record = crate::attempt_queue::decode_record(
        bytes,
        crate::attempt_queue::AttemptId::from_bytes(key)?,
    )?;
    if record.state == AttemptState::Landing {
        // A landing needs its executor to finish its audited cancellation.
        // Do not invent a completed/cancelled receipt during backup.
        return Err(Error::InvalidConfig(
            "checkpoint requires landing attempts to settle".into(),
        ));
    }
    if record.state == AttemptState::Leased {
        record.state = AttemptState::Queued;
        record.lease_owner = None;
        record.claimed_at = None;
    }
    let mut out = vec![version];
    out.extend(rmp_serde::to_vec_named(&record).map_err(|_| codec_error())?);
    Ok(out)
}

/// [`unlease_attempt`] for an opaque response's queue row (FIX 9390): one
/// the strict reader refuses lands exactly as it rested (`None`), indexed
/// nowhere; one it reads is unleased as every other is.
pub(super) fn unlease_opaque_attempt(key: &[u8], bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let id = crate::attempt_queue::AttemptId::from_bytes(key)?;
    if crate::attempt_queue::decode_record(bytes, id).is_err() {
        return Ok(None);
    }
    unlease_attempt(key, bytes).map(Some)
}
/// Whether the row `raw` embeds its own body: a summary's, and a claim's
/// that is not a lexical query hint. A header-only claim (an erase's shell,
/// a retired response's) embeds nothing and is never decoded here (FIX
/// 8827): its markers and fences stand as they are.
pub(super) fn has_embedding_source(raw: &[u8]) -> Result<bool> {
    let header = EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    match header.entity_type {
        crate::registry::ENTITY_TYPE_SUMMARY => Ok(!body.is_empty()),
        crate::registry::ENTITY_TYPE_CLAIM if body.is_empty() => Ok(false),
        crate::registry::ENTITY_TYPE_CLAIM => Ok(crate::claim::decode_claim_body(body, true)?
            .predicate
            != crate::claim::PREDICATE_LEXICAL_QUERY_HINT),
        _ => Ok(false),
    }
}

/// Whether a checkpoint's vector for `id`, whose row is `raw`, has a
/// canonical source a restore embeds it again from, as [`rebuild`] does: its
/// own body ([`has_embedding_source`]) or, for a TURN, its messages' text
/// read in `txn` (FIX 8826).
pub(super) fn has_checkpoint_embedding_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    if has_embedding_source(raw)? {
        return Ok(true);
    }
    let header = EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
    Ok(header.entity_type == crate::registry::ENTITY_TYPE_TURN
        && crate::embed::turn_text_in_txn(vault, txn, id)?.is_some())
}
/// Marks a restored record to be embedded again and queues the worker's job
/// for it: the image holds no vectors, and the worker leases queued jobs only,
/// so a marker alone left a restored vault without them for good.
fn mark_for_reembedding(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    text: &[u8],
) -> Result<()> {
    vault.store.mark_pending_embedding(txn, id, text)?;
    #[cfg(feature = "sync")]
    if vault.config.embedding_model.is_some() {
        crate::sync::queue::push_embed_job_in_txn(
            &vault.store,
            txn,
            id,
            crate::embed::EMBED_PRIORITY_BACKFILL,
        )?;
    }
    Ok(())
}

/// Rebuilds every entity's mechanical projections. A claim in `opaque`, a
/// step claim whose response never decoded and landed as it rested (FIX
/// 6227), keeps its type and time index rows; nothing is decoded, indexed
/// or embedded again from its body. A queue row in `opaque_attempts`, an
/// agent dispatch's that never decoded, is indexed nowhere (FIX 9390).
pub(super) fn rebuild(
    vault: &Vault,
    opaque: &std::collections::BTreeSet<EntityId>,
    opaque_attempts: &std::collections::BTreeSet<Vec<u8>>,
) -> Result<(usize, usize, usize)> {
    vault.with_write_txn_grouped(|txn| {
        let rows = crate::ports::EntityStoreRead::port_entity_raw_records(&vault.store, txn)?
            .collect::<Result<Vec<_>>>()?;
        let mut embeddings = 0;
        for (id, raw) in &rows {
            let header = EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
            crate::batch::stage_entity_index_rows(
                &vault.store,
                txn,
                id,
                header.entity_type,
                TimeRange {
                    start: header.occurred_start,
                    end: header.occurred_end,
                },
                header.learned_at,
            )?;
            if opaque.contains(id) {
                continue;
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            match header.entity_type {
                // An erase's shell, a soft-erased claim's or one a restore
                // left a retired response's (KS-2B1), indexes nothing.
                crate::registry::ENTITY_TYPE_CLAIM if body.is_empty() => {}
                crate::registry::ENTITY_TYPE_CLAIM => {
                    let claim = crate::claim::decode_claim_body(body, true)?;
                    crate::dreamer_runner::index_dreamer_milestone_claim_for_put(
                        &vault.store,
                        txn,
                        id,
                        &claim,
                        header.learned_at,
                    )?;
                    crate::llm::index_dreamer_step_claim_for_put(
                        &vault.store,
                        txn,
                        id,
                        &claim,
                        header.learned_at,
                    )?;
                }
                crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT => {
                    crate::counterparty_contact::rebuild_checkpoint_contact_index(
                        &vault.store,
                        txn,
                        *id,
                        body,
                    )?;
                }
                crate::registry::ENTITY_TYPE_CONNECTOR_KEY => {
                    crate::connector_key::rebuild_checkpoint_connector_index(
                        &vault.store,
                        txn,
                        *id,
                        body,
                    )?;
                }
                _ => {}
            }
            if has_embedding_source(raw)? {
                mark_for_reembedding(vault, txn, id, &raw[ENTITY_METADATA_HEADER_LEN..])?;
                embeddings += 1;
            }
            // A TURN embeds its messages' text, so it is marked at that text.
            if header.entity_type == crate::registry::ENTITY_TYPE_TURN
                && let Some(text) = crate::embed::turn_text_in_txn(vault, txn, id)?
            {
                mark_for_reembedding(vault, txn, id, text.as_bytes())?;
                embeddings += 1;
            }
        }
        // A worker attached later, to a vault restored under no model or by a
        // build without the queue, requeues them at its cold attach.
        if embeddings > 0 {
            vault
                .store
                .hnsw_meta
                .put(txn, crate::embed::COLD_ATTACH_PENDING_KEY, b"1")?;
        }
        let sources = INDEX_SOURCE_TEXT.scan(&vault.store, txn)?;
        let mut texts = 0;
        let mut oversized = 0_usize;
        for (id, fields) in sources {
            if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &id)? {
                continue;
            }
            match crate::bm25::index_text(&vault.store, txn, &vault.analyzer, &id, &fields) {
                Ok(()) => texts += 1,
                // Text indexed before the per-document ceiling stays unindexed
                // rather than holding the whole restore: its write door refuses it now.
                Err(Error::Store(crate::error::StoreError::IndexedTextTooLarge { .. })) => {
                    oversized += 1;
                }
                Err(error) => return Err(error),
            }
        }
        if oversized > 0 {
            tracing::warn!(
                oversized,
                "checkpoint restore left documents past the text ceiling out of search"
            );
        }
        let phonetic = INDEX_SOURCE_PHONETIC.scan(&vault.store, txn)?;
        for (id, codes) in phonetic {
            if !crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &id)? {
                continue;
            }
            crate::batch::apply_phonetic(&vault.store, txn, id, &codes)?;
        }
        let windows = crate::ports::WindowDeletionRows::port_window_doc_rows_raw(
            &vault.store,
            txn,
            |window, _| window.as_str().to_owned(),
        )?
        .collect::<Result<Vec<_>>>()?;
        for window in windows {
            WINDOW_FULL_RESYNC_MARKER.put(&vault.store, txn, &window, &[1u8])?;
        }
        crate::conversation_dag::rebuild_thread_meta_projection_in_txn(vault, txn)?;
        crate::attempt_queue::rebuild_checkpoint_indexes(&vault.store, txn, opaque_attempts)?;
        vault.store.rebuild_commitment_due_sidecars(txn)?;
        vault.store.rebuild_pending_gate_consent_sidecars(txn)?;
        crate::workspace_roster::rebuild_project_revision_indexes(&vault.store, txn)?;
        // Runtime budget rows were excluded from the image, not refunded in the billing ledger.
        Ok((rows.len(), texts, embeddings))
    })
}

/// Backfills that own their transactions run after the base index transaction.
pub(super) fn rebuild_auxiliary(vault: &Vault, checkpoint_time: u64) -> Result<()> {
    crate::skill_hub::backfill_content_hash_index_if_needed(vault)?;
    // Restored PROJECT rows bypassed the staging hook: keep their chains.
    vault.capture_project_revisions(true)?;
    crate::skill_convert::rebuild_skill_source_index(vault)?;
    crate::edit_distance::routing::rebuild_routing_projection(vault)?;
    crate::edit_distance::reservoir::rebuild_reservoir_index(vault)?;
    vault.rebuild_ramp_stats_from_receipts()?;
    crate::human_task::HumanTaskFollowupDriver::new(vault).rebuild_cursors(checkpoint_time)?;
    Ok(())
}

/// The host's own MACRO home candidacy `current` keeps, for a restore that
/// takes its place on this host (FIX 5661 C2b); `None` when it keeps none or
/// it does not read, and the restore then elects nothing.
pub(super) fn host_candidacy(current: &Vault) -> Option<Vec<crate::DreamerHomeNodeCandidate>> {
    let read = || -> Result<_> {
        let txn = current.store.env.read_txn()?;
        crate::dreamer_runner::DreamerRunnerStore::new(current).home_candidates_in_txn(&txn)
    };
    match read() {
        Ok(candidacy) => candidacy,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the live vault's home candidacy did not read; the restore elects no home"
            );
            None
        }
    }
}

/// FIX 5661 C2b: re-elects the restored vault's MACRO home before it is
/// returned, over the live authority it carries and `candidacy`, the host's
/// own candidacy the vault it replaces kept: landing cleared that Runtime
/// row with the image's. Never the image's candidacy or another machine's;
/// with none, nothing is elected and the host declares on its next start.
/// The carrier's head stays the live vault's: moving off the image's
/// designation is no home move. A failure is logged and the image's
/// designation stands.
pub(super) fn reelect_home(
    vault: &Vault,
    candidacy: Option<&[crate::DreamerHomeNodeCandidate]>,
    now: u64,
) {
    let Some(candidacy) = candidacy else {
        return;
    };
    let elect =
        || crate::dreamer_runner::DreamerRunnerStore::new(vault).elect_home_node(candidacy, now);
    #[cfg(feature = "sync")]
    let elected = crate::sync::home_handoff::keep_move_through(vault, elect);
    #[cfg(not(feature = "sync"))]
    let elected = elect();
    if let Err(error) = elected {
        tracing::warn!(
            kind = ?error.kind(),
            "the restored vault did not re-elect its home; the image's designation stands"
        );
    }
}
