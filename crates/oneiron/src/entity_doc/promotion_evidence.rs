//! Canonical citation checks on the same document snapshot a promotion commits,
//! and the citation pins every local claim write keeps (FIX 904).
use super::{invalid, storage, verbs};
use crate::claim::{ClaimBody, EvidenceKind, EvidenceRef};
use crate::ports::{EdgeStoreRead, EntityStoreRead};
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use sha2::{Digest, Sha256};

/// Validate the document identity, live pin, stable span and optional SHA-256.
/// MESSAGE citations name their actual parent TURN for the promotion writer.
/// A moved frontier is refused, not replaced with a newer current head.
pub(crate) fn promotion_evidence_source_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    evidence: &EvidenceRef,
) -> Result<EntityId> {
    citation_source_in_txn(&vault.store, txn, evidence)
}

/// [`promotion_evidence_source_in_txn`] on the store a batch write holds.
fn citation_source_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    evidence: &EvidenceRef,
) -> Result<EntityId> {
    use crate::registry::*;
    let entity = EntityId::from_hex(&evidence.entity)?;
    let kind = store
        .port_entity_record(txn, &entity)?
        .map(|row| row.entity_type);
    let matches_kind = match evidence.kind {
        EvidenceKind::Turn => kind == Some(ENTITY_TYPE_TURN),
        EvidenceKind::Message => kind == Some(ENTITY_TYPE_MESSAGE),
        EvidenceKind::Note => kind == Some(ENTITY_TYPE_NOTE),
        EvidenceKind::AssetText => kind == Some(ENTITY_TYPE_ASSET_TEXT),
        EvidenceKind::ImportRecord => false,
    };
    if !matches_kind {
        return Err(invalid("citation kind has no matching document producer"));
    }
    if evidence.kind == EvidenceKind::Note && evidence.span.is_none() {
        return Err(invalid("note evidence requires a stable span"));
    }
    let head = storage::head(store, txn, &entity)?;
    if head.document != evidence.doc {
        return Err(invalid("citation names another document"));
    }
    let doc = storage::load(store, txn, &head)?;
    if doc.frontier() != evidence.at {
        return Err(invalid("citation frontier changed before promotion"));
    }
    let quote = match &evidence.span {
        Some(span) => {
            let (start, end) = verbs::resolve_cursors(&doc, &evidence.at, &span.start, &span.end)?;
            if start == end {
                return Err(invalid("evidence span is empty"));
            }
            doc.text()
                .chars()
                .skip(start)
                .take(end - start)
                .collect::<String>()
        }
        None => doc.text(),
    };
    if evidence
        .quote_sha256
        .is_some_and(|expected| <[u8; 32]>::from(Sha256::digest(quote.as_bytes())) != expected)
    {
        return Err(invalid("evidence quote SHA-256 differs"));
    }
    if evidence.kind != EvidenceKind::Message {
        return Ok(entity);
    }
    let parents = store
        .port_edge_peers(
            txn,
            &entity,
            crate::ports::EdgeDirection::Out,
            crate::edge::EdgeKind::ChildOf,
        )?
        .collect::<Result<Vec<_>>>()?;
    let [turn] = parents.as_slice() else {
        return Err(invalid("message evidence needs exactly one parent TURN"));
    };
    let parent = store.port_entity_record(txn, turn)?;
    if parent.map(|row| row.entity_type) != Some(ENTITY_TYPE_TURN) {
        return Err(invalid("message evidence parent is not a TURN"));
    }
    Ok(*turn)
}

/// Refuses a promotion whose citations do not all verify in its own write.
/// The claim write that lands them pins them
/// ([`retain_fresh_claim_citations_in_txn`]); this pins nothing again.
pub(crate) fn verify_promotion_evidence_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    refs: &[EvidenceRef],
) -> Result<()> {
    for reference in refs {
        promotion_evidence_source_in_txn(vault, txn, reference)?;
    }
    Ok(())
}

/// Pins, in a local claim write, each typed citation `body` adds over the
/// row it replaces at `citer` (FIX 904). Each is checked against its
/// document in this snapshot. One that holds records its citation floor and
/// derived edge. One that does not (a moved frontier, a source not yet
/// arrived, a citation no producer checked) is kept as written and never
/// refused or rebound to today's head: it keeps its source dependency where
/// the source is present, earns no floor, and is recorded not verified. The
/// writers that cite fresh refuse a citation that does not hold themselves,
/// as before. A citation the stored row already holds (a lifecycle close
/// keeps its own) is not a new one, and a replicated row is never pinned
/// here.
pub(crate) fn retain_fresh_claim_citations_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citer: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let refs = body.evidence_refs()?;
    if refs.is_empty() {
        return Ok(());
    }
    let stored = stored_claim_citations(store, txn, citer)?;
    for reference in refs.iter().filter(|reference| !stored.contains(reference)) {
        if citation_source_in_txn(store, txn, reference).is_ok() {
            pin_citation_in_txn(store, txn, citer, reference)?;
            continue;
        }
        let citer_hex = citer.to_hex();
        tracing::warn!(citer = %citer_hex, "a typed citation is not verified; kept unpinned");
        if let Ok(entity) = EntityId::from_hex(&reference.entity)
            && store.port_entity_present(txn, &entity)?
        {
            crate::ports::record_derived_edge_in_txn(store, txn, citer, &entity)?;
        }
    }
    Ok(())
}

/// Records `citer`'s floor at the cited document's live frontier and its
/// derived edge to the document, for a citation verified in this snapshot.
fn pin_citation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citer: &EntityId,
    reference: &EvidenceRef,
) -> Result<()> {
    let entity = EntityId::from_hex(&reference.entity)?;
    let qualified = super::source_frontier_in_txn(store, txn, &entity)?
        .ok_or(invalid("citation document disappeared"))?;
    super::record_citation_floor_in_txn(store, txn, &entity, citer, Some(&qualified))?;
    crate::ports::record_derived_edge_in_txn(store, txn, citer, &entity)
}

/// The typed citations of the claim row stored at `id`, if one is.
fn stored_claim_citations(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EvidenceRef>> {
    let Some(raw) = store.port_entity_raw(txn, id)? else {
        return Ok(Vec::new());
    };
    let is_claim = crate::batch::EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM);
    let stored = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .filter(|_| is_claim)
        .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
        .and_then(|stored| stored.evidence_refs().ok());
    Ok(stored.unwrap_or_default())
}
