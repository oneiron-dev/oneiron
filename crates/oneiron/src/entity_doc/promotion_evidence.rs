//! Canonical citation checks on the same document snapshot a promotion commits.
use super::{invalid, storage, verbs};
use crate::dreamer_promotion::{EvidenceKind, EvidenceRef};
use crate::ports::EdgeStoreRead;
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
    use crate::registry::*;
    let entity = EntityId::from_hex(&evidence.entity)?;
    let kind = vault.get_entity_type_in_txn(txn, &entity)?;
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
    let head = storage::head(&vault.store, txn, &entity)?;
    if head.document != evidence.doc {
        return Err(invalid("citation names another document"));
    }
    let doc = storage::load(&vault.store, txn, &head)?;
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
    let parents = vault
        .store
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
    if vault.get_entity_type_in_txn(txn, turn)? != Some(ENTITY_TYPE_TURN) {
        return Err(invalid("message evidence parent is not a TURN"));
    }
    Ok(*turn)
}

pub(crate) fn retain_promotion_evidence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    citer: &EntityId,
    refs: &[EvidenceRef],
) -> Result<()> {
    for reference in refs {
        promotion_evidence_source_in_txn(vault, txn, reference)?;
        let entity = EntityId::from_hex(&reference.entity)?;
        let qualified = super::source_frontier_in_txn(&vault.store, txn, &entity)?
            .ok_or(invalid("citation document disappeared"))?;
        super::record_citation_floor_in_txn(&vault.store, txn, &entity, citer, Some(&qualified))?;
        crate::ports::record_derived_edge_in_txn(&vault.store, txn, citer, &entity)?;
    }
    Ok(())
}
