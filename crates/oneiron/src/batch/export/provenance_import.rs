//! Ordered archive restore through MODEL and edge-provenance owning doors.
use super::document_import::{import_edge, matches_row, parse_id};
use super::{ExportEdge, ExportEntity, WholeVaultDocument};
use crate::claim::{ClaimBody, ClaimSubject, decode_claim_body};
use crate::{
    Vault,
    entity_id::EntityId,
    error::{Error, Result},
    serialize::ExportBody,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn is_provenance(row: &ExportEntity) -> bool {
    row.entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && row
            .body
            .to_bytes()
            .ok()
            .and_then(|bytes| decode_claim_body(&bytes, true).ok())
            .is_some_and(|body| body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE)
}
pub(super) struct ModelImports {
    pub(super) map: BTreeMap<EntityId, EntityId>,
    pub(super) inserted: usize,
    pub(super) unchanged: usize,
}
pub(super) fn restore_models(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &WholeVaultDocument,
) -> Result<ModelImports> {
    let mut known = BTreeSet::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_MODEL])?
    {
        let (key, _) = row?;
        known.insert(crate::vault::entity_id_from_type_index_key(&key)?);
    }
    let mut inserted = 0;
    let mut unchanged = 0;
    let mut map = BTreeMap::new();
    for row in doc
        .entities()
        .filter(|row| row.entity_type == crate::registry::ENTITY_TYPE_MODEL)
    {
        let bytes = row.body.to_bytes()?;
        let (name, version) = crate::provenance::decode_model_entity_body(&bytes)?;
        let local = vault.ensure_model_substrate_in_txn(txn, &name, &version, row.learned_at)?;
        if known.insert(local) {
            inserted += 1;
        } else {
            unchanged += 1;
        }
        map.insert(parse_id(&row.id)?, local);
    }
    Ok(ModelImports {
        map,
        inserted,
        unchanged,
    })
}
pub(super) fn mapped_edge(
    edge: &ExportEdge,
    models: &BTreeMap<EntityId, EntityId>,
) -> Result<ExportEdge> {
    let mut edge = edge.clone();
    if let Some(id) = models.get(&parse_id(&edge.source)?) {
        edge.source = id.to_hex();
    }
    if let Some(id) = models.get(&parse_id(&edge.target)?) {
        edge.target = id.to_hex();
    }
    Ok(edge)
}
pub(super) struct ProvenanceImport {
    rows: Vec<(ExportEntity, EntityId, ClaimBody)>,
    pub(super) ids: BTreeSet<EntityId>,
}
impl ProvenanceImport {
    pub(super) fn new(
        doc: &WholeVaultDocument,
        models: &BTreeMap<EntityId, EntityId>,
    ) -> Result<Self> {
        let mut rows = Vec::new();
        for row in doc.entities().filter(|row| is_provenance(row)) {
            let id = parse_id(&row.id)?;
            let mut body = decode_claim_body(&row.body.to_bytes()?, true)?;
            if let ClaimSubject::Edge { source, target, .. } = &mut body.subject {
                *source = models.get(source).copied().unwrap_or(*source);
                *target = models.get(target).copied().unwrap_or(*target);
            }
            rows.push((
                row.clone(),
                id,
                crate::provenance::archived_provenance_body(&body, models)?,
            ));
        }
        rows.sort_by_key(|(row, id, _)| (row.learned_at, *id));
        let ids = rows.iter().map(|(_, id, _)| *id).collect();
        Ok(Self { rows, ids })
    }
    pub(super) fn restore(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<(usize, usize)> {
        let mut inserted = 0;
        let mut unchanged = 0;
        for (row, id, body) in &self.rows {
            let expected =
                ExportBody::from_bytes(&crate::claim::encode_claim_body(body)?, row.entity_type);
            if let Some(existing) = vault.store.entities.get(txn, id.as_bytes())? {
                if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
                    || !matches_row(row, &existing, &expected)
                {
                    return Err(invalid("archive provenance ID collision"));
                }
                unchanged += 1;
                continue;
            }
            vault.restore_archived_provenance_in_txn(
                txn,
                id,
                body,
                crate::temporal::TimeRange {
                    start: row.occurred_start,
                    end: row.occurred_end,
                },
                row.learned_at,
            )?;
            inserted += 1;
        }
        // A superseded row is never silently resurrected if its closing history
        // was absent or ambiguous. Every final lifecycle must reproduce exactly.
        for (row, id, body) in &self.rows {
            let actual = vault
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let expected =
                ExportBody::from_bytes(&crate::claim::encode_claim_body(body)?, row.entity_type);
            if !matches_row(row, &actual, &expected) {
                return Err(invalid("archive provenance lifecycle not reconstructed"));
            }
        }
        Ok((inserted, unchanged))
    }
}
pub(super) fn stage_edge(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    edge: &ExportEdge,
    inserted: &BTreeSet<EntityId>,
) -> Result<()> {
    if edge.provenance.is_none() {
        return import_edge(vault, txn, edge, inserted);
    }
    let source = parse_id(&edge.source)?;
    let target = parse_id(&edge.target)?;
    let kind = crate::edge::EdgeKind::try_from_u8(edge.kind)
        .ok_or_else(|| invalid("archive edge kind"))?;
    let key = crate::store::Store::encode_edge_key(&source, kind, &target);
    if let Some(raw) = vault.store.edges_out.get(txn, &key)? {
        let existing = crate::edge::parse_strict_edge_record(&key, &raw)?.decoded;
        if existing.weight != edge.weight
            || existing.created_at != edge.created_at
            || existing.vad.map(|v| [v.valence, v.arousal, v.dominance]) != edge.vad
        {
            return Err(invalid("archive base edge collision"));
        }
        return Ok(());
    }
    let mut bare = edge.clone();
    bare.provenance = None;
    import_edge(vault, txn, &bare, inserted)
}
fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("provenance import: {reason}"))
}
