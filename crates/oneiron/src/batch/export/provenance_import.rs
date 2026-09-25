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
    pending: BTreeMap<EntityId, Vec<(ExportEntity, EntityId, ClaimBody)>>,
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
        let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for row in rows {
            let ClaimSubject::Edge {
                source,
                kind,
                target,
            } = row.2.subject
            else {
                return Err(invalid("provenance subject must be an edge"));
            };
            groups
                .entry((source, kind as u8, target))
                .or_default()
                .push(row);
        }
        let pending = groups.into_values().map(|rows| (rows[0].1, rows)).collect();
        Ok(Self { pending, ids })
    }
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub(super) fn pending_ids(&self) -> impl Iterator<Item = EntityId> + '_ {
        self.pending
            .values()
            .flat_map(|rows| rows.iter().map(|(_, id, _)| *id))
    }
    pub(super) fn ready(&self, blocked: &BTreeSet<EntityId>) -> Result<Vec<EntityId>> {
        let mut ready = Vec::new();
        for (key, rows) in &self.pending {
            let mut waiting = false;
            for (_, _, body) in rows {
                let ClaimSubject::Edge { source, target, .. } = body.subject else {
                    return Err(invalid("provenance subject must be an edge"));
                };
                let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
                waiting |= [source, target, record.actor_entity_ref]
                    .into_iter()
                    .chain(record.substrate_ref)
                    .any(|id| blocked.contains(&id));
            }
            if !waiting {
                ready.push(*key);
            }
        }
        Ok(ready)
    }
    pub(super) fn restore(
        &mut self,
        key: EntityId,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        edges: &[ExportEdge],
        inserted_ids: &BTreeSet<EntityId>,
    ) -> Result<(BTreeSet<EntityId>, usize)> {
        let rows = self.pending.remove(&key).ok_or(Error::InvariantViolation(
            "provenance import queue lost cohort",
        ))?;
        let ClaimSubject::Edge {
            source,
            kind,
            target,
        } = rows[0].2.subject
        else {
            return Err(invalid("provenance subject must be an edge"));
        };
        let edge = edges
            .iter()
            .find(|edge| {
                edge.source == source.to_hex()
                    && edge.kind == kind as u8
                    && edge.target == target.to_hex()
            })
            .ok_or_else(|| invalid("provenance subject edge missing from archive"))?;
        stage_edge(vault, txn, edge, inserted_ids)?;
        let new_ids = rows
            .iter()
            .filter_map(
                |(_, id, _)| match vault.store.entities.get(txn, id.as_bytes()) {
                    Ok(None) => Some(Ok(*id)),
                    Ok(Some(_)) => None,
                    Err(error) => Some(Err(error)),
                },
            )
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let (inserted, unchanged) = restore_cohort(vault, txn, &rows)?;
        if inserted != new_ids.len() {
            return Err(Error::InvariantViolation("provenance import count drift"));
        }
        Ok((new_ids, unchanged))
    }
}
fn restore_cohort(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    rows: &[(ExportEntity, EntityId, ClaimBody)],
) -> Result<(usize, usize)> {
    let mut inserted = 0;
    let mut unchanged = 0;
    for (row, id, body) in rows {
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
    for (row, id, body) in rows {
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
