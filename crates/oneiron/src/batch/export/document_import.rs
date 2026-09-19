//! Validating JSON import through ordinary admission doors, never sync replay.
use std::collections::{BTreeMap, BTreeSet};

use super::{ExportEdge, ExportEntity, WholeVaultDocument, WholeVaultImportReceipt};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, decode_claim_body, encode_claim_body,
};
use crate::edge::{EdgeKind, parse_strict_edge_record};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL, ENTITY_TYPE_WORKFLOW,
};
use crate::serialize::ExportBody;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::live_entity_row_in_txn;

impl Vault {
    /// Validates a JSON document and its six-part shape without writing anything.
    /// The returned data remains untrusted. A manifest is not an approval grant.
    pub fn read_whole_vault_json(&self, bytes: &[u8]) -> Result<WholeVaultDocument> {
        let document: WholeVaultDocument = serde_json::from_slice(bytes)
            .map_err(|_| invalid("invalid whole-vault document JSON"))?;
        document.validate(self)?;
        Ok(document)
    }

    /// Reimports a JSON export atomically. IDs, times, ordinary body fields and
    /// public edges survive. New claims are Imported + Proposed (Rejected stays
    /// Rejected); lifecycle and scope are retained. Skills return as candidates;
    /// agent definitions are disabled and proposed until locally reviewed.
    ///
    /// Same-ID divergent rows are refused, never overwritten. Maintenance rows,
    /// witness messages, notes, reserved claims and owned/provenanced edges need
    /// their owning import adapter and fail through the existing public doors.
    /// Such a failure aborts the entire transaction, not a partial import.
    pub fn import_whole_vault_json(&self, bytes: &[u8]) -> Result<WholeVaultImportReceipt> {
        let document = self.read_whole_vault_json(bytes)?;
        let authority = self
            .classify_vault_import_manifest(&document.manifest.storage.to_json_pretty()?, None)?;
        // Classification is advisory provenance, not an admission capability.
        // Even a forged same-chain manifest cannot enable replay or Auto here.
        let mut wtxn = self.store.env.write_txn()?;
        let mut pending = BTreeMap::new();
        let mut unchanged_entities = 0;
        for row in document.entities() {
            let id = parse_id(&row.id)?;
            if self.store.off_record_sessions.contains_entity(&id)? {
                return Err(invalid("import ID belongs to an off-record overlay"));
            }
            let existing = self.store.entities.get(&wtxn, id.as_bytes())?;
            if let Some(existing) = existing {
                if !live_entity_row_in_txn(&self.store, &wtxn, &id)?.is_live() {
                    return Err(invalid("import ID collides with a deleted entity"));
                }
                if matches_row(row, &existing, &row.body) {
                    unchanged_entities += 1;
                    continue;
                }
                let body = imported_body(row)?;
                if matches_row(
                    row,
                    &existing,
                    &ExportBody::from_bytes(&body, row.entity_type),
                ) {
                    unchanged_entities += 1;
                    continue;
                }
                return Err(invalid("import ID collides with different entity data"));
            }
            self.store.validate_public_entity_type(row.entity_type)?;
            pending.insert(id, (row, imported_body(row)?));
        }
        let inserted_ids: BTreeSet<_> = pending.keys().copied().collect();
        let inserted_entities = pending.len();
        // Resolve reference dependencies without assuming UUID or export order.
        // A cycle or an unavailable subject fails without a partial commit.
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .iter()
                .filter_map(
                    |(id, (row, body))| match dependencies(row.entity_type, body) {
                        Ok(refs)
                            if refs
                                .iter()
                                .all(|reference| !pending.contains_key(reference)) =>
                        {
                            Some(Ok(*id))
                        }
                        Ok(_) => None,
                        Err(error) => Some(Err(error)),
                    },
                )
                .collect::<Result<_>>()?;
            if ready.is_empty() {
                return Err(invalid("cyclic import subject or fork dependencies"));
            }
            for id in ready {
                let (row, body) = pending
                    .remove(&id)
                    .ok_or(Error::InvariantViolation("import queue lost row"))?;
                let occurred = TimeRange {
                    start: row.occurred_start,
                    end: row.occurred_end,
                };
                match row.entity_type {
                    ENTITY_TYPE_CLAIM => self.put_claim_in_txn(
                        &mut wtxn,
                        &id,
                        &decode_claim_body(&body, false)?,
                        occurred,
                        row.learned_at,
                    )?,
                    ENTITY_TYPE_SKILL => self.put_skill_record_in_txn(
                        &mut wtxn,
                        &id,
                        &crate::skill::decode_skill_record(&body)?,
                        occurred,
                        row.learned_at,
                    )?,
                    _ => self
                        .batch_in()
                        .put(&id, row.entity_type, occurred, row.learned_at, &body)
                        .apply(&mut wtxn)?,
                }
            }
        }
        for edge in &document.evidence_ledger.edges {
            import_edge(self, &mut wtxn, edge, &inserted_ids)?;
        }
        wtxn.commit()?;
        Ok(WholeVaultImportReceipt {
            authority,
            inserted_entities,
            unchanged_entities,
        })
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("whole-vault import: {reason}"))
}

pub(super) fn parse_id(text: &str) -> Result<EntityId> {
    let id = EntityId::from_hex(text)?;
    if id.to_hex() != text {
        return Err(invalid("entity ID must be lowercase hex"));
    }
    Ok(id)
}

fn matches_row(row: &ExportEntity, raw: &[u8], expected: &ExportBody) -> bool {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return false;
    };
    header.entity_type == row.entity_type
        && header.occurred_start == row.occurred_start
        && header.occurred_end == row.occurred_end
        && header.learned_at == row.learned_at
        && ExportBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..], row.entity_type) == *expected
}

fn imported_body(row: &ExportEntity) -> Result<Vec<u8>> {
    let bytes = row.body.to_bytes()?;
    match row.entity_type {
        ENTITY_TYPE_CLAIM => {
            let mut body = decode_claim_body(&bytes, false)?;
            body.source = Some(ClaimSource::Imported);
            if body.approval != ClaimApprovalStatus::Rejected {
                body.approval = ClaimApprovalStatus::Proposed;
            }
            encode_claim_body(&body)
        }
        ENTITY_TYPE_SKILL => {
            let mut body = crate::skill::decode_skill_record(&bytes)?;
            body.source = ClaimSource::Imported;
            body.approval_status = ClaimApprovalStatus::Proposed;
            body.lifecycle_status = crate::skill::SkillLifecycle::Candidate;
            crate::skill::encode_skill_record(&body)
        }
        ENTITY_TYPE_AGENT_DEF => {
            let mut body = crate::agent_def::decode_agent_definition(&bytes)?;
            body.source = ClaimSource::Imported;
            body.approval_status = ClaimApprovalStatus::Proposed;
            body.enabled = false;
            body.ceiling = crate::agent_def::AgentCeiling::Proposed;
            crate::agent_def::encode_agent_definition(&body)
        }
        _ => Ok(bytes),
    }
}

fn dependencies(entity_type: u8, bytes: &[u8]) -> Result<Vec<EntityId>> {
    Ok(match entity_type {
        ENTITY_TYPE_CLAIM => match decode_claim_body(bytes, false)?.subject {
            ClaimSubject::Entity(id) => vec![id],
            ClaimSubject::Edge { source, target, .. } => vec![source, target],
        },
        ENTITY_TYPE_SKILL => crate::skill::decode_skill_record(bytes)?
            .forked_from
            .into_iter()
            .collect(),
        ENTITY_TYPE_AGENT_DEF => crate::agent_def::decode_agent_definition(bytes)?
            .forked_from
            .into_iter()
            .collect(),
        ENTITY_TYPE_WORKFLOW => {
            let definition = crate::agent_def::workflow::decode_workflow(bytes)?;
            definition
                .steps
                .into_iter()
                .chain(definition.forked_from)
                .collect()
        }
        _ => Vec::new(),
    })
}

fn import_edge(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    edge: &ExportEdge,
    inserted: &BTreeSet<EntityId>,
) -> Result<()> {
    let source = parse_id(&edge.source)?;
    let target = parse_id(&edge.target)?;
    let kind = EdgeKind::try_from_u8(edge.kind).ok_or_else(|| invalid("unknown edge kind"))?;
    let key = Store::encode_edge_key(&source, kind, &target);
    if let Some(raw) = vault.store.edges_out.get(wtxn, &key)? {
        let existing = parse_strict_edge_record(&key, &raw)?;
        let same = existing.decoded.weight == edge.weight
            && existing.decoded.created_at == edge.created_at
            && existing
                .decoded
                .vad
                .map(|v| [v.valence, v.arousal, v.dominance])
                == edge.vad
            && existing
                .decoded
                .provenance
                .map(|p| [p.confirmation_status as u8, p.actor_class as u8])
                == edge.provenance;
        if same {
            return Ok(());
        }
        // A newly imported claim's typed door creates its own ClaimOf link.
        // Restoring this exported public link's original timestamp is safe.
        if kind != EdgeKind::ClaimOf || !inserted.contains(&source) {
            return Err(invalid(
                "import edge collides with different stored metadata",
            ));
        }
    }
    if edge.provenance.is_some() {
        return Err(invalid(
            "provenanced edge import requires its owning claim adapter",
        ));
    }
    let vad = edge
        .vad
        .map_or(crate::affect::Vad::NEUTRAL, |v| crate::affect::Vad {
            valence: v[0],
            arousal: v[1],
            dominance: v[2],
        });
    vault
        .batch_in()
        .edge_with_created_at_and_vad(&source, kind, &target, edge.weight, edge.created_at, vad)
        .apply(wtxn)
}
