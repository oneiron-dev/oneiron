//! One vault-owned Dreamer principal; job kinds are facets, not new authorities.
use crate::attempt_queue::AttemptRecord;
use crate::batch::{BatchOp, EntityMetadataHeader, apply_ops};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use serde::{Deserialize, Serialize};
const ACTOR_KEY: &[u8] = b"dreamer:authority:v1:actor";
const ATTEMPT_PREFIX: &[u8] = b"dreamer:authority:v1:attempt:";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerAuthorityStamp {
    pub attempt_id: [u8; 16],
    #[serde(with = "crate::serialize::entity_ref")]
    pub actor: EntityId,
    pub facet: String,
    pub receipt_id: [u8; 16],
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer authority binding".into())
}
impl Vault {
    /// Resolves the vault-owned system principal. Open seeds it without granting
    /// a ceiling, consent grant, or privilege.
    pub fn dreamer_authority(&self) -> Result<WriteActor> {
        self.with_write_txn(|txn| self.dreamer_authority_in_txn(txn, crate::unix_seconds_now()))
    }
    pub(crate) fn dreamer_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        now: u64,
    ) -> Result<WriteActor> {
        // The id is shared across replicas of one vault, but the local binding
        // cannot be redirected to another MACHINE or a deleted shell.
        let actor =
            crate::codebase::entity_id_from_hash_material(b"oneiron.dreamer.authority.v1", &[])?;
        if let Some(raw) = self.store.vault_meta.get(&*txn, ACTOR_KEY)? {
            let raw_id: &[u8] = &raw;
            let id = EntityId::from_bytes(raw_id.try_into().map_err(|_| invalid())?)?;
            if id != actor {
                return Err(invalid());
            }
            let entity = self
                .store
                .entities
                .get(&*txn, id.as_bytes())?
                .ok_or_else(invalid)?;
            if EntityMetadataHeader::parse(&entity)
                .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_MACHINE)
                || entity.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                    != Some(b"Dreamer authority".as_slice())
            {
                return Err(invalid());
            }
            return Ok(WriteActor::new(id, EdgeActorClass::System));
        }
        if let Some(raw) = self.store.entities.get(&*txn, actor.as_bytes())? {
            if EntityMetadataHeader::parse(&raw)
                .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_MACHINE)
                || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                    != Some(b"Dreamer authority".as_slice())
            {
                return Err(invalid());
            }
            self.store
                .vault_meta
                .put(txn, ACTOR_KEY, actor.as_bytes())?;
            return Ok(WriteActor::new(actor, EdgeActorClass::System));
        }
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![BatchOp::Put {
                id: actor,
                entity_type: crate::registry::ENTITY_TYPE_MACHINE,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: b"Dreamer authority".to_vec(),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        self.store
            .vault_meta
            .put(txn, ACTOR_KEY, actor.as_bytes())?;
        Ok(WriteActor::new(actor, EdgeActorClass::System))
    }
    /// Proposal envelope shared by maintenance facets. Approval is never Auto.
    pub fn dreamer_proposal_envelope(
        &self,
        facet: &str,
        attempt: crate::attempt_queue::AttemptId,
    ) -> Result<WriteEnvelope> {
        let stamp = self
            .dreamer_attempt_authority(attempt)?
            .ok_or_else(invalid)?;
        if stamp.facet != facet {
            return Err(invalid());
        }
        let actor = self.dreamer_authority()?;
        if actor.entity_ref() != stamp.actor {
            return Err(invalid());
        }
        let provenance = WriteProvenance::new(rmpv::Value::Map(vec![
            (
                rmpv::Value::from("surface"),
                rmpv::Value::from("dreamer.runner"),
            ),
            (rmpv::Value::from("facet"), rmpv::Value::from(facet)),
            (
                rmpv::Value::from("attempt_id"),
                rmpv::Value::Binary(attempt.as_bytes().to_vec()),
            ),
        ]))?;
        Ok(WriteEnvelope::new(
            actor,
            ClaimSource::Generated,
            provenance,
            ClaimApprovalStatus::Proposed,
        ))
    }
    pub(crate) fn dreamer_actor_for_attempt(
        &self,
        id: crate::attempt_queue::AttemptId,
    ) -> Result<WriteActor> {
        let stamp = self.dreamer_attempt_authority(id)?.ok_or_else(invalid)?;
        Ok(WriteActor::new(stamp.actor, EdgeActorClass::System))
    }
    pub fn dreamer_attempt_authority(
        &self,
        id: crate::attempt_queue::AttemptId,
    ) -> Result<Option<DreamerAuthorityStamp>> {
        let txn = self.store.env.read_txn()?;
        let key = [ATTEMPT_PREFIX, id.as_bytes()].concat();
        self.store
            .vault_meta
            .get(&txn, &key)?
            .map(|raw| {
                let stamp: DreamerAuthorityStamp =
                    serde_json::from_slice(&raw).map_err(|_| invalid())?;
                if stamp.attempt_id != *id.as_bytes()
                    || stamp.facet.trim().is_empty()
                    || self.store.vault_meta.get(&txn, ACTOR_KEY)?.as_deref()
                        != Some(stamp.actor.as_bytes().as_slice())
                    || self
                        .store
                        .entities
                        .get(&txn, stamp.actor.as_bytes())?
                        .is_none_or(|raw| {
                            EntityMetadataHeader::parse(&raw).is_none_or(|h| {
                                h.entity_type != crate::registry::ENTITY_TYPE_MACHINE
                            }) || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                                != Some(b"Dreamer authority".as_slice())
                        })
                {
                    return Err(invalid());
                }
                Ok(stamp)
            })
            .transpose()
    }
}
pub(super) fn stamp_attempt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    facet: &str,
) -> Result<()> {
    // The generic runner also carries independent agent dispatch. Those jobs
    // retain their own principals and are NOT Dreamer facets.
    if facet == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
        || (record.kind != super::DREAMER_RUNNER_ATTEMPT_KIND
            && !record.kind.starts_with("dreamer."))
    {
        return Ok(());
    }
    let actor = vault.dreamer_authority_in_txn(txn, record.created_at)?;
    let key = [ATTEMPT_PREFIX, record.id.as_bytes()].concat();
    if let Some(raw) = vault.store.vault_meta.get(&*txn, &key)? {
        let stamp: DreamerAuthorityStamp = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        if stamp.actor != actor.entity_ref()
            || stamp.attempt_id != *record.id.as_bytes()
            || stamp.facet != facet
        {
            return Err(invalid());
        }
        return Ok(());
    }
    let receipt_id = GateDecisionId::now();
    let receipt = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: receipt_id,
        created_at: record.created_at,
        outcome: "allow".into(),
        reason_codes: vec!["gate.dreamer.facet_admitted".into()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: actor.actor_class().gate_actor_class().into(),
        actor_ref: Some(actor.entity_ref().to_hex()),
        content_kind: "dreamer_authority".into(),
        policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
        claim_id: None,
        grant_ref: None,
        diff_handle: record.id.as_bytes().to_vec(),
        read_frontier_hash: crate::gate::resolve_policy_manifest(&vault.store, &*txn)?
            .read_frontier_hash()?,
        redacted_at: None,
    };
    vault.store.append_gate_decision_in_txn(txn, &receipt)?;
    let stamp = DreamerAuthorityStamp {
        attempt_id: *record.id.as_bytes(),
        actor: actor.entity_ref(),
        facet: facet.into(),
        receipt_id: receipt_id.as_bytes(),
    };
    vault.store.vault_meta.put(
        txn,
        &key,
        &serde_json::to_vec(&stamp).map_err(|_| invalid())?,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests;
