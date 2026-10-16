//! Two vault-owned base-agent principals on one runner: the Dreamer and the
//! Coach (ARCH-0026 #base-agents). Job kinds are facets of one of them, not
//! new authorities.
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::batch::{BatchOp, EntityMetadataHeader, apply_ops};
use crate::side_table::{self, LegacyJson, Named, Raw, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::{
    ClaimApprovalStatus, ClaimSource, EdgeActorClass, EntityId, Error, Result, TimeRange, Vault,
    WriteActor, WriteEnvelope, WriteProvenance,
};
use serde::{Deserialize, Serialize};
mod policy;
pub use policy::{
    BaseAgent, DreamerAgentBoundary, base_agent_for_facet, dreamer_facet_for_job_type,
    warrants_new_agent,
};

/// Pointer to the single vault-owned Dreamer principal actor entity id.
const ACTOR: SideTable<(), EntityId, Raw> = SideTable::new(&side_table::DREAMER_AUTHORITY_ACTOR);
/// Stamp binding one attempt id to the Dreamer principal, facet, and
/// gate-decision receipt that admitted it.
const ATTEMPT: SideTable<AttemptId, DreamerAuthorityStamp, LegacyJson> =
    SideTable::new(&side_table::DREAMER_AUTHORITY_ATTEMPT);

/// The resident one dreaming attempt runs as (OF-490): its own stamp, never
/// the Dreamer's, bound at enqueue.
const RESIDENT_ATTEMPT: SideTable<AttemptId, ResidentAuthorityStamp, Named> =
    SideTable::new(&side_table::DREAMER_RESIDENT_ATTEMPT);

/// A resident's stamp on one of its own dreaming attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentAuthorityStamp {
    pub attempt_id: [u8; 16],
    pub resident: EntityId,
    pub receipt_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerAuthorityStamp {
    pub attempt_id: [u8; 16],
    #[serde(with = "crate::serialize::entity_ref")]
    pub actor: EntityId,
    pub facet: String,
    pub receipt_id: [u8; 16],
}
/// The seeded MACHINE row's body; the row itself carries seed time 0.
const ACTOR_BODY: &[u8] = b"Dreamer authority";
/// The Coach's seeded MACHINE row body, seeded like the Dreamer's at time 0.
const COACH_BODY: &[u8] = b"Coach authority";
pub(crate) fn dreamer_actor_id() -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(b"oneiron.dreamer.authority.v1", &[])
}
pub(crate) fn coach_actor_id() -> Result<EntityId> {
    crate::codebase::entity_id_from_hash_material(b"oneiron.coach.authority.v1", &[])
}
/// The fixed body of a base-agent principal row; `None` for any other id.
fn base_agent_body(id: EntityId) -> Result<Option<&'static [u8]>> {
    Ok(if id == dreamer_actor_id()? {
        Some(ACTOR_BODY)
    } else if id == coach_actor_id()? {
        Some(COACH_BODY)
    } else {
        None
    })
}
/// Whether `id` is one of the two fixed base-agent principal rows, which every
/// replica seeds identically and no write, delete or tombstone may change.
pub(crate) fn is_base_agent_actor(id: &EntityId) -> Result<bool> {
    Ok(base_agent_body(*id)?.is_some())
}

pub(crate) fn guard_actor_put(
    id: EntityId,
    entity_type: u8,
    data: &[u8],
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let Some(body) = base_agent_body(id)? else {
        return Ok(());
    };
    if entity_type != crate::registry::ENTITY_TYPE_MACHINE
        || data != body
        || occurred.start != 0
        || occurred.end != 0
        || learned_at != 0
    {
        return Err(Error::Registry(
            crate::error::RegistryError::DreamerActorImmutable,
        ));
    }
    Ok(())
}

pub(crate) fn guard_actor_delete(id: &EntityId) -> Result<()> {
    if is_base_agent_actor(id)? {
        return Err(Error::Registry(
            crate::error::RegistryError::DreamerActorImmutable,
        ));
    }
    Ok(())
}

fn invalid() -> Error {
    Error::InvalidConfig("invalid Dreamer authority binding".into())
}
impl Vault {
    /// Resolves the vault-owned system principal. Open seeds it without granting
    /// a ceiling, consent grant, or privilege.
    pub fn dreamer_authority(&self) -> Result<WriteActor> {
        self.with_write_txn_grouped(|txn| {
            self.dreamer_authority_in_txn(txn, self.now_recorded_at())
        })
    }
    pub(crate) fn dreamer_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        _now: u64,
    ) -> Result<WriteActor> {
        // The id is shared across replicas of one vault, but the local binding
        // cannot be redirected to another MACHINE or a deleted shell.
        let actor = dreamer_actor_id()?;
        let bound = ACTOR.get(&self.store, &*txn, &())?;
        if bound.is_some_and(|id| id != actor) {
            return Err(invalid());
        }
        let row = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &*txn, &actor)?;
        match row.as_deref().map(|raw| {
            (
                EntityMetadataHeader::parse(raw).map(|h| h.entity_type),
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..),
            )
        }) {
            Some((Some(crate::registry::ENTITY_TYPE_MACHINE), Some(ACTOR_BODY))) => {}
            // Earlier builds minted this id as an Agent PERSON on first use.
            // It is re-born as the System MACHINE row under the same id, so
            // its host key can be enrolled before any Dreamer write needs it.
            Some((Some(crate::registry::ENTITY_TYPE_PERSON), Some(ACTOR_BODY))) => {
                crate::batch::drop_seeded_actor_row(&self.store, txn, &actor)?;
                self.seed_actor_in_txn(txn, actor, ACTOR_BODY)?;
            }
            Some(_) => return Err(invalid()),
            None if bound.is_some() => return Err(invalid()),
            None => self.seed_actor_in_txn(txn, actor, ACTOR_BODY)?,
        }
        if bound.is_none() {
            ACTOR.put(&self.store, txn, &(), &actor)?;
        }
        Ok(WriteActor::new(actor, EdgeActorClass::System))
    }
    /// Resolves the Coach, the second base agent: ARCH-0066's healer on the
    /// Dreamer's runner. Open seeds it with no policy row, so its writes stay
    /// under the default Proposed actor ceiling and it reads nothing until a
    /// grant names it.
    pub fn coach_authority(&self) -> Result<WriteActor> {
        self.with_write_txn_grouped(|txn| self.coach_authority_in_txn(txn))
    }
    pub(crate) fn coach_authority_in_txn(&self, txn: &mut heed::RwTxn<'_>) -> Result<WriteActor> {
        // No local pointer: the row is immutable once seeded, and the id is
        // the same fixed hash on every replica.
        let actor = coach_actor_id()?;
        let row = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &*txn, &actor)?;
        match row.as_deref().map(|raw| {
            (
                EntityMetadataHeader::parse(raw).map(|h| h.entity_type),
                raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..),
            )
        }) {
            Some((Some(crate::registry::ENTITY_TYPE_MACHINE), Some(COACH_BODY))) => {}
            Some(_) => return Err(invalid()),
            None => self.seed_actor_in_txn(txn, actor, COACH_BODY)?,
        }
        Ok(WriteActor::new(actor, EdgeActorClass::System))
    }
    fn base_agent_authority_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        agent: BaseAgent,
        now: u64,
    ) -> Result<WriteActor> {
        match agent {
            BaseAgent::Dreamer => self.dreamer_authority_in_txn(txn, now),
            BaseAgent::Coach => self.coach_authority_in_txn(txn),
        }
    }
    fn seed_actor_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        body: &[u8],
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![BatchOp::Put {
                id: actor,
                entity_type: crate::registry::ENTITY_TYPE_MACHINE,
                occurred: TimeRange { start: 0, end: 0 },
                learned_at: 0,
                data: body.to_vec(),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
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
        let actor = self.with_write_txn_grouped(|txn| {
            self.base_agent_authority_in_txn(txn, base_agent_for_facet(facet), 0)
        })?;
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
    /// The base-agent principal the attempt was stamped with: the Dreamer or
    /// the Coach.
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
        self.dreamer_attempt_authority_in_txn(&txn, id)
    }

    /// Validates a queued authority stamp at the SAME wake ledger revision.
    pub(crate) fn dreamer_attempt_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::attempt_queue::AttemptId,
    ) -> Result<Option<DreamerAuthorityStamp>> {
        ATTEMPT
            .get(&self.store, txn, &id)?
            .map(|stamp| {
                let dreamer = ACTOR.get(&self.store, txn, &())?;
                let body = base_agent_body(stamp.actor)?;
                if stamp.attempt_id != *id.as_bytes()
                    || stamp.facet.trim().is_empty()
                    || !admits_stamp_actor(
                        base_agent_for_facet(&stamp.facet),
                        stamp.actor,
                        dreamer,
                    )?
                    || crate::ports::EntityStoreRead::port_entity_raw(
                        &self.store,
                        txn,
                        &stamp.actor,
                    )?
                    .is_none_or(|raw| {
                        EntityMetadataHeader::parse(&raw)
                            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_MACHINE)
                            || raw.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != body
                    })
                {
                    return Err(invalid());
                }
                Ok(stamp)
            })
            .transpose()
    }
}
/// A stamp names its facet's base agent. A Coach facet also keeps the Dreamer
/// it was stamped with before the Coach existed: a stamp is a birth fact.
fn admits_stamp_actor(
    agent: BaseAgent,
    actor: EntityId,
    dreamer: Option<EntityId>,
) -> Result<bool> {
    Ok(dreamer == Some(actor) || (agent == BaseAgent::Coach && actor == coach_actor_id()?))
}
pub(crate) fn stamp_attempt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
    facet: &str,
) -> Result<()> {
    // A resident's own dreaming runs under the resident's stamp.
    if record.kind == super::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND {
        return stamp_resident_attempt(vault, txn, record);
    }
    // The generic runner also carries independent agent dispatch. Those jobs
    // retain their own principals and are NOT base-agent facets.
    if facet == crate::agent_dispatch::AGENT_DISPATCH_ATTEMPT_TYPE
        || (record.kind != super::DREAMER_RUNNER_ATTEMPT_KIND
            && !record.kind.starts_with("dreamer.")
            && !record.kind.starts_with("coach."))
    {
        return Ok(());
    }
    // The queue dedupes by kind and key, not by payload. Do not let two
    // different job types sharing a facet replay each other's queue row.
    if super::decode_dreamer_attempt_payload(&record.payload)?.attempt_type != facet {
        return Err(Error::InvalidConfig(
            "Dreamer dedupe key refers to another job type".into(),
        ));
    }
    let facet = dreamer_facet_for_job_type(facet).unwrap_or(facet);
    let agent = base_agent_for_facet(facet);
    let actor = vault.base_agent_authority_in_txn(txn, agent, record.created_at)?;
    if let Some(stamp) = ATTEMPT.get(&vault.store, &*txn, &record.id)? {
        let dreamer = ACTOR.get(&vault.store, &*txn, &())?;
        if !admits_stamp_actor(agent, stamp.actor, dreamer)?
            || stamp.attempt_id != *record.id.as_bytes()
            || stamp.facet != facet
        {
            return Err(invalid());
        }
        return Ok(());
    }
    let receipt_id = GateDecisionId::from_bytes(*vault.new_entity_id()?.as_bytes());
    let receipt = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: receipt_id,
        created_at: record.created_at,
        outcome: "allow".into(),
        reason_codes: vec![
            match agent {
                BaseAgent::Dreamer => "gate.dreamer.facet_admitted",
                BaseAgent::Coach => "gate.coach.facet_admitted",
            }
            .into(),
        ],
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
    ATTEMPT.put(&vault.store, txn, &record.id, &stamp)?;
    Ok(())
}
/// Binds a resident dreaming attempt to its resident: an enabled agent
/// definition whose dreaming is not off. The row id is the resident's actor.
fn stamp_resident_attempt(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AttemptRecord,
) -> Result<()> {
    let payload = super::decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != super::DREAMER_RESIDENT_DREAM_ATTEMPT_KIND {
        return Err(invalid());
    }
    let resident = crate::dreamer_consolidation::resident_of_dream_input(&payload.input)?;
    if let Some(stamp) = RESIDENT_ATTEMPT.get(&vault.store, &*txn, &record.id)? {
        if stamp.resident != resident || stamp.attempt_id != *record.id.as_bytes() {
            return Err(invalid());
        }
        return Ok(());
    }
    let definition = vault.read_agent_definition_in_txn(txn, &resident)?;
    if !definition.enabled || definition.dreaming_mode() == crate::agent_def::DreamingMode::Off {
        return Err(Error::InvalidConfig(
            "a resident whose dreaming is off does not dream".into(),
        ));
    }
    let receipt_id = GateDecisionId::from_bytes(*vault.new_entity_id()?.as_bytes());
    let receipt = GateDecisionRecord {
        version: GATE_DECISION_LEDGER_VERSION,
        decision_id: receipt_id,
        created_at: record.created_at,
        outcome: "allow".into(),
        reason_codes: vec!["gate.dreamer.resident_admitted".into()],
        receipt_reasons: Vec::new(),
        system_notices: Vec::new(),
        actor_class: EdgeActorClass::Agent.gate_actor_class().into(),
        actor_ref: Some(resident.to_hex()),
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
    RESIDENT_ATTEMPT.put(
        &vault.store,
        txn,
        &record.id,
        &ResidentAuthorityStamp {
            attempt_id: *record.id.as_bytes(),
            resident,
            receipt_id: receipt_id.as_bytes(),
        },
    )
}

impl Vault {
    /// The resident a dreaming attempt runs as, by its own stamp.
    pub fn resident_actor_for_attempt(&self, id: AttemptId) -> Result<WriteActor> {
        let txn = self.store.env.read_txn()?;
        let stamp = RESIDENT_ATTEMPT
            .get(&self.store, &txn, &id)?
            .ok_or_else(invalid)?;
        if stamp.attempt_id != *id.as_bytes() {
            return Err(invalid());
        }
        Ok(WriteActor::new(stamp.resident, EdgeActorClass::Agent))
    }
}
#[cfg(test)]
mod tests;
