//! Owner-bound foreign introductions. Every claim/effect reads the live clamp.
use super::ceiling::{
    PolicyApprovalCeiling, foreign_agent_ceiling_after_widen_request,
    foreign_agent_effective_ceiling,
};
use super::definition_ceiling::definition_only_ceiling_for_actor;
use super::input::{GateActor, GateContentKind, GateEvaluatorInput, GateProvenanceHandles};
use super::{GateOutcome, PolicyCriticality, resolve_policy_manifest};
use crate::agent_def::AgentCeiling;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::store::{GateDecisionId, GateDecisionRecord, Store};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Introduction {
    introducer: [u8; 16],
    introducer_class: u8,
    confirmed_auto: bool,
    owner: [u8; 16],
    // A successful explicit widening is invalidated by any policy-frontier change.
    widen: Option<([u8; 32], bool)>,
}
fn key(id: EntityId) -> Vec<u8> {
    let mut key = b"gate.foreign-agent.v1:".to_vec();
    key.extend(id.as_bytes());
    key
}
fn load(store: &Store, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<Option<Introduction>> {
    store
        .vault_meta
        .get(txn, &key(actor))?
        .map(|raw| {
            rmp_serde::from_slice(&raw)
                .map_err(|_| Error::CorruptedIndex("foreign agent introduction"))
        })
        .transpose()
}
fn put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    row: &Introduction,
) -> Result<()> {
    let raw = rmp_serde::to_vec_named(row)
        .map_err(|_| Error::InvariantViolation("foreign agent encode"))?;
    store.vault_meta.put(txn, &key(actor), &raw)?;
    Ok(())
}
fn ceiling(auto: bool) -> PolicyApprovalCeiling {
    if auto {
        PolicyApprovalCeiling::Auto
    } else {
        PolicyApprovalCeiling::Proposed
    }
}
pub(super) fn resolve(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Result<Option<PolicyApprovalCeiling>> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return Ok(None);
    }
    let policy = resolve_policy_manifest(store, txn)?;
    resolve_chain(store, txn, actor, &policy, &mut Vec::new())
}
fn resolve_chain(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
    policy: &super::PolicyManifestResolution,
    seen: &mut Vec<EntityId>,
) -> Result<Option<PolicyApprovalCeiling>> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return Ok(None);
    }
    if seen.contains(&actor.entity_ref()) || seen.len() >= 64 {
        return Ok(Some(PolicyApprovalCeiling::Proposed));
    }
    seen.push(actor.entity_ref());
    let Some(row) = load(store, txn, actor.entity_ref())? else {
        // Foreign status is an explicit authenticated introduction, not a
        // product-band type byte or a guess from an entity's prose.
        return Ok(None);
    };
    let owner = EntityId::from_bytes(row.owner)?;
    if store
        .entities
        .get(txn, owner.as_bytes())?
        .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
        .is_none_or(|header| header.entity_type != crate::registry::ENTITY_TYPE_PERSON)
    {
        return Ok(Some(PolicyApprovalCeiling::Proposed));
    }
    if let Some((frontier, auto)) = row.widen
        && frontier == policy.read_frontier_hash()?
    {
        return Ok(Some(ceiling(auto)));
    }
    let introducer = WriteActor::new(
        EntityId::from_bytes(row.introducer)?,
        EdgeActorClass::try_from_u8(row.introducer_class)
            .ok_or(Error::CorruptedIndex("foreign introducer class"))?,
    );
    let mut cap = policy.actor_ceiling(
        introducer.actor_class().gate_actor_class(),
        Some(&introducer.entity_ref().to_hex()),
    );
    if let Some(definition) = definition_only_ceiling_for_actor(store, txn, introducer) {
        cap = cap.restrict(definition);
    }
    if let Some(parent) = resolve_chain(store, txn, introducer, policy, seen)? {
        cap = cap.restrict(parent);
    }
    Ok(Some(foreign_agent_effective_ceiling(
        ceiling(row.confirmed_auto),
        cap,
    )))
}
impl Vault {
    /// Records an explicit owner-confirmed introduction, not a caller-asserted ceiling.
    pub fn register_foreign_agent(
        &self,
        owner: &AuthenticatedOwner,
        foreign: EntityId,
        introducer: WriteActor,
        confirmed: AgentCeiling,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            if foreign == introducer.entity_ref()
                || self.store.entities.get(txn, foreign.as_bytes())?.is_none()
                || self
                    .store
                    .entities
                    .get(txn, introducer.entity_ref().as_bytes())?
                    .is_none()
            {
                return Err(Error::InvalidClaimBody("foreign introduction identity"));
            }
            if load(&self.store, txn, foreign)?.is_some() {
                return Err(Error::InvalidClaimBody(
                    "foreign introduction already exists; use widening door",
                ));
            }
            put(
                &self.store,
                txn,
                foreign,
                &Introduction {
                    introducer: *introducer.entity_ref().as_bytes(),
                    introducer_class: introducer.actor_class() as u8,
                    confirmed_auto: confirmed == AgentCeiling::Auto,
                    owner: *owner.actor().as_bytes(),
                    widen: None,
                },
            )
        })
    }

    /// Widen-on-request: an authenticated owner request still needs normal Gate Allow.
    /// A Pending/Deny leaves the stored introduction unchanged and records the verdict.
    pub fn request_foreign_agent_widen(
        &self,
        owner: &AuthenticatedOwner,
        foreign: EntityId,
        requested: AgentCeiling,
    ) -> Result<bool> {
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let mut row = load(&self.store, txn, foreign)?.ok_or(Error::EntityNotFound)?;
            let policy = resolve_policy_manifest(&self.store, txn)?;
            let current = resolve(
                &self.store,
                txn,
                WriteActor::new(foreign, EdgeActorClass::Agent),
            )?
            .unwrap_or(PolicyApprovalCeiling::Proposed);
            let input = GateEvaluatorInput {
                actor: GateActor {
                    actor_class: "human".to_owned(),
                    actor_ref: Some(owner.actor().to_hex()),
                    delegation_grant_ref: None,
                },
                // A widen request carries no claim candidate or sensitivity.
                // Owner authority and actor ceilings still pass the normal gate.
                source: None,
                content_kind: GateContentKind::Claim,
                sensitivity_band: None,
                criticality: PolicyCriticality::Normal,
                policy_manifest_version: super::POLICY_SCHEMA_VERSION.to_owned(),
                provenance: GateProvenanceHandles {
                    actor_entity_ref: Some(owner.actor()),
                    ..Default::default()
                },
                external_effect: None,
                agent_definition_ceiling: None,
                foreign_agent_ceiling: None,
                consent: None,
            };
            let decision = policy.evaluate_gate(&input);
            let requested = PolicyApprovalCeiling::from_agent_ceiling(requested);
            let next = foreign_agent_ceiling_after_widen_request(current, requested, &decision);
            let allow = decision.outcome() == GateOutcome::Allow;
            let frontier = policy.read_frontier_hash()?;
            if allow {
                row.widen = Some((frontier, next == PolicyApprovalCeiling::Auto));
                put(&self.store, txn, foreign, &row)?;
            }
            self.store.append_fresh_gate_decision_in_txn(
                txn,
                &mut GateDecisionRecord {
                    version: 0,
                    decision_id: GateDecisionId::now(),
                    created_at: crate::unix_seconds_now(),
                    outcome: decision.outcome().as_str().to_owned(),
                    reason_codes: decision
                        .reason_codes()
                        .iter()
                        .map(|code| code.as_str().to_owned())
                        .collect(),
                    receipt_reasons: Vec::new(),
                    system_notices: Vec::new(),
                    actor_class: "human".to_owned(),
                    actor_ref: Some(owner.actor().to_hex()),
                    content_kind: "claim".to_owned(),
                    policy_manifest_version: super::POLICY_SCHEMA_VERSION.to_owned(),
                    claim_id: None,
                    grant_ref: Some(format!("foreign:{}", foreign.to_hex())),
                    diff_handle: vec![u8::from(requested == PolicyApprovalCeiling::Auto)],
                    read_frontier_hash: frontier,
                    redacted_at: None,
                },
            )?;
            Ok(allow)
        })
    }
}
