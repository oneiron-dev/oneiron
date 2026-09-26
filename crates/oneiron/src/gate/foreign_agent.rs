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
use crate::side_table::{self, Named, SideTable};
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
/// Per-actor foreign-introduction ceiling and widen state for an owner-bound agent
/// introduction. Key: id16.
const INTRODUCTION: SideTable<EntityId, Introduction, Named> =
    SideTable::new(&side_table::GATE_FOREIGN_AGENT_INTRODUCTION);
fn load(store: &Store, txn: &heed::RoTxn<'_>, actor: EntityId) -> Result<Option<Introduction>> {
    INTRODUCTION.get(store, txn, &actor)
}
fn put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    row: &Introduction,
) -> Result<()> {
    INTRODUCTION.put(store, txn, &actor, row)
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
            if row.owner != *owner.actor().as_bytes() {
                return Err(Error::Gate(
                    crate::error::GateError::ConsentOwnerNotAuthenticated(
                        "foreign introduction belongs to another owner",
                    ),
                ));
            }
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

    /// A foreign principal known only by its transport identity (an OAuth
    /// relay subject) holds a Grant with a scope and a ceiling, like every
    /// other actor: read and propose, capped at Proposed. Its transport key
    /// is not an authority key; only the owner mints this Grant, into the
    /// trusted default manifest. The returned ledger row is the receipt.
    pub fn grant_foreign_principal(
        &self,
        owner: &AuthenticatedOwner,
        principal: &str,
    ) -> Result<GateDecisionRecord> {
        use super::constants::{
            ACTOR_CEILING_KEY, ACTOR_CLASS_KEY, ACTOR_REF_KEY, GRANT_EFFECTOR_KEY,
            GRANT_RECEIPT_REQUIRED_KEY, GRANT_SCOPE_KEY, POLICY_ACTOR_CEILINGS_KEY,
            POLICY_SCOPED_GRANTS_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
        };
        use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
        use rmpv::Value;

        // A grant matches its actor_ref verbatim, so a padded name is refused
        // rather than normalized into a Grant nobody holds.
        if principal.trim() != principal {
            return Err(Error::InvalidClaimBody("foreign principal identity"));
        }
        crate::consent::ActorBound::new(principal)?;
        let mut scope = crate::federation::Scope::top();
        scope.verbs =
            crate::federation::ScopeAxis::Some(["read".to_owned(), "propose".to_owned()].into());
        let grant = Value::Map(vec![
            (ACTOR_REF_KEY.into(), principal.into()),
            (
                GRANT_EFFECTOR_KEY.into(),
                SCOPED_READ_EFFECTOR_CORE_READ.into(),
            ),
            (
                GRANT_SCOPE_KEY.into(),
                crate::federation::scope_codec::encode_scope_value(&scope)?,
            ),
            (GRANT_RECEIPT_REQUIRED_KEY.into(), false.into()),
        ]);
        let ceiling = Value::Map(vec![
            (
                ACTOR_CLASS_KEY.into(),
                EdgeActorClass::Agent.gate_actor_class().into(),
            ),
            (ACTOR_REF_KEY.into(), principal.into()),
            (ACTOR_CEILING_KEY.into(), "proposed".into()),
        ]);
        self.with_write_txn(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            let id = super::default_policy_manifest_id()?;
            let raw = self
                .store
                .entities
                .get(txn, id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            let body = raw
                .get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("policy manifest header"))?;
            // A separate pack would narrow the fold's single-valued predicates,
            // and re-stamping an untrusted body would launder it.
            if header.entity_type != crate::registry::ENTITY_TYPE_POLICY_MANIFEST
                || !super::manifest_authenticity::manifest_is_trusted(&self.store, txn, &id, body)?
            {
                return Err(Error::InvalidConfig(
                    "a foreign grant extends only the trusted default policy".to_owned(),
                ));
            }
            let Value::Map(mut entries) = rmpv::decode::read_value(&mut &body[..])
                .map_err(|_| Error::CorruptedIndex("policy manifest"))?
            else {
                return Err(Error::CorruptedIndex("policy manifest"));
            };
            for (table, row) in [
                (POLICY_SCOPED_GRANTS_KEY, &grant),
                (POLICY_ACTOR_CEILINGS_KEY, &ceiling),
            ] {
                match entries
                    .iter_mut()
                    .find(|(key, _)| key.as_str() == Some(table))
                {
                    Some((_, Value::Array(rows))) => {
                        if !rows.contains(row) {
                            rows.push(row.clone());
                        }
                    }
                    Some(_) => return Err(Error::CorruptedIndex("policy manifest table")),
                    None => entries.push((table.into(), Value::Array(vec![row.clone()]))),
                }
            }
            let mut data = Vec::new();
            rmpv::encode::write_value(&mut data, &Value::Map(entries))
                .map_err(|_| Error::InvariantViolation("foreign grant manifest encode"))?;
            let diff_handle = blake3::hash(&data).as_bytes().to_vec();
            crate::batch::apply_ops(
                &self.store,
                &self.config,
                &self.analyzer,
                txn,
                vec![BatchOp::Put {
                    id,
                    entity_type: crate::registry::ENTITY_TYPE_POLICY_MANIFEST,
                    occurred: crate::TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    learned_at: header.learned_at,
                    data,
                    allow_maintenance: true,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                }],
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
                true,
                true,
            )?;
            let mut receipt = GateDecisionRecord {
                version: 0,
                decision_id: GateDecisionId::from_bytes(self.store.clock.ulid()?),
                created_at: crate::ports::recorded_at_in_txn(&self.store, txn)?,
                outcome: GateOutcome::Allow.as_str().to_owned(),
                reason_codes: vec!["gate.allow.owner_foreign_grant".to_owned()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: EdgeActorClass::Human.gate_actor_class().to_owned(),
                actor_ref: Some(owner.actor().to_hex()),
                content_kind: GateContentKind::PolicyManifest.as_str().to_owned(),
                policy_manifest_version: super::POLICY_SCHEMA_VERSION.to_owned(),
                claim_id: None,
                grant_ref: Some(format!("foreign:{principal}")),
                diff_handle,
                read_frontier_hash: resolve_policy_manifest(&self.store, txn)?
                    .read_frontier_hash()?,
                redacted_at: None,
            };
            self.store
                .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
            Ok(receipt)
        })
    }
}
