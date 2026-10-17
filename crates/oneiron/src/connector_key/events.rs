//! Durable, revocable connector-event subscriptions and atomic wake decisions.
//! Subscriptions are gated claims; wakes reuse the Dreamer queue and key budgets.
use super::txn::{
    append_connector_key_op_record, read_connector_key_in_txn, suspend_connector_key_in_txn,
};
use super::{
    ConnectorKeyStatus, EffectorBudgetChargeOutcome, EffectorBudgetOnExhaust,
    budget_exhausted_reason, charge_effector_budgets,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

const PREDICATE: &str = "agent.connector_subscription";
/// Hash domain separator for a wake decision's identity, matching the
/// [`WAKE_DECISION`] table's declared prefix bytes (kept as its own constant
/// because it also seeds the hash preimage below, not only the storage key).
const DECISION_PREFIX: &[u8] = b"connector.wake.v1:";
/// vault_meta idempotent wake-decision row: hash32 (of subscription id +
/// event id, domain-separated by [`DECISION_PREFIX`]) -> the decision.
const WAKE_DECISION: SideTable<[u8; 32], ConnectorWakeDecision, LegacyJson> =
    SideTable::new(&side_table::CONNECTOR_WAKE_DECISION);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorEventFilter {
    pub connector: String,
    pub event_kind: Option<String>,
    pub predicate: Option<String>,
}
impl ConnectorEventFilter {
    pub fn matches(&self, event: &ConnectorEvent) -> bool {
        self.connector == event.connector
            && self
                .event_kind
                .as_ref()
                .is_none_or(|kind| kind == &event.event_kind)
            && self
                .predicate
                .as_ref()
                .is_none_or(|p| p == &event.predicate)
    }
    fn validate(&self) -> Result<()> {
        if self.connector != super::normalize_connector_key(&self.connector)
            || !valid_ref(&self.connector)
            || self.event_kind.as_ref().is_some_and(|s| !valid_ref(s))
            || self.predicate.as_ref().is_some_and(|s| !valid_ref(s))
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorEvent {
    pub event_id: String,
    pub connector: String,
    pub event_kind: String,
    pub predicate: String,
    pub payload: Json,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSubscription {
    pub version: u8,
    #[serde(with = "crate::serialize::entity_ref")]
    pub agent: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub owner: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub connector_key: EntityId,
    pub filter: ConnectorEventFilter,
    pub active: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorWakeStatus {
    Enqueued,
    KeyInactive,
    BudgetExhausted,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorWakeDecision {
    #[serde(with = "crate::serialize::entity_ref")]
    pub subscription: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub agent: EntityId,
    pub status: ConnectorWakeStatus,
    pub attempt_id: Option<[u8; 16]>,
    pub event_hash: String,
}
fn invalid() -> Error {
    Error::InvalidConfig("invalid connector event subscription".into())
}
fn valid_ref(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim() && value.len() <= 256 && !value.contains('\0')
}
/// Structural event check shared by preflight and the atomic ingress door.
pub(crate) fn validate_connector_event(event: &ConnectorEvent) -> Result<()> {
    if !valid_ref(&event.event_id) || !valid_ref(&event.event_kind) || !valid_ref(&event.predicate)
    {
        return Err(invalid());
    }
    ConnectorEventFilter {
        connector: event.connector.clone(),
        event_kind: None,
        predicate: None,
    }
    .validate()
}
fn decode_subscription(body: &crate::ClaimBody) -> Result<ConnectorSubscription> {
    let row: ConnectorSubscription =
        serde_json::from_str(body.value.as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    row.filter.validate()?;
    if row.version != 1 || body.subject != ClaimSubject::Entity(row.agent) {
        return Err(invalid());
    }
    Ok(row)
}
/// One wake decision's identity: its subscription and the event's id,
/// domain-separated by [`DECISION_PREFIX`]. It keys the decision row and
/// dedupes the wake attempt.
fn wake_decision_identity(subscription: &EntityId, event_id: &str) -> blake3::Hash {
    let mut hash = blake3::Hasher::new();
    hash.update(DECISION_PREFIX);
    hash.update(subscription.as_bytes());
    hash.update(&(event_id.len() as u64).to_be_bytes());
    hash.update(event_id.as_bytes());
    hash.finalize()
}
fn subscriptions(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, ConnectorSubscription)>> {
    let mut result = Vec::new();
    for id in crate::claim::claim_ids_for_predicate_in_txn(store, txn, PREDICATE)? {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        // A pack hook's binding shares the row kind (ARCH-0080 §7); it is not
        // a connector-event subscription.
        if body.predicate != PREDICATE || crate::skill_hub::pack_catalog::is_hook_binding(&body) {
            continue;
        }
        let row = decode_subscription(&body)?;
        if body.lifecycle == ClaimLifecycleStatus::Active
            && matches!(
                body.approval,
                ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
            )
        {
            result.push((id, row));
        }
    }
    Ok(result)
}
impl Vault {
    pub fn subscribe_connector_event(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        connector_key: EntityId,
        filter: ConnectorEventFilter,
    ) -> Result<EntityId> {
        filter.validate()?;
        let txn = self.store.env.read_txn()?;
        let key = read_connector_key_in_txn(&self.store, &txn, &connector_key)?
            .ok_or(Error::EntityNotFound)?;
        if key.connector != filter.connector
            || key.actor_entity_ref.is_some_and(|bound| bound != agent)
        {
            return Err(invalid());
        }
        drop(txn);
        let id = EntityId::now();
        self.write_connector_subscription(
            owner,
            id,
            ConnectorSubscription {
                version: 1,
                agent,
                owner: owner.revalidate(self)?,
                connector_key,
                filter,
                active: true,
            },
        )?;
        Ok(id)
    }
    pub fn connector_event_subscriptions(
        &self,
        agent: EntityId,
    ) -> Result<Vec<(EntityId, ConnectorSubscription)>> {
        let txn = self.store.env.read_txn()?;
        Ok(subscriptions(&self.store, &txn)?
            .into_iter()
            .filter(|(_, row)| row.agent == agent)
            .collect())
    }
    /// The connector event `event_id` woke `agent` with (OF-519), read back
    /// through the wake decision each of `agent`'s subscriptions recorded
    /// for it and the wake attempt that froze the event. A reply's sink
    /// follows its intent's trigger here to the event it answers. `None`
    /// when no subscription of `agent` took the event, or its attempt is
    /// gone.
    ///
    /// # Errors
    /// The subscriptions or wake decisions could not be read.
    pub fn connector_event_woken(
        &self,
        agent: EntityId,
        event_id: &str,
    ) -> Result<Option<ConnectorEvent>> {
        let attempts = {
            let txn = self.store.env.read_txn()?;
            let mut attempts = Vec::new();
            for (id, row) in subscriptions(&self.store, &txn)? {
                if row.agent != agent {
                    continue;
                }
                let key = *wake_decision_identity(&id, event_id).as_bytes();
                if let Some(decision) = WAKE_DECISION.get(&self.store, &txn, &key)?
                    && let Some(attempt) = decision.attempt_id
                {
                    attempts.push(attempt);
                }
            }
            attempts
        };
        let runner = DreamerRunnerStore::new(self);
        for attempt in attempts {
            let Ok(Some(status)) = crate::attempt_queue::AttemptId::from_bytes(&attempt)
                .and_then(|attempt| runner.status(attempt))
            else {
                continue;
            };
            let Value::Map(fields) = &status.payload.input else {
                continue;
            };
            let frozen = fields
                .iter()
                .find(|(key, _)| key.as_str() == Some("connector_event"))
                .and_then(|(_, value)| value.as_str());
            if let Some(event) =
                frozen.and_then(|frozen| serde_json::from_str::<ConnectorEvent>(frozen).ok())
                && event.event_id == event_id
            {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }
    pub fn revoke_connector_event_subscription(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
    ) -> Result<()> {
        let body = self.get_claim(&id)?.ok_or(Error::EntityNotFound)?;
        if body.predicate != PREDICATE {
            return Err(invalid());
        }
        let mut row = decode_subscription(&body)?;
        if row.owner != owner.revalidate(self)? {
            return Err(invalid());
        }
        row.active = false;
        self.write_connector_subscription(owner, id, row)
    }
    fn write_connector_subscription(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        row: ConnectorSubscription,
    ) -> Result<()> {
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner.revalidate(self)?, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from("surface"),
                    Value::from("connector.subscription"),
                ),
                (
                    Value::from("owner_decision"),
                    Value::Binary(owner.decision_id().as_bytes().to_vec()),
                ),
            ]))?,
            ClaimApprovalStatus::Approved,
        );
        let value = serde_json::to_string(&row).map_err(|_| invalid())?;
        let candidate = ClaimCandidate::new(
            PREDICATE,
            ClaimSubject::Entity(row.agent),
            Value::from(value),
            1.0,
        );
        let now = crate::unix_seconds_now();
        // Checked again in the writer's snapshot: a revocation that commits
        // first subscribes nothing.
        self.batch()
            .claim_candidate(
                &id,
                candidate,
                &envelope,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
            )
            .commit_with_target_guard(|txn| owner.revalidate_in_txn(self, txn).map(drop))
    }
    /// Host ingress. The event data never becomes authority. Match, live-key
    /// check, budget charge, wake enqueue and decision receipt share one txn.
    pub fn ingest_connector_event(
        &self,
        event: &ConnectorEvent,
    ) -> Result<Vec<ConnectorWakeDecision>> {
        let decisions = self.with_write_txn_grouped(|txn| {
            self.ingest_connector_event_in_txn(txn, event, None, crate::unix_seconds_now())
        })?;
        self.signal_connector_wakes(&decisions);
        Ok(decisions)
    }

    /// The foreign-pack door attenuates host ingress to exactly the acting
    /// agent and the key granted to that run. Caller owns the transaction so
    /// the live grant, event admission and budget debit co-commit.
    #[cfg(any(test, feature = "microvm-firecracker"))]
    pub(crate) fn ingest_connector_event_for_pack_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        event: &ConnectorEvent,
        agent: EntityId,
        connector_key: EntityId,
        now: u64,
    ) -> Result<Vec<ConnectorWakeDecision>> {
        self.ingest_connector_event_in_txn(txn, event, Some((agent, Some(connector_key))), now)
    }

    /// Surface ingress (OF-218): a routed inbound event wakes only the
    /// subscriptions of the actor its receiving identity routed to, under
    /// whichever key that actor subscribed with. Match, live-key check,
    /// budget charge, wake enqueue and decision receipt share one txn, as
    /// host ingress does.
    pub fn ingest_surface_connector_event(
        &self,
        event: &ConnectorEvent,
        agent: EntityId,
        now: u64,
    ) -> Result<Vec<ConnectorWakeDecision>> {
        let decisions = self.with_write_txn_grouped(|txn| {
            self.ingest_connector_event_in_txn(txn, event, Some((agent, None)), now)
        })?;
        self.signal_connector_wakes(&decisions);
        Ok(decisions)
    }

    /// Post-commit: an enqueued wake re-arms the Dreamer's deadline source,
    /// which watches proactivity changes rather than the attempt queue.
    fn signal_connector_wakes(&self, decisions: &[ConnectorWakeDecision]) {
        if decisions
            .iter()
            .any(|decision| decision.status == ConnectorWakeStatus::Enqueued)
        {
            self.store.notify_proactivity_changes();
        }
    }

    fn ingest_connector_event_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        event: &ConnectorEvent,
        // The acting agent, and the one key granted to it when a pack run
        // carries one.
        scope: Option<(EntityId, Option<EntityId>)>,
        now: u64,
    ) -> Result<Vec<ConnectorWakeDecision>> {
        validate_connector_event(event)?;
        let frozen = serde_json::to_vec(event).map_err(|_| invalid())?;
        let event_hash = blake3::hash(&frozen).to_hex().to_string();
        let mut decisions = Vec::new();
        for (id, row) in subscriptions(&self.store, &*txn)? {
            // A subscription awaiting its owner's confirmation lists, but wakes
            // nothing until it is cleared.
            if !row.active
                || !row.filter.matches(event)
                || scope.is_some_and(|(agent, key)| {
                    row.agent != agent || key.is_some_and(|key| row.connector_key != key)
                })
                || !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, &*txn, &id)?
            {
                continue;
            }
            let identity = wake_decision_identity(&id, &event.event_id);
            let key = *identity.as_bytes();
            if let Some(old) = WAKE_DECISION.get(&self.store, &*txn, &key)? {
                if old.event_hash != event_hash || old.subscription != id || old.agent != row.agent
                {
                    return Err(invalid());
                }
                decisions.push(old);
                continue;
            }
            let status = self.admit_connector_event_wake(txn, &row, now)?;
            let attempt_id = if status == ConnectorWakeStatus::Enqueued {
                let payload = DreamerAttemptPayload {
                    attempt_type: "connector_event".into(),
                    input: Value::Map(vec![
                        (
                            Value::from("agent_ref"),
                            Value::Binary(row.agent.as_bytes().to_vec()),
                        ),
                        (
                            Value::from("connector_event"),
                            Value::from(String::from_utf8(frozen.clone()).map_err(|_| invalid())?),
                        ),
                        (Value::from("source"), Value::from("tool_output")),
                    ]),
                    parent_attempt: None,
                };
                let outcome = crate::dreamer_wake::request_wake_in_txn(
                    &DreamerRunnerStore::new(self),
                    txn,
                    crate::dreamer_wake::WakeTrigger::Event,
                    payload,
                    Some(identity.to_hex().to_string()),
                    None,
                    now,
                )?;
                let (EnqueueDreamerAttemptOutcome::Enqueued(attempt)
                | EnqueueDreamerAttemptOutcome::Existing(attempt)) = outcome;
                Some(*attempt.attempt.id.as_bytes())
            } else {
                None
            };
            let decision = ConnectorWakeDecision {
                subscription: id,
                agent: row.agent,
                status,
                attempt_id,
                event_hash: event_hash.clone(),
            };
            let reason = match status {
                ConnectorWakeStatus::Enqueued => "gate.connector_wake.enqueued",
                ConnectorWakeStatus::KeyInactive => "gate.connector_wake.key_inactive",
                ConnectorWakeStatus::BudgetExhausted => "gate.connector_wake.budget_exhausted",
            };
            let receipt = GateDecisionRecord {
                version: GATE_DECISION_LEDGER_VERSION,
                decision_id: GateDecisionId::now(),
                created_at: now,
                outcome: if status == ConnectorWakeStatus::Enqueued {
                    "allow"
                } else {
                    "pending"
                }
                .into(),
                reason_codes: vec![reason.into()],
                receipt_reasons: Vec::new(),
                system_notices: Vec::new(),
                actor_class: "agent".into(),
                actor_ref: Some(row.agent.to_hex()),
                content_kind: "connector_wake".into(),
                policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
                claim_id: Some(*id.as_bytes()),
                grant_ref: None,
                diff_handle: identity.as_bytes().to_vec(),
                read_frontier_hash: crate::gate::resolve_policy_manifest(&self.store, &*txn)?
                    .read_frontier_hash()?,
                redacted_at: None,
            };
            self.store.append_gate_decision_in_txn(txn, &receipt)?;
            WAKE_DECISION.put(&self.store, txn, &key, &decision)?;
            self.record_connector_notification_in_txn(txn, id, &event.event_id, attempt_id, now)?;
            decisions.push(decision);
        }
        Ok(decisions)
    }

    fn admit_connector_event_wake(
        &self,
        txn: &mut heed::RwTxn<'_>,
        row: &ConnectorSubscription,
        now: u64,
    ) -> Result<ConnectorWakeStatus> {
        let Some(mut key) = read_connector_key_in_txn(&self.store, &*txn, &row.connector_key)?
        else {
            return Ok(ConnectorWakeStatus::KeyInactive);
        };
        if key.status != ConnectorKeyStatus::Active
            || key.connector != row.filter.connector
            || key.actor_entity_ref.is_some_and(|actor| actor != row.agent)
        {
            return Ok(ConnectorWakeStatus::KeyInactive);
        }
        match charge_effector_budgets(
            &self.store,
            txn,
            &row.connector_key,
            &mut key,
            &row.filter.connector,
            false,
            now,
        )? {
            EffectorBudgetChargeOutcome::Charged(_) | EffectorBudgetChargeOutcome::NoRows(_) => {
                Ok(ConnectorWakeStatus::Enqueued)
            }
            EffectorBudgetChargeOutcome::Exhausted {
                row_index,
                on_exhaust,
                ..
            } => {
                if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                    key = suspend_connector_key_in_txn(
                        &self.store,
                        txn,
                        &row.connector_key,
                        &key,
                        budget_exhausted_reason(row_index),
                        now,
                    )?;
                    let floor = crate::gate::resolve_policy_manifest(&self.store, &*txn)?
                        .read_frontier_hash()?;
                    append_connector_key_op_record(
                        &self.store,
                        txn,
                        &row.connector_key,
                        "gate.connector_key.wake_suspend",
                        &key,
                        floor,
                        now,
                    )?;
                }
                Ok(ConnectorWakeStatus::BudgetExhausted)
            }
        }
    }
}
#[cfg(test)]
mod tests;
