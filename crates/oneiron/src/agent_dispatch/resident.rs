//! Persistent resident bindings. Goal records are data, never prompt edits.
use super::{AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent};
use crate::claim::{ClaimSubject, claim_surfaceable};
use crate::consent::AuthenticatedOwner;
use crate::error::{ArtifactError, Error, Result};
use crate::task_verb::ConsultPayloadRef;
use crate::write_envelope::ClaimCandidate;
use crate::{
    ClaimApprovalStatus, ClaimSource, EntityId, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};
use rmpv::Value;

const PREDICATE: &str = "agent.resident";

/// Wake policy changes scheduling only. It conveys no scope or approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentWakeMode {
    HumanMessages,
    AllAddressed,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentGoalRecord {
    pub goal: ConsultPayloadRef,
    pub why: ConsultPayloadRef,
    pub axes: Vec<ConsultPayloadRef>,
}

/// A leader is an ordinary persistent AGENT_DEF with this data binding.
/// Its inbox remains the engine's identity-stamped inbox, not a new mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentAgentSpec {
    pub agent_def_ref: EntityId,
    pub inbox_identity_ref: EntityId,
    pub home_conversation_ref: EntityId,
    pub home_message_ref: EntityId,
    pub goal: ResidentGoalRecord,
    pub wake: ResidentWakeMode,
}

fn invalid() -> Error {
    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
        "invalid resident binding",
    ))
}

impl Vault {
    /// Owner configures a resident through the ordinary claim gate. This never
    /// writes AGENT_DEF.instructions, grants scope, or mutates room membership.
    pub fn bind_resident_agent(
        &self,
        owner: &AuthenticatedOwner,
        spec: &ResidentAgentSpec,
        now: u64,
    ) -> Result<EntityId> {
        validate(self, spec)?;
        let previous = self.resident_binding(spec.agent_def_ref)?;
        if previous.as_ref().is_some_and(|(_, stored)| stored == spec) {
            return Ok(previous.expect("checked").0);
        }
        let envelope = WriteEnvelope::new(
            WriteActor::new(owner.actor(), crate::edge::EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::Map(vec![
                (Value::from("op"), Value::from("agent.bind_resident")),
                (
                    Value::from("authentication"),
                    Value::from(format!("{:?}", owner.decision_id())),
                ),
            ]))?,
            ClaimApprovalStatus::Approved,
        );
        let id = EntityId::now();
        self.with_write_txn(|txn| {
            self.batch_in()
                .claim_candidate(
                    &id,
                    ClaimCandidate::new(
                        PREDICATE,
                        ClaimSubject::Entity(spec.agent_def_ref),
                        encode(spec),
                        1.0,
                    ),
                    &envelope,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )
                .apply(txn)?;
            if let Some((old, _)) = &previous {
                self.supersede_claim_in_txn(txn, &id, old, now)?;
            }
            Ok(())
        })?;
        Ok(id)
    }

    /// Returns references to the goal/why/axes and room node as ordinary data.
    pub fn resident_agent(&self, agent: EntityId) -> Result<Option<ResidentAgentSpec>> {
        Ok(self.resident_binding(agent)?.map(|(_, record)| record))
    }

    /// The resident inbox is the same live identity-filtered inbox lens.
    pub fn resident_agent_inbox(
        &self,
        agent: EntityId,
        limit: usize,
    ) -> Result<Vec<crate::agent_inbox_lens::AgentInboxLensItem>> {
        let Some(spec) = self.resident_agent(agent)? else {
            return Ok(Vec::new());
        };
        self.agent_inbox_lens(crate::agent_inbox_lens::AgentInboxLensQuery {
            identity_ref: Some(spec.inbox_identity_ref),
            limit: limit.min(64),
            before: None,
        })
    }

    fn resident_binding(&self, agent: EntityId) -> Result<Option<(EntityId, ResidentAgentSpec)>> {
        let mut found = None;
        for id in self.claims_for_subject(&agent)? {
            let Some(body) = self.get_claim(&id)? else {
                continue;
            };
            if body.predicate != PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            let spec = decode(agent, &body.value)?;
            validate(self, &spec)?;
            if found.as_ref().is_some_and(|(_, old)| old != &spec) {
                return Err(invalid());
            }
            found = Some((id, spec));
        }
        Ok(found)
    }
}

impl AgentDispatcher<'_> {
    /// Host maintenance entry for one resident's actual inbox. Repeated items
    /// reuse dispatch dedupe. A private chat does not become project context:
    /// the dispatched definition resolves its normal scope; goal refs stay data.
    pub fn dispatch_resident_inbox(
        &self,
        agent: EntityId,
        limit: usize,
        now: u64,
    ) -> Result<Vec<AgentDispatchOutcome>> {
        let Some(spec) = self.vault.resident_agent(agent)? else {
            return Ok(Vec::new());
        };
        if spec.wake == ResidentWakeMode::Manual {
            return Ok(Vec::new());
        }
        // The inbox lens actor_ref is the RECEIVER. Classify the sender from
        // the durable identity-stamped event, never from receiver identity.
        let rows = crate::attempt_queue::AttemptQueue::new(self.vault).list_kind_bounded(
            crate::surface_event::SURFACE_EVENT_ATTEMPT_KIND,
            crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        )?;
        let mut outcomes = Vec::new();
        for row in rows {
            let payload = crate::surface_event::decode_surface_event_attempt_payload(&row.payload)?;
            let event = payload.event;
            if event.receiving_identity_ref != spec.inbox_identity_ref.to_hex()
                || event.actor_ref != agent.to_hex()
                || !matches!(
                    event.action,
                    crate::surface_event::SurfaceEventAction::Message
                )
            {
                continue;
            }
            if spec.wake == ResidentWakeMode::HumanMessages {
                let crate::surface_event::SurfaceCounterpartyStamp::Known { counterparty_ref } =
                    event.counterparty
                else {
                    continue;
                };
                if self
                    .vault
                    .get_entity_type(&EntityId::from_hex(&counterparty_ref)?)?
                    != Some(crate::registry::ENTITY_TYPE_PERSON)
                {
                    continue;
                }
            }
            if outcomes.len() >= limit.min(64) {
                break;
            }
            let intent = blake3::hash(event.correlation_id.as_bytes()).to_hex();
            let outcome = self.dispatch(DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: Some(format!(
                    "resident:{}:{}:{}",
                    agent.to_hex(),
                    spec.inbox_identity_ref.to_hex(),
                    intent
                )),
                run_id: Some(format!("resident:{}", agent.to_hex())),
                now,
            })?;
            if !matches!(outcome, AgentDispatchOutcome::Existing(_)) {
                outcomes.push(outcome);
            }
        }
        Ok(outcomes)
    }
}

fn validate(vault: &Vault, spec: &ResidentAgentSpec) -> Result<()> {
    if vault.get_entity_type(&spec.agent_def_ref)? != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
        || vault.get_entity_type(&spec.home_conversation_ref)?
            != Some(crate::registry::ENTITY_TYPE_CONVERSATION)
        || vault.get_entity_type(&spec.home_message_ref)?
            != Some(crate::registry::ENTITY_TYPE_MESSAGE)
        || spec.goal.axes.len() > 32
    {
        return Err(invalid());
    }
    let identity = vault
        .get_channel_identity(&spec.inbox_identity_ref)?
        .ok_or_else(invalid)?;
    if identity.binding.actor_ref() != Some(spec.agent_def_ref) {
        return Err(invalid());
    }
    let parents: Vec<_> = vault
        .edges_out(&spec.home_message_ref)?
        .into_iter()
        .filter(|edge| edge.kind == crate::edge::EdgeKind::BelongsTo)
        .collect();
    if parents.len() != 1 || parents[0].target != spec.home_conversation_ref {
        return Err(invalid());
    }
    for reference in std::iter::once(spec.goal.goal)
        .chain(std::iter::once(spec.goal.why))
        .chain(spec.goal.axes.iter().copied())
    {
        ConsultPayloadRef::parse(vault, &reference.short_ref())?;
    }
    Ok(())
}

fn encode(spec: &ResidentAgentSpec) -> Value {
    Value::Array(vec![
        Value::from(1),
        Value::from(spec.inbox_identity_ref.to_hex()),
        Value::from(spec.home_conversation_ref.to_hex()),
        Value::from(spec.home_message_ref.to_hex()),
        Value::from(spec.goal.goal.short_ref()),
        Value::from(spec.goal.why.short_ref()),
        Value::Array(
            spec.goal
                .axes
                .iter()
                .map(|r| Value::from(r.short_ref()))
                .collect(),
        ),
        Value::from(match spec.wake {
            ResidentWakeMode::HumanMessages => "human_messages",
            ResidentWakeMode::AllAddressed => "all_addressed",
            ResidentWakeMode::Manual => "manual",
        }),
    ])
}
fn decode(agent: EntityId, value: &Value) -> Result<ResidentAgentSpec> {
    let a = value
        .as_array()
        .filter(|a| a.len() == 8)
        .ok_or_else(invalid)?;
    if a[0].as_u64() != Some(1) {
        return Err(invalid());
    }
    let text = |index: usize| a[index].as_str().ok_or_else(invalid);
    let entity = |index| EntityId::from_hex(text(index)?).map_err(|_| invalid());
    let reference = |text: &str| -> Result<ConsultPayloadRef> {
        let (kind, id) = text.split_once('_').ok_or_else(invalid)?;
        let id = EntityId::from_hex(id).map_err(|_| invalid())?;
        match kind {
            "cl" => Ok(ConsultPayloadRef::Claim(id)),
            "tn" => Ok(ConsultPayloadRef::Turn(id)),
            _ => Err(invalid()),
        }
    };
    let wake = match text(7)? {
        "human_messages" => ResidentWakeMode::HumanMessages,
        "all_addressed" => ResidentWakeMode::AllAddressed,
        "manual" => ResidentWakeMode::Manual,
        _ => return Err(invalid()),
    };
    Ok(ResidentAgentSpec {
        agent_def_ref: agent,
        inbox_identity_ref: entity(1)?,
        home_conversation_ref: entity(2)?,
        home_message_ref: entity(3)?,
        goal: ResidentGoalRecord {
            goal: reference(text(4)?)?,
            why: reference(text(5)?)?,
            axes: a[6]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .map(|v| reference(v.as_str().ok_or_else(invalid)?))
                .collect::<Result<_>>()?,
        },
        wake,
    })
}
