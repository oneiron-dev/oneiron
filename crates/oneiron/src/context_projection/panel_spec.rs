//! The referenced lead-panel spec: typed shape, codec, durable persistence, and task-input planner.

use serde::{Deserialize, Serialize};

use super::spec::{ContextSpec, validate_context_spec, validate_panel_text};
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::RecordError;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::task_verb::{ConsultPayload, ConsultPayloadRef, TaskAssignee};
use crate::temporal::TimeRange;

/// Most members one panel spec may carry.
pub const LEAD_PANEL_MAX_MEMBERS: usize = 16;

/// Pinned schema version of the persisted `LeadPanelSpec` entity body.
pub const LEAD_PANEL_SPEC_SCHEMA_VERSION: u64 = 1;

/// Pinned `role` discriminant of the persisted `LeadPanelSpec` entity body.
pub const LEAD_PANEL_SPEC_ROLE: &str = "lead_panel_spec";

// ── typed referenced panel spec ─────────────────────────────────────────

/// A blind panel, its single judge pass, and its one synthesis.
///
/// Persisted as its own typed spec entity; NEVER inline in a `ConsultPayload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeadPanelSpec {
    pub members: Vec<PanelMemberSpec>,
    pub judge: PanelJudgeSpec,
    pub synthesis: PanelSynthesisSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelMemberSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub instructions: String,
    pub context_spec: ContextSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelJudgeSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub rubric: String,
    pub context_spec: ContextSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanelSynthesisSpec {
    #[serde(with = "assignee_wire")]
    pub responder: TaskAssignee,
    pub instructions: String,
    pub context_spec: ContextSpec,
}

/// Structural validation of a panel spec, independent of any vault.
pub fn validate_lead_panel_spec(spec: &LeadPanelSpec) -> Result<()> {
    if spec.members.is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec must name a member",
        )));
    }
    if spec.members.len() > LEAD_PANEL_MAX_MEMBERS {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec names too many members",
        )));
    }
    for (index, member) in spec.members.iter().enumerate() {
        if !matches!(member.responder, TaskAssignee::Peer { .. }) {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "panel responders must be Peer",
            )));
        }
        validate_panel_text(&member.instructions, "panel member instructions")?;
        validate_context_spec(&member.context_spec)?;
        // Distinct responders keep "N members" a count of ANSWERS, not of
        // duplicate asks landing on one actor.
        if spec.members[..index]
            .iter()
            .any(|prior| prior.responder == member.responder)
        {
            return Err(Error::Record(RecordError::InvalidTaskBody(
                "panel spec names one responder twice",
            )));
        }
    }
    if !matches!(spec.judge.responder, TaskAssignee::Peer { .. })
        || !matches!(spec.synthesis.responder, TaskAssignee::Peer { .. })
    {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel responders must be Peer",
        )));
    }
    validate_panel_text(&spec.judge.rubric, "panel judge rubric")?;
    validate_context_spec(&spec.judge.context_spec)?;
    validate_panel_text(&spec.synthesis.instructions, "panel synthesis instructions")?;
    validate_context_spec(&spec.synthesis.context_spec)
}

/// Persists a panel spec as a durable TURN and returns the already-legal
/// consult ref that points at it. No NOTE payload-ref variant, no new TASK
/// field, no inline text.
pub fn persist_lead_panel_spec(
    vault: &Vault,
    spec: &LeadPanelSpec,
    now: u64,
) -> Result<ConsultPayloadRef> {
    validate_lead_panel_spec(spec)?;
    let body = encode_lead_panel_spec(spec)?;
    let spec_ref = EntityId::now();
    vault.put_entity(
        &spec_ref,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &body,
    )?;
    Ok(ConsultPayloadRef::Turn(spec_ref))
}

/// Loads and validates the panel spec a consult ref points at.
pub fn load_lead_panel_spec(vault: &Vault, spec_ref: ConsultPayloadRef) -> Result<LeadPanelSpec> {
    let ConsultPayloadRef::Turn(entity_ref) = spec_ref else {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec ref must name the durable spec turn",
        )));
    };
    let raw = vault
        .get_raw(&entity_ref)?
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "panel spec ref does not resolve",
        )))?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::Record(
        RecordError::InvalidTaskBody("panel spec row header is malformed"),
    ))?;
    if header.entity_type != ENTITY_TYPE_TURN {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec ref is not a turn row",
        )));
    }
    let spec = decode_lead_panel_spec(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    validate_lead_panel_spec(&spec)?;
    Ok(spec)
}

/// Encodes a panel spec into its pinned-key entity body.
pub fn encode_lead_panel_spec(spec: &LeadPanelSpec) -> Result<Vec<u8>> {
    let json = serde_json::to_string(spec)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("panel spec does not encode")))?;
    let value = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("role"),
            rmpv::Value::from(LEAD_PANEL_SPEC_ROLE),
        ),
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from(LEAD_PANEL_SPEC_SCHEMA_VERSION),
        ),
        (rmpv::Value::from("spec"), rmpv::Value::from(json.as_str())),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value).map_err(|_| {
        Error::Record(RecordError::InvalidTaskBody(
            "panel spec body does not encode",
        ))
    })?;
    Ok(out)
}

/// Decodes a pinned-key panel-spec entity body.
pub fn decode_lead_panel_spec(bytes: &[u8]) -> Result<LeadPanelSpec> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor).map_err(|_| {
        Error::Record(RecordError::InvalidTaskBody(
            "panel spec body is not MessagePack",
        ))
    })?;
    let rmpv::Value::Map(entries) = value else {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec body must be a map",
        )));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    if field("role").and_then(rmpv::Value::as_str) != Some(LEAD_PANEL_SPEC_ROLE) {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec body role is not a panel",
        )));
    }
    if field("schema_version").and_then(rmpv::Value::as_u64) != Some(LEAD_PANEL_SPEC_SCHEMA_VERSION)
    {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel spec schema version must be 1",
        )));
    }
    let json = field("spec")
        .and_then(rmpv::Value::as_str)
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "panel spec body carries no spec",
        )))?;
    serde_json::from_str(json)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("panel spec does not decode")))
}

/// Which settled results a planned TASK must wait for before it is mintable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelResultInputs {
    None,
    AllMemberResults,
    AllMemberAndJudgeResults,
}

/// A typed INPUT the lead turns into a real TASK with `tasks.create`. It is not
/// a pre-allocated task id, and it carries no entity the lead has not minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadPanelTaskInputSpec {
    pub responder: TaskAssignee,
    pub consult: ConsultPayload,
    pub context_spec: ContextSpec,
    pub result_inputs: PanelResultInputs,
}

/// The lead's plan for one panel run: N blind members, one judge pass, one
/// synthesis. Ordering is carried by [`PanelResultInputs`], not by a scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadPanelExecutionPlan {
    pub member_tasks: Vec<LeadPanelTaskInputSpec>,
    pub judge_task: LeadPanelTaskInputSpec,
    pub synthesis_task: LeadPanelTaskInputSpec,
}

/// Plans the typed task inputs for one `ask(lead, panel-spec)` run.
///
/// Every planned `ConsultPayload` uses ONE-1699's fields only: the shared
/// `question_ref`, `context_refs` carrying the persisted panel-spec ref, and
/// the shared `correlation_ref`. Member inputs carry NO sibling results — panel
/// blindness is structural, not a runtime check.
///
/// # Errors
///
/// [`RecordError::InvalidTaskBody`](crate::error::RecordError::InvalidTaskBody) when the spec is malformed or when the question
/// and panel-spec refs collide (a consult refuses duplicate refs).
pub fn plan_lead_panel_tasks(
    question_ref: ConsultPayloadRef,
    panel_spec_ref: ConsultPayloadRef,
    correlation_ref: EntityId,
    spec: &LeadPanelSpec,
) -> Result<LeadPanelExecutionPlan> {
    validate_lead_panel_spec(spec)?;
    if question_ref == panel_spec_ref {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "panel question and spec must be distinct refs",
        )));
    }
    let consult = || ConsultPayload::question(question_ref, vec![panel_spec_ref], correlation_ref);
    Ok(LeadPanelExecutionPlan {
        member_tasks: spec
            .members
            .iter()
            .map(|member| LeadPanelTaskInputSpec {
                responder: member.responder,
                consult: consult(),
                context_spec: member.context_spec.clone(),
                result_inputs: PanelResultInputs::None,
            })
            .collect(),
        judge_task: LeadPanelTaskInputSpec {
            responder: spec.judge.responder,
            consult: consult(),
            context_spec: spec.judge.context_spec.clone(),
            result_inputs: PanelResultInputs::AllMemberResults,
        },
        synthesis_task: LeadPanelTaskInputSpec {
            responder: spec.synthesis.responder,
            consult: consult(),
            context_spec: spec.synthesis.context_spec.clone(),
            result_inputs: PanelResultInputs::AllMemberAndJudgeResults,
        },
    })
}

/// Serde adapter for ONE-1699's `TaskAssignee`, which is consumed read-only and
/// carries no derives of its own.
mod assignee_wire {
    use super::TaskAssignee;
    use crate::entity_id::EntityId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize, Deserialize)]
    struct Wire {
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        entity_ref: Option<String>,
    }

    pub(super) fn serialize<S: Serializer>(
        assignee: &TaskAssignee,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        Wire {
            kind: assignee.as_str().to_owned(),
            entity_ref: assignee.entity_ref().map(|id| id.to_hex()),
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<TaskAssignee, D::Error> {
        let wire = Wire::deserialize(deserializer)?;
        let entity_ref = wire
            .entity_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| serde::de::Error::custom("assignee ref must be a hex EntityId"))?;
        match (wire.kind.as_str(), entity_ref) {
            ("dreamer", None) => Ok(TaskAssignee::Dreamer),
            ("agent_def", Some(agent_def_ref)) => Ok(TaskAssignee::AgentDef { agent_def_ref }),
            ("peer", Some(actor_ref)) => Ok(TaskAssignee::Peer { actor_ref }),
            ("human", Some(actor_ref)) => Ok(TaskAssignee::Human { actor_ref }),
            _ => Err(serde::de::Error::custom(
                "assignee kind and ref do not agree",
            )),
        }
    }
}
