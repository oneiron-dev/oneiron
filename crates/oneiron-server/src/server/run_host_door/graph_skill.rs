//! One attached run's saved graph workflow, using the host's decision ladder.

use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{HostWriteOrigin, MemoryError, MemoryResult};
use oneiron::receipt::{GraphSkillRunOutcome, GraphSkillRunRequest};
use oneiron::{EntityId, WriteActor};
use serde_json::Value;

use super::{decode, encode};
use crate::decision_verdict::on_caller_payer;
use crate::server::SyncServer;

mod answerer;
use answerer::SavedGraphAnswerer;

pub(super) fn run(
    server: &SyncServer,
    actor: WriteActor,
    origin: &HostWriteOrigin,
    run_id: Option<EntityId>,
    line: Option<&RunAdmission>,
    input: Value,
    evidence: &mut Option<Vec<EntityId>>,
    current: Option<oneiron::claim::ScopedReadActorKey>,
) -> MemoryResult<Value> {
    let request: GraphSkillRunRequest = decode(input)?;
    request.validate()?;
    let skill = EntityId::from_hex(&request.skill)?;
    let lease = match run_id {
        Some(run) => server
            .live_runs
            .skill_lease_for_origin(server.vault(), run, actor, origin)?,
        None => None,
    };
    let (leased, executor) = lease.ok_or_else(|| {
        MemoryError::bad_request("self.skills.graph requires this caller's live attached run")
    })?;
    let mut answerer = SavedGraphAnswerer::new(
        server,
        actor,
        request.ceiling,
        request.unit_deadline_ms,
        request.posture,
        request.criteria,
    );
    let ran = on_caller_payer(line.and_then(RunAdmission::payer), || {
        oneiron::skill::execute_graph_workflow_skill_with_read_key(
            server.vault(),
            &leased,
            &skill,
            &request.reference,
            &executor,
            actor.entity_ref(),
            actor,
            &mut answerer,
            oneiron_vault_contract::now_ts(),
            current,
        )
    });
    let outcome = match ran {
        Ok(result) => GraphSkillRunOutcome::from(result),
        Err(failure) => GraphSkillRunOutcome::from_failure(failure)?,
    };
    if let Some(rows) = evidence {
        rows.push(skill);
        for answer in outcome.stages().iter().flatten().flatten() {
            rows.extend(answer.decision.evidence.iter().copied());
            rows.extend([answer.decision.receipt.principal, answer.claim, answer.unit]);
            rows.extend(answer.omitted.iter().map(|omitted| omitted.id));
        }
    }
    encode(outcome)
}
