//! Run resident-authored graph workflows from the admitted skill source tree.

use super::SkillRole;
use crate::attempt_queue::AttemptRecord;
use crate::error::{ArtifactError, Error, Result};
use crate::llm::decision::questions::{
    AnswerRecord, GraphAnswerer, GraphQuestionInput, GraphQuestionRef,
    run_graph_question_with_proposals,
};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Policy is authored in a skill file, not shipped as an engine question set.
/// Stages can ask per-unit questions, roll up their answers, then propose a pick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillProgram {
    pub stages: Vec<GraphSkillStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillStage {
    pub question: GraphQuestionRef,
    pub inputs: Vec<GraphSkillInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillInput {
    pub context: GraphQuestionInput,
    /// Answers from earlier stages become ordinary, scoped evidence. A missing
    /// answer holds this input back; an abstention never becomes a negative.
    pub answers: Vec<GraphSkillAnswerRef>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSkillAnswerRef {
    pub stage: usize,
    /// None selects all inputs in the stage (for a campaign rollup).
    pub input: Option<usize>,
}

/// Entries retain their input positions, including abstentions. The last
/// stage is still only proposed work; this API neither keeps nor sends it.
#[derive(Debug, Clone, Default)]
pub struct GraphSkillResult {
    pub stages: Vec<Vec<Option<AnswerRecord>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("graph skill failed at stage {stage:?}, input {input:?}: {error}")]
pub struct GraphSkillFailure {
    pub stage: Option<usize>,
    pub input: Option<usize>,
    pub error: Box<Error>,
    pub completed: GraphSkillResult,
}

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidSkillBody(reason))
}

impl GraphSkillProgram {
    /// Structure only: every stage, input and reference is admitted however
    /// many there are, and each input runs as its own question (FIX 10152).
    fn validate(&self) -> Result<()> {
        if self.stages.is_empty() {
            return Err(invalid("graph workflow requires at least one stage"));
        }
        for (stage, step) in self.stages.iter().enumerate() {
            if step.inputs.is_empty() || step.question.version == 0 {
                return Err(invalid("invalid graph workflow stage"));
            }
            for input in &step.inputs {
                for source in &input.answers {
                    if source.stage >= stage
                        || source
                            .input
                            .is_some_and(|index| index >= self.stages[source.stage].inputs.len())
                    {
                        return Err(invalid("graph workflow must reference an earlier input"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Load the exact resident-owned workflow revision into the caller's live
/// attempt manifest, then run its saved graph questions. The file is JSON
/// data in that hash-checked source tree, never a host path or executable.
/// The resident authors the context joins, question versions, rollups and pick;
/// the engine supplies scoped reads, proposal writes and outcome receipts.
#[expect(
    clippy::too_many_arguments,
    reason = "the host lends its live attempt, resident, asker, answerer and clock"
)]
pub fn execute_graph_workflow_skill(
    vault: &Vault,
    leased: &AttemptRecord,
    skill: &EntityId,
    reference: &str,
    executor: &str,
    principal: EntityId,
    actor: WriteActor,
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> std::result::Result<GraphSkillResult, GraphSkillFailure> {
    let prepare = || -> Result<GraphSkillProgram> {
        let owner = leased
            .lease_owner
            .as_deref()
            .ok_or(invalid("graph workflow requires a live attempt lease"))?;
        crate::skill_reliability::validate_executor(executor)?;
        let loaded = vault.load_resident_skill_pack(
            leased.id,
            &actor.entity_ref(),
            skill,
            owner,
            leased.attempt_count,
            executor,
            now,
        )?;
        if loaded.record.role != SkillRole::Workflow {
            return Err(invalid("graph workflow requires a workflow skill"));
        }
        let file = loaded
            .source_files
            .as_ref()
            .and_then(|files| files.iter().find(|file| file.path == reference))
            .ok_or(invalid("graph workflow is absent from stored skill source"))?;
        let program: GraphSkillProgram = serde_json::from_slice(&file.content)
            .map_err(|_| invalid("invalid graph workflow program"))?;
        program.validate()?;
        Ok(program)
    };
    let program = prepare().map_err(|error| GraphSkillFailure {
        stage: None,
        input: None,
        error: Box::new(error),
        completed: GraphSkillResult::default(),
    })?;
    let mut completed = GraphSkillResult::default();
    for (stage, step) in program.stages.iter().enumerate() {
        completed.stages.push(Vec::new());
        for (input_index, input) in step.inputs.iter().enumerate() {
            let mut context = input.context.clone();
            // Sets keep the joins linear in the sources however many there are.
            let mut evidence: HashSet<EntityId> = context.evidence.iter().copied().collect();
            let mut proposed = HashSet::new();
            let mut proposals = Vec::new();
            let mut missing = false;
            for source in &input.answers {
                let rows = &completed.stages[source.stage];
                let selected = match source.input {
                    Some(index) => &rows[index..=index],
                    None => rows.as_slice(),
                };
                for answer in selected {
                    match answer {
                        Some(answer) => {
                            if evidence.insert(answer.claim) {
                                context.evidence.push(answer.claim);
                            }
                            if proposed.insert(answer.claim) {
                                proposals.push(answer.clone());
                            }
                        }
                        None => missing = true,
                    }
                }
            }
            if missing {
                completed.stages[stage].push(None);
                continue;
            }
            match run_graph_question_with_proposals(
                vault,
                principal,
                actor,
                step.question,
                &[context],
                &proposals,
                answerer,
                now,
            ) {
                Ok(result) => completed.stages[stage].push(result.answers.into_iter().next()),
                Err(failure) => {
                    return Err(GraphSkillFailure {
                        stage: Some(stage),
                        input: Some(input_index),
                        error: failure.error,
                        completed,
                    });
                }
            }
        }
    }
    Ok(completed)
}
