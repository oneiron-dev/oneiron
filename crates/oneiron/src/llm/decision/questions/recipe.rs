//! Explicit, resident-authored context recipes over immutable graph questions.

use super::{GraphAnswerer, GraphAskFailure, GraphAskResult, GraphDecision, read_question};
use crate::llm::decision::DecisionAnswer;
use crate::{EntityId, Error, Vault, WriteActor};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A skill pins the definition, including its outcome binding and decision dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQuestionRef {
    #[serde(with = "super::super::codec::entity")]
    pub id: EntityId,
    pub version: u32,
}

/// The unit and the exact sources selected by the resident's recipe. Sources
/// are required: a missing contact, variant or signal means abstain, not no.
/// The same unit may occur with different evidence (for example, variants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQuestionInput {
    #[serde(with = "super::super::codec::entity")]
    pub unit: EntityId,
    #[serde(with = "super::super::codec::entities")]
    pub evidence: Vec<EntityId>,
}

/// Run saved graph questions using explicit joins instead of the default
/// outgoing-neighbor recipe. Every answer stays a proposal and is registered
/// with the existing outcome projector. The callback uses the same answerer
/// seam as a one-off graph ask; it does not acquire any extra authority.
/// Missing required sources abstain without exposing their bodies. Earlier
/// commits remain in `GraphAskFailure::completed` if later work fails.
#[expect(
    clippy::too_many_arguments,
    reason = "the host supplies its existing principal, actor, answerer and clock"
)]
pub fn run_graph_question(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    reference: GraphQuestionRef,
    inputs: &[GraphQuestionInput],
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> std::result::Result<GraphAskResult, GraphAskFailure> {
    run_graph_question_with_proposals(
        vault,
        principal,
        actor,
        reference,
        inputs,
        &[],
        answerer,
        now,
    )
}

/// Prior proposals come only from the workflow runner's completed stages.
pub(crate) fn run_graph_question_with_proposals(
    vault: &Vault,
    principal: EntityId,
    actor: WriteActor,
    reference: GraphQuestionRef,
    inputs: &[GraphQuestionInput],
    proposals: &[super::AnswerRecord],
    answerer: &mut impl GraphAnswerer,
    now: u64,
) -> std::result::Result<GraphAskResult, GraphAskFailure> {
    let validate = || -> crate::Result<()> {
        let record = read_question(vault, principal, reference.id, Some(reference.version))?
            .ok_or(Error::EntityNotFound)?;
        if record.definition.adapter != "graph" || inputs.len() > 4096 {
            return Err(Error::InvalidConfig("invalid graph question recipe".into()));
        }
        for input in inputs {
            if !record.definition.units.contains(&input.unit)
                || input.evidence.len() > 4096
                || input.evidence.contains(&input.unit)
                || input.evidence.iter().collect::<HashSet<_>>().len() != input.evidence.len()
            {
                return Err(Error::InvalidConfig(
                    "invalid graph question sources".into(),
                ));
            }
        }
        Ok(())
    };
    validate().map_err(GraphAskFailure::before_units)?;
    let mut completed = GraphAskResult {
        answers: Vec::new(),
        abstained: Vec::new(),
    };
    for input in inputs {
        let answer = (|| -> crate::Result<Option<super::AnswerRecord>> {
            let prepared = super::standing::prepare_graph_answer(
                vault, principal, reference, actor, input, proposals,
            );
            let (record, context, frontier) = match prepared {
                Ok(prepared) => prepared,
                Err(Error::EntityNotFound) => return Ok(None),
                Err(error) => return Err(error),
            };
            let question = &record.definition.question;
            let images = if answerer.reads_images() {
                let lane = vault.scoped_read(super::graph_ask::asker_reader(vault, principal)?);
                super::graph_ask::unit_images(&lane, &context)?
            } else {
                Vec::new()
            };
            let audio = if answerer.reads_audio() {
                let lane = vault.scoped_read(super::graph_ask::asker_reader(vault, principal)?);
                super::graph_ask::unit_audio(&lane, &context)?
            } else {
                Vec::new()
            };
            match answerer.decide(question, &context, &images, &audio)? {
                None => Ok(None),
                Some(GraphDecision::Prediction(prediction)) => {
                    if prediction.answer == DecisionAnswer::Abstain {
                        return Ok(None);
                    }
                    super::graph_ask::validate_prediction(question, &prediction)?;
                    super::standing::backfill_graph_answer(
                        vault, principal, reference, actor, context, frontier, prediction,
                        proposals, now,
                    )
                    .map(Some)
                }
                Some(GraphDecision::Decision(decision)) => {
                    super::graph_ask::validate_decision(question, principal, &decision)?;
                    if decision.answer == DecisionAnswer::Abstain {
                        return Ok(None);
                    }
                    super::standing::backfill_graph_decision(
                        vault, principal, reference, actor, context, frontier, &images,
                        &audio, *decision, proposals, now,
                    )
                    .map(Some)
                }
            }
        })();
        match answer {
            Ok(Some(answer)) => completed.answers.push(answer),
            Ok(None) => completed.abstained.push(input.unit),
            Err(error) => {
                return Err(GraphAskFailure {
                    failed_unit: Some(input.unit),
                    error: Box::new(error),
                    completed,
                });
            }
        }
    }
    Ok(completed)
}
