//! One unit's answer from a graph answerer (FIX 8914, pure moves from `refresh.rs`).

use super::super::graph_ask::{self, GraphAnswerer, GraphDecision};
use super::super::reader_authority::question_lane;
use super::super::records::{AnswerProposal, QuestionRecord};
use super::{Answered, Proposed};
use crate::claim::ClaimSubject;
use crate::{ClaimCandidate, EntityId, Result, Vault};

/// One unit's answer from a graph answerer, read under `record`'s principal:
/// the unit and its eligible neighbours, as a one-off graph ask reads them,
/// a neighbour no one answer can rest on beside the unit named as omitted.
/// A unit no one answer can stay inside abstains before any model runs, as
/// the answer would read wider than a source it rests on. With `evidence`
/// (a backfill join, FIX 2383) the unit is shown those sources instead of
/// its neighbours, and abstains when one is out of reach.
pub(super) fn graph_proposal(
    vault: &Vault,
    record: &QuestionRecord,
    answerer: &mut impl GraphAnswerer,
    unit: EntityId,
    kind: u8,
    body: &[u8],
    evidence: Option<&[EntityId]>,
) -> Result<Option<Answered>> {
    let lane = question_lane(vault, graph_ask::asker_reader(vault, record.principal)?);
    let context = match evidence {
        Some(evidence) => graph_ask::recipe_context(&lane, unit, kind, body.to_vec(), evidence)?,
        None => graph_ask::unit_context(&lane, unit, kind, body.to_vec())?,
    };
    let Some(context) = context else {
        return Ok(None);
    };
    {
        let txn = vault.store.env.read_txn()?;
        let Some(rows) = graph_ask::sources_unchanged_in_txn(&lane, &txn, &context)? else {
            return Ok(None);
        };
        let mut probe = ClaimCandidate::new(
            "judgment.answer",
            ClaimSubject::Entity(unit),
            rmpv::Value::Nil,
            1.0,
        );
        if super::super::standing::constrain_sources(&mut probe, &rows, record.principal).is_err() {
            return Ok(None);
        }
    }
    let images = if answerer.reads_images() && record.definition.media.images {
        graph_ask::unit_images(&lane, &context)?
    } else {
        Vec::new()
    };
    let audio = if answerer.reads_audio() && record.definition.media.audio {
        graph_ask::unit_audio(&lane, &context)?
    } else {
        Vec::new()
    };
    let question = &record.definition.question;
    let proposal = match answerer.decide(question, &context, &images, &audio)? {
        None => None,
        Some(GraphDecision::Prediction(prediction)) => {
            graph_ask::validate_prediction(question, &prediction)?;
            let paired = prediction
                .paired
                .map(|reading| reading.bind(prediction.provider.clone()))
                .into_iter()
                .collect();
            Some(Proposed::Proposal(AnswerProposal {
                answer: prediction.answer,
                probability: Some(prediction.probability),
                providers: vec![prediction.provider],
                paired,
                rule: prediction.rule,
            }))
        }
        Some(GraphDecision::Decision(decision)) => {
            graph_ask::validate_decision(question, record.principal, &decision)?;
            Some(Proposed::Decision(Box::new(graph_ask::decided(
                &context, &images, &audio, *decision,
            ))))
        }
    };
    Ok(proposal.map(|proposal| Answered {
        proposal,
        context: Some(context),
    }))
}
