//! The table's arms for the question readers: a graph answer, a standing
//! answer's pinned sources and a refresh's claim unit.

use super::*;
use crate::llm::decision::questions::{
    AnswerProposal, GraphAnswerer, GraphPrediction, GraphUnitContext, RefreshTrigger,
    StandingAnswer, backfill_standing_answer, refresh_question, run_graph_ask,
    standing_source_frontier,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionClass, DecisionQuestion, DecisionRung, ProviderPin,
};

/// The principal and subject land through the entity door and the principal
/// may read, as a host sets up a question.
fn question_readers(vault: &Vault, principal: EntityId, subject: EntityId) -> Result<WriteActor> {
    for id in [principal, subject] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange { start: 1, end: 1 },
            1,
            b"source",
        )?;
    }
    crate::test_util::authorize_readers(vault, &[&principal.to_hex()]);
    Ok(WriteActor::new(principal, EdgeActorClass::Human))
}

fn provider() -> ProviderPin {
    ProviderPin {
        rung: DecisionRung::Rule,
        model: "fixture".into(),
        version: "one".into(),
    }
}

/// Answers yes to every unit and keeps each context it was shown.
#[derive(Default)]
struct Answerer {
    contexts: Vec<GraphUnitContext>,
}

impl GraphAnswerer for Answerer {
    fn answer(
        &mut self,
        _question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        self.contexts.push(context.clone());
        Ok(Some(GraphPrediction {
            answer: DecisionAnswer::Choice("yes".into()),
            probability: 0.8,
            provider: provider(),
            cost_per_thousand: 0.25,
        }))
    }
}

fn graph_question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 1,
        text: "Is the evidence relevant?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Choice {
            options: vec!["yes".into(), "no".into()],
        },
        accept_type: false,
    }
}

/// A held claim is no unit to answer and no neighbour to draw from; a settled
/// neighbour still is, and the answer still commits.
pub(super) fn graph_answer(
    vault: &Vault,
    [principal, subject, claim, control]: [EntityId; 4],
    reader: ConsolidationReader,
) -> Result<()> {
    let actor = question_readers(vault, principal, subject)?;
    let ask = |v: &Vault, units: &[EntityId], answerer: &mut Answerer| {
        run_graph_ask(v, principal, actor, graph_question(), units, answerer, 10)
            .map_err(|failure| *failure.error)
    };
    check_transition(vault, claim, reader, |v, id| {
        let mut answerer = Answerer::default();
        let answered = ask(v, &[*id], &mut answerer)?
            .answers
            .iter()
            .any(|answer| answer.unit == *id);
        assert_eq!(
            answered,
            !answerer.contexts.is_empty(),
            "{reader:?}: a held unit reached the answerer"
        );
        Ok(answered)
    })?;
    vault.put_edge(&subject, EdgeKind::Mentions, &claim, 0.8)?;
    vault.put_edge(&subject, EdgeKind::Mentions, &control, 0.8)?;
    check_transition(vault, claim, reader, |v, id| {
        let mut answerer = Answerer::default();
        let result = ask(v, &[subject], &mut answerer)?;
        assert_eq!(
            result.answers.len(),
            1,
            "{reader:?}: the answer did not commit"
        );
        let [context] = answerer.contexts.as_slice() else {
            panic!("{reader:?}: one context, found {}", answerer.contexts.len());
        };
        assert!(
            context.sources.iter().any(|source| source.id == control),
            "{reader:?}: settled neighbour missing"
        );
        Ok(context.sources.iter().any(|source| source.id == *id))
    })
}

/// A standing answer pinned to a held claim does not land; once the owner
/// answers, the same pin admits it.
pub(super) fn standing_answer_source(
    vault: &Vault,
    [principal, subject, claim]: [EntityId; 3],
    reader: ConsolidationReader,
) -> Result<()> {
    let actor = question_readers(vault, principal, subject)?;
    let question = fixture_question(vault, principal, vec![subject], None)?;
    let pin = standing_source_frontier(vault, principal, question, 1, actor, subject, &[claim])?;
    check_transition(vault, claim, reader, |v, id| {
        let answer = StandingAnswer {
            unit: subject,
            answer: DecisionAnswer::Noul(true),
            probability: Some(0.9),
            evidence: vec![*id],
            providers: vec![provider()],
            source_frontier: pin,
        };
        match backfill_standing_answer(v, principal, question, 1, actor, answer, 10) {
            Ok(record) => {
                assert_eq!(record.unit, subject, "{reader:?}: reader output");
                Ok(true)
            }
            Err(Error::EntityNotFound) => Ok(false),
            Err(error) => Err(error),
        }
    })
}

/// A refresh answers no held claim unit, and never shows it to the answerer.
pub(super) fn question_refresh_source(
    vault: &Vault,
    [principal, subject, claim]: [EntityId; 3],
    reader: ConsolidationReader,
) -> Result<()> {
    let actor = question_readers(vault, principal, subject)?;
    let question = fixture_question(vault, principal, vec![claim], None)?;
    check_transition(vault, claim, reader, |v, id| {
        let mut asked = 0;
        let answers = refresh_question(
            v,
            actor,
            principal,
            question,
            RefreshTrigger::Manual,
            1,
            |_, _, _| {
                asked += 1;
                Ok(AnswerProposal {
                    answer: DecisionAnswer::Noul(true),
                    probability: Some(0.8),
                    providers: vec![provider()],
                })
            },
        )?;
        let answered = answers.iter().any(|answer| answer.unit == *id);
        assert_eq!(
            answered,
            asked > 0,
            "{reader:?}: a held unit reached the answerer"
        );
        Ok(answered)
    })
}
