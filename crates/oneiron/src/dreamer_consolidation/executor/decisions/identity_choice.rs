//! The one final identity choice (FIX 8693). A pack asks which listed id a
//! candidate names in groups: one choice per option group of at most
//! `IDS_PER_QUESTION` ids, and per state page when the pack is paged. Each
//! group's answer reads under its own provider's calibration, so no group's
//! probability is ranked against another's. The ids the groups named are the
//! shortlist: none names none; one is the answer, as a single question's is;
//! two or more get one final typed choice over exactly those ids, its state
//! carrying each of them whole, and its answer is the pack's. Past
//! `IDS_PER_QUESTION` shortlisted ids that round asks in groups again, each
//! naming at most one, until one choice is left. A final choice that abstains
//! or names no shortlisted id keeps the pick a pack made before it had one:
//! the shortlisted id its groups read most probable, so a pack that resolved
//! still resolves.

use super::{NONE, id_options};
use crate::dreamer_consolidation::call_labels::CallLabelMap;
use crate::dreamer_consolidation::executor::ConsolidationExecutor;
use crate::dreamer_consolidation::provenance::KeptDecision;
use crate::dreamer_consolidation::resources::BranchResources;
use crate::dreamer_consolidation::settle::decision_pages::measure_state;
use crate::dreamer_consolidation::step_charge::StepChargeTally;
use crate::dreamer_wake::WakePassDeadline;
use crate::entity_id::EntityId;
use crate::llm::decision::catalogue::QuestionFamily;
use crate::llm::decision::{AnswerContract, AskTo, DecisionAnswer, DecisionQuestion};
use crate::llm::{DurableStepContext, DurableStepResult};

/// The ids `decisions` name, in order and each once: every read choice
/// answer that is an id, never [`NONE`]. A probability only says the answer
/// was read, as before; no decision's probability ranks them.
fn named_ids(decisions: &[KeptDecision]) -> Vec<EntityId> {
    let mut named = Vec::new();
    for decision in decisions {
        if let Some(DecisionAnswer::Choice(label)) = decision.answer()
            && decision.probability().is_some()
            && label != NONE
            && let Ok(id) = EntityId::from_hex(label)
            && !named.contains(&id)
        {
            named.push(id);
        }
    }
    named
}

/// The shortlisted id `groups` read most probable: the pick a pack made
/// before it asked a final choice.
fn most_probable(groups: &[KeptDecision]) -> Option<EntityId> {
    groups
        .iter()
        .filter_map(
            |decision| match (decision.answer(), decision.probability()) {
                (Some(DecisionAnswer::Choice(label)), Some(probability)) if label != NONE => {
                    EntityId::from_hex(label).ok().map(|id| (id, probability))
                }
                _ => None,
            },
        )
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(id, _)| id)
}

/// How a final identity choice is asked: its question family, the key parts
/// its questions extend, the host's wording, and whether [`NONE`] answers it.
pub(in crate::dreamer_consolidation::executor) struct FinalChoice<'a> {
    pub(in crate::dreamer_consolidation::executor) family: &'a QuestionFamily,
    pub(in crate::dreamer_consolidation::executor) key: &'a [&'a [u8]],
    pub(in crate::dreamer_consolidation::executor) wording: &'a str,
    pub(in crate::dreamer_consolidation::executor) none: bool,
}

/// The id a final choice keeps, if any, and its rounds' decisions.
type Chosen = (Option<EntityId>, Vec<KeptDecision>);

impl ConsolidationExecutor<'_> {
    /// The id `groups` choose (the module's rule), with every final round's
    /// decisions, each round read as its pack was: on the pack's step and
    /// pass clock, branch, route `to`, `correlation` and `evidence`. Each
    /// round reads the `state` its caller builds over its shortlisted ids and
    /// questions, each by the label the round's map assigns it. None when the
    /// step trapped.
    #[expect(
        clippy::too_many_arguments,
        reason = "the pack's step, clock, branch, route and evidence join the choice and the charge tally"
    )]
    pub(in crate::dreamer_consolidation::executor) async fn choose_identity(
        &self,
        step_ctx: &DurableStepContext<'_>,
        pass: &WakePassDeadline,
        resources: &BranchResources<'_>,
        to: &AskTo,
        correlation: EntityId,
        evidence: &[EntityId],
        choice: &FinalChoice<'_>,
        groups: &[KeptDecision],
        state: &(
             dyn Fn(&[EntityId], &[DecisionQuestion], &mut CallLabelMap) -> serde_json::Value + Sync
         ),
        charges: &mut StepChargeTally,
    ) -> DurableStepResult<Option<Chosen>> {
        let mut shortlist = named_ids(groups);
        let asked = shortlist.len();
        let mut kept = Vec::new();
        let mut round = 0_usize;
        while shortlist.len() > 1 {
            round += 1;
            let round_key = round.to_string();
            let mut labels = CallLabelMap::default();
            let mut questions = Vec::new();
            for (group, (options, shown)) in id_options(&shortlist, choice.none, &mut labels)
                .into_iter()
                .enumerate()
            {
                let group = group.to_string();
                let mut parts: Vec<&[u8]> = choice.key.to_vec();
                parts.extend([b"final".as_slice(), round_key.as_bytes(), group.as_bytes()]);
                let question = choice.family.question(
                    &parts,
                    choice.wording.to_owned(),
                    AnswerContract::Choice { options },
                )?;
                labels.show_choices(question.id, shown);
                questions.push(question);
            }
            self.label_questions(&mut labels, &questions);
            let read = state(&shortlist, &questions, &mut labels);
            measure_state(step_ctx.vault, &read);
            let Some(decided) = self
                .decide(
                    step_ctx,
                    pass,
                    resources,
                    to,
                    correlation,
                    &questions,
                    evidence,
                    &read,
                    &labels,
                    charges,
                )
                .await?
            else {
                return Ok(None);
            };
            // One question names at most one id, so a round of one is the last.
            let named: Vec<EntityId> = named_ids(&decided)
                .into_iter()
                .filter(|id| shortlist.contains(id))
                .collect();
            kept.extend(decided);
            if named.is_empty() {
                tracing::warn!(
                    target: "oneiron::dreamer",
                    code = "identity_final_unnamed",
                    shortlisted = asked,
                    "a final identity choice named no shortlisted id; the most probable stands"
                );
                return Ok(Some((most_probable(groups), kept)));
            }
            shortlist = named;
        }
        Ok(Some((shortlist.first().copied(), kept)))
    }
}
