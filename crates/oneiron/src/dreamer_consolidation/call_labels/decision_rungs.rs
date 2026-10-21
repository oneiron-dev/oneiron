//! The host ladder's model rungs through one call's labels (FIX 7506 P2).
//! A Dreamer decision pack past its generated first read, and a parked
//! conflict's settlement ask, go up to the host's own rungs: each sees a
//! choice's options as the call's map shows them, and its answer reads back
//! as the canonical option at the same index. The rule rung answers from
//! canonical rows and is never wrapped; questions, options, answers and
//! receipts stay canonical.

use crate::Result;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionCall, DecisionLadder, DecisionPack, DecisionProvider,
    DecisionQuestion, DecisionWireLabels, HostRuleRef, ProviderCapability, ProviderDecision,
    ProviderPin,
};

/// One model rung through a call's labels.
struct Shown<'a> {
    rung: &'a dyn DecisionProvider,
    labels: &'a dyn DecisionWireLabels,
}

/// A ladder's model rungs (local, System One, escalation and big), each
/// through one call's labels.
pub(in crate::dreamer_consolidation) struct LabelledRungs<'a> {
    local: Option<Shown<'a>>,
    system_one: Option<Shown<'a>>,
    escalation: Option<Shown<'a>>,
    big: Option<Shown<'a>>,
}

impl<'a> LabelledRungs<'a> {
    /// `ladder`'s model rungs through `labels`.
    pub(in crate::dreamer_consolidation) fn of(
        ladder: &DecisionLadder<'a>,
        labels: &'a dyn DecisionWireLabels,
    ) -> Self {
        let shown =
            |rung: Option<&'a dyn DecisionProvider>| rung.map(|rung| Shown { rung, labels });
        Self {
            local: shown(ladder.local),
            system_one: shown(ladder.system_one),
            escalation: shown(ladder.escalation),
            big: shown(ladder.big),
        }
    }

    /// `ladder` with these rungs in its model slots; its rule rung, person
    /// queue, questions, route and correlation as they are.
    pub(in crate::dreamer_consolidation) fn ladder(
        &'a self,
        ladder: &DecisionLadder<'a>,
    ) -> DecisionLadder<'a> {
        let slot = |shown: &'a Option<Shown<'a>>| {
            shown
                .as_ref()
                .map(|shown| shown as &'a dyn DecisionProvider)
        };
        DecisionLadder {
            rule: ladder.rule,
            local: slot(&self.local),
            system_one: slot(&self.system_one),
            escalation: slot(&self.escalation),
            big: slot(&self.big),
            human: ladder.human,
            human_pin: ladder.human_pin.clone(),
            ask_to: ladder.ask_to,
            paired: ladder.paired,
            person: ladder.person,
            presence: ladder.presence,
            correlation: ladder.correlation,
        }
    }
}

impl Shown<'_> {
    /// `question` as this call shows it, when the call shows any of its
    /// options otherwise.
    fn shown(&self, question: &DecisionQuestion) -> Option<DecisionQuestion> {
        let AnswerContract::Choice { options } = &question.contract else {
            return None;
        };
        let shown: Vec<String> = options
            .iter()
            .enumerate()
            .map(|(index, option)| {
                self.labels
                    .choice_option(question.id, index, option)
                    .unwrap_or_else(|| option.clone())
            })
            .collect();
        (shown != *options).then(|| DecisionQuestion {
            contract: AnswerContract::Choice { options: shown },
            ..question.clone()
        })
    }
}

/// `decision` as `question` answers it: an option `shown` showed reads back
/// as `question`'s option at the same index. Any other answer is as the rung
/// gave it, for the ladder to check against `question` as it does today.
fn canonical(
    question: &DecisionQuestion,
    shown: &DecisionQuestion,
    mut decision: ProviderDecision,
) -> ProviderDecision {
    let (AnswerContract::Choice { options }, AnswerContract::Choice { options: wire }) =
        (&question.contract, &shown.contract)
    else {
        return decision;
    };
    let option = match &decision.answer {
        DecisionAnswer::Choice(label) => wire
            .iter()
            .position(|text| text == label)
            .and_then(|index| options.get(index)),
        _ => None,
    };
    if let Some(option) = option {
        decision.answer = DecisionAnswer::Choice(option.clone());
    }
    decision
}

impl DecisionProvider for Shown<'_> {
    fn pin(&self) -> ProviderPin {
        self.rung.pin()
    }

    fn capability(&self) -> ProviderCapability {
        self.rung.capability()
    }

    fn reads_images(&self) -> bool {
        self.rung.reads_images()
    }

    fn image_edge(&self) -> Option<u32> {
        self.rung.image_edge()
    }

    fn reads_audio(&self) -> bool {
        self.rung.reads_audio()
    }

    fn leaves_host(&self) -> bool {
        self.rung.leaves_host()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let Some(shown) = self.shown(call.question) else {
            return self.rung.decide(call);
        };
        let decision = self.rung.decide(&DecisionCall {
            question: &shown,
            ..*call
        })?;
        Ok(canonical(call.question, &shown, decision))
    }

    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        let shown: Vec<Option<DecisionQuestion>> = pack
            .questions
            .iter()
            .map(|question| self.shown(question))
            .collect();
        if shown.iter().all(Option::is_none) {
            return self.rung.decide_pack(pack);
        }
        let questions: Vec<&DecisionQuestion> = pack
            .questions
            .iter()
            .zip(&shown)
            .map(|(question, shown)| shown.as_ref().unwrap_or(*question))
            .collect();
        let decisions = self.rung.decide_pack(&DecisionPack {
            questions: &questions,
            ..*pack
        })?;
        Ok(decisions
            .into_iter()
            .enumerate()
            .map(
                |(index, decision)| match (pack.questions.get(index), questions.get(index)) {
                    (Some(question), Some(shown)) => canonical(question, shown, decision),
                    _ => decision,
                },
            )
            .collect())
    }

    fn rule_row(
        &self,
        call: &DecisionCall<'_>,
        decision: &ProviderDecision,
    ) -> Option<HostRuleRef> {
        self.rung.rule_row(call, decision)
    }
}
