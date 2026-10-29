//! Decision ladder runner.
//! Entry: DecisionLadder.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    AskTo, DecisionLadder, DecisionPack, HumanDecisionRequest, OpenPack, Read, Readings, Route,
    abstained, ask, asks_person, millis, price_answers, step_cause, take, takes, validate_pin,
    validate_state,
};
use crate::llm::decision::policy::{DecisionBandPolicy, Reversibility};
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion,
    DecisionReceipt, DecisionRung, DecisionTime, HumanAskReason, Reasoning, ReceiptAsk, StopCause,
    TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde_json::Value;

impl DecisionLadder<'_> {
    /// One typed decision under one clock, `deadline` (an anytime budget, or a raw
    /// deadline): [`Self::run_pack`] with one question.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack(
            &[question],
            principal,
            evidence,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(decisions.remove(0))
    }

    /// [`Self::run`] over images the question reads, as in "where is `mug` in
    /// `camera`?". Only providers that read images take it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's images, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_images(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        self.run_media(
            question,
            principal,
            evidence,
            images,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run`] over the images and audio clips the question reads. Only providers
    /// that read every medium the call carries take it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's media, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_media(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        audio: &[DecisionAudio],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack_media(
            &[question],
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(decisions.remove(0))
    }

    /// Several typed questions over one state, asked as one pack under one clock. The first
    /// permitted rung reads them in one request (several in turn past the policy's
    /// questions-per-call row), with the person question ("ask a person?")
    /// beside them as its own typed question when the dial reaches the person. Then each
    /// answer routes on its own to its own receipt: a stronger rung starts only while work
    /// time is left, and only for a cause: a rung that abstained, or once, for the first
    /// answer, a small margin under an enforced band or a paired reading at its row. A step
    /// skips a rung with no provider, or one that cannot take the question, up to the
    /// ceiling; with none left the call abstains. At a cut a
    /// reversible step takes the answer it holds and an irreversible one abstains and asks;
    /// with no answer, or an answer inside its band, the call abstains. The last quarter of
    /// the time stays the answer's.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        self.run_pack_images(
            questions,
            principal,
            evidence,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run_pack`] over images the questions read. Each image fills the state field
    /// of its name, and each receipt keeps every image's evidence ref and version, never
    /// its pixels. A Box question needs at least one image.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's images, state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack_images(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        self.run_pack_media(
            questions,
            principal,
            evidence,
            images,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run_pack_images`] over audio clips as well. A clip fills the state field of
    /// its name like an image, and each receipt keeps every clip's evidence ref and
    /// version, never its samples.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's media, state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack_media(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        audio: &[DecisionAudio],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        let pack = self.open(
            questions,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        let mut readings = pack.readings();
        let mut first = Vec::with_capacity(questions.len());
        if dial.first == DecisionRung::Human {
            first.extend(questions.iter().map(|_| None));
        } else {
            // Past the questions-per-call row the pack goes as several requests in turn.
            let per_call = policy.questions_per_call();
            for (chunk, readings) in questions
                .chunks(per_call)
                .zip(readings.chunks_mut(per_call))
            {
                let call = DecisionPack {
                    questions: chunk,
                    evidence,
                    images,
                    audio,
                    state,
                    deadline,
                };
                first.extend(
                    self.read(dial.first, &call, pack.person, readings)?
                        .into_iter()
                        .map(Some),
                );
            }
        }
        self.close(&pack, first, readings)
    }

    /// A pack's checked routing inputs, before its first read.
    #[expect(
        clippy::too_many_arguments,
        reason = "the inputs of run_pack_media, checked once for every first read"
    )]
    pub(in crate::llm::decision) fn open<'a>(
        &'a self,
        questions: &'a [&'a DecisionQuestion],
        principal: EntityId,
        evidence: &'a [EntityId],
        images: &'a [DecisionImage],
        audio: &'a [DecisionAudio],
        state: &'a Value,
        dial: DecisionDial,
        policy: &'a DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &'a RetrievalDeadline,
    ) -> Result<OpenPack<'a>> {
        if questions.is_empty() {
            return Err(invalid("invalid decision pack"));
        }
        for (index, question) in questions.iter().enumerate() {
            question.validate()?; // Provenance cannot reach any provider or queue.
            if questions[..index]
                .iter()
                .any(|earlier| earlier.id == question.id)
            {
                return Err(invalid("invalid decision pack"));
            }
        }
        validate_state(state)?;
        DecisionImage::check_call(
            images,
            state,
            questions.iter().any(|question| question.contract.locates()),
        )
        .map_err(|_| invalid("invalid decision images"))?;
        DecisionAudio::check_call(audio, images, state)
            .map_err(|_| invalid("invalid decision audio"))?;
        dial.band.validate()?;
        if dial.first > dial.ceiling {
            return Err(invalid("invalid decision dial"));
        }
        // Only a surface whose dial reaches the person rung routes on a person reading.
        let person_row = policy
            .person_threshold()
            .filter(|_| dial.ceiling == DecisionRung::Human);
        let person = self.person.filter(|_| person_row.is_some());
        if let Some(person) = person {
            person.validate()?;
            if person.contract != AnswerContract::Noul
                || questions.iter().any(|question| question.id == person.id)
            {
                return Err(invalid("invalid person question"));
            }
        }
        if let Some(paired) = self.paired {
            paired.validate()?;
            if paired.contract != AnswerContract::Noul
                || questions.iter().any(|question| question.id == paired.id)
                || person.is_some_and(|person| person.id == paired.id)
            {
                return Err(invalid("invalid paired question"));
            }
        }
        let rows = questions
            .iter()
            .map(|question| policy.resolve(question, reversibility, dial.band))
            .collect::<Result<Vec<_>>>()?;
        Ok(OpenPack {
            questions,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            rows,
            person_row,
            paired: self.paired,
            person,
            policy,
            reversibility,
            deadline,
        })
    }

    /// Each question's routing after its first read, `first` (none when the dial starts at
    /// the person).
    pub(in crate::llm::decision) fn close(
        &self,
        pack: &OpenPack<'_>,
        first: Vec<Option<Read>>,
        readings: Vec<Readings>,
    ) -> Result<Vec<TypedDecision>> {
        pack.questions
            .iter()
            .zip(&pack.rows)
            .zip(first)
            .zip(readings)
            .map(|(((&question, &row), first), readings)| {
                let route = Route {
                    question,
                    principal: pack.principal,
                    evidence: pack.evidence,
                    images: pack.images,
                    audio: pack.audio,
                    state: pack.state,
                    dial: pack.dial,
                    row,
                    person_row: pack.person_row,
                    person: pack.person,
                    policy: pack.policy,
                    reversibility: pack.reversibility,
                    deadline: pack.deadline,
                };
                self.route(&route, first, readings)
            })
            .collect()
    }

    /// One question's routing after the first read, `first` (none when the dial starts at
    /// the person).
    fn route(
        &self,
        call: &Route<'_>,
        first: Option<Read>,
        mut readings: Readings,
    ) -> Result<TypedDecision> {
        let Route {
            question,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            row,
            person_row,
            person,
            policy,
            reversibility,
            deadline,
        } = *call;
        let mut rung = dial.first;
        let mut prior = None;
        // The pin that served `prior`: a later cut rung's pin joins the receipt
        // (FIX 9907) but never speaks for an answer it did not give. Its cost goes with it.
        let mut prior_pin = None;
        let mut prior_cost = None;
        let mut answered = None;
        let mut in_band = false;
        let mut needs_person = false;
        let mut unavailable = false;
        let mut stop = StopCause::Done;
        let mut reasoning = Reasoning::NotNeeded;
        // Whether the first answer has been weighed for the one step up, and the cause of
        // the read in hand when it is that step.
        let mut weighed = false;
        let mut stepping = None;
        let mut next_read = first;
        // The think row routes only on a paired reading, so it applies only beside one.
        let think_row = policy.think_threshold().filter(|_| self.paired.is_some());
        while let Some(read) = next_read.take() {
            let answer = match read {
                Read::Answer(answer) => answer,
                Read::NotStarted => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Skipped(cause);
                    }
                    break;
                }
                Read::Cut => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Cut(cause);
                    }
                    break;
                }
            };
            if let Some(cause) = stepping.take() {
                reasoning = Reasoning::Ran(cause);
            }
            answered = Some(rung);
            needs_person = asks_person(&answer, person_row);
            // A rung that abstains answered nothing, so the question goes on to the next
            // rung that can take it (ARCH-0076 #fit-ask: rules first, then the local head,
            // ending at the next authorised role). The first answer may step up once more.
            let passes = answer.answer == DecisionAnswer::Abstain;
            let cause = if passes || weighed {
                None
            } else {
                weighed = true;
                in_band = answer.probability.is_some_and(|p| row.band.contains(p));
                step_cause(&answer, in_band, row.mode, think_row)
            };
            prior = Some(answer);
            prior_pin = readings.pins.last().cloned();
            prior_cost = readings.cost;
            if needs_person {
                rung = DecisionRung::Human;
                break;
            }
            if (!passes && cause.is_none()) || rung >= dial.ceiling {
                break;
            }
            // A stronger rung, the person's included, starts only while work time is left.
            match self.next_available(rung, dial.ceiling, question, images, audio) {
                None => {
                    unavailable = true;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(_) if !deadline.decision_may_start() => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(DecisionRung::Human) => rung = DecisionRung::Human,
                Some(next) => {
                    let questions = [question];
                    let pack = DecisionPack {
                        questions: &questions,
                        evidence,
                        images,
                        audio,
                        state,
                        deadline,
                    };
                    next_read = Some(
                        self.read(next, &pack, person, std::slice::from_mut(&mut readings))?
                            .remove(0),
                    );
                    rung = next;
                    stepping = cause;
                }
            }
        }
        // At a cut an irreversible step never takes an unfinished answer, and no step
        // takes an answer the call does not have, or one inside its band, enforced or
        // in shadow (packet rule 5: an in-band answer is not eligible).
        let abstains_at_cut = stop == StopCause::Deadline
            && (prior
                .as_ref()
                .is_none_or(|prior| prior.answer == DecisionAnswer::Abstain)
                || reversibility == Reversibility::OutboundEffect
                || in_band);
        if abstains_at_cut && dial.ceiling == DecisionRung::Human {
            rung = DecisionRung::Human;
        }
        let mut human_ask = None;
        let mut asked = None;
        let outcome = if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if needs_person {
                HumanAskReason::NeedsPerson
            } else if abstains_at_cut {
                HumanAskReason::Deadline
            } else if prior.is_some() {
                HumanAskReason::Uncertain
            } else {
                HumanAskReason::OwnerSelected
            };
            let to = self.ask_to.cloned().unwrap_or_else(AskTo::owner);
            // The ask carries the state the reads weighed (FIX 2424), and its receipt
            // names the role it went to (ARCH-0076, "Who answered").
            let seq = self.human.queue_with_state(
                HumanDecisionRequest {
                    question: question.clone(),
                    principal,
                    evidence: evidence.to_vec(),
                    reason,
                    // The prior is the last provider read's answer, from the pin that
                    // served it.
                    prior_provider: prior.as_ref().and(prior_pin.clone()),
                    prior,
                    queue_pin: self.human_pin.clone(),
                    to: to.clone(),
                    correlation: self.correlation,
                },
                state,
            )?;
            asked = Some(ReceiptAsk::queued(&to, seq));
            readings.pins.push(self.human_pin.clone());
            human_ask = Some(reason);
            abstained()
        } else if abstains_at_cut {
            human_ask = Some(HumanAskReason::Deadline);
            abstained()
        } else if unavailable {
            // No rung up to the ceiling can take the step: a typed abstention.
            human_ask = Some(HumanAskReason::ProviderUnavailable);
            abstained()
        } else {
            prior.expect("a non-human rung has an answer")
        };
        // A rung that abstained answered nothing.
        let answered = answered.filter(|_| outcome.answer != DecisionAnswer::Abstain);
        let evidence_versions = images
            .iter()
            .map(|image| image.evidence.clone())
            .chain(audio.iter().map(|clip| clip.evidence.clone()))
            .collect();
        Ok(TypedDecision {
            answer: outcome.answer,
            probability: outcome.probability,
            evidence: evidence.to_vec(),
            in_band,
            human_ask,
            receipt: DecisionReceipt {
                question: question.id,
                question_version: question.version,
                principal,
                providers: readings.pins,
                band: row.band,
                band_version: row.version,
                evidence_versions,
                // The cost its answering provider knows, at the rung that answered.
                cost_per_thousand: prior_cost.filter(|_| answered.is_some()),
                paired: readings.paired,
                person: readings.person,
                time: Some(DecisionTime {
                    budget_ms: millis(deadline.budget()),
                    used_ms: millis(deadline.used()),
                    stop,
                    answered,
                    reasoning,
                }),
                images: readings.images,
                think_row: think_row.map(|row| row.version),
                person_row: person_row.map(|row| row.version),
                rule: readings
                    .rule
                    .filter(|_| answered == Some(DecisionRung::Rule)),
                asked,
            },
        })
    }

    /// One provider request on the call's clock, one read per pack question. Routing skips
    /// an empty slot, so only the dial's own first rung reaches here empty or unable to take
    /// a question, and it fails even with no time left. A failure with time left still
    /// fails the call.
    fn read(
        &self,
        rung: DecisionRung,
        pack: &DecisionPack<'_>,
        person: Option<&DecisionQuestion>,
        readings: &mut [Readings],
    ) -> Result<Vec<Read>> {
        let provider = self
            .slot(rung)
            .ok_or_else(|| invalid("decision provider unavailable"))?;
        let pin = provider.pin();
        validate_pin(&pin, rung)?;
        if !pack
            .questions
            .iter()
            .all(|question| takes(provider, question, pack.images, pack.audio))
        {
            return Err(invalid("decision provider cannot take the question"));
        }
        if !pack.deadline.decision_may_start() {
            return Ok((0..pack.questions.len())
                .map(|_| Read::NotStarted)
                .collect());
        }
        let reads = take(&pin, pack, ask(provider, pack, person), readings)?;
        // Each answer's receipt carries what its provider knows it costs.
        price_answers(&reads, readings, provider.cost_per_thousand());
        // A rule row that answered is named on its question's receipt.
        if rung == DecisionRung::Rule {
            for (index, (read, readings)) in reads.iter().zip(readings.iter_mut()).enumerate() {
                if let (Read::Answer(answer), Some(call)) = (read, pack.call(index))
                    && answer.answer != DecisionAnswer::Abstain
                {
                    readings.rule = provider.rule_row(&call, answer);
                }
            }
        }
        // Each measurement that answered pins what it was sent of every image.
        if !pack.images.is_empty() {
            let edge = provider.image_edge();
            for (read, readings) in reads.iter().zip(readings.iter_mut()) {
                if !matches!(read, Read::Answer(_)) {
                    continue;
                }
                for image in pack.images {
                    if readings
                        .images
                        .iter()
                        .any(|row| row.provider == pin && row.name == image.name)
                    {
                        continue;
                    }
                    let row = image
                        .pin(pin.clone(), edge)
                        .map_err(|_| invalid("invalid decision images"))?;
                    readings.images.push(row);
                }
            }
        }
        Ok(reads)
    }
}
