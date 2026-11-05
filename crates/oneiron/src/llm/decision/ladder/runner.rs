//! Decision ladder runner.
//! Entry: DecisionLadder.
//! Definitions: types stay in the parent; this module owns the listed impls.

use super::{
    DecisionLadder, DecisionPack, OpenPack, Read, Readings, Route, ask, price_answers, take, takes,
    validate_pin, validate_state,
};
use crate::llm::decision::policy::{DecisionBandPolicy, Reversibility};
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion,
    DecisionRung, StopCause, TypedDecision,
};
use crate::llm::run_admission::RunAdmission;
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

    /// [`Self::run`] metered on the caller's run (FIX 10443): every provider that
    /// spends admits on `run`, sourced with the call's evidence, instead of a run of
    /// its own. Dial, bands, policy, principal, evidence, state, wording and receipts
    /// are [`Self::run`]'s own.
    #[expect(
        clippy::too_many_arguments,
        reason = "the caller's run joins run's state, clock, question, scope, dial and policy"
    )]
    pub fn run_with_run(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
        run: &RunAdmission,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack_media_with_run(
            &[question],
            principal,
            evidence,
            &[],
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
            run,
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
    /// rung in span that serves the pack reads them in one request (several in turn past
    /// the policy's questions-per-call row), stepping past a rung with no provider or one
    /// that cannot take them, with the person question ("ask a person?")
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
        let mut pack = self.open(
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
            // An empty rung is skipped, not a refusal: the first rung in span that serves
            // the pack reads every chunk (FIX 12278).
            let serving = self
                .first_serving(dial.first, dial.ceiling, questions, images, audio)
                .ok_or_else(|| invalid("decision provider unavailable"))?;
            pack.dial.first = serving;
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
                    run: None,
                };
                first.extend(
                    self.read(serving, &call, pack.person, readings)?
                        .into_iter()
                        .map(Some),
                );
            }
        }
        self.close(&pack, first, readings)
    }

    /// [`Self::run_pack_media`] metered on the caller's run (FIX 10443): the terminal
    /// run-scoped entry; [`Self::run_with_run`] is its one-question form. Routing,
    /// dial, bands, policy, wording, receipts and journal are [`Self::run_pack_media`]'s
    /// own; only provider metering moves onto `run`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the caller's run joins run_pack_media's media, state, clock, questions, scope, dial and policy"
    )]
    pub fn run_pack_media_with_run(
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
        run: &RunAdmission,
    ) -> Result<Vec<TypedDecision>> {
        let mut pack = self.open(
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
            // An empty rung is skipped, not a refusal: the first rung in span that serves
            // the pack reads every chunk (FIX 12278).
            let serving = self
                .first_serving(dial.first, dial.ceiling, questions, images, audio)
                .ok_or_else(|| invalid("decision provider unavailable"))?;
            pack.dial.first = serving;
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
                    run: Some(run),
                };
                first.extend(
                    self.read(serving, &call, pack.person, readings)?
                        .into_iter()
                        .map(Some),
                );
            }
        }
        self.close_with_run(&pack, first, readings, run)
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
                self.route(&route, first, readings, None)
            })
            .collect()
    }

    /// [`Self::close`] metered on the caller's run (FIX 10443): each step-up read admits
    /// on `run`.
    pub(in crate::llm::decision) fn close_with_run(
        &self,
        pack: &OpenPack<'_>,
        first: Vec<Option<Read>>,
        readings: Vec<Readings>,
        run: &RunAdmission,
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
                self.route(&route, first, readings, Some(run))
            })
            .collect()
    }

    /// One provider request on the call's clock, one read per pack question. The first read
    /// steps past a rung with no provider, or one that cannot take the pack, onto the first
    /// rung in span that serves it, and a step-up only reads an admitted rung, so no caller
    /// reaches here empty or unable to take a question; the checks below stay as defense
    /// and fail even with no time left. A failure with time left still fails the call.
    pub(super) fn read(
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
                .map(|_| Read::NotStarted(StopCause::Deadline))
                .collect());
        }
        // A choice wider than the provider's option bound is read in chunks (FIX 11235).
        let reads = if pack
            .questions
            .iter()
            .all(|question| provider.capability().takes(question))
        {
            take(&pin, pack, ask(provider, pack, person), readings)?
        } else {
            super::tournament::read_pack(provider, &pin, pack, person, readings)?
        };
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
