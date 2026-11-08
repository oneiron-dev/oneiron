//! The run's existing ladder configured from each immutable saved question.

use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphDecision, GraphPrediction, GraphUnitContext, QuestionCriteria,
    QuestionRecord, question_call_budget,
};
use oneiron::llm::decision::{DecisionAudio, DecisionImage, DecisionQuestion, DecisionRung};
use oneiron::{Error, HostingPrivacyPosture, Result, WriteActor};

use crate::decision_graph::LadderGraphAnswerer;
use crate::server::SyncServer;

/// The host ladder answering each saved workflow question under that
/// question's own stored dial, clock, criteria and posture, with explicit
/// caller options. Privacy always keeps the stricter posture.
pub(super) struct SavedGraphAnswerer<'s> {
    server: &'s SyncServer,
    actor: WriteActor,
    ceiling: Option<DecisionRung>,
    explicit_ms: Option<u64>,
    posture: Option<HostingPrivacyPosture>,
    criteria: Option<QuestionCriteria>,
    active: Option<LadderGraphAnswerer<'s>>,
}

impl<'s> SavedGraphAnswerer<'s> {
    /// The run's optional overrides; each prepare clones from them, so they
    /// stay immutable across stages.
    pub(super) fn new(
        server: &'s SyncServer,
        actor: WriteActor,
        ceiling: Option<DecisionRung>,
        explicit_ms: Option<u64>,
        posture: Option<HostingPrivacyPosture>,
        criteria: Option<QuestionCriteria>,
    ) -> Self {
        Self {
            server,
            actor,
            ceiling,
            explicit_ms,
            posture,
            criteria,
            active: None,
        }
    }

    /// The prepared ladder, or the caller's bug: the recipe always
    /// prepares each input's question before its media or decision call.
    fn prepared(&mut self) -> Result<&mut LadderGraphAnswerer<'s>> {
        self.active.as_mut().ok_or(Error::InvariantViolation(
            "a saved graph answer needs its prepared question",
        ))
    }
}

impl GraphAnswerer for SavedGraphAnswerer<'_> {
    /// A fresh ladder from the actual stored definition: its exact dial
    /// with only the ceiling narrowed, its own clock unless the run names
    /// one, its own criteria unless the run names some, and the stricter
    /// meet of the saved, request and vault postures.
    fn prepare_saved_question(&mut self, record: &QuestionRecord) -> Result<()> {
        let definition = &record.definition;
        let mut dial = definition.dial;
        if let Some(cap) = self.ceiling {
            dial.ceiling = dial.ceiling.min(cap);
        }
        let budget = match self.explicit_ms {
            Some(ms) => question_call_budget(self.server.vault(), Some(ms))?,
            None => definition.deadline(self.server.vault())?,
        };
        let criteria = self
            .criteria
            .clone()
            .unwrap_or_else(|| definition.criteria.clone());
        self.active = Some(
            LadderGraphAnswerer::new(self.server, self.actor, dial, budget, None)?
                .with_posture(definition.posture)
                .with_posture_ceiling(self.posture)
                .with_criteria(criteria),
        );
        Ok(())
    }

    fn saved_criteria_override(&self) -> Option<&QuestionCriteria> {
        self.criteria.as_ref()
    }

    fn answer(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        self.prepared()?.answer(question, context)
    }

    fn reads_images(&self) -> bool {
        self.active.as_ref().is_some_and(|live| live.reads_images())
    }

    fn reads_audio(&self) -> bool {
        self.active.as_ref().is_some_and(|live| live.reads_audio())
    }

    fn decide(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Result<Option<GraphDecision>> {
        self.prepared()?.decide(question, context, images, audio)
    }
}
