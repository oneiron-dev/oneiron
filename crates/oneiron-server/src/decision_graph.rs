//! Typed judgments over graph units (ARCH-0076, OF-506): the host's decision
//! ladder answers a graph question. A unit's sources ride as the call's
//! state, its image assets as images read at the Local-vision rung, and the
//! ladder's full decision comes back for the engine to land, keeping its
//! receipt. The standing pump answers each due standing question here, as
//! the question's own principal under the question's own dial.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphDecision, GraphPrediction, GraphUnitContext, refresh_due_questions_with,
};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionDial, DecisionImage, DecisionProvider, DecisionQuestion, DecisionRung,
    Reversibility,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::task_verb::sdk::AI_VERDICT_DEADLINE_MS;
use oneiron::{EdgeActorClass, EntityId, Error, Result, WriteActor};

use crate::ai_host::LocalVisionModel;
use crate::decision_verdict::vision_rung;
use crate::server::SyncServer;

/// How often the pump looks for due standing questions.
const PUMP_EVERY: Duration = Duration::from_secs(60);
/// One unit's clock on the ladder: an `ai.verdict` call's default.
const UNIT_BUDGET: Duration = Duration::from_millis(AI_VERDICT_DEADLINE_MS);

/// The host's ladder answering graph questions for one asker, each unit on
/// a clock of its own.
pub(crate) struct LadderGraphAnswerer<'s> {
    server: &'s SyncServer,
    principal: EntityId,
    class: EdgeActorClass,
    dial: DecisionDial,
    budget: Duration,
    /// A Local-vision seat is bound and the dial spans its rung.
    vision: bool,
}

impl<'s> LadderGraphAnswerer<'s> {
    /// An answerer for `asker`, climbing `dial` with `budget` per unit. A
    /// ceiling of `human` is held at `big`: a graph answer never queues an
    /// owner ask.
    pub(crate) fn new(
        server: &'s SyncServer,
        asker: WriteActor,
        mut dial: DecisionDial,
        budget: Duration,
    ) -> Result<Self> {
        dial.ceiling = dial.ceiling.min(DecisionRung::Big);
        if dial.first > dial.ceiling {
            return Err(Error::InvalidConfig(
                "a graph question's dial starts at the owner ask".into(),
            ));
        }
        Ok(Self {
            server,
            principal: asker.entity_ref(),
            class: asker.actor_class(),
            vision: LocalVisionModel::bound(&server.ai)
                && dial.first <= DecisionRung::Local
                && DecisionRung::Local <= dial.ceiling,
            dial,
            budget,
        })
    }
}

impl GraphAnswerer for LadderGraphAnswerer<'_> {
    /// The ladder's answer as a bare prediction, pinned to the rung that
    /// answered, for a caller that keeps only that.
    fn answer(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
    ) -> Result<Option<GraphPrediction>> {
        let Some(GraphDecision::Decision(decision)) = self.decide(question, context, &[])? else {
            return Ok(None);
        };
        let decision = *decision;
        let answered = decision.receipt.time.as_ref().and_then(|time| time.answered);
        let provider = decision
            .receipt
            .providers
            .iter()
            .rev()
            .find(|pin| Some(pin.rung) == answered)
            .cloned();
        Ok(match (decision.probability, provider) {
            (Some(probability), Some(provider)) if decision.answer != DecisionAnswer::Abstain => {
                Some(GraphPrediction {
                    answer: decision.answer,
                    probability,
                    provider,
                    cost_per_thousand: decision.receipt.cost_per_thousand.unwrap_or(0.0),
                    paired: None,
                })
            }
            _ => None,
        })
    }

    fn reads_images(&self) -> bool {
        self.vision
    }

    /// The unit through the ladder. Its images are read from the
    /// Local-vision rung, seated on a run of the asker's own; a rung above
    /// it that reads no image is skipped.
    fn decide(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
        images: &[DecisionImage],
    ) -> Result<Option<GraphDecision>> {
        let host = self.server.decision_host();
        let state = context.state(images);
        let evidence: Vec<EntityId> = context.sources.iter().map(|source| source.id).collect();
        let deadline = RetrievalDeadline::hard(Instant::now(), self.budget);
        let mut dial = self.dial;
        let local = if images.is_empty() {
            None
        } else {
            dial.first = DecisionRung::Local;
            Some(
                vision_rung(self.server, self.principal, self.class, images, "graph.ask")
                    .map_err(|error| Error::InvalidConfig(error.to_string()))?,
            )
        };
        let mut ladder = host.ladder().ladder();
        if let Some(rung) = &local {
            ladder.local = Some(rung as &dyn DecisionProvider);
        }
        let decision = ladder.run_images(
            question,
            self.principal,
            &evidence,
            images,
            &state,
            dial,
            &host.bands(),
            Reversibility::ReversibleRead,
            &deadline,
        )?;
        Ok(Some(GraphDecision::Decision(Box::new(decision))))
    }
}

/// Starts the standing pump. Each pass runs on a blocking thread: the
/// ladder's model rungs block on the server's runtime.
pub(crate) fn spawn(server: &Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(PUMP_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            match tokio::task::spawn_blocking(move || pump(&server)).await {
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "standing question pump failed; it runs again next tick");
                }
                Err(error) => tracing::warn!(%error, "standing question pump stopped"),
                Ok(Ok(())) => {}
            }
        }
    })
}

/// One pass: every due standing question, each asked as its principal on
/// the ladder under its own dial. A failed question waits for its next due
/// pass; its error logs by kind, as its text can quote the vault.
fn pump(server: &SyncServer) -> Result<()> {
    let batch = refresh_due_questions_with(
        server.vault(),
        oneiron_vault_contract::now_ts(),
        |record, asker| {
            LadderGraphAnswerer::new(server, asker, record.definition.dial, UNIT_BUDGET)
        },
    )?;
    for failure in &batch.failures {
        tracing::warn!(
            question = %failure.question.to_hex(),
            kind = ?failure.error.kind(),
            "a standing question was not refreshed; it runs again when due"
        );
    }
    Ok(())
}
