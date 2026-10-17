//! Typed judgments over graph units (ARCH-0076, OF-506): the host's decision
//! ladder answers a graph question. A unit's sources ride as the call's
//! state, its image assets as images read at the Local-vision rung, its
//! audio assets as clips heard at the first rung that reads audio, and the
//! ladder's full decision comes back for the engine to land, keeping its
//! receipt. The standing pump answers each due standing question here, as
//! the question's own principal under the question's own dial, criteria
//! and call clock, on the vault's home node only. It sleeps until the next
//! question falls due and wakes early on a committed change.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphDecision, GraphPrediction, GraphUnitContext, QuestionCriteria,
    refresh_due_questions_with,
};
use oneiron::llm::decision::{
    DecisionAnswer, DecisionAudio, DecisionBandPolicy, DecisionDial, DecisionImage,
    DecisionProvider, DecisionQuestion, DecisionRung, LocatedDecision, Reversibility,
    TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{DreamerRunnerStore, EdgeActorClass, EntityId, Error, Result, Vault, WriteActor};

use crate::ai_host::LocalVisionModel;
use crate::decision_verdict::vision_rung;
use crate::server::SyncServer;

/// The longest the pump sleeps. An arrival on a unit that is not a claim
/// queues its question without a change signal, so the pump re-reads its
/// due work at least this often.
const ARRIVAL_SWEEP: Duration = Duration::from_secs(60);
/// The shortest the pump sleeps between passes, so work a pass leaves due
/// never spins it.
const PASS_FLOOR: Duration = Duration::from_secs(1);

/// The host's ladder answering graph questions for one asker, each unit on
/// a clock of its own.
pub(crate) struct LadderGraphAnswerer<'s> {
    server: &'s SyncServer,
    principal: EntityId,
    class: EdgeActorClass,
    dial: DecisionDial,
    budget: Duration,
    /// The question's criteria, beside the sources in each call's state.
    criteria: QuestionCriteria,
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
            criteria: QuestionCriteria::default(),
        })
    }

    /// The answerer, judging each unit by `criteria`.
    pub(crate) fn with_criteria(mut self, criteria: QuestionCriteria) -> Self {
        self.criteria = criteria;
        self
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
        let Some(GraphDecision::Decision(decision)) = self.decide(question, context, &[], &[])?
        else {
            return Ok(None);
        };
        let decision = *decision;
        let answered = decision
            .receipt
            .time
            .as_ref()
            .and_then(|time| time.answered);
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

    /// A rung inside the dial hears audio: the Big rung over a model its
    /// binding says hears it.
    fn reads_audio(&self) -> bool {
        self.server
            .decision_host()
            .ladder()
            .ladder()
            .first_media_reader(self.dial.first, self.dial.ceiling, false, true)
            .is_some()
    }

    /// The unit through the ladder. Its images are read from the
    /// Local-vision rung, seated on a run of the asker's own; its clips
    /// start at the first rung in the dial that hears them. A unit with
    /// both starts at a rung that reads both, or abstains: no rung is
    /// handed one of the two alone. A rung above that cannot read the
    /// call's media is skipped.
    fn decide(
        &mut self,
        question: &DecisionQuestion,
        context: &GraphUnitContext,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Result<Option<GraphDecision>> {
        let host = self.server.decision_host();
        let state = context.state_under(images, audio, &self.criteria);
        let evidence: Vec<EntityId> = context.sources.iter().map(|source| source.id).collect();
        let deadline = RetrievalDeadline::hard(Instant::now(), self.budget);
        let mut dial = self.dial;
        let local = if images.is_empty() {
            None
        } else {
            Some(
                vision_rung(self.server, self.principal, self.class, images, "graph.ask")
                    .map_err(|error| Error::InvalidConfig(error.to_string()))?,
            )
        };
        let mut ladder = host.ladder().ladder();
        if let Some(rung) = &local {
            ladder.local = Some(rung as &dyn DecisionProvider);
        }
        if !(images.is_empty() && audio.is_empty()) {
            let Some(first) = ladder.first_media_reader(
                dial.first,
                dial.ceiling,
                !images.is_empty(),
                !audio.is_empty(),
            ) else {
                return Ok(None);
            };
            dial.first = first;
        }
        let decision = ladder.run_media(
            question,
            self.principal,
            &evidence,
            images,
            audio,
            &state,
            dial,
            &host.bands(),
            Reversibility::ReversibleRead,
            &deadline,
        )?;
        Ok(Some(GraphDecision::Decision(Box::new(decision))))
    }
}

/// One call on the host's ladder, for a graph or an artifact unit.
pub(crate) struct LadderCall<'a> {
    pub(crate) principal: EntityId,
    pub(crate) class: EdgeActorClass,
    pub(crate) question: &'a DecisionQuestion,
    pub(crate) evidence: &'a [EntityId],
    pub(crate) images: &'a [DecisionImage],
    pub(crate) state: &'a serde_json::Value,
    pub(crate) dial: DecisionDial,
    pub(crate) policy: &'a DecisionBandPolicy,
    pub(crate) reversibility: Reversibility,
    pub(crate) deadline: &'a RetrievalDeadline,
    /// The run label a vision seat's read is recorded under.
    pub(crate) label: &'a str,
}

/// The call through the host's ladder. A call with images starts at the
/// Local-vision rung, seated on a run of the asker's own, when the dial
/// spans it; a rung above it that reads no image is skipped. Without that
/// rung the call reads its state alone.
pub(crate) fn ladder_decide(server: &SyncServer, call: LadderCall<'_>) -> Result<TypedDecision> {
    let host = server.decision_host();
    let mut dial = call.dial;
    let sees = !call.images.is_empty()
        && LocalVisionModel::bound(&server.ai)
        && dial.first <= DecisionRung::Local
        && DecisionRung::Local <= dial.ceiling;
    let local = if sees {
        dial.first = DecisionRung::Local;
        Some(
            vision_rung(server, call.principal, call.class, call.images, call.label)
                .map_err(|error| Error::InvalidConfig(error.to_string()))?,
        )
    } else {
        None
    };
    let images = if sees { call.images } else { &[] };
    let mut ladder = host.ladder().ladder();
    if let Some(rung) = &local {
        ladder.local = Some(rung as &dyn DecisionProvider);
    }
    ladder.run_images(
        call.question,
        call.principal,
        call.evidence,
        images,
        call.state,
        dial,
        call.policy,
        call.reversibility,
        call.deadline,
    )
}

/// A Box or Point call through the host's ladder, seated as [`ladder_decide`]
/// seats it: the host's presence question first, then the coordinates
/// ([`oneiron::llm::decision::DecisionLadder::run_located`]).
pub(crate) fn ladder_located(
    server: &SyncServer,
    call: LadderCall<'_>,
) -> Result<LocatedDecision> {
    let host = server.decision_host();
    let mut dial = call.dial;
    let sees = !call.images.is_empty()
        && LocalVisionModel::bound(&server.ai)
        && dial.first <= DecisionRung::Local
        && DecisionRung::Local <= dial.ceiling;
    let local = if sees {
        dial.first = DecisionRung::Local;
        Some(
            vision_rung(server, call.principal, call.class, call.images, call.label)
                .map_err(|error| Error::InvalidConfig(error.to_string()))?,
        )
    } else {
        None
    };
    let images = if sees { call.images } else { &[] };
    let mut ladder = host.ladder().ladder();
    if let Some(rung) = &local {
        ladder.local = Some(rung as &dyn DecisionProvider);
    }
    ladder.run_located(
        call.question,
        call.principal,
        call.evidence,
        images,
        call.state,
        dial,
        call.policy,
        call.reversibility,
        call.deadline,
    )
}

/// Starts the standing pump. It sleeps until the next standing question
/// falls due or a committed write changes the vault's due work, then runs
/// one pass on a blocking thread: the ladder's model rungs block on the
/// server's runtime.
pub(crate) fn spawn(server: &Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(server);
    // Subscribed before the first read, so no change between them is lost.
    let mut changes = server.vault().subscribe_proactivity_changes();
    tokio::spawn(async move {
        loop {
            let Some(server) = weak.upgrade() else {
                break;
            };
            let next = tokio::task::spawn_blocking(move || {
                pump_due(&server, oneiron_vault_contract::now_ts())?;
                server.vault().next_question_refresh_at()
            })
            .await;
            let next = match next {
                Ok(Ok(next)) => next,
                Ok(Err(error)) => {
                    tracing::warn!(kind = ?error.kind(), "standing question pump failed; it runs again on the next change");
                    None
                }
                Err(error) => {
                    tracing::warn!(%error, "standing question pump stopped");
                    None
                }
            };
            let wait = next.map_or(ARRIVAL_SWEEP, |at| {
                Duration::from_secs(at.saturating_sub(oneiron_vault_contract::now_ts()))
                    .clamp(PASS_FLOOR, ARRIVAL_SWEEP)
            });
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    })
}

/// One pass on the vault's home node: every due standing question, each
/// asked as its principal on the ladder under its own dial, criteria and
/// call clock. Off home it does nothing. The engine holds a failed question
/// before it is due again; its error logs by kind, as its text can quote the
/// vault.
pub(crate) fn pump_due(server: &SyncServer, now: u64) -> Result<()> {
    if !at_home(server.vault(), now)? {
        return Ok(());
    }
    let batch = refresh_due_questions_with(server.vault(), now, |record, asker| {
        Ok(LadderGraphAnswerer::new(
            server,
            asker,
            record.definition.dial,
            record.definition.deadline(),
        )?
        .with_criteria(record.definition.criteria.clone()))
    })?;
    for failure in &batch.failures {
        tracing::warn!(
            question = %failure.question.to_hex(),
            kind = ?failure.error.kind(),
            "a standing question was not refreshed; it is held, then runs again"
        );
    }
    Ok(())
}

/// Whether this server is the vault's home: the elected home names this
/// server's stable client identity, the gate the shared timer puts on macro
/// work and digests. A vault no node has claimed is claimed here, as serve's
/// Dreamer claims it, so standing questions run with the Dreamer off.
fn at_home(vault: &Vault, now: u64) -> Result<bool> {
    let store = DreamerRunnerStore::new(vault);
    let local = store.local_home_node_candidate(true, true, false)?;
    let home = match store.home_node_designation()? {
        Some(home) => Some(home),
        None => store.elect_home_node(&[local], now)?,
    };
    Ok(home.is_some_and(|home| home.node_id == local.node_id))
}
