//! Typed judgments over graph units (ARCH-0076, OF-506): the host's decision
//! ladder answers a graph question. A unit's sources ride as the call's
//! state, its image assets as images read at the Local-vision rung, its
//! audio assets as clips heard at the first rung that reads audio, and the
//! ladder's full decision comes back for the engine to land, keeping its
//! receipt. The standing pump answers each due standing question here, for
//! the question's own principal under the question's own dial, criteria
//! and call clock, on the vault's home node only. A question whose posture
//! is stricter than the vault's is answered without the rungs that send
//! unit text off the host where it forbids that. A dial up to the person
//! asks the question's responsible role, its principal, and the ask climbs
//! to the vault's owners (OF-516); each pass also climbs every open ask no
//! live actor holds. It sleeps until the next question falls due and wakes
//! early on a committed change.
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::llm::decision::questions::{
    GraphAnswerer, GraphDecision, GraphPrediction, GraphUnitContext, QuestionCriteria,
    refresh_due_artifact_questions, refresh_due_questions_by_role,
};
use oneiron::llm::decision::{
    AskTo, DecisionAnswer, DecisionAudio, DecisionBandPolicy, DecisionDial, DecisionImage,
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, LocatedDecision,
    Reversibility, TypedDecision,
};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::{
    DreamerRunnerStore, EdgeActorClass, EntityId, Error, HostingPrivacyPosture, Result, Vault,
    WriteActor,
};

use crate::ai_host::LocalVisionModel;
use crate::decision_artifact::HostUnitDecider;
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
    /// Whose question the ladder answers: its receipt and asks name them.
    principal: EntityId,
    /// Who runs it: a Local-vision read is seated on a run of theirs.
    runner: WriteActor,
    /// Where a person ask goes; none holds the dial below the person.
    ask_to: Option<AskTo>,
    dial: DecisionDial,
    budget: Duration,
    /// The question's criteria, beside the sources in each call's state.
    criteria: QuestionCriteria,
    /// A Local-vision seat is bound and the dial spans its rung.
    vision: bool,
    /// The question's posture, when it is stricter than the vault's.
    posture: Option<HostingPrivacyPosture>,
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
        Ok(Self::build(
            server,
            asker.entity_ref(),
            asker,
            None,
            dial,
            budget,
        ))
    }

    /// An answerer for `principal`'s standing question, run by `runner` and
    /// climbing all of `dial`: a dial up to the person queues its ask to
    /// `to`, the question's responsible role (OF-516), which the ask climbs.
    pub(crate) fn routed(
        server: &'s SyncServer,
        principal: EntityId,
        runner: WriteActor,
        to: AskTo,
        dial: DecisionDial,
        budget: Duration,
    ) -> Self {
        Self::build(server, principal, runner, Some(to), dial, budget)
    }

    fn build(
        server: &'s SyncServer,
        principal: EntityId,
        runner: WriteActor,
        ask_to: Option<AskTo>,
        dial: DecisionDial,
        budget: Duration,
    ) -> Self {
        Self {
            server,
            principal,
            runner,
            ask_to,
            vision: LocalVisionModel::bound(&server.ai)
                && dial.first <= DecisionRung::Local
                && DecisionRung::Local <= dial.ceiling,
            dial,
            budget,
            criteria: QuestionCriteria::default(),
            posture: None,
        }
    }

    /// The answerer, judging each unit by `criteria`.
    pub(crate) fn with_criteria(mut self, criteria: QuestionCriteria) -> Self {
        self.criteria = criteria;
        self
    }

    /// The answerer under the question's own `posture`
    /// ([`question_posture`]).
    pub(crate) fn with_posture(mut self, posture: Option<HostingPrivacyPosture>) -> Self {
        self.posture = question_posture(self.server, posture);
        self
    }

    /// `ladder` without the rungs that send unit text off the host, where
    /// the question's posture forbids that.
    fn postured<'l>(&self, ladder: DecisionLadder<'l>) -> DecisionLadder<'l> {
        match self.posture {
            Some(posture) => {
                ladder.under_posture(posture, self.server.decision_host().remote_opt_in())
            }
            None => ladder,
        }
    }
}

/// A question's `posture` where it is stricter than the vault's; `None`
/// holds the vault's, which the rungs keep themselves.
pub(crate) fn question_posture(
    server: &SyncServer,
    posture: Option<HostingPrivacyPosture>,
) -> Option<HostingPrivacyPosture> {
    let vault = server.vault().privacy_posture();
    posture
        .map(|posture| stricter(vault, posture))
        .filter(|posture| *posture != vault)
}

/// `ladder` without the rungs a question's stricter `posture` keeps unit
/// text from, and `dial` starting at the first rung it leaves in the dial,
/// when there is one.
fn under_question_posture<'l>(
    server: &SyncServer,
    ladder: DecisionLadder<'l>,
    posture: Option<HostingPrivacyPosture>,
    dial: &mut DecisionDial,
) -> DecisionLadder<'l> {
    let Some(posture) = posture else {
        return ladder;
    };
    let ladder = ladder.under_posture(posture, server.decision_host().remote_opt_in());
    if let Some(first) = ladder.first_media_reader(dial.first, dial.ceiling, false, false) {
        dial.first = first;
    }
    ladder
}

/// The stricter of two postures: RELAY keeps unit text on the host,
/// SELF-HOST sends it off only on an opt-in, MANAGED sends it.
fn stricter(a: HostingPrivacyPosture, b: HostingPrivacyPosture) -> HostingPrivacyPosture {
    let rank = |posture| match posture {
        HostingPrivacyPosture::Hosted => 0,
        HostingPrivacyPosture::SelfHostLocal => 1,
        HostingPrivacyPosture::Relay => 2,
    };
    if rank(b) > rank(a) { b } else { a }
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
        self.postured(self.server.decision_host().ladder().ladder())
            .first_media_reader(self.dial.first, self.dial.ceiling, false, true)
            .is_some()
    }

    /// The unit through the ladder. Its images are read from the
    /// Local-vision rung, seated on a run of the asker's own; its clips
    /// start at the first rung in the dial that hears them. A unit with
    /// both starts at a rung that reads both, or abstains: no rung is
    /// handed one of the two alone. A rung above that cannot read the
    /// call's media is skipped. Under a stricter posture a text call starts
    /// at the first rung the posture leaves in the dial, or at the person
    /// when the dial reaches one; with neither it abstains.
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
                vision_rung(
                    self.server,
                    self.runner.entity_ref(),
                    self.runner.actor_class(),
                    images,
                    "graph.ask",
                )
                .map_err(|error| Error::InvalidConfig(error.to_string()))?,
            )
        };
        let mut ladder = host.ladder().ladder();
        if let Some(rung) = &local {
            ladder.local = Some(rung as &dyn DecisionProvider);
        }
        ladder.ask_to = self.ask_to.as_ref();
        let ladder = self.postured(ladder);
        let text = images.is_empty() && audio.is_empty();
        if !text || self.posture.is_some() {
            match ladder.first_media_reader(
                dial.first,
                dial.ceiling,
                !images.is_empty(),
                !audio.is_empty(),
            ) {
                Some(first) => dial.first = first,
                None if text && dial.ceiling == DecisionRung::Human => {
                    dial.first = DecisionRung::Human;
                }
                None => return Ok(None),
            }
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
    /// Where a person ask goes; none is the vault's owners.
    pub(crate) ask_to: Option<&'a AskTo>,
    /// The question's posture where it is stricter than the vault's
    /// ([`question_posture`]).
    pub(crate) posture: Option<HostingPrivacyPosture>,
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
    ladder.ask_to = call.ask_to;
    let ladder = under_question_posture(server, ladder, call.posture, &mut dial);
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
pub(crate) fn ladder_located(server: &SyncServer, call: LadderCall<'_>) -> Result<LocatedDecision> {
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
    ladder.ask_to = call.ask_to;
    let ladder = under_question_posture(server, ladder, call.posture, &mut dial);
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
                let question = server.vault().next_question_refresh_at()?;
                let wake = server.vault().next_answer_wake_at()?;
                Ok::<_, oneiron::Error>(question.into_iter().chain(wake).min())
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
/// asked for its principal on the ladder under its own dial, criteria and
/// call clock, run by the first live holder of its responsible-role chain;
/// then every open ask no live actor holds climbs to the next role that has
/// one. Off home it does nothing. The engine holds a failed question before
/// it is due again; its error logs by kind, as its text can quote the vault.
pub(crate) fn pump_due(server: &SyncServer, now: u64) -> Result<()> {
    if !at_home(server.vault(), now)? {
        return Ok(());
    }
    let batch = refresh_due_questions_by_role(server.vault(), now, |record, runner, to| {
        Ok(LadderGraphAnswerer::routed(
            server,
            record.principal,
            runner,
            to,
            record.definition.dial,
            record.definition.deadline(),
        )
        .with_criteria(record.definition.criteria.clone())
        .with_posture(record.definition.posture))
    })?;
    for failure in &batch.failures {
        tracing::warn!(
            question = %failure.question.to_hex(),
            kind = ?failure.error.kind(),
            "a standing question was not refreshed; it is held, then runs again"
        );
    }
    let host = server.decision_host();
    let artifacts =
        refresh_due_artifact_questions(server.vault(), now, &host.bands(), |record, actor| {
            Ok(
                HostUnitDecider::new(server, actor.actor_class(), "vault.artifacts.ask")
                    .with_question(&record.definition),
            )
        })?;
    for failure in &artifacts.failures {
        tracing::warn!(
            question = %failure.question.to_hex(),
            artifact = ?failure.artifact.map(|artifact| artifact.to_hex()),
            kind = ?failure.error.kind(),
            "a standing artifact question was not asked; it is held, then runs again"
        );
    }
    match server.vault().climb_unheld_decision_asks() {
        Ok(climbed) => {
            for (seq, role) in &climbed {
                tracing::info!(seq, role = ?role.role, "an unheld decision ask climbed");
            }
        }
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "unheld decision asks were not climbed");
        }
    }
    crate::decision_artifact::pump_answer_wakes(server, now)
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
