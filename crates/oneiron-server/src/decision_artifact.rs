//! Typed judgments over artifact units (ARCH-0076, OF-506): the host's
//! decide() for a sheet row, a paragraph, a slide or a file in a folder. The
//! engine prepares each unit's state and images from pinned bytes; this
//! decider asks the host's ladder as the asker, its images read at the
//! Local-vision rung, and returns the full decision for the engine to land
//! as a proposal held for Keep.
use std::borrow::Cow;

use oneiron::edit_roundtrip::slides_review::SlideRenderer;
use oneiron::edit_roundtrip::{UnitCall, UnitDecider};
use oneiron::edit_settle::ReaskShape;
use oneiron::llm::decision::questions::{QuestionCriteria, QuestionDefinition};
use oneiron::llm::decision::{
    DecisionDial, DecisionImage, DecisionQuestion, DecisionRung, LocatedDecision, TypedDecision,
};
use oneiron::{EdgeActorClass, HostingPrivacyPosture, Result};
use serde_json::Value;

use crate::ai_host::LocalVisionModel;
use crate::decision_graph::{LadderCall, ladder_decide, ladder_located, question_posture};
use crate::server::SyncServer;

/// The host's ladder answering artifact units for one asker class; each
/// call names its principal, as the engine bound it.
pub(crate) struct HostUnitDecider<'s> {
    server: &'s SyncServer,
    class: EdgeActorClass,
    /// The run label a vision seat's read is recorded under.
    label: &'static str,
    /// A standing question's criteria, beside each unit's state.
    criteria: QuestionCriteria,
    /// A standing question's posture where it is stricter than the vault's.
    posture: Option<HostingPrivacyPosture>,
}

impl<'s> HostUnitDecider<'s> {
    pub(crate) fn new(server: &'s SyncServer, class: EdgeActorClass, label: &'static str) -> Self {
        Self {
            server,
            class,
            label,
            criteria: QuestionCriteria::default(),
            posture: None,
        }
    }

    /// The decider for a standing question: its criteria ride each unit's
    /// state, and its posture bounds the ladder.
    pub(crate) fn with_question(mut self, definition: &QuestionDefinition) -> Self {
        self.criteria = definition.criteria.clone();
        self.posture = question_posture(self.server, definition.posture);
        self
    }

    /// `state` with the criteria beside it, when there are any.
    fn state<'c>(&self, state: &'c Value) -> Cow<'c, Value> {
        if self.criteria.is_empty() {
            return Cow::Borrowed(state);
        }
        let mut state = state.clone();
        if let Some(fields) = state.as_object_mut() {
            fields.insert("criteria".into(), serde_json::json!(self.criteria));
        }
        Cow::Owned(state)
    }
}

impl UnitDecider for HostUnitDecider<'_> {
    fn reads_images(&self) -> bool {
        LocalVisionModel::bound(&self.server.ai)
    }

    /// Images ride to the Local-vision rung, when it is bound and the dial
    /// spans it, as [`ladder_decide`] sends them.
    fn first_taking(
        &self,
        _question: &DecisionQuestion,
        dial: DecisionDial,
        _images: &[DecisionImage],
    ) -> Option<DecisionRung> {
        (self.reads_images()
            && dial.first <= DecisionRung::Local
            && DecisionRung::Local <= dial.ceiling)
            .then_some(DecisionRung::Local)
    }

    fn decide_unit(&self, call: &UnitCall<'_>) -> Result<TypedDecision> {
        let state = self.state(call.state);
        ladder_decide(self.server, self.ladder_call(call, &state))
    }

    /// Presence first on the host's ladder, its images seated as
    /// [`Self::decide_unit`] seats them.
    fn decide_located(&self, call: &UnitCall<'_>) -> Result<LocatedDecision> {
        let state = self.state(call.state);
        ladder_located(self.server, self.ladder_call(call, &state))
    }
}

impl HostUnitDecider<'_> {
    /// `call` as the host's ladder takes it, asked as this decider's class.
    fn ladder_call<'c>(&self, call: &'c UnitCall<'c>, state: &'c Value) -> LadderCall<'c> {
        LadderCall {
            principal: call.principal,
            class: self.class,
            question: call.question,
            evidence: call.evidence,
            images: call.images,
            state,
            dial: call.dial,
            policy: call.policy,
            reversibility: call.reversibility,
            deadline: call.deadline,
            label: self.label,
            ask_to: None,
            posture: self.posture,
        }
    }
}

/// Wakes the proposer of every held artifact answer whose changed units
/// have been quiet for the vault's interval (ARCH-0075 §4): its question is
/// asked again of those units on the head, as its principal on the host's
/// ladder, and the answers wait as a fresh proposal for Keep; a changed
/// slide is asked over the host's LibreOffice render of it. The caller
/// runs this on the vault's home node only. A failed wake is held, then
/// tried again; its error logs by kind, as its text can quote the vault.
pub(crate) fn pump_answer_wakes(server: &SyncServer, now: u64) -> Result<()> {
    let vault = server.vault();
    let host = server.decision_host();
    for wake in vault.due_answer_wakes(now)? {
        // Only a slide wake looks for the renderer.
        let renderer = matches!(wake.shape, ReaskShape::Slides { .. })
            .then(crate::slide_render::host_renderer)
            .flatten()
            .map(|renderer| renderer as &dyn SlideRenderer);
        let woke = vault.answer_wake_actor(&wake).and_then(|actor| {
            vault.wake_answer_proposer(
                &wake,
                actor,
                &HostUnitDecider::new(server, actor.actor_class(), "vault.artifacts.ask"),
                host.dial(DecisionRung::Big),
                &host.bands(),
                renderer,
                now,
            )
        });
        if let Err(error) = woke {
            tracing::warn!(
                artifact = %wake.artifact.to_hex(),
                kind = ?error.kind(),
                "a held answer's proposer was not woken; the wake is held, then runs again"
            );
        }
    }
    Ok(())
}
