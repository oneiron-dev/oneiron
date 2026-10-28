//! Decision graph ladder calls for graph and artifact units.
//! Entry: LadderCall.
//! Definitions: LadderCall and call functions live here; posture helpers stay in the parent.

use super::{
    AskTo, DecisionBandPolicy, DecisionDial, DecisionImage, DecisionProvider, DecisionQuestion,
    DecisionRung, EdgeActorClass, EntityId, Error, HostingPrivacyPosture, LocalVisionModel,
    LocatedDecision, Result, RetrievalDeadline, Reversibility, SyncServer, TypedDecision,
    under_question_posture, vision_rung,
};

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
    /// The unit's own work, so each unit keeps its own person ask.
    pub(crate) correlation: Option<EntityId>,
    /// The question's posture where it is stricter than the vault's
    /// ([`question_posture`](super::question_posture)).
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
    ladder.correlation = call.correlation;
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
    ladder.correlation = call.correlation;
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
