//! Typed judgments over artifact units (ARCH-0076, OF-506): the host's
//! decide() for a sheet row, a paragraph, a slide or a file in a folder. The
//! engine prepares each unit's state and images from pinned bytes; this
//! decider asks the host's ladder as the asker, its images read at the
//! Local-vision rung, and returns the full decision for the engine to land
//! as a proposal held for Keep.
use oneiron::edit_roundtrip::{UnitCall, UnitDecider};
use oneiron::llm::decision::{
    DecisionDial, DecisionImage, DecisionQuestion, DecisionRung, LocatedDecision, TypedDecision,
};
use oneiron::{EdgeActorClass, Result};

use crate::ai_host::LocalVisionModel;
use crate::decision_graph::{LadderCall, ladder_decide, ladder_located};
use crate::server::SyncServer;

/// The host's ladder answering artifact units for one asker class; each
/// call names its principal, as the engine bound it.
pub(crate) struct HostUnitDecider<'s> {
    server: &'s SyncServer,
    class: EdgeActorClass,
    /// The run label a vision seat's read is recorded under.
    label: &'static str,
}

impl<'s> HostUnitDecider<'s> {
    pub(crate) fn new(server: &'s SyncServer, class: EdgeActorClass, label: &'static str) -> Self {
        Self {
            server,
            class,
            label,
        }
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
        ladder_decide(self.server, self.ladder_call(call))
    }

    /// Presence first on the host's ladder, its images seated as
    /// [`Self::decide_unit`] seats them.
    fn decide_located(&self, call: &UnitCall<'_>) -> Result<LocatedDecision> {
        ladder_located(self.server, self.ladder_call(call))
    }
}

impl HostUnitDecider<'_> {
    /// `call` as the host's ladder takes it, asked as this decider's class.
    fn ladder_call<'c>(&self, call: &'c UnitCall<'c>) -> LadderCall<'c> {
        LadderCall {
            principal: call.principal,
            class: self.class,
            question: call.question,
            evidence: call.evidence,
            images: call.images,
            state: call.state,
            dial: call.dial,
            policy: call.policy,
            reversibility: call.reversibility,
            deadline: call.deadline,
            label: self.label,
            ask_to: None,
        }
    }
}

/// Wakes the proposer of every held artifact answer whose changed units
/// have been quiet for the vault's interval (ARCH-0075 §4): its question is
/// asked again of those units on the head, as its principal on the host's
/// ladder, and the answers wait as a fresh proposal for Keep. The caller
/// runs this on the vault's home node only. A failed wake is held, then
/// tried again; its error logs by kind, as its text can quote the vault.
pub(crate) fn pump_answer_wakes(server: &SyncServer, now: u64) -> Result<()> {
    let vault = server.vault();
    let host = server.decision_host();
    for wake in vault.due_answer_wakes(now)? {
        let woke = vault.answer_wake_actor(&wake).and_then(|actor| {
            vault.wake_answer_proposer(
                &wake,
                actor,
                &HostUnitDecider::new(server, actor.actor_class(), "vault.artifacts.ask"),
                host.dial(DecisionRung::Big),
                &host.bands(),
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
