//! The house mind's one typed question on a conversation (OF-501, ARCH-0067):
//! does this sound like a project? A person's turn queued it by reference; it
//! runs here, off the turn, on the host's ladder. A yes dispatches the house
//! mind as an ordinary attempt to draft a card on the source message. Nothing
//! here mints a project, and a spawn never mints a TASK.
use super::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::context_projection::ContextSpec;
use crate::edge::EdgeActorClass;
use crate::llm::decision::catalogue::PROJECT_PROPOSAL;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, HeldLadder, Reversibility,
    TypedDecision, cut_text, fit_state,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::workspace_roster::{
    ClaimedProjectDetection, ProjectDetectionAnswer, ProjectDetectionSource,
    ProjectDetectionVerdict, claim_project_detection, fail_project_detection, project_house_agent,
    settle_project_detection,
};
use crate::{EntityId, Error, Result};
use std::time::{Duration, Instant};

/// The host's typed project question: its ladder, the dial and learned bands
/// the question runs under, its wording, and each question's anytime budget.
/// The wording is the host's configuration or skill text, never engine text.
pub struct ProjectDetection {
    pub ladder: HeldLadder,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub budget: Duration,
}

/// What one pass over the queued questions did.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ProjectDetectionRun {
    /// No question was queued.
    Idle,
    /// The source is gone, or the house mind may not read it: nothing kept.
    Unread,
    /// No, or an abstention: nothing kept.
    NotAProject,
    /// The ladder asked a person; the source stays pending. A person's yes to
    /// the question is not the mint tap.
    AskedPerson,
    /// Yes: the house mind was dispatched to draft the card.
    Drafting(Box<AgentDispatchOutcome>),
    /// Yes, but no house agent can be dispatched: the receipt is kept.
    NoHouseAgent,
}

impl AgentDispatcher<'_> {
    /// Claims the oldest queued project question and asks it. The source is
    /// read under the house mind's own scope; a question that cannot be asked
    /// fails its attempt, and the conversation's next person turn asks again.
    pub fn run_project_detection(
        &self,
        detection: &ProjectDetection,
        lease_owner: &str,
        now: u64,
    ) -> Result<ProjectDetectionRun> {
        let Some(claimed) = claim_project_detection(self.vault, lease_owner, now)? else {
            return Ok(ProjectDetectionRun::Idle);
        };
        match self.ask_project_question(detection, &claimed, lease_owner, now) {
            Ok(run) => Ok(run),
            Err(error) => {
                fail_project_detection(self.vault, &claimed, lease_owner, error.to_string(), now)?;
                Err(error)
            }
        }
    }

    fn ask_project_question(
        &self,
        detection: &ProjectDetection,
        claimed: &ClaimedProjectDetection,
        lease_owner: &str,
        now: u64,
    ) -> Result<ProjectDetectionRun> {
        let (Some(source), Some(house)) = (claimed.source, project_house_agent(self.vault)?) else {
            settle_project_detection(self.vault, claimed, lease_owner, None)?;
            return Ok(ProjectDetectionRun::Unread);
        };
        let Some(text) = self.source_text(house, &source)? else {
            settle_project_detection(self.vault, claimed, lease_owner, None)?;
            return Ok(ProjectDetectionRun::Unread);
        };
        let decision = ask(detection, &source, &text)?;
        let answer = match (&decision.answer, decision.human_ask.is_some()) {
            (DecisionAnswer::Noul(true), _) => ProjectDetectionAnswer::Yes,
            (DecisionAnswer::Abstain, true) => ProjectDetectionAnswer::AskedPerson,
            _ => {
                settle_project_detection(self.vault, claimed, lease_owner, None)?;
                return Ok(ProjectDetectionRun::NotAProject);
            }
        };
        // Only a house agent that can run drafts; the yes is kept either way.
        let drafter = (answer == ProjectDetectionAnswer::Yes
            && self
                .dispatchable_definition(&AgentDispatchTarget::Custom(house))
                .is_ok())
        .then_some(house);
        let verdict = ProjectDetectionVerdict {
            source,
            answer,
            receipt: decision.receipt,
            house: drafter,
        };
        settle_project_detection(self.vault, claimed, lease_owner, Some(&verdict))?;
        match (answer, drafter) {
            (ProjectDetectionAnswer::AskedPerson, _) => Ok(ProjectDetectionRun::AskedPerson),
            (ProjectDetectionAnswer::Yes, None) => Ok(ProjectDetectionRun::NoHouseAgent),
            (ProjectDetectionAnswer::Yes, Some(house)) => {
                match self.dispatch_drafter(house, &source, now) {
                    Ok(outcome) => Ok(ProjectDetectionRun::Drafting(Box::new(outcome))),
                    // The question is settled and its yes kept; only the
                    // drafting attempt is missing.
                    Err(error) => {
                        tracing::warn!(%error, "house mind not dispatched to draft a project card");
                        Ok(ProjectDetectionRun::NoHouseAgent)
                    }
                }
            }
        }
    }

    /// The source message's words as the house mind may read them; `None`
    /// when it is gone or withheld from that scope.
    fn source_text(
        &self,
        house: EntityId,
        source: &ProjectDetectionSource,
    ) -> Result<Option<String>> {
        let read = self
            .vault
            .memory(house, EdgeActorClass::Agent)
            .get_entity(&source.message.to_hex())
            .map_err(|error| Error::InvalidConfig(format!("project question source: {error}")))?;
        Ok(read
            .value
            .and_then(|view| view.body)
            .and_then(|body| body.get("content")?.as_str().map(str::to_owned))
            .filter(|text| !text.is_empty()))
    }

    /// The house mind, as an ordinary attempt, drafts the card. Its brief
    /// names references only; its own skills say how to draft.
    fn dispatch_drafter(
        &self,
        house: EntityId,
        source: &ProjectDetectionSource,
        now: u64,
    ) -> Result<AgentDispatchOutcome> {
        let brief = serde_json::json!({
            "project_proposal": {
                "conversation": source.conversation.to_hex(),
                "turn": source.turn.to_hex(),
                "source_message": source.message.to_hex(),
                "thread": source.thread.map(|thread| thread.to_hex()),
                "principal": source.author.to_hex(),
            }
        });
        self.dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(house),
                parent_attempt: None,
                dedupe_key: Some(format!("project-proposal:{}", source.message.to_hex())),
                run_id: Some(format!("project-proposal:{}", source.conversation.to_hex())),
                now,
            },
            AgentSpawnContext::default()
                .with_context_spec(ContextSpec::default().with_briefing(brief.to_string()))
                .with_origin_conversation(source.conversation),
        )
    }
}

/// The one typed question over the source's words, on the host's ladder, for
/// the person who wrote them. A reversible read: nothing is written on its
/// answer but the kept receipt.
fn ask(
    detection: &ProjectDetection,
    source: &ProjectDetectionSource,
    text: &str,
) -> Result<TypedDecision> {
    let question =
        PROJECT_PROPOSAL.question(&[], detection.wording.clone(), AnswerContract::Noul)?;
    let state = fit_state(text.len(), |cut| {
        serde_json::json!({
            "conversation": source.conversation.to_hex(),
            "source_message": source.message.to_hex(),
            "in_room_thread": source.thread.is_some(),
            "text": cut_text(text, cut),
            "cut_at_bytes": cut,
        })
    });
    detection.ladder.ladder().run(
        &question,
        source.author,
        &[source.message],
        &state,
        detection.dial,
        &detection.bands,
        Reversibility::ReversibleRead,
        &RetrievalDeadline::hard(Instant::now(), detection.budget),
    )
}
