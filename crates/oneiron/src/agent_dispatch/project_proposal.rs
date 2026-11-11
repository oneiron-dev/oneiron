//! The house mind's one typed question on a conversation (OF-501, ARCH-0067):
//! does this sound like a project? A person's turn queued it by reference; it
//! runs here, off the turn, on the host's ladder. A yes dispatches the house
//! mind as an ordinary attempt to draft a card on the source message. Nothing
//! here mints a project, and a spawn never mints a TASK.
use super::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::claim::ScopedReadActorKey;
use crate::context_projection::ContextSpec;
use crate::edge::EdgeActorClass;
use crate::llm::decision::catalogue::PROJECT_PROPOSAL;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBandPolicy, DecisionDial, HeldLadder, Reversibility,
    TypedDecision, cut_text, fit_state,
};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::retrieval_depth::RetrievalDeadline;
use crate::settings::ReadDestination;
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
            settle_project_detection(self.vault, claimed, lease_owner, None, None)?;
            return Ok(ProjectDetectionRun::Unread);
        };
        let Some(text) = self.source_text(house, &source)? else {
            settle_project_detection(self.vault, claimed, lease_owner, None, Some(house))?;
            return Ok(ProjectDetectionRun::Unread);
        };
        let decision = ask(detection, &source, &text)?;
        let answer = match (&decision.answer, decision.human_ask.is_some()) {
            (DecisionAnswer::Noul(true), _) => ProjectDetectionAnswer::Yes,
            (DecisionAnswer::Abstain, true) => ProjectDetectionAnswer::AskedPerson,
            _ => {
                settle_project_detection(self.vault, claimed, lease_owner, None, Some(house))?;
                return Ok(ProjectDetectionRun::NotAProject);
            }
        };
        // Only a house agent that can run drafts; the yes is kept either way
        // unless the house was erased while the question ran (FIX 4977).
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
        // A source whose person was erased while the question ran keeps no
        // answer, and no drafter is sent for it (FIX 3520).
        if !settle_project_detection(
            self.vault,
            claimed,
            lease_owner,
            Some(&verdict),
            Some(house),
        )? {
            return Ok(ProjectDetectionRun::Unread);
        }
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
    /// when it is gone or withheld from it. The house reads a person's turn
    /// as the Dreamer does (`dreamer_consolidation/turn_text.rs`
    /// `message_reader`), as a vault-internal reader under the relationship
    /// gate: a MESSAGE that names a relationship or a private scope passes
    /// only on the house's own live grants, and one that names neither is
    /// the vault's own and reads. Under the access gate an agent with no
    /// grant reads no unscoped MESSAGE, so every question settled unread
    /// before it was asked.
    pub(super) fn source_text(
        &self,
        house: EntityId,
        source: &ProjectDetectionSource,
    ) -> Result<Option<String>> {
        let key = ScopedReadActorKey::with_actor_class(
            house.to_hex(),
            EdgeActorClass::Agent.gate_actor_class(),
        )
        .ok_or_else(|| Error::InvalidConfig("project question reader is not an actor".into()))?
        .require_relationship_grants(Some(house))
        .for_destination(&ReadDestination::on_device());
        let reader = self.vault.scoped_read(key);
        // The grant time is persisted before the snapshot opens, so a grant
        // that expired while the question waited is judged expired.
        let row = reader.with_grant_read_snapshot(|txn| {
            reader.get_entities_parts_in_txn(txn, std::slice::from_ref(&source.message))
        })?;
        let Some((kind, _, body)) = row.into_iter().next().flatten() else {
            return Ok(None);
        };
        if kind != ENTITY_TYPE_MESSAGE {
            return Ok(None);
        }
        Ok(message_content(&body).filter(|text| !text.is_empty()))
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
                .with_caller_origin(super::CallerOrigin::NativeHost)
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

/// The `content` string of a stored MESSAGE body: one MessagePack map whose
/// keys are not ordered (a document-backed row carries `content` last).
/// `None` for a body that is not one map, or that has no string `content`.
fn message_content(body: &[u8]) -> Option<String> {
    let mut cursor = body;
    let rmpv::Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    if !cursor.is_empty() {
        return None;
    }
    entries
        .into_iter()
        .find(|(key, _)| key.as_str() == Some("content"))
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}
