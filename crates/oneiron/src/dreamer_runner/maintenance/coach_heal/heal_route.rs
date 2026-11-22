//! The heal route and the ladder that asks the route question: what the
//! Coach proposes the agent needs, and the host principal, dial, bands,
//! wording and budget the answers run under.

use super::*;

/// What the Coach proposes the agent needs (ARCH-0066 #healer). The Coach
/// fixes the agent, never the task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealRoute {
    /// Edit the skill the agent ran.
    SkillEdit,
    /// Inject a prompt and fork-resume from the pre-fail checkpoint.
    PromptInject,
    /// Fix what the agent runs in: a tool, a grant, a connector.
    Environment,
    /// A person looks at it.
    Person,
}

impl HealRoute {
    const ALL: [Self; 4] = [
        Self::SkillEdit,
        Self::PromptInject,
        Self::Environment,
        Self::Person,
    ];

    /// The route's Choice option and proposal spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillEdit => "skill_edit",
            Self::PromptInject => "prompt_inject",
            Self::Environment => "environment",
            Self::Person => "person",
        }
    }

    pub(in crate::dreamer_runner::maintenance) fn parse(raw: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.as_str() == raw)
    }
}

/// The host's decision ladder for the route question: the principal the
/// answers are for, the dial and bands they run under, the host's wording,
/// and each question's own budget.
pub struct HealDecisions<'a> {
    pub ladder: DecisionLadder<'a>,
    pub principal: EntityId,
    pub dial: DecisionDial,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub budget: Duration,
}

impl HealDecisions<'_> {
    /// `Ok(None)`: the ladder answered off the contract.
    pub(in crate::dreamer_runner::maintenance) fn route(
        &self,
        about: &[u8],
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> Result<Option<HealRoute>> {
        let question = COACH_HEAL_ROUTE.question(
            &[about],
            self.wording.clone(),
            AnswerContract::Choice {
                options: HealRoute::ALL
                    .iter()
                    .map(|route| route.as_str().to_owned())
                    .collect(),
            },
        )?;
        let decision = self.ladder.run(
            &question,
            self.principal,
            evidence,
            state,
            self.dial,
            &self.bands,
            Reversibility::ReversibleRead,
            &RetrievalDeadline::hard(Instant::now(), self.budget),
        )?;
        Ok(match &decision.answer {
            DecisionAnswer::Choice(choice) => HealRoute::parse(choice),
            _ => None,
        })
    }

    /// The route and how it was reached. A failed or off-contract answer
    /// goes to a person.
    pub(super) fn route_or_person(
        &self,
        about: &[u8],
        evidence: &[EntityId],
        state: &serde_json::Value,
    ) -> (HealRoute, &'static str) {
        match self.route(about, evidence, state) {
            Ok(Some(route)) => (route, "ladder"),
            Ok(None) => (HealRoute::Person, "abstained"),
            Err(_) => (HealRoute::Person, "unanswered"),
        }
    }
}
