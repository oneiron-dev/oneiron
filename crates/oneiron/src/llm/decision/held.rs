//! What a component that outlives one call holds to ask typed questions (a worker thread, a
//! provider a host keeps): the ladder's slots owned, and the call's bounded state.

use std::sync::Arc;

use super::types::invalid;
use super::{
    DecisionLadder, DecisionProvider, DecisionQuestion, DecisionRung, HumanDecisionQueue,
    HumanDecisionRequest, ProviderPin,
};
use crate::Result;

/// [`DecisionLadder`]'s slots, owned.
#[derive(Clone)]
pub struct HeldLadder {
    pub rule: Option<Arc<dyn DecisionProvider>>,
    pub local: Option<Arc<dyn DecisionProvider>>,
    pub system_one: Option<Arc<dyn DecisionProvider>>,
    pub escalation: Option<Arc<dyn DecisionProvider>>,
    pub big: Option<Arc<dyn DecisionProvider>>,
    pub human: Arc<dyn HumanDecisionQueue>,
    pub human_pin: ProviderPin,
    /// The host's paired question; see [`DecisionLadder::paired`].
    pub paired: Option<DecisionQuestion>,
    pub person: Option<DecisionQuestion>,
    /// The host's presence question; see [`DecisionLadder::presence`].
    pub presence: Option<DecisionQuestion>,
}

impl HeldLadder {
    /// A ladder with no provider in any slot and no person to ask: a caller's own read
    /// ([`super::GeneratedRung`]) is its one rung. A dial that reaches the person fails.
    #[must_use]
    pub fn unstaffed() -> Self {
        Self {
            rule: None,
            local: None,
            system_one: None,
            escalation: None,
            big: None,
            human: Arc::new(NoPerson),
            human_pin: ProviderPin {
                rung: DecisionRung::Human,
                model: "no-person".into(),
                version: "1".into(),
            },
            paired: None,
            person: None,
            presence: None,
        }
    }

    /// The ladder for one call, borrowing these slots.
    #[must_use]
    pub fn ladder(&self) -> DecisionLadder<'_> {
        DecisionLadder {
            rule: self.rule.as_deref(),
            local: self.local.as_deref(),
            system_one: self.system_one.as_deref(),
            escalation: self.escalation.as_deref(),
            big: self.big.as_deref(),
            human: self.human.as_ref(),
            human_pin: self.human_pin.clone(),
            ask_to: None,
            paired: self.paired.as_ref(),
            person: self.person.as_ref(),
            presence: self.presence.as_ref(),
            correlation: None,
        }
    }
}

/// The person queue of a host with no person to ask.
struct NoPerson;

impl HumanDecisionQueue for NoPerson {
    fn queue(&self, _: HumanDecisionRequest) -> Result<()> {
        Err(invalid("no person to ask"))
    }
}

pub use crate::model_decision::{cut_text, fit_reserve_state, fit_state, fit_state_with_budget};
