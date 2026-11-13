//! Decision ladder person asks and the roles they go to.
//! Entry: HumanDecisionRequest.
//! Definitions: this module; the parent re-exports the old paths.

use super::ProviderDecision;
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    DecisionAnswer, DecisionQuestion, HumanAskReason, PersonChangedAnswer, ProviderPin,
};
use crate::{EntityId, Result as VaultResult};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::decision::ladder::roles::{
    AskTo, HumanDecisionRequest, ResolvedRole, RoleHolder,
};

pub trait HumanDecisionQueue: Send + Sync {
    fn queue(&self, request: HumanDecisionRequest) -> VaultResult<()>;

    /// [`Self::queue`] with the state the ladder's reads weighed (FIX 2424): the
    /// caller-scoped pack snapshot, built from the request's own evidence, so a holder
    /// answers over the same candidate values the model read. The arrival number when the
    /// queue numbers its asks. A queue that keeps no state queues the request as it is.
    fn queue_with_state(
        &self,
        request: HumanDecisionRequest,
        _state: &serde_json::Value,
    ) -> VaultResult<Option<u64>> {
        self.queue(request).map(|()| None)
    }

    /// [`Self::queue_with_state`] for an ask about one consent effect (FIX 2975): the
    /// queue keeps `consent` on the ask, with the owner's nearest reason on record
    /// pre-filled. A queue that keeps no consent queues the request as it is.
    fn queue_with_consent(
        &self,
        request: HumanDecisionRequest,
        state: Option<&serde_json::Value>,
        _consent: &super::AskConsent,
    ) -> VaultResult<Option<u64>> {
        match state {
            Some(state) => self.queue_with_state(request, state),
            None => self.queue(request).map(|()| None),
        }
    }
}

pub use crate::store::decision_ask_role::AskRole;

/// The host's role chain (Q3 by role): the next role an ask goes to.
pub trait AskRoleResolver: Send + Sync {
    /// The first role on `to`'s chain after `after` (from `to.role` when none), up to
    /// `to.ceiling`, with a live holder who may answer for `to.act`. None when no role up
    /// to the ceiling has one: the ask stays unresolved, never with wider authority.
    fn next_role(&self, to: &AskTo, after: Option<&AskRole>) -> VaultResult<Option<ResolvedRole>>;
}

pub use crate::model_decision::{AskAct, HolderKind, RoleRank};
