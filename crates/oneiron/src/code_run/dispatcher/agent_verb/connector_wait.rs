//! A connector call's answer as a run takes it (ONE-2510): one held or
//! retried parks the run on the call's ref.

use serde_json::Value;

use super::SecretUseAnswer;
use crate::EntityId;
use crate::code_run::ConnectorCallReply;
use crate::code_run::types::{
    SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
};
use crate::secret_custody::SECRET_USE_CONNECTOR_CALL;
use crate::task_verb::sdk::AgentVerb;

/// `connector.call`'s answer as the run takes it (ONE-2510): a call held for
/// consent or governance, or a delivery the same send retries, parks the run
/// on the call's ref as an outbound-effect wait, which the connector settler
/// answers with the call's settled reply. `self.use`'s `connector.call`
/// parks the same way on the call its answer holds (OF-560). Any other
/// answer, and any other verb's, stands.
pub(super) fn connector_call_answer(
    verb: AgentVerb,
    outcome: SelfDispatchOutcome,
) -> SelfDispatchOutcome {
    let wait_id = match &outcome {
        SelfDispatchOutcome::AgentVerb(answer) => held_call_ref(verb, &answer.output),
        _ => None,
    };
    let Some(wait_id) = wait_id else {
        return outcome;
    };
    SelfDispatchOutcome::DurableWait(SelfDurableWait {
        wait_id,
        effect: SelfEffect::AgentVerb,
        reason: SelfDurableWaitReason::OutboundEffect,
        prompt: Some(format!("connector_call:{}", wait_id.to_hex())),
    })
}

/// The ref of the connector call a verb's answer holds or retries: a
/// `connector.call` reply's, or the one inside a `self.use` answer whose
/// operation was `connector.call`.
pub(super) fn held_call_ref(verb: AgentVerb, output: &Value) -> Option<EntityId> {
    let reply = match verb {
        AgentVerb::ConnectorCall => output.clone(),
        AgentVerb::SelfUse => {
            let answer = serde_json::from_value::<SecretUseAnswer>(output.clone()).ok()?;
            if answer.receipt.operation != SECRET_USE_CONNECTOR_CALL {
                return None;
            }
            answer.result?
        }
        _ => return None,
    };
    serde_json::from_value::<ConnectorCallReply>(reply)
        .ok()?
        .wait_ref()
}
