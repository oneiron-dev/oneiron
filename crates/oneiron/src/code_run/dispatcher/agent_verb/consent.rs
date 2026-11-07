//! Code mode's code consent call site, and the durable wait a held
//! `connector.call` or a held browser act parks its run on (DOOR-079 1a,
//! ONE-2510, FIX 10423).

use serde_json::Value;

use crate::EntityId;
use crate::code_run::ConnectorCallReply;
use crate::code_run::consent_wait::{self, CodeConsentCallSite};
use crate::code_run::payload::agent_verb_call_identity as call_identity;
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    SelfAgentVerbCall, SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
};
use crate::error::Result;
use crate::secret_custody::SECRET_USE_CONNECTOR_CALL;
use crate::task_verb::sdk::AgentVerb;

use super::super::{ExecutorCallSite, HostSelfDispatcher};
use super::SecretUseAnswer;

impl HostSelfDispatcher<'_> {
    /// Where a write a code consent wait may bind sits in the run (DOOR-079
    /// 1a): the wait id its write receipt and call identity fix, and the
    /// step, bridge position and write ordinal, all from the executor's own
    /// call site. `None` for a verb no code consent wait binds.
    pub(super) fn code_consent_site(
        &self,
        call: &SelfAgentVerbCall,
        site: ExecutorCallSite<'_>,
        ordinal: u64,
        receipt_id: EntityId,
    ) -> Result<Option<CodeConsentCallSite>> {
        if !consent_wait::code_consent_binds(call.verb) {
            return Ok(None);
        }
        let request_digest =
            *blake3::hash(&call_identity(call.verb.as_str(), &call.input)).as_bytes();
        Ok(Some(CodeConsentCallSite {
            wait_id: consent_wait::code_consent_wait_id(receipt_id, &request_digest)?,
            run_id: site.run_id,
            run_ref: self.run_ref.clone(),
            step_start: site.step_start,
            bridge_seq: site.seq,
            write_ordinal: ordinal,
            write_receipt_id: receipt_id,
            request_digest,
            origin: self.code_consent_origin.clone(),
        }))
    }

    /// A verb's answer as the run takes it, when a code consent wait may
    /// bind it: a held call its wait was bound to parks the run on that
    /// wait, which only its owner's answer and the effect's own gate settle.
    /// A browser call whose press held an act its host bound to the wait at
    /// this call's own site parks the same way (FIX 10423), whatever its
    /// answer said. Every other answer is [`connector_call_answer`]'s.
    pub(super) fn code_consent_answer(
        &self,
        consent_site: Option<&CodeConsentCallSite>,
        verb: AgentVerb,
        outcome: SelfDispatchOutcome,
    ) -> Result<SelfDispatchOutcome> {
        if let Some(consent_site) = consent_site
            && verb.is_browser()
            && let ExecutorStorage::Canonical(vault) = &self.storage
            && consent_wait::code_consent_binds_held_browser(vault, consent_site.wait_id)?
        {
            return Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: consent_site.wait_id,
                effect: SelfEffect::AgentVerb,
                reason: SelfDurableWaitReason::OutboundEffect,
                prompt: Some(format!("code_consent:{}", consent_site.wait_id.to_hex())),
            }));
        }
        if let (Some(consent_site), SelfDispatchOutcome::AgentVerb(answer)) =
            (consent_site, &outcome)
            && let Some(call_ref) = held_call_ref(verb, &answer.output)
            && let ExecutorStorage::Canonical(vault) = &self.storage
            && consent_wait::code_consent_binds_held_call(vault, consent_site.wait_id, call_ref)?
        {
            return Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: consent_site.wait_id,
                effect: SelfEffect::AgentVerb,
                reason: SelfDurableWaitReason::OutboundEffect,
                prompt: Some(format!("code_consent:{}", consent_site.wait_id.to_hex())),
            }));
        }
        Ok(connector_call_answer(verb, outcome))
    }
}

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
fn held_call_ref(verb: AgentVerb, output: &Value) -> Option<EntityId> {
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
