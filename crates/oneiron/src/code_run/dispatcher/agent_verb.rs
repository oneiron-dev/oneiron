//! Code mode's `self.memory.<verb>`: the run's write origin and the receipt a write keeps.

use crate::code_run::replay::{CodeRunBridgeCall, CodeRunDeterminism, CodeRunReplayRecord};
use crate::code_run::storage::derived_executor_id;
use crate::code_run::types::{
    AgentVerbRefusal, SelfAgentVerbCall, SelfCall, SelfDeniedResult, SelfDispatchOutcome,
    SelfDispatcher, SelfEffect,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::HostWriteOrigin;

use super::HostSelfDispatcher;

const AGENT_VERB_RECEIPT_DOMAIN: &[u8] = b"oneiron:executor-agent-verb-receipt:v1";

impl HostSelfDispatcher<'_> {
    /// A refused verb is the guest's to handle, like any typed refusal: it
    /// does not halt the run, and the verb's own gate owns its writes.
    ///
    /// Every call carries the run's host-owned write origin. A write at a
    /// durable run's bridge position also keeps its receipt under that
    /// position, reserved before the door runs: a step resumed after its write
    /// committed but before its checkpoint gets the first receipt back, and a
    /// write that may have committed without one fails closed, never repeats.
    pub(super) fn dispatch_agent_verb(
        &self,
        call: SelfAgentVerbCall,
        position: Option<(EntityId, u64)>,
    ) -> Result<SelfDispatchOutcome> {
        let Some(door) = &self.agent_verbs else {
            return Ok(answered(Err(AgentVerbRefusal {
                code: "agent_verb_door_unbound".to_owned(),
                message: "this run's host binds no SDK verb door".to_owned(),
            })));
        };
        let origin = HostWriteOrigin::new(
            self.agent_verb_envelope(call.verb, position.map(|(_, seq)| seq))?,
        );
        let Some((run_id, seq)) = position.filter(|_| call.verb.writes()) else {
            return Ok(answered(door.call(&call, &origin)));
        };
        let receipt_id = derived_executor_id(
            AGENT_VERB_RECEIPT_DOMAIN,
            &[
                self.run_ref.as_bytes(),
                run_id.as_bytes(),
                &seq.to_le_bytes(),
            ],
        )?;
        let bridge = SelfCall::AgentVerb(call.clone());
        if let Some(receipt) = self.storage.get_code_run_replay_record(&receipt_id)? {
            if receipt.bridge_calls.is_empty() {
                return Err(Error::ConcurrentWrite(
                    "agent verb write is in flight or needs reconciliation",
                ));
            }
            // The cursor refuses a different call at this position.
            return receipt.replay_cursor().dispatch(bridge);
        }
        let mut receipt = CodeRunReplayRecord::new(receipt_id, CodeRunDeterminism::new(0, [0; 32]));
        let generation = self
            .storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, None, None)?;
        let outcome = answered(door.call(&call, &origin));
        receipt
            .bridge_calls
            .push(CodeRunBridgeCall::record(0, &bridge, &outcome, 0, 0)?);
        self.storage
            .put_code_run_replay_record_if_generation_with_heal(&receipt, Some(generation), None)?;
        Ok(outcome)
    }
}

fn answered(
    outcome: std::result::Result<serde_json::Value, AgentVerbRefusal>,
) -> SelfDispatchOutcome {
    outcome.map_or_else(
        |refusal| {
            SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::AgentVerb,
                outcome: refusal.code,
                reason_codes: vec![refusal.message],
            })
        },
        SelfDispatchOutcome::AgentVerb,
    )
}
