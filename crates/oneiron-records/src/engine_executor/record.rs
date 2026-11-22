//! Moved from `crates/oneiron/src/engine_executor/record.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::code_run::types::outcome::SelfDurableWaitReason;
use crate::engine_executor::types::EngineExecutorResult;
use oneiron_base::error::Error;

pub fn durable_wait_reason_str(reason: SelfDurableWaitReason) -> &'static str {
    match reason {
        SelfDurableWaitReason::HumanInput => "human_input",
        SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

pub fn durable_wait_reason_from_str(value: &str) -> EngineExecutorResult<SelfDurableWaitReason> {
    match value {
        "human_input" => Ok(SelfDurableWaitReason::HumanInput),
        "destructive_effect" => Ok(SelfDurableWaitReason::DestructiveEffect),
        "outbound_effect" => Ok(SelfDurableWaitReason::OutboundEffect),
        "peer_result" => Ok(SelfDurableWaitReason::PeerResult),
        _ => Err(Error::CorruptedIndex("executor replay durable wait reason").into()),
    }
}
