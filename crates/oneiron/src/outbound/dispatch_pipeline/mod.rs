//! O2 resolve-gate-window-execute dispatch pipeline: replay-first ledger contract,
//! gate decision, delivery-window door, connector execution, and receipt fields.

mod frozen_payload;
mod pipeline;
mod policy_risk;
mod retry_after;
mod sender_identity;
mod transport;
mod vault;

pub use self::pipeline::OutboundDispatchPipeline;
pub(crate) use self::policy_risk::GATE_OUTCOME_PENDING;
pub(crate) use self::retry_after::PROVIDER_RETRY_AFTER_FIELD;
pub(crate) use sender_identity::enrich_dispatch_channel_identity;
#[cfg(test)]
pub(crate) use sender_identity::resolve_channel_identity_ref_for_connector;
