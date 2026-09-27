//! O2 resolve-gate-window-execute dispatch pipeline: replay-first ledger contract,
//! gate decision, delivery-window door, connector execution, and receipt fields.

pub(super) mod admission;
mod effect;
mod frozen_payload;
mod govern;
mod pipeline;
mod policy_risk;
pub(super) mod retry_after;
pub(super) mod seat_policy;
mod sender_identity;
mod transport;
mod vault;
pub(super) mod verdict;

pub use self::pipeline::OutboundDispatchPipeline;
pub(super) use self::policy_risk::GATE_OUTCOME_PENDING;
pub(super) use self::retry_after::PROVIDER_RETRY_AFTER_FIELD;
pub(super) use sender_identity::enrich_dispatch_channel_identity;
pub(crate) use sender_identity::resolve_channel_identity_ref_for_connector;
