//! Moved from `crates/oneiron/src/policy_model/request.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("policy.classify.subject")]
pub enum PolicyClassifySubject {
    OutboundContent,
    Action,
}
