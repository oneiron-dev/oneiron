//! Moved from `crates/oneiron/src/dreamer_wake/policy/observation.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_wake::policy::*;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WakeCadenceRequest {}
