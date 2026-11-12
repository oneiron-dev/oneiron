//! Moved from `crates/oneiron/src/connector_key/lifecycle/proxy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde_json::json;
use std::collections::BTreeMap;

/// The connector the OpenAI proxy registers as.
pub const PROXY_CONNECTOR: &str = "openai_proxy";
