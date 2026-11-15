//! Moved from `crates/oneiron/src/channel_identity_provider/stalwart/send.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;

pub const NATIVE_MAIL_MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
