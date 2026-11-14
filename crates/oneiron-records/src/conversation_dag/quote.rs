//! Moved from `crates/oneiron/src/conversation_dag/quote.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use rmpv::Value;
use std::collections::BTreeMap;

pub fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
