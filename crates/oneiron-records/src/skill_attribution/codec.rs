//! Moved from `crates/oneiron/src/skill_attribution/codec.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(crate) use oneiron_store::skill_attribution::codec::*;
use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;
use std::io::Cursor;

pub const AUDIT_ROW_LABEL: &str = "skill attribution audit row";
