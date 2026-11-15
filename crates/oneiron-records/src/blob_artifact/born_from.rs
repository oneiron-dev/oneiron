//! Moved from `crates/oneiron/src/blob_artifact/born_from.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

pub const SOURCE_TASK: u8 = b't';

pub const SOURCE_ASK: u8 = b'a';

pub const SOURCE_CODE_RUN: u8 = b'c';

pub const SOURCE_SKILL: u8 = b's';

pub const SOURCE_AGENT_RUN: u8 = b'r';
