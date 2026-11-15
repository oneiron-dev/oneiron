//! Moved from `crates/oneiron/src/recovery/checkpoint/payload/seal.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use getrandom::SysRng;
use oneiron_base::error::Error;
use oneiron_crypto::seal;
use oneiron_store::key_custody::identity::CustodyKind;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub fn corrupt() -> Error {
    CustodyKind::CheckpointPayload.corrupt()
}
