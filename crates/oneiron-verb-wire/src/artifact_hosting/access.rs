//! Moved from `crates/oneiron/src/artifact_hosting/access.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::artifact_hosting::*;
use heed::RwTxn;
use rand_core::OsRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub fn link_digest(token: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("oneiron artifact link token v1", token)
}
