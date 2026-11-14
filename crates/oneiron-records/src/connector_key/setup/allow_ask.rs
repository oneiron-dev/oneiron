//! Moved from `crates/oneiron/src/connector_key/setup/allow_ask.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::setup::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Read;
use std::time::Duration;
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// One allow put to the owner: the ask's arrival number and exactly what a
/// yes allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSetupOwnerAsk {
    /// The ask's arrival number on the decision-ask queue.
    pub seq: u64,
    /// The owner door whose yes lands it.
    pub door: String,
    pub connection: String,
    /// The connection's permissions a yes allows, exactly: any other one
    /// allowed before is withdrawn.
    pub permissions: Vec<String>,
}
