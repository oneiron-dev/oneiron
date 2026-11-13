//! Moved from `crates/oneiron/src/authority/owner_act.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Instant;

/// What an owner act's commit did about the key work that follows it (mesh
/// contract §5, the honest receipt). Only a holder opens, mints or rewraps a
/// key: a carrier that holds none records the decision, and its receipt says
/// so, never "done".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyWork {
    /// The decision is recorded and needs no key work: the world reads
    /// everywhere, so no key counts for it.
    Recorded,
    /// The decision is recorded, and a holder still has to mint or rewrap
    /// the key: this install may not read the world, or holds no wrap of
    /// its current key.
    AwaitingHolder,
    /// The decision is recorded and this install did the key work in the
    /// same commit: it minted the world's first key, wrapped the current key
    /// to the readers that lacked it, or found every reader holding it.
    Enacted,
}
