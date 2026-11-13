//! Moved from `crates/oneiron/src/authority/handoff_equivocation.rs` (lib split W2: wire types below the lib).
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
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Instant;

/// The saved fork alarm for one key a held handoff retired: the refused row
/// that raised it and the handoffs the key signed. It stays until the vault's
/// owner acknowledges it; a refused row the owner has not seen raises it again.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffAlarm {
    /// The retired key, `suite:hex`.
    pub signer: String,
    /// The refused row's hash, hex.
    pub refused: String,
    /// The held handoffs the key signed, hex.
    pub handoffs: Vec<String>,
    pub raised_at: u64,
    pub acknowledged: Option<AuthorityHandoffAlarmAck>,
    /// Refused rows the owner has acknowledged.
    pub seen: BTreeSet<String>,
}

/// Who acknowledged an alarm, and when.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHandoffAlarmAck {
    pub by: String,
    pub at: u64,
}
