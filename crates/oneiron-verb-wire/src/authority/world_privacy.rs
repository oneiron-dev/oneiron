//! Moved from `crates/oneiron/src/authority/world_privacy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
pub use oneiron_base::machine_destination::Destination;
pub use oneiron_base::machine_destination::EffectiveRead;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::time::Instant;

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveModelOrder {
    Inherit,
    Ordered(Vec<String>),
    /// Concurrent edits named different orders.
    Conflicted,
}

/// One world's settings as the fold decides them.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub struct EffectiveWorldPrivacy {
    pub read: EffectiveRead,
    pub sealed: SealedCopies,
    pub models: EffectiveModelOrder,
}

impl Default for EffectiveWorldPrivacy {
    fn default() -> Self {
        PrivacyMeet::of(&WorldPrivacy::default()).effective()
    }
}

impl EffectiveWorldPrivacy {
    /// Any world under a conflicted vault root: readable nowhere, editable by
    /// no one, with no sealed copies and no model order.
    pub fn unknowable() -> Self {
        Self {
            read: EffectiveRead::Conflicted {
                contenders: BTreeSet::new(),
            },
            sealed: SealedCopies::Off,
            models: EffectiveModelOrder::Conflicted,
        }
    }
}
