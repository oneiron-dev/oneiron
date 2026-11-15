//! Moved from `crates/oneiron/src/store/healer_oversight.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;

pub const DOMAIN: &[u8] = b"oneiron:healer-oversight:v1\0";
