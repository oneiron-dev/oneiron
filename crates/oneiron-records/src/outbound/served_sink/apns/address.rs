//! Moved from `crates/oneiron/src/outbound/served_sink/apns/address.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::Serialize;

pub const ADDRESS_PREFIX: &str = "apns-address:";

pub const TARGET_PREFIX: &str = "apns-device:";
