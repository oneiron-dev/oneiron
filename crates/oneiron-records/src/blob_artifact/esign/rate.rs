//! Moved from `crates/oneiron/src/blob_artifact/esign/rate.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

pub fn unknown_esign_rate_verb() -> String {
    "unknown".to_owned()
}

pub fn unknown_esign_rate_actor_class() -> String {
    "unknown".to_owned()
}

/// Local per-window call count. A capability is never stored in this receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRateReceipt {
    pub document: String,
    pub recipient: Option<String>,
    pub window_started_at_secs: u64,
    pub count: u64,
    /// The call's verb and class; old mixed counter reads say "unknown".
    #[serde(default = "unknown_esign_rate_verb")]
    pub verb: String,
    #[serde(default = "unknown_esign_rate_actor_class")]
    pub actor_class: String,
    /// The verified actor id, or `None` for bearer-only or an id-less credential.
    #[serde(default)]
    pub actor: Option<String>,
}

/// OF-520 question at the first crossing of an advisory threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EsignRateCheck {
    pub receipt: EsignRateReceipt,
    pub threshold: u64,
    /// The `[limits]` row, by its config key, a signature upload or a signing
    /// door's request body crossed, when this check is that crossing and not
    /// a ceremony burst (FIX 3807, 3808): `threshold` is then the row's bound
    /// and `receipt.count` what the upload or body measured.
    #[serde(default)]
    pub limit: Option<String>,
}

impl EsignRateCheck {
    pub const KIND: &'static str = "esign_ceremony_burst";

    /// The kind of a signature upload's or a signing door body's `[limits]`
    /// crossing.
    pub const LIMIT_KIND: &'static str = "esign_signature_limit";
}
