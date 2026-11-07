//! The supervisor-pinned public recipient for checkpoint host-order members.
//!
//! Managed process starts receive one JSON object on their own inherited
//! pipe, followed by EOF. A vault VM receives the same object in its provision
//! prelude; its bootstrap passes it to the engine on that pipe. The engine
//! checks the full ONHB bundle and its pinned fingerprint before using it.

use serde::{Deserialize, Serialize};

/// Public material, never the recipient's private key. The supervisor pins
/// this binding; an owner setting or an untrusted caller cannot supply it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHostHoldsRecipient {
    /// The standard-base64 ONHB public bundle, including its nonzero epoch.
    pub bundle_b64: String,
    /// SHA-256 of the exact decoded bundle, as 64 hexadecimal digits.
    pub fingerprint: String,
}

impl std::fmt::Debug for CheckpointHostHoldsRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckpointHostHoldsRecipient(..)")
    }
}
