//! Moved from `crates/oneiron/src/authority/forwarded_caller.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A caller's own holder proof, as its device forwards it: the slip token it
/// presented and the fields of the `x-oneiron-binding` header it signed,
/// unchanged. Not a credential of its own: the home verifies it again.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedCallerProof {
    /// The caller's `v2.slip.` token.
    pub token: String,
    /// The holder proof's signed timestamp.
    pub timestamp: u64,
    /// The holder proof's nonce: 32 lowercase hex characters.
    pub nonce: String,
    /// The holder's Ed25519 signature, 128 lowercase hex characters.
    pub signature: String,
}

/// Hand-written so the token cannot reach a log through a derive.
impl std::fmt::Debug for ForwardedCallerProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ForwardedCallerProof")
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}

/// The forwarding device's machine and its install key's signature over
/// [`forwarded_request_transcript`], in the [`MACHINE_PROOF_HEADER`] value's
/// encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardingMachineProof {
    /// The MACHINE id, canonical hex.
    pub machine: String,
    /// 128 lowercase hex characters.
    pub signature: String,
}
