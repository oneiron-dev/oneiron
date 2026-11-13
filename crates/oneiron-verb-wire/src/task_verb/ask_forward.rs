//! Moved from `crates/oneiron/src/task_verb/ask_forward.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The holder's proof for one intent: their slip, and their signature over
/// the slip's binding transcript (`CapabilitySlip::binding_transcript`) of
/// [`ask_forward_challenge`]. It proves this one intent; the request that
/// carries it authenticates apart, as every request does (FIX 20468).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskForwardHolderProof {
    /// The holder's `v2.slip.` token.
    pub token: String,
    /// The holder's Ed25519 signature, 128 lowercase hex characters.
    pub signature: String,
}

/// Hand-written so the token cannot reach a log through a derive.
impl std::fmt::Debug for AskForwardHolderProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AskForwardHolderProof")
            .finish_non_exhaustive()
    }
}

impl AskForwardHolderProof {
    /// The signature's bytes: exactly 128 lowercase hex characters.
    fn signature_bytes(&self) -> Option<[u8; 64]> {
        holder_signature_bytes(&self.signature)
    }
}

/// A holder signature's bytes: exactly 128 lowercase hex characters.
pub fn holder_signature_bytes(signature: &str) -> Option<[u8; 64]> {
    let text = signature.as_bytes();
    if text.len() != 128 {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0_u8; 64];
    for (byte, pair) in bytes.iter_mut().zip(text.chunks_exact(2)) {
        let [high, low] = pair else {
            return None;
        };
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(bytes)
}
