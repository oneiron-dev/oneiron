//! Stable invocation identity across transport wrappers and runtime hooks.

use serde::{Deserialize, Serialize};

/// One logical verb's id, minted once where the call enters and passed
/// across transport wrappers and internal dispatch (review fix M7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvocationId(pub [u8; 16]);

impl InvocationId {
    /// A fresh id for a call that carried none.
    #[must_use]
    pub fn mint() -> Self {
        Self(*uuid::Uuid::now_v7().as_bytes())
    }

    /// The id of one code-mode step: the same across replays of the run, so
    /// a retried step finds its saved Ask continuation.
    #[must_use]
    pub fn of_run_step(run_id: &[u8], seq: u64) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key("oneiron runtime hook invocation v1");
        hasher.update(run_id);
        hasher.update(&seq.to_le_bytes());
        let mut id = [0; 16];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self(id)
    }

    /// 32 lowercase hex digits.
    #[must_use]
    pub fn to_hex(self) -> String {
        uuid::Uuid::from_bytes(self.0).simple().to_string()
    }

    /// Parses [`Self::to_hex`]; `None` for anything else.
    #[must_use]
    pub fn parse_hex(text: &str) -> Option<Self> {
        if text.len() != 32 {
            return None;
        }
        uuid::Uuid::try_parse(text)
            .ok()
            .map(|id| Self(id.into_bytes()))
    }
}
