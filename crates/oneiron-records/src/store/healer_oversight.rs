//! Moved from `crates/oneiron/src/store/healer_oversight.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

pub const DOMAIN: &[u8] = b"oneiron:healer-oversight:v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversightKind {
    Coverage,
    ReviewLatency,
    EscalationRate,
}

impl OversightKind {
    fn tag(self) -> u8 {
        match self {
            Self::Coverage => 0,
            Self::ReviewLatency => 1,
            Self::EscalationRate => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightCounts {
    pub vault_device: u64,
    pub observed_at: u64,
    pub kind: OversightKind,
    pub proposed: u64,
    pub reviewed: u64,
    pub escalated: u64,
    pub review_latency_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightReceipt {
    pub counts: OversightCounts,
    pub signer: [u8; 32],
    pub signature: Vec<u8>,
}

impl OversightReceipt {
    pub fn verify(&self, expected_signer: &[u8; 32]) -> bool {
        if &self.signer != expected_signer {
            return false;
        }
        let Ok(key) = VerifyingKey::from_bytes(expected_signer) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        let Ok(bytes) = signed_bytes(&self.counts) else {
            return false;
        };
        key.verify_strict(&bytes, &signature).is_ok()
    }
}

pub fn signed_bytes(counts: &OversightCounts) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(
        rmp_serde::to_vec_named(counts).map_err(|_| Error::CorruptedIndex("healer oversight"))?,
    );
    Ok(bytes)
}
