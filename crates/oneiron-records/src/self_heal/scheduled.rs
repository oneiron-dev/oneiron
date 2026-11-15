//! Moved from `crates/oneiron/src/self_heal/scheduled.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::self_heal::tripwires::policy::TripwirePolicyReceipt;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDetectorRun {
    pub instance: String,
    pub run_ref: String,
    pub public_key: [u8; 32],
    pub event_bodies: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
    /// The tripwire policy the run's detectors read, as it was resolved
    /// (FIX 10096); `None` for a run that read none. Signed with the run.
    pub policy: Option<TripwirePolicyReceipt>,
}

impl SignedDetectorRun {
    fn transcript(&self) -> Result<Vec<u8>> {
        let mut out = b"oneiron/self-heal/detector-run/v1".to_vec();
        for bytes in [
            self.instance.as_bytes(),
            self.run_ref.as_bytes(),
            &self.public_key,
        ] {
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(&(self.event_bodies.len() as u64).to_be_bytes());
        for body in &self.event_bodies {
            out.extend_from_slice(&(body.len() as u64).to_be_bytes());
            out.extend_from_slice(body);
        }
        // A run with no policy signs exactly what it signed before.
        if let Some(policy) = &self.policy {
            let bytes = policy.transcript_bytes()?;
            out.extend_from_slice(b"policy");
            out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
}
