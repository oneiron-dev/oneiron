//! Moved from `crates/oneiron/src/lens/mediation/mediation_frame_write.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensGateWriteChokepoint {
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensHostImport {
    ScopedRead,
    ResolveBackingRef,
    EmitAtom,
    VaultWrite,
    BatchWrite,
    EvaluateGate,
    CheckClaimPolicyForWrite,
}

impl LensHostImport {
    #[must_use]
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::VaultWrite
                | Self::BatchWrite
                | Self::EvaluateGate
                | Self::CheckClaimPolicyForWrite
        )
    }
}
