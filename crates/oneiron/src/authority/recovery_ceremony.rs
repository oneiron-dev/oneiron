//! Explicit genesis recovery-secret acknowledgement and its visible fragile flag.
use super::*;
use crate::error::Result;

/// Visible setup warning until a dismissed backup step gains a second device.
pub const GENESIS_FRAGILE_FLAG: &str = "GENESIS_FRAGILE";

/// Mandatory genesis step. Only a one-way commitment enters the authority log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisRecoveryStep {
    /// The owner acknowledged saving the recovery secret.
    Saved([u8; 32]),
    /// The owner explicitly dismissed saving it; setup remains visibly fragile.
    Dismissed([u8; 32]),
}
impl GenesisRecoveryStep {
    /// Commits the vault-scoped secret without storing its bytes.
    pub fn acknowledge(secret: &[u8; 32], saved: bool) -> Result<Self> {
        if secret == &[0; 32] {
            return Err(invalid_authority());
        }
        let commitment = blake3::derive_key("oneiron/genesis-recovery-secret/v1", secret);
        Ok(if saved {
            Self::Saved(commitment)
        } else {
            Self::Dismissed(commitment)
        })
    }
    pub(super) fn commitment(&self) -> [u8; 32] {
        match self {
            Self::Saved(c) | Self::Dismissed(c) => *c,
        }
    }
    pub(super) fn dismissed(&self) -> bool {
        matches!(self, Self::Dismissed(_))
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self.commitment() == [0; 32] {
            Err(invalid_authority())
        } else {
            Ok(())
        }
    }
}
