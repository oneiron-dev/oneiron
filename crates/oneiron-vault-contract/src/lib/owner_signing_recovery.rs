//! Owner-signing recovery (FIX 5260): an adopted vault proves, on its
//! supervisor's challenge, that it still holds the spawn token it was
//! started with, so a supervisor that restarted signs for the owner again
//! without waiting for the vault's next ledger push.
//!
//! The supervisor sends
//! [`CtlRequest::RecoverOwnerSigning`](crate::CtlRequest::RecoverOwnerSigning)
//! on ctl with a fresh challenge. The vault answers on the supervisor socket
//! its ledger pushes already go to: one [`OwnerSigningRecovery`] line, and one
//! [`OwnerSigningRecoveryAck`] line back. Then it answers the ctl request with
//! [`CtlResponse::OwnerSigningRecovered`](crate::CtlResponse::OwnerSigningRecovered),
//! which says whether the supervisor acked and carries nothing else. The token
//! never rides ctl or HTTP, and neither side stores it for this.

use serde::{Deserialize, Serialize};

use super::{TOKEN_LEN, TokenHex, valid_vault_name};

/// The proof's op discriminator.
pub const OWNER_SIGNING_RECOVERY_OP: &str = "owner_signing_recovery";

/// The challenge's length in bytes. It rides as twice as many lowercase hex
/// digits.
pub const OWNER_SIGNING_CHALLENGE_LEN: usize = 32;

/// Vault → supervisor, on the supervisor socket ledger pushes use: the proof
/// that answers one recovery challenge. `token` is the spawn token the vault
/// holds, on the channel that already carries it with every push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerSigningRecovery {
    pub op: String, // "owner_signing_recovery"
    pub vault: String,
    pub token: TokenHex,
    /// The challenge from the ctl request, echoed exactly.
    pub challenge: String,
}

impl OwnerSigningRecovery {
    /// Reject-not-truncate shape check: op discriminator, vault name, token
    /// shape and challenge shape. Supervisors call this immediately after
    /// parsing an untrusted proof.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == OWNER_SIGNING_RECOVERY_OP, "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        anyhow::ensure!(
            valid_owner_signing_challenge(&self.challenge),
            "malformed challenge"
        );
        Ok(())
    }
}

/// Supervisor → vault on the proof's connection: whether the supervisor took
/// the proof and signs for the owner again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerSigningRecoveryAck {
    pub recovered: bool,
}

/// Whether `challenge` is exactly [`OWNER_SIGNING_CHALLENGE_LEN`] bytes as
/// lowercase hex.
#[must_use]
pub fn valid_owner_signing_challenge(challenge: &str) -> bool {
    challenge.len() == OWNER_SIGNING_CHALLENGE_LEN * 2
        && challenge
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
