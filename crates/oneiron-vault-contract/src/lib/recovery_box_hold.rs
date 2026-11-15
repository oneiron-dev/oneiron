//! The kit-only hold on a hosted vault's recovery box (Fable pass 27 R7;
//! Engine RULING WAYBACK-BOX-HOLD-RELAY = A, 16 Nov 01:02).
//!
//! The box lives on the control plane, behind the node's bearer, which a
//! vault never holds. When the owner's recovery preset enters "Nobody but
//! me" the vault asks its supervisor to hold the box kit-only (the deposit
//! is withdrawn and every enrol is refused while the hold stands), and when
//! it leaves that preset, to lift the hold. The ask goes to the supervisor
//! socket its ledger pushes already go to, on a connection of its own: one
//! [`RecoveryBoxKitOnly`] line, and one [`RecoveryBoxKitOnlyAck`] line back.
//! The supervisor proves it as it proves a push (the peer's UID, then the
//! spawn token's digest against the live generation) and forwards the
//! choice to the control plane under the vault's placement. The token rides
//! no other channel and neither side stores it for this.
//!
//! A supervisor built before this op reads the line as a ledger page and
//! refuses it, and so does a vault VM's helper until it passes the op: the
//! vault reads any answer other than `held: true` as a refusal, so its
//! preset switch fails closed.

use serde::{Deserialize, Serialize};

use super::{TOKEN_LEN, TokenHex, valid_vault_name};

/// The request's op discriminator.
pub const RECOVERY_BOX_KIT_ONLY_OP: &str = "recovery_box_kit_only";

/// The longest refusal code an ack may carry.
pub const RECOVERY_BOX_REFUSAL_MAX: usize = 64;

/// Vault → supervisor, on the supervisor socket ledger pushes use: the
/// owner's kit-only choice for this vault's recovery box. `token` is the
/// spawn token the vault holds, on the channel that already carries it with
/// every push.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxKitOnly {
    pub op: String, // "recovery_box_kit_only"
    pub vault: String,
    pub token: TokenHex,
    /// True when the vault enters a kit-only preset, false when it leaves.
    pub kit_only: bool,
}

impl RecoveryBoxKitOnly {
    /// Reject-not-truncate shape check: op discriminator, vault name and
    /// token shape. Supervisors call this immediately after parsing an
    /// untrusted request; vaults call it before sending one.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == RECOVERY_BOX_KIT_ONLY_OP, "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        Ok(())
    }
}

/// Supervisor → vault on the request's connection. `held` is true only when
/// the control plane took the choice (or the node has no control plane, so
/// no box); otherwise `error` names why, never the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxKitOnlyAck {
    pub held: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RecoveryBoxKitOnlyAck {
    /// Whether the ack is one a vault may read: `held` with no error, or not
    /// held with a refusal code of at most [`RECOVERY_BOX_REFUSAL_MAX`]
    /// lowercase letters, digits and underscores.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        match (&self.held, &self.error) {
            (true, None) => true,
            (false, Some(code)) => valid_recovery_box_refusal_code(code),
            _ => false,
        }
    }
}

/// Whether `code` is a refusal code an ack may carry.
#[must_use]
pub fn valid_recovery_box_refusal_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= RECOVERY_BOX_REFUSAL_MAX
        && code
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}
