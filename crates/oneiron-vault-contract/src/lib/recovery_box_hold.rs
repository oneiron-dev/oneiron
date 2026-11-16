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
//!
//! Two more ops go the same way (WAYBACK-WAIT-BINDS-HONEST-CLIENT-ONLY = B,
//! lead 17 Nov 00:1x): the box releases the recovery-authority seed only
//! after the vault's recovery wait, which the vault reports with
//! [`RecoveryBoxWait`] (answered by a [`RecoveryBoxKitOnlyAck`]-shaped ack),
//! and an owner device's cancel voids the box's pending release with
//! [`RecoveryBoxCancel`] (answered by a [`RecoveryBoxCancelAck`], which says
//! whether a release was pending). The cancel names who cancelled
//! ([`RecoveryBoxCancelledBy`]), which the box's receipt and the owner's
//! notice carry (WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B).

use serde::{Deserialize, Serialize};

use super::{TOKEN_LEN, TokenHex, valid_vault_name};

/// The requests' op discriminators.
pub const RECOVERY_BOX_KIT_ONLY_OP: &str = "recovery_box_kit_only";
pub const RECOVERY_BOX_WAIT_OP: &str = "recovery_box_wait";
pub const RECOVERY_BOX_CANCEL_OP: &str = "recovery_box_cancel";

/// The longest recovery wait the box takes, in seconds: 30 days.
pub const RECOVERY_BOX_WAIT_MAX_SECS: u64 = 30 * 24 * 3_600;

/// The longest refusal code an ack may carry.
pub const RECOVERY_BOX_REFUSAL_MAX: usize = 64;

/// The lowercase hex digits of a canceller's person id (an `EntityId`).
pub const RECOVERY_BOX_PERSON_HEX_LEN: usize = 32;

/// The lowercase hex digits of a canceller's device key (32 bytes).
pub const RECOVERY_BOX_DEVICE_KEY_HEX_LEN: usize = 64;

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
        validate_vault_and_token(&self.vault, &self.token)
    }
}

/// Vault → supervisor, on the same socket: the vault's recovery wait (the
/// owner Setting `recovery.wait`) in whole seconds, which the box's release
/// of the recovery-authority seed waits. Answered by a
/// [`RecoveryBoxKitOnlyAck`]-shaped ack: `held` when the box took it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxWait {
    pub op: String, // "recovery_box_wait"
    pub vault: String,
    pub token: TokenHex,
    /// 0 to [`RECOVERY_BOX_WAIT_MAX_SECS`].
    pub wait_secs: u64,
}

impl RecoveryBoxWait {
    /// As [`RecoveryBoxKitOnly::validate`], and the wait within its bound.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == RECOVERY_BOX_WAIT_OP, "unknown op");
        anyhow::ensure!(
            self.wait_secs <= RECOVERY_BOX_WAIT_MAX_SECS,
            "wait over 30 days"
        );
        validate_vault_and_token(&self.vault, &self.token)
    }
}

/// Vault → supervisor, on the same socket: an owner device's cancel of the
/// box's pending release of the recovery-authority seed. The vault sends it
/// only for an owner act it proved (a live owner key of the vault).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxCancel {
    pub op: String, // "recovery_box_cancel"
    pub vault: String,
    pub token: TokenHex,
    /// Who cancelled, as the vault proved it.
    pub cancelled_by: RecoveryBoxCancelledBy,
    /// The receipt number of the `recovery_started` act the owner's device
    /// saw: the box voids only the pending release that act started, so a
    /// replayed cancel voids no later one. Absent: whichever is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_receipt: Option<u64>,
}

impl RecoveryBoxCancel {
    /// As [`RecoveryBoxKitOnly::validate`], and the canceller's shape.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == RECOVERY_BOX_CANCEL_OP, "unknown op");
        self.cancelled_by.validate()?;
        validate_vault_and_token(&self.vault, &self.token)
    }
}

/// Who cancelled a pending release: the owner's person id and the owner
/// device key whose signed proof the vault checked. The box records both on
/// its cancel receipt and the owner's notice; it cannot check them itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxCancelledBy {
    /// [`RECOVERY_BOX_PERSON_HEX_LEN`] lowercase hex digits.
    pub person: String,
    /// [`RECOVERY_BOX_DEVICE_KEY_HEX_LEN`] lowercase hex digits.
    pub device_key: String,
}

impl RecoveryBoxCancelledBy {
    /// Reject-not-truncate shape check of both ids.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            oneiron_hex::is_lower_hex(&self.person, Some(RECOVERY_BOX_PERSON_HEX_LEN)),
            "malformed canceller person"
        );
        anyhow::ensure!(
            oneiron_hex::is_lower_hex(&self.device_key, Some(RECOVERY_BOX_DEVICE_KEY_HEX_LEN)),
            "malformed canceller device key"
        );
        Ok(())
    }
}

/// The vault name and spawn token shape every box op carries.
fn validate_vault_and_token(vault: &str, token: &TokenHex) -> anyhow::Result<()> {
    anyhow::ensure!(valid_vault_name(vault), "bad vault name");
    let t = token.expose();
    anyhow::ensure!(
        t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
        "malformed token"
    );
    Ok(())
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

/// Supervisor → vault for a [`RecoveryBoxCancel`]: `held` with `cancelled`
/// (whether a pending release was voided; false when none was pending, or
/// when the node has no control plane and so no box), or not held with
/// `error`, never the token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBoxCancelAck {
    pub held: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RecoveryBoxCancelAck {
    /// Whether the ack is one a vault may read: `held` with `cancelled` and
    /// no error, or not held with a refusal code and no `cancelled`.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        match (&self.held, &self.cancelled, &self.error) {
            (true, Some(_), None) => true,
            (false, None, Some(code)) => valid_recovery_box_refusal_code(code),
            _ => false,
        }
    }
}
