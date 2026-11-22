//! One owner key change on a hosted vault, reported to its supervisor
//! (Engine ruling 21 Nov 06:00: every owner key change on a hosted vault is
//! reported by the hosted server to the control plane, which emails the
//! account's owner).
//!
//! The report goes to the supervisor socket the wake ledger already pushes
//! to, on a connection of its own: one [`OwnerKeyChangeReport`] line, and
//! one [`OwnerKeyChangeReportAck`] line back. The supervisor proves it as it
//! proves a push (the peer's UID, then the spawn token's digest against the
//! live generation) and forwards the change to the control plane under the
//! vault's placement. The token rides no other channel and neither side
//! stores it for this.
//!
//! The report names the change's authority entry hash, the change kind, the
//! key's shape and the signer-claimed time alone: no public key, machine id
//! or name. The engine never learns the address the control plane emails.
//!
//! A supervisor built before this op reads the line as a ledger page and
//! refuses it, and so does a vault VM's helper until it passes the op: the
//! vault reads any answer other than `reported: true` as a failure, so the
//! change stays unreported and goes out again on the next sweep.

use serde::{Deserialize, Deserializer, Serialize};

use super::{TOKEN_LEN, TokenHex, valid_vault_name};

/// The request's op discriminator.
pub const OWNER_KEY_CHANGE_OP: &str = "owner_key_change";

/// The longest refusal code an ack may carry.
pub const OWNER_KEY_CHANGE_REFUSAL_MAX: usize = 64;

/// The largest `at` the wire carries: 2^53 - 1, the largest integer every
/// JSON reader holds exactly.
pub const OWNER_KEY_CHANGE_AT_MAX: u64 = (1 << 53) - 1;

/// The `at` a vault sends for an entry whose signer claimed the unix time
/// `claimed`: the claim, or [`OWNER_KEY_CHANGE_AT_MAX`] for a claim above
/// it. The authority format admits any u64 claim, and the time is only the
/// signer's claim: the control plane keeps it and mails every new entry
/// whatever it says. So a claim past the wire's range still reports its
/// change, which a signer could otherwise keep from ever being mailed.
#[must_use]
pub fn owner_key_change_wire_at(claimed: u64) -> u64 {
    claimed.min(OWNER_KEY_CHANGE_AT_MAX)
}

/// Vault → supervisor, on the supervisor socket ledger pushes use: one owner
/// key change of this vault. `token` is the spawn token the vault holds, on
/// the channel that already carries it with every push. `entry` is the
/// change's authority entry hash; `change` is what happened (`enrolled`,
/// `confirmed`, `removed`, `removed_by_ended_key`, `removed_in_conflict`,
/// `bound_by_passkey`, `bound_by_device_key`); `key` is the shape of the key
/// the change names (`device_key`, `passkey`, `recovery_authority`); `at` is
/// the entry's signer-claimed unix time in seconds, as
/// [`owner_key_change_wire_at`] carries it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerKeyChangeReport {
    pub op: String, // "owner_key_change"
    pub vault: String,
    pub token: TokenHex,
    pub entry: String,
    pub change: String,
    pub key: String,
    pub at: u64,
}

impl OwnerKeyChangeReport {
    /// Reject-not-truncate shape check: op discriminator, vault name, token
    /// shape, entry hash shape, change and key names, and the signer-claimed
    /// time's range. Supervisors call this immediately after parsing an
    /// untrusted request; vaults call it before sending one.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == OWNER_KEY_CHANGE_OP, "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        anyhow::ensure!(valid_entry_hex(&self.entry), "malformed entry");
        anyhow::ensure!(
            matches!(
                self.change.as_str(),
                "enrolled"
                    | "confirmed"
                    | "removed"
                    | "removed_by_ended_key"
                    | "removed_in_conflict"
                    | "bound_by_passkey"
                    | "bound_by_device_key"
            ),
            "unknown change"
        );
        anyhow::ensure!(
            matches!(
                self.key.as_str(),
                "device_key" | "passkey" | "recovery_authority"
            ),
            "unknown key"
        );
        anyhow::ensure!(self.at <= OWNER_KEY_CHANGE_AT_MAX, "at out of range");
        Ok(())
    }
}

/// Whether `entry` is an authority entry hash as the wire carries it: 64
/// lowercase hex.
fn valid_entry_hex(entry: &str) -> bool {
    entry.len() == 64
        && entry
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

/// Supervisor → vault on the request's connection. `reported` is true only
/// when the control plane took the change; otherwise `error` names why,
/// never the token. `error` is absent or a string: a `null` is no absence,
/// so `{"reported":true,"error":null}` does not read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerKeyChangeReportAck {
    pub reported: bool,
    #[serde(
        default,
        deserialize_with = "present_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<String>,
}

/// A field that, when present, must be a string: only its absence reads as
/// `None` (through `default`).
fn present_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

impl OwnerKeyChangeReportAck {
    /// Whether the ack is one a vault may read: `reported` with no error, or
    /// not reported with a refusal code of at most
    /// [`OWNER_KEY_CHANGE_REFUSAL_MAX`] lowercase letters, digits and
    /// underscores.
    #[must_use]
    pub fn well_formed(&self) -> bool {
        match (&self.reported, &self.error) {
            (true, None) => true,
            (false, Some(code)) => valid_owner_key_change_refusal_code(code),
            _ => false,
        }
    }
}

/// Whether `code` is a refusal code an ack may carry.
#[must_use]
pub fn valid_owner_key_change_refusal_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= OWNER_KEY_CHANGE_REFUSAL_MAX
        && code
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}
