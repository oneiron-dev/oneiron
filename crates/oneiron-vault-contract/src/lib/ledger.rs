//! Vault-to-supervisor ledger push and ack wire types.

use serde::{Deserialize, Serialize};

use super::{TOKEN_LEN, TokenHex, WakeEntry, valid_vault_name, validate_wake_entries};

/// Vault → supervisor push on the shared supervisor socket. Token-authenticated,
/// rev-ordered, full replacement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerUpdate {
    pub op: String, // "ledger_update"
    pub vault: String,
    pub token: TokenHex,
    pub rev: u64,
    pub entries: Vec<WakeEntry>,
}

impl LedgerUpdate {
    /// Reject-not-truncate enforcement of the wire limits: op discriminator,
    /// vault name, token shape, entry count, per-entry bounds. Supervisors
    /// call this immediately after parsing an untrusted push.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == "ledger_update", "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        validate_wake_entries(&self.entries)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAck {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
