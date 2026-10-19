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
    /// The vault's live training setting, reported with every push (contract
    /// v3). A push that carries none is refused, never read as off.
    pub training: ManagedTrainingSetting,
}

impl LedgerUpdate {
    /// Reject-not-truncate enforcement of the wire limits: op discriminator,
    /// vault name, token shape, entry count, per-entry bounds, the training
    /// setting's shape. Supervisors call this immediately after parsing an
    /// untrusted push.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == "ledger_update", "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        validate_wake_entries(&self.entries)?;
        self.training.validate()
    }
}

/// The vault's live "Learn from my conversations" setting, as the vault reads
/// it (contract v3): what its supervisor keeps, so a status read there shows
/// it without waking the vault. Read-only status: it names no actor and
/// grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedTrainingSetting {
    /// Whether the vault's conversations count for training now. No choice,
    /// an off and conflicting choices all read as off.
    pub on: bool,
    /// Whether people may leave their own messages out now; never true while
    /// `on` is false.
    pub allow_opt_out: bool,
    /// The setting's revision: the digest of its live choices, 64 lowercase
    /// hex, all zeros while none is live. A digest, not a counter.
    pub revision: String,
    /// The PERSON whose act the choice in force is, 32 lowercase hex; null
    /// while none counts, or when the vault does not hold that act's row.
    pub set_by: Option<String>,
}

impl ManagedTrainingSetting {
    /// Shape check: the revision is 64 lowercase hex and `set_by`, when
    /// present, 32 lowercase hex.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            lowercase_hex(&self.revision, 64),
            "malformed training revision"
        );
        if let Some(set_by) = &self.set_by {
            anyhow::ensure!(lowercase_hex(set_by, 32), "malformed training set_by");
        }
        Ok(())
    }
}

/// Whether `value` is exactly `len` lowercase hex digits.
fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAck {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
