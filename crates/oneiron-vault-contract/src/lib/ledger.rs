//! Vault-to-supervisor ledger push and ack wire types.

use serde::{Deserialize, Serialize};

use super::{LedgerPage, LedgerReportHead, TOKEN_LEN, TokenHex, valid_vault_name};

/// Vault → supervisor push on the shared supervisor socket: one page of a
/// rev-ordered, full-replacement report ([`LedgerPage`], FIX 9549).
/// Token-authenticated: every page
/// carries the token, and a report's pages go in order on one connection,
/// each answered by a [`LedgerAck`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerUpdate {
    pub op: String, // "ledger_update"
    pub vault: String,
    pub token: TokenHex,
    /// The page, the vault's live training setting in it (contract v3): a
    /// page that carries none is refused, never read as off.
    pub page: LedgerPage,
}

impl LedgerUpdate {
    /// Reject-not-truncate enforcement of the wire limits: op discriminator,
    /// vault name, token shape, and the page's shape ([`LedgerPage::validate`]:
    /// its digest and offset, its entry count for that offset, per-entry
    /// bounds, the training setting's shape). Supervisors call this
    /// immediately after parsing an untrusted push.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.op == "ledger_update", "unknown op");
        anyhow::ensure!(valid_vault_name(&self.vault), "bad vault name");
        let t = self.token.expose();
        anyhow::ensure!(
            t.len() == TOKEN_LEN * 2 && t.bytes().all(|b| b.is_ascii_hexdigit()),
            "malformed token"
        );
        self.page.validate()
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
pub(super) fn lowercase_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The supervisor's answer to one [`LedgerUpdate`] page: a receipt, and on
/// the report's last page, whether the report is committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAck {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The report the answered page belongs to; `null` only when the line
    /// named none the supervisor could read.
    #[serde(deserialize_with = "Option::deserialize")]
    pub report: Option<LedgerReportHead>,
    /// The answered page's offset; `null` as `report` is.
    #[serde(deserialize_with = "Option::deserialize")]
    pub offset: Option<u64>,
    /// True only on the answer to a report's last page, once the supervisor
    /// holds that report, or a later revision, durably. A page's receipt is
    /// never a commit.
    pub committed: bool,
}
