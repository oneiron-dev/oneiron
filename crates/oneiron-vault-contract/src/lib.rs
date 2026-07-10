//! Supervisor ⇄ vault child-process contract: wire types, credential framing,
//! limits. Both sides of the seam build against this crate so framing bugs
//! cannot diverge: the node supervisor (Hypnos) on one side, and every
//! vault-process implementation on the other (the engine's managed serve
//! mode, the conformance stub, or any self-hosted supervisor speaking the
//! same protocol).
//!
//! Versioning: crate SemVer and wire compatibility are separate things. The
//! wire is governed by [`CONTRACT_VERSION`]; any incompatible wire change
//! (new required field, new enum variant a peer must understand) bumps it.
//! Consumers pin this crate at an exact revision and run cross-repo
//! conformance before moving the pin.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub const CONTRACT_VERSION: u32 = 1;

/// Credentials fd carries exactly this many bytes: DEK(32) ‖ spawn-token(32).
pub const CREDENTIALS_LEN: usize = 64;
pub const DEK_LEN: usize = 32;
pub const TOKEN_LEN: usize = 32;

/// Wire limits. Violations are rejected, never truncated.
pub const MAX_CTL_LINE: usize = 64 * 1024;
pub const MAX_LEDGER_ENTRIES: usize = 128;
pub const MAX_REASON_TAG: usize = 64;

/// Ready byte written to the ready fd once both sockets are bound.
pub const READY_BYTE: u8 = 0x01;

/// Vault name = DNS label.
pub fn valid_vault_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Timestamps ride the wire as unix seconds (UTC by construction).
pub type UnixTs = u64;

pub fn now_ts() -> UnixTs {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    Exact { at: UnixTs },
    Window { start: UnixTs, end: UnixTs },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WakeEntry {
    /// Stable, vault-assigned id.
    pub id: String,
    pub at: Schedule,
    /// Opaque, ≤ MAX_REASON_TAG bytes.
    pub reason_tag: String,
}

impl WakeEntry {
    /// Concrete fire time. Window jitter: start + blake3-free stable hash of the
    /// vault name modulo width (pinned algorithm lives supervisor-side; this
    /// helper is only used by tests). Zero-width window = Exact(start).
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.id.is_empty() && self.id.len() <= 128, "bad entry id");
        anyhow::ensure!(self.reason_tag.len() <= MAX_REASON_TAG, "reason_tag too long");
        if let Schedule::Window { start, end } = self.at {
            anyhow::ensure!(end >= start, "window end < start");
        }
        Ok(())
    }
}

/// Requests the supervisor sends on the vault's ctl socket. One JSON line per
/// connection, one response line back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CtlRequest {
    PrepareReap,
    ReapAbort,
    AlarmDue { id: String, reason_tag: String },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CtlResponse {
    PrepareReap { quiescent: bool, ledger_rev: u64, next_wake: Vec<WakeEntry> },
    Ping { ok: bool, vault: String, pid: u32, contract_version: u32 },
    Ok { ok: bool },
}

/// Hex of the 32-byte spawn token. Debug is redacted so the value can never
/// reach logs through derived formatting; contents zeroized on drop.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct TokenHex(String);

impl TokenHex {
    pub fn new(hex: String) -> Self {
        Self(hex)
    }
    pub fn from_token(token: &[u8; TOKEN_LEN]) -> Self {
        Self(hex(token))
    }
    /// Deliberate accessor — the only way to read the value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for TokenHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenHex(<redacted>)")
    }
}

impl Drop for TokenHex {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAck {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Credentials as read by the vault process.
pub struct Credentials {
    pub dek: [u8; DEK_LEN],
    pub token: [u8; TOKEN_LEN],
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.dek.zeroize();
        self.token.zeroize();
    }
}

/// Vault side: read exactly CREDENTIALS_LEN bytes from the inherited fd,
/// verify EOF, fail loudly otherwise. Must be called before the data dir is
/// opened. `read_exact` loops internally; a trailing byte is fatal.
pub fn read_credentials(mut r: impl Read) -> anyhow::Result<Credentials> {
    let mut buf = [0u8; CREDENTIALS_LEN];
    r.read_exact(&mut buf).map_err(|e| anyhow::anyhow!("credentials short read: {e}"))?;
    let mut trailing = [0u8; 1];
    match r.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            buf.zeroize();
            anyhow::bail!("credentials fd carried trailing bytes");
        }
        Err(e) => {
            buf.zeroize();
            anyhow::bail!("credentials EOF check failed: {e}");
        }
    }
    let mut dek = [0u8; DEK_LEN];
    let mut token = [0u8; TOKEN_LEN];
    dek.copy_from_slice(&buf[..DEK_LEN]);
    token.copy_from_slice(&buf[DEK_LEN..]);
    buf.zeroize();
    Ok(Credentials { dek, token })
}

/// Supervisor side: write DEK ‖ token and close (drop) the write end.
pub fn write_credentials(mut w: impl Write, dek: &[u8; DEK_LEN], token: &[u8; TOKEN_LEN]) -> anyhow::Result<()> {
    let mut buf = [0u8; CREDENTIALS_LEN];
    buf[..DEK_LEN].copy_from_slice(dek);
    buf[DEK_LEN..].copy_from_slice(token);
    let res = w.write_all(&buf).and_then(|_| w.flush());
    buf.zeroize();
    res.map_err(|e| anyhow::anyhow!("credentials write: {e}"))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_roundtrip() {
        let dek = [7u8; DEK_LEN];
        let token = [9u8; TOKEN_LEN];
        let mut buf = Vec::new();
        write_credentials(&mut buf, &dek, &token).unwrap();
        assert_eq!(buf.len(), CREDENTIALS_LEN);
        let creds = read_credentials(&buf[..]).unwrap();
        assert_eq!(creds.dek, dek);
        assert_eq!(creds.token, token);
    }

    #[test]
    fn credentials_reject_short_and_long() {
        assert!(read_credentials(&[0u8; 63][..]).is_err());
        assert!(read_credentials(&[0u8; 65][..]).is_err());
    }

    #[test]
    fn token_debug_redacted() {
        let t = TokenHex::new("deadbeef".into());
        assert_eq!(format!("{t:?}"), "TokenHex(<redacted>)");
        assert_eq!(t.expose(), "deadbeef");
    }

    #[test]
    fn vault_names() {
        assert!(valid_vault_name("test-vault"));
        assert!(valid_vault_name("a"));
        assert!(!valid_vault_name(""));
        assert!(!valid_vault_name("-a"));
        assert!(!valid_vault_name("A"));
        assert!(!valid_vault_name("a.b"));
        assert!(!valid_vault_name(&"x".repeat(64)));
    }
}
