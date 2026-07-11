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
pub const MAX_WAKE_ID: usize = 128;

/// Ready byte written to the ready fd once both sockets are bound.
pub const READY_BYTE: u8 = 0x01;

/// Vault name = DNS label.
pub fn valid_vault_name(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b[b.len() - 1] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Timestamps ride the wire as unix seconds (UTC by construction).
pub type UnixTs = u64;

pub fn now_ts() -> UnixTs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
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

/// Shared id/reason_tag bounds for anything carrying wake fields — ledger
/// entries and `alarm_due` requests alike. Control bytes (< 0x20) are
/// rejected: serde_json escapes each as a 6-char `\u00XX`, which would let a
/// bounds-valid entry list serialize past [`MAX_CTL_LINE`] (the worst
/// remaining expansion is the 2-char escapes for `"` and `\`, which the
/// `max_valid_wake_list_fits_ctl_line` test proves stays under the cap).
fn validate_wake_fields(id: &str, reason_tag: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!id.is_empty() && id.len() <= MAX_WAKE_ID, "bad entry id");
    anyhow::ensure!(!id.bytes().any(|b| b < 0x20), "control bytes in entry id");
    anyhow::ensure!(reason_tag.len() <= MAX_REASON_TAG, "reason_tag too long");
    anyhow::ensure!(
        !reason_tag.bytes().any(|b| b < 0x20),
        "control bytes in reason_tag"
    );
    Ok(())
}

impl WakeEntry {
    /// Bounds checks only (id length/charset, reason_tag length/charset,
    /// window ordering). Concrete fire-time selection and window jitter live
    /// supervisor-side.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_wake_fields(&self.id, &self.reason_tag)?;
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
    /// Fields carry the same bounds as [`WakeEntry`]; vaults must run
    /// [`CtlRequest::validate`] after parsing — deserialization alone does
    /// not enforce the wire limits.
    AlarmDue {
        id: String,
        reason_tag: String,
    },
    Ping,
}

impl CtlRequest {
    /// Vault-side reject-not-truncate enforcement: `alarm_due` fields share
    /// the [`WakeEntry`] bounds; the other variants carry no fields. Vaults
    /// call this immediately after parsing a ctl line.
    pub fn validate(&self) -> anyhow::Result<()> {
        if let CtlRequest::AlarmDue { id, reason_tag } = self {
            validate_wake_fields(id, reason_tag)?;
        }
        Ok(())
    }
}

/// Untagged: variant selection is structural, tried in declaration order.
/// INVARIANT: each variant's required-field set must stay disjoint from every
/// variant above it, and new variants are appended last — otherwise a
/// malformed reply can silently match a later, more permissive variant
/// (e.g. `Ok`). Supervisors that need strict rejection should deserialize the
/// concrete response shape they expect for the request they sent. Tagging
/// this enum is a wire break — contract v2 material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CtlResponse {
    /// Supervisors must run [`validate_wake_entries`] on `next_wake` before
    /// trusting it — deserialization alone does not enforce the wire limits.
    PrepareReap {
        quiescent: bool,
        ledger_rev: u64,
        next_wake: Vec<WakeEntry>,
    },
    Ping {
        ok: bool,
        vault: String,
        pid: u32,
        contract_version: u32,
    },
    Ok {
        ok: bool,
    },
}

/// Hex of the 32-byte spawn token. Debug is redacted so the value can never
/// reach logs through derived formatting; contents zeroized on drop.
/// Deliberately does NOT implement `PartialEq` — `String` equality exits on
/// the first mismatched byte and leaks prefix timing of the expected token
/// to a guessing client. Compare with [`TokenHex::ct_eq`] (or compare
/// digests, as Hypnos does).
#[derive(Clone, Serialize, Deserialize)]
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
    /// Constant-time equality over the decoded token bytes (hex case does
    /// not matter), via [`subtle`]. Malformed hex on either side compares
    /// unequal. Decode cost depends only on the caller's own inputs, never
    /// on where the first differing byte sits; length is not secret.
    pub fn ct_eq(&self, other: &TokenHex) -> bool {
        // Zeroizing: decoded token bytes are wiped on every path, including
        // when only one side parses (malformed probe against a valid token).
        let a = from_hex(&self.0).map(zeroize::Zeroizing::new);
        let b = from_hex(&other.0).map(zeroize::Zeroizing::new);
        match (a, b) {
            (Some(a), Some(b)) => {
                bool::from(subtle::ConstantTimeEq::ct_eq(a.as_slice(), b.as_slice()))
            }
            _ => false,
        }
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

/// Shared wire-limit enforcement for any wake-entry list — ledger pushes and
/// `prepare_reap` replies alike: entry count bound + per-entry bounds.
pub fn validate_wake_entries(entries: &[WakeEntry]) -> anyhow::Result<()> {
    anyhow::ensure!(
        entries.len() <= MAX_LEDGER_ENTRIES,
        "too many ledger entries"
    );
    for e in entries {
        e.validate()?;
    }
    Ok(())
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
    if let Err(e) = r.read_exact(&mut buf) {
        // A short read may still have written partial secret bytes.
        buf.zeroize();
        anyhow::bail!("credentials short read: {e}");
    }
    let mut trailing = [0u8; 1];
    loop {
        match r.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => {
                buf.zeroize();
                anyhow::bail!("credentials fd carried trailing bytes");
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                buf.zeroize();
                anyhow::bail!("credentials EOF check failed: {e}");
            }
        }
    }
    let mut dek = [0u8; DEK_LEN];
    let mut token = [0u8; TOKEN_LEN];
    dek.copy_from_slice(&buf[..DEK_LEN]);
    token.copy_from_slice(&buf[DEK_LEN..]);
    buf.zeroize();
    Ok(Credentials { dek, token })
}

/// Supervisor side: write DEK ‖ token. Pass the writer BY VALUE so its fd
/// closes when this returns — the vault's EOF check blocks until the write
/// end closes, so handing in `&mut w` (which `impl Write` permits) risks a
/// startup hang.
pub fn write_credentials(
    mut w: impl Write,
    dek: &[u8; DEK_LEN],
    token: &[u8; TOKEN_LEN],
) -> anyhow::Result<()> {
    let mut buf = [0u8; CREDENTIALS_LEN];
    buf[..DEK_LEN].copy_from_slice(dek);
    buf[DEK_LEN..].copy_from_slice(token);
    let res = w.write_all(&buf).and_then(|_| w.flush());
    buf.zeroize();
    res.map_err(|e| anyhow::anyhow!("credentials write: {e}"))
}

pub fn hex(bytes: &[u8]) -> String {
    // Single allocation, no per-byte format! temporaries (secret material may
    // pass through here via TokenHex::from_token).
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    // Byte-wise: never slices the &str, so non-ASCII input returns None
    // instead of panicking on a char boundary.
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks_exact(2)
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some(((hi as u8) << 4) | lo as u8)
        })
        .collect()
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
    fn hex_roundtrip() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(hex(&bytes), "000fa5ff");
        assert_eq!(from_hex("000fa5ff").unwrap(), bytes.to_vec());
    }

    /// TokenHex is #[serde(transparent)]: the wire shape must stay byte-identical
    /// to the plain String field it replaced (contract version 1 unchanged).
    #[test]
    fn ledger_update_wire_shape() {
        let u = LedgerUpdate {
            op: "ledger_update".into(),
            vault: "v".into(),
            token: TokenHex::new("aa".into()),
            rev: 1,
            entries: vec![],
        };
        let j = serde_json::to_value(&u).unwrap();
        assert_eq!(j["token"], "aa");
        let back: LedgerUpdate = serde_json::from_str(
            r#"{"op":"ledger_update","vault":"v","token":"aa","rev":1,"entries":[]}"#,
        )
        .unwrap();
        assert_eq!(back.token.expose(), "aa");
    }

    #[test]
    fn vault_names() {
        assert!(valid_vault_name("test-vault"));
        assert!(valid_vault_name("a"));
        assert!(!valid_vault_name(""));
        assert!(!valid_vault_name("-a"));
        assert!(!valid_vault_name("a-"));
        assert!(!valid_vault_name("A"));
        assert!(!valid_vault_name("a.b"));
        assert!(!valid_vault_name(&"x".repeat(64)));
    }

    #[test]
    fn from_hex_rejects_malformed() {
        assert!(from_hex("abc").is_none()); // odd length
        assert!(from_hex("zz").is_none()); // non-hex
        assert!(from_hex("€a").is_none()); // even byte length, non-ASCII: must not panic
    }

    #[test]
    fn ledger_update_validate() {
        let mut u = LedgerUpdate {
            op: "ledger_update".into(),
            vault: "v".into(),
            token: TokenHex::from_token(&[0u8; TOKEN_LEN]),
            rev: 1,
            entries: vec![],
        };
        u.validate().unwrap();

        u.op = "nope".into();
        assert!(u.validate().is_err());
        u.op = "ledger_update".into();

        u.vault = "../x".into();
        assert!(u.validate().is_err());
        u.vault = "v".into();

        u.token = TokenHex::new("zz".into());
        assert!(u.validate().is_err());
        u.token = TokenHex::from_token(&[0u8; TOKEN_LEN]);

        u.entries = (0..=MAX_LEDGER_ENTRIES)
            .map(|i| WakeEntry {
                id: format!("e{i}"),
                at: Schedule::Exact { at: 0 },
                reason_tag: String::new(),
            })
            .collect();
        assert!(u.validate().is_err());
        // Same list through the shared helper (the prepare_reap path).
        assert!(validate_wake_entries(&u.entries).is_err());
        assert!(validate_wake_entries(&u.entries[..1]).is_ok());
    }

    #[test]
    fn wake_fields_reject_control_bytes() {
        let mut e = WakeEntry {
            id: "ok".into(),
            at: Schedule::Exact { at: 0 },
            reason_tag: "tag".into(),
        };
        e.validate().unwrap();
        e.id = "a\nb".into();
        assert!(e.validate().is_err());
        e.id = "ok".into();
        e.reason_tag = "t\u{0}g".into();
        assert!(e.validate().is_err());
    }

    #[test]
    fn ctl_request_validate() {
        let ok = CtlRequest::AlarmDue {
            id: "e1".into(),
            reason_tag: "cron".into(),
        };
        ok.validate().unwrap();
        CtlRequest::Ping.validate().unwrap();
        let bad = [
            CtlRequest::AlarmDue {
                id: String::new(),
                reason_tag: String::new(),
            },
            CtlRequest::AlarmDue {
                id: "e1".into(),
                reason_tag: "x".repeat(MAX_REASON_TAG + 1),
            },
            CtlRequest::AlarmDue {
                id: "e\u{1b}1".into(),
                reason_tag: String::new(),
            },
        ];
        for req in bad {
            assert!(req.validate().is_err());
        }
    }

    #[test]
    fn token_ct_eq() {
        let a = TokenHex::from_token(&[0xabu8; TOKEN_LEN]);
        let b = TokenHex::from_token(&[0xabu8; TOKEN_LEN]);
        let c = TokenHex::from_token(&[0xacu8; TOKEN_LEN]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        // hex case must not matter — compare decoded bytes, not strings
        let upper = TokenHex::new("AB".repeat(TOKEN_LEN));
        assert!(a.ct_eq(&upper));
        // malformed hex compares unequal, never panics
        assert!(!a.ct_eq(&TokenHex::new("zz".into())));
        assert!(!a.ct_eq(&TokenHex::new(String::new())));
    }

    /// The contract's guarantee that validate() and the line cap agree: a
    /// maximal validator-passing message must still fit MAX_CTL_LINE. Control
    /// bytes are rejected precisely because their 6-char `\u00XX` escapes
    /// would break this bound; the worst remaining JSON expansion is the
    /// 2-char escapes for `"` and `\`, exercised here.
    #[test]
    fn max_valid_wake_list_fits_ctl_line() {
        let entry = WakeEntry {
            id: "\\".repeat(MAX_WAKE_ID),
            at: Schedule::Window {
                start: u64::MAX - 1,
                end: u64::MAX,
            },
            reason_tag: "\"".repeat(MAX_REASON_TAG),
        };
        entry.validate().unwrap();
        let entries = vec![entry; MAX_LEDGER_ENTRIES];
        validate_wake_entries(&entries).unwrap();

        let resp = serde_json::to_string(&CtlResponse::PrepareReap {
            quiescent: false,
            ledger_rev: u64::MAX,
            next_wake: entries.clone(),
        })
        .unwrap();
        assert!(
            resp.len() <= MAX_CTL_LINE,
            "prepare_reap line {} exceeds cap",
            resp.len()
        );

        let push = serde_json::to_string(&LedgerUpdate {
            op: "ledger_update".into(),
            vault: "x".repeat(63),
            token: TokenHex::from_token(&[0xffu8; TOKEN_LEN]),
            rev: u64::MAX,
            entries,
        })
        .unwrap();
        assert!(
            push.len() <= MAX_CTL_LINE,
            "ledger_update line {} exceeds cap",
            push.len()
        );
    }
}
