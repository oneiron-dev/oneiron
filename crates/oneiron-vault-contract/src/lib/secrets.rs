//! Spawn-token hex type, credential framing, and hex codec.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroize;

use super::{CREDENTIALS_LEN, DEK_LEN, TOKEN_LEN};

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
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            let hi = (p[0] as char).to_digit(16)?;
            let lo = (p[1] as char).to_digit(16)?;
            Some(((hi as u8) << 4) | lo as u8)
        })
        .collect()
}
