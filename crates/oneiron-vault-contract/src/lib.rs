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

/// First contract version carrying the SLIM rung. The v1 -> v2 bump is
/// additive-only: every v1 request and response keeps byte-identical semantics
/// except `Ping.contract_version`, which now reports 2 as the negotiation signal;
/// v1 peers are never sent a v2-only request.
pub const SLIM_CONTRACT_VERSION: u32 = 2;

pub const CONTRACT_VERSION: u32 = SLIM_CONTRACT_VERSION;

/// True when a peer advertising `version` accepts the SLIM ctl surface.
/// Supervisors ping first and send `Shed` only when this holds. With a v1 peer,
/// they skip the shed rung and retain the existing reap protocol.
#[must_use]
pub const fn supports_slim(version: u32) -> bool {
    version >= SLIM_CONTRACT_VERSION
}

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

/// The commitment RECURRENCE vocabulary (CMT-2, ONE-1539).
///
/// Strictly additive and strictly nested: the root [`Schedule`] above is the
/// wake-ledger's one-shot instruction to the supervisor and is untouched, so
/// [`CONTRACT_VERSION`] does not move. This module is the shared *recurrence*
/// vocabulary — one implementation, two consumers (ARCH-0060 [CAL-03]): a
/// commitment series, and an ICS poll cadence expressed as an interval on this
/// same enum rather than as a second recurrence primitive ([CAL-02]).
///
/// Nothing here reaches the wire today. It lives in the contract crate so the
/// vocabulary a vault persists and a supervisor would one day schedule against
/// cannot fork into two spellings.
pub mod commitment {
    use super::UnixTs;
    use serde::{Deserialize, Serialize};

    /// The window a [`Schedule::Quota`] counts its occurrences inside.
    ///
    /// User-local by construction: a quota week is the week the OWNER lives in,
    /// so the window carries its IANA zone rather than being derived from a
    /// fixed 604800-second stride off the epoch.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum QuotaWindow {
        /// The ISO-8601 week (Monday 00:00 local through the following Monday,
        /// exclusive) observed in `tz`.
        IsoWeek { tz: String },
    }

    /// How a commitment recurs.
    ///
    /// `Rrule` is decodable in v1 but not evaluable: expansion belongs to the
    /// calendar layer's single recurrence implementation, and a second parser
    /// vendored behind this enum is exactly the fork this module exists to
    /// prevent.
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum Schedule {
        /// One occurrence at `due`, then done.
        Once { due: UnixTs },
        /// Every `period` seconds off the `anchor` grid.
        Interval { period: u64, anchor: UnixTs },
        /// `count` occurrences per `window`, no fixed instant within it.
        Quota { count: u32, window: QuotaWindow },
        /// An RFC 5545 recurrence rule, evaluated by the calendar layer.
        Rrule { rrule_string: String, tz: String },
    }
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

/// Wire spelling is pinned to the engine's `slim::ShedCause`; the contract
/// crate must not depend on `oneiron`, so the duplication is deliberate.
/// The vault-side adapter maps with a total function, never a parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedCause {
    LongOutboundWait,
    MemoryPressure,
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
    /// Appended last. `waited_secs` is the supervisor's own observation of the
    /// wait; the engine validates positivity, never policy.
    Shed {
        cause: ShedCause,
        waited_secs: u64,
    },
}

impl CtlRequest {
    /// Vault-side reject-not-truncate enforcement: `alarm_due` fields share
    /// the [`WakeEntry`] bounds; `shed` requires a positive observed wait, not
    /// a policy threshold. Vaults call this immediately after parsing a ctl line.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            CtlRequest::AlarmDue { id, reason_tag } => validate_wake_fields(id, reason_tag)?,
            CtlRequest::Shed { waited_secs, .. } => {
                anyhow::ensure!(*waited_secs > 0, "shed requires a positive waited_secs");
            }
            CtlRequest::PrepareReap | CtlRequest::ReapAbort | CtlRequest::Ping => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShedStatus {
    Entered,
    AlreadySlim,
    Refused,
}

/// Wire mirror of the engine's `ShedBlocker`. Stringly by design so a newer
/// vault's blocker kind stays displayable by an older supervisor; `detail`
/// is human-facing and bounded by [`MAX_CTL_LINE`] at the framing layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShedBlockerWire {
    pub kind: String,
    pub detail: String,
}

/// Untagged: variant selection is structural, tried in declaration order.
/// INVARIANT: each variant's required-field set must stay disjoint from every
/// variant above it, and new variants are appended last — otherwise a
/// malformed reply can silently match a later, more permissive variant
/// (e.g. `Ok`). Supervisors that need strict rejection should deserialize the
/// concrete response shape they expect for the request they sent. Tagging
/// this enum is a wire break; the additive SLIM v2 extension keeps it untagged.
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
    /// Appended last. Required fields {slim, status} are disjoint from every
    /// variant above ({quiescent, ledger_rev, next_wake},
    /// {ok, vault, pid, contract_version}, {ok}), preserving the untagged
    /// declaration-order invariant. Do NOT add a required `ok` field here:
    /// it would let the `Ok` variant shadow this one during untagged
    /// matching (unknown fields are ignored, so `Ok { ok }` would accept a
    /// `Slim` line that carried `ok`).
    ///
    /// Out-of-workspace ctl-server mapping specification:
    /// - engine `Entered { dropped, .. }` -> `slim=true`, `status=entered`,
    ///   `reclaimed_bytes=Some(dropped.estimated_reclaimed_bytes)`,
    ///   `dropped_windows=Some(dropped.sync_windows)`, `blocker=None`;
    /// - engine `AlreadySlim` after a selected-identity re-drop -> `slim=true`,
    ///   `status=already_slim`, both fresh numerics `Some(..)`, `blocker=None`;
    /// - engine `AlreadySlim` from the no-identity selection-failure path ->
    ///   `slim=true`, `status=already_slim`, both numerics absent, `blocker=None`;
    /// - engine `Refused(blocker)` -> `status=refused`, both numerics absent,
    ///   `blocker=Some(mapped_blocker)`. For known kinds, `slim=true` iff the kind
    ///   is `already_slim_for_different_step`; the other known blockers report
    ///   `slim=false`. Unknown blocker kinds may report either residency.
    ///
    /// `slim` always reports residency at return, never whether this call entered it.
    Slim {
        slim: bool,
        status: ShedStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reclaimed_bytes: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dropped_windows: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocker: Option<ShedBlockerWire>,
    },
}

impl CtlResponse {
    /// Validate SLIM status, residency, numerics, and blocker combinations after
    /// parsing. Existing responses keep their prior validation requirements;
    /// `PrepareReap.next_wake` still uses [`validate_wake_entries`].
    pub fn validate(&self) -> anyhow::Result<()> {
        if let CtlResponse::Slim {
            slim,
            status,
            reclaimed_bytes,
            dropped_windows,
            blocker,
        } = self
        {
            match status {
                ShedStatus::Entered => anyhow::ensure!(
                    *slim
                        && reclaimed_bytes.is_some()
                        && dropped_windows.is_some()
                        && blocker.is_none(),
                    "entered SLIM requires slim residency, both numerics, and no blocker"
                ),
                ShedStatus::AlreadySlim => anyhow::ensure!(
                    *slim
                        && (reclaimed_bytes.is_some() == dropped_windows.is_some())
                        && blocker.is_none(),
                    "already_slim SLIM requires slim residency, paired numerics, and no blocker"
                ),
                ShedStatus::Refused => {
                    let blocker = blocker
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("refused SLIM requires a blocker"))?;
                    anyhow::ensure!(
                        reclaimed_bytes.is_none() && dropped_windows.is_none(),
                        "refused SLIM forbids numerics"
                    );
                    let residency_matches = match blocker.kind.as_str() {
                        "no_pending_outbound_step"
                        | "multiple_pending_outbound_steps"
                        | "sync_window_busy" => !*slim,
                        "already_slim_for_different_step" => *slim,
                        _ => true,
                    };
                    anyhow::ensure!(
                        residency_matches,
                        "refused SLIM residency must correlate with blocker kind"
                    );
                }
            }
        }
        Ok(())
    }
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

    // Frozen v1 schemas model peers that have not learned Shed/Slim. Keep the
    // original variant order and permissive unknown-field behavior here.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case")]
    enum V1CtlRequest {
        PrepareReap,
        ReapAbort,
        AlarmDue { id: String, reason_tag: String },
        Ping,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(untagged)]
    enum V1CtlResponse {
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

    fn ctl_response_fixtures() -> Vec<(CtlResponse, &'static str)> {
        vec![
            (
                CtlResponse::PrepareReap {
                    quiescent: false,
                    ledger_rev: 7,
                    next_wake: vec![],
                },
                r#"{"quiescent":false,"ledger_rev":7,"next_wake":[]}"#,
            ),
            (
                CtlResponse::Ping {
                    ok: true,
                    vault: "v".into(),
                    pid: 42,
                    contract_version: CONTRACT_VERSION,
                },
                r#"{"ok":true,"vault":"v","pid":42,"contract_version":2}"#,
            ),
            (CtlResponse::Ok { ok: true }, r#"{"ok":true}"#),
            (CtlResponse::Ok { ok: false }, r#"{"ok":false}"#),
            (
                CtlResponse::Slim {
                    slim: true,
                    status: ShedStatus::Entered,
                    reclaimed_bytes: Some(4096),
                    dropped_windows: Some(2),
                    blocker: None,
                },
                r#"{"slim":true,"status":"entered","reclaimed_bytes":4096,"dropped_windows":2}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: true,
                    status: ShedStatus::AlreadySlim,
                    reclaimed_bytes: Some(0),
                    dropped_windows: Some(0),
                    blocker: None,
                },
                r#"{"slim":true,"status":"already_slim","reclaimed_bytes":0,"dropped_windows":0}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: true,
                    status: ShedStatus::AlreadySlim,
                    reclaimed_bytes: None,
                    dropped_windows: None,
                    blocker: None,
                },
                r#"{"slim":true,"status":"already_slim"}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: false,
                    status: ShedStatus::Refused,
                    reclaimed_bytes: None,
                    dropped_windows: None,
                    blocker: Some(ShedBlockerWire {
                        kind: "no_pending_outbound_step".into(),
                        detail: "no pending step".into(),
                    }),
                },
                r#"{"slim":false,"status":"refused","blocker":{"kind":"no_pending_outbound_step","detail":"no pending step"}}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: false,
                    status: ShedStatus::Refused,
                    reclaimed_bytes: None,
                    dropped_windows: None,
                    blocker: Some(ShedBlockerWire {
                        kind: "multiple_pending_outbound_steps".into(),
                        detail: "2 pending steps".into(),
                    }),
                },
                r#"{"slim":false,"status":"refused","blocker":{"kind":"multiple_pending_outbound_steps","detail":"2 pending steps"}}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: false,
                    status: ShedStatus::Refused,
                    reclaimed_bytes: None,
                    dropped_windows: None,
                    blocker: Some(ShedBlockerWire {
                        kind: "sync_window_busy".into(),
                        detail: "1 outstanding handle".into(),
                    }),
                },
                r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy","detail":"1 outstanding handle"}}"#,
            ),
            (
                CtlResponse::Slim {
                    slim: true,
                    status: ShedStatus::Refused,
                    reclaimed_bytes: None,
                    dropped_windows: None,
                    blocker: Some(ShedBlockerWire {
                        kind: "already_slim_for_different_step".into(),
                        detail: "different step".into(),
                    }),
                },
                r#"{"slim":true,"status":"refused","blocker":{"kind":"already_slim_for_different_step","detail":"different step"}}"#,
            ),
        ]
    }

    #[test]
    fn reap_flow_byte_identical() {
        // A v1 conversation stays byte-identical apart from the advertised
        // version in the Ping reply. The v1 response schema accepts v2 Ping.
        for (request, reply) in [
            (
                r#"{"op":"ping"}"#,
                r#"{"ok":true,"vault":"v","pid":42,"contract_version":1}"#,
            ),
            (
                r#"{"op":"prepare_reap"}"#,
                r#"{"quiescent":true,"ledger_rev":7,"next_wake":[{"id":"w1","at":{"kind":"exact","at":7},"reason_tag":"tag"}]}"#,
            ),
            (r#"{"op":"reap_abort"}"#, r#"{"ok":true}"#),
        ] {
            let old_request: V1CtlRequest = serde_json::from_str(request).unwrap();
            let new_request: CtlRequest = serde_json::from_str(request).unwrap();
            new_request.validate().unwrap();
            assert_eq!(serde_json::to_string(&old_request).unwrap(), request);
            assert_eq!(serde_json::to_string(&new_request).unwrap(), request);

            let old_reply: V1CtlResponse = serde_json::from_str(reply).unwrap();
            let mut new_reply: CtlResponse = serde_json::from_str(reply).unwrap();
            assert_eq!(serde_json::to_string(&old_reply).unwrap(), reply);
            assert_eq!(serde_json::to_string(&new_reply).unwrap(), reply);
            if let CtlResponse::Ping {
                contract_version, ..
            } = &mut new_reply
            {
                assert!(!supports_slim(*contract_version));
                *contract_version = CONTRACT_VERSION;
            }
            new_reply.validate().unwrap();
            let encoded = serde_json::to_string(&new_reply).unwrap();
            assert_eq!(
                encoded,
                reply.replace("\"contract_version\":1", "\"contract_version\":2")
            );
            let v1_decoded: V1CtlResponse = serde_json::from_str(&encoded).unwrap();
            assert_eq!(serde_json::to_string(&v1_decoded).unwrap(), encoded);
        }
    }

    #[test]
    fn alarm_due_wire_bytes_unchanged() {
        let wire = r#"{"op":"alarm_due","id":"w1","reason_tag":"cron"}"#;
        let old: V1CtlRequest = serde_json::from_str(wire).unwrap();
        let new: CtlRequest = serde_json::from_str(wire).unwrap();
        new.validate().unwrap();
        assert!(matches!(new, CtlRequest::AlarmDue { .. }));
        assert_eq!(serde_json::to_string(&old).unwrap(), wire);
        assert_eq!(serde_json::to_string(&new).unwrap(), wire);
    }

    #[test]
    fn ctl_version_gating() {
        assert_eq!(SLIM_CONTRACT_VERSION, 2);
        assert_eq!(CONTRACT_VERSION, 2);
        for (version, supported) in [
            (0, false),
            (1, false),
            (2, true),
            (3, true),
            (u32::MAX, true),
        ] {
            assert_eq!(supports_slim(version), supported);
            let wire =
                format!(r#"{{"ok":true,"vault":"v","pid":42,"contract_version":{version}}}"#);
            let CtlResponse::Ping {
                contract_version, ..
            } = serde_json::from_str(&wire).unwrap()
            else {
                panic!("Ping must not decode as Ok");
            };
            assert_eq!(supports_slim(contract_version), supported);
        }
        for (cause, spelling) in [
            (ShedCause::LongOutboundWait, "long_outbound_wait"),
            (ShedCause::MemoryPressure, "memory_pressure"),
        ] {
            for waited_secs in [0, 1, u64::MAX] {
                let request = CtlRequest::Shed { cause, waited_secs };
                let wire =
                    format!(r#"{{"op":"shed","cause":"{spelling}","waited_secs":{waited_secs}}}"#);
                assert_eq!(serde_json::to_string(&request).unwrap(), wire);
                assert_eq!(request.validate().is_ok(), waited_secs > 0);
                assert!(serde_json::from_str::<V1CtlRequest>(&wire).is_err());
                let decoded: CtlRequest = serde_json::from_str(&wire).unwrap();
                assert_eq!(decoded.validate().is_ok(), waited_secs > 0);
                assert!(matches!(
                    decoded,
                    CtlRequest::Shed { cause: c, waited_secs: w } if c == cause && w == waited_secs
                ));
            }
        }
    }

    #[test]
    fn shed_request_rejects_malformed_json() {
        for wire in [
            r#"{"op":"future_op"}"#,
            r#"{"op":"shed","waited_secs":1}"#,
            r#"{"op":"shed","cause":"memory_pressure"}"#,
            r#"{"op":"shed","cause":"future_cause","waited_secs":1}"#,
            r#"{"op":"shed","cause":"LongOutboundWait","waited_secs":1}"#,
            r#"{"op":"shed","cause":null,"waited_secs":1}"#,
            r#"{"op":"shed","cause":7,"waited_secs":1}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":null}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":"1"}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":true}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":-1}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":1.5}"#,
            r#"{"op":"shed","cause":"memory_pressure","waited_secs":18446744073709551616}"#,
        ] {
            assert!(serde_json::from_str::<CtlRequest>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn ctl_response_untagged_invariant_holds() {
        for (response, expected) in ctl_response_fixtures() {
            response.validate().unwrap();
            let encoded = serde_json::to_string(&response).unwrap();
            assert_eq!(encoded, expected);
            let decoded: CtlResponse = serde_json::from_str(&encoded).unwrap();
            assert_eq!(
                std::mem::discriminant(&decoded),
                std::mem::discriminant(&response),
                "{encoded}"
            );
            decoded.validate().unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), expected);
            if matches!(response, CtlResponse::Slim { .. }) {
                assert!(serde_json::from_str::<V1CtlResponse>(&encoded).is_err());
            }
        }
    }

    #[test]
    fn slim_response_field_combinations_validate() {
        for status in [
            ShedStatus::Entered,
            ShedStatus::AlreadySlim,
            ShedStatus::Refused,
        ] {
            for slim in [false, true] {
                for reclaimed_bytes in [None, Some(0), Some(u64::MAX)] {
                    for dropped_windows in [None, Some(0), Some(u64::MAX)] {
                        for kind in [
                            None,
                            Some("no_pending_outbound_step"),
                            Some("multiple_pending_outbound_steps"),
                            Some("sync_window_busy"),
                            Some("already_slim_for_different_step"),
                            Some("future_blocker"),
                        ] {
                            let response = CtlResponse::Slim {
                                slim,
                                status,
                                reclaimed_bytes,
                                dropped_windows,
                                blocker: kind.map(|kind| ShedBlockerWire {
                                    kind: kind.into(),
                                    detail: "detail".into(),
                                }),
                            };
                            let valid = matches!(
                                (status, slim, reclaimed_bytes, dropped_windows, kind),
                                (ShedStatus::Entered, true, Some(_), Some(_), None)
                                    | (ShedStatus::AlreadySlim, true, Some(_), Some(_), None)
                                    | (ShedStatus::AlreadySlim, true, None, None, None)
                                    | (
                                        ShedStatus::Refused,
                                        false,
                                        None,
                                        None,
                                        Some(
                                            "no_pending_outbound_step"
                                                | "multiple_pending_outbound_steps"
                                                | "sync_window_busy"
                                        )
                                    )
                                    | (
                                        ShedStatus::Refused,
                                        true,
                                        None,
                                        None,
                                        Some("already_slim_for_different_step")
                                    )
                                    | (ShedStatus::Refused, _, None, None, Some("future_blocker"))
                            );
                            assert_eq!(response.validate().is_ok(), valid, "{response:?}");
                            let wire = serde_json::to_string(&response).unwrap();
                            let decoded: CtlResponse = serde_json::from_str(&wire).unwrap();
                            assert_eq!(decoded.validate().is_ok(), valid, "{wire}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn slim_absent_optionals_serialize_as_absent_keys() {
        for (response, _) in ctl_response_fixtures() {
            let json = serde_json::to_value(&response).unwrap();
            if let CtlResponse::Slim {
                reclaimed_bytes,
                dropped_windows,
                blocker,
                ..
            } = response
            {
                assert!(
                    json.get("ok").is_none(),
                    "Slim must never be shadowed by Ok"
                );
                for (key, present) in [
                    ("reclaimed_bytes", reclaimed_bytes.is_some()),
                    ("dropped_windows", dropped_windows.is_some()),
                    ("blocker", blocker.is_some()),
                ] {
                    assert_eq!(json.get(key).is_some(), present, "{key}: {json}");
                    assert!(!json.get(key).is_some_and(serde_json::Value::is_null));
                }
            }
        }
        // Null optionals decode as None, but are never emitted as null.
        let response: CtlResponse = serde_json::from_str(
            r#"{"slim":true,"status":"already_slim","reclaimed_bytes":null,"dropped_windows":null,"blocker":null}"#,
        )
        .unwrap();
        response.validate().unwrap();
        assert_eq!(
            serde_json::to_string(&response).unwrap(),
            r#"{"slim":true,"status":"already_slim"}"#
        );
    }

    #[test]
    fn slim_response_rejects_malformed_json() {
        for wire in [
            r#"{}"#,
            r#"{"slim":true}"#,
            r#"{"status":"entered"}"#,
            r#"{"slim":"true","status":"entered"}"#,
            r#"{"slim":null,"status":"already_slim"}"#,
            r#"{"slim":true,"status":"future_status"}"#,
            r#"{"slim":true,"status":"AlreadySlim"}"#,
            r#"{"slim":true,"status":null}"#,
            r#"{"slim":true,"status":1}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":-1,"dropped_windows":0}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":18446744073709551616,"dropped_windows":0}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":1.5,"dropped_windows":0}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":"1","dropped_windows":0}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":-1}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":18446744073709551616}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":1.5}"#,
            r#"{"slim":true,"status":"entered","reclaimed_bytes":0,"dropped_windows":"1"}"#,
            r#"{"slim":false,"status":"refused","blocker":{}}"#,
            r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy"}}"#,
            r#"{"slim":false,"status":"refused","blocker":{"detail":"busy"}}"#,
            r#"{"slim":false,"status":"refused","blocker":{"kind":null,"detail":"busy"}}"#,
            r#"{"slim":false,"status":"refused","blocker":{"kind":"sync_window_busy","detail":1}}"#,
            r#"{"slim":false,"status":"refused","blocker":"sync_window_busy"}"#,
        ] {
            assert!(serde_json::from_str::<CtlResponse>(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn shed_blocker_wire_kind_spellings_are_pinned() {
        for (kind, wire) in [
            (
                "no_pending_outbound_step",
                r#"{"kind":"no_pending_outbound_step","detail":"detail"}"#,
            ),
            (
                "multiple_pending_outbound_steps",
                r#"{"kind":"multiple_pending_outbound_steps","detail":"detail"}"#,
            ),
            (
                "sync_window_busy",
                r#"{"kind":"sync_window_busy","detail":"detail"}"#,
            ),
            (
                "already_slim_for_different_step",
                r#"{"kind":"already_slim_for_different_step","detail":"detail"}"#,
            ),
        ] {
            let blocker = ShedBlockerWire {
                kind: kind.into(),
                detail: "detail".into(),
            };
            assert_eq!(serde_json::to_string(&blocker).unwrap(), wire);
            assert_eq!(
                serde_json::from_str::<ShedBlockerWire>(wire).unwrap(),
                blocker
            );
        }
    }

    #[test]
    fn shed_blocker_wire_preserves_unknown_kinds() {
        for (slim, wire) in [
            (
                false,
                r#"{"slim":false,"status":"refused","blocker":{"kind":"future_blocker","detail":"wait for \"adapter\""}}"#,
            ),
            (
                true,
                r#"{"slim":true,"status":"refused","blocker":{"kind":"future_blocker","detail":"wait for \"adapter\""}}"#,
            ),
        ] {
            let response: CtlResponse = serde_json::from_str(wire).unwrap();
            response.validate().unwrap();
            assert_eq!(serde_json::to_string(&response).unwrap(), wire);
            let CtlResponse::Slim {
                slim: decoded_slim,
                status: ShedStatus::Refused,
                blocker: Some(blocker),
                ..
            } = response
            else {
                panic!("unknown blocker must remain displayable");
            };
            assert_eq!(decoded_slim, slim);
            assert_eq!(blocker.kind, "future_blocker");
            assert_eq!(blocker.detail, "wait for \"adapter\"");
        }
    }

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

    /// CMT-2 (ONE-1539): the commitment recurrence enum is a NESTED addition.
    /// The root wake `Schedule` and `WakeEntry` stay byte-identical alongside
    /// the nested vocabulary's own tagged shape. SLIM, not recurrence, now
    /// accounts for the v2 wire version.
    #[test]
    fn commitment_schedule_enum_is_nested_and_leaves_the_wake_ledger_alone() {
        use super::commitment::{QuotaWindow, Schedule as CommitmentSchedule};

        assert_eq!(CONTRACT_VERSION, SLIM_CONTRACT_VERSION);

        // Root fixtures, byte for byte.
        assert_eq!(
            serde_json::to_string(&Schedule::Exact { at: 7 }).unwrap(),
            r#"{"kind":"exact","at":7}"#
        );
        assert_eq!(
            serde_json::to_string(&Schedule::Window { start: 1, end: 2 }).unwrap(),
            r#"{"kind":"window","start":1,"end":2}"#
        );
        assert_eq!(
            serde_json::to_string(&WakeEntry {
                id: "w1".into(),
                at: Schedule::Exact { at: 7 },
                reason_tag: "tag".into(),
            })
            .unwrap(),
            r#"{"id":"w1","at":{"kind":"exact","at":7},"reason_tag":"tag"}"#
        );

        // The nested vocabulary: same `tag = "kind"` / snake_case convention,
        // its own namespace, and no variant name shared with the root enum.
        for (value, json) in [
            (
                CommitmentSchedule::Once { due: 10 },
                r#"{"kind":"once","due":10}"#,
            ),
            (
                CommitmentSchedule::Interval {
                    period: 86_400,
                    anchor: 100,
                },
                r#"{"kind":"interval","period":86400,"anchor":100}"#,
            ),
            (
                CommitmentSchedule::Quota {
                    count: 3,
                    window: QuotaWindow::IsoWeek {
                        tz: "Europe/London".into(),
                    },
                },
                r#"{"kind":"quota","count":3,"window":{"kind":"iso_week","tz":"Europe/London"}}"#,
            ),
            (
                CommitmentSchedule::Rrule {
                    rrule_string: "FREQ=WEEKLY".into(),
                    tz: "UTC".into(),
                },
                r#"{"kind":"rrule","rrule_string":"FREQ=WEEKLY","tz":"UTC"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), json);
            assert_eq!(
                serde_json::from_str::<CommitmentSchedule>(json).unwrap(),
                value
            );
        }

        // A root-schedule payload is NOT a commitment schedule and vice versa:
        // the two enums never silently cross-deserialize.
        assert!(serde_json::from_str::<CommitmentSchedule>(r#"{"kind":"exact","at":7}"#).is_err());
        assert!(serde_json::from_str::<Schedule>(r#"{"kind":"once","due":10}"#).is_err());
    }
}
