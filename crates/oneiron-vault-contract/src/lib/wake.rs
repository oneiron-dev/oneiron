//! Vault naming, timestamps, wake schedule and entry validation.

use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{MAX_LEDGER_ENTRIES, MAX_REASON_TAG, MAX_WAKE_ID};

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
pub(super) fn validate_wake_fields(id: &str, reason_tag: &str) -> anyhow::Result<()> {
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
