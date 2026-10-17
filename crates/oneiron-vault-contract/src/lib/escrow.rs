//! The vault's data-key escrow on its way to the registry (CROSS-ARCH-0022
//! #ov-custody, invariant 03: escrow is delivered, not assumed).
//!
//! The vault process seals its data key to each escrow recipient the node's
//! operator installed and writes one report per capsule into the outbox the
//! supervisor named (`--escrow-outbox-dir`). The node ships each file to the
//! registry and removes it only after a durable store acknowledgement. The
//! vault hands a capsule over once; a report always carries the same id, so
//! one written again after a crash is the same row to the receiver.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The report's wire schema version.
pub const ESCROW_REPORT_SCHEMA_VERSION: u32 = 1;
/// The report's type tag.
pub const ESCROW_REPORT_TYPE: &str = "vault_key_escrow";

/// One escrow capsule of the vault's data key. None of it is secret: the
/// capsule opens only with its recipient's secret half.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowCapsuleReport {
    pub schema_version: u32,
    pub report_type: String,
    /// The receiver's idempotency key: the blake3 of the capsule, hex.
    pub report_id: String,
    pub vault_name: String,
    /// The 32-byte vault id the capsule is bound to, hex.
    pub vault_id: String,
    /// The recipient's role: `managed` or `break-glass`.
    pub role: String,
    /// The wrap's label: `<role>.<16 hex of the recipient key's blake3>`.
    pub label: String,
    /// The vault's id for the wrap, as an unlock names it.
    pub wrap_id: String,
    /// The commitment an opened data key must match, hex.
    pub key_commitment: String,
    /// The E0 `VaultDek` envelope (X25519 + ML-KEM-1024 hybrid capsule), hex.
    pub capsule: String,
    /// The vault clock, in seconds, when the capsule was sealed.
    pub sealed_at: u64,
}

/// The file one capsule's report is spooled under, or `None` for a label
/// that cannot name a file.
#[must_use]
pub fn escrow_report_file_name(label: &str) -> Option<String> {
    let ok = !label.is_empty()
        && label.len() <= 64
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !label.starts_with('.');
    ok.then(|| format!("vault-key-escrow-{label}.json"))
}

/// Writes `report` into `outbox` durably: a private temporary sibling,
/// synced, renamed over the report's file, then the directory synced. A
/// crash leaves either the whole report or none of it.
pub fn spool_escrow_report(outbox: &Path, report: &EscrowCapsuleReport) -> anyhow::Result<PathBuf> {
    let name = escrow_report_file_name(&report.label)
        .ok_or_else(|| anyhow::anyhow!("an escrow label cannot name a spool file"))?;
    let target = outbox.join(&name);
    let tmp = outbox.join(format!(".{name}.{}.tmp", std::process::id()));
    let data = serde_json::to_vec_pretty(report)?;
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp).and_then(|mut file| {
        file.write_all(&data)?;
        file.sync_all()
    });
    if let Err(error) = written.and_then(|()| std::fs::rename(&tmp, &target)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error.into());
    }
    std::fs::File::open(outbox)?.sync_all()?;
    Ok(target)
}
