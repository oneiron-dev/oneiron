//! `[models.snapshots]`: the owner's policy for this host's sealed inference
//! snapshots (DESIGN-V2 §7, V2-R3). Sealed on-disk parking is on by default,
//! each vault may keep up to 8 GiB of sealed bodies, and a vault lock waits
//! at most 10 s in all for the workers' release before it aborts and
//! restarts those that did not answer. A vault's own table overrides any of
//! the three for that vault alone.
//!
//! ```toml
//! [models.snapshots]
//! enabled = true
//! disk_bytes_per_vault = 8589934592
//! lock_release_timeout_ms = 10000
//!
//! [models.snapshots.vaults.<vault id, 64 lowercase hex>]
//! disk_bytes_per_vault = 0
//! ```
//!
//! A budget of zero keeps nothing; turning parking off purges what is kept.
//! None of this is an engine `[limits]` row: retention is housekeeping (an
//! eviction, a skipped park, a recompute), never a refusal a caller sees.
use std::collections::BTreeMap;
use std::time::Duration;

use oneiron::inference_snapshot::retention::SnapshotBudget;
use serde::Deserialize;

/// Whether sealed on-disk parking is on when the config says nothing.
pub const DEFAULT_SNAPSHOTS_ENABLED: bool = true;
/// The sealed bytes one vault may keep on disk by default: 8 GiB.
pub const DEFAULT_SNAPSHOT_DISK_BYTES_PER_VAULT: u64 = 8 * 1024 * 1024 * 1024;
/// The one total bound a vault lock waits for every worker's release, in
/// milliseconds, before it aborts the incarnations still owing one: 10 s.
pub const DEFAULT_SNAPSHOT_LOCK_RELEASE_TIMEOUT_MS: u64 = 10_000;

/// `[models.snapshots]` as written.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotPolicyFile {
    enabled: Option<bool>,
    disk_bytes_per_vault: Option<u64>,
    lock_release_timeout_ms: Option<u64>,
    #[serde(default)]
    vaults: BTreeMap<String, VaultPolicyFile>,
}

/// `[models.snapshots.vaults.<vault id>]` as written: any of the three.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultPolicyFile {
    enabled: Option<bool>,
    disk_bytes_per_vault: Option<u64>,
    lock_release_timeout_ms: Option<u64>,
}

/// One vault's resolved snapshot policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultSnapshotPolicy {
    /// Whether sealed on-disk parking is on.
    pub enabled: bool,
    /// The sealed bytes the vault may keep on disk; zero keeps none.
    pub disk_bytes: u64,
    /// The one total bound a lock waits for its workers' release.
    pub lock_release_timeout: Duration,
}

impl Default for VaultSnapshotPolicy {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_SNAPSHOTS_ENABLED,
            disk_bytes: DEFAULT_SNAPSHOT_DISK_BYTES_PER_VAULT,
            lock_release_timeout: Duration::from_millis(DEFAULT_SNAPSHOT_LOCK_RELEASE_TIMEOUT_MS),
        }
    }
}

impl VaultSnapshotPolicy {
    /// The disk budget the vault's retention ledger keeps it inside.
    #[must_use]
    pub fn budget(&self) -> SnapshotBudget {
        SnapshotBudget {
            enabled: self.enabled,
            disk_bytes: self.disk_bytes,
        }
    }
}

/// The resolved `[models.snapshots]`: the host's policy, and each vault's
/// own where its table names one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotPolicy {
    pub default: VaultSnapshotPolicy,
    pub vaults: BTreeMap<[u8; 32], VaultSnapshotPolicy>,
}

impl SnapshotPolicy {
    /// The policy for the vault with id `vault`.
    #[must_use]
    pub fn for_vault(&self, vault: &[u8; 32]) -> VaultSnapshotPolicy {
        self.vaults.get(vault).copied().unwrap_or(self.default)
    }
}

/// A vault id as its table names it: 64 lowercase hex characters.
fn vault_key(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// A timeout in milliseconds as a duration: at least one millisecond.
fn timeout(at: &str, ms: u64) -> anyhow::Result<Duration> {
    anyhow::ensure!(
        ms > 0,
        "{at}.lock_release_timeout_ms must be greater than zero"
    );
    Ok(Duration::from_millis(ms))
}

impl SnapshotPolicyFile {
    pub(super) fn resolve(self) -> anyhow::Result<SnapshotPolicy> {
        let base = VaultSnapshotPolicy::default();
        let default = VaultSnapshotPolicy {
            enabled: self.enabled.unwrap_or(base.enabled),
            disk_bytes: self.disk_bytes_per_vault.unwrap_or(base.disk_bytes),
            lock_release_timeout: match self.lock_release_timeout_ms {
                Some(ms) => timeout("models.snapshots", ms)?,
                None => base.lock_release_timeout,
            },
        };
        let mut vaults = BTreeMap::new();
        for (name, file) in self.vaults {
            let at = format!("models.snapshots.vaults.{name}");
            let Some(vault) = vault_key(&name) else {
                anyhow::bail!("{at}: a vault id is 64 lowercase hex characters");
            };
            let policy = VaultSnapshotPolicy {
                enabled: file.enabled.unwrap_or(default.enabled),
                disk_bytes: file.disk_bytes_per_vault.unwrap_or(default.disk_bytes),
                lock_release_timeout: match file.lock_release_timeout_ms {
                    Some(ms) => timeout(&at, ms)?,
                    None => default.lock_release_timeout,
                },
            };
            vaults.insert(vault, policy);
        }
        Ok(SnapshotPolicy { default, vaults })
    }
}
