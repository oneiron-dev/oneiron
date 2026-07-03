//! Per-connection federation quota and maintenance ingest quota decisions.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use super::types::WindowKey;
use crate::authority::{AuthorityKey, AuthorityVaultId};
use crate::types::bytes_to_hex_lower;
use crate::{Error, Result, Vault};

const MAINTENANCE_INGEST_QUOTA_PREFIX: &[u8] = b"m:maintenance_ingest_quota:v1:";
const MAINTENANCE_INGEST_QUOTA_CONFIG_KEY: &[u8] = b"m:maintenance_ingest_quota_config:v1";
const MAINTENANCE_INGEST_QUOTA_VALUE_LEN: usize = 12;
const MAINTENANCE_INGEST_QUOTA_PEER_DOMAIN: &[u8] = b"oneiron/maintenance-ingest-quota/v1/peer";
/// Default accepted maintenance-band replay ops per peer per quota window.
///
/// This is a generous device-local DoS bound for signed maintenance records
/// arriving through sync replay doors, not a policy rate limiter.
pub const DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW: u32 = 4096;
/// Default maintenance-band replay quota window length, in seconds.
pub const DEFAULT_MAINTENANCE_INGEST_QUOTA_WINDOW_SECS: u64 = 60 * 60;

/// Default distinct-window cap for one federated selector connection.
pub const DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION: usize = 64;
/// Default pause after a federated connection exceeds its quota.
pub const DEFAULT_FEDERATION_FLOOD_PAUSE_SECS: u64 = 30;

/// Decision returned by the federation quota gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowBlock {
    /// The request may proceed.
    Allow,
    /// The request is temporarily paused for this connection.
    Pause(FederationPauseReason),
    /// The request is permanently blocked by configuration.
    Block(FederationBlockReason),
}

/// Reason a federated connection entered or remains in pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationPauseReason {
    /// A new window would exceed the connection's distinct-window quota.
    WindowQuotaExceeded,
    /// A previous quota decision is still within its pause interval.
    FloodPauseActive,
}

/// Reason a federated connection is blocked rather than paused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationBlockReason {
    /// The configured per-connection federated window quota is zero.
    WindowQuotaDisabled,
}

/// Tunables for one federated connection's quota state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FederationQuotaConfig {
    /// Maximum distinct valid window keys one federated connection may touch.
    pub max_windows_per_connection: usize,
    /// Pause duration after quota overflow.
    pub flood_pause: Duration,
}

impl FederationQuotaConfig {
    /// Builds quota tunables from server config values.
    #[must_use]
    pub fn new(max_windows_per_connection: usize, flood_pause_secs: u64) -> Self {
        Self {
            max_windows_per_connection,
            flood_pause: Duration::from_secs(flood_pause_secs),
        }
    }
}

impl Default for FederationQuotaConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FEDERATION_WINDOWS_PER_CONNECTION,
            DEFAULT_FEDERATION_FLOOD_PAUSE_SECS,
        )
    }
}

/// Observable snapshot of a federated connection's quota state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationQuotaSnapshot {
    /// Number of distinct windows accepted on this connection.
    pub windows_touched: usize,
    /// Configured distinct-window cap.
    pub max_windows_per_connection: usize,
    /// Current allow/pause/block decision at the snapshot time.
    pub decision: AllowBlock,
    /// Remaining pause duration when paused.
    pub pause_remaining: Option<Duration>,
}

/// Mutable quota state for one federated selector connection.
#[derive(Debug, Clone)]
pub struct FederationConnectionQuota {
    config: FederationQuotaConfig,
    windows_touched: HashSet<WindowKey>,
    paused_until: Option<Instant>,
    last_decision: AllowBlock,
}

impl FederationConnectionQuota {
    /// Creates empty quota state for a single connection.
    #[must_use]
    pub fn new(config: FederationQuotaConfig) -> Self {
        Self {
            config,
            windows_touched: HashSet::new(),
            paused_until: None,
            last_decision: AllowBlock::Allow,
        }
    }

    /// Evaluates whether this connection may touch `key` at `now`.
    pub fn allow_window(&mut self, key: &WindowKey, now: Instant) -> AllowBlock {
        if self.config.max_windows_per_connection == 0 {
            return self.record(AllowBlock::Block(
                FederationBlockReason::WindowQuotaDisabled,
            ));
        }

        if self.pause_remaining(now).is_some() {
            return self.record(AllowBlock::Pause(FederationPauseReason::FloodPauseActive));
        }
        self.paused_until = None;

        if self.windows_touched.contains(key) {
            return self.record(AllowBlock::Allow);
        }

        if self.windows_touched.len() >= self.config.max_windows_per_connection {
            self.paused_until = now.checked_add(self.config.flood_pause).or(Some(now));
            return self.record(AllowBlock::Pause(
                FederationPauseReason::WindowQuotaExceeded,
            ));
        }

        self.windows_touched.insert(key.clone());
        self.record(AllowBlock::Allow)
    }

    /// Returns a snapshot suitable for logs, health surfaces, and tests.
    #[must_use]
    pub fn snapshot(&self, now: Instant) -> FederationQuotaSnapshot {
        let pause_remaining = self.pause_remaining(now);
        let decision = if self.config.max_windows_per_connection == 0 {
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        } else if pause_remaining.is_some() {
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        } else {
            self.last_decision
        };

        FederationQuotaSnapshot {
            windows_touched: self.windows_touched.len(),
            max_windows_per_connection: self.config.max_windows_per_connection,
            decision,
            pause_remaining,
        }
    }

    fn record(&mut self, decision: AllowBlock) -> AllowBlock {
        self.last_decision = decision;
        decision
    }

    fn pause_remaining(&self, now: Instant) -> Option<Duration> {
        self.paused_until
            .and_then(|until| until.checked_duration_since(now))
            .filter(|remaining| !remaining.is_zero())
    }
}

/// Owner-visible snapshot of one local maintenance-ingest quota bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceIngestQuotaSnapshot {
    /// Stable BLAKE3 peer digest used as the local quota key.
    pub peer_key_hex: String,
    /// Start of the current quota bucket, in Unix seconds.
    pub window_start_secs: u64,
    /// Accepted signed maintenance-band replay ops in the bucket.
    pub accepted_count: u32,
    /// Configured cap for the bucket.
    pub max_ops_per_peer_window: u32,
    /// Configured quota bucket width, in seconds.
    pub quota_window_secs: u64,
}

/// Device-local maintenance-band replay quota tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintenanceIngestQuotaConfig {
    /// Accepted signed maintenance-band replay ops per peer per quota window.
    pub max_ops_per_peer_window: u32,
    /// Quota bucket width, in seconds.
    pub quota_window_secs: u64,
}

impl Default for MaintenanceIngestQuotaConfig {
    fn default() -> Self {
        Self {
            max_ops_per_peer_window: DEFAULT_MAINTENANCE_INGEST_MAX_OPS_PER_PEER_WINDOW,
            quota_window_secs: DEFAULT_MAINTENANCE_INGEST_QUOTA_WINDOW_SECS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaintenanceIngestPeerKey([u8; 32]);

/// A quota debit that can be restored when later replicated-write validation
/// rejects the same remote op in a still-open Observer-B transaction.
pub(crate) struct MaintenanceIngestQuotaDebit {
    key: Vec<u8>,
    previous_value: Option<[u8; MAINTENANCE_INGEST_QUOTA_VALUE_LEN]>,
}

pub(crate) fn try_accept_maintenance_ingest_peer_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    peer_key: MaintenanceIngestPeerKey,
    now_secs: u64,
) -> Result<Option<MaintenanceIngestQuotaDebit>> {
    let config = maintenance_ingest_quota_config_in_rw_txn(vault, &*wtxn)?;
    let max_ops = config.max_ops_per_peer_window;
    let quota_window_secs = config.quota_window_secs;

    let window_start_secs = now_secs - (now_secs % quota_window_secs);
    let key = maintenance_ingest_quota_key(peer_key);
    let previous_value = match vault.store.sync_queue.get(&*wtxn, key.as_slice())? {
        Some(value) => {
            if value.len() != MAINTENANCE_INGEST_QUOTA_VALUE_LEN {
                return Err(Error::CorruptedIndex("maintenance ingest quota value"));
            }
            let mut raw = [0_u8; MAINTENANCE_INGEST_QUOTA_VALUE_LEN];
            raw.copy_from_slice(value);
            Some(raw)
        }
        None => None,
    };
    let (stored_window_start, stored_accepted_count) = match previous_value {
        Some(value) => decode_maintenance_ingest_quota_value(&value)?,
        None => (window_start_secs, 0),
    };

    let accepted_count = if stored_window_start == window_start_secs {
        stored_accepted_count
    } else {
        0
    };

    if accepted_count >= max_ops {
        return Err(Error::MaintenanceIngestQuotaExceeded {
            peer_key_hex: bytes_to_hex_lower(&peer_key.0),
            accepted_count,
            max_ops_per_peer_window: max_ops,
            window_start_secs,
            quota_window_secs,
        });
    }

    let next_count = accepted_count
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("maintenance ingest quota"))?;
    let value = encode_maintenance_ingest_quota_value(window_start_secs, next_count);
    vault.store.sync_queue.put(wtxn, key.as_slice(), &value)?;
    Ok(Some(MaintenanceIngestQuotaDebit {
        key,
        previous_value,
    }))
}

pub(crate) fn rollback_maintenance_ingest_debit_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    debit: MaintenanceIngestQuotaDebit,
) -> Result<()> {
    match debit.previous_value {
        Some(value) => vault
            .store
            .sync_queue
            .put(wtxn, debit.key.as_slice(), &value)?,
        None => {
            vault.store.sync_queue.delete(wtxn, debit.key.as_slice())?;
        }
    }
    Ok(())
}

/// Lists device-local maintenance-ingest quota counters.
pub fn maintenance_ingest_quota_snapshots(
    vault: &Vault,
) -> Result<Vec<MaintenanceIngestQuotaSnapshot>> {
    let rtxn = vault.store.env.read_txn()?;
    let config = maintenance_ingest_quota_config_in_ro_txn(vault, &rtxn)?;
    let mut snapshots = Vec::new();
    for row in vault
        .store
        .sync_queue
        .prefix_iter(&rtxn, MAINTENANCE_INGEST_QUOTA_PREFIX)?
    {
        let (key, value) = row?;
        if key.len() != MAINTENANCE_INGEST_QUOTA_PREFIX.len() + 32 {
            return Err(Error::CorruptedIndex("maintenance ingest quota key"));
        }
        let peer_key = &key[MAINTENANCE_INGEST_QUOTA_PREFIX.len()..];
        let (window_start_secs, accepted_count) = decode_maintenance_ingest_quota_value(value)?;
        snapshots.push(MaintenanceIngestQuotaSnapshot {
            peer_key_hex: bytes_to_hex_lower(peer_key),
            window_start_secs,
            accepted_count,
            max_ops_per_peer_window: config.max_ops_per_peer_window,
            quota_window_secs: config.quota_window_secs,
        });
    }
    snapshots.sort_by(|left, right| left.peer_key_hex.cmp(&right.peer_key_hex));
    Ok(snapshots)
}

/// Returns the device-local maintenance-ingest quota tunables.
pub fn maintenance_ingest_quota_config(vault: &Vault) -> Result<MaintenanceIngestQuotaConfig> {
    let rtxn = vault.store.env.read_txn()?;
    maintenance_ingest_quota_config_in_ro_txn(vault, &rtxn)
}

/// Stores device-local maintenance-ingest quota tunables.
///
/// The row lives in `sync_queue`'s `m:` family and is never mirrored into CRDT
/// state. Existing accepted counters are left in place; a lower cap can make a
/// peer over-quota until the next bucket.
pub fn set_maintenance_ingest_quota_config(
    vault: &Vault,
    config: MaintenanceIngestQuotaConfig,
) -> Result<()> {
    validate_maintenance_ingest_quota_config(config)?;
    let mut wtxn = vault.store.env.write_txn()?;
    let value = encode_maintenance_ingest_quota_config(config);
    vault
        .store
        .sync_queue
        .put(&mut wtxn, MAINTENANCE_INGEST_QUOTA_CONFIG_KEY, &value)?;
    wtxn.commit()?;
    Ok(())
}

pub(crate) fn peer_key_from_authority_key(key: &AuthorityKey) -> MaintenanceIngestPeerKey {
    match key {
        AuthorityKey::Ed25519(bytes) => peer_key_from_signature_key(b"ed25519", bytes),
        AuthorityKey::P256(bytes) => peer_key_from_signature_key(b"p256", bytes),
    }
}

pub(crate) fn peer_key_from_redaction_pubkey(pubkey: &[u8; 32]) -> MaintenanceIngestPeerKey {
    peer_key_from_signature_key(b"ed25519", pubkey)
}

pub(crate) fn peer_key_from_unknown_authority_signer(
    vault_id: AuthorityVaultId,
) -> MaintenanceIngestPeerKey {
    peer_key_from_signature_key(b"authority-unknown-vault", &vault_id)
}

fn peer_key_from_signature_key(suite: &[u8], public_key: &[u8]) -> MaintenanceIngestPeerKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MAINTENANCE_INGEST_QUOTA_PEER_DOMAIN);
    hasher.update(&[0]);
    hasher.update(suite);
    hasher.update(&[0]);
    hasher.update(public_key);
    MaintenanceIngestPeerKey(*hasher.finalize().as_bytes())
}

fn maintenance_ingest_quota_key(peer_key: MaintenanceIngestPeerKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(MAINTENANCE_INGEST_QUOTA_PREFIX.len() + peer_key.0.len());
    key.extend_from_slice(MAINTENANCE_INGEST_QUOTA_PREFIX);
    key.extend_from_slice(&peer_key.0);
    key
}

fn encode_maintenance_ingest_quota_value(window_start_secs: u64, accepted_count: u32) -> [u8; 12] {
    let mut value = [0_u8; MAINTENANCE_INGEST_QUOTA_VALUE_LEN];
    value[..8].copy_from_slice(&window_start_secs.to_le_bytes());
    value[8..].copy_from_slice(&accepted_count.to_le_bytes());
    value
}

fn decode_maintenance_ingest_quota_value(value: &[u8]) -> Result<(u64, u32)> {
    if value.len() != MAINTENANCE_INGEST_QUOTA_VALUE_LEN {
        return Err(Error::CorruptedIndex("maintenance ingest quota value"));
    }
    let window_start_secs = u64::from_le_bytes(
        value[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("maintenance ingest quota value"))?,
    );
    let accepted_count = u32::from_le_bytes(
        value[8..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("maintenance ingest quota value"))?,
    );
    Ok((window_start_secs, accepted_count))
}

fn maintenance_ingest_quota_config_in_ro_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<MaintenanceIngestQuotaConfig> {
    let Some(value) = vault
        .store
        .sync_queue
        .get(txn, MAINTENANCE_INGEST_QUOTA_CONFIG_KEY)?
    else {
        return Ok(MaintenanceIngestQuotaConfig::default());
    };
    decode_maintenance_ingest_quota_config(value)
}

fn maintenance_ingest_quota_config_in_rw_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
) -> Result<MaintenanceIngestQuotaConfig> {
    let Some(value) = vault
        .store
        .sync_queue
        .get(txn, MAINTENANCE_INGEST_QUOTA_CONFIG_KEY)?
    else {
        return Ok(MaintenanceIngestQuotaConfig::default());
    };
    decode_maintenance_ingest_quota_config(value)
}

fn validate_maintenance_ingest_quota_config(config: MaintenanceIngestQuotaConfig) -> Result<()> {
    if config.max_ops_per_peer_window == 0 {
        return Err(Error::InvalidConfig(
            "maintenance ingest quota max_ops_per_peer_window must be greater than zero".to_owned(),
        ));
    }
    if config.quota_window_secs == 0 {
        return Err(Error::InvalidConfig(
            "maintenance ingest quota quota_window_secs must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

fn encode_maintenance_ingest_quota_config(config: MaintenanceIngestQuotaConfig) -> [u8; 12] {
    let mut value = [0_u8; MAINTENANCE_INGEST_QUOTA_VALUE_LEN];
    value[..4].copy_from_slice(&config.max_ops_per_peer_window.to_le_bytes());
    value[4..].copy_from_slice(&config.quota_window_secs.to_le_bytes());
    value
}

fn decode_maintenance_ingest_quota_config(value: &[u8]) -> Result<MaintenanceIngestQuotaConfig> {
    if value.len() != MAINTENANCE_INGEST_QUOTA_VALUE_LEN {
        return Err(Error::CorruptedIndex("maintenance ingest quota config"));
    }
    let config = MaintenanceIngestQuotaConfig {
        max_ops_per_peer_window: u32::from_le_bytes(
            value[..4]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("maintenance ingest quota config"))?,
        ),
        quota_window_secs: u64::from_le_bytes(
            value[4..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("maintenance ingest quota config"))?,
        ),
    };
    validate_maintenance_ingest_quota_config(config)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: &str) -> WindowKey {
        WindowKey::new(value)
    }

    #[test]
    fn federation_quota_allows_known_windows_after_quota_is_reached() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(quota.snapshot(now).windows_touched, 1);
    }

    #[test]
    fn federation_quota_exceeded_enters_observable_pause() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 30));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(
            quota.allow_window(&key("2026-04"), now),
            AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
        );

        let snapshot = quota.snapshot(now);
        assert_eq!(
            snapshot.decision,
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        );
        assert_eq!(snapshot.pause_remaining, Some(Duration::from_secs(30)));
        assert_eq!(snapshot.windows_touched, 1);
    }

    #[test]
    fn federation_pause_resumes_after_pause_duration() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(1, 1));

        assert_eq!(quota.allow_window(&key("2026-03"), now), AllowBlock::Allow);
        assert_eq!(
            quota.allow_window(&key("2026-04"), now),
            AllowBlock::Pause(FederationPauseReason::WindowQuotaExceeded)
        );
        assert_eq!(
            quota.allow_window(&key("2026-03"), now),
            AllowBlock::Pause(FederationPauseReason::FloodPauseActive)
        );

        let resumed = now + Duration::from_secs(1);
        assert_eq!(
            quota.allow_window(&key("2026-03"), resumed),
            AllowBlock::Allow
        );
    }

    #[test]
    fn zero_federation_quota_blocks_connection() {
        let now = Instant::now();
        let mut quota = FederationConnectionQuota::new(FederationQuotaConfig::new(0, 30));

        assert_eq!(
            quota.allow_window(&key("2026-03"), now),
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        );
        assert_eq!(
            quota.snapshot(now).decision,
            AllowBlock::Block(FederationBlockReason::WindowQuotaDisabled)
        );
    }
}
