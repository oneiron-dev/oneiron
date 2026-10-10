//! Vault-resident operational schedules and per-pass limits (DEC-0005).
//! Absence reads the shipped defaults; trusted manifests compose restrictively.

use rmpv::Value;

use crate::error::{Error, Result};
use crate::store::Store;
use crate::vault::Vault;

use super::resolution::resolve_policy_manifest;

pub(super) const LINEAR_MIRROR_KEY: &str = "linear_mirror_policy";
pub(super) const LINEAR_SYNC_KEY: &str = "linear_sync_budget";
pub(super) const WAVE_HANDOFF_KEY: &str = "wave_handoff_policy";
pub(super) const PRECEDENCE_KEY: &str = "operational_policy_precedence";

/// Default nested narrowing. A holder may replace its own local selection,
/// but may never exceed the vault's authority (the same clamp as nesting).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum PolicyPrecedence {
    #[default]
    NestedNarrowing,
    HolderOverrideCappedAtVault,
}

impl PolicyPrecedence {
    pub(super) fn decode(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_override_capped_at_vault" => Some(Self::HolderOverrideCappedAtVault),
            _ => None,
        }
    }
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::HolderOverrideCappedAtVault => "holder_override_capped_at_vault",
        }
    }
}

/// The polling floor is a minimum wait; the request timeout is a maximum
/// duration of an authenticated transport attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinearMirrorPolicy {
    pub poll_interval_secs: u64,
    pub policy_frontier: [u8; 32],
    pub request_timeout_secs: u64,
}

impl Default for LinearMirrorPolicy {
    fn default() -> Self {
        Self {
            poll_interval_secs: 30,
            request_timeout_secs: 15,
            policy_frontier: [0; 32],
        }
    }
}

impl LinearMirrorPolicy {
    fn valid(self) -> bool {
        (1..=86_400).contains(&self.poll_interval_secs)
            && (1..=300).contains(&self.request_timeout_secs)
    }
    pub(super) fn decode(value: &Value) -> Option<Self> {
        let e = entries(value, &["poll_interval_secs", "request_timeout_secs"])?;
        let row = Self {
            poll_interval_secs: number(e, "poll_interval_secs")?,
            request_timeout_secs: number(e, "request_timeout_secs")?,
            policy_frontier: [0; 32],
        };
        row.valid().then_some(row)
    }
    pub(super) fn restrict(self, other: Self) -> Self {
        Self {
            poll_interval_secs: self.poll_interval_secs.max(other.poll_interval_secs),
            request_timeout_secs: self.request_timeout_secs.min(other.request_timeout_secs),
            policy_frontier: self.policy_frontier,
        }
    }
    /// Holder settings are optional. A holder can make a poll less frequent
    /// or a request shorter; attempted widening is rejected, not clamped.
    pub fn with_holder(self, holder: Option<Self>) -> Result<Self> {
        let Some(holder) = holder else {
            return Ok(self);
        };
        if !holder.valid()
            || holder.restrict(self).poll_interval_secs != holder.poll_interval_secs
            || holder.restrict(self).request_timeout_secs != holder.request_timeout_secs
        {
            return Err(Error::InvalidConfig(
                "linear mirror holder override exceeds vault policy".into(),
            ));
        }
        Ok(Self {
            policy_frontier: self.policy_frontier,
            ..holder
        })
    }
}

/// Maximum number of inbound pages attempted before outbound reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinearSyncBudget {
    pub max_pull_pages_per_pass: usize,
    pub policy_frontier: [u8; 32],
}

impl Default for LinearSyncBudget {
    fn default() -> Self {
        Self {
            max_pull_pages_per_pass: 64,
            policy_frontier: [0; 32],
        }
    }
}

impl LinearSyncBudget {
    fn valid(self) -> bool {
        (1..=1024).contains(&self.max_pull_pages_per_pass)
    }
    pub(super) fn decode(value: &Value) -> Option<Self> {
        let e = entries(value, &["max_pull_pages_per_pass"])?;
        let row = Self {
            max_pull_pages_per_pass: usize::try_from(number(e, "max_pull_pages_per_pass")?).ok()?,
            policy_frontier: [0; 32],
        };
        row.valid().then_some(row)
    }
    pub(super) fn restrict(self, other: Self) -> Self {
        Self {
            max_pull_pages_per_pass: self
                .max_pull_pages_per_pass
                .min(other.max_pull_pages_per_pass),
            policy_frontier: self.policy_frontier,
        }
    }
    pub fn with_holder(self, holder: Option<Self>) -> Result<Self> {
        let Some(holder) = holder else {
            return Ok(self);
        };
        if !holder.valid() || holder.max_pull_pages_per_pass > self.max_pull_pages_per_pass {
            return Err(Error::InvalidConfig(
                "linear sync holder override exceeds vault policy".into(),
            ));
        }
        Ok(Self {
            policy_frontier: self.policy_frontier,
            ..holder
        })
    }
}

/// The wave dispatch read page and retry backoff window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaveHandoffPolicy {
    pub scan_limit: usize,
    pub policy_frontier: [u8; 32],
    pub retry_floor_ms: u64,
    pub retry_cap_ms: u64,
}

impl Default for WaveHandoffPolicy {
    fn default() -> Self {
        Self {
            scan_limit: 256,
            retry_floor_ms: 500,
            retry_cap_ms: 60_000,
            policy_frontier: [0; 32],
        }
    }
}

impl WaveHandoffPolicy {
    fn valid(self) -> bool {
        (1..=256).contains(&self.scan_limit)
            && (1..=60_000).contains(&self.retry_floor_ms)
            && (self.retry_floor_ms..=300_000).contains(&self.retry_cap_ms)
    }
    pub(super) fn decode(value: &Value) -> Option<Self> {
        let e = entries(value, &["scan_limit", "retry_floor_ms", "retry_cap_ms"])?;
        let row = Self {
            scan_limit: usize::try_from(number(e, "scan_limit")?).ok()?,
            retry_floor_ms: number(e, "retry_floor_ms")?,
            retry_cap_ms: number(e, "retry_cap_ms")?,
            policy_frontier: [0; 32],
        };
        row.valid().then_some(row)
    }
    pub(super) fn restrict(self, other: Self) -> Self {
        Self {
            scan_limit: self.scan_limit.min(other.scan_limit),
            retry_floor_ms: self.retry_floor_ms.max(other.retry_floor_ms),
            retry_cap_ms: self.retry_cap_ms.max(other.retry_cap_ms),
            policy_frontier: self.policy_frontier,
        }
    }
    pub fn with_holder(self, holder: Option<Self>) -> Result<Self> {
        let Some(holder) = holder else {
            return Ok(self);
        };
        if !holder.valid()
            || holder.scan_limit > self.scan_limit
            || holder.retry_floor_ms < self.retry_floor_ms
            || holder.retry_cap_ms < self.retry_cap_ms
        {
            return Err(Error::InvalidConfig(
                "wave handoff holder override exceeds vault policy".into(),
            ));
        }
        Ok(Self {
            policy_frontier: self.policy_frontier,
            ..holder
        })
    }
}

fn entries<'a>(value: &'a Value, fields: &[&str]) -> Option<&'a [(Value, Value)]> {
    let Value::Map(entries) = value else {
        return None;
    };
    if entries.len() != fields.len()
        || entries
            .iter()
            .any(|(key, _)| key.as_str().is_none_or(|key| !fields.contains(&key)))
    {
        return None;
    }
    Some(entries)
}
fn number(entries: &[(Value, Value)], field: &str) -> Option<u64> {
    let mut matches = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(field));
    let (_, value) = matches.next()?;
    matches.next().is_none().then(|| value.as_u64()).flatten()
}

impl Vault {
    /// Resolve policy in one fresh vault snapshot. No host-supplied value can
    /// override a malformed, unsupported, or missing policy manifest.
    pub fn linear_mirror_policy(&self) -> Result<LinearMirrorPolicy> {
        let policy = operational_resolution(&self.store)?;
        Ok(LinearMirrorPolicy {
            policy_frontier: policy.read_frontier_hash()?,
            ..policy.linear_mirror()
        })
    }
    pub fn linear_sync_budget(&self) -> Result<LinearSyncBudget> {
        let policy = operational_resolution(&self.store)?;
        Ok(LinearSyncBudget {
            policy_frontier: policy.read_frontier_hash()?,
            ..policy.linear_sync()
        })
    }
    pub fn wave_handoff_policy(&self) -> Result<WaveHandoffPolicy> {
        let policy = operational_resolution(&self.store)?;
        Ok(WaveHandoffPolicy {
            policy_frontier: policy.read_frontier_hash()?,
            ..policy.wave_handoff()
        })
    }
}

fn operational_resolution(store: &Store) -> Result<super::resolution::PolicyManifestResolution> {
    let txn = store.env.read_txn()?;
    let policy = resolve_policy_manifest(store, &txn)?;
    if policy.is_fail_closed() {
        return Err(Error::InvalidConfig(
            "operational policy manifest resolution is fail-closed".into(),
        ));
    }
    Ok(policy)
}
