//! Content-free, versioned tier-1 agent failure counts. This taxonomy is not
//! the failure ladder's retry-routing class or a detector's repair tier.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::config::failure_signals::FailureSignalConfig;
use crate::error::{Error, Result};

/// Adding a class (including graduating `Other`) requires a new taxonomy
/// variant and version; never reinterpret an existing exported v1 class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "taxonomy_version", content = "failure_class")]
pub enum FailureTaxonomy {
    #[serde(rename = "v1")]
    V1(FailureClassV1),
}

/// The nine closed classes of the first observability taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassV1 {
    RefusalOverreach,
    TaskFailure,
    UserFrustration,
    MemoryMiss,
    MemoryIntrusion,
    PersonaBreak,
    LatencyAbandon,
    SilentDegradation,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    System,
    Custom,
}

/// Only a registered component label and its version, never prompt or content.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VersionedComponent {
    pub name: String,
    pub version: String,
}

/// The closed dimensions of a bucket. `ts_bucket` is a UTC Unix-hour start
/// (seconds since epoch). A producer supplies the observation time; this
/// component rounds it down and does not accept caller-chosen bucket values.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FailureSignalDimensions {
    #[serde(flatten)]
    pub taxonomy: FailureTaxonomy,
    pub agent_kind: AgentKind,
    pub agent: VersionedComponent,
    pub model: VersionedComponent,
    pub engine: VersionedComponent,
    /// Required for `Other` only. Bounded machine identifier, never a sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detector_id: Option<String>,
    pub ts_bucket: i64,
}

/// A tier-1 export row has only dimensions and a count. There is no transcript,
/// detail, entity reference, actor name, or free-form content field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tier1FailureCount {
    #[serde(flatten)]
    pub dimensions: FailureSignalDimensions,
    pub count: u64,
}

/// One vault's in-memory aggregate. No cross-vault or process-wide state.
#[derive(Default)]
pub struct FailureSignalCounts {
    counts: Mutex<BTreeMap<FailureSignalDimensions, u64>>,
}

impl FailureSignalCounts {
    /// Record one typed observation. Off-record observations must never enter
    /// this door; no sample or diagnostic detail is accepted by its type.
    pub fn record(
        &self,
        config: FailureSignalConfig,
        mut dimensions: FailureSignalDimensions,
        observed_at: i64,
    ) -> Result<()> {
        if !config.exports() {
            return Ok(());
        }
        dimensions.ts_bucket = observed_at.div_euclid(3600) * 3600;
        validate(&dimensions)?;
        let mut counts = self
            .counts
            .lock()
            .map_err(|_| Error::InvalidConfig("failure signal counters poisoned".into()))?;
        let count = counts.entry(dimensions).or_default();
        *count = count
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("failure signal count"))?;
        Ok(())
    }

    /// Snapshot content-free counts. OSS/self-host exports remain default-off.
    pub fn export(&self, config: FailureSignalConfig) -> Result<Vec<Tier1FailureCount>> {
        if !config.exports() {
            return Ok(Vec::new());
        }
        let counts = self
            .counts
            .lock()
            .map_err(|_| Error::InvalidConfig("failure signal counters poisoned".into()))?;
        Ok(counts
            .iter()
            .map(|(dimensions, count)| Tier1FailureCount {
                dimensions: dimensions.clone(),
                count: *count,
            })
            .collect())
    }
}

fn validate(d: &FailureSignalDimensions) -> Result<()> {
    fn machine_id(s: &str) -> bool {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    }
    for component in [&d.agent, &d.model, &d.engine] {
        if !machine_id(&component.name) || !machine_id(&component.version) {
            return Err(Error::InvalidConfig(
                "failure signal component label must be a bounded machine identifier".into(),
            ));
        }
    }
    match (d.taxonomy, d.detector_id.as_deref()) {
        (FailureTaxonomy::V1(FailureClassV1::Other), Some(id)) if machine_id(id) => {}
        (FailureTaxonomy::V1(FailureClassV1::Other), _) => {
            return Err(Error::InvalidConfig(
                "other requires a bounded detector id".into(),
            ));
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(Error::InvalidConfig(
                "detector id belongs only to other".into(),
            ));
        }
    }
    Ok(())
}

impl crate::Vault {
    /// Record a detector's content-free classification for this vault.
    pub fn record_failure_signal(
        &self,
        dimensions: FailureSignalDimensions,
        observed_at: i64,
    ) -> Result<()> {
        self.store.diagnostics.failure_signals.record(
            self.config.failure_signals,
            dimensions,
            observed_at,
        )
    }

    /// Export this vault's current tier-1 aggregate, subject to deployment policy.
    pub fn export_tier1_failure_counts(&self) -> Result<Vec<Tier1FailureCount>> {
        self.store
            .diagnostics
            .failure_signals
            .export(self.config.failure_signals)
    }
}

#[cfg(test)]
mod tests;
