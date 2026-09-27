//! Content-free, versioned tier-1 agent failure counts. This taxonomy is not
//! the failure ladder's retry-routing class or a detector's repair tier.

use std::collections::BTreeMap;
use std::sync::Mutex;

use rand_core::RngCore;
use serde::{Deserialize, Serialize};

pub(crate) mod policy;

use crate::config::failure_signals::FailureSignalConfig;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{LlmRole, ModelId};
use crate::vault::LiveEntityRow;

/// Graduating `Other` requires a new taxonomy variant and version; never
/// reinterpret a previously exported class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "taxonomy_version", content = "failure_class")]
pub enum FailureTaxonomy {
    #[serde(rename = "v1")]
    V1(FailureClassV1),
}

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

/// The closed, content-free surface vocabulary. A new surface needs a reviewed
/// enum addition, not a caller-supplied name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSurface {
    Chat,
    Voice,
    Code,
    Task,
    Background,
    Other,
}

/// Raw metadata is accepted only at the recording door and is never stored in
/// the aggregate or returned by export. These values may be user-authored.
#[derive(Debug, Clone)]
pub struct VersionedComponent {
    pub name: String,
    pub version: String,
}

/// Classification supplied by a detector, with no caller-chosen event time or
/// detector ID. The record door derives both from a stored diagnostic witness.
#[derive(Debug, Clone)]
pub struct FailureSignalInput {
    pub taxonomy: FailureTaxonomy,
    pub agent_surface: AgentSurface,
    pub agent_kind: AgentKind,
    pub agent: VersionedComponent,
    /// Required for system agents; pinned to the compiled seeded roster.
    pub agent_ref: Option<EntityId>,
    /// Terminal runner step cited by the diagnostic, if this failure came
    /// from an LLM execution. None exports an honest unattributed model.
    pub model_step_ref: Option<EntityId>,
}

/// Only keyed, per-vault opaque tokens enter the export. The secret key stays
/// on the vault handle; even a guessed custom name cannot be tested offline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportVersionedComponent {
    name: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FailureSignalDimensions {
    #[serde(flatten)]
    taxonomy: FailureTaxonomy,
    agent_surface: AgentSurface,
    agent_kind: AgentKind,
    agent: ExportVersionedComponent,
    model: ExportVersionedComponent,
    engine: ExportVersionedComponent,
    /// Opaque ID derived from the verified diagnostic, only for `Other`.
    #[serde(skip_serializing_if = "Option::is_none")]
    detector_id: Option<String>,
    /// UTC Unix-hour start (seconds since epoch).
    ts_bucket: i64,
    /// Exact resolution so a live policy change cannot merge unlike buckets.
    bucket_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tier1FailureCount {
    #[serde(flatten)]
    dimensions: FailureSignalDimensions,
    count: u64,
}

impl Tier1FailureCount {
    /// The exact content-free dimensions of this aggregate.
    #[must_use]
    pub const fn dimensions(&self) -> &FailureSignalDimensions {
        &self.dimensions
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

impl FailureSignalDimensions {
    #[must_use]
    pub const fn taxonomy(&self) -> FailureTaxonomy {
        self.taxonomy
    }
    #[must_use]
    pub const fn agent_surface(&self) -> AgentSurface {
        self.agent_surface
    }
    #[must_use]
    pub const fn agent_kind(&self) -> AgentKind {
        self.agent_kind
    }
    #[must_use]
    pub const fn ts_bucket(&self) -> i64 {
        self.ts_bucket
    }
    #[must_use]
    pub const fn bucket_seconds(&self) -> u64 {
        self.bucket_seconds
    }
}

#[derive(Default)]
struct VerifiedIdentity {
    agent: Option<VersionedComponent>,
    model: Option<ModelId>,
}

/// One open vault's in-memory counts. Neither the key nor raw input is exported.
pub(crate) struct FailureSignalCounts {
    key: [u8; 32],
    counts: Mutex<BTreeMap<FailureSignalDimensions, u64>>,
}

impl Default for FailureSignalCounts {
    fn default() -> Self {
        let mut key = [0; 32];
        rand_core::OsRng.fill_bytes(&mut key);
        Self {
            key,
            counts: Mutex::default(),
        }
    }
}

impl FailureSignalCounts {
    fn token(&self, domain: &[u8], raw: &str) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.key);
        hasher.update(domain);
        hasher.update(&(raw.len() as u64).to_le_bytes());
        hasher.update(raw.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    fn record(
        &self,
        config: FailureSignalConfig,
        input: FailureSignalInput,
        verified: VerifiedIdentity,
        policy: policy::Resolved,
        observed_at: i64,
        detector_id: &str,
    ) -> Result<()> {
        if !config.exports() {
            return Ok(());
        }
        let ts_bucket = bucket_start(observed_at, policy.bucket_seconds)?;
        if !bounded(&input.agent, policy.max_component_bytes) {
            return Err(Error::InvalidConfig(
                "failure signal component must be a bounded identifier".into(),
            ));
        }
        let dimensions = FailureSignalDimensions {
            taxonomy: input.taxonomy,
            agent_surface: input.agent_surface,
            agent_kind: input.agent_kind,
            agent: if let Some(identity) = verified.agent {
                ExportVersionedComponent {
                    name: identity.name,
                    version: identity.version,
                }
            } else {
                component(self, b"agent", &input.agent)
            },
            model: executed_model(self, verified.model.as_ref()),
            engine: ExportVersionedComponent {
                name: "oneiron".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            detector_id: matches!(input.taxonomy, FailureTaxonomy::V1(FailureClassV1::Other)).then(
                || {
                    registered_detector(detector_id)
                        .map_or_else(|| self.token(b"detector", detector_id), str::to_owned)
                },
            ),
            ts_bucket,
            bucket_seconds: policy.bucket_seconds,
        };
        let mut counts = self
            .counts
            .lock()
            .map_err(|_| Error::InvariantViolation("failure signal counters poisoned"))?;
        let count = counts.entry(dimensions).or_default();
        *count = count
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("failure signal count"))?;
        Ok(())
    }

    fn export(&self, config: FailureSignalConfig) -> Result<Vec<Tier1FailureCount>> {
        if !config.exports() {
            return Ok(Vec::new());
        }
        let counts = self
            .counts
            .lock()
            .map_err(|_| Error::InvariantViolation("failure signal counters poisoned"))?;
        Ok(counts
            .iter()
            .map(|(dimensions, count)| Tier1FailureCount {
                dimensions: dimensions.clone(),
                count: *count,
            })
            .collect())
    }
}

fn executed_model(
    counts: &FailureSignalCounts,
    model: Option<&ModelId>,
) -> ExportVersionedComponent {
    let Some(model) = model else {
        return ExportVersionedComponent {
            name: "unattributed".into(),
            version: "unattributed".into(),
        };
    };
    // Only compiled public model IDs are cleartext. A host's override may be
    // arbitrary/private metadata, so it remains an opaque per-vault identity.
    let registered = [
        LlmRole::Orchestrator,
        LlmRole::Subagent,
        LlmRole::Summarizer,
    ]
    .into_iter()
    .any(|role| role.default_model_id_str() == model.as_str());
    if registered {
        ExportVersionedComponent {
            name: format!("{}/{}", model.provider(), model.name()),
            version: model.revision().to_owned(),
        }
    } else {
        ExportVersionedComponent {
            name: counts.token(
                b"model.name",
                &format!("{}/{}", model.provider(), model.name()),
            ),
            version: counts.token(b"model.version", model.revision()),
        }
    }
}

/// Only compiled detector identities may travel across vaults in clear.
/// Unknown/custom detector IDs remain per-vault opaque tokens.
fn registered_detector(id: &str) -> Option<&'static str> {
    const IDS: [&str; 7] = [
        "consent.denied.v1",
        "retrieval.miss.v1",
        "consolidation.error.v1",
        "dreamer.degenerate.v1",
        "conversation.silent.v1",
        "consent.storm.v1",
        "predicate.drift.v1",
    ];
    IDS.into_iter().find(|registered| *registered == id)
}

fn bounded(component: &VersionedComponent, max_bytes: u64) -> bool {
    [&component.name, &component.version]
        .into_iter()
        .all(|s| !s.is_empty() && u64::try_from(s.len()).is_ok_and(|n| n <= max_bytes))
}
fn component(
    counts: &FailureSignalCounts,
    domain: &[u8],
    value: &VersionedComponent,
) -> ExportVersionedComponent {
    let mut name_domain = domain.to_vec();
    name_domain.extend_from_slice(b".name");
    let mut version_domain = domain.to_vec();
    version_domain.extend_from_slice(b".version");
    ExportVersionedComponent {
        name: counts.token(&name_domain, &value.name),
        version: counts.token(&version_domain, &value.version),
    }
}
fn bucket_start(observed_at: i64, bucket_seconds: u64) -> Result<i64> {
    let width = i64::try_from(bucket_seconds)
        .map_err(|_| Error::ArithmeticOverflow("failure signal bucket width"))?;
    if width == 0 {
        return Err(Error::InvalidConfig(
            "failure signal bucket width must be positive".into(),
        ));
    }
    observed_at
        .div_euclid(width)
        .checked_mul(width)
        .ok_or(Error::ArithmeticOverflow("failure signal hour bucket"))
}

impl crate::Vault {
    /// Record a failure only for a live DIAGNOSTIC in the base vault. Session
    /// overlay events have no base row and cannot supply this witness, even
    /// after their off-record room closes. No source ref reaches the export.
    pub fn record_failure_signal(
        &self,
        evidence_id: EntityId,
        input: FailureSignalInput,
    ) -> Result<()> {
        if !self.config.failure_signals.exports() {
            return Ok(());
        }
        if self
            .store
            .off_record_sessions
            .contains_entity(&evidence_id)?
        {
            return Err(Error::InvariantViolation(
                "off-record evidence cannot enter failure signals",
            ));
        }
        let rtxn = self.store.env.read_txn()?;
        let body = match crate::vault::live_entity_row_in_txn(&self.store, &rtxn, &evidence_id)? {
            LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_DIAGNOSTIC,
                body,
            } => body,
            _ => {
                return Err(Error::InvalidConfig(
                    "failure signal requires an on-record diagnostic".into(),
                ));
            }
        };
        let event = crate::self_heal::decode_diagnostic_event_body(&body)?;
        if crate::self_heal::diagnostic_event_id(&event.detector_id, &body) != evidence_id {
            return Err(Error::InvariantViolation(
                "failure signal diagnostic address changed",
            ));
        }
        crate::self_heal::tier1_source::verify(&self.store, &rtxn, &event, input.model_step_ref)?;
        let verified_model = input
            .model_step_ref
            .map(|step| {
                crate::llm::verified_executed_model(
                    self,
                    &rtxn,
                    &step,
                    event.replay.run_ref.as_deref().unwrap_or_default(),
                )
            })
            .transpose()?
            .flatten();
        if input.model_step_ref.is_some() && verified_model.is_none() {
            return Err(Error::InvalidConfig(
                "failure signal requires a verified terminal model step".into(),
            ));
        }
        // heed permits only one read slot per thread on this handle. The
        // source check is complete; release its snapshot before resolving the
        // seeded AGENT_DEF through the ordinary vault reader.
        drop(rtxn);
        let registered_agent = if input.agent_kind == AgentKind::System {
            let id = input.agent_ref.ok_or(Error::InvalidConfig(
                "system failure signal requires seeded agent id".into(),
            ))?;
            let (name, version) = crate::agent_def::system_export_identity(&id)?.ok_or(
                Error::InvalidConfig("system failure signal agent is not seeded".into()),
            )?;
            let stored = self
                .get_agent_definition(&id)?
                .ok_or(Error::InvalidConfig("seeded system agent is absent".into()))?;
            if stored.logical_id.as_deref() != Some(name)
                || stored.version != version
                || input.agent.name != name
                || input.agent.version != version
            {
                return Err(Error::InvalidConfig(
                    "system failure signal identity differs from compiled roster".into(),
                ));
            }
            Some(VersionedComponent {
                name: name.to_owned(),
                version: version.to_owned(),
            })
        } else {
            if let Some(id) = input.agent_ref {
                if crate::agent_def::system_export_identity(&id)?.is_some() {
                    return Err(Error::InvalidConfig(
                        "custom failure signal cannot claim a seeded agent".into(),
                    ));
                }
                let stored = self.get_agent_definition(&id)?.ok_or(Error::InvalidConfig(
                    "custom failure signal agent is absent".into(),
                ))?;
                if stored.agent_id != input.agent.name || stored.version != input.agent.version {
                    return Err(Error::InvalidConfig(
                        "custom failure signal agent identity differs from stored definition"
                            .into(),
                    ));
                }
            }
            None
        };
        let policy = {
            let txn = self.store.env.read_txn()?;
            let manifest = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
            if manifest.diagnostics().loaded_manifest_forces_fail_closed() {
                return Err(Error::InvalidConfig(
                    "failure signal policy manifest malformed".into(),
                ));
            }
            policy::resolve(&manifest.failure_signal_policy, input.agent_ref)
        };
        let observed_at = i64::try_from(event.valid_from)
            .map_err(|_| Error::ArithmeticOverflow("failure signal observation time"))?;
        self.store.diagnostics.failure_signals.record(
            self.config.failure_signals,
            input,
            VerifiedIdentity {
                agent: registered_agent,
                model: verified_model,
            },
            policy,
            observed_at,
            &event.detector_id,
        )
    }

    /// Export this vault's current content-free tier-1 aggregate.
    pub fn export_tier1_failure_counts(&self) -> Result<Vec<Tier1FailureCount>> {
        self.store
            .diagnostics
            .failure_signals
            .export(self.config.failure_signals)
    }
}

#[cfg(test)]
mod tests;
