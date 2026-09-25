//! Host-configured remote rung and cached per-entity egress decisions.
use super::{EmbedderConfig, EmbedderLocality, EmbedderProvider, EndpointEmbedderConfig};
use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct EgressPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    /// An explicit host authorization, never a default verdict.
    pub allow_all: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemoteEmbedderConfig {
    pub endpoint: String,
    pub model_key: String,
    pub locality: EmbedderLocality,
    #[serde(default)]
    pub artifact: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default = "remote_lease")]
    pub lease_ms: u64,
    #[serde(default = "remote_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
}
fn remote_lease() -> u64 {
    oneiron::embed::DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS
}
fn remote_timeout() -> u64 {
    60_000
}

impl RemoteEmbedderConfig {
    pub(crate) fn endpoint_config(&self, primary: &EmbedderConfig) -> EmbedderConfig {
        let mut config = primary.clone();
        config.provider = EmbedderProvider::Endpoint;
        config.remote = None;
        config.endpoint = EndpointEmbedderConfig {
            endpoint: Some(self.endpoint.clone()),
            model_key: Some(self.model_key.clone()),
            locality: self.locality,
            artifact: self.artifact.clone(),
            api_key_env: self.api_key_env.clone(),
            timeout_ms: self.timeout_ms,
        };
        config
    }
}

/// Used by config resolution AND slot construction so programmatic hosts cannot
/// bypass the startup egress requirement.
pub(crate) fn validate_remote(primary: &EmbedderConfig) -> oneiron::Result<()> {
    use oneiron::Error;
    if primary.endpoint.locality != EmbedderLocality::OnDevice {
        return Err(Error::InvalidConfig("third-party and owner-server endpoints require embedder.remote, an egress predicate and an on-device primary".into()));
    }
    let Some(remote) = &primary.remote else {
        return Ok(());
    };
    if !primary.is_active()
        || remote.locality == EmbedderLocality::OnDevice
        || remote.lease_ms == 0
        || remote.timeout_ms == 0
        || remote.endpoint.trim().is_empty()
        || remote.model_key.trim().is_empty()
    {
        return Err(Error::InvalidConfig("invalid remote embedder rung".into()));
    }
    let policy = remote.egress.as_ref().ok_or_else(|| {
        Error::InvalidConfig("remote embedder requires a host egress predicate".into())
    })?;
    for id in policy.allow.iter().chain(&policy.deny) {
        oneiron::EntityId::from_hex(id)
            .map_err(|_| Error::InvalidConfig("egress policy entity id is invalid".into()))?;
    }
    Ok(())
}
