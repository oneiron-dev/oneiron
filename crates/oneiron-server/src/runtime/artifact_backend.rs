//! Host-configured concurrency custody for artifact backend requests.

use std::sync::Arc;

pub(crate) struct ArtifactBackendHost {
    pub(crate) profile: crate::config::ArtifactBackendConfig,
    pub(crate) sessions: Arc<tokio::sync::Semaphore>,
}

impl ArtifactBackendHost {
    pub(crate) fn new(profile: crate::config::ArtifactBackendConfig) -> anyhow::Result<Self> {
        profile.validate()?;
        let sessions = Arc::new(tokio::sync::Semaphore::new(profile.max_concurrent_sessions));
        Ok(Self { profile, sessions })
    }
}
