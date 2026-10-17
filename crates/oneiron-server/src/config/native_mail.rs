//! `[native_mail]`: the host's own mail server, a Stalwart instance serving
//! one domain the owner controls (OF-519).
//!
//! File-only, like `[browser]`. The host owns the server, its DNS and its
//! keys; the section names where it is, so the native mail pack's connection
//! check can reach it with the credential the owner stored. Absent means the
//! check refuses and the pack stays a Candidate.

use oneiron::channel_identity_provider::native_mail::NativeMailRunMode;
use oneiron::channel_identity_provider::stalwart::StalwartConfig;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeMailConfig {
    /// The server's JMAP session URL: https, or http on loopback.
    pub session_url: String,
    /// The exact domain the server delivers for.
    pub domain: String,
    /// The domain's id in the server's registry.
    pub domain_id: String,
    /// What the host calls this server; the domain when unset.
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub mode: NativeMailMode,
}

/// Who runs the server: the owner on their own host, or Oneiron's cloud.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeMailMode {
    #[default]
    SelfRun,
    CloudRun,
}

impl NativeMailConfig {
    /// The placement the engine's Stalwart client connects with. A check binds
    /// no owner mailbox, so the instance stands for the owner binding too.
    pub(crate) fn stalwart(&self) -> oneiron::Result<StalwartConfig> {
        let instance = self.instance.clone().unwrap_or_else(|| self.domain.clone());
        StalwartConfig::new(
            &self.session_url,
            instance.clone(),
            instance,
            &self.domain,
            self.domain_id.clone(),
            match self.mode {
                NativeMailMode::SelfRun => NativeMailRunMode::SelfRun,
                NativeMailMode::CloudRun => NativeMailRunMode::CloudRun,
            },
        )
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.stalwart()
            .map(|_| ())
            .map_err(|error| anyhow::anyhow!("[native_mail]: {error}"))
    }
}
