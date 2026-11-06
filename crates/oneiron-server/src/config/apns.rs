//! `[apns]`: the Apple push applications this host sends through.
//! File-only, like `[channel_endpoints]`. Absent, or no application named,
//! means Apple push sends have no application to send with. Each entry names
//! one application's team, signing key, topic and environment; the signing
//! key itself stays in the secret store and the entry carries only its
//! reference, never key material.
//!
//! ```toml
//! [apns]
//! [[apns.applications]]
//! id = "main"
//! team_id = "TEAMID1234"
//! key_id = "KEYID12345"
//! topic = "com.example.app"
//! environment = "production"
//! signing_key_ref = "<immutable SECRET record id>"
//! ```

use oneiron::outbound::ApnsAppConfig;
use serde::Deserialize;

/// The Apple push applications a host sends through; none by default.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApnsConfig {
    /// One entry per application, as `[[apns.applications]]`; empty sends none.
    #[serde(default)]
    pub applications: Vec<ApnsAppConfig>,
}

impl ApnsConfig {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        let mut ids = std::collections::BTreeSet::new();
        for app in &self.applications {
            app.validate()
                .map_err(|error| anyhow::anyhow!("[apns]: {error}"))?;
            if !ids.insert(app.id.as_str()) {
                anyhow::bail!("[apns] lists application {} twice", app.id);
            }
        }
        Ok(())
    }
}
