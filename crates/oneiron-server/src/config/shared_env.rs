//! `[[shared_env]]`: the dedicated shared-vault envs this host keeps open.
//!
//! One entry names one membership: the env directory holding the shared
//! vault, the shared `vault_id` and this member's person id the leave check
//! names, and the per-shared dial inputs (the shared home's sync endpoint
//! and this membership's lane slip file). The supervisor supplies managed
//! entries explicitly, never from HOME or XDG (FIX 5768); this module reads
//! no environment itself.
//!
//! File-only, like `[device_sync]`. The credential stays in its own file,
//! never in this one.

use std::path::PathBuf;

use serde::Deserialize;

/// One dedicated shared-vault env, as configured.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SharedEnvConfig {
    /// The dedicated env's directory: the vault root the registry opens.
    pub path: PathBuf,
    /// The shared vault id this membership names (the leave check's `vault_id`).
    pub vault_id: u64,
    /// This member's person id, 32 hex characters (the leave check's `member`).
    pub member: String,
    /// The shared home's sync endpoint, as `[device_sync]` names one: a `ws`
    /// or `wss` URL whose path is `/ws`.
    pub home_url: String,
    /// The file holding this membership's lane slip, in the `v2.cred.`
    /// one-string form. Only its owner may read it.
    pub credential_file: PathBuf,
}

impl SharedEnvConfig {
    /// Truthful malformed-input errors only: an empty path, a member that is
    /// not a person id, a home endpoint that is not a sync URL, an empty
    /// credential path. A bad entry never refuses the serve: the registry
    /// logs and skips it.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.path.as_os_str().is_empty(),
            "[shared_env] path names the dedicated env's directory"
        );
        oneiron::EntityId::from_hex(self.member.trim()).map_err(|_| {
            anyhow::anyhow!("[shared_env] member is not a person id (32 hex characters)")
        })?;
        crate::config::device_sync::validate_home_url(&self.home_url)
            .map_err(|error| anyhow::anyhow!("[shared_env] {error}"))?;
        anyhow::ensure!(
            !self.credential_file.as_os_str().is_empty(),
            "[shared_env] credential_file names the lane slip file"
        );
        Ok(())
    }
}
