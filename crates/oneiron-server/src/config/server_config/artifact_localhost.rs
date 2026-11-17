//! The host a local vault answers on under `*.localhost` (APP-HOST = A),
//! which serve names on the operator's log at start.

use oneiron_vault_contract::artifact_origin::{
    ArtifactHost, ArtifactHostRead, LOCAL_ARTIFACT_DOMAIN,
};

use super::SyncServerConfig;

impl SyncServerConfig {
    /// The host this vault answers on under `*.localhost` (APP-HOST = A):
    /// `<name>.localhost`, and each app at `<app>--<name>.localhost`, on the
    /// artifact listener's port. `None` on a managed vault (its internal
    /// authority alone), with no vault name, or for a name the artifact
    /// listener does not serve, as `api::artifact_app` reads them. Serve names
    /// it on the operator's own log at start; the unauthenticated
    /// `/api/health` names no vault (FIX LOCALHOST-HOST-DISCOVERY).
    pub fn local_artifact_vault_host(&self) -> Option<String> {
        if self.artifact_internal_vault_id.is_some() {
            return None;
        }
        let name = self.artifact_vault_name.as_deref()?.to_ascii_lowercase();
        let host = ArtifactHost::vault(name.as_str()).name(LOCAL_ARTIFACT_DOMAIN)?;
        // The listener reads the configured domains first and `localhost`
        // last, so a configured domain that claims this host answers it.
        let mut domains = self.artifact_domains.clone();
        domains.push(LOCAL_ARTIFACT_DOMAIN.to_owned());
        match ArtifactHost::read(&host, &domains) {
            ArtifactHostRead::Named(named) if named.vault == name && named.app.is_none() => {
                Some(host)
            }
            _ => None,
        }
    }
}
