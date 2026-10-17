//! `[device_sync]`: the home this machine keeps its vault in sync with.
//! Every machine but the elected home dials its home (ARCH-0023b); the home
//! dials no one.
//!
//! File-only, like `[native_mail]`. Absent means this machine dials no one.
//! Present, `serve` dials the named home over the paired mesh once this
//! install is an enrolled machine and the home a live paired one
//! (`crate::device_sync`). The credential stays in its own file, never in
//! this one.

use std::path::PathBuf;

use oneiron::EntityId;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSyncConfig {
    /// The home's MACHINE id, 64 hex characters.
    pub home_machine: String,
    /// The home's sync endpoint as the upgrade names it: a `ws` or `wss` URL
    /// whose path is `/ws`. The mesh carries the socket, so its host only
    /// names the home.
    pub home_url: String,
    /// The file holding the paired owner-grade credential the upgrade
    /// presents, in the `v2.cred.` one-string form. Only its owner may read
    /// it.
    pub credential_file: PathBuf,
    /// The worlds this machine follows, by id; none until named.
    #[serde(default)]
    pub worlds: Vec<String>,
}

impl DeviceSyncConfig {
    /// The home's MACHINE.
    pub(crate) fn home(&self) -> anyhow::Result<EntityId> {
        EntityId::from_hex(self.home_machine.trim()).map_err(|_| {
            anyhow::anyhow!("[device_sync] home_machine is not a MACHINE id (64 hex characters)")
        })
    }

    /// The worlds this machine follows.
    pub(crate) fn followed_worlds(&self) -> anyhow::Result<Vec<EntityId>> {
        self.worlds
            .iter()
            .map(|world| {
                EntityId::from_hex(world.trim())
                    .map_err(|_| anyhow::anyhow!("[device_sync] worlds: {world} is not a world id"))
            })
            .collect()
    }

    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.home()?;
        self.followed_worlds()?;
        let url: axum::http::Uri = self
            .home_url
            .parse()
            .map_err(|_| anyhow::anyhow!("[device_sync] home_url is not a URL"))?;
        anyhow::ensure!(
            matches!(url.scheme_str(), Some("ws" | "wss"))
                && url.host().is_some()
                && url.path() == "/ws",
            "[device_sync] home_url must be a ws:// or wss:// URL whose path is /ws"
        );
        Ok(())
    }
}
