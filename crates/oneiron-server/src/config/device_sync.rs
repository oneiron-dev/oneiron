//! `[device_sync]`: the home this machine keeps its vault in sync with.
//! Every machine but the elected home dials its home (ARCH-0023b); the home
//! dials no one.
//!
//! File-only, like `[native_mail]`. `oneiron device enrol` records the home
//! this machine enrolled with (`crate::device_enrolment`), and `serve` dials
//! it with no section at all. A section names the worlds this machine follows
//! and may name a home by hand instead, all three of `home_machine`,
//! `home_url` and `credential_file` together. With neither a section nor an
//! enrolment, this machine dials no one. The credential stays in its own
//! file, never in this one.

use std::path::PathBuf;

use oneiron::EntityId;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceSyncConfig {
    /// The home's MACHINE id, 32 hex characters. Absent, the enrolled home.
    #[serde(default)]
    pub home_machine: Option<String>,
    /// The home's sync endpoint as the upgrade names it: a `ws` or `wss` URL
    /// whose path is `/ws`. Over the mesh its host only names the home; a
    /// home with no paired mesh address is dialed at it directly, over
    /// `wss` (or `ws` to a loopback host).
    #[serde(default)]
    pub home_url: Option<String>,
    /// The file holding the paired owner-grade credential the upgrade
    /// presents, in the `v2.cred.` one-string form. Only its owner may read
    /// it.
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
    /// The worlds this machine follows, by id; none until named.
    #[serde(default)]
    pub worlds: Vec<String>,
    /// The home's sync node id, as `oneiron whoami` prints it there
    /// (`sync_node_id`). Named, this machine holds that node as its elected
    /// home and routes residence reads to `home_url`. Absent, the enrolled
    /// home's; a home named by hand without it keeps the home this machine
    /// holds, and a Dreamer here that claimed this machine keeps it.
    #[serde(default)]
    pub home_node_id: Option<u64>,
}

/// A home named by hand: all three of its fields.
pub(crate) struct NamedHome<'a> {
    pub(crate) machine: EntityId,
    pub(crate) url: &'a str,
    pub(crate) credential_file: &'a std::path::Path,
}

impl DeviceSyncConfig {
    /// The home this section names by hand, if it names one.
    pub(crate) fn named_home(&self) -> anyhow::Result<Option<NamedHome<'_>>> {
        match (&self.home_machine, &self.home_url, &self.credential_file) {
            (None, None, None) => Ok(None),
            (Some(machine), Some(url), Some(credential_file)) => Ok(Some(NamedHome {
                machine: parse_machine(machine)
                    .map_err(|error| anyhow::anyhow!("[device_sync] {error}"))?,
                url,
                credential_file,
            })),
            _ => anyhow::bail!(
                "[device_sync] names a home with all three of home_machine, home_url and \
                 credential_file, or with none of them (the enrolled home)"
            ),
        }
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
        if let Some(home) = self.named_home()? {
            validate_home_url(home.url)
                .map_err(|error| anyhow::anyhow!("[device_sync] {error}"))?;
        }
        self.followed_worlds()?;
        anyhow::ensure!(
            self.home_node_id != Some(0),
            "[device_sync] home_node_id is the home's sync node id, never 0"
        );
        Ok(())
    }
}

/// A home's MACHINE id.
pub(crate) fn parse_machine(machine: &str) -> anyhow::Result<EntityId> {
    EntityId::from_hex(machine.trim())
        .map_err(|_| anyhow::anyhow!("home_machine is not a MACHINE id (32 hex characters)"))
}

/// A home's sync endpoint: a `ws` or `wss` URL whose path is `/ws`.
pub(crate) fn validate_home_url(url: &str) -> anyhow::Result<()> {
    let url: axum::http::Uri = url
        .parse()
        .map_err(|_| anyhow::anyhow!("home_url is not a URL"))?;
    anyhow::ensure!(
        matches!(url.scheme_str(), Some("ws" | "wss"))
            && url.host().is_some()
            && url.path() == "/ws",
        "home_url must be a ws:// or wss:// URL whose path is /ws"
    );
    Ok(())
}
