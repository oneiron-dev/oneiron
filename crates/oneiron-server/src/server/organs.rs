//! The organs on the server's one host ([`SyncServer::organs`]): at boot it
//! takes every organ an Active pack carries a build of for this platform,
//! before the mesh listener offers it to the owner's other nodes (OF-575).
//! The seal installs through its worker, whose grant names the seal's asks
//! and fetch origins.

use std::path::PathBuf;

use oneiron::skill_hub::pack_catalog::host_platform;
use oneiron_organ_host::seal::SEAL_ORGAN;
use oneiron_organ_host::{HostError, OrganTier, pack_spec};

use super::SyncServer;

/// Where pack organ builds are written: `ONEIRON_ORGAN_DIR`, else
/// `oneiron-organs` under the OS temp directory.
const ORGAN_DIR_ENV: &str = "ONEIRON_ORGAN_DIR";

/// The tier a pack's organ installs at. A pack's build is pinned by its
/// blake3 and the owner installed the pack, so it runs as first party, as
/// the seal's pack build already does; a third-party tier is refused until
/// filesystem confinement lands.
const PACK_ORGAN_TIER: OrganTier = OrganTier::FirstParty;

/// The directory pack organ builds are written under.
pub(crate) fn organ_dir() -> PathBuf {
    std::env::var_os(ORGAN_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map_or_else(
            || std::env::temp_dir().join("oneiron-organs"),
            PathBuf::from,
        )
}

impl SyncServer {
    /// Installs every Active pack's organ that has a build for this platform
    /// and is not on the host yet; the first pack to name an organ wins. A
    /// build that cannot be read or written is logged and skipped. Blocking:
    /// it reads the vault and writes the builds.
    pub(crate) fn install_pack_organs(&self) {
        let entries = match self.vault.pack_organs() {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%error, "the pack organs");
                return;
            }
        };
        let platform = host_platform();
        let dir = organ_dir();
        for entry in entries {
            let name = entry.organ.name.as_str();
            if name == SEAL_ORGAN
                || !entry.held_platforms.contains(&platform)
                || self.organs.status(name).is_some()
            {
                continue;
            }
            let spec = self
                .vault
                .pack_organ_build(&entry.pack_name, name, &platform)
                .map_err(HostError::from)
                .and_then(|binary| pack_spec(&binary, &dir, PACK_ORGAN_TIER));
            match spec {
                Ok(spec) => self.organs.install(spec),
                Err(error) => {
                    tracing::warn!(organ = %name, pack = %entry.pack_name, %error, "pack organ install");
                }
            }
        }
    }
}
