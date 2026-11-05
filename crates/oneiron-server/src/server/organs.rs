//! The organs on the server's one host ([`SyncServer::organs`]): every organ
//! an Active pack carries a build of for this platform (OF-575). At boot they
//! install before the mesh listener offers the host to the owner's other
//! nodes; while it runs, the listener's tick (`pack_organ_tick`) keeps the
//! host in step with the vault's installed packs, so a pack installed, updated or removed since, or a
//! build the vault came to hold since, reaches the host without a restart.
//! The seal installs through its worker, whose grant names the seal's asks
//! and fetch origins.
//!
//! A pack build's tier is its verified provenance alone (FIX 7644): first
//! party when the operator listed its blake3 (`--trusted-organ-build`), else
//! third party, which the host starts only inside a filesystem fence
//! (Landlock on Linux, Seatbelt on macOS, FIX 7885) and refuses on a host
//! with none. Owner installation and a content pin prove which bytes run,
//! not that they are reviewed repo code (ARCH-0075).

use std::collections::BTreeSet;
use std::path::PathBuf;
#[cfg(feature = "mesh")]
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard, PoisonError};

#[cfg(feature = "mesh")]
use oneiron::skill_hub::pack_catalog::PackInstallReceipt;
use oneiron::skill_hub::pack_catalog::{PackOrgan, PackOrganBuild, host_platform};
#[cfg(feature = "mesh")]
use oneiron_organ_host::MeshCancel;
use oneiron_organ_host::seal::SEAL_ORGAN;
use oneiron_organ_host::{HostError, OrganSpec, OrganTier, filesystem_confined, pack_spec};

use super::SyncServer;

/// Where pack organ builds are written on a host that names no directory
/// ([`SyncServer::with_organ_dir`]): `ONEIRON_ORGAN_DIR`, else
/// `oneiron-organs` under the OS temp directory.
const ORGAN_DIR_ENV: &str = "ONEIRON_ORGAN_DIR";

/// One pass over the pack organs at a time: the boot install and the
/// listener's tick never install the same organ twice over each other.
static PASS: Mutex<()> = Mutex::new(());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The directory pack organ builds are written under on a host that names
/// none.
fn ambient_organ_dir() -> PathBuf {
    std::env::var_os(ORGAN_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map_or_else(
            || std::env::temp_dir().join("oneiron-organs"),
            PathBuf::from,
        )
}

/// Whether `spec` is the install `organ`'s `build` makes at
/// `expected_tier`: the same pinned binary under the same tier, version pin
/// and grant. A build whose tier changed is reinstalled.
fn installed_as(
    spec: &OrganSpec,
    organ: &PackOrgan,
    build: &PackOrganBuild,
    expected_tier: OrganTier,
) -> bool {
    spec.tier == expected_tier
        && spec
            .program_hash
            .is_some_and(|hash| hash.to_hex() == build.blake3)
        && spec.version_pin == organ.version
        && spec.verbs == organ.verbs
        && spec.kinds.as_ref() == Some(&organ.kinds)
        && spec.media_types == organ.media_types
        && organ.threads.is_none_or(|threads| spec.threads == threads)
        && organ
            .memory_bytes
            .is_none_or(|memory| spec.memory_bytes == memory)
}

/// What the listener's tick watches between passes: the installs the last
/// pass saw, and the organs it found no build of for this platform yet.
#[cfg(feature = "mesh")]
#[derive(Default)]
struct PackOrganWatch {
    installs: Option<Vec<PackInstallReceipt>>,
    unbuilt: Vec<(String, String)>,
}

/// The mesh listener's tick, as [`SyncServer::pack_organ_tick`] makes it.
#[cfg(feature = "mesh")]
type PackOrganTick =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

impl SyncServer {
    /// Writes pack organ builds under `dir`, the seal's among them: the
    /// host's own directory (managed serve's, FIX 3565), in place of the
    /// environment's and the OS temp directory.
    #[must_use]
    pub(crate) fn with_organ_dir(mut self, dir: PathBuf) -> Self {
        self.organ_dir = Some(dir);
        self
    }

    /// The directory pack organ builds are written under: the host's own,
    /// else `ONEIRON_ORGAN_DIR`, else `oneiron-organs` under the OS temp
    /// directory.
    pub(crate) fn organ_dir(&self) -> PathBuf {
        self.organ_dir.clone().unwrap_or_else(ambient_organ_dir)
    }

    /// The tier a pack organ `build` installs at (FIX 7644): first party
    /// only when the operator listed its blake3 among the server's trusted
    /// organ builds ([`crate::config::SyncServerConfig::trusted_organ_builds`]),
    /// else third party. The digest is the one the vault verified the
    /// build's bytes against, and the host checks the file against it before
    /// every start. Nothing the pack carries adds to the list.
    pub(crate) fn pack_build_tier(&self, build: &PackOrganBuild) -> OrganTier {
        if self
            .config
            .trusted_organ_builds
            .contains(build.blake3.as_str())
        {
            OrganTier::FirstParty
        } else {
            OrganTier::ThirdParty
        }
    }

    /// Brings the host in step with the vault's Active packs: every organ a
    /// pack carries a build of for this platform is installed, the first
    /// pack to name an organ winning; one whose pack now carries another
    /// build, version or grant is reinstalled; and a pack organ no Active
    /// pack carries any more is uninstalled. A build that cannot be read or
    /// written is logged and skipped, and an unread catalog changes nothing.
    /// Blocking: it reads the vault and writes the builds.
    pub(crate) fn install_pack_organs(&self) {
        let _ = self.reconcile_pack_organs(&|| false);
    }

    /// [`Self::install_pack_organs`]. The organs an Active pack declares a
    /// build of for this platform that the vault does not hold yet, as (pack,
    /// organ); `None` when the catalog could not be read, or when `stopped`
    /// ended the pass before its next organ (FIX 4755): what it installed
    /// stays, nothing is uninstalled, and the next pass starts over.
    fn reconcile_pack_organs(&self, stopped: &dyn Fn() -> bool) -> Option<Vec<(String, String)>> {
        let _pass = lock(&PASS);
        let entries = match self.vault.pack_organs() {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%error, "the pack organs");
                return None;
            }
        };
        let platform = host_platform();
        let dir = self.organ_dir();
        let mut carried = BTreeSet::new();
        let mut unbuilt = Vec::new();
        for entry in &entries {
            if stopped() {
                return None;
            }
            let name = entry.organ.name.as_str();
            if name == SEAL_ORGAN || carried.contains(name) {
                continue;
            }
            let Some(build) = entry.organ.build(&platform) else {
                continue;
            };
            if !entry.held_platforms.contains(&platform) {
                unbuilt.push((entry.pack_name.clone(), name.to_owned()));
                continue;
            }
            carried.insert(name);
            let tier = self.pack_build_tier(build);
            if self
                .organs
                .spec(name)
                .is_some_and(|spec| installed_as(&spec, &entry.organ, build, tier))
            {
                continue;
            }
            let spec = self
                .vault
                .pack_organ_build(&entry.pack_name, name, &platform)
                .map_err(HostError::from)
                .and_then(|binary| pack_spec(&binary, &dir, tier));
            match spec {
                Ok(spec) => {
                    if tier == OrganTier::ThirdParty && !filesystem_confined() {
                        tracing::warn!(
                            organ = %name,
                            pack = %entry.pack_name,
                            build = %build.blake3,
                            %platform,
                            "pack organ build is third party: it will not start on this host, which has no filesystem fence for organs (Landlock ABI 3 on Linux, sandbox-exec on macOS); to run it as first party, the operator lists its blake3 with --trusted-organ-build"
                        );
                    }
                    self.organs.install(spec);
                }
                Err(error) => {
                    tracing::warn!(organ = %name, pack = %entry.pack_name, %error, "pack organ install");
                }
            }
        }
        for (name, _) in self.organs.installed() {
            // A pass installs every pack build pinned, whatever its tier,
            // and this host pins no other organ but the seal, which follows
            // its own worker: a pinned install here is a pack's.
            let pack_organ = self
                .organs
                .spec(&name)
                .is_some_and(|spec| spec.program_hash.is_some());
            if name != SEAL_ORGAN
                && !carried.contains(name.as_str())
                && pack_organ
                && self.organs.uninstall(&name)
            {
                tracing::info!(organ = %name, "pack organ uninstalled: no Active pack carries it");
            }
        }
        Some(unbuilt)
    }

    /// The mesh listener's tick that keeps the host's pack organs in step
    /// with the vault while the listener runs. Each tick reads the vault's
    /// install receipts, and passes over the organs again when they changed
    /// (a pack installed, updated or removed) or when a build the last pass
    /// waited on is now held. It runs on a blocking thread, and once the
    /// listener's `stop` begins it starts no next organ (FIX 4755).
    #[cfg(feature = "mesh")]
    pub(crate) fn pack_organ_tick(self: &Arc<Self>, stop: MeshCancel) -> PackOrganTick {
        let server = Arc::clone(self);
        let watch = Arc::new(Mutex::new(PackOrganWatch::default()));
        Arc::new(
            move || -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
                let server = Arc::clone(&server);
                let watch = Arc::clone(&watch);
                let stop = stop.clone();
                Box::pin(async move {
                    let rescanned = tokio::task::spawn_blocking(move || {
                        server.rescan_pack_organs(&watch, &|| stop.is_stopping())
                    })
                    .await;
                    if let Err(error) = rescanned {
                        tracing::warn!(%error, "pack organ rescan");
                    }
                })
            },
        )
    }

    /// One tick of [`Self::pack_organ_tick`], until `stopped`.
    #[cfg(feature = "mesh")]
    fn rescan_pack_organs(&self, watch: &Mutex<PackOrganWatch>, stopped: &dyn Fn() -> bool) {
        let mut watch = lock(watch);
        let installs = match self.vault.installed_packs() {
            Ok(installs) => installs,
            Err(error) => {
                tracing::warn!(%error, "the installed packs");
                return;
            }
        };
        let platform = host_platform();
        let built = watch
            .unbuilt
            .iter()
            .any(|(pack, organ)| self.vault.pack_organ_build(pack, organ, &platform).is_ok());
        if watch.installs.as_ref() == Some(&installs) && !built {
            return;
        }
        if let Some(unbuilt) = self.reconcile_pack_organs(stopped) {
            watch.installs = Some(installs);
            watch.unbuilt = unbuilt;
        }
    }
}
