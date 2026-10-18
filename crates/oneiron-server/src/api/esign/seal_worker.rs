//! The seal task's worker (OF-415, ARCH-0064 section 7): every tick it
//! seals the documents whose signing finished, through the seal organ and
//! the host's seal key, as a task, never inside a request. With no key
//! configured, sealing waits and the worker says so once; a document never
//! fails for it, and one whose seal failed is queued again by the backstop.
//!
//! The key and its chain are files the host names ([`SealConfig`]): on a
//! self-hosted server `ONEIRON_SEAL_KEY` (PKCS#8, PEM or DER) and
//! `ONEIRON_SEAL_CHAIN` (PEM, the signer first). `ONEIRON_SEAL_TRUST` names
//! the trust anchors (PEM; the chain's last certificate when unset),
//! `ONEIRON_SEAL_TSA` a timestamp authority (a B-T seal; B-B without one),
//! and `ONEIRON_SEAL_URL` the signing page the evidence names (the sign page
//! at the host's public origin when unset). A managed vault reads no
//! environment, so its supervisor passes the same settings per vault as
//! `--seal-key-file`, `--seal-chain-file`, `--seal-trust-file`,
//! `--seal-tsa-url`, `--seal-signing-url` and `--seal-organ` (FIX 3487).
//! The seal organ is the build an installed pack carries for this platform,
//! written under `ONEIRON_ORGAN_DIR`, or the program `ONEIRON_SEAL_ORGAN`
//! (`--seal-organ`) names. A pack build follows the packs: when the
//! vault's installs change and the seal build they carry is not the one
//! installed (a seal pack updated or removed), the host drops it, and the
//! tick installs the current one, or waits for one.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::blob_artifact::esign::{EsignSealRun, SealProfile};
use oneiron::skill_hub::pack_catalog::{PackInstallReceipt, host_platform};
use oneiron_organ_host::seal::{
    FileSealKeys, HostedSealer, SEAL_ORGAN, SealKeys, SealSettings, SealTsa, pem_certificates,
    seal_spec, seal_spec_from_pack,
};
use oneiron_organ_host::{FetchGrant, FetchOrigin, OrganSpec};

use crate::builtin_host::public_origin;
use crate::server::{HousekeepingAdmission, SyncServer};

/// Each setting's environment variable and its managed flag.
type SettingName = (&'static str, &'static str);
const KEY: SettingName = ("ONEIRON_SEAL_KEY", "--seal-key-file");
const CHAIN: SettingName = ("ONEIRON_SEAL_CHAIN", "--seal-chain-file");
const TRUST: SettingName = ("ONEIRON_SEAL_TRUST", "--seal-trust-file");
const TSA: SettingName = ("ONEIRON_SEAL_TSA", "--seal-tsa-url");
const URL: SettingName = ("ONEIRON_SEAL_URL", "--seal-signing-url");
const ORGAN: SettingName = ("ONEIRON_SEAL_ORGAN", "--seal-organ");

/// The host's seal settings: the environment's on a self-hosted server, a
/// managed vault's own from its argv.
#[derive(Clone, Debug, Default)]
pub(crate) struct SealConfig {
    /// The seal key (PKCS#8, PEM or DER).
    pub(crate) key: Option<PathBuf>,
    /// Its certificate chain (PEM, the signer first).
    pub(crate) chain: Option<PathBuf>,
    /// The trust anchors (PEM); the chain's last certificate when unset.
    pub(crate) trust: Option<PathBuf>,
    /// A timestamp authority's URL: a B-T seal, B-B without one.
    pub(crate) tsa: Option<String>,
    /// The signing page the evidence names.
    pub(crate) signing_url: Option<String>,
    /// The seal organ's program, in place of an installed pack's build.
    pub(crate) organ: Option<PathBuf>,
    /// From a managed vault's argv: its messages name the flags.
    pub(crate) argv: bool,
}

impl SealConfig {
    /// The `ONEIRON_SEAL_*` environment.
    fn from_env() -> Self {
        let text = |(name, _): SettingName| std::env::var(name).ok().filter(|v| !v.is_empty());
        Self {
            key: env_path(KEY),
            chain: env_path(CHAIN),
            trust: env_path(TRUST),
            tsa: text(TSA),
            signing_url: text(URL),
            organ: env_path(ORGAN),
            argv: false,
        }
    }

    /// What sets `setting` on this host.
    fn name(&self, (env, flag): SettingName) -> &'static str {
        if self.argv { flag } else { env }
    }
}

/// The public sign page under the host's origin (the `/sign` route).
const SIGN_PAGE_PATH: &str = "/sign";

const TICK: Duration = Duration::from_secs(30);
const LEASE_OWNER: &str = "esign-seal-worker";
/// Documents one tick seals at most.
const PER_TICK: usize = 8;
/// The most bytes one CRL or timestamp fetch brings back.
const FETCH_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Starts the seal worker on the server's runtime, every tick admitted, on
/// the environment's seal settings. It seals on the server's organ host,
/// the one the mesh listener offers.
pub(crate) fn spawn(server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    spawn_admitted(
        server,
        crate::server::admit_every_pass(),
        SealConfig::from_env(),
    )
}

/// [`spawn`] under a host's freeze (a managed host that reaps its vault): a
/// tick runs only when `admit` lets it, and holds what it was given until
/// its seals are written. It seals on `seal`, the vault's own settings.
pub(crate) fn spawn_admitted(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    seal: SealConfig,
) -> tokio::task::JoinHandle<()> {
    let seal = Arc::new(seal);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut said: Option<String> = None;
        let mut installs: Option<Vec<PackInstallReceipt>> = None;
        loop {
            every.tick().await;
            let Some(pass) = admit() else {
                continue;
            };
            let server = Arc::clone(&server);
            let seal = Arc::clone(&seal);
            let mut seen = installs.take();
            let Ok((ticked, seen)) = tokio::task::spawn_blocking(move || {
                let _pass = pass;
                let ticked = tick(&server, &seal, &mut seen);
                (ticked, seen)
            })
            .await
            else {
                continue;
            };
            installs = seen;
            match ticked {
                Ok(runs) => {
                    said = None;
                    for run in runs {
                        if let EsignSealRun::Failed { document, reason } = run {
                            let document = document.map(|id| id.to_hex()).unwrap_or_default();
                            tracing::warn!(%document, %reason, "esign seal failed; the backstop queues it again");
                        }
                    }
                }
                Err(waiting) => {
                    if said.as_deref() != Some(waiting.as_str()) {
                        tracing::info!(%waiting, "esign seals wait");
                        said = Some(waiting);
                    }
                }
            }
        }
    })
}

fn env_path((name, _): SettingName) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// One tick on `seal`. `Err` says why seals wait. `installs` is what the
/// last tick saw of the vault's pack installs.
fn tick(
    server: &SyncServer,
    seal: &SealConfig,
    installs: &mut Option<Vec<PackInstallReceipt>>,
) -> Result<Vec<EsignSealRun>, String> {
    let host = &*server.organs;
    if seal.organ.is_none() {
        follow_seal_pack(server, installs);
    }
    let (Some(key), Some(chain)) = (&seal.key, &seal.chain) else {
        return Err(format!(
            "no seal certificate configured: set {} and {}",
            seal.name(KEY),
            seal.name(CHAIN)
        ));
    };
    let keys = FileSealKeys::load(key, chain).map_err(|err| format!("the seal key: {err}"))?;
    let tsa = seal.tsa.clone();
    if host.status(SEAL_ORGAN).is_none() {
        host.install(install(server, seal, fetch_grant(seal, tsa.as_deref())?)?);
    }
    let anchors = match &seal.trust {
        Some(path) => {
            let pem = std::fs::read(&path)
                .map_err(|err| format!("the seal trust anchors {}: {err}", path.display()))?;
            pem_certificates(&pem).map_err(|err| format!("the seal trust anchors: {err}"))?
        }
        None => {
            let identity = keys
                .identity(Instant::now())
                .map_err(|err| format!("the seal key: {err}"))?;
            vec![
                identity
                    .chain
                    .last()
                    .cloned()
                    .unwrap_or(identity.signer_certificate),
            ]
        }
    };
    let mut settings = SealSettings::new(anchors, "esign.seal");
    let profile = match tsa {
        Some(url) => {
            settings.timestamp_authorities.push(SealTsa {
                url,
                policy_oid: None,
            });
            SealProfile::BaselineT
        }
        None => SealProfile::BaselineB,
    };
    let url = signing_url(server, seal)?;
    let sealer = HostedSealer::new(host, &server.vault, &keys, settings);
    server
        .vault
        .run_esign_seals(&sealer, profile, &url, LEASE_OWNER, PER_TICK)
        .map_err(|err| format!("the seal queue: {err}"))
}

/// The signing page the evidence names: the configured one, else the sign
/// page at the host's public origin. With neither, seals wait: the
/// certificate names only an https URL.
fn signing_url(server: &SyncServer, seal: &SealConfig) -> Result<String, String> {
    if let Some(url) = &seal.signing_url {
        return Ok(url.clone());
    }
    public_origin(server.config.oauth_resource_indicator.as_deref())
        .map(|origin| format!("{origin}{SIGN_PAGE_PATH}"))
        .ok_or_else(|| {
            format!(
                "no public signing page: set {}, or oauth_resource_indicator to the host's https origin",
                seal.name(URL)
            )
        })
}

/// The seal organ to install: the program the host names, else the build
/// an installed pack carries for this platform.
fn install(server: &SyncServer, seal: &SealConfig, fetch: FetchGrant) -> Result<OrganSpec, String> {
    if let Some(program) = &seal.organ {
        return Ok(seal_spec(program.clone(), fetch));
    }
    let platform = host_platform();
    let entry = server
        .vault
        .pack_organs()
        .map_err(|err| format!("the pack organs: {err}"))?
        .into_iter()
        .find(|entry| entry.organ.name == SEAL_ORGAN && entry.held_platforms.contains(&platform))
        .ok_or_else(|| {
            format!(
                "no installed pack carries the seal organ for {platform}; install one, or set {}",
                seal.name(ORGAN)
            )
        })?;
    let binary = server
        .vault
        .pack_organ_build(&entry.pack_name, SEAL_ORGAN, &platform)
        .map_err(|err| format!("the seal organ build: {err}"))?;
    seal_spec_from_pack(&binary, &crate::server::organ_dir(), fetch)
        .map_err(|err| format!("the seal organ build: {err}"))
}

/// Drops the seal organ the host installed from a pack once the vault's
/// pack installs changed and the seal build they carry for this platform is
/// not the installed one: the tick then installs the current build, or
/// waits for one. Unchanged installs read nothing more.
fn follow_seal_pack(server: &SyncServer, seen: &mut Option<Vec<PackInstallReceipt>>) {
    let installs = match server.vault.installed_packs() {
        Ok(installs) => installs,
        Err(error) => {
            tracing::warn!(%error, "the installed packs");
            return;
        }
    };
    if seen.as_ref().is_none_or(|seen| *seen == installs) {
        *seen = Some(installs);
        return;
    }
    if let Some(installed) = server.organs.spec(SEAL_ORGAN) {
        let platform = host_platform();
        let entries = match server.vault.pack_organs() {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(%error, "the pack organs");
                return;
            }
        };
        let carried = entries
            .iter()
            .find(|entry| {
                entry.organ.name == SEAL_ORGAN && entry.held_platforms.contains(&platform)
            })
            .and_then(|entry| entry.organ.build(&platform))
            .map(|build| build.blake3.as_str());
        if installed.program_hash.map(|hash| hash.to_hex()).as_deref() != carried
            && server.organs.uninstall(SEAL_ORGAN)
        {
            tracing::info!("the seal organ's pack changed; the seal installs its current build");
        }
    }
    *seen = Some(installs);
}

/// Where the seal may fetch: its timestamp authority's origin.
fn fetch_grant(seal: &SealConfig, tsa: Option<&str>) -> Result<FetchGrant, String> {
    let mut grant = FetchGrant {
        max_bytes: FETCH_MAX_BYTES,
        ..FetchGrant::default()
    };
    if let Some(tsa) = tsa {
        let name = seal.name(TSA);
        let url = reqwest::Url::parse(tsa).map_err(|_| format!("{name} is not a URL"))?;
        let host = url
            .host_str()
            .ok_or_else(|| format!("{name} names no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| format!("{name} names no port"))?;
        grant
            .origins
            .push(FetchOrigin::new(url.scheme(), host, port));
    }
    Ok(grant)
}
