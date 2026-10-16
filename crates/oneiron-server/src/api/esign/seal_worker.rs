//! The seal task's worker (OF-415, ARCH-0064 section 7): every tick it
//! seals the documents whose signing finished, through the seal organ and
//! the host's seal key, as a task, never inside a request. With no key
//! configured, sealing waits and the worker says so once; a document never
//! fails for it, and one whose seal failed is queued again by the backstop.
//!
//! The key and its chain are files the host names: `ONEIRON_SEAL_KEY`
//! (PKCS#8, PEM or DER) and `ONEIRON_SEAL_CHAIN` (PEM, the signer first).
//! `ONEIRON_SEAL_TRUST` names the trust anchors (PEM; the chain's last
//! certificate when unset), `ONEIRON_SEAL_TSA` a timestamp authority (a
//! B-T seal; B-B without one), and `ONEIRON_SEAL_URL` the signing page the
//! evidence names. The seal organ is the build an installed pack carries
//! for this platform, written under `ONEIRON_ORGAN_DIR`, or the program
//! `ONEIRON_SEAL_ORGAN` names.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use oneiron::blob_artifact::esign::{EsignSealRun, SealProfile};
use oneiron::skill_hub::pack_catalog::host_platform;
use oneiron_organ_host::seal::{
    FileSealKeys, HostedSealer, SEAL_ORGAN, SealKeys, SealSettings, SealTsa, pem_certificates,
    seal_spec, seal_spec_from_pack,
};
use oneiron_organ_host::{FetchGrant, FetchOrigin, HostConfig, OrganHost, OrganSpec};

use crate::server::SyncServer;

const KEY_ENV: &str = "ONEIRON_SEAL_KEY";
const CHAIN_ENV: &str = "ONEIRON_SEAL_CHAIN";
const TRUST_ENV: &str = "ONEIRON_SEAL_TRUST";
const TSA_ENV: &str = "ONEIRON_SEAL_TSA";
const URL_ENV: &str = "ONEIRON_SEAL_URL";
const ORGAN_ENV: &str = "ONEIRON_SEAL_ORGAN";
const ORGAN_DIR_ENV: &str = "ONEIRON_ORGAN_DIR";

const TICK: Duration = Duration::from_secs(30);
const LEASE_OWNER: &str = "esign-seal-worker";
/// Documents one tick seals at most.
const PER_TICK: usize = 8;
/// The most bytes one CRL or timestamp fetch brings back.
const FETCH_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Starts the seal worker on the server's runtime.
pub(crate) fn spawn(server: Arc<SyncServer>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let host = Arc::new(OrganHost::new(HostConfig::default()));
        let mut every = tokio::time::interval(TICK);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut said: Option<String> = None;
        loop {
            every.tick().await;
            let server = Arc::clone(&server);
            let host = Arc::clone(&host);
            let Ok(ticked) = tokio::task::spawn_blocking(move || tick(&server, &host)).await else {
                continue;
            };
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

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

/// One tick. `Err` says why seals wait.
fn tick(server: &SyncServer, host: &OrganHost) -> Result<Vec<EsignSealRun>, String> {
    let (Some(key), Some(chain)) = (env_path(KEY_ENV), env_path(CHAIN_ENV)) else {
        return Err(format!(
            "no seal certificate configured: set {KEY_ENV} and {CHAIN_ENV}"
        ));
    };
    let keys = FileSealKeys::load(&key, &chain).map_err(|err| format!("the seal key: {err}"))?;
    let tsa = std::env::var(TSA_ENV).ok().filter(|url| !url.is_empty());
    if host.status(SEAL_ORGAN).is_none() {
        host.install(install(server, fetch_grant(tsa.as_deref())?)?);
    }
    let anchors = match env_path(TRUST_ENV) {
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
    let sealer = HostedSealer::new(host, &server.vault, &keys, settings);
    let url = std::env::var(URL_ENV).unwrap_or_else(|_| "/sign".to_owned());
    server
        .vault
        .run_esign_seals(&sealer, profile, &url, LEASE_OWNER, PER_TICK)
        .map_err(|err| format!("the seal queue: {err}"))
}

/// The seal organ to install: the program the host names, else the build
/// an installed pack carries for this platform.
fn install(server: &SyncServer, fetch: FetchGrant) -> Result<OrganSpec, String> {
    if let Some(program) = env_path(ORGAN_ENV) {
        return Ok(seal_spec(program, fetch));
    }
    let platform = host_platform();
    let entry = server
        .vault
        .pack_organs()
        .map_err(|err| format!("the pack organs: {err}"))?
        .into_iter()
        .find(|entry| entry.organ.name == SEAL_ORGAN && entry.held_platforms.contains(&platform))
        .ok_or_else(|| {
            format!("no installed pack carries the seal organ for {platform}; install one, or set {ORGAN_ENV}")
        })?;
    let binary = server
        .vault
        .pack_organ_build(&entry.pack_name, SEAL_ORGAN, &platform)
        .map_err(|err| format!("the seal organ build: {err}"))?;
    let dir =
        env_path(ORGAN_DIR_ENV).unwrap_or_else(|| std::env::temp_dir().join("oneiron-organs"));
    seal_spec_from_pack(&binary, Path::new(&dir), fetch)
        .map_err(|err| format!("the seal organ build: {err}"))
}

/// Where the seal may fetch: its timestamp authority's origin.
fn fetch_grant(tsa: Option<&str>) -> Result<FetchGrant, String> {
    let mut grant = FetchGrant {
        max_bytes: FETCH_MAX_BYTES,
        ..FetchGrant::default()
    };
    if let Some(tsa) = tsa {
        let url = reqwest::Url::parse(tsa).map_err(|_| format!("{TSA_ENV} is not a URL"))?;
        let host = url
            .host_str()
            .ok_or_else(|| format!("{TSA_ENV} names no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| format!("{TSA_ENV} names no port"))?;
        grant
            .origins
            .push(FetchOrigin::new(url.scheme(), host, port));
    }
    Ok(grant)
}
