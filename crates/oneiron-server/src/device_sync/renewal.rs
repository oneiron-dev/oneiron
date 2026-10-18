//! FIX 3377: the device renews its paired owner credential at its home
//! (`POST /v1/core/slips/renew`,
//! [`oneiron_remote::OneironClient::renew_owner_device_credential`]).
//!
//! It renews once at start, then at half each new slip's lifetime, which it
//! reads from that slip's own claims: never the home's `expires_at` against
//! this machine's clock. A renewal writes the replacement over the
//! credential file and hands it to the connection, which is rebuilt on it.
//! A failed one keeps the old file and connection, whose slip stays live
//! until it runs out, and tries again. A refusal (an expired or revoked slip)
//! stands until this machine is paired again.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::commands::credential_file::{self, PairedCredentialFile};

/// The first wait after a failed renewal; each failure after it doubles it.
const RETRY_FIRST: Duration = Duration::from_secs(30);

/// The longest wait between failed renewals.
const RETRY_MOST: Duration = Duration::from_secs(15 * 60);

/// The answers that refuse for good: the home judged the slip (expired,
/// revoked, no longer an owner device's), or this install is no machine of
/// the vault. Any other failure but [`UNUSABLE`] is tried again.
const REFUSALS: [&str; 2] = ["UNAUTHORIZED", "FORBIDDEN"];

/// The answer to a request that can never be made from here, such as a
/// cleartext origin off this machine.
const UNUSABLE: &str = "BAD_REQUEST";

/// The pairing again a refusal asks for.
const PAIR_AGAIN: &str = "pair this machine again: stop the vault, remove its device-sync \
                          enrolment (the .json and .cred files) and run `oneiron device enrol` \
                          with a new link";

/// A renewed credential, written to its file, and how long its slip lives.
pub(super) struct Renewed {
    pub(super) credential: PairedCredentialFile,
    ttl_secs: u64,
}

/// Why a renewal did not land.
enum Failure {
    /// Refused for good: pair again.
    Refused(String),
    /// Never possible from here.
    Unusable(String),
    /// Failed this time.
    Failed(String),
}

/// The renewal schedule of one credential file.
pub(super) struct Renewal {
    /// The home's http(s) origin; `None` when its URL gives none.
    origin: Option<String>,
    credential_file: PathBuf,
    vault: Arc<oneiron::Vault>,
    due: Instant,
    retry: Duration,
    /// The renewal under way, kept across a caller that stopped waiting.
    in_flight: Option<JoinHandle<Result<Renewed, Failure>>>,
    /// Refused or unusable: no renewal until the next start.
    refused: bool,
}

impl Renewal {
    /// Renews the credential in `credential_file` at the home `url` names,
    /// the first time at once.
    pub(super) fn new(url: &str, credential_file: PathBuf, vault: Arc<oneiron::Vault>) -> Self {
        let origin = origin(url);
        if origin.is_none() {
            tracing::warn!(
                "device credential renewal off: home_url is not a ws:// or wss:// URL, so it \
                 names no origin to renew at"
            );
        }
        Self {
            origin,
            credential_file,
            vault,
            due: Instant::now(),
            retry: RETRY_FIRST,
            in_flight: None,
            refused: false,
        }
    }

    /// The next renewed credential. Never ends once a renewal is refused.
    /// Cancel-safe: a renewal still under way when the caller stops waiting
    /// is the one the next call waits on.
    pub(super) async fn next(&mut self) -> Renewed {
        loop {
            let Some(origin) = self.origin.clone().filter(|_| !self.refused) else {
                return std::future::pending().await;
            };
            if self.in_flight.is_none() {
                tokio::time::sleep_until(self.due).await;
                let (path, vault) = (self.credential_file.clone(), Arc::clone(&self.vault));
                self.in_flight = Some(tokio::task::spawn_blocking(move || {
                    renew(&origin, &path, &vault)
                }));
            }
            let Some(in_flight) = self.in_flight.as_mut() else {
                continue;
            };
            let outcome = in_flight.await;
            self.in_flight = None;
            let reason = match outcome {
                Ok(Ok(renewed)) => {
                    let next = Duration::from_secs((renewed.ttl_secs / 2).max(1));
                    self.due = Instant::now() + next;
                    self.retry = RETRY_FIRST;
                    tracing::info!(next_in_secs = next.as_secs(), "device credential renewed");
                    return renewed;
                }
                Ok(Err(Failure::Refused(reason))) => {
                    tracing::warn!(
                        "device credential renewal refused ({reason}); the credential runs \
                         until it expires; {PAIR_AGAIN}"
                    );
                    self.refused = true;
                    continue;
                }
                Ok(Err(Failure::Unusable(reason))) => {
                    tracing::warn!("device credential renewal off ({reason})");
                    self.refused = true;
                    continue;
                }
                Ok(Err(Failure::Failed(reason))) => reason,
                Err(error) => format!("the renewal task failed: {error}"),
            };
            tracing::warn!(
                retry_in_secs = self.retry.as_secs(),
                "device credential renewal failed ({reason}); the current credential stays"
            );
            self.due = Instant::now() + self.retry;
            self.retry = (self.retry * 2).min(RETRY_MOST);
        }
    }
}

/// One renewal of the credential `path` holds, off the async loop: the
/// replacement, written over `path`, read back as the file now holds it.
fn renew(origin: &str, path: &Path, vault: &oneiron::Vault) -> Result<Renewed, Failure> {
    let failed = |error: anyhow::Error| Failure::Failed(format!("{error:#}"));
    let current = PairedCredentialFile::read(path).map_err(failed)?;
    let replacement = oneiron_remote::OneironClient::renew_owner_device_credential(
        origin,
        &current.credential(),
        vault,
        None,
    )
    .map_err(|error| {
        let reason = format!("{}: {}", error.code, error.message);
        if REFUSALS.contains(&error.code.as_str()) {
            Failure::Refused(reason)
        } else if error.code == UNUSABLE {
            Failure::Unusable(reason)
        } else {
            Failure::Failed(reason)
        }
    })?;
    credential_file::replace(path, replacement.as_bytes()).map_err(failed)?;
    let credential = PairedCredentialFile::read(path).map_err(failed)?;
    let ttl_secs = oneiron::authority::CapabilitySlip::from_token(&credential.token)
        .map_err(|_| Failure::Failed("the renewed credential holds no v2 slip".to_owned()))?
        .claims
        .ttl_secs;
    Ok(Renewed {
        credential,
        ttl_secs,
    })
}

/// The home's http(s) origin from its sync URL, the inverse of the
/// enrolment's `/ws` URL: `wss` → `https`, `ws` → `http`, `/ws` dropped.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = match scheme {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let rest = rest.strip_suffix("/ws").unwrap_or(rest);
    Some(format!("{scheme}://{rest}"))
}
