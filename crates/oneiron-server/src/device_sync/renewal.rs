//! FIX 3377: the device renews its paired owner credential at its home
//! (`POST /v1/core/slips/renew`,
//! [`oneiron_remote::OneironClient::renew_owner_device_credential`]). A link
//! that dials its home over the mesh posts the same request on one mesh
//! stream instead (FIX 3561): the home's sync route serves the whole router.
//!
//! It renews once at start, then at half each new slip's lifetime, which it
//! reads from that slip's own claims: never the home's `expires_at` against
//! this machine's clock. A renewal only fetches the replacement: the link
//! writes it over the credential file itself, unless a stop came first, and
//! rebuilds the connection on it (FIX 3563). A failed renewal, or a write
//! that fails, keeps the old file and connection, whose slip stays live
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

/// The home's renew route, which its mesh sync route serves too.
const RENEW_PATH: &str = "/v1/core/slips/renew";

/// The pairing again a refusal asks for.
const PAIR_AGAIN: &str = "pair this machine again: stop the vault, remove its device-sync \
                          enrolment (the .json and .cred files) and run `oneiron device enrol` \
                          with a new link";

/// A renewed credential the home answered, not yet written to its file,
/// and how long its slip lives.
pub(super) struct Candidate {
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
    /// The link's mesh carrier to the home, when it dials one: the renewal
    /// goes over it rather than to the origin.
    dialer: Option<Arc<dyn oneiron::sync::SyncDialer>>,
    due: Instant,
    retry: Duration,
    /// The renewal under way, kept across a caller that stopped waiting.
    in_flight: Option<JoinHandle<Result<Candidate, Failure>>>,
    /// Refused or unusable: no renewal until the next start.
    refused: bool,
}

impl Renewal {
    /// Renews the credential in `credential_file` at the home `url` names,
    /// over `dialer` when the link has one, the first time at once.
    pub(super) fn new(
        url: &str,
        credential_file: PathBuf,
        vault: Arc<oneiron::Vault>,
        dialer: Option<Arc<dyn oneiron::sync::SyncDialer>>,
    ) -> Self {
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
            dialer,
            due: Instant::now(),
            retry: RETRY_FIRST,
            in_flight: None,
            refused: false,
        }
    }

    /// The next renewed credential, not yet written: the caller writes it
    /// with [`Self::commit`], or reports it unused with [`Self::failed`].
    /// Never ends once a renewal is refused. Cancel-safe: a renewal still
    /// under way when the caller stops waiting is the one the next call
    /// waits on, and one no call takes writes nothing.
    pub(super) async fn next(&mut self) -> Candidate {
        loop {
            let Some(origin) = self.origin.clone().filter(|_| !self.refused) else {
                return std::future::pending().await;
            };
            if self.in_flight.is_none() {
                tokio::time::sleep_until(self.due).await;
                let (path, vault) = (self.credential_file.clone(), Arc::clone(&self.vault));
                self.in_flight = Some(match self.dialer.clone() {
                    Some(dialer) => tokio::spawn(async move {
                        renew_mesh(&origin, &path, &vault, dialer.as_ref()).await
                    }),
                    None => tokio::task::spawn_blocking(move || renew(&origin, &path, &vault)),
                });
            }
            let Some(in_flight) = self.in_flight.as_mut() else {
                continue;
            };
            let outcome = in_flight.await;
            self.in_flight = None;
            let reason = match outcome {
                Ok(Ok(candidate)) => return candidate,
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
            self.failed(&reason);
        }
    }

    /// Writes `candidate` over the credential file, whole or not at all
    /// ([`credential_file::replace`]), and says whether it landed. It awaits
    /// nothing, so no stop comes between the caller's last look for one and
    /// the write's end. Only a landed write is a renewal: the next one is due
    /// at half the new slip's lifetime. A failed write keeps the old file and
    /// is tried again as any failed renewal is.
    pub(super) fn commit(&mut self, candidate: &Candidate) -> bool {
        let written = credential_file::replace(
            &self.credential_file,
            candidate.credential.credential().as_bytes(),
        );
        match written {
            Ok(()) => {
                let next = Duration::from_secs((candidate.ttl_secs / 2).max(1));
                self.due = Instant::now() + next;
                self.retry = RETRY_FIRST;
                tracing::info!(next_in_secs = next.as_secs(), "device credential renewed");
                true
            }
            Err(error) => {
                self.failed(&format!("{error:#}"));
                false
            }
        }
    }

    /// A renewal that did not land, for `reason`: the current credential
    /// stays, and it is tried again after the retry wait, which then doubles.
    pub(super) fn failed(&mut self, reason: &str) {
        tracing::warn!(
            retry_in_secs = self.retry.as_secs(),
            "device credential renewal failed ({reason}); the current credential stays"
        );
        self.due = Instant::now() + self.retry;
        self.retry = (self.retry * 2).min(RETRY_MOST);
    }
}

/// One renewal of the credential `path` holds, off the async loop: the
/// replacement the home answered, read but not written.
fn renew(origin: &str, path: &Path, vault: &oneiron::Vault) -> Result<Candidate, Failure> {
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
    candidate(&replacement)
}

/// The same renewal over one fresh mesh stream to the home: the same
/// bearer, holder proof, machine proof and empty body the origin call
/// sends, answered by the same route.
async fn renew_mesh(
    origin: &str,
    path: &Path,
    vault: &oneiron::Vault,
    dialer: &dyn oneiron::sync::SyncDialer,
) -> Result<Candidate, Failure> {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, Uri, header};
    use oneiron::authority::{
        CapabilitySlip, MACHINE_PROOF_HEADER, holder_proof, machine_proof_header_value,
    };
    let failed = |error: &dyn std::fmt::Display| Failure::Failed(format!("{error:#}"));
    let mut current = PairedCredentialFile::read(path).map_err(|e| failed(&e))?;
    let slip = CapabilitySlip::from_token(&current.token).map_err(|e| failed(&e))?;
    let key = current.signing_key().map_err(|e| failed(&e))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| failed(&e))?
        .as_secs();
    let proof = holder_proof(&slip, &key, timestamp).map_err(|e| failed(&e))?;
    let nonce = proof
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Failure::Failed("could not sign the renewal's holder proof".to_owned()))?;
    let (machine, signature) = vault
        .machine_connection_proof(&current.token, timestamp, nonce)
        .map_err(|e| failed(&e))?
        .ok_or_else(|| {
            Failure::Refused("this install is not a machine of the vault yet".to_owned())
        })?;
    let uri: Uri = origin.parse().map_err(|e| failed(&e))?;
    let host = uri
        .authority()
        .ok_or_else(|| Failure::Unusable("the home's origin names no host".to_owned()))?;
    let request = Request::post(RENEW_PATH)
        .header(header::HOST, host.as_str())
        .header(header::AUTHORIZATION, format!("Bearer {}", current.token))
        .header("x-oneiron-binding", proof.to_string())
        .header(
            MACHINE_PROOF_HEADER,
            machine_proof_header_value(machine, &signature),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close")
        .body(Body::from("{}"))
        .map_err(|e| failed(&e))?;
    let stream = dialer.dial().await.map_err(|e| failed(&e))?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Body>(hyper_util::rt::TokioIo::new(stream))
            .await
            .map_err(|e| failed(&e))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
    let status = response.status();
    let bytes = to_bytes(
        Body::new(response.into_body()),
        oneiron_remote::MAX_REMOTE_RESPONSE_BYTES,
    )
    .await
    .map_err(|e| failed(&e))?;
    if !status.is_success() {
        let reason = format!(
            "home answered {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        return Err(match status.as_u16() {
            401 | 403 => Failure::Refused(reason),
            400 => Failure::Unusable(reason),
            _ => Failure::Failed(reason),
        });
    }
    #[derive(serde::Deserialize)]
    struct Reply {
        token: String,
    }
    let reply: Reply = serde_json::from_slice(&bytes).map_err(|e| failed(&e))?;
    CapabilitySlip::from_token(&reply.token)
        .map_err(|_| Failure::Failed(format!("the home answered {status} with no slip")))?;
    current.token = reply.token;
    candidate(&current.credential())
}

/// `replacement` read as the file would hold it, with its slip's lifetime.
/// Nothing is written here: the link writes it ([`Renewal::commit`]).
fn candidate(replacement: &str) -> Result<Candidate, Failure> {
    let credential = PairedCredentialFile::parse(replacement).ok_or_else(|| {
        Failure::Failed("the renewed credential is not a paired credential".to_owned())
    })?;
    let ttl_secs = oneiron::authority::CapabilitySlip::from_token(&credential.token)
        .map_err(|_| Failure::Failed("the renewed credential holds no v2 slip".to_owned()))?
        .claims
        .ttl_secs;
    Ok(Candidate {
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
