//! FIX 3377: the device renews its paired owner credential at its home
//! (`POST /v1/core/slips/renew`), with the request
//! [`oneiron_remote::OneironClient::renew_owner_device_credential`] makes,
//! sent on an async client of the renewal's own, so a stopping link aborts it
//! where it stands and waits for its end (FIX 5772). A link that dials its
//! home over the mesh posts the same request on one mesh stream instead (FIX
//! 3561): the home's sync route serves the whole router.
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

/// The header the renewal's holder proof crosses in.
const BINDING_HEADER: &str = "x-oneiron-binding";

/// How long a direct renewal waits to reach the home's origin: the SDK's own
/// connect timeout, kept when the request moved here.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a direct renewal waits for the home's whole answer: the SDK's own
/// request timeout, kept likewise. A renewal over the mesh meets it too, from
/// its dial to the answer's last byte (FIX 8635). A stop never waits it out:
/// it aborts the renewal ([`Renewal::stop`]).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

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
    /// The renewal under way, a task on the async loop: kept across a
    /// caller that stopped waiting, and ended by [`Self::stop`].
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
                let dialer = self.dialer.clone();
                self.in_flight = Some(tokio::spawn(async move {
                    match dialer {
                        Some(dialer) => renew_mesh(&origin, &path, &vault, dialer.as_ref()).await,
                        None => renew(&origin, &path, &vault).await,
                    }
                }));
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

    /// Ends the renewal under way, if one is, and waits until it has: its
    /// request is dropped where it stands, mesh or direct, so none of it
    /// outlives the link (FIX 5772). A renewal only fetches, so nothing is
    /// written, and one cut short is no failure.
    pub(super) async fn stop(&mut self) {
        let Some(in_flight) = self.in_flight.take() else {
            return;
        };
        in_flight.abort();
        if let Err(error) = in_flight.await
            && error.is_panic()
        {
            tracing::warn!(%error, "device credential renewal task");
        }
    }
}

/// The schedule goes when its link stops, which first ends a renewal under
/// way ([`Renewal::stop`]). A schedule dropped any other way aborts that
/// renewal, mesh or direct, so it neither reads the vault for its machine
/// proof nor dials over a mesh that is closing (FIX 5773), though it cannot
/// wait for its end. Neither writes anything.
impl Drop for Renewal {
    fn drop(&mut self) {
        if let Some(in_flight) = &self.in_flight {
            in_flight.abort();
        }
    }
}

/// A failure this time, for `error`.
fn failed(error: &dyn std::fmt::Display) -> Failure {
    Failure::Failed(format!("{error:#}"))
}

/// What one renewal request carries: the credential it renews, a fresh
/// holder proof its connection key signs, and this install's machine proof
/// over the same token, timestamp and nonce.
struct Proofs {
    current: PairedCredentialFile,
    binding: String,
    machine: String,
}

/// Reads the credential `path` holds and signs its renewal's proofs.
/// `unpaired` is the failure for a credential whose slip or key does not
/// parse.
fn prepare(
    path: &Path,
    vault: &oneiron::Vault,
    unpaired: fn(String) -> Failure,
) -> Result<Proofs, Failure> {
    use oneiron::authority::{CapabilitySlip, holder_proof, machine_proof_header_value};
    let not_paired = |error: &dyn std::fmt::Display| {
        unpaired(format!(
            "the credential is not a paired credential: {error:#}"
        ))
    };
    let current = PairedCredentialFile::read(path).map_err(|e| failed(&e))?;
    let slip = CapabilitySlip::from_token(&current.token).map_err(|e| not_paired(&e))?;
    let key = current.signing_key().map_err(|e| not_paired(&e))?;
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
    Ok(Proofs {
        binding: proof.to_string(),
        machine: machine_proof_header_value(machine, &signature),
        current,
    })
}

/// One renewal of the credential `path` holds at the home's `origin`: the
/// replacement the home answered, read but not written. It sends what the
/// SDK's renewal sends, with the SDK's timeouts, origin rules and refusal
/// codes, on the async loop, so a stop aborts it where it stands.
async fn renew(origin: &str, path: &Path, vault: &oneiron::Vault) -> Result<Candidate, Failure> {
    use oneiron::authority::MACHINE_PROOF_HEADER;
    use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};

    let url = renew_url(origin)?;
    let Proofs {
        mut current,
        binding,
        machine,
    } = prepare(path, vault, Failure::Unusable)?;
    let mut bearer = HeaderValue::try_from(format!("Bearer {}", current.token)).map_err(|_| {
        Failure::Refused("the credential is not a valid HTTP header value".to_owned())
    })?;
    bearer.set_sensitive(true);
    let mut binding = HeaderValue::try_from(binding)
        .map_err(|_| Failure::Failed("could not sign the renewal's holder proof".to_owned()))?;
    binding.set_sensitive(true);
    let client = reqwest::Client::builder()
        // A redirect must not move the bearer off the home's origin, or from
        // HTTPS to cleartext.
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|error| Failure::Failed(format!("could not build the HTTP client: {error}")))?;
    let response = client
        .post(url)
        .header(AUTHORIZATION, bearer)
        .header(BINDING_HEADER, binding)
        .header(MACHINE_PROOF_HEADER, machine)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body("{}")
        .send()
        .await
        .map_err(|error| sent(&error))?;
    let status = response.status();
    let bytes = response.bytes().await.map_err(|error| sent(&error))?;
    if !status.is_success() {
        return Err(refusal(status, &bytes));
    }
    current.token = renewed(status, &bytes)?;
    candidate(&current.credential())
}

/// The renew route at the home's `origin`, which is `https`, or `http` on
/// this machine, and carries no userinfo, query or fragment, as the SDK asks
/// of any origin it sends a bearer to. No reason echoes the origin.
fn renew_url(origin: &str) -> Result<reqwest::Url, Failure> {
    let unusable = |reason: &str| Failure::Unusable(format!("the home's origin {reason}"));
    let mut url =
        reqwest::Url::parse(origin).map_err(|error| unusable(&format!("is not a URL: {error}")))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !matches!((url.scheme(), loopback), ("https", _) | ("http", true)) {
        return Err(unusable("must be https://, or http:// on this machine"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(unusable("must not carry userinfo"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(unusable("must not carry a query or fragment"));
    }
    // With a trailing slash the route joins under the origin's own path.
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    url.join(RENEW_PATH.trim_start_matches('/'))
        .map_err(|error| unusable(&format!("names no renew route: {error}")))
}

/// A direct request that failed, named without its URL or body.
fn sent(error: &reqwest::Error) -> Failure {
    let reason = if error.is_timeout() {
        "the request to the home timed out"
    } else if error.is_connect() {
        "could not connect to the home"
    } else {
        "the request to the home failed"
    };
    Failure::Failed(reason.to_owned())
}

/// The engine's error envelope, read for its code and message alone.
#[derive(serde::Deserialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

/// The envelope's `{code, message}`; its other fields are not read here.
#[derive(serde::Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
}

/// Why the home did not renew, by the code its error envelope names, as the
/// SDK reads a refusal. A body that is no envelope, such as a proxy's page,
/// is tried again, and none of it is logged.
fn refusal(status: reqwest::StatusCode, bytes: &[u8]) -> Failure {
    let Some(ErrorBody { code, message }) = serde_json::from_slice::<ErrorEnvelope>(bytes)
        .ok()
        .map(|envelope| envelope.error)
        .filter(|error| !error.code.is_empty())
    else {
        return Failure::Failed(format!(
            "the home answered {status} with a body that is not an Oneiron error envelope"
        ));
    };
    let reason = format!("{code}: {message}");
    if REFUSALS.contains(&code.as_str()) {
        Failure::Refused(reason)
    } else if code == UNUSABLE {
        Failure::Unusable(reason)
    } else {
        Failure::Failed(reason)
    }
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
    use oneiron::authority::MACHINE_PROOF_HEADER;
    let Proofs {
        mut current,
        binding,
        machine,
    } = prepare(path, vault, Failure::Failed)?;
    let uri: Uri = origin.parse().map_err(|e| failed(&e))?;
    let host = uri
        .authority()
        .ok_or_else(|| Failure::Unusable("the home's origin names no host".to_owned()))?;
    let request = Request::post(RENEW_PATH)
        .header(header::HOST, host.as_str())
        .header(header::AUTHORIZATION, format!("Bearer {}", current.token))
        .header(BINDING_HEADER, binding)
        .header(MACHINE_PROOF_HEADER, machine)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .header(header::CONNECTION, "close")
        .body(Body::from("{}"))
        .map_err(|e| failed(&e))?;
    // The dial, the handshake, the exchange and the connection's drive meet
    // one request timeout, as a direct renewal does: one that runs past it
    // fails, the old credential stands and the renewal is tried again
    // (FIX 8635).
    let renewal = async {
        let stream = dialer.dial().await.map_err(|e| failed(&e))?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake::<_, Body>(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|e| failed(&e))?;
        let exchange = async move {
            let response = sender.send_request(request).await.map_err(|e| failed(&e))?;
            let status = response.status();
            let bytes = to_bytes(
                Body::new(response.into_body()),
                oneiron_remote::MAX_REMOTE_RESPONSE_BYTES,
            )
            .await
            .map_err(|e| failed(&e))?;
            Ok::<_, Failure>((status, bytes))
        };
        // The connection is driven here, beside its one exchange, never on a
        // task of its own, so a renewal aborted at stop leaves none of it
        // behind.
        tokio::pin!(exchange, connection);
        let mut driving = true;
        Ok::<_, Failure>(loop {
            tokio::select! {
                exchanged = &mut exchange => break exchanged?,
                _ = &mut connection, if driving => driving = false,
            }
        })
    };
    let (status, bytes) = tokio::time::timeout(REQUEST_TIMEOUT, renewal)
        .await
        .map_err(|_| Failure::Failed("the renewal over the mesh timed out".to_owned()))??;
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
    current.token = renewed(status, &bytes)?;
    candidate(&current.credential())
}

/// The renew route's success body.
#[derive(serde::Deserialize)]
struct Renewed {
    token: String,
}

/// The new slip a success answer of `status` carries, once it parses as a
/// v2 slip. Its key is the old one: the caller keeps the same seed.
fn renewed(status: impl std::fmt::Display, bytes: &[u8]) -> Result<String, Failure> {
    let reply: Renewed = serde_json::from_slice(bytes).map_err(|e| failed(&e))?;
    oneiron::authority::CapabilitySlip::from_token(&reply.token)
        .map_err(|_| Failure::Failed(format!("the home answered {status} with no slip")))?;
    Ok(reply.token)
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
