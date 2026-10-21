//! The outside import's per-call transport (FIX 6871, G7 PR1).
//!
//! [`external_import_host`] builds, from the credential this request
//! verified, the one [`ExternalGitSourceHost`] a `vault.code.imports.*` call
//! lends its handle. It carries transport and custody, never authority:
//!
//! - **Fetch.** The source is read over https from its own host only. A
//!   named binding's `Authorization` header is injected inside the custody
//!   door and never leaves it. Before Git runs, one probe of the source's
//!   advertisement resolves redirects: one that stays on the same https
//!   host is followed with the binding; any other is a refusal naming its
//!   target, so the caller can import from there. Git itself then fetches
//!   the resolved URL with redirects off.
//! - **Push.** Stock Git pushes from the scratch store to a relay of this
//!   invocation alone: a loopback listener on an OS-assigned port under an
//!   unguessable in-memory path, serving the receive-pack advertisement
//!   and RPC of the one selected repository and route. Each request carries
//!   the ORIGINAL verified credential, checked again for revocation, through
//!   the ordinary receive-pack gate (Write, unrestricted record scope, a
//!   registered principal), and is served by [`run_serve`] exactly as a
//!   `/git` push is: the same push decision, transfer permits, push turn,
//!   bounds, door scan, quarantine and final recheck. The relay is no
//!   public route, mints no token and stops when the push returns.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::response::Response;
use axum::routing::{get, post};
use oneiron::federation::GitPushCaller;
use oneiron::git_wire::{
    FetchedExternalGit, GitImportFetchOutcome, GitImportPushOutcome, GitOid, GitRefName, GitWire,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::origin::smart_http;
use oneiron::repo_mutation::external_import::{
    EXTERNAL_IMPORT_FETCH_EFFECTOR, ExternalGitSourceHost, ExternalImportDoor,
    ExternalImportLookup, ExternalImportSource, REDIRECT_REFUSED,
};
use tokio::runtime::Handle;
use tokio::sync::oneshot;

use super::gate::{
    admit_import_relay, advertised_service, header_value, push_caller, remote_user, text_response,
};
use super::routes::{GitService, advertisement_request};
use super::serve::run_serve;
use crate::auth::{CoreAuth, is_revoked_or_unreadable};
use crate::server::SyncServer;

/// The served name every relay path carries; the relay serves one repo.
const RELAY_REPO_SEGMENT: &str = "import.git";

/// The transport the verified credential `auth` lends one import call,
/// bound to its registered principal.
///
/// # Errors
/// A credential that binds no registered principal.
pub(crate) fn external_import_host(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
) -> MemoryResult<Arc<dyn ExternalGitSourceHost>> {
    let Some(caller) = push_caller(auth) else {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "an outside import needs a credential that binds a registered principal",
            &["Present a credential whose principal_ref names you."],
        ));
    };
    Ok(Arc::new(GitImportRelayHost {
        server: Arc::clone(server),
        auth: auth.clone(),
        caller,
        runtime: Handle::current(),
    }))
}

/// One call's transport: the verified credential, its pusher and the
/// runtime its relay serves on.
struct GitImportRelayHost {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    caller: GitPushCaller,
    runtime: Handle,
}

/// Whether `auth`'s token was revoked since it was verified (or its
/// registry cannot be read). A capability slip is judged by the door's own
/// final recheck.
fn revoked(server: &SyncServer, auth: &CoreAuth) -> bool {
    auth.jti().is_some_and(|jti| {
        jti.len() != 64 && is_revoked_or_unreadable(jti, server.vault().as_ref())
    })
}

impl ExternalGitSourceHost for GitImportRelayHost {
    fn caller(&self) -> &GitPushCaller {
        &self.caller
    }

    fn revalidate(&self) -> oneiron::Result<()> {
        if revoked(&self.server, &self.auth) {
            return Err(oneiron::Error::Refused(
                "external_import_credential_revoked: the credential this import runs under no \
                 longer stands"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    fn fetch_exact(
        &self,
        wire: &GitWire<'_>,
        source: &ExternalImportSource,
        binding: Option<&str>,
    ) -> oneiron::Result<GitImportFetchOutcome> {
        let source_ref = GitRefName::parse_full(source.source_ref.clone())?;
        let base = GitOid::parse_hex(source.base_commit.clone())?;
        let head = GitOid::parse_hex(source.head_commit.clone())?;
        let Some(secret_ref) = binding else {
            return match resolve_source_url(&source.host, &source.repository, None) {
                Ok(url) => wire.fetch_external_exact(&url, &source_ref, &base, &head, None),
                Err(refused) => Ok(refused),
            };
        };
        let mut answer = Err(oneiron::Error::InvariantViolation(
            "an outside import fetch never ran",
        ));
        self.server.vault().inject_secret_at_door(
            secret_ref,
            EXTERNAL_IMPORT_FETCH_EFFECTOR,
            &mut |value: &[u8]| {
                let Ok(text) = std::str::from_utf8(value) else {
                    answer = Ok(GitImportFetchOutcome::Refused(
                        "binding_not_a_header".to_owned(),
                    ));
                    return Ok(());
                };
                let header = zeroize::Zeroizing::new(text.trim().to_owned());
                answer = match resolve_source_url(
                    &source.host,
                    &source.repository,
                    Some(header.as_str()),
                ) {
                    Ok(url) => wire.fetch_external_exact(
                        &url,
                        &source_ref,
                        &base,
                        &head,
                        Some(header.as_str()),
                    ),
                    Err(refused) => Ok(refused),
                };
                Ok(())
            },
        )?;
        answer
    }

    fn push_exact(
        &self,
        wire: &GitWire<'_>,
        fetched: &FetchedExternalGit,
        lookup: &ExternalImportLookup,
        name: &GitRefName,
        expected: Option<&GitOid>,
        commit: &GitOid,
    ) -> oneiron::Result<GitImportPushOutcome> {
        let relay = ImportRelay::start(self, lookup)?;
        let pushed = wire.push_external_to_door(fetched, &relay.url, name, commit, expected);
        let refused = relay.stop();
        Ok(match (pushed?, refused) {
            (GitImportPushOutcome::Applied, _) => GitImportPushOutcome::Applied,
            (_, Some(status)) => {
                GitImportPushOutcome::Rejected(format!("door_refused_http_{status}"))
            }
            (other, None) => other,
        })
    }
}

/// The URL the source's advertisement answers from, after following each
/// redirect that stays on its own https `origin` (with `header` when one is
/// bound). A redirect anywhere else refuses, naming its target; a loop
/// refuses. No credential reaches another host, and no bound is added.
fn resolve_source_url(
    origin: &str,
    repository: &str,
    header: Option<&str>,
) -> std::result::Result<String, GitImportFetchOutcome> {
    let refused = |reason: &str| GitImportFetchOutcome::Refused(reason.to_owned());
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| refused("source_client_unavailable"))?;
    let mut url = repository.trim_end_matches('/').to_owned();
    let mut seen = BTreeSet::new();
    while seen.insert(url.clone()) {
        let mut request = client.get(format!("{url}/info/refs?service=git-upload-pack"));
        if let Some(header) = header {
            let mut value = reqwest::header::HeaderValue::from_str(header)
                .map_err(|_| refused("binding_not_a_header"))?;
            value.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        let response = request.send().map_err(|_| refused("source_unreachable"))?;
        if !response.status().is_redirection() {
            return Ok(url);
        }
        let target = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|location| response.url().join(location).ok())
            .ok_or_else(|| refused("source_redirect_without_target"))?;
        let redirected = redirected_repository(&target);
        if target.scheme() != "https" || format!("https://{}", authority(&target)) != origin {
            return Err(GitImportFetchOutcome::Refused(format!(
                "{REDIRECT_REFUSED}{redirected}"
            )));
        }
        url = redirected;
    }
    Err(refused("source_redirect_loop"))
}

/// The repository a redirected advertisement names: its scheme, host and
/// path, without the smart-HTTP suffix, userinfo, query or fragment.
fn redirected_repository(target: &reqwest::Url) -> String {
    let path = target.path();
    let path = path
        .strip_suffix("/info/refs")
        .unwrap_or(path)
        .trim_end_matches('/');
    format!("{}://{}{path}", target.scheme(), authority(target))
}

/// `host[:port]`, lowercase, the port only when it is not the default.
fn authority(target: &reqwest::Url) -> String {
    let host = target.host_str().unwrap_or_default().to_ascii_lowercase();
    match target.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// What one relay serves, and the first refusal it answered.
struct RelayState {
    server: Arc<SyncServer>,
    auth: CoreAuth,
    repo: String,
    ticket: Option<String>,
    refused: Mutex<Option<u16>>,
}

impl RelayState {
    /// The original credential, checked again and admitted by the ordinary
    /// receive-pack gate.
    fn admitted(&self) -> Result<CoreAuth, Box<Response>> {
        if revoked(&self.server, &self.auth) {
            return Err(Box::new(text_response(
                StatusCode::UNAUTHORIZED,
                "the credential this import runs under no longer stands",
            )));
        }
        admit_import_relay(self.auth.clone(), GitService::ReceivePack)
    }

    /// Notes a refusing answer, then hands it back.
    fn observed(&self, response: Response) -> Response {
        let status = response.status();
        if (status.is_client_error() || status.is_server_error())
            && let Ok(mut refused) = self.refused.lock()
        {
            refused.get_or_insert(status.as_u16());
        }
        response
    }
}

/// `GET <relay>/info/refs?service=git-receive-pack`: the advertisement.
async fn relay_info_refs(
    State(relay): State<Arc<RelayState>>,
    RawQuery(query): RawQuery,
) -> Response {
    match advertised_service(&query.unwrap_or_default()) {
        Ok(GitService::ReceivePack) => {}
        Ok(GitService::UploadPack) => {
            return relay.observed(text_response(
                StatusCode::FORBIDDEN,
                "the import relay serves receive-pack only",
            ));
        }
        Err(refusal) => return relay.observed(refusal.response()),
    }
    let auth = match relay.admitted() {
        Ok(auth) => auth,
        Err(response) => return relay.observed(*response),
    };
    let mut request =
        advertisement_request(&relay.repo, GitService::ReceivePack, remote_user(&auth));
    if let Some(ticket) = &relay.ticket {
        request
            .query_string
            .push_str(&format!("&checkout-lease={ticket}"));
    }
    let response = run_serve(
        Arc::clone(&relay.server),
        relay.repo.clone(),
        request,
        Body::empty(),
        push_caller(&auth),
    )
    .await;
    relay.observed(response)
}

/// `POST <relay>/git-receive-pack`: the push, streamed.
async fn relay_receive_pack(
    State(relay): State<Arc<RelayState>>,
    parts: Parts,
    body: Body,
) -> Response {
    let auth = match relay.admitted() {
        Ok(auth) => auth,
        Err(response) => return relay.observed(*response),
    };
    let headers = &parts.headers;
    let request = smart_http::ServeRequest {
        method: "POST".to_owned(),
        path_info: format!("/{}.git/{}", relay.repo, GitService::ReceivePack.as_str()),
        query_string: relay
            .ticket
            .as_ref()
            .map_or_else(String::new, |ticket| format!("checkout-lease={ticket}")),
        content_type: header_value(headers, CONTENT_TYPE.as_str()),
        content_length: header_value(headers, CONTENT_LENGTH.as_str())
            .and_then(|value| value.parse::<u64>().ok()),
        content_encoding: header_value(headers, CONTENT_ENCODING.as_str()),
        git_protocol: None,
        remote_user: remote_user(&auth),
        remote_addr: None,
    };
    let response = run_serve(
        Arc::clone(&relay.server),
        relay.repo.clone(),
        request,
        body,
        push_caller(&auth),
    )
    .await;
    relay.observed(response)
}

/// One invocation's loopback relay.
struct ImportRelay {
    url: String,
    stop: Option<oneshot::Sender<()>>,
    state: Arc<RelayState>,
}

impl ImportRelay {
    /// Serves the route `lookup` selects, as `host`'s caller, on an
    /// OS-assigned loopback port under a fresh unguessable path.
    fn start(host: &GitImportRelayHost, lookup: &ExternalImportLookup) -> oneiron::Result<Self> {
        let mut secret = [0_u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
        let secret: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
        let ticket = match &lookup.door {
            ExternalImportDoor::Raw => None,
            ExternalImportDoor::Checkout { checkout, epoch } => Some(format!("{checkout}.{epoch}")),
        };
        let state = Arc::new(RelayState {
            server: Arc::clone(&host.server),
            auth: host.auth.clone(),
            repo: lookup.repo.clone(),
            ticket,
            refused: Mutex::new(None),
        });
        let base = format!("/{secret}/{RELAY_REPO_SEGMENT}");
        let app = Router::new()
            .route(&format!("{base}/info/refs"), get(relay_info_refs))
            .route(
                &format!("{base}/git-receive-pack"),
                post(relay_receive_pack),
            )
            .with_state(Arc::clone(&state));
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let listener = {
            let _entered = host.runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let (stop, stopped) = oneshot::channel::<()>();
        drop(host.runtime.spawn(async move {
            let shutdown = async move {
                let _ = stopped.await;
            };
            if let Err(error) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                tracing::warn!(%error, "the outside import relay stopped with an error");
            }
        }));
        Ok(Self {
            url: format!("http://127.0.0.1:{port}{base}"),
            stop: Some(stop),
            state,
        })
    }

    /// Stops the relay and answers the first refusing status it served.
    fn stop(mut self) -> Option<u16> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.state.refused.lock().ok().and_then(|refused| *refused)
    }
}

impl Drop for ImportRelay {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
