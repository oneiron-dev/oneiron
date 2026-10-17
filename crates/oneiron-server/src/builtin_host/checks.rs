//! The served host's connection checks: the engine's provider checks, plus
//! two that need this host's own config. `browser.session` is local
//! readiness rather than a provider call: it starts this host's `[browser]`
//! guest through the engine's sandbox selector, attaches the driver to a
//! blank page, and closes the session. The check guest has no egress at all:
//! it visits no site. `native_mail.jmap` connects to the `[native_mail]`
//! server with the stored credential, as the native mail host does, and
//! reads its domain; it sends no mail and changes no DNS.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use oneiron::Vault;
use oneiron::channel_identity_provider::stalwart::StalwartClient;
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::select_backend_for_session;
use oneiron::connector_key::{
    BROWSER_SESSION_CHECK, NATIVE_MAIL_JMAP_CHECK, PackConnectionCheck, PackConnectionEvidence,
    PackConnectionVerifier, ProviderConnectionChecks,
};
use oneiron_browser::{BrowserGuest, BrowserSession};
use oneiron_container::{
    EgressRelay, GuestSeccomp, GuestSpec, HttpRequest, HttpResponse, ImageRef, SessionManifest,
};

use crate::config::NativeMailConfig;
use crate::server::SyncServer;

/// The guest binary the browser image runs, as a code run starts it.
const BROWSER_GUEST_COMMAND: &str = "/usr/local/bin/oneiron-browser-guest";

/// What the owner's setup doors check a connection with on this host.
pub(crate) struct HostConnectionChecks {
    provider: ProviderConnectionChecks,
    browser: Option<BrowserGuest>,
    native_mail: Option<NativeMailConfig>,
}

impl HostConnectionChecks {
    pub(crate) fn new(server: &SyncServer) -> oneiron::Result<Self> {
        Ok(Self {
            provider: ProviderConnectionChecks::new()?,
            browser: server.browser_guest().cloned(),
            native_mail: server.config.native_mail.clone(),
        })
    }
}

impl PackConnectionVerifier for HostConnectionChecks {
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> Result<PackConnectionEvidence, String> {
        match check.check {
            BROWSER_SESSION_CHECK => {
                let guest = self
                    .browser
                    .as_ref()
                    .ok_or_else(|| "this host has no [browser] guest configured".to_owned())?;
                browser_session_ready(guest)
            }
            NATIVE_MAIL_JMAP_CHECK => {
                let server = self
                    .native_mail
                    .as_ref()
                    .ok_or_else(|| "this host has no [native_mail] server configured".to_owned())?;
                native_mail_ready(vault, check, server)
            }
            _ => self.provider.verify(vault, check),
        }
    }
}

/// Connects to the host's mail server with the connection's first credential
/// and reads its domain, through the engine's Stalwart client. The stored
/// value is the whole `Authorization` header (`Basic ...` or `Bearer ...`)
/// or a bare bearer token; it never leaves the credential door's closure.
fn native_mail_ready(
    vault: &Vault,
    check: &PackConnectionCheck<'_>,
    server: &NativeMailConfig,
) -> Result<PackConnectionEvidence, String> {
    let placement = server
        .stalwart()
        .map_err(|error| format!("the [native_mail] server is misconfigured: {error}"))?;
    let secret = check
        .secrets
        .first()
        .ok_or_else(|| "the connection names no credential to check".to_owned())?;
    let mut connected = None;
    vault
        .inject_secret_at_door(&secret.name, &secret.effector, &mut |value: &[u8]| {
            let value = std::str::from_utf8(value)
                .map_err(|_| {
                    oneiron::Error::InvalidConfig("the stored credential is not text".to_owned())
                })?
                .trim();
            let header = if value.starts_with("Basic ") || value.starts_with("Bearer ") {
                value.to_owned()
            } else {
                format!("Bearer {value}")
            };
            let header = reqwest::header::HeaderValue::from_str(&header).map_err(|_| {
                oneiron::Error::InvalidConfig(
                    "the stored credential is not a header value".to_owned(),
                )
            })?;
            connected = Some(
                StalwartClient::connect(placement.clone(), header)
                    .map(|_| ())
                    .map_err(|error| format!("the mail server refused the check: {error}")),
            );
            Ok(())
        })
        .map_err(|error| format!("the stored credential could not be read: {error}"))?;
    connected.unwrap_or_else(|| Err("the mail server was not reached".to_owned()))?;
    let proof = format!(
        "{}\n{}\n{}",
        server.session_url, server.domain, server.domain_id
    );
    Ok(PackConnectionEvidence {
        account: format!("{} on {}", placement.domain(), placement.instance_ref()),
        provider_account: Some(placement.domain().to_owned()),
        scopes: Vec::new(),
        evidence: blake3::hash(proof.as_bytes()).to_hex().to_string(),
    })
}

/// Starts one browser session the way a code run does, and closes it. The
/// evidence is the digest of what the guest's fence proved.
fn browser_session_ready(guest: &BrowserGuest) -> Result<PackConnectionEvidence, String> {
    let backend = select_backend_for_session(
        SandboxGuestTier::Untrusted,
        guest.runtime.clone(),
        &guest.image,
    )
    .map_err(|error| format!("no sandbox can start the browser guest: {error}"))?;
    let spec = GuestSpec {
        image: ImageRef::pinned(&guest.image)
            .map_err(|error| format!("the browser guest image is not pinned: {error}"))?,
        user: (10001, 10001),
        limits: guest.limits,
        seccomp: GuestSeccomp::EngineFence,
        read_only_mounts: Vec::new(),
    };
    let relay: Arc<dyn EgressRelay> = Arc::new(NoEgress);
    let transport = backend
        .start_session(&spec, &[BROWSER_GUEST_COMMAND.into()], Arc::clone(&relay))
        .map_err(|error| format!("the browser guest did not start: {error}"))?;
    let session = BrowserSession::attach(guest, transport, relay)
        .map_err(|error| format!("the browser driver did not open a page: {error}"))?;
    let manifest = session.manifest().clone();
    drop(session);
    let proof = serde_json::to_vec(&manifest)
        .map_err(|_| "the browser guest's manifest is unreadable".to_owned())?;
    Ok(PackConnectionEvidence {
        account: format!(
            "browser guest {} on {} ({})",
            manifest.image, manifest.runtime, manifest.backend
        ),
        provider_account: None,
        scopes: Vec::new(),
        evidence: blake3::hash(&proof).to_hex().to_string(),
    })
}

/// A readiness check's relay: the guest reaches nothing.
struct NoEgress;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "a browser readiness check has no egress",
    )
}

impl EgressRelay for NoEgress {
    fn connect(&self, _target: SocketAddr) -> io::Result<TcpStream> {
        Err(refused())
    }

    fn authorize_datagram(&self, _target: SocketAddr) -> io::Result<()> {
        Err(refused())
    }

    fn record_session(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn record_abandoned(&self, _manifest: &SessionManifest) -> io::Result<()> {
        Ok(())
    }

    fn datagram(&self, _target: SocketAddr, _bytes: &[u8]) -> io::Result<Vec<u8>> {
        Err(refused())
    }

    fn fetch(&self, _request: HttpRequest) -> io::Result<HttpResponse> {
        Err(refused())
    }

    fn transferred(&self, _target: SocketAddr, _content_hash: [u8; 32], _bytes: u64) {}
}
