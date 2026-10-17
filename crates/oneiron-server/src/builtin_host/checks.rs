//! The served host's connection checks: the engine's provider checks, plus
//! `browser.session`, which is local readiness rather than a provider call.
//! It starts this host's `[browser]` guest through the engine's sandbox
//! selector, attaches the driver to a blank page, and closes the session.
//! The check guest has no egress at all: it visits no site.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use oneiron::Vault;
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::microvm::select_backend_for_session;
use oneiron::connector_key::{
    BROWSER_SESSION_CHECK, PackConnectionCheck, PackConnectionEvidence, PackConnectionVerifier,
    ProviderConnectionChecks,
};
use oneiron_browser::{BrowserGuest, BrowserSession};
use oneiron_container::{
    EgressRelay, GuestSeccomp, GuestSpec, HttpRequest, HttpResponse, ImageRef, SessionManifest,
};

use crate::server::SyncServer;

/// The guest binary the browser image runs, as a code run starts it.
const BROWSER_GUEST_COMMAND: &str = "/usr/local/bin/oneiron-browser-guest";

/// What the owner's setup doors check a connection with on this host.
pub(crate) struct HostConnectionChecks {
    provider: ProviderConnectionChecks,
    browser: Option<BrowserGuest>,
}

impl HostConnectionChecks {
    pub(crate) fn new(server: &SyncServer) -> oneiron::Result<Self> {
        Ok(Self {
            provider: ProviderConnectionChecks::new()?,
            browser: server.browser_guest().cloned(),
        })
    }
}

impl PackConnectionVerifier for HostConnectionChecks {
    fn verify(
        &self,
        vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> Result<PackConnectionEvidence, String> {
        if check.check != BROWSER_SESSION_CHECK {
            return self.provider.verify(vault, check);
        }
        let guest = self
            .browser
            .as_ref()
            .ok_or_else(|| "this host has no [browser] guest configured".to_owned())?;
        browser_session_ready(guest)
    }
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
