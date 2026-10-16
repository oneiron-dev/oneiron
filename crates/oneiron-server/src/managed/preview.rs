//! Native forwarding for a manifest-declared private session port.
//!
//! The runtime supplies a connector to the verified process inside its sandbox.
//! Each lease gets an origin with no vault API, and only a loopback listener.
//! A remote host carries it over the existing vault transport, not a tunnel.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use oneiron::artifact_hosting::preview::{
    PreviewEndpoint, PreviewSessionManifest, PreviewStage, PrivatePreview,
};
use oneiron_vault_contract::host::{PreviewHostFuture, PreviewPortHost};
use oneiron_vault_contract::{TokenHex, now_ts};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::{ManagedShutdown, ShutdownSignal};

#[path = "preview/http.rs"]
mod http;

/// The adapter may connect to a guest socket, a local child, or a stream on
/// the vault's existing transport. No destination comes from an HTTP request.
pub trait PreviewIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> PreviewIo for T {}

pub type PreviewConnection = Box<dyn PreviewIo>;
pub type PreviewConnectFuture<'a> =
    Pin<Box<dyn Future<Output = io::Result<PreviewConnection>> + Send + 'a>>;

/// The session runtime vouches for the complete manifest, including owner,
/// process identity, port and lease. `stopped` must also resolve for a process
/// that ended before it was polled. It ends on lease cancellation as well as
/// process exit; the wall-clock expiry is enforced separately by this host.
pub trait PreviewProcess: Send + Sync {
    fn manifest(&self) -> &PreviewSessionManifest;
    fn connect(&self, port: u16) -> PreviewConnectFuture<'_>;
    fn stopped(&self) -> ShutdownSignal;
}

/// Used by both desktop and managed hosts. Construct it with that host's stop
/// signal and its session's verified process connector, before opening a port.
pub struct LocalPreviewHost {
    process: Arc<dyn PreviewProcess>,
    host_stop: ManagedShutdown,
    active: Mutex<Option<Weak<SharedPreview>>>,
}

impl LocalPreviewHost {
    pub fn new(process: Arc<dyn PreviewProcess>, host_stop: ManagedShutdown) -> Self {
        Self {
            process,
            host_stop,
            active: Mutex::new(None),
        }
    }
}

impl PreviewPortHost for LocalPreviewHost {
    type Lease = PreviewLease;

    fn open_preview(
        &self,
        manifest: PreviewSessionManifest,
    ) -> PreviewHostFuture<'_, PreviewLease> {
        Box::pin(async move {
            anyhow::ensure!(!self.host_stop.is_triggered(), "preview host stopped");
            anyhow::ensure!(
                manifest == *self.process.manifest(),
                "preview manifest mismatch"
            );
            let preview = PrivatePreview::new(manifest.clone(), now_ts())?;
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let port = listener.local_addr()?.port();
            let mut origin_id = [0_u8; 16];
            OsRng.fill_bytes(&mut origin_id);
            // A distinct .localhost host also separates cookies, which ports
            // alone do not. Browsers resolve this reserved suffix to loopback.
            let authority = format!(
                "preview-{}.localhost:{port}",
                oneiron::artifact_hex(&origin_id)
            );
            let endpoint = PreviewEndpoint {
                session_ref: manifest.session_ref,
                lease_ref: manifest.lease_ref,
                local_url: format!("http://{authority}"),
                stage: PreviewStage::Draft,
                expires_at: manifest.expires_at,
            };
            let shared = Arc::new(SharedPreview {
                preview: Mutex::new(preview),
                endpoint,
                authority,
                process: Arc::clone(&self.process),
                closed: ManagedShutdown::new(),
                audience_changed: watch::channel(()).0,
            });
            {
                let mut active = self.active.lock().expect("preview host lock");
                anyhow::ensure!(
                    !active
                        .as_ref()
                        .and_then(Weak::upgrade)
                        .is_some_and(|previous| previous.is_live()),
                    "session preview already open"
                );
                *active = Some(Arc::downgrade(&shared));
            }
            let lease = PreviewLease {
                shared: Arc::clone(&shared),
            };
            tokio::spawn(run_listener(listener, shared, self.host_stop.clone()));
            Ok(lease)
        })
    }
}

/// The session runtime owns this handle. Ending the lease, dropping it,
/// stopping the host or losing the process closes all forwarding, including
/// streaming responses and upgraded WebSockets.
pub struct PreviewLease {
    shared: Arc<SharedPreview>,
}

impl PreviewLease {
    pub fn endpoint(&self) -> &PreviewEndpoint {
        &self.shared.endpoint
    }

    pub fn is_live(&self) -> bool {
        self.shared.is_live()
    }

    /// Call after authenticating the principal on the host's normal surface.
    /// An invitee cannot use this door until the owner has named them.
    pub fn access_url(&self, principal: &str) -> anyhow::Result<Zeroizing<String>> {
        let token = self
            .shared
            .preview
            .lock()
            .expect("preview lock")
            .access_token(principal, now_ts())?;
        Ok(self.shared.access_url(&token))
    }

    pub fn invite(&self, owner: &str, principal: &str) -> anyhow::Result<()> {
        self.shared
            .preview
            .lock()
            .expect("preview lock")
            .invite(owner, principal, now_ts())?;
        Ok(())
    }

    pub fn revoke_invite(&self, owner: &str, principal: &str) -> anyhow::Result<bool> {
        let removed = self
            .shared
            .preview
            .lock()
            .expect("preview lock")
            .revoke_invite(owner, principal, now_ts())?;
        self.shared.audience_changed.send_replace(());
        Ok(removed)
    }

    pub fn share_url(&self, owner: &str) -> anyhow::Result<Zeroizing<String>> {
        let token = self
            .shared
            .preview
            .lock()
            .expect("preview lock")
            .share(owner, now_ts())?;
        self.shared.audience_changed.send_replace(());
        Ok(self.shared.access_url(&token))
    }

    pub fn revoke_share(&self, owner: &str) -> anyhow::Result<bool> {
        let removed = self
            .shared
            .preview
            .lock()
            .expect("preview lock")
            .revoke_share(owner, now_ts())?;
        self.shared.audience_changed.send_replace(());
        Ok(removed)
    }

    pub fn close(&self) {
        self.shared.close();
    }
}

impl Drop for PreviewLease {
    fn drop(&mut self) {
        self.close();
    }
}

struct SharedPreview {
    preview: Mutex<PrivatePreview>,
    endpoint: PreviewEndpoint,
    authority: String,
    process: Arc<dyn PreviewProcess>,
    closed: ManagedShutdown,
    audience_changed: watch::Sender<()>,
}

impl SharedPreview {
    fn is_live(&self) -> bool {
        !self.closed.is_triggered() && self.preview.lock().expect("preview lock").is_live(now_ts())
    }

    fn access_url(&self, token: &TokenHex) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{}/__oneiron_preview_access?token={}",
            self.endpoint.local_url,
            token.expose()
        ))
    }

    fn admits(&self, token: &str) -> bool {
        !self.closed.is_triggered()
            && self
                .preview
                .lock()
                .expect("preview lock")
                .admits_token(token, now_ts())
    }

    fn close(&self) {
        self.closed.trigger();
        self.preview
            .lock()
            .expect("preview lock")
            .end_lease(&self.endpoint.lease_ref);
    }
}

/// A request retains its own credential while bytes are in flight. Audience
/// revocation closes old streams too, not just their next HTTP request.
#[derive(Clone)]
struct Access {
    shared: Arc<SharedPreview>,
    token: TokenHex,
    changed: watch::Receiver<()>,
}

impl Access {
    fn authorize(shared: &Arc<SharedPreview>, token: &str) -> Option<Self> {
        let changed = shared.audience_changed.subscribe();
        shared.admits(token).then(|| Self {
            shared: Arc::clone(shared),
            token: TokenHex::new(token.to_owned()),
            changed,
        })
    }

    async fn revoked(mut self) {
        loop {
            if !self.shared.admits(self.token.expose()) {
                return;
            }
            tokio::select! {
                biased;
                () = self.shared.closed.triggered() => return,
                changed = self.changed.changed() => if changed.is_err() { return; },
            }
        }
    }
}

async fn run_listener(
    listener: TcpListener,
    shared: Arc<SharedPreview>,
    host_stop: ManagedShutdown,
) {
    let mut connections = JoinSet::new();
    let mut process_stopped = shared.process.stopped();
    let expires = tokio::time::sleep(Duration::from_secs(
        shared.endpoint.expires_at.saturating_sub(now_ts()),
    ));
    tokio::pin!(expires);
    loop {
        tokio::select! {
            biased;
            () = shared.closed.triggered() => break,
            () = host_stop.triggered() => break,
            () = &mut expires => break,
            () = &mut process_stopped => break,
            result = listener.accept() => {
                let Ok((socket, _)) = result else { break; };
                connections.spawn(http::serve_connection(socket, Arc::clone(&shared)));
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    shared.close();
    drop(listener);
    connections.abort_all();
}
