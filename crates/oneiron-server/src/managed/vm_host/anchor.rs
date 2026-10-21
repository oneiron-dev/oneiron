//! The host's half of a vault VM's custody anchor channels (FIX 6517,
//! [`oneiron_vault_contract::vm_anchor`]).
//!
//! The supervisor names the anchor URL the vault's effective settings bind,
//! a restore's plan included, exactly as they spell it (never logged), and
//! may hand the door's owner credential on a pipe of its own, which needs
//! that URL ([`VmAnchorHostIo`]). On every cold boot that serves, once the
//! guest is provisioned, the host answers the guest's exchange with the
//! header. After the engine's credential frame it sends the credential: read
//! from its pipe at the first such boot and held in memory, wiped on drop,
//! for every later one. It waits for the guest's reply before the ready
//! byte. The credential is never in the profile, the boot arguments, a
//! drive, the outbox or a log; a RAM snapshot holds the guest's copy as it
//! holds the data key, and a resume runs no second exchange.
//!
//! The proxy runs with each VMM generation, and its exit, a stop, a kill or
//! the driver's drop ends it with every stream it carries. Each guest stream
//! names the bound URL by its digest; the host dials that URL's host and
//! port, its one destination, and carries bytes until either side ends. It
//! adds no credential and reads nothing that passes. A host bound to no URL
//! refuses every stream.

use super::restore::{distinct, proven};
use super::{API_TIMEOUT, VaultVm, VmExitWatch};
use crate::managed::listener::bind_unix_socket;
use oneiron_vault_contract::vm::{VM_ANCHOR_PORT, VM_ANCHOR_PROXY_PORT, guest_initiated_socket};
use oneiron_vault_contract::vm_anchor::{
    MAX_VM_ANCHOR_CREDENTIAL_BYTES, MAX_VM_ANCHOR_PROXY_RECORD_BYTES, MAX_VM_ANCHOR_RECORD_BYTES,
    VM_ANCHOR_PROXY_REVISION, VM_ANCHOR_WIRE_REVISION, VmAnchorHeader, VmAnchorProxyHello,
    VmAnchorProxyRefusal, VmAnchorProxyReply, VmAnchorReply, anchor_identity_digest,
    decode_vm_anchor_record, encode_vm_anchor_record, vm_anchor_payload_prefix,
    vm_anchor_record_len,
};
use serde::de::DeserializeOwned;
use std::io::Read as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use zeroize::Zeroizing;

/// A failed proxy accept is retried after this pause rather than in a hot
/// loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// What a vault VM's custody anchor takes from its supervisor (FIX 6517):
/// the anchor URL, byte for byte as the vault's effective settings name it,
/// and the read end of a pipe carrying the door's owner credential, the one
/// object and EOF a node's engine reads on `--custody-anchor-credentials-fd`.
/// A credential needs its URL. Without either the guest's anchor stays where
/// its settings leave it: unset, or pending.
pub struct VmAnchorHostIo {
    pub url: Option<String>,
    pub credentials: Option<OwnedFd>,
}

impl VmAnchorHostIo {
    /// `host vm`'s anchor inputs: `fd` taken over, once, before any
    /// descriptor is read, and refused when it names one of `taken`, when it
    /// is not a pipe's read end, or when no `url` came with it.
    pub(super) fn adopt(
        url: Option<String>,
        fd: Option<RawFd>,
        taken: &[(&str, RawFd)],
    ) -> anyhow::Result<Self> {
        let Some(fd) = fd else {
            return Ok(Self {
                url,
                credentials: None,
            });
        };
        anyhow::ensure!(
            url.is_some(),
            "--custody-anchor-credentials-fd needs --custody-anchor-url, the URL its credential is for"
        );
        let mut fds = taken.to_vec();
        fds.push(("--custody-anchor-credentials-fd", fd));
        distinct(&fds)?;
        proven("--custody-anchor-credentials-fd", fd, false)?;
        // SAFETY: `fd` arrives on argv from the supervisor and is this
        // process's to own; nothing else takes it over, and it is read once,
        // after the first credential frame went to the guest.
        let credentials = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            url,
            credentials: Some(credentials),
        })
    }
}

/// A vault VM's two anchor sockets, bound before any VMM runs, and what the
/// supervisor bound them to.
pub(super) struct HostAnchor {
    exchange: UnixListener,
    proxy: Arc<UnixListener>,
    bound: Option<Arc<BoundUrl>>,
    credential: Credential,
    /// The running generation's proxy.
    serving: Option<Serving>,
}

/// The anchor URL boots are bound to: as configured, its digest, and the
/// host and port it names, the proxy's one destination.
struct BoundUrl {
    url: String,
    digest: String,
    host: String,
    port: u16,
}

/// The door's owner credential: its pipe until the first delivery reads it,
/// then its bytes.
enum Credential {
    None,
    Unread(OwnedFd),
    Held(Zeroizing<Vec<u8>>),
}

/// One generation's proxy task, ended when this drops.
struct Serving(tokio::task::AbortHandle);

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl HostAnchor {
    /// Binds the exchange's and the proxy's host sockets beside `vsock`, the
    /// VM's device socket.
    pub(super) fn bind(vsock: &Path) -> anyhow::Result<Self> {
        let exchange = bind_unix_socket(&guest_initiated_socket(vsock, VM_ANCHOR_PORT))?;
        let proxy = bind_unix_socket(&guest_initiated_socket(vsock, VM_ANCHOR_PROXY_PORT))?;
        Ok(Self {
            exchange,
            proxy: Arc::new(proxy),
            bound: None,
            credential: Credential::None,
            serving: None,
        })
    }

    /// Ends the running generation's proxy and every stream it carries.
    pub(super) fn end_proxy(&mut self) {
        self.serving = None;
    }
}

impl BoundUrl {
    /// `url`, refused unless it is an http or https URL with a host. A
    /// refusal never names it.
    fn parse(url: String) -> anyhow::Result<Self> {
        let parsed = reqwest::Url::parse(&url)
            .ok()
            .filter(|parsed| matches!(parsed.scheme(), "http" | "https"));
        let origin = parsed.as_ref().and_then(|parsed| {
            // An IPv6 literal keeps its brackets in the URL, not in an address.
            let host = parsed
                .host_str()?
                .trim_start_matches('[')
                .trim_end_matches(']');
            Some((host.to_owned(), parsed.port_or_known_default()?))
        });
        let Some((host, port)) = origin.filter(|(host, _)| !host.is_empty()) else {
            anyhow::bail!("--custody-anchor-url is not an http or https URL with a host");
        };
        Ok(Self {
            digest: anchor_identity_digest(&url),
            url,
            host,
            port,
        })
    }
}

impl VaultVm {
    /// Binds the vault's custody anchor to `io` for every cold boot from here
    /// on (FIX 6517): the URL the guest's header names and its proxy reaches,
    /// and the credential sent after each boot's credential frame. A VM bound
    /// to neither sends a header with neither. Refused while a VMM runs.
    pub fn attach_anchor(&mut self, io: VmAnchorHostIo) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.is_running(),
            "the vault VM is running; bind its custody anchor before it starts"
        );
        anyhow::ensure!(
            io.url.is_some() || io.credentials.is_none(),
            "a custody anchor credential needs the anchor URL it is for"
        );
        if let Some(credentials) = &io.credentials {
            proven(
                "the custody anchor credential",
                credentials.as_raw_fd(),
                false,
            )?;
        }
        self.anchor.bound = io.url.map(BoundUrl::parse).transpose()?.map(Arc::new);
        self.anchor.credential = io.credentials.map_or(Credential::None, Credential::Unread);
        Ok(())
    }

    /// The anchor exchange's header, a serving cold boot's step once the
    /// guest is provisioned and before its engine starts: the bound URL, and
    /// whether a credential follows. It starts this generation's proxy, and
    /// returns the connection for the credential's delivery. The accept is
    /// within the boot `timeout`.
    pub(super) async fn send_anchor_header(
        &mut self,
        timeout: Duration,
    ) -> anyhow::Result<UnixStream> {
        let (mut stream, _) =
            tokio::time::timeout(timeout, self.anchor.exchange.accept()).await??;
        let header = VmAnchorHeader {
            revision: VM_ANCHOR_WIRE_REVISION,
            vault: self.vault.clone(),
            anchor_url: self.anchor.bound.as_ref().map(|bound| bound.url.clone()),
            has_credentials: !matches!(self.anchor.credential, Credential::None),
        };
        stream
            .write_all(&encode_vm_anchor_record(
                &header,
                MAX_VM_ANCHOR_RECORD_BYTES,
            )?)
            .await?;
        self.serve_anchor_proxy();
        Ok(stream)
    }

    /// The credential, after the engine's credential frame went: its length
    /// and its bytes, or a length of zero when there is none, a half-close,
    /// then the guest's reply, which must say the bytes crossed for this
    /// vault and URL. The first delivery reads the credential's pipe. The
    /// reply's wait is within the boot `timeout`.
    pub(super) async fn deliver_anchor(
        &mut self,
        mut stream: UnixStream,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let credential = std::mem::replace(&mut self.anchor.credential, Credential::None);
        self.anchor.credential = match credential {
            Credential::Unread(fd) => {
                let read = tokio::task::spawn_blocking(move || read_credential(fd));
                Credential::Held(read.await??)
            }
            other => other,
        };
        let bytes: &[u8] = match &self.anchor.credential {
            Credential::Held(bytes) => bytes.as_slice(),
            Credential::None | Credential::Unread(_) => &[],
        };
        stream
            .write_all(&vm_anchor_payload_prefix(bytes.len())?)
            .await?;
        stream.write_all(bytes).await?;
        stream.shutdown().await?;
        let reply = tokio::time::timeout(
            timeout,
            read_record::<VmAnchorReply>(&mut stream, MAX_VM_ANCHOR_RECORD_BYTES),
        )
        .await??;
        let digest = self
            .anchor
            .bound
            .as_ref()
            .map(|bound| bound.digest.as_str());
        match reply {
            VmAnchorReply::Accepted {
                revision,
                vault,
                anchor_identity_digest: answered,
            } if revision == VM_ANCHOR_WIRE_REVISION
                && vault == self.vault
                && answered.as_deref() == digest =>
            {
                Ok(())
            }
            VmAnchorReply::Accepted { .. } => {
                anyhow::bail!("vault VM took its custody anchor for another vault or URL")
            }
            VmAnchorReply::Refused { code } => {
                anyhow::bail!("vault VM refused its custody anchor exchange ({code:?})")
            }
        }
    }

    /// Starts the running generation's proxy, ending any before it: it
    /// serves until this generation's VMM exits or the driver ends it.
    pub(super) fn serve_anchor_proxy(&mut self) {
        let task = tokio::spawn(proxy(
            Arc::clone(&self.anchor.proxy),
            self.vault.clone(),
            self.anchor.bound.clone(),
            self.exit.clone(),
        ));
        self.anchor.serving = Some(Serving(task.abort_handle()));
    }
}

/// Reads the credential's pipe to its end into a buffer wiped on drop, sized
/// once to the exchange's bound so it never moves: a credential over it is
/// refused, since the exchange cannot carry it.
fn read_credential(fd: OwnedFd) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut pipe = std::fs::File::from(fd);
    let mut held = Zeroizing::new(vec![0u8; MAX_VM_ANCHOR_CREDENTIAL_BYTES + 1]);
    let mut len = 0;
    loop {
        match pipe.read(&mut held[len..]) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => anyhow::bail!("the custody anchor credential's pipe did not read"),
        }
        anyhow::ensure!(
            len <= MAX_VM_ANCHOR_CREDENTIAL_BYTES,
            "the custody anchor credential is over the VM exchange's {MAX_VM_ANCHOR_CREDENTIAL_BYTES} bytes"
        );
    }
    held.truncate(len);
    Ok(held)
}

/// One record from a stream.
async fn read_record<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    cap: usize,
) -> anyhow::Result<T> {
    let mut prefix = [0u8; 4];
    stream.read_exact(&mut prefix).await?;
    let mut body = vec![0u8; vm_anchor_record_len(prefix, cap)?];
    stream.read_exact(&mut body).await?;
    decode_vm_anchor_record(&body)
}

/// One generation's proxy: each guest stream admitted and carried, until
/// `exit` sees the VMM end. Streams in flight end with it.
async fn proxy(
    listener: Arc<UnixListener>,
    vault: String,
    bound: Option<Arc<BoundUrl>>,
    exit: Option<VmExitWatch>,
) {
    let exited = async move {
        match exit {
            Some(exit) => {
                let _ = exit.wait().await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(exited);
    let mut streams = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            () = &mut exited => return,
            accepted = listener.accept() => match accepted {
                Ok((guest, _)) => {
                    streams.spawn(carry(guest, vault.clone(), bound.clone()));
                }
                Err(error) => {
                    tracing::warn!(%error, "vault VM anchor proxy accept failed");
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                }
            },
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
}

/// One guest stream: its hello checked against the boot's binding, the bound
/// URL's host and port dialled, the answer, then the bytes both ways until
/// either side ends.
async fn carry(mut guest: UnixStream, vault: String, bound: Option<Arc<BoundUrl>>) {
    let (reply, origin) = match admit(&mut guest, &vault, bound.as_deref()).await {
        Ok(origin) => (
            VmAnchorProxyReply::Accepted {
                revision: VM_ANCHOR_PROXY_REVISION,
            },
            Some(origin),
        ),
        Err(code) => (VmAnchorProxyReply::Refused { code }, None),
    };
    let Ok(reply) = encode_vm_anchor_record(&reply, MAX_VM_ANCHOR_PROXY_RECORD_BYTES) else {
        return;
    };
    if guest.write_all(&reply).await.is_err() {
        return;
    }
    if let Some(mut origin) = origin {
        let _ = tokio::io::copy_bidirectional(&mut guest, &mut origin).await;
    }
}

/// The bound origin's connection for a guest stream whose hello names this
/// vault and the bound URL, on the proxy's revision.
async fn admit(
    guest: &mut UnixStream,
    vault: &str,
    bound: Option<&BoundUrl>,
) -> Result<TcpStream, VmAnchorProxyRefusal> {
    let hello = tokio::time::timeout(
        API_TIMEOUT,
        read_record::<VmAnchorProxyHello>(guest, MAX_VM_ANCHOR_PROXY_RECORD_BYTES),
    )
    .await;
    let Ok(Ok(hello)) = hello else {
        return Err(VmAnchorProxyRefusal::HelloInvalid);
    };
    if hello.revision != VM_ANCHOR_PROXY_REVISION {
        return Err(VmAnchorProxyRefusal::RevisionUnsupported);
    }
    if hello.vault != vault {
        return Err(VmAnchorProxyRefusal::VaultMismatch);
    }
    let Some(bound) = bound else {
        return Err(VmAnchorProxyRefusal::NoAnchor);
    };
    if hello.anchor_identity_digest != bound.digest {
        return Err(VmAnchorProxyRefusal::IdentityMismatch);
    }
    let dialled = TcpStream::connect((bound.host.as_str(), bound.port));
    match tokio::time::timeout(API_TIMEOUT, dialled).await {
        Ok(Ok(origin)) => Ok(origin),
        _ => {
            tracing::warn!(
                reason = "vm_anchor_unreachable",
                vault = %vault,
                "the vault VM's custody anchor door is out of the host's reach"
            );
            Err(VmAnchorProxyRefusal::Unreachable)
        }
    }
}
