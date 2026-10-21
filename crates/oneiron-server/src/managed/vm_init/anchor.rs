//! The bootstrap's half of a vault VM's custody anchor channels (FIX 6517,
//! [`oneiron_vault_contract::vm_anchor`]), on every cold boot that serves.
//!
//! Before the engine starts, the bootstrap dials the host's anchor exchange
//! and reads its header alone: the anchor URL the host bound, and whether a
//! credential follows. With a URL it binds the engine's socket to that URL,
//! [`VM_GUEST_ANCHOR_SOCKET`]; with a credential it makes an ordinary pipe,
//! whose read end the engine takes as `--custody-anchor-credentials-fd`, as
//! a node's child does. The engine is told the exchange's revision, the URL
//! and the socket. The credential comes only after the engine's credential
//! frame, so it is taken beside the engine: read whole into a buffer wiped
//! on drop, checked to be the one payload with nothing after it, and only
//! then written into the pipe and the pipe closed, the EOF the engine's
//! native reader waits for. A payload that breaks never reaches the engine
//! as an EOF: the bootstrap ends the engine first, and only then lets the
//! pipe go.
//!
//! Each stream on the socket dials the host's anchor proxy and names the
//! bound URL by its digest; once accepted it carries bytes both ways until
//! either side ends. It reaches nothing else, and the bootstrap reads none
//! of it.

use anyhow::Context as _;
use oneiron_vault_contract::host_adapters::connect_blocking;
use oneiron_vault_contract::vm::{VM_ANCHOR_PORT, VM_ANCHOR_PROXY_PORT, VM_HOST_CID};
use oneiron_vault_contract::vm_anchor::{
    MAX_VM_ANCHOR_PROXY_RECORD_BYTES, MAX_VM_ANCHOR_RECORD_BYTES, VM_ANCHOR_PROXY_REVISION,
    VM_ANCHOR_WIRE_REVISION, VM_GUEST_ANCHOR_SOCKET, VmAnchorHeader, VmAnchorProxyHello,
    VmAnchorProxyReply, VmAnchorRefusal, VmAnchorReply, anchor_identity_digest,
    encode_vm_anchor_record, read_vm_anchor_record, vm_anchor_payload_len,
};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::mpsc;
use zeroize::Zeroizing;

/// A serving boot's anchor, its header read, before the engine starts.
pub(super) struct Anchor {
    channel: File,
    vault: String,
    /// The bound URL, when the host bound one.
    url: Option<String>,
    /// The credential's pipe, when one follows: the engine's read end, then
    /// the bootstrap's write end.
    pipe: Option<(PipeReader, PipeWriter)>,
    bridge: Option<Bridge>,
}

/// The anchor beside a running engine. Its socket is shut when this drops.
pub(super) struct Anchored {
    _bridge: Option<Bridge>,
}

/// The engine's socket to the bound anchor URL.
struct Bridge(UnixListener);

/// Dials the exchange and reads the host's header for `vault`'s boot,
/// refused, and the host told why, unless this end takes it; then binds the
/// socket for the bound URL, `uid`'s alone, and makes the credential's pipe
/// when one follows.
pub(super) fn exchange(vault: &str, uid: u32) -> anyhow::Result<Anchor> {
    let mut channel = connect_blocking(VM_HOST_CID, VM_ANCHOR_PORT)
        .context("dialling the host's custody anchor exchange")?;
    let header = read_vm_anchor_record::<VmAnchorHeader>(&mut channel, MAX_VM_ANCHOR_RECORD_BYTES)
        .map_err(|_| VmAnchorRefusal::HeaderInvalid)
        .and_then(|header| header.check(vault).map(|()| header));
    let header = match header {
        Ok(header) => header,
        Err(code) => {
            answer(&mut channel, &VmAnchorReply::Refused { code });
            anyhow::bail!("the host's custody anchor header was refused ({code:?})");
        }
    };
    let bridge = match &header.anchor_url {
        Some(_) => Some(Bridge::bind(uid)?),
        None => None,
    };
    let pipe = if header.has_credentials {
        Some(std::io::pipe().context("making the custody anchor credential's pipe")?)
    } else {
        None
    };
    Ok(Anchor {
        channel,
        vault: vault.to_owned(),
        url: header.anchor_url,
        pipe,
        bridge,
    })
}

impl Anchor {
    /// The engine's flags for this anchor: the exchange's revision, the
    /// bound URL and its socket, and the credential pipe's read end.
    pub(super) fn flags(&self) -> Vec<OsString> {
        let mut flags: Vec<OsString> = vec![
            "--vm-anchor-revision".into(),
            VM_ANCHOR_WIRE_REVISION.to_string().into(),
        ];
        if let Some(url) = &self.url {
            let route = [
                "--vm-anchor-url",
                url.as_str(),
                "--vm-anchor-socket",
                VM_GUEST_ANCHOR_SOCKET,
            ];
            flags.extend(route.map(OsString::from));
        }
        if let Some((read, _)) = &self.pipe {
            let fd = read.as_raw_fd().to_string();
            flags.extend(["--custody-anchor-credentials-fd", fd.as_str()].map(OsString::from));
        }
        flags
    }

    /// The credential pipe's read end, as `oneiron_spawn::command_with_fds`
    /// places it.
    pub(super) fn fds(&self) -> Vec<(RawFd, RawFd)> {
        self.pipe
            .iter()
            .map(|(read, _)| (read.as_raw_fd(), read.as_raw_fd()))
            .collect()
    }

    /// Once the engine started: lets the bootstrap's copy of the engine's
    /// read end go, takes the payload beside the engine and serves the
    /// socket. A payload that breaks hands the open pipe to `lost`, for the
    /// bootstrap to end the engine before it lets the pipe go.
    pub(super) fn start(self, lost: mpsc::Sender<PipeWriter>) -> anyhow::Result<Anchored> {
        let Self {
            channel,
            vault,
            url,
            pipe,
            bridge,
        } = self;
        let pipe = pipe.map(|(read, write)| {
            drop(read);
            write
        });
        let digest = url.as_deref().map(anchor_identity_digest);
        if let (Some(bridge), Some(digest)) = (&bridge, &digest) {
            bridge.serve(vault.clone(), digest.clone())?;
        }
        std::thread::Builder::new()
            .name("vm-anchor-exchange".into())
            .spawn(move || receive(channel, &vault, digest, pipe, &lost))?;
        Ok(Anchored { _bridge: bridge })
    }
}

/// Takes the payload, answers the host, and writes the credential into the
/// engine's pipe and closes it; or, when the payload broke, answers why and
/// hands the open pipe to `lost`.
fn receive(
    mut channel: File,
    vault: &str,
    digest: Option<String>,
    pipe: Option<PipeWriter>,
    lost: &mpsc::Sender<PipeWriter>,
) {
    match read_payload(&mut channel, pipe.is_some()) {
        Ok(credential) => {
            let reply = VmAnchorReply::Accepted {
                revision: VM_ANCHOR_WIRE_REVISION,
                vault: vault.to_owned(),
                anchor_identity_digest: digest,
            };
            answer(&mut channel, &reply);
            if let Some(mut pipe) = pipe
                && pipe.write_all(&credential).is_err()
            {
                eprintln!("oneiron-vm-init: the engine took no custody anchor credential");
            }
        }
        Err(code) => {
            eprintln!("oneiron-vm-init: the custody anchor exchange broke ({code:?})");
            answer(&mut channel, &VmAnchorReply::Refused { code });
            if let Some(pipe) = pipe {
                eprintln!("oneiron-vm-init: ending the engine before its credential pipe ends");
                let _ = lost.send(pipe);
            }
        }
    }
}

/// The payload: its length, exactly that many bytes into a buffer wiped on
/// drop, then the host's end with no byte before it. A credential the header
/// did not announce is refused.
fn read_payload(
    channel: &mut File,
    announced: bool,
) -> Result<Zeroizing<Vec<u8>>, VmAnchorRefusal> {
    let broken = |_: std::io::Error| VmAnchorRefusal::PayloadInvalid;
    let mut prefix = [0u8; 4];
    channel.read_exact(&mut prefix).map_err(broken)?;
    let len = vm_anchor_payload_len(prefix)?;
    if len > 0 && !announced {
        return Err(VmAnchorRefusal::PayloadInvalid);
    }
    let mut credential = Zeroizing::new(vec![0u8; len]);
    channel.read_exact(&mut credential[..]).map_err(broken)?;
    let mut after = [0u8; 1];
    match channel.read(&mut after) {
        Ok(0) => Ok(credential),
        _ => Err(VmAnchorRefusal::PayloadInvalid),
    }
}

/// Sends `reply` on the exchange; a host that takes it no more is told on
/// the console.
fn answer(channel: &mut File, reply: &VmAnchorReply) {
    let sent = encode_vm_anchor_record(reply, MAX_VM_ANCHOR_RECORD_BYTES)
        .and_then(|bytes| channel.write_all(&bytes).map_err(Into::into));
    if sent.is_err() {
        eprintln!("oneiron-vm-init: answering the host's custody anchor exchange failed");
    }
}

impl Bridge {
    /// Binds [`VM_GUEST_ANCHOR_SOCKET`] in the engine's own run directory,
    /// for `uid` alone.
    fn bind(uid: u32) -> anyhow::Result<Self> {
        let path = Path::new(VM_GUEST_ANCHOR_SOCKET);
        let listener = UnixListener::bind(path).context("binding the custody anchor socket")?;
        std::os::unix::fs::chown(path, Some(uid), Some(uid))
            .and_then(|()| std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)))
            .context("giving the custody anchor socket to the vault's UID")?;
        Ok(Self(listener))
    }

    /// Carries each stream on the socket on a thread of its own, until the
    /// listener is shut.
    fn serve(&self, vault: String, digest: String) -> anyhow::Result<()> {
        let listener = self.0.try_clone()?;
        std::thread::Builder::new()
            .name("vm-anchor-bridge".into())
            .spawn(move || accept(&listener, &vault, &digest))?;
        Ok(())
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        // SAFETY: shutdown takes no pointers, on a socket this holds; it
        // wakes the bridge's accept, which then ends.
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR) };
        let _ = std::fs::remove_file(VM_GUEST_ANCHOR_SOCKET);
    }
}

fn accept(listener: &UnixListener, vault: &str, digest: &str) {
    loop {
        match listener.accept() {
            Ok((engine, _)) => {
                let (vault, digest) = (vault.to_owned(), digest.to_owned());
                let started = std::thread::Builder::new()
                    .name("vm-anchor-stream".into())
                    .spawn(move || {
                        if let Err(error) = carry(engine, &vault, digest) {
                            eprintln!("oneiron-vm-init: a custody anchor stream ended: {error:#}");
                        }
                    });
                if started.is_err() {
                    eprintln!("oneiron-vm-init: a custody anchor stream found no thread");
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::Interrupted | ErrorKind::ConnectionAborted
                ) => {}
            Err(_) => return,
        }
    }
}

/// One stream from the engine: dials the host's proxy, says the hello, and
/// once accepted carries the bytes both ways until either side ends.
fn carry(mut engine: UnixStream, vault: &str, digest: String) -> anyhow::Result<()> {
    let mut host = connect_blocking(VM_HOST_CID, VM_ANCHOR_PROXY_PORT)
        .context("dialling the host's custody anchor proxy")?;
    let hello = VmAnchorProxyHello {
        revision: VM_ANCHOR_PROXY_REVISION,
        vault: vault.to_owned(),
        anchor_identity_digest: digest,
    };
    host.write_all(&encode_vm_anchor_record(
        &hello,
        MAX_VM_ANCHOR_PROXY_RECORD_BYTES,
    )?)?;
    let reply: VmAnchorProxyReply =
        read_vm_anchor_record(&mut host, MAX_VM_ANCHOR_PROXY_RECORD_BYTES)?;
    match reply {
        VmAnchorProxyReply::Accepted { revision } if revision == VM_ANCHOR_PROXY_REVISION => {}
        VmAnchorProxyReply::Accepted { .. } => {
            anyhow::bail!("the host's custody anchor proxy speaks another revision")
        }
        VmAnchorProxyReply::Refused { code } => {
            anyhow::bail!("the host's custody anchor proxy refused the stream ({code:?})")
        }
    }
    let (mut from_engine, mut to_host) = (engine.try_clone()?, host.try_clone()?);
    let outbound = std::thread::Builder::new()
        .name("vm-anchor-out".into())
        .spawn(move || {
            let _ = std::io::copy(&mut from_engine, &mut to_host);
            // SAFETY: shutdown takes no pointers, on a socket `to_host` holds.
            unsafe { libc::shutdown(to_host.as_raw_fd(), libc::SHUT_WR) };
        })?;
    let _ = std::io::copy(&mut host, &mut engine);
    // The origin is done: the engine's side ends both ways, which ends the
    // other direction too.
    let _ = engine.shutdown(std::net::Shutdown::Both);
    let _ = outbound.join();
    Ok(())
}
