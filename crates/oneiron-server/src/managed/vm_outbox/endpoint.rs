//! The companion's local lifecycle endpoint, `/run/oneiron-outbox/
//! lifecycle.sock`: a root-owned socket only root and the vault's UID can
//! reach (root:UID 0660 in a root:UID 0750 directory, and the peer's UID
//! checked), for exactly four requests from the engine. `status` reports the
//! carrier's wire revision once its storage is laid out and its carrier runs;
//! `park` and `resume` bracket an idle report, so no commit is in flight when
//! the host snapshots the VM; `register_backup` names the engine's actual
//! backup plan, its directory and label.
//!
//! None of them is a root operation on the engine's say-so. A registered
//! directory is taken only inside the vault's encrypted storage, reached part
//! by part without following a link, owned by the vault's UID, with its
//! label's handoff policy installed; the companion then writes there only the
//! host's stage acks, as that UID's 0600 files.

use super::Gate;
use super::local::{open_dir_at, open_dir_path};
use oneiron_vault_contract::backup_handoff::{
    BACKUP_HANDOFF_DIR, BACKUP_HANDOFF_POLICY_FILE, BACKUP_HANDOFF_SCHEMA_VERSION,
    BackupHandoffPolicy, backup_handoff_dir,
};
use oneiron_vault_contract::vm::VM_GUEST_STORAGE_DIR;
use oneiron_vault_contract::vm_outbox::VM_OUTBOX_WIRE_REVISION;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use std::fs::{File, Permissions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, fchown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

const ENDPOINT_PARENT: &str = "/run";
const ENDPOINT_DIR: &str = "oneiron-outbox";
const ENDPOINT_LEAF: &str = "lifecycle.sock";
const ENDPOINT: &str = "/run/oneiron-outbox/lifecycle.sock";
/// One request or reply line: the bound of this local codec only.
const MAX_LINE: u64 = 4096;
/// The longest handoff policy file read back.
const MAX_POLICY_BYTES: u64 = 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Status,
    Park,
    Resume,
    RegisterBackup { dir: PathBuf, label: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
enum Reply {
    Status { revision: u32 },
    Parked,
    Resumed,
    Registered,
    Refused { detail: String },
}

/// The engine's registered backup plan: its directory, held, and label.
pub(super) struct BackupPlanRoot {
    pub(super) dir: File,
    pub(super) label: String,
}

/// The plan the engine registered this boot, if it did.
pub(super) type Registry = Arc<Mutex<Option<BackupPlanRoot>>>;

/// Binds the endpoint for `uid`: its directory root:UID 0750, its socket
/// root:UID 0660, a stale one replaced.
pub(super) fn bind(uid: u32) -> std::io::Result<UnixListener> {
    let run = open_dir_path(Path::new(ENDPOINT_PARENT))?;
    match rustix::fs::mkdirat(&run, ENDPOINT_DIR, Mode::from_raw_mode(0o750)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let dir = open_dir_at(&run, ENDPOINT_DIR)?;
    fchown(&dir, Some(0), Some(uid))?;
    dir.set_permissions(Permissions::from_mode(0o750))?;
    match rustix::fs::unlinkat(&dir, ENDPOINT_LEAF, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(ENDPOINT)?;
    std::os::unix::fs::chown(ENDPOINT, Some(0), Some(uid))?;
    std::fs::set_permissions(ENDPOINT, Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Answers the endpoint on its own thread for the life of the companion.
pub(super) fn serve(
    listener: UnixListener,
    uid: u32,
    gate: Arc<Gate>,
    registry: Registry,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("vm-outbox-endpoint".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let answered = stream.and_then(|stream| answer(stream, uid, &gate, &registry));
                if let Err(error) = answered {
                    tracing::warn!(
                        reason = "vm_outbox_endpoint_failed",
                        %error,
                        "an outbox companion lifecycle request went unanswered"
                    );
                }
            }
        })?;
    Ok(())
}

fn answer(stream: UnixStream, uid: u32, gate: &Gate, registry: &Registry) -> std::io::Result<()> {
    let peer = peer_uid(&stream)?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(MAX_LINE)
        .read_line(&mut line)?;
    let reply = if peer != 0 && peer != uid {
        Reply::Refused {
            detail: "only the vault's engine reaches its outbox companion".into(),
        }
    } else {
        match serde_json::from_str::<Request>(line.trim_end()) {
            Ok(Request::Status) => Reply::Status {
                revision: VM_OUTBOX_WIRE_REVISION,
            },
            Ok(Request::Park) => {
                gate.park();
                Reply::Parked
            }
            Ok(Request::Resume) => {
                gate.resume();
                Reply::Resumed
            }
            Ok(Request::RegisterBackup { dir, label }) => match register(&dir, &label, uid) {
                Ok(plan) => {
                    *registry.lock().unwrap_or_else(PoisonError::into_inner) = Some(plan);
                    Reply::Registered
                }
                Err(detail) => Reply::Refused { detail },
            },
            Err(_) => Reply::Refused {
                detail: "not a lifecycle request".into(),
            },
        }
    };
    let mut reply = serde_json::to_string(&reply).map_err(std::io::Error::other)?;
    reply.push('\n');
    (&stream).write_all(reply.as_bytes())
}

/// The peer's UID, as the kernel took it at connect.
fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `len` are valid for writes of the stated
    // size, and the descriptor is a connected socket `stream` owns.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

/// The backup plan at `dir` with `label`, held, when it is one the companion
/// may write stage acks into.
fn register(dir: &Path, label: &str, uid: u32) -> Result<BackupPlanRoot, String> {
    let refused = |what: &str| format!("the backup directory {}: {what}", dir.display());
    if backup_handoff_dir(dir, label).is_none() {
        return Err("a backup label is one plain path part".into());
    }
    let inside = dir
        .strip_prefix(VM_GUEST_STORAGE_DIR)
        .map_err(|_| refused("is not in the vault's encrypted storage"))?;
    let mut held =
        open_dir_path(Path::new(VM_GUEST_STORAGE_DIR)).map_err(|e| refused(&e.to_string()))?;
    let mut depth = 0usize;
    for component in inside.components() {
        let Component::Normal(part) = component else {
            return Err(refused("is not a plain path"));
        };
        let part = part.to_str().ok_or_else(|| refused("is not UTF-8"))?;
        held = open_dir_at(&held, part).map_err(|e| refused(&e.to_string()))?;
        depth += 1;
    }
    if depth == 0 {
        return Err(refused("is the storage itself"));
    }
    let owned = |dir: &File| {
        dir.metadata()
            .is_ok_and(|metadata| metadata.uid() == uid && metadata.mode() & 0o077 == 0)
    };
    if !owned(&held) {
        return Err(refused("is not the vault UID's alone"));
    }
    let handoff = open_dir_at(&held, BACKUP_HANDOFF_DIR)
        .and_then(|handoff| open_dir_at(&handoff, label))
        .map_err(|_| refused("has no handoff directory for the label"))?;
    if !owned(&handoff) {
        return Err(refused(
            "has a handoff directory that is not the vault UID's alone",
        ));
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let policy = rustix::fs::openat(&handoff, BACKUP_HANDOFF_POLICY_FILE, flags, Mode::empty())
        .map_err(|_| refused("has no handoff policy for the label"))?;
    let mut bytes = Vec::new();
    File::from(policy)
        .take(MAX_POLICY_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| refused(&e.to_string()))?;
    let pinned = serde_json::from_slice::<BackupHandoffPolicy>(&bytes).is_ok_and(|policy| {
        policy.schema_version == BACKUP_HANDOFF_SCHEMA_VERSION && policy.label == label
    });
    if !pinned {
        return Err(refused("has a handoff policy for another label"));
    }
    Ok(BackupPlanRoot {
        dir: held,
        label: label.to_owned(),
    })
}

/// One request to the companion, from the engine.
fn call(request: &Request) -> std::io::Result<Reply> {
    let mut stream = UnixStream::connect(ENDPOINT)?;
    let mut line = serde_json::to_string(request).map_err(std::io::Error::other)?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let mut reply = String::new();
    BufReader::new(stream)
        .take(MAX_LINE)
        .read_line(&mut reply)?;
    serde_json::from_str(reply.trim_end()).map_err(std::io::Error::other)
}

/// The carrier's revision the companion reports, or `None` when no companion
/// answers: an image without one, or one that did not come up.
pub(in crate::managed) fn companion_revision() -> Option<u32> {
    match call(&Request::Status) {
        Ok(Reply::Status { revision }) => Some(revision),
        _ => None,
    }
}

/// Tells the companion the engine's backup plan: its directory and label.
pub(in crate::managed) fn register_backup(dir: &Path, label: &str) -> anyhow::Result<()> {
    match call(&Request::RegisterBackup {
        dir: dir.to_path_buf(),
        label: label.to_owned(),
    })? {
        Reply::Registered => Ok(()),
        Reply::Refused { detail } => anyhow::bail!("the outbox companion refused: {detail}"),
        _ => anyhow::bail!("the outbox companion answered another request"),
    }
}

/// Parks the companion before the engine reports idle: it finishes a local
/// commit in flight and starts none until [`resume_companion`].
pub(in crate::managed) async fn park_companion() {
    lifecycle(Request::Park).await;
}

/// Opens the companion again once the host resumed the vault.
pub(in crate::managed) async fn resume_companion() {
    lifecycle(Request::Resume).await;
}

async fn lifecycle(request: Request) {
    let answered = tokio::task::spawn_blocking(move || call(&request))
        .await
        .map_err(std::io::Error::other)
        .and_then(|reply| reply);
    if let Err(error) = answered {
        tracing::warn!(
            reason = "vm_outbox_companion_unreachable",
            %error,
            "the vault VM's outbox companion did not answer; its carrier keeps its work"
        );
    }
}
