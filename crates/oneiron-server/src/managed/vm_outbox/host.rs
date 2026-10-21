//! The host's end of a vault VM's outbox carrier: an attachment bound to
//! one VM's guest-initiated socket for port 1030 before its VMM starts, and
//! the roots it maps each kind onto, the host's existing outbox trees. The
//! node's own shippers keep reading those trees, VM running or not; the
//! attachment is not a second shipper. The same attachment serves the
//! standalone `oneiron-server host vm` and any supervisor's VM launcher; only
//! the roots differ.
//!
//! Its stop and destroy part is [`VmOutboxAttachment::drain`]: new transfers
//! are denied and the commit in flight finishes. Proving the host copies
//! gone (the vault disk, these roots' copies, the carrier records) is the
//! supervisor's destroy journal's, not this.
//!
//! The backup label the guest names as its engine's registered one is kept
//! in the carrier's records, for the vault the attachment is bound to, and
//! [`read_vm_backup_label`] reads it (FIX 7046). It proves the label the
//! expected VM's carrier reported, not a signed fact of the backups: a node
//! still checks each held artifact's commitment against its own pins. Until
//! a session keeps the label its guest names, that session's backup sets
//! wait, deferred, and its other kinds go on (FIX 7127).

use super::local::{Owner, make_dir_at, open_dir_path};
use super::store::{self, BackupLabelBinding, Store};
use super::transfer::Link;
use super::{Carrier, Gate, Mode, Roots};
use crate::managed::listener::bind_unix_socket;
use oneiron_vault_contract::backup_handoff::{BACKUP_HANDOFF_DIR, backup_handoff_dir};
use oneiron_vault_contract::vm_outbox::{
    VmOutboxDeferral, VmOutboxKind, VmOutboxOutcome, VmOutboxSide,
};
use serde::Deserialize;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// A failed accept is retried after this pause rather than in a hot loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// What a backup label binding's wait is said under: its record's name,
/// which no backup member's can be.
const BINDING_SAID: &str = "backup-label.json";

/// Where the host keeps one VM's outbox, kind by kind: the trees its own
/// shippers already read, and the carrier's records. A kind left out is one
/// this host carries nothing of; the guest keeps that kind's work, deferred.
/// No key, credential or secret is named here.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmOutboxHostRoots {
    /// The carrier's records for this VM: owner-only, outside every outbox.
    pub store: PathBuf,
    /// The vault's escrow outbox; hosted custody rides its `custody/`.
    #[serde(default)]
    pub escrow_outbox: Option<PathBuf>,
    /// The vault's e-sign delivery outbox.
    #[serde(default)]
    pub esign_outbox: Option<PathBuf>,
    /// The vault's publisher training outbox, its intake key pair included.
    #[serde(default)]
    pub training_outbox: Option<PathBuf>,
    /// Where the node stages the vault's escrow recipients' public keys
    /// (`managed.pub`, `break-glass.pub`).
    #[serde(default)]
    pub recipients: Option<PathBuf>,
    /// The host's copy of the vault's backup directory: its sealed backups
    /// as the guest names them, and the node's stage acks under
    /// `.backup-handoff/<label>/`, which the node's backup stage reads and
    /// writes as it does a process vault's.
    #[serde(default)]
    pub backups: Option<PathBuf>,
}

struct HostRoots(VmOutboxHostRoots);

impl Roots for HostRoots {
    fn open(&self, kind: VmOutboxKind) -> std::io::Result<Option<File>> {
        let roots = &self.0;
        let (path, child) = match kind {
            VmOutboxKind::Escrow => (roots.escrow_outbox.as_deref(), None),
            VmOutboxKind::Custody => (roots.escrow_outbox.as_deref(), Some("custody")),
            VmOutboxKind::Esign => (roots.esign_outbox.as_deref(), None),
            VmOutboxKind::Training => (roots.training_outbox.as_deref(), None),
            VmOutboxKind::Recipients => (roots.recipients.as_deref(), None),
            VmOutboxKind::Backup => (roots.backups.as_deref(), None),
            VmOutboxKind::BackupStageAck => (roots.backups.as_deref(), Some(BACKUP_HANDOFF_DIR)),
        };
        let Some(path) = path else {
            return Ok(None);
        };
        let dir = match open_dir_path(path) {
            Ok(dir) => dir,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        match child {
            Some(child) => make_dir_at(&dir, child, Owner::Host).map(Some),
            None => Ok(Some(dir)),
        }
    }

    fn takes(&self, _kind: VmOutboxKind, _member: &str) -> bool {
        true
    }
}

/// The host's end of one VM's outbox carrier.
pub struct VmOutboxAttachment {
    gate: Arc<Gate>,
}

impl VmOutboxAttachment {
    /// Binds `socket`, the VM's guest-initiated socket for the carrier port,
    /// and serves the VM bound to `vault` on its own thread, one connection
    /// at a time, with `roots`. Bind it before the VMM starts, so the guest
    /// never dials an unbound port.
    pub fn bind(socket: &Path, vault: String, roots: VmOutboxHostRoots) -> anyhow::Result<Self> {
        let listener = bind_unix_socket(socket)?.into_std()?;
        listener.set_nonblocking(false)?;
        std::fs::create_dir_all(&roots.store)?;
        std::fs::set_permissions(&roots.store, std::fs::Permissions::from_mode(0o700))?;
        let store = Store::open(open_dir_path(&roots.store)?)?;
        let gate = Arc::new(Gate::default());
        let mut carrier = Carrier::new(
            VmOutboxSide::Host,
            Owner::Host,
            Box::new(HostRoots(roots)),
            store,
            Arc::clone(&gate),
        );
        std::thread::Builder::new()
            .name("vm-outbox-host".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    let served = stream.map_err(anyhow::Error::from).and_then(|stream| {
                        let mut link = Link::new(stream.try_clone()?, stream);
                        carrier.host_session(&mut link, &vault)
                    });
                    if let Err(error) = served {
                        tracing::warn!(
                            reason = "vm_outbox_session_ended",
                            vault = %vault,
                            error = %format!("{error:#}"),
                            "a vault VM's outbox carrier session ended; both ends keep their work"
                        );
                        std::thread::sleep(ACCEPT_BACKOFF);
                    }
                }
            })?;
        Ok(Self { gate })
    }

    /// Parks the attachment before the VM is snapshotted: the commit in
    /// flight finishes and nothing new is published until [`Self::resume`].
    pub fn park(&self) {
        self.gate.park();
    }

    /// Opens the attachment again when the VM starts or resumes.
    pub fn resume(&self) {
        self.gate.resume();
    }

    /// The stop and destroy step: denies new transfers and lets the commit
    /// in flight finish.
    pub fn drain(&self) {
        self.gate.drain();
    }
}

/// The backup label the VM bound to `vault` last reported its engine
/// registered, read from `roots`' carrier records alone: no VM is started or
/// asked, and no backup's name is read. `None` until a registration was
/// reported (no records yet included); an error for a record that does not
/// read, is not the store's own private file, names an invalid label, or
/// belongs to another vault.
pub fn read_vm_backup_label(
    roots: &VmOutboxHostRoots,
    vault: &str,
) -> anyhow::Result<Option<String>> {
    let dir = match open_dir_path(&roots.store) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(binding) = store::read_backup_label(&dir)? else {
        return Ok(None);
    };
    anyhow::ensure!(
        valid_backup_label(&binding.label),
        "the backup label record names an invalid label"
    );
    anyhow::ensure!(
        binding.vault == vault,
        "the backup label record belongs to another vault"
    );
    Ok(Some(binding.label))
}

/// Whether `label` is one the guest's endpoint registers: one plain path
/// part, as a handoff directory names it.
fn valid_backup_label(label: &str) -> bool {
    backup_handoff_dir(Path::new(""), label).is_some()
}

impl Carrier {
    /// Opens a session's wait for its backup label: the backup sets wait
    /// until the guest names one this session keeps, whatever an earlier
    /// session kept.
    pub(super) fn await_backup_label(&mut self) {
        self.backup_wait = Some(VmOutboxOutcome::deferred(
            VmOutboxDeferral::TargetUnavailable,
            "the guest's backup label registration",
            "the guest has not named a backup label this session kept",
        ));
    }

    /// Why `kind`'s sets wait in this session, when it is a backup kind and
    /// no label the guest named this session is kept: such a set is taken
    /// whole and answered with this, and none is sent. `None` on the guest,
    /// whose sets never wait on it.
    pub(super) fn backup_waits(&self, kind: VmOutboxKind) -> Option<&VmOutboxOutcome> {
        match kind {
            VmOutboxKind::Backup | VmOutboxKind::BackupStageAck => self.backup_wait.as_ref(),
            _ => None,
        }
    }

    /// Keeps `label`, which the guest named as its engine's registered
    /// backup label, for `vault`, the attachment's own, and ends the
    /// session's wait for one. A label the guest's endpoint would never
    /// register, or a record that cannot be written, keeps the backup sets
    /// waiting, said once, while the session goes on; the guest names it
    /// again on its next turn. A record kept for an earlier label is not
    /// this one's. A draining end records nothing new, so its sets wait too.
    pub(super) fn bind_backup_label(&mut self, vault: &str, label: String) {
        let waits = if valid_backup_label(&label) {
            let gate = Arc::clone(&self.gate);
            let held = gate.hold();
            let written = if *held == Mode::Draining {
                Some(VmOutboxOutcome::deferred(
                    VmOutboxDeferral::Draining,
                    "this end's stop",
                    "the carrier records nothing new while it stops",
                ))
            } else {
                self.store
                    .bind_backup_label(BackupLabelBinding {
                        vault: vault.to_owned(),
                        label,
                    })
                    .err()
                    .map(|error| binding_outcome(&error))
            };
            drop(held);
            written
        } else {
            Some(VmOutboxOutcome::deferred(
                VmOutboxDeferral::TargetUnavailable,
                "the guest's backup label",
                "the guest named a backup label that is not one plain path part",
            ))
        };
        match &waits {
            Some(VmOutboxOutcome::Deferred {
                code,
                bound,
                detail,
            }) => self.say(
                VmOutboxKind::Backup,
                BINDING_SAID,
                &format!("its backup label is not kept ({code:?}) on {bound}: {detail}"),
            ),
            _ => self.settled(VmOutboxKind::Backup, BINDING_SAID),
        }
        self.backup_wait = waits;
    }
}

/// A binding record that did not write, as a deferral naming its bound.
fn binding_outcome(error: &std::io::Error) -> VmOutboxOutcome {
    if matches!(error.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT)) {
        return VmOutboxOutcome::deferred(
            VmOutboxDeferral::Capacity,
            "free space on the host's carrier record filesystem",
            "the filesystem is full; the backup sets are kept",
        );
    }
    VmOutboxOutcome::deferred(
        VmOutboxDeferral::Io,
        "the host's backup label record",
        &error.to_string(),
    )
}
