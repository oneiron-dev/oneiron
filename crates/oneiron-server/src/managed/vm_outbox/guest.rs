//! `oneiron-vm-outbox`: the vault VM's root outbox companion (FIX 5235,
//! FIX 5467). `oneiron-vm-init` starts it after provisioning, before the
//! engine, with the vault's name and the UID its binding names; nothing the
//! engine says chooses either.
//!
//! It lays out the outbox on the vault disk, outside the encrypted storage
//! as a node keeps its outboxes:
//!
//! ```text
//! /vault/outbox              root:UID 0750, never the UID's
//!   .carrier/                root 0700: the carrier's records, no secret
//!   escrow/ esign/           UID:UID 0700, the engine's outboxes
//!   training/                root:UID 0750, as a node lays it out:
//!     .lock                  UID:UID 0600, the engine's tick lock
//!     offers/ controls/ receipts/ scopes/   UID:UID 0700
//!     intake-recipient.v1 intake-receipt-key.v1   root:UID 0640
//!   recipients/              root:UID 0750: managed.pub, break-glass.pub
//!                            root:UID 0640
//! ```
//!
//! Then it binds its lifecycle endpoint (`endpoint`), says `ready` on its
//! standard output, and carries: it dials the host's carrier port and runs
//! sessions for as long as it lives, waiting one rescan period after a
//! session ends or a dial fails, and keeping its work across both. A
//! SIGTERM, which `oneiron-vm-init` sends once the engine exits, drains it:
//! a local commit in flight finishes, a network transfer parks (its sender
//! replays it on the next boot), and it exits. No deadline is added.

use super::endpoint::{self, Registry};
use super::local::{Owner, open_dir_at, open_dir_path};
use super::store::Store;
use super::transfer::Link;
use super::{Carrier, Gate, Roots};
use oneiron_vault_contract::backup_handoff::BACKUP_HANDOFF_DIR;
use oneiron_vault_contract::conversation_training::{
    CONTROLS_DIR, OFFERS_DIR, RECEIPTS_DIR, SCOPES_DIR,
};
use oneiron_vault_contract::host_adapters::connect_blocking;
use oneiron_vault_contract::valid_vault_name;
use oneiron_vault_contract::vm::{VM_HOST_CID, VM_OUTBOX_PORT};
use oneiron_vault_contract::vm_outbox::{VM_GUEST_OUTBOX_DIR, VmOutboxKind, VmOutboxSide};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use std::fs::{File, Permissions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{PermissionsExt, fchown};
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use tracing_subscriber::util::SubscriberInitExt as _;

const CARRIER: &str = ".carrier";
const ESCROW: &str = "escrow";
const CUSTODY: &str = "custody";
const ESIGN: &str = "esign";
const TRAINING: &str = "training";
const RECIPIENTS: &str = "recipients";
const TRAINING_LOCK: &str = ".lock";

/// `oneiron-vm-outbox`'s whole run: success once it drained, a failure when
/// it could not lay out or bind, which `oneiron-vm-init` reads as no carrier.
pub fn run_vm_outbox() -> ExitCode {
    let _ = crate::logging::subscriber(tracing_subscriber::EnvFilter::new("info"), std::io::stderr)
        .try_init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("oneiron-vm-outbox: {error:#}");
            ExitCode::FAILURE
        }
    }
}

/// What `oneiron-vm-init` passes: `--vault-name <name> --uid <uid>`.
fn parse(mut args: impl Iterator<Item = std::ffi::OsString>) -> anyhow::Result<(String, u32)> {
    let (mut vault, mut uid) = (None, None);
    while let Some(flag) = args.next() {
        let value = args.next().and_then(|value| value.into_string().ok());
        match flag.to_str() {
            Some("--vault-name") => vault = value,
            Some("--uid") => uid = value.and_then(|value| value.parse::<u32>().ok()),
            _ => anyhow::bail!("an argument oneiron-vm-outbox does not take"),
        }
    }
    match (vault, uid) {
        (Some(vault), Some(uid)) if valid_vault_name(&vault) && uid != 0 && uid != u32::MAX => {
            Ok((vault, uid))
        }
        _ => anyhow::bail!("no valid --vault-name or no non-root --uid"),
    }
}

fn run() -> anyhow::Result<()> {
    let (vault, uid) = parse(std::env::args_os().skip(1))?;
    // Blocked before any thread starts, so only the stop watch takes them.
    let stops = block_stop_signals()?;
    let outbox = lay_out(uid)?;
    let store = Store::open(open_dir_at(&outbox, CARRIER)?)?;
    let gate = Arc::new(Gate::default());
    let registry = Registry::default();
    endpoint::serve(
        endpoint::bind(uid)?,
        uid,
        Arc::clone(&gate),
        Arc::clone(&registry),
    )?;
    let connection: Arc<Mutex<Option<File>>> = Arc::default();
    watch_stop(stops, Arc::clone(&gate), Arc::clone(&connection))?;
    let mut stdout = std::io::stdout();
    stdout.write_all(b"ready\n")?;
    stdout.flush()?;
    let roots = GuestRoots { outbox, registry };
    let mut carrier = Carrier::new(
        VmOutboxSide::Guest,
        Owner::Guest { uid },
        Box::new(roots),
        store,
        gate,
    );
    carry(&mut carrier, &vault, &connection);
    Ok(())
}

/// Dials the host and runs sessions until the companion drains.
fn carry(carrier: &mut Carrier, vault: &str, connection: &Mutex<Option<File>>) {
    let mut said: Option<String> = None;
    loop {
        if !carrier.gate.proceed() {
            return;
        }
        let ended = connect_blocking(VM_HOST_CID, VM_OUTBOX_PORT)
            .map_err(anyhow::Error::from)
            .and_then(|stream| {
                let mut link = Link::new(stream.try_clone()?, stream.try_clone()?);
                *connection.lock().unwrap_or_else(PoisonError::into_inner) = Some(stream);
                let ended = carrier.guest_session(&mut link, vault);
                *connection.lock().unwrap_or_else(PoisonError::into_inner) = None;
                ended
            });
        match ended {
            Ok(()) => said = None,
            Err(error) => {
                let what = format!("{error:#}");
                if said.as_deref() != Some(what.as_str()) {
                    tracing::warn!(
                        reason = "vm_outbox_relay_unavailable",
                        bound = "the host's outbox carrier port (vsock 1030)",
                        error = %what,
                        "the vault VM's outbox carrier cannot reach its host; the work is kept and \
                         the carrier dials again"
                    );
                    said = Some(what);
                }
            }
        }
        if !carrier.gate.idle() {
            return;
        }
    }
}

/// SIGTERM and SIGINT, blocked in this thread and every thread it starts.
fn block_stop_signals() -> std::io::Result<libc::sigset_t> {
    // SAFETY: an all-zero sigset_t is valid storage, and sigemptyset fills
    // it before any other use.
    let mut stops: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: each call writes only to `stops`, which outlives it, and
    // pthread_sigmask reads it and no old mask.
    let blocked = unsafe {
        libc::sigemptyset(&raw mut stops) == 0
            && libc::sigaddset(&raw mut stops, libc::SIGTERM) == 0
            && libc::sigaddset(&raw mut stops, libc::SIGINT) == 0
            && libc::pthread_sigmask(libc::SIG_BLOCK, &raw const stops, std::ptr::null_mut()) == 0
    };
    if !blocked {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stops)
}

/// Waits for a stop signal on its own thread, then drains the carrier and
/// ends its connection, so a transfer blocked on the host parks.
fn watch_stop(
    stops: libc::sigset_t,
    gate: Arc<Gate>,
    connection: Arc<Mutex<Option<File>>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("vm-outbox-stop".into())
        .spawn(move || {
            let mut signal = 0;
            // SAFETY: `stops` was filled by sigemptyset and sigaddset, and
            // sigwait writes only to `signal`.
            unsafe { libc::sigwait(&raw const stops, &raw mut signal) };
            gate.drain();
            if let Some(stream) = connection
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
            {
                // SAFETY: shutdown takes no pointers; the descriptor is a
                // socket the slot holds open.
                unsafe { libc::shutdown(stream.as_raw_fd(), libc::SHUT_RDWR) };
            }
        })?;
    Ok(())
}

/// The guest's roots: fixed directories under the held outbox, and the
/// backup plan the engine registered.
struct GuestRoots {
    outbox: File,
    registry: Registry,
}

impl Roots for GuestRoots {
    fn open(&self, kind: VmOutboxKind) -> std::io::Result<Option<File>> {
        let opened = match kind {
            VmOutboxKind::Escrow => open_dir_at(&self.outbox, ESCROW),
            VmOutboxKind::Custody => {
                open_dir_at(&self.outbox, ESCROW).and_then(|escrow| open_dir_at(&escrow, CUSTODY))
            }
            VmOutboxKind::Esign => open_dir_at(&self.outbox, ESIGN),
            VmOutboxKind::Training => open_dir_at(&self.outbox, TRAINING),
            VmOutboxKind::Recipients => open_dir_at(&self.outbox, RECIPIENTS),
            VmOutboxKind::Backup | VmOutboxKind::BackupStageAck => {
                let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(plan) = registry.as_ref() else {
                    return Ok(None);
                };
                if kind == VmOutboxKind::Backup {
                    plan.dir.try_clone()
                } else {
                    open_dir_at(&plan.dir, BACKUP_HANDOFF_DIR)
                }
            }
        };
        match opened {
            Ok(dir) => Ok(Some(dir)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn takes(&self, kind: VmOutboxKind, member: &str) -> bool {
        if !matches!(kind, VmOutboxKind::Backup | VmOutboxKind::BackupStageAck) {
            return true;
        }
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry.as_ref().is_some_and(|plan| match kind {
            VmOutboxKind::Backup => member
                .strip_prefix(plan.label.as_str())
                .is_some_and(|rest| rest.starts_with('-')),
            _ => member
                .split_once('/')
                .is_some_and(|(label, _)| label == plan.label),
        })
    }
}

/// Lays out `/vault/outbox` for `uid` and returns it, held.
fn lay_out(uid: u32) -> anyhow::Result<File> {
    let outbox_path = Path::new(VM_GUEST_OUTBOX_DIR);
    let (Some(vault), Some(leaf)) = (
        outbox_path.parent(),
        outbox_path.file_name().and_then(std::ffi::OsStr::to_str),
    ) else {
        anyhow::bail!("the guest outbox has no parent");
    };
    let vault = open_dir_path(vault)?;
    let outbox = owned_dir(&vault, leaf, 0, uid, 0o750)?;
    owned_dir(&outbox, CARRIER, 0, 0, 0o700)?;
    for name in [ESCROW, ESIGN] {
        owned_dir(&outbox, name, uid, uid, 0o700)?;
    }
    let training = owned_dir(&outbox, TRAINING, 0, uid, 0o750)?;
    for name in [OFFERS_DIR, CONTROLS_DIR, RECEIPTS_DIR, SCOPES_DIR] {
        owned_dir(&training, name, uid, uid, 0o700)?;
    }
    let flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let lock = File::from(rustix::fs::openat(
        &training,
        TRAINING_LOCK,
        flags,
        Mode::from_raw_mode(0o600),
    )?);
    anyhow::ensure!(
        lock.metadata()?.is_file(),
        "the training lock is not a regular file"
    );
    fchown(&lock, Some(uid), Some(uid))?;
    lock.set_permissions(Permissions::from_mode(0o600))?;
    owned_dir(&outbox, RECIPIENTS, 0, uid, 0o750)?;
    training.sync_all()?;
    outbox.sync_all()?;
    vault.sync_all()?;
    Ok(outbox)
}

/// The directory `name` in `parent`, made when missing, given `owner`,
/// `group` and `mode`. Its parent is root's, so what stands at the name is
/// root's making; a link there is refused.
fn owned_dir(
    parent: &File,
    name: &str,
    owner: u32,
    group: u32,
    mode: u32,
) -> std::io::Result<File> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(mode)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    let dir = open_dir_at(parent, name)?;
    fchown(&dir, Some(owner), Some(group))?;
    dir.set_permissions(Permissions::from_mode(mode))?;
    Ok(dir)
}
