//! A vault VM's root bootstrap, `oneiron-vm-init` (FIX 6308): the step
//! between the image's shell init, which mounts the disks, and the managed
//! engine, which it starts as the vault's own non-root UID.
//!
//! On a cold boot it dials the host's provision connection
//! ([`oneiron_vault_contract::vm_provision`]) before any engine runs and
//! takes the vault's binding and fscrypt key there. It checks the binding
//! against the guest's boot arguments and its vault drive, installs the key
//! and checks the kernel's identifier for it, and lays out the encrypted
//! storage, the UID table and the socket directories ([`layout`]). It answers
//! the host, its copy of the key already wiped, and only then starts the
//! engine: supplementary groups cleared, then the GID and the UID set to the
//! binding's, with no environment but `PATH` and no descriptor beyond the
//! standard three. The engine dials its own credential connection and
//! reports its own readiness after the unchanged managed gates; nothing here
//! stands in for either.
//!
//! Before all of it the bootstrap asks the host's restore channel for the
//! boot's mode (FIX 6584, [`restore`]). An ordinary open is all of the
//! above. A cold restore leaves the data directory for the restore to make,
//! mounts the restore's source drive when the host attached one, and hands
//! the engine its two restore pipes, which the bootstrap carries over the
//! channel. An inspection installs the key, reads the commit marker and
//! answers, and starts nothing.
//!
//! A boot that serves then reads the host's custody anchor header before
//! the engine starts, and carries the anchor's credential into the engine
//! after the engine's credential frame, on a pipe of the engine's own, and
//! its streams to the anchor URL the host bound, through a socket of the
//! engine's own (FIX 6517, [`anchor`]).
//!
//! It stays root only to supervise, and to run the outbox companion
//! `oneiron-vm-outbox` beside the engine ([`outbox`], FIX 5235): started
//! before the engine, it lays out the outbox and carries it to the host, and
//! the engine gets its outbox flags only once it is ready. When the engine
//! exits the bootstrap stops the companion and waits for it (a local commit
//! in flight finishes, a network transfer parks), then ends whatever the
//! engine left running, syncs, removes the key from the filesystem's keyring
//! and exits with the engine's status; the image's init then powers the VM
//! off.

mod anchor;
mod fscrypt;
mod layout;
mod outbox;
mod restore;

use self::fscrypt::{KeyIdentifier, Removal};
use anyhow::Context as _;
use oneiron_vault_contract::host_adapters::connect_blocking;
use oneiron_vault_contract::vm::{
    MAX_VM_FRAME, VM_BOOT_PORT, VM_GUEST_DATA_DIR, VM_GUEST_KEYS_DIR, VM_HOST_CID, decode_vm_frame,
    encode_vm_frame,
};
use oneiron_vault_contract::vm_provision::{
    VmFscryptKey, VmProvision, VmProvisionFailure, VmProvisionReply,
};
use oneiron_vault_contract::vm_restore::VmRestoreBoot;
use oneiron_vault_contract::{CONTRACT_VERSION, hex};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::{ExitCode, ExitStatus, Stdio};
use std::sync::mpsc;

/// The engine the bootstrap starts, beside it in the image.
const ENGINE: &str = "/usr/bin/oneiron-server";
/// The engine's whole environment: the search path a process supervisor
/// gives it too.
const ENGINE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Why provisioning was refused, as the host is told it.
struct Refusal {
    code: VmProvisionFailure,
    detail: String,
}

impl Refusal {
    fn new(code: VmProvisionFailure, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// What the image's init passes: the vault and the derivation owner its boot
/// arguments name, then `--` and the engine flags the bootstrap does not own
/// (its sockets, its settings and its supervisor's bindings).
struct InitArgs {
    vault: String,
    owner: String,
    engine_flags: Vec<OsString>,
}

impl InitArgs {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self, &'static str> {
        let (mut vault, mut owner) = (None, None);
        loop {
            let Some(flag) = args.next() else {
                return Err("no -- before the engine's flags");
            };
            let slot = match flag.to_str() {
                Some("--") => break,
                Some("--vault-name") => &mut vault,
                Some("--derivation-owner") => &mut owner,
                _ => return Err("an argument oneiron-vm-init does not take"),
            };
            *slot = args.next().and_then(|value| value.into_string().ok());
        }
        match (vault, owner) {
            (Some(vault), Some(owner)) => Ok(Self {
                vault,
                owner,
                engine_flags: args.collect(),
            }),
            _ => Err("no --vault-name or no --derivation-owner"),
        }
    }
}

/// A provisioned guest: the held vault root, the installed key's identifier,
/// the UID the engine runs as, and a cold restore's mounted source drive.
struct Provisioned {
    root: File,
    identifier: KeyIdentifier,
    uid: u32,
    source: Option<restore::SourceMount>,
}

/// `oneiron-vm-init`'s whole run. Its exit status is the engine's, or a
/// failure when provisioning was refused and no engine ran.
pub fn run_vm_init() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("oneiron-vm-init: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let args = InitArgs::parse(std::env::args_os().skip(1));
    // The host names this boot's mode before anything is laid out.
    let vault = args.as_ref().map_or("", |args| args.vault.as_str());
    let (boot, restore_channel) = restore::exchange(vault)?;
    let mut channel = connect_blocking(VM_HOST_CID, VM_BOOT_PORT)
        .context("dialling the host's provision connection")?;
    let provisioned = provision(&mut channel, args.as_ref().map_err(|fault| *fault), &boot);
    let reply = match &provisioned {
        Ok((frame, _)) => VmProvisionReply::Provisioned {
            revision: frame.revision,
            vault: frame.vault.clone(),
            binding: frame.binding.clone(),
        },
        Err(refusal) => VmProvisionReply::refused(refusal.code, &refusal.detail),
    };
    let answered = encode_vm_frame(&reply)
        .and_then(|line| channel.write_all(line.as_bytes()).map_err(Into::into))
        .context("answering the host's provision connection");
    drop(channel);
    let (frame, mut provisioned) = provisioned.map_err(|refusal| {
        anyhow::anyhow!(
            "provisioning refused ({}): {}",
            refusal.code,
            refusal.detail
        )
    })?;
    if let Err(error) = answered {
        remove_key(&provisioned);
        return Err(error);
    }
    let args = args.map_err(anyhow::Error::msg)?;
    let status = match boot {
        VmRestoreBoot::Open => {
            drop(restore_channel);
            run_engine(&args, provisioned.uid, None)
        }
        VmRestoreBoot::Restore { .. } => run_engine(&args, provisioned.uid, Some(restore_channel)),
        VmRestoreBoot::InspectMarker { identity } => {
            let observation =
                restore::observe(&provisioned.root, &provisioned.identifier, provisioned.uid);
            let answered =
                restore::answer_inspection(restore_channel, &frame, identity, observation);
            remove_key(&provisioned);
            return answered.map(|()| ExitCode::SUCCESS);
        }
    };
    // Nothing the engine started is left to hold the source drive.
    drop(provisioned.source.take());
    rustix::fs::sync();
    remove_key(&provisioned);
    let status = status?;
    Ok(ExitCode::from(
        status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(1),
    ))
}

/// One boot-channel line, read byte by byte so no key byte after it is
/// buffered here.
fn read_line(channel: &mut File) -> anyhow::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.last() != Some(&b'\n') {
        anyhow::ensure!(line.len() < MAX_VM_FRAME, "the frame is over its bound");
        channel.read_exact(&mut byte)?;
        line.push(byte[0]);
    }
    Ok(String::from_utf8(line)?)
}

/// The provision connection's guest side, up to its answer: the frame and
/// the key, the binding's checks, the key's installation and the layout
/// `boot` takes, a cold restore's source drive mounted last. A refusal after
/// the key went in removes it again.
fn provision(
    channel: &mut File,
    args: Result<&InitArgs, &'static str>,
    boot: &VmRestoreBoot,
) -> Result<(VmProvision, Provisioned), Refusal> {
    let malformed = |error: anyhow::Error| {
        Refusal::new(
            VmProvisionFailure::MalformedBinding,
            format!("the provision frame: {error:#}"),
        )
    };
    let frame: VmProvision = read_line(channel)
        .and_then(|line| decode_vm_frame(&line))
        .map_err(malformed)?;
    let key = VmFscryptKey::read_from(&mut *channel).map_err(malformed)?;
    frame
        .validate()
        .map_err(|(code, fault)| Refusal::new(code, fault))?;
    let args = args.map_err(|fault| {
        Refusal::new(
            VmProvisionFailure::ProvisionFailed,
            format!("the image's init passed {fault}"),
        )
    })?;
    let owner = &frame.binding.derivation_owner;
    if frame.vault != args.vault || !owner.eq_ignore_ascii_case(&args.owner) {
        return Err(Refusal::new(
            VmProvisionFailure::ContradictoryBinding,
            "the binding names another vault or derivation owner than the boot arguments",
        ));
    }
    let root = layout::open_vault_root()?;
    layout::check_disk(&root, &frame.binding.vault_disk_uuid)?;
    // An inspection makes nothing on the disk: it reads what is there.
    let inspecting = matches!(boot, VmRestoreBoot::InspectMarker { .. });
    let restoring = matches!(boot, VmRestoreBoot::Restore { .. });
    let control = if inspecting {
        layout::existing_control(&root)?
    } else {
        Some(layout::open_control(&root)?)
    };
    let record = layout::ProvisionRecord::of(&frame);
    let recorded = match &control {
        Some(control) => layout::recorded(control, &record)?,
        None => false,
    };
    let identifier = install_key(&root, key, &frame.binding.fscrypt_key_identifier)?;
    let mut provisioned = Provisioned {
        root,
        identifier,
        uid: frame.binding.guest_uid,
        source: None,
    };
    let uid = provisioned.uid;
    let laid_out = match &control {
        Some(control) if !inspecting => {
            layout::lay_out_storage(&provisioned.root, uid, &identifier, !restoring)
                .and_then(|()| {
                    if recorded {
                        Ok(())
                    } else {
                        layout::write_record(control, &record)
                    }
                })
                .and_then(|()| layout::install_uid_table(&frame.vault, uid, restoring))
                .and_then(|()| layout::own_run_dirs(uid))
        }
        _ => Ok(()),
    };
    let laid_out = laid_out.and_then(|()| match boot {
        VmRestoreBoot::Restore {
            source_device: Some(device),
        } => restore::SourceMount::mount(*device).map(|mount| provisioned.source = Some(mount)),
        _ => Ok(()),
    });
    if let Err(refusal) = laid_out {
        remove_key(&provisioned);
        return Err(refusal);
    }
    Ok((frame, provisioned))
}

/// Adds `key` to the vault filesystem's keyring and wipes it, then refuses
/// unless the kernel's identifier for it is `expected`.
fn install_key(root: &File, key: VmFscryptKey, expected: &str) -> Result<KeyIdentifier, Refusal> {
    let added = fscrypt::add_key(root, &key);
    drop(key);
    let identifier = added.map_err(|error| {
        let code = if fscrypt::unsupported(&error) {
            VmProvisionFailure::FscryptUnavailable
        } else {
            VmProvisionFailure::ProvisionFailed
        };
        Refusal::new(code, format!("adding the vault's key: {error}"))
    })?;
    if hex(&identifier) != expected {
        let _ = fscrypt::remove_key(root, &identifier);
        return Err(Refusal::new(
            VmProvisionFailure::KeyMismatch,
            "the kernel's identifier for the key is not the binding's",
        ));
    }
    Ok(identifier)
}

/// Removes the vault's key from the filesystem's keyring, through the held
/// unencrypted vault root.
fn remove_key(provisioned: &Provisioned) {
    match fscrypt::remove_key(&provisioned.root, &provisioned.identifier) {
        Ok(Removal::Removed | Removal::Absent) => {}
        Ok(Removal::FilesBusy) => eprintln!(
            "oneiron-vm-init: the vault's key is removed; files still open keep it until they close"
        ),
        Err(error) => eprintln!("oneiron-vm-init: removing the vault's key failed: {error}"),
    }
}

/// Starts the outbox companion, then the engine as `uid`, and waits for the
/// engine; then stops the companion, and ends and reaps what is left. The
/// host's custody anchor header is read before either, and the anchor's
/// credential taken beside the engine. A cold restore's engine
/// (`restore_channel`) gets its two restore pipes, and the restore's last
/// result record goes out before this returns.
fn run_engine(
    args: &InitArgs,
    uid: u32,
    restore_channel: Option<File>,
) -> anyhow::Result<ExitStatus> {
    // Whatever the engine leaves behind is reparented here, not to PID 1, so
    // it is reaped before the key goes. Any nonzero argument sets it.
    rustix::process::set_child_subreaper(Some(rustix::process::getpid()))
        .context("becoming the engine's subreaper")?;
    let anchor = anchor::exchange(&args.vault, uid)?;
    let companion = outbox::start(&args.vault, uid, ENGINE_PATH);
    let mut flags = if companion.is_some() {
        outbox::engine_flags()
    } else {
        Vec::new()
    };
    flags.extend(anchor.flags());
    let anchor_fds = anchor.fds();
    // A pipe the engine reads that broke before its end comes back here.
    let (lost_sender, lost) = mpsc::channel();
    let mut restoring = None;
    let mut anchored = None;
    let status = match restore_channel {
        None => start_engine(args, uid, &flags, &anchor_fds).and_then(|mut engine| {
            anchored = Some(anchor.start(lost_sender)?);
            restore::supervise(&mut engine, &lost)
        }),
        Some(channel) => restore::start(channel, lost_sender.clone(), |fds, restore_flags| {
            let fds = [fds, &anchor_fds[..]].concat();
            start_engine(args, uid, &[&flags[..], restore_flags].concat(), &fds)
        })
        .and_then(|started| {
            let restoring = restoring.insert(started);
            anchored = Some(anchor.start(lost_sender)?);
            restoring.wait(&lost)
        }),
    };
    // The anchor's socket goes with the engine.
    drop(anchored);
    // The companion goes first, while the key is in: it may be writing into
    // the encrypted storage. Then everything else, the broker among it.
    if let Some(companion) = companion {
        companion.stop();
    }
    end_leftovers();
    if let Some(restoring) = restoring {
        restoring.finish();
    }
    status
}

/// The engine as `uid`, with the init's flags and `flags`, and `fds` as
/// `oneiron_spawn::command_with_fds` places them.
fn start_engine(
    args: &InitArgs,
    uid: u32,
    flags: &[OsString],
    fds: &[(RawFd, RawFd)],
) -> anyhow::Result<std::process::Child> {
    let mut command = oneiron_spawn::command_with_fds(ENGINE, fds);
    command
        .arg("serve")
        .args(["--managed-by-hypnos", "--vsock-guest", "--contract-version"])
        .arg(CONTRACT_VERSION.to_string())
        .arg("--vault-name")
        .arg(&args.vault)
        .arg("--derivation-owner")
        .arg(&args.owner)
        .args([
            "--data-dir",
            VM_GUEST_DATA_DIR,
            "--keystore-dir",
            VM_GUEST_KEYS_DIR,
        ])
        .args(&args.engine_flags)
        .args(flags)
        .env_clear()
        .env("PATH", ENGINE_PATH)
        .stdin(Stdio::null());
    // SAFETY: the hook runs in the forked child before exec and calls only
    // setgroups, setgid and setuid, which are async-signal-safe, then reads
    // errno; it allocates nothing.
    unsafe { command.pre_exec(move || drop_privileges(uid)) };
    command.spawn().context("starting the engine")
}

/// Clears the supplementary groups, then sets the GID and the UID to `uid`.
/// After the UID there is no way back to root.
fn drop_privileges(uid: u32) -> std::io::Result<()> {
    // SAFETY: setgroups reads no memory when its count is zero; setgid and
    // setuid take no pointers.
    let dropped = unsafe {
        libc::setgroups(0, std::ptr::null()) == 0
            && libc::setgid(uid) == 0
            && libc::setuid(uid) == 0
    };
    if !dropped {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Ends every process the engine left behind, its broker among them, and
/// reaps them all. The engine has exited, so all that remains besides this
/// process and PID 1 is what it started.
fn end_leftovers() {
    // SAFETY: kill takes no pointers; -1 signals every process this one may,
    // except PID 1 and itself.
    unsafe { libc::kill(-1, libc::SIGKILL) };
    // Until no child is left (ECHILD), retrying an interrupted wait.
    while let Ok(Some(_)) | Err(rustix::io::Errno::INTR) =
        rustix::process::wait(rustix::process::WaitOptions::empty())
    {}
}
