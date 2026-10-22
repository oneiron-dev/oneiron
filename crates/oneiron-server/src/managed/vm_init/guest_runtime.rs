//! The guests' container runtime in a vault VM (FIX 7671, placement A): the
//! root bootstrap's preparation, for the vault's UID, of the runtime the
//! image stages, and the engine's bindings for it. It does inside the VM what
//! a native node's supervisor does for a vault UID (Hypnos's guest runtime
//! lifecycle, FIX 7667), once on each boot that serves, an open and a cold
//! restore alike, after the key and the storage's layout and before the
//! engine starts. An inspection never reaches it.
//!
//! The config drive's binding files ([`VM_GUEST_BROWSER_RUNTIME_FILE`],
//! [`VM_GUEST_DESKTOP_RUNTIME_FILE`]), read with the drive's other typed
//! files' bound, say which guests the supervisor binds; with neither the
//! guests stay dark. The steps then go in order, and the first that fails
//! names the [`GuestRuntimeFact`] and ends the preparation:
//!
//! 1. userspace: each binding file names the image descriptor's CLI
//!    ([`VM_GUEST_RUNTIME_DESCRIPTOR`]), and every file the descriptor names
//!    is staged root's with its bytes and its mode. It goes first because
//!    every later step runs or reads one of those files.
//! 2. nss: the vault UID resolves as its own identity, a systemd userdb
//!    drop-in on the runtime tmpfs, which the image's `nsswitch.conf` has
//!    nss-systemd read, as on a native node.
//! 3. subids: the vault UID's one row of [`VM_GUEST_SUBID_COUNT`]
//!    subordinate IDs from [`VM_GUEST_SUBID_BASE`], written on the runtime
//!    tmpfs and bind-mounted over the image's empty `/etc/subuid` and
//!    `/etc/subgid`, numeric and local to the VM.
//! 4. userns: user namespaces, and the distro's set-user-ID mapping helpers
//!    on the CLI's `PATH`.
//! 5. limits: cgroup v2 with its memory, cpu and pids controllers, and a
//!    cgroup delegated to the vault UID, which every CLI call here and the
//!    engine start in.
//! 6. dirs: the CLI's `HOME` and `XDG_RUNTIME_DIR`, made in the encrypted
//!    storage by the layout's held-directory helpers, the runtime directory
//!    emptied of an earlier boot's state (FIX 8936).
//! 7. The CLI's own mapping (userns), then each image in the vault UID's own
//!    store: found by its id, or loaded from its archive (its bytes checked
//!    again first) and found then (image import, image id). A load a killed
//!    boot cut off records no image, so the next boot loads it again.
//!
//! Every CLI call runs as the vault UID, with no supplementary group and
//! exactly the environment the engine gives its CLI. The engine gets one
//! [`GUEST_RUNTIME_FACT_ARG`] either way; its runtime flags and
//! `ONEIRON_FENCE_LAUNCHER` only when the runtime is provisioned, and the
//! container directories' flags once they are made. A failure is reported
//! and the boot goes on: it refuses no provisioning, stops no vault and
//! passes no flag that would stand over the owner's own section.
//! Provisioned is the imports and the observed preconditions, never a
//! started guest: nothing here starts a browser or waits on a clock.

mod store;

use self::store::Cli;
use super::config_drive::read_known;
use super::layout;
use oneiron_vault_contract::GuestRuntimeFact as Fact;
use oneiron_vault_contract::vm::{
    VM_GUEST_BROWSER_RUNTIME_FILE, VM_GUEST_CONTAINER_HOME, VM_GUEST_CONTAINER_RUNTIME_DIR,
    VM_GUEST_DESKTOP_RUNTIME_FILE, VM_GUEST_RUNTIME_DESCRIPTOR, VM_GUEST_SUBID_BASE,
    VM_GUEST_SUBID_COUNT, VmGuestRuntimeDescriptor,
};
use oneiron_vault_contract::{GUEST_RUNTIME_FACT_ARG, GuestRuntimeFact, hex};
use sha2::{Digest as _, Sha256};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// The variable the engine's fence configuration reads its launcher from
/// (`oneiron_container::FenceConfig::from_env`).
const FENCE_LAUNCHER_ENV: &str = "ONEIRON_FENCE_LAUNCHER";
/// The `PATH` the engine gives its container CLI (oneiron-container), and so
/// every CLI call here, with its directories in order.
const CLI_PATH: &str = "/usr/bin:/bin";
const CLI_PATH_DIRS: [&str; 2] = ["/usr/bin", "/bin"];
/// The longest descriptor read: a bound on its codec, not on the runtime.
const MAX_DESCRIPTOR_BYTES: u64 = 1 << 20;
/// The image's NSS configuration, whose `passwd` line must name `systemd`.
const NSSWITCH: &str = "/etc/nsswitch.conf";
/// The runtime drop-in directory nss-systemd reads, on the `/run` tmpfs.
const USERDB_DIR: &str = "/run/userdb";
/// The vault UID identity's name, before its UID: a native node's too.
const USER_PREFIX: &str = "oneiron-vault-";
/// The identity's login shell: no one logs in to a vault VM.
const NOLOGIN: &str = "/usr/sbin/nologin";
/// The subordinate ID files' directory on the `/run` tmpfs, root's, and
/// each file's leaf there and the image's empty mountpoint it covers.
const IDS_DIR: &str = "/run/oneiron-ids";
const SUBID_FILES: [(&str, &str); 2] = [("subuid", "/etc/subuid"), ("subgid", "/etc/subgid")];
const MAX_USER_NAMESPACES: &str = "/proc/sys/user/max_user_namespaces";
/// The cgroup v2 hierarchy, the cgroup in it delegated to the vault UID,
/// and that cgroup's `cgroup.procs`, which a process joins it through.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_DIR: &str = "/sys/fs/cgroup/oneiron-vault";
const CGROUP_PROCS: &CStr = c"/sys/fs/cgroup/oneiron-vault/cgroup.procs";
/// The controllers the guests' `--memory`, `--cpus` and `--pids-limit` need.
const CONTROLLERS: [&str; 3] = ["memory", "cpu", "pids"];
/// The files of a delegated cgroup its delegate owns, beside the directory.
const DELEGATED_FILES: [&str; 3] = ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"];

/// The step that did not hold: its fact, and what it found.
struct Failed {
    fact: GuestRuntimeFact,
    detail: String,
}

fn fail(fact: GuestRuntimeFact) -> impl Fn(String) -> Failed {
    move |detail| Failed { fact, detail }
}

/// What the preparation gives the engine.
pub(super) struct GuestRuntime {
    fact: GuestRuntimeFact,
    /// Whether the container CLI's two directories were made.
    dirs: bool,
    /// The provisioned runtime's bindings; none for any other fact.
    bound: Option<Bound>,
}

/// A provisioned runtime's bindings for the engine, which also starts in
/// the delegated cgroup.
struct Bound {
    /// `--browser-runtime` and `--desktop-runtime`, each with the
    /// descriptor's CLI, for the binding files that are there.
    runtimes: Vec<OsString>,
    fence: PathBuf,
}

impl GuestRuntime {
    /// The engine's flags: the bound runtimes, the container directories
    /// when they were made, and the fact.
    pub(super) fn engine_flags(&self) -> Vec<OsString> {
        let mut flags = self
            .bound
            .as_ref()
            .map_or_else(Vec::new, |bound| bound.runtimes.clone());
        if self.dirs {
            flags.extend(
                [
                    "--container-home",
                    VM_GUEST_CONTAINER_HOME,
                    "--container-runtime-dir",
                    VM_GUEST_CONTAINER_RUNTIME_DIR,
                ]
                .map(OsString::from),
            );
        }
        flags.push(GUEST_RUNTIME_FACT_ARG.into());
        flags.push(self.fact.as_str().into());
        flags
    }

    /// The fence launcher's variable and its guest path, provisioned only.
    pub(super) fn fence_env(&self) -> Option<(&'static str, &Path)> {
        let bound = self.bound.as_ref()?;
        Some((FENCE_LAUNCHER_ENV, bound.fence.as_path()))
    }

    /// Whether the engine starts in the delegated cgroup ([`join_cgroup`]):
    /// provisioned only.
    pub(super) fn joins_cgroup(&self) -> bool {
        self.bound.is_some()
    }
}

/// Prepares the runtime for `uid`, reading the binding files only from a
/// config drive the image's init mounted (`config_mounted`), and reports
/// its fact.
pub(super) fn prepare(uid: u32, config_mounted: bool) -> GuestRuntime {
    let mut dirs = false;
    let (fact, bound) = match steps(uid, config_mounted, &mut dirs) {
        Ok(bound) => {
            eprintln!(
                "oneiron-vm-init: {}: both guest images are in the vault UID's own store and \
                 every precondition held; no guest was started",
                Fact::GuestRuntimeProvisioned.as_str()
            );
            (Fact::GuestRuntimeProvisioned, Some(bound))
        }
        Err(Failed { fact, detail }) => {
            eprintln!(
                "oneiron-vm-init: {}: {detail}; the engine starts with no guest runtime bound",
                fact.as_str()
            );
            (fact, None)
        }
    };
    GuestRuntime { fact, dirs, bound }
}

/// Every step in its order, stopping at the first that fails.
fn steps(uid: u32, config_mounted: bool, dirs: &mut bool) -> Result<Bound, Failed> {
    let requested = bindings(config_mounted)?;
    let descriptor = descriptor()?;
    let cli = descriptor.cli.as_os_str().as_bytes();
    for (_, file, named) in &requested {
        if named.as_slice() != cli {
            return Err(fail(Fact::GuestRuntimeUserspaceMissing)(format!(
                "the config drive's {file} does not name the image's container CLI"
            )));
        }
    }
    closure(&descriptor)?;
    identity(uid)?;
    subids(uid)?;
    userns()?;
    limits(uid)?;
    layout::own_container_dirs(uid)
        .map_err(|refusal| fail(Fact::GuestRuntimeDirsUnavailable)(refusal.detail))?;
    *dirs = true;
    let cli = Cli {
        program: &descriptor.cli,
        uid,
    };
    cli.mapping()?;
    let imported = [
        ("browser", &descriptor.browser_image),
        ("desktop", &descriptor.desktop_image),
    ]
    .map(|(name, archive)| cli.import(name, archive));
    // Both are tried; an import that failed comes before an id that
    // differs, as the facts are ordered.
    for fact in [
        Fact::GuestRuntimeImageImportFailed,
        Fact::GuestRuntimeImageIdMismatch,
    ] {
        if let Some(Err(failed)) = imported
            .iter()
            .find(|outcome| outcome.as_ref().is_err_and(|failed| failed.fact == fact))
        {
            return Err(fail(fact)(failed.detail.clone()));
        }
    }
    Ok(Bound {
        runtimes: requested
            .into_iter()
            .flat_map(|(flag, _, _)| [OsString::from(flag), descriptor.cli.clone().into()])
            .collect(),
        fence: descriptor.fence,
    })
}

/// The binding files that are there, each as its engine flag, its path and
/// its value less at most one final LF: none at all is dark, and one that
/// cannot be read is no usable binding, never absent.
fn bindings(config_mounted: bool) -> Result<Vec<(&'static str, &'static str, Vec<u8>)>, Failed> {
    if !config_mounted {
        return Err(fail(Fact::GuestRuntimeDisabled)(
            "no config drive is mounted, so no guest runtime is bound".into(),
        ));
    }
    let mut requested = Vec::new();
    for (flag, file) in [
        ("--browser-runtime", VM_GUEST_BROWSER_RUNTIME_FILE),
        ("--desktop-runtime", VM_GUEST_DESKTOP_RUNTIME_FILE),
    ] {
        let bytes = read_known(file)
            .map_err(|error| fail(Fact::GuestRuntimeUserspaceMissing)(error.to_string()))?;
        if let Some(mut bytes) = bytes {
            if bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            requested.push((flag, file, bytes));
        }
    }
    if requested.is_empty() {
        return Err(fail(Fact::GuestRuntimeDisabled)(
            "the config drive binds no guest runtime".into(),
        ));
    }
    Ok(requested)
}

/// The image's descriptor: root's, within its bound, in its form.
fn descriptor() -> Result<VmGuestRuntimeDescriptor, Failed> {
    let userspace = fail(Fact::GuestRuntimeUserspaceMissing);
    let path = VM_GUEST_RUNTIME_DESCRIPTOR;
    let file = match open_root_file(Path::new(path)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(userspace(format!(
                "the image stages no guest runtime: {path} is not there"
            )));
        }
        Err(error) => return Err(userspace(format!("{path}: {error}"))),
    };
    let mut bytes = Vec::new();
    file.take(MAX_DESCRIPTOR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| userspace(format!("{path}: {error}")))?;
    if bytes.len() as u64 > MAX_DESCRIPTOR_BYTES {
        return Err(userspace(format!(
            "{path} is over {MAX_DESCRIPTOR_BYTES} bytes"
        )));
    }
    let descriptor: VmGuestRuntimeDescriptor = serde_json::from_slice(&bytes)
        .map_err(|_| userspace(format!("{path} is not a guest runtime descriptor")))?;
    descriptor
        .validate()
        .map_err(|fault| userspace(format!("{path}: {fault}")))?;
    Ok(descriptor)
}

/// Opens `path` without following a final link, and refuses it unless it
/// is a regular file root owns and only root may write.
fn open_root_file(path: &Path) -> io::Result<File> {
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::Error::other("not a regular file root alone may write"));
    }
    Ok(file)
}

/// The SHA-256 of what is left of `file`, in lowercase hex.
fn sha256_hex(mut file: File) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

/// Every file the descriptor names, as the image staged it: root's, with
/// exactly its mode and its bytes.
fn closure(descriptor: &VmGuestRuntimeDescriptor) -> Result<(), Failed> {
    let userspace = fail(Fact::GuestRuntimeUserspaceMissing);
    for staged in &descriptor.closure {
        let shown = staged.guest_path.display();
        let file = open_root_file(&staged.guest_path)
            .map_err(|error| userspace(format!("{shown}: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| userspace(format!("{shown}: {error}")))?;
        if metadata.gid() != 0 || metadata.mode() & 0o7777 != staged.mode {
            return Err(userspace(format!(
                "{shown} is not root:root with mode {:o}",
                staged.mode
            )));
        }
        let digest = sha256_hex(file).map_err(|error| userspace(format!("{shown}: {error}")))?;
        if digest != staged.sha256 {
            return Err(userspace(format!(
                "{shown} is not the bytes the image staged"
            )));
        }
    }
    Ok(())
}

/// The vault UID's identity: the image's NSS reads systemd's drop-ins, the
/// drop-in and its UID link are written whole on the runtime tmpfs, and the
/// UID then resolves as its own name with the container CLI's `HOME`.
fn identity(uid: u32) -> Result<(), Failed> {
    let nss = fail(Fact::GuestRuntimeNssUnavailable);
    let text =
        std::fs::read_to_string(NSSWITCH).map_err(|error| nss(format!("{NSSWITCH}: {error}")))?;
    let reads_dropins = text
        .lines()
        .filter_map(|line| line.split('#').next())
        .find_map(|line| line.trim().strip_prefix("passwd:"))
        .is_some_and(|sources| sources.split_whitespace().any(|source| source == "systemd"));
    if !reads_dropins {
        return Err(nss(format!(
            "{NSSWITCH}'s passwd line names no systemd, so no drop-in identity resolves"
        )));
    }
    let name = format!("{USER_PREFIX}{uid}");
    write_identity(uid, &name).map_err(|error| nss(format!("{USERDB_DIR}: {error}")))?;
    match resolve(uid) {
        Some((found, home)) if found == name && home == Path::new(VM_GUEST_CONTAINER_HOME) => {
            Ok(())
        }
        Some((found, _)) => Err(nss(format!(
            "UID {uid} resolves as {found}, not {name} with home {VM_GUEST_CONTAINER_HOME}"
        ))),
        None => Err(nss(format!("UID {uid} resolves to no user"))),
    }
}

/// `name`'s user record for `uid`, root's 0644, and the `<uid>.user` link
/// nss-systemd looks a UID up by: locked, with no password and no group.
fn write_identity(uid: u32, name: &str) -> io::Result<()> {
    make_root_dir(USERDB_DIR)?;
    let record = serde_json::json!({
        "userName": name,
        "uid": uid,
        "gid": uid,
        "realName": "Oneiron vault guest runtime (oneiron-vm-init, FIX 7671)",
        "homeDirectory": VM_GUEST_CONTAINER_HOME,
        "shell": NOLOGIN,
        "locked": true,
    });
    let leaf = format!("{name}.user");
    write_root_file(
        &Path::new(USERDB_DIR).join(&leaf),
        format!("{record}\n").as_bytes(),
    )?;
    std::os::unix::fs::symlink(&leaf, Path::new(USERDB_DIR).join(format!("{uid}.user")))
}

/// A root directory on the runtime tmpfs, mode 0755, made on this boot.
fn make_root_dir(path: &str) -> io::Result<()> {
    std::fs::create_dir(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// `bytes` as the new file `path`, root's and readable by every UID.
fn write_root_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
    file.write_all(bytes)
}

/// The name and home NSS resolves `uid` to; `None` when it resolves to none.
fn resolve(uid: u32) -> Option<(String, PathBuf)> {
    let mut buffer = vec![libc::c_char::default(); 16 * 1024];
    // SAFETY: an all-zero passwd is a valid value of the plain C struct,
    // which getpwuid_r fills.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to a live local, and the buffer's length is
    // its own; getpwuid_r writes only inside them.
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &raw mut found,
        )
    };
    if code != 0 || found.is_null() || entry.pw_name.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: both point into `buffer`, NUL-terminated by getpwuid_r, and
    // are read before it goes.
    let (name, home) = unsafe { (CStr::from_ptr(entry.pw_name), CStr::from_ptr(entry.pw_dir)) };
    Some((
        name.to_string_lossy().into_owned(),
        PathBuf::from(OsStr::from_bytes(home.to_bytes())),
    ))
}

/// The vault UID's one row of subordinate IDs, refused when the range
/// holds the UID itself, written in both files and bind-mounted over the
/// image's empty ones.
fn subids(uid: u32) -> Result<(), Failed> {
    let conflict = fail(Fact::GuestRuntimeSubidsConflict);
    let first = u64::from(VM_GUEST_SUBID_BASE);
    if (first..first + u64::from(VM_GUEST_SUBID_COUNT)).contains(&u64::from(uid)) {
        return Err(conflict(format!(
            "the vault UID {uid} lies in its own subordinate IDs \
             {VM_GUEST_SUBID_BASE}+{VM_GUEST_SUBID_COUNT}"
        )));
    }
    let row = format!("{uid}:{VM_GUEST_SUBID_BASE}:{VM_GUEST_SUBID_COUNT}\n");
    make_root_dir(IDS_DIR).map_err(|error| conflict(format!("{IDS_DIR}: {error}")))?;
    for (leaf, target) in SUBID_FILES {
        let source = Path::new(IDS_DIR).join(leaf);
        write_root_file(&source, row.as_bytes())
            .and_then(|()| bind_over(&source, target))
            .map_err(|error| conflict(format!("{target}: {error}")))?;
    }
    Ok(())
}

/// Bind-mounts `source` over the image's `target`.
fn bind_over(source: &Path, target: &str) -> io::Result<()> {
    let source = CString::new(source.as_os_str().as_bytes())?;
    let target = CString::new(target)?;
    // SAFETY: both pointers are NUL-terminated strings that outlive the
    // call, and a bind mount takes no filesystem type or data.
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if mounted != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// User namespaces, and each mapping helper the CLI finds on its `PATH`:
/// root's set-user-ID file, writable by root alone and run by every UID.
fn userns() -> Result<(), Failed> {
    let unavailable = fail(Fact::GuestRuntimeUsernsUnavailable);
    let count = std::fs::read_to_string(MAX_USER_NAMESPACES)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok());
    match count {
        Some(count) if count > 0 => {}
        Some(_) => {
            return Err(unavailable(
                "user.max_user_namespaces is 0: no user namespace can be made".into(),
            ));
        }
        None => {
            return Err(unavailable(
                "user.max_user_namespaces does not read: this kernel makes no user namespace"
                    .into(),
            ));
        }
    }
    for helper in ["newuidmap", "newgidmap"] {
        let Some((path, metadata)) = CLI_PATH_DIRS.iter().find_map(|dir| {
            let path = Path::new(dir).join(helper);
            std::fs::metadata(&path)
                .ok()
                .map(|metadata| (path, metadata))
        }) else {
            return Err(unavailable(format!("no {helper} in {CLI_PATH}")));
        };
        let mode = metadata.mode();
        if !metadata.is_file()
            || metadata.uid() != 0
            || mode & 0o022 != 0
            || mode & 0o4001 != 0o4001
        {
            return Err(unavailable(format!(
                "{} is not root's set-user-ID file that every UID may run",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Cgroup v2, mounted here when it is not yet, with the memory, cpu and
/// pids controllers given to its children, and [`CGROUP_DIR`] made and
/// delegated to `uid`: the directory and the files its delegate owns.
fn limits(uid: u32) -> Result<(), Failed> {
    let unavailable = fail(Fact::GuestRuntimeLimitsUnavailable);
    let root = Path::new(CGROUP_ROOT);
    let controllers = root.join("cgroup.controllers");
    // Only a cgroup v2 hierarchy holds `cgroup.controllers`.
    if !controllers.is_file() {
        mount_cgroup2().map_err(|error| {
            unavailable(format!("mounting cgroup v2 at {CGROUP_ROOT}: {error}"))
        })?;
    }
    let available = std::fs::read_to_string(&controllers)
        .map_err(|error| unavailable(format!("{}: {error}", controllers.display())))?;
    let missing: Vec<&str> = CONTROLLERS
        .into_iter()
        .filter(|want| !available.split_whitespace().any(|have| have == *want))
        .collect();
    if !missing.is_empty() {
        return Err(unavailable(format!(
            "cgroup v2 lacks the {} controller",
            missing.join(", ")
        )));
    }
    let enable = CONTROLLERS
        .map(|controller| format!("+{controller}"))
        .join(" ");
    std::fs::write(root.join("cgroup.subtree_control"), enable)
        .map_err(|error| unavailable(format!("{CGROUP_ROOT}/cgroup.subtree_control: {error}")))?;
    let leaf = Path::new(CGROUP_DIR);
    std::fs::create_dir(leaf)
        .or_else(|error| match error.kind() {
            io::ErrorKind::AlreadyExists => Ok(()),
            _ => Err(error),
        })
        .and_then(|()| {
            std::iter::once(leaf.to_path_buf())
                .chain(DELEGATED_FILES.iter().map(|file| leaf.join(file)))
                .try_for_each(|path| std::os::unix::fs::chown(path, Some(uid), Some(uid)))
        })
        .map_err(|error| unavailable(format!("delegating {CGROUP_DIR}: {error}")))
}

fn mount_cgroup2() -> io::Result<()> {
    let target = CString::new(CGROUP_ROOT)?;
    // SAFETY: every pointer is a NUL-terminated string that outlives the
    // call; cgroup2 reads its data as one option string.
    let mounted = unsafe {
        libc::mount(
            c"cgroup2".as_ptr(),
            target.as_ptr(),
            c"cgroup2".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            c"nsdelegate".as_ptr().cast(),
        )
    };
    if mounted != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Moves the calling process into the delegated cgroup, through its
/// `cgroup.procs` opened by its fixed path. It makes only open, write and
/// close calls and allocates nothing, so a forked child may call it before
/// exec, whatever descriptors the spawn has moved by then.
pub(super) fn join_cgroup() -> io::Result<()> {
    // SAFETY: a static NUL-terminated path; open is async-signal-safe.
    let procs = unsafe { libc::open(CGROUP_PROCS.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if procs < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: one byte of a static string, written to the descriptor just
    // opened, then closed; write and close are async-signal-safe.
    let (written, error, _) = unsafe {
        let written = libc::write(procs, c"0".as_ptr().cast(), 1);
        (written, io::Error::last_os_error(), libc::close(procs))
    };
    if written != 1 {
        return Err(error);
    }
    Ok(())
}
