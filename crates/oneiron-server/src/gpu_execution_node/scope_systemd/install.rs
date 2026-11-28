//! `oneiron execution-node install` (root, once per machine and again after
//! a template's maximum grows; pass 33, 7.6; EM-4 = A): the one privileged
//! step. It makes the job account, writes the root-owned unit template and
//! the job control socket through which the engine's account starts and
//! stops its instances and nothing else ([`super::control`]; the engine's
//! account gets no polkit grant), makes the state and payload directories
//! the engine's and the device query's lock root's
//! ([`super::device_query::provision_lock`]), reloads the service manager
//! and starts the socket. It is idempotent: a second run with the same
//! inputs changes nothing. Before any change it refuses an engine's
//! directory that overlaps the lock's, and an oneiron binary beneath it
//! ([`super::device_query::require_install_paths_apart`]), and any entry
//! where the version before this one kept its query lock in the state
//! directory ([`super::device_query::require_no_old_state_dir_lock`]).
//! Before any change it also refuses a work directory whose path staging
//! would refuse ([`crate::gpu_execution_node::jobs::staging::work_dir_verdict`]).

use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::super::node_settings::ExecutionNodeSettings;
use super::UNIT_TEMPLATE_PATH;
use super::control::{CONTROL_SERVICE_UNIT_PATH, CONTROL_SOCKET_UNIT, CONTROL_SOCKET_UNIT_PATH};
use super::device_query::{
    DEVICE_QUERY_LOCK_DIR, DEVICE_QUERY_LOCK_FILE, provision_lock, require_install_paths_apart,
    require_no_old_state_dir_lock,
};
use super::safe_fs::{
    account, account_entry, borrow, facts, make_dir_beneath, open_dir_beneath, open_dir_path,
    require_root_owned,
};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, tool_path};
use super::unit_file::{
    UnitInputs, plain_account, render_control_service, render_control_socket, render_job_unit,
    unit_path_word,
};
use crate::gpu_execution_node::jobs::staging::{
    WorkDirAccess, WorkDirFault, WorkDirVerdict, work_dir_verdict_for,
};

/// What `install` is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallRequest {
    pub node_file: PathBuf,
    pub engine_account: String,
    /// More paths no job may open (the vault's trees and the keystore when
    /// they are outside the engine account's home).
    pub protect: Vec<PathBuf>,
    /// Print what would be written, and write nothing.
    pub dry_run: bool,
}

/// Runs the install.
///
/// # Errors
///
/// The first check or step that failed, in words.
pub fn install(request: &InstallRequest) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions.
    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root && !request.dry_run {
        return Err("install needs root (or --dry-run)".to_owned());
    }
    let binary = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| format!("the oneiron binary: {error}"))?;
    let settings = ExecutionNodeSettings::read(&request.node_file)?
        .ok_or_else(|| format!("{}: no node file", request.node_file.display()))?;
    if is_root {
        require_root_owned(&binary).map_err(|why| {
            format!("the binary the unit runs as root must be root's alone: {why}")
        })?;
        require_root_owned(&request.node_file)?;
    }
    for name in [&request.engine_account, &settings.job_account] {
        if !plain_account(name) {
            return Err(format!(
                "{name:?}: an account name here is 1 to 32 of a-z, 0-9, '-' and '_'"
            ));
        }
    }
    if request.engine_account == settings.job_account || settings.job_account == "root" {
        return Err("the job account must be neither root nor the engine's account".to_owned());
    }
    let (engine_uid, engine_gid, engine_home) = account(&request.engine_account)
        .map_err(|error| format!("engine account {}: {error}", request.engine_account))?;
    let mut protected = vec![engine_home];
    protected.extend(request.protect.iter().cloned());
    protected.sort();
    protected.dedup();
    let runtime_max_secs = unit_runtime_max_secs(&settings);
    let inputs = UnitInputs {
        binary,
        node_file: request.node_file.clone(),
        engine_account: request.engine_account.clone(),
        job_account: settings.job_account.clone(),
        state_dir: settings.state_dir.clone(),
        work_dir: settings.work_dir.clone(),
        protected,
        runtime_max_secs,
        stop_grace_secs: settings.stop_grace_secs,
        start_timeout_secs: settings.unit_start_timeout_secs,
    };
    for path in [
        &inputs.binary,
        &inputs.node_file,
        &inputs.state_dir,
        &inputs.work_dir,
    ]
    .into_iter()
    .chain(inputs.protected.iter())
    {
        unit_path_word(path)?;
    }
    let lock_dir = Path::new(DEVICE_QUERY_LOCK_DIR);
    require_install_paths_apart(
        &inputs.state_dir,
        &inputs.work_dir,
        &inputs.binary,
        lock_dir,
    )?;
    let engine_access = WorkDirAccess {
        uid: engine_uid,
        gid: engine_gid,
        groups: super::safe_fs::account_groups(&request.engine_account, engine_gid).map_err(
            |error| {
                format!(
                    "the groups of the engine account {}: {error}",
                    request.engine_account
                )
            },
        )?,
    };
    require_work_dir_chain(&inputs.work_dir, &request.engine_account, &engine_access)?;
    let unit = render_job_unit(&inputs);
    let socket = render_control_socket(engine_gid);
    let handler = render_control_service(&inputs);
    if request.dry_run {
        stdout_line!(
            "--- {UNIT_TEMPLATE_PATH}\n{unit}--- {CONTROL_SOCKET_UNIT_PATH}\n{socket}--- {CONTROL_SERVICE_UNIT_PATH}\n{handler}--- {DEVICE_QUERY_LOCK_DIR}/{DEVICE_QUERY_LOCK_FILE}\nroot's empty file, mode 0600, in root's directory, mode 0700\n"
        );
        print_templates(&settings);
        return Ok(());
    }
    // Before any other change: an entry where the version before this one
    // kept its query lock means a query of it may still hold that lock.
    require_no_old_state_dir_lock(&inputs.state_dir)?;
    ensure_job_account(&settings.job_account, engine_uid)?;
    ensure_dir(&inputs.state_dir, engine_uid, engine_gid, 0o700)?;
    ensure_dir(
        &inputs.state_dir.join("control"),
        engine_uid,
        engine_gid,
        0o700,
    )?;
    ensure_dir(&inputs.work_dir, engine_uid, engine_gid, 0o755)?;
    // Before the socket starts: a handler never makes the lock.
    let lock_changed = provision_lock(lock_dir)?;
    let unit_changed = write_if_changed(Path::new(UNIT_TEMPLATE_PATH), &unit)?;
    let socket_changed = write_if_changed(Path::new(CONTROL_SOCKET_UNIT_PATH), &socket)?;
    let handler_changed = write_if_changed(Path::new(CONTROL_SERVICE_UNIT_PATH), &handler)?;
    if unit_changed || socket_changed || handler_changed {
        run_tool("systemctl", &["daemon-reload"], SYSTEMCTL_TIMEOUT)?;
    }
    run_tool(
        "systemctl",
        &["enable", "--quiet", CONTROL_SOCKET_UNIT],
        SYSTEMCTL_TIMEOUT,
    )?;
    // A changed socket unit (another engine group) takes effect only once
    // the socket is made again.
    let socket_verb = if socket_changed { "restart" } else { "start" };
    run_tool(
        "systemctl",
        &[socket_verb, CONTROL_SOCKET_UNIT],
        SYSTEMCTL_TIMEOUT,
    )?;
    let said = |changed: bool| if changed { "written" } else { "unchanged" };
    stdout_line!(
        "installed: {UNIT_TEMPLATE_PATH} ({}), {CONTROL_SOCKET_UNIT_PATH} ({}, started), {CONTROL_SERVICE_UNIT_PATH} ({}), {DEVICE_QUERY_LOCK_DIR}/{DEVICE_QUERY_LOCK_FILE} ({}), job account {}, RuntimeMaxSec {runtime_max_secs}",
        said(unit_changed),
        said(socket_changed),
        said(handler_changed),
        said(lock_changed),
        settings.job_account
    );
    print_templates(&settings);
    stdout_line!("next: `oneiron execution-node check` as root proves each bound in a probe unit");
    Ok(())
}

/// Refuses a work directory whose path staging would refuse, before any
/// change: the staging rule
/// ([`crate::gpu_execution_node::jobs::staging::work_dir_verdict_for`]) for
/// the engine's account, with the engine's file access, so a directory root
/// may search but the engine may not is refused here as staging refuses it.
/// A path that is not there yet passes even where the engine may not make
/// it, because the root install makes the missing path: [`ensure_dir`] makes
/// missing parents root's (mode 0755) and the leaf the engine's, which pass.
fn require_work_dir_chain(
    work_dir: &Path,
    engine_account: &str,
    engine: &WorkDirAccess,
) -> Result<(), String> {
    let engine_uid = engine.uid;
    match work_dir_verdict_for(work_dir, engine)
        .map_err(|why| format!("work_dir {}: not judged for the engine account {engine_account} (uid {engine_uid}): {why}", work_dir.display()))?
    {
        WorkDirVerdict::Passes(_) | WorkDirVerdict::Missing { .. } => Ok(()),
        WorkDirVerdict::Unsafe(unsafe_) if unsafe_.fault == WorkDirFault::EngineMayNotWrite => {
            Err(format!(
                "work_dir {}: {}, judged for the engine account {engine_account} \
                 (uid {engine_uid}): staging would fail every job (checkout_failed); \
                 give {engine_account} write access to it, or pick another work_dir",
                unsafe_.path.display(),
                unsafe_.fault
            ))
        }
        WorkDirVerdict::Unsafe(unsafe_) => Err(format!(
            "work_dir {}: {}, judged for the engine account {engine_account} (uid {engine_uid}): staging would refuse every job (work_dir_unsafe); give the path to root or to {engine_account}, or pick another work_dir",
            unsafe_.path.display(),
            unsafe_.fault
        )),
    }
}

fn print_templates(settings: &ExecutionNodeSettings) {
    for name in settings.templates.keys() {
        if let Some(digest) = settings.template_digest(name) {
            stdout_line!("template {name} digest {digest}");
        }
    }
}

/// The shells of an account no one logs in to.
const NO_LOGIN_SHELLS: [&str; 5] = [
    "/usr/sbin/nologin",
    "/usr/bin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
];

/// Above this uid an account is a login account (`SYS_UID_MAX` of
/// login.defs(5), shadow's default).
const SYSTEM_UID_MAX: u32 = 999;

/// Makes the job account as a system account with no login and no home,
/// unless it exists. An account that exists must be such an account and not
/// the engine's (review r1 of #10439): a name that collides with a login
/// account would give every workload that account's uid.
fn ensure_job_account(name: &str, engine_uid: u32) -> Result<(), String> {
    match account_entry(name) {
        Ok(found) => {
            return existing_job_account_fits(&found.shell, found.uid, engine_uid)
                .map_err(|why| format!("job account {name}: {why}"));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("job account {name}: {error}")),
    }
    let shell = NO_LOGIN_SHELLS[..3]
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .unwrap_or("/bin/false");
    if tool_path("useradd").is_none() {
        return Err(format!("no account {name}, and no useradd to make it"));
    }
    run_tool(
        "useradd",
        &[
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            shell,
            name,
        ],
        SYSTEMCTL_TIMEOUT,
    )
    .map(drop)
}

/// Why an existing account cannot be the job account: a login shell, a uid
/// outside the system range (root included), or the engine's own uid.
fn existing_job_account_fits(shell: &Path, uid: u32, engine_uid: u32) -> Result<(), String> {
    if uid == engine_uid {
        return Err("it is the engine's account".to_owned());
    }
    if uid == 0 || uid > SYSTEM_UID_MAX {
        return Err(format!(
            "uid {uid} is not a system account's (1 to {SYSTEM_UID_MAX})"
        ));
    }
    if !NO_LOGIN_SHELLS
        .iter()
        .any(|allowed| shell == Path::new(allowed))
    {
        return Err(format!("its shell {} allows a login", shell.display()));
    }
    Ok(())
}

/// Makes `path` the account's directory. It walks from `/` one component at
/// a time, each opened beneath the one before it and never through a link
/// (review r2 R2-10): a missing component is made root's (mode 0755), the
/// last one `uid:gid` with `mode`, and each owner and mode is set on the
/// directory this step opened, not on a path. A last component that exists
/// must already be the account's.
fn ensure_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    use std::path::Component;
    let fail = |why: &dyn std::fmt::Display| format!("{}: {why}", path.display());
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => names.push(name),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(fail(&"a path with '..'"));
            }
        }
    }
    let Some((last, parents)) = names.split_last() else {
        return Err(fail(&"not a directory below /"));
    };
    let mut current = open_dir_path(Path::new("/")).map_err(|error| fail(&error))?;
    for name in parents {
        current = open_or_make(&current, name, 0o755, (0, 0))
            .map_err(|error| fail(&error))?
            .0;
    }
    let (leaf, made) =
        open_or_make(&current, last, mode, (uid, gid)).map_err(|error| fail(&error))?;
    if !made {
        let found = facts(borrow(&leaf)).map_err(|error| fail(&error))?;
        if found.uid != uid {
            return Err(fail(&format!(
                "owned by uid {}, not the engine's account (uid {uid})",
                found.uid
            )));
        }
    }
    Ok(())
}

/// The directory `name` beneath `dir`, opened never through a link, or made
/// with `owner` and `mode` when absent; with whether this call made it.
fn open_or_make(
    dir: &OwnedFd,
    name: &OsStr,
    mode: u32,
    owner: (u32, u32),
) -> std::io::Result<(OwnedFd, bool)> {
    match open_dir_beneath(borrow(dir), name) {
        Ok(found) => Ok((found, false)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let text = name
                .to_str()
                .ok_or_else(|| std::io::Error::other("a name that is not UTF-8"))?;
            make_dir_beneath(borrow(dir), text, mode, owner).map(|made| (made, true))
        }
        Err(error) => Err(error),
    }
}

/// Writes `text` to `path` (root-owned, mode 0644) when it differs; returns
/// whether it wrote.
fn write_if_changed(path: &Path, text: &str) -> Result<bool, String> {
    use std::os::unix::fs::PermissionsExt as _;
    if std::fs::read_to_string(path).is_ok_and(|old| old == text) {
        return Ok(false);
    }
    let dir = path.parent().ok_or("a path with no directory")?;
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let staging = path.with_extension("oneiron-new");
    std::fs::write(&staging, text).map_err(|error| format!("{}: {error}", staging.display()))?;
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o644))
        .map_err(|error| format!("{}: {error}", staging.display()))?;
    std::fs::rename(&staging, path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(true)
}

/// The job unit template's `RuntimeMaxSec`, a backstop behind each run's
/// cutoff timer: the longest run any template allows, which for a session
/// template is its `session_max_secs` across renewals (pass 34, 2.5; row
/// W1), so the backstop never ends a paid session at one chunk's maximum.
#[must_use]
pub fn unit_runtime_max_secs(settings: &ExecutionNodeSettings) -> u64 {
    settings
        .templates
        .values()
        .map(|template| {
            template
                .session_max_secs()
                .map_or(template.max_secs, |longest| longest.max(template.max_secs))
        })
        .max()
        .unwrap_or(0)
        .max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_job_account_must_be_a_system_account_with_no_login_and_not_the_engines() {
        let nologin = Path::new("/usr/bin/nologin");
        assert_eq!(existing_job_account_fits(nologin, 970, 971), Ok(()));
        assert_eq!(
            existing_job_account_fits(Path::new("/bin/false"), 970, 971),
            Ok(())
        );
        assert!(existing_job_account_fits(Path::new("/bin/bash"), 970, 971).is_err());
        assert!(existing_job_account_fits(nologin, 1000, 971).is_err());
        assert!(existing_job_account_fits(nologin, 0, 971).is_err());
        assert!(existing_job_account_fits(nologin, 971, 971).is_err());
    }

    #[test]
    fn install_refuses_a_work_dir_whose_path_staging_would_refuse() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("resolved temp dir");
        let open = root.join("open");
        let work = open.join("work");
        let ok = root.join("ok");
        let good = ok.join("work");
        for (path, mode) in [(&open, 0o777), (&work, 0o755), (&ok, 0o755), (&good, 0o755)] {
            std::fs::create_dir(path).expect("make test directory");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .expect("test directory mode");
        }
        let me = WorkDirAccess::this_process().expect("this process's file access");
        let why = require_work_dir_chain(&work, "oneiron", &me)
            .expect_err("the work directory beneath the open ancestor is refused");
        assert!(why.contains(open.display().to_string().as_str()), "{why}");
        assert!(why.contains("work_dir_unsafe"), "{why}");
        assert_eq!(require_work_dir_chain(&good, "oneiron", &me), Ok(()));
        let missing = ok.join("missing").join("work");
        assert_eq!(require_work_dir_chain(&missing, "oneiron", &me), Ok(()));
        if rustix::process::geteuid().as_raw() != 0 {
            let ro = root.join("ro");
            std::fs::create_dir(&ro).expect("make test directory");
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555))
                .expect("test directory mode");
            let why = require_work_dir_chain(&ro, "oneiron", &me)
                .expect_err("a work directory the engine may not write in is refused");
            assert!(why.contains("checkout_failed"), "{why}");
            assert_eq!(
                require_work_dir_chain(&ro.join("missing").join("work"), "oneiron", &me),
                Ok(()),
                "install makes a missing path even where the engine may not"
            );
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755))
                .expect("restore test directory mode");
        }
    }
}
