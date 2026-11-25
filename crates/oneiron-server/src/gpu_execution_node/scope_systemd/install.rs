//! `oneiron execution-node install` (root, once per machine and again after
//! a template's maximum grows; pass 33, 7.6; EM-4 = A): the one privileged
//! step. It checks the node's job range against the system's accounts,
//! groups and subordinate ids (each job runs as its own uid from it: FIX
//! EXEC-UNIT-CROSS-JOB-SAME-UID; no job account is made), writes the
//! root-owned unit template and
//! the job control socket through which the engine's account starts and
//! stops its instances and nothing else ([`super::control`]; the engine's
//! account gets no polkit grant), makes the state and payload directories
//! the engine's, reloads the service manager and starts the socket. It is
//! idempotent: a second run with the same inputs changes nothing.

use std::ffi::OsStr;
use std::ops::Range;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use super::super::node_settings::ExecutionNodeSettings;
use super::UNIT_TEMPLATE_PATH;
use super::control::{CONTROL_SERVICE_UNIT_PATH, CONTROL_SOCKET_UNIT, CONTROL_SOCKET_UNIT_PATH};
use super::safe_fs::{
    account, borrow, facts, make_dir_beneath, open_dir_beneath, open_dir_path, require_root_owned,
};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool};
use super::unit_file::{
    UnitInputs, plain_account, render_control_service, render_control_socket, render_job_unit,
    unit_path_word,
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
    let name = &request.engine_account;
    if !plain_account(name) {
        return Err(format!(
            "{name:?}: an account name here is 1 to 32 of a-z, 0-9, '-' and '_'"
        ));
    }
    let (engine_uid, engine_gid, engine_home) = account(&request.engine_account)
        .map_err(|error| format!("engine account {}: {error}", request.engine_account))?;
    check_job_range(&settings.job_uids(), (engine_uid, engine_gid))?;
    let mut protected = vec![engine_home];
    protected.extend(request.protect.iter().cloned());
    protected.sort();
    protected.dedup();
    let runtime_max_secs = settings
        .templates
        .values()
        .map(|template| template.max_secs)
        .max()
        .unwrap_or(0)
        .max(1);
    let inputs = UnitInputs {
        binary,
        node_file: request.node_file.clone(),
        engine_account: request.engine_account.clone(),
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
    let unit = render_job_unit(&inputs);
    let socket = render_control_socket(engine_gid);
    let handler = render_control_service(&inputs);
    if request.dry_run {
        stdout_line!(
            "--- {UNIT_TEMPLATE_PATH}\n{unit}--- {CONTROL_SOCKET_UNIT_PATH}\n{socket}--- {CONTROL_SERVICE_UNIT_PATH}\n{handler}"
        );
        print_templates(&settings);
        return Ok(());
    }
    ensure_dir(&inputs.state_dir, engine_uid, engine_gid, 0o700)?;
    ensure_dir(
        &inputs.state_dir.join("control"),
        engine_uid,
        engine_gid,
        0o700,
    )?;
    ensure_dir(&inputs.work_dir, engine_uid, engine_gid, 0o755)?;
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
        "installed: {UNIT_TEMPLATE_PATH} ({}), {CONTROL_SOCKET_UNIT_PATH} ({}, started), {CONTROL_SERVICE_UNIT_PATH} ({}), job uids {}..{}, RuntimeMaxSec {runtime_max_secs}",
        said(unit_changed),
        said(socket_changed),
        said(handler_changed),
        settings.job_uids().start,
        settings.job_uids().end
    );
    print_templates(&settings);
    stdout_line!("next: `oneiron execution-node check` as root proves each bound in a probe unit");
    Ok(())
}

fn print_templates(settings: &ExecutionNodeSettings) {
    for name in settings.templates.keys() {
        if let Some(digest) = settings.template_digest(name) {
            stdout_line!("template {name} digest {digest}");
        }
    }
}

/// What an id file lists, and so which of its fields are ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdFile {
    /// `/etc/passwd`: a uid and a gid per line.
    Accounts,
    /// `/etc/group`: a gid per line.
    Groups,
    /// `/etc/subuid`, `/etc/subgid`: a range per line (`name:first:count`),
    /// the ids a user's own namespaces map to.
    Subordinate,
}

/// The files whose ids the job range must not meet.
const ID_FILES: [(&str, IdFile); 4] = [
    ("/etc/passwd", IdFile::Accounts),
    ("/etc/group", IdFile::Groups),
    ("/etc/subuid", IdFile::Subordinate),
    ("/etc/subgid", IdFile::Subordinate),
];

/// The node's job range meets no account, group or subordinate range the
/// system files name, nor the engine's ids: a job's uid is no one else's. An
/// account a name service holds (LDAP, for instance) is checked again for
/// each id the prepare step gives ([`super::job_ids`]).
fn check_job_range(range: &Range<u32>, engine: (u32, u32)) -> Result<(), String> {
    if range.contains(&engine.0) || range.contains(&engine.1) {
        return Err(format!(
            "the job range {}..{} holds the engine's uid {} or gid {}",
            range.start, range.end, engine.0, engine.1
        ));
    }
    for (path, kind) in ID_FILES {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("{path}: {error}")),
        };
        if let Some(line) = first_overlap(&text, kind, range) {
            return Err(format!(
                "{path}: '{line}' meets the job range {}..{}: set job_uid_first and job_uid_count in the node file to a free range",
                range.start, range.end
            ));
        }
    }
    Ok(())
}

/// The first line of an id file whose ids meet `range`.
fn first_overlap<'a>(text: &'a str, kind: IdFile, range: &Range<u32>) -> Option<&'a str> {
    let field =
        |fields: &[&str], at: usize| fields.get(at).and_then(|field| field.parse::<u64>().ok());
    let (start, end) = (u64::from(range.start), u64::from(range.end));
    text.lines().find(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        let ids_meet = |at: usize| field(&fields, at).is_some_and(|id| (start..end).contains(&id));
        match kind {
            IdFile::Accounts => ids_meet(2) || ids_meet(3),
            IdFile::Groups => ids_meet(2),
            IdFile::Subordinate => match (field(&fields, 1), field(&fields, 2)) {
                (Some(first), Some(count)) => first < end && first.saturating_add(count) > start,
                _ => false,
            },
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_range_meets_no_account_group_or_subordinate_range() {
        let range = 1_879_048_192..1_879_113_728;
        let accounts =
            "root:x:0:0::/root:/bin/bash\noneiron:x:970:971::/var/lib/oneiron:/bin/bash\n";
        assert_eq!(first_overlap(accounts, IdFile::Accounts, &range), None);
        let taken = "odd:x:1879048200:100::/:/bin/false\n";
        assert_eq!(
            first_overlap(taken, IdFile::Accounts, &range),
            Some(taken.trim_end())
        );
        let group_only = "odd:x:100:1879048200::/:/bin/false\n";
        assert!(first_overlap(group_only, IdFile::Accounts, &range).is_some());
        assert!(first_overlap("jobs:x:1879113727:\n", IdFile::Groups, &range).is_some());
        assert_eq!(
            first_overlap("jobs:x:1879113728:\n", IdFile::Groups, &range),
            None
        );
        // useradd's subordinate ranges sit far below the default range.
        assert_eq!(
            first_overlap("lexi:100000:65536\n", IdFile::Subordinate, &range),
            None
        );
        assert!(first_overlap("big:1879000000:100000\n", IdFile::Subordinate, &range).is_some());
        assert!(check_job_range(&range, (1_879_048_192, 971)).is_err());
    }
}
