//! The job cache in a run's view (FLEET-TOOL-PARITY row 5, [NODE-TEMPLATE-CACHE-DIR]), as root
//! makes it before the job's view is built and takes it away after the job.
//!
//! - **Kept.** The launch holds its template's kept cache: the entry `<cache_dir>/<name>` stays
//!   the engine's (pass 34 row P2's cache budget moves it out of use); inside it, `data` is the
//!   job account's (mode 0700), made on first use. Each is opened beneath the cache directory
//!   with no link followed. A kept cache that does not pass runs cold, with a journal line.
//! - **Cold.** Any other run of the template: `<payload>/cache`, made fresh for the job account.
//! - **The view.** The opened directory is bound, through its descriptor, at
//!   `/run/oneiron-caches/<instance>` under a directory only root enters, as the payload is
//!   ([`super::exchange::publish_payload`]). The unit binds that source writable at
//!   `execution_node.job_cache.mount`; `exec.json` lists the mount as a write path, and the
//!   run's environment names it (`ONEIRON_JOB_CACHE`) and says `kept` or `cold`
//!   (`ONEIRON_JOB_CACHE_STATE`).
//! - **Removal.** The engine cannot delete what the job account wrote. After each job's end,
//!   root starts a transient `job-cache-sweep` (Nice 19, idle I/O class) that removes each
//!   job-owned `data` tree among the cache directory's removed caches (`.oneiron-evicted`), with
//!   no link followed and no mount crossed; the engine's next cache pass deletes the rest.

use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::super::jobs::LaunchFile;
use super::super::node_settings::{EVICTED_DIR_NAME, ExecutionNodeSettings, NodeTemplate};
use super::exchange::root_dir;
use super::records::ExecFile;
use super::safe_fs::{self, borrow, make_dir_beneath, open_dir_beneath, open_dir_path};
use super::step::StepContext;
use super::systemd_unit::run_tool;
use super::unit_file::installed_binds_job_cache;

/// The root-only directory the job caches' bind sources lie in, one per instance.
pub const JOB_CACHE_ROOT: &str = "/run/oneiron-caches";
/// The job account's directory inside a kept cache entry.
pub const JOB_CACHE_DATA_DIR_NAME: &str = "data";
/// A cold run's cache directory inside its payload.
pub const JOB_CACHE_COLD_DIR_NAME: &str = "cache";
/// The environment variable that names the mount to the run.
pub const JOB_CACHE_ENV: &str = "ONEIRON_JOB_CACHE";
/// The environment variable that says `kept` or `cold` to the run.
pub const JOB_CACHE_STATE_ENV: &str = "ONEIRON_JOB_CACHE_STATE";
/// The transient unit the end step starts the sweep in.
pub const JOB_CACHE_SWEEP_UNIT: &str = "oneiron-job-cache-sweep";

/// The longest the end step waits for the sweep's start: `--no-block` returns at once, and the
/// end step's whole run fits in its stop grace.
const SWEEP_START_WAIT: Duration = Duration::from_secs(1);

/// The run's cache as root made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobCacheView {
    /// Where the run sees it.
    pub mount: PathBuf,
    /// The kept cache; false: a fresh empty one in the payload.
    pub kept: bool,
}

/// Root's half of the launch's job cache, after the payload is published and before
/// `exec.json` is written: `None` for a launch with none. The node must let runs write a job
/// cache, the template must name the launch's key, and the installed unit must bind it at the
/// node's mount.
///
/// # Errors
///
/// The refusal reason, for the key's end.
pub(super) fn prepare(
    context: &StepContext,
    launch: &LaunchFile,
    template: &NodeTemplate,
    unit_text: &str,
    payload: &OwnedFd,
) -> Result<Option<JobCacheView>, String> {
    let Some(cache) = launch.cache.as_ref() else {
        return Ok(None);
    };
    let settings = &context.settings;
    if !settings.job_cache.writable {
        return Err("job_cache_not_permitted: execution_node.job_cache.writable is off".to_owned());
    }
    if template.job_cache.as_deref() != Some(cache.key.as_str()) {
        return Err(
            "job_cache_not_the_templates: launch.json names another cache than the template's job_cache"
                .to_owned(),
        );
    }
    let mount = &settings.job_cache.mount;
    if !installed_binds_job_cache(unit_text, mount) {
        return Err(
            "template_outdated: the job unit does not bind this job cache mount: run `oneiron execution-node install` again"
                .to_owned(),
        );
    }
    let kept = if cache.kept {
        match kept_data_dir(context, template, &cache.key) {
            Ok(data) => Some(data),
            Err(why) => {
                journal_line!(
                    "job-prepare: {}: the kept cache {} runs cold: {why}",
                    context.unit(),
                    cache.key
                );
                None
            }
        }
    } else {
        None
    };
    let view = JobCacheView {
        mount: mount.clone(),
        kept: kept.is_some(),
    };
    let dir = match kept {
        Some(data) => data,
        None => make_dir_beneath(
            borrow(payload),
            JOB_CACHE_COLD_DIR_NAME,
            0o700,
            (context.job_uid, context.job_gid),
        )
        .map_err(|error| format!("job_cache_not_fresh: {error}"))?,
    };
    publish(&context.args.instance, &dir)?;
    Ok(Some(view))
}

/// The kept cache's `data` directory, the job account's, inside the engine's entry `key` names
/// directly in the cache directory: made on first use.
fn kept_data_dir(
    context: &StepContext,
    template: &NodeTemplate,
    key: &str,
) -> Result<OwnedFd, String> {
    let path = template.warm.get(key).ok_or("job_cache_unmapped")?;
    let cache_root = context.settings.cache_root();
    let name = match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if parent == cache_root.as_path() => name,
        _ => return Err("job_cache_not_in_cache_dir".to_owned()),
    };
    let root =
        open_dir_path(&cache_root).map_err(|error| format!("cache_dir_unreadable: {error}"))?;
    engines_alone(context, &root, "cache_dir")?;
    let entry = open_dir_beneath(borrow(&root), name)
        .map_err(|error| format!("job_cache_entry_missing: {error}"))?;
    engines_alone(context, &entry, "job_cache_entry")?;
    match open_dir_beneath(borrow(&entry), OsStr::new(JOB_CACHE_DATA_DIR_NAME)) {
        Ok(data) => {
            let found = safe_fs::facts(borrow(&data)).map_err(|error| error.to_string())?;
            if found.uid != context.job_uid {
                return Err("job_cache_data_not_the_jobs".to_owned());
            }
            Ok(data)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => make_dir_beneath(
            borrow(&entry),
            JOB_CACHE_DATA_DIR_NAME,
            0o700,
            (context.job_uid, context.job_gid),
        )
        .map_err(|error| format!("job_cache_data: {error}")),
        Err(error) => Err(format!("job_cache_data: {error}")),
    }
}

/// `dir` is the engine's, and no group or other account writes in it.
fn engines_alone(context: &StepContext, dir: &OwnedFd, what: &str) -> Result<(), String> {
    let found = safe_fs::facts(borrow(dir)).map_err(|error| error.to_string())?;
    if found.uid != context.engine_uid || found.mode & 0o022 != 0 {
        return Err(format!(
            "{what}_not_engines: it must be the engine's, with no group or other writes"
        ));
    }
    Ok(())
}

/// Publishes `dir` as the job cache's bind source `<JOB_CACHE_ROOT>/<instance>`: a bind mount of
/// that directory through its descriptor, under a directory only root can enter (mode 0700).
fn publish(instance: &str, dir: &OwnedFd) -> Result<(), String> {
    let root = root_dir(JOB_CACHE_ROOT, 0o700).map_err(|why| format!("job_cache_root: {why}"))?;
    drop(
        make_dir_beneath(borrow(&root), instance, 0o700, (0, 0))
            .map_err(|error| format!("job_cache_not_fresh: {error}"))?,
    );
    let source = CString::new(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .map_err(|error| error.to_string())?;
    let target = CString::new(
        Path::new(JOB_CACHE_ROOT)
            .join(instance)
            .as_os_str()
            .as_bytes(),
    )
    .map_err(|error| error.to_string())?;
    // SAFETY: both strings are NUL terminated. The source is the descriptor's own directory (the
    // kernel resolves the /proc link to it), bound without its submounts onto a mount point only
    // root reaches.
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
        return Err(format!(
            "job_cache_not_published: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// What the run's `exec.json` gains for `view`: the mount as a write path, and the two
/// environment variables that name it and say `kept` or `cold`.
pub fn add_to_exec(exec: &mut ExecFile, view: &JobCacheView) {
    exec.write.push(view.mount.clone());
    exec.env
        .insert(JOB_CACHE_ENV.to_owned(), view.mount.display().to_string());
    exec.env.insert(
        JOB_CACHE_STATE_ENV.to_owned(),
        String::from(if view.kept { "kept" } else { "cold" }),
    );
}

/// Takes away the job cache's bind source of `instance` (a checked job instance), as
/// [`super::exchange::withdraw`] takes the payload's: a step that fails is skipped, and what is
/// left goes at the next boot.
pub fn withdraw(instance: &str) {
    let target = Path::new(JOB_CACHE_ROOT).join(instance);
    if let Ok(c) = CString::new(target.as_os_str().as_bytes()) {
        // SAFETY: c is NUL terminated; the mount point is never followed as a link, and a lazy
        // detach leaves the job's own view alone.
        let _ = unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
    }
    let _ = std::fs::remove_dir(&target);
}

/// Starts the sweep of job-written cache data after a job's end, when this node lets runs write
/// a job cache: a transient unit of its own, so the end step never waits for it. While one runs,
/// another start is refused, and the running one sweeps.
pub(super) fn start_sweep(context: &StepContext) {
    if !context.settings.job_cache.writable {
        return;
    }
    let Some(binary) = std::env::current_exe()
        .ok()
        .and_then(|path| path.to_str().map(str::to_owned))
    else {
        return;
    };
    let Some(node_file) = context.args.node_file.to_str() else {
        return;
    };
    let unit = format!("--unit={JOB_CACHE_SWEEP_UNIT}");
    let args = [
        "--no-block",
        "--collect",
        "--quiet",
        unit.as_str(),
        "--property=Nice=19",
        "--property=IOSchedulingClass=idle",
        binary.as_str(),
        "job-cache-sweep",
        "--node-file",
        node_file,
    ];
    if let Err(why) = run_tool("systemd-run", &args, SWEEP_START_WAIT) {
        journal_line!("job-ended: the job cache sweep did not start: {why}");
    }
}

/// `oneiron job-cache-sweep --node-file <path>`, root's sweep of job-written cache data: among
/// the cache directory's removed caches, each entry's `data` that is the job account's is
/// removed, walked with no link followed and no mount crossed. Returns the exit status.
#[must_use]
pub fn run_sweep(args: &[String]) -> i32 {
    let node_file = match args {
        [flag, path] if flag == "--node-file" => PathBuf::from(path),
        _ => {
            journal_line!("job-cache-sweep: usage: job-cache-sweep --node-file <path>");
            return 2;
        }
    };
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        journal_line!("job-cache-sweep: needs root");
        return 2;
    }
    let settings = match ExecutionNodeSettings::read(&node_file) {
        Ok(Some(settings)) => settings,
        Ok(None) => return 0,
        Err(why) => {
            journal_line!("job-cache-sweep: {why}");
            return 1;
        }
    };
    match sweep(&settings) {
        Ok(removed) => {
            if removed > 0 {
                journal_line!("job-cache-sweep: removed {removed} job cache data trees");
            }
            0
        }
        Err(why) => {
            journal_line!("job-cache-sweep: {why}");
            1
        }
    }
}

/// The sweep of `settings`' cache directory: how many `data` trees it removed.
fn sweep(settings: &ExecutionNodeSettings) -> Result<usize, String> {
    let (job_uid, _, _) = safe_fs::account(&settings.job_account)
        .map_err(|error| format!("job account {}: {error}", settings.job_account))?;
    let cache_root = settings.cache_root();
    let root = match open_dir_path(&cache_root) {
        Ok(root) => root,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("{}: {error}", cache_root.display())),
    };
    let evicted = match open_dir_beneath(borrow(&root), OsStr::new(EVICTED_DIR_NAME)) {
        Ok(evicted) => evicted,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(format!("{EVICTED_DIR_NAME}: {error}")),
    };
    // Every name is read before any tree is removed.
    let mut names: Vec<OsString> = Vec::new();
    for entry in rustix::fs::Dir::read_from(&evicted).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let child = entry.file_name();
        if child != c"." && child != c".." {
            names.push(OsStr::from_bytes(child.to_bytes()).to_owned());
        }
    }
    let data = CString::new(JOB_CACHE_DATA_DIR_NAME).map_err(|error| error.to_string())?;
    let mut removed = 0;
    for name in names {
        let Ok(entry) = open_dir_beneath(borrow(&evicted), &name) else {
            continue;
        };
        let Ok(found) = safe_fs::facts_beneath(borrow(&entry), JOB_CACHE_DATA_DIR_NAME) else {
            continue;
        };
        if !found.is_dir || found.is_link || found.uid != job_uid {
            continue;
        }
        match crate::gpu_execution_node::jobs::warm::remove_tree(borrow(&entry), &data) {
            Ok(()) => removed += 1,
            Err(error) => {
                journal_line!(
                    "job-cache-sweep: {}/{}: {error}",
                    EVICTED_DIR_NAME,
                    Path::new(&name).display()
                );
            }
        }
    }
    Ok(removed)
}
