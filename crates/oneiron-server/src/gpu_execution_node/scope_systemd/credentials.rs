//! Job credentials (FIX [NODE-JOB-CREDENTIALS]; FLEET-TOOL-PARITY section
//! 4): a template names root-owned files, and every job of that template
//! gets them as systemd credentials. The engine account never reads them,
//! and a pin has no field that could carry or name one.
//!
//! The service manager reads `LoadCredential=` as it spawns the unit's first
//! command, which is root's prepare step, so prepare cannot choose a job's
//! files for its own unit; and the one unit template cannot name a
//! template's files. So the unit template loads one directory per instance,
//! `<CREDENTIALS_STAGING_ROOT>/<instance>` ([`load_credential_line`]), and
//! root's job control handler stages it just before it starts the unit
//! ([`stage_for_start`]). The directory is always made, empty for a template
//! that names no credential, so the load never fails on a missing path.
//! Each named file is copied in only after its check ([`check_source`]). A
//! file that does not pass is left out and does not fail the start: prepare
//! then refuses the job with the reason ([`check_for_launch`]).
//!
//! The service manager loads each file of the directory as `job_<name>`
//! (systemd.exec(5), `LoadCredential=` with a directory) into
//! `/run/credentials/<unit>/`: readable by the job account alone, removed
//! when the unit stops, and hidden from every other unit that has a mount
//! namespace. Prepare removes the staged copy first ([`withdraw`]), so the
//! secret is then held only there; the end step removes it too, and each
//! later start sweeps away a copy older than the unit's start timeout, which
//! a start that failed or was stopped before its first command left. The
//! workload finds the directory in `CREDENTIALS_DIRECTORY`
//! and reads it through its file wall ([`grant_exec`]).
//!
//! Every job runs as the one job account (FIX EXEC-UNIT-CROSS-JOB-SAME-UID),
//! and only the Landlock wall keeps one job out of another's files and
//! memory: Landlock refuses a ptrace access from one domain into another
//! that is not its child, the read modes included. So a credentialed job
//! launches only while every template on the node requires the file wall
//! ([`walled_node`]; ANSWER CREDENTIALS-SAME-UID-GUARD = A), unless the node
//! file sets `credentials_need_walled_node = false`. With one account per
//! job (#10493) the guard may relax; a later row decides.
//!
//! UNCONFIRMED until `scripts/execution-node/field/credential_probe.sh` runs
//! on a node: the load at the first spawn, the `job_<name>` naming and the
//! 1 MiB cap. Prepare's loaded check is fail-closed for all three: a
//! credentialed job never runs without its files.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use oneiron::job_workload::ScopeBound;

use super::super::jobs::job_unit::LAUNCH_FILE_NAME;
use super::super::jobs::{JobKeyId, LaunchFile};
use super::super::node_settings::{ExecutionNodeSettings, NodeTemplate};
use super::UNIT_TEMPLATE_PATH;
use super::control::CONTROL_SERVICE_UNIT_PATH;
use super::safe_fs::{
    boot_id, borrow, facts_beneath, make_dir_beneath, open_dir_path, read_beneath, remove_beneath,
    require_owned_by_root_or, write_beneath,
};
use super::step::{RECORD_MAX_BYTES, StepArgs, StepContext};

/// Root's directory (mode 0700) of the staged copies, one directory per job
/// instance: the control handler's `RuntimeDirectory=`.
pub const CREDENTIALS_STAGING_ROOT: &str = "/run/oneiron-credentials";

/// The control handler's `RuntimeDirectory=` name for
/// [`CREDENTIALS_STAGING_ROOT`].
const STAGING_RUNTIME_DIRECTORY: &str = "oneiron-credentials";

/// The id the unit template loads the staged directory under: each file
/// `<name>` in it becomes the credential `job_<name>`.
pub const CREDENTIAL_ID: &str = "job";

/// Where the service manager keeps a unit's loaded credentials.
const SERVICE_CREDENTIALS_ROOT: &str = "/run/credentials";

/// The variable that names the loaded directory, as the service manager
/// names it.
pub const CREDENTIALS_DIRECTORY_ENV: &str = "CREDENTIALS_DIRECTORY";

/// The most bytes one job's credentials hold together: systemd's credential
/// cap (systemd.exec(5)), UNCONFIRMED until `credential_probe.sh` runs on a
/// node.
pub const CREDENTIALS_TOTAL_BYTES_MAX: u64 = 1 << 20;

/// The unit template's line that loads the staged directory of `%i`.
#[must_use]
pub fn load_credential_line() -> String {
    format!("LoadCredential={CREDENTIAL_ID}:{CREDENTIALS_STAGING_ROOT}/%i")
}

/// Whether an installed unit template loads the staged directory.
#[must_use]
pub fn unit_loads_credentials(unit_text: &str) -> bool {
    let line = load_credential_line();
    unit_text.lines().any(|found| found.trim_end() == line)
}

/// The control handler service's lines that give it
/// [`CREDENTIALS_STAGING_ROOT`]: root's alone, kept between handlers.
#[must_use]
pub fn control_service_lines() -> String {
    format!(
        "RuntimeDirectory={STAGING_RUNTIME_DIRECTORY}\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\n"
    )
}

/// Whether an installed control handler service stages credentials.
#[must_use]
pub fn control_service_stages(service_text: &str) -> bool {
    let line = format!("RuntimeDirectory={STAGING_RUNTIME_DIRECTORY}");
    service_text.lines().any(|found| found.trim_end() == line)
}

/// The name the service manager gives the staged file `name`.
#[must_use]
pub fn loaded_name(name: &str) -> String {
    format!("{CREDENTIAL_ID}_{name}")
}

/// The directory the service manager loads `unit`'s credentials into.
#[must_use]
pub fn loaded_dir(unit: &str) -> PathBuf {
    Path::new(SERVICE_CREDENTIALS_ROOT).join(unit)
}

/// The guard of a credentialed job (ANSWER CREDENTIALS-SAME-UID-GUARD = A):
/// every template of the node requires the file wall, unless the node file
/// turns the guard off. The wall has one enforcer, Landlock (`job-exec`
/// records a wall it could not apply as not enforced), so a template that
/// requires `file_wall` at any strength runs only under Landlock.
///
/// # Errors
///
/// `credentials_need_walled_node`, naming the first template that does not.
pub fn walled_node(settings: &ExecutionNodeSettings) -> Result<(), String> {
    if !settings.credentials_need_walled_node {
        return Ok(());
    }
    let unwalled = settings.templates.iter().find(|(_, template)| {
        !template
            .require
            .iter()
            .any(|requirement| requirement.bound == ScopeBound::FileWall)
    });
    match unwalled {
        None => Ok(()),
        Some((name, _)) => Err(format!(
            "credentials_need_walled_node: template {name} does not require file_wall, so its jobs \
             may run without the Landlock wall beside this one under the same account; require it \
             there, or set credentials_need_walled_node = false on a node that runs one job at a time"
        )),
    }
}

/// The size of the file `name` beneath `dir`, or why it may not be a
/// credential: it must be a regular file (never a link), owned by `owner`
/// (root, or a test's own account), with no group or other access, and of
/// at most `budget` bytes.
fn source_facts(dir: BorrowedFd<'_>, name: &str, owner: u32, budget: u64) -> Result<u64, String> {
    let found = facts_beneath(dir, name).map_err(|error| error.to_string())?;
    if found.is_link {
        return Err("a link: name the real file".to_owned());
    }
    if !found.is_regular {
        return Err("not a regular file".to_owned());
    }
    if found.uid != owner {
        return Err(format!("owned by uid {}, not root", found.uid));
    }
    if found.mode & 0o077 != 0 {
        return Err(format!(
            "mode {:o} gives group or others access: chmod 0400",
            found.mode
        ));
    }
    if found.size > budget {
        return Err(format!(
            "{} bytes, past the {budget} bytes left of the {CREDENTIALS_TOTAL_BYTES_MAX} a job's credentials hold together",
            found.size
        ));
    }
    Ok(found.size)
}

/// The directory of the file at `path`, opened never through a link, and
/// the file's name, once the whole path passes [`require_owned_by_root_or`].
fn open_source(path: &Path, owner: u32) -> Result<(OwnedFd, String), String> {
    require_owned_by_root_or(path, owner)?;
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| format!("{}: no file name", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{}: no directory", path.display()))?;
    let dir = open_dir_path(parent).map_err(|error| error.to_string())?;
    Ok((dir, name.to_owned()))
}

/// The size of the credential file at `path`, or why it may not be one: the
/// whole path is `owner`'s or root's and writable by no one else, and the
/// file is a regular one of `owner`'s with no group or other access and at
/// most `budget` bytes.
///
/// # Errors
///
/// The fault, naming the path.
pub fn check_source(path: &Path, owner: u32, budget: u64) -> Result<u64, String> {
    let (dir, name) = open_source(path, owner)?;
    source_facts(borrow(&dir), &name, owner, budget)
        .map_err(|why| format!("{}: {why}", path.display()))
}

/// The bytes of the credential file at `path`, after [`check_source`].
fn read_source(path: &Path, owner: u32, budget: u64) -> Result<Vec<u8>, String> {
    let (dir, name) = open_source(path, owner)?;
    source_facts(borrow(&dir), &name, owner, budget)
        .map_err(|why| format!("{}: {why}", path.display()))?;
    read_beneath(borrow(&dir), &name, budget, Some(owner))
        .map_err(|error| format!("{}: {error}", path.display()))?
        .ok_or_else(|| format!("{}: gone", path.display()))
}

/// Makes `<root>/<instance>` afresh, owned by `owner`, mode 0700: a copy
/// left from an earlier start goes first.
fn fresh_dir(root: &Path, instance: &str, owner: (u32, u32)) -> Result<OwnedFd, String> {
    withdraw_at(root, instance)?;
    let parent = open_dir_path(root).map_err(|error| format!("{}: {error}", root.display()))?;
    make_dir_beneath(borrow(&parent), instance, 0o700, owner)
        .map_err(|error| format!("{}/{instance}: {error}", root.display()))
}

/// Copies each of `credentials` into `dir` (mode 0400, owned by
/// `staged_owner`) after its check, at most [`CREDENTIALS_TOTAL_BYTES_MAX`]
/// bytes together. Returns why, for each name not copied.
fn copy_into(
    dir: BorrowedFd<'_>,
    credentials: &BTreeMap<String, PathBuf>,
    source_owner: u32,
    staged_owner: (u32, u32),
) -> Vec<String> {
    let mut left = CREDENTIALS_TOTAL_BYTES_MAX;
    let mut skipped = Vec::new();
    for (name, path) in credentials {
        let copied = read_source(path, source_owner, left).and_then(|bytes| {
            write_beneath(dir, name, &bytes, 0o400, Some(staged_owner)).map_err(|error| {
                // A half-written copy would load as a credential of its own.
                let _ = remove_beneath(dir, &format!("{name}.new"));
                error.to_string()
            })?;
            Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        });
        match copied {
            Ok(size) => left = left.saturating_sub(size),
            Err(why) => skipped.push(format!("{name}: {why}")),
        }
    }
    skipped
}

/// The control handler's step just before it starts the unit of `id`: it
/// stages the directory the unit template loads, and sweeps away the copies
/// older starts left ([`sweep_stale`]). On a node whose installed unit
/// template predates credentials it does nothing.
///
/// # Errors
///
/// Only when the directory cannot be made (`credentials_not_staged`): the
/// unit would then fail its load, so the start is refused instead. A
/// launch or a file that does not pass goes to the journal, and prepare
/// refuses the job with the reason.
pub fn stage_for_start(
    node_file: Option<&Path>,
    engine_account: &str,
    id: &JobKeyId,
) -> Result<(), String> {
    let loads = std::fs::read_to_string(UNIT_TEMPLATE_PATH)
        .is_ok_and(|unit_text| unit_loads_credentials(&unit_text));
    if !loads {
        return Ok(());
    }
    let root = Path::new(CREDENTIALS_STAGING_ROOT);
    let dir = fresh_dir(root, id.as_str(), (0, 0)).map_err(|why| {
        format!("credentials_not_staged: {why}: run `oneiron execution-node install` again")
    })?;
    let Some(node_file) = node_file else {
        return Ok(());
    };
    // The step's own argument parser, as the unit's root steps take them.
    let args = [
        "--node-file".to_owned(),
        node_file.display().to_string(),
        "--engine-account".to_owned(),
        engine_account.to_owned(),
        id.as_str().to_owned(),
    ];
    let context = match StepArgs::parse(&args).and_then(StepContext::open) {
        Ok(context) => context,
        Err(why) => {
            journal_line!("job-control: {id}: no credential staged: {why}");
            return Ok(());
        }
    };
    for why in sweep_stale(root, id.as_str(), context.settings.unit_start_timeout_secs) {
        journal_line!("job-control: {why}");
    }
    match launch_credentials(&context) {
        Ok(credentials) => {
            for why in copy_into(borrow(&dir), &credentials, 0, (0, 0)) {
                journal_line!("job-control: {id}: credential not staged: {why}");
            }
        }
        Err(why) => journal_line!("job-control: {id}: no credential staged: {why}"),
    }
    Ok(())
}

/// Removes each staged copy beneath `root` but `keep`'s that is older than
/// `older_than_secs`, the job unit's start timeout. The service manager
/// loads a copy as its unit's start begins, and prepare then removes it, so
/// an older copy belongs to a start that failed or was stopped before its
/// first command. Returns what it could not remove.
fn sweep_stale(root: &Path, keep: &str, older_than_secs: u64) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let now = std::time::SystemTime::now();
    let mut faults = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == keep || JobKeyId::parse(name).is_none() {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|found| found.modified())
            .is_ok_and(|modified| {
                now.duration_since(modified)
                    .is_ok_and(|age| age.as_secs() > older_than_secs)
            });
        if false && stale && let Err(why) = withdraw_at(root, name) {
            faults.push(why);
        }
    }
    faults
}

/// The credentials of the template the key's `launch.json` names, checked
/// as the prepare step checks the launch: the key is this instance's, the
/// launch is this boot's, the pin passes the node file's admission, and the
/// node passes [`walled_node`]. Empty for a template that names none.
fn launch_credentials(context: &StepContext) -> Result<BTreeMap<String, PathBuf>, String> {
    let bytes = read_beneath(
        borrow(&context.control),
        LAUNCH_FILE_NAME,
        RECORD_MAX_BYTES,
        None,
    )
    .map_err(|error| format!("launch_file_unreadable: {error}"))?
    .ok_or("launch_file_missing")?;
    let launch: LaunchFile =
        serde_json::from_slice(&bytes).map_err(|error| format!("launch_file_invalid: {error}"))?;
    if JobKeyId::for_key(&launch.key).as_str() != context.args.instance {
        return Err("key_not_instance".to_owned());
    }
    if launch.boot_id != boot_id() {
        return Err("launch_from_another_boot".to_owned());
    }
    context.settings.admit_pin(&launch.pin)?;
    let template = context
        .settings
        .templates
        .get(&launch.pin.template)
        .ok_or("template_unknown")?;
    if template.credentials.is_empty() {
        return Ok(BTreeMap::new());
    }
    walled_node(&context.settings)?;
    Ok(template.credentials.clone())
}

/// Prepare's check of a launch of `template` in `unit`, whose installed
/// template text is `unit_text`: for a template that names credentials, the
/// node passes [`walled_node`], the unit and its control service are
/// installed with credentials, and the service manager loaded every named
/// file. Returns the names, for the prepared record; never their values.
///
/// # Errors
///
/// The refusal: `credentials_need_walled_node`, `template_outdated` or
/// `credential_not_loaded`.
pub fn check_for_launch(
    settings: &ExecutionNodeSettings,
    template: &NodeTemplate,
    unit: &str,
    unit_text: &str,
) -> Result<Vec<String>, String> {
    if template.credentials.is_empty() {
        return Ok(Vec::new());
    }
    walled_node(settings)?;
    let handler_stages = std::fs::read_to_string(CONTROL_SERVICE_UNIT_PATH)
        .is_ok_and(|service_text| control_service_stages(&service_text));
    if !unit_loads_credentials(unit_text) || !handler_stages {
        return Err(
            "template_outdated: the job unit or its control service predates credentials: run `oneiron execution-node install` again"
                .to_owned(),
        );
    }
    check_loaded(&loaded_dir(unit), &template.credentials, 0)?;
    Ok(template.credentials.keys().cloned().collect())
}

/// Every one of `credentials` is a regular file in `dir`, under the name the
/// service manager gives it.
///
/// # Errors
///
/// `credential_not_loaded`, naming the first that is not, with its file's
/// fault when the file check finds one.
fn check_loaded(
    dir: &Path,
    credentials: &BTreeMap<String, PathBuf>,
    source_owner: u32,
) -> Result<(), String> {
    for (name, path) in credentials {
        let loaded = dir.join(loaded_name(name));
        if std::fs::symlink_metadata(&loaded).is_ok_and(|found| found.file_type().is_file()) {
            continue;
        }
        let why = match check_source(path, source_owner, CREDENTIALS_TOTAL_BYTES_MAX) {
            Err(why) => why,
            Ok(_) => format!(
                "{} is not there: the start staged no copy (the job control journal says why), or the job's files together pass {CREDENTIALS_TOTAL_BYTES_MAX} bytes",
                loaded.display()
            ),
        };
        return Err(format!("credential_not_loaded: {name}: {why}"));
    }
    Ok(())
}

/// Gives the workload of a credentialed `template` the loaded directory of
/// `unit`: its path in `CREDENTIALS_DIRECTORY` (`env`), and leave to read it
/// through the file wall (`read`). A template with none gets neither.
pub fn grant_exec(
    env: &mut BTreeMap<String, String>,
    read: &mut Vec<PathBuf>,
    unit: &str,
    template: &NodeTemplate,
) {
    if template.credentials.is_empty() {
        return;
    }
    let dir = loaded_dir(unit);
    env.insert(
        CREDENTIALS_DIRECTORY_ENV.to_owned(),
        dir.display().to_string(),
    );
    read.push(dir);
}

/// Removes the staged copy of `instance`, if any. Prepare does it first, and
/// the end step again.
pub fn withdraw(instance: &str) {
    if let Err(why) = withdraw_at(Path::new(CREDENTIALS_STAGING_ROOT), instance) {
        journal_line!("credentials: {why}");
    }
}

/// [`withdraw`] beneath `root`, for a job instance only.
fn withdraw_at(root: &Path, instance: &str) -> Result<(), String> {
    if JobKeyId::parse(instance).is_none() {
        return Err(format!("{instance:?} is not a job instance"));
    }
    let path = root.join(instance);
    // `remove_dir_all` removes a link itself and never what it names.
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("{}: not removed: {error}", path.display())),
    }
}

/// What `install` says of each credential of the template `name`: `ok` and
/// its size, or its file's fault; and the guard's refusal, when the node
/// would refuse the template's jobs.
#[must_use]
pub fn install_lines(settings: &ExecutionNodeSettings, name: &str) -> Vec<String> {
    let Some(template) = settings.templates.get(name) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = template
        .credentials
        .iter()
        .map(|(credential, path)| {
            let verdict = check_source(path, 0, CREDENTIALS_TOTAL_BYTES_MAX)
                .map_or_else(|why| why, |size| format!("ok, {size} bytes"));
            format!(
                "template {name} credential {credential} {}: {verdict}",
                path.display()
            )
        })
        .collect();
    if !template.credentials.is_empty()
        && let Err(why) = walled_node(settings)
    {
        lines.push(format!("template {name}: {why}"));
    }
    lines
}

#[cfg(test)]
mod tests;
