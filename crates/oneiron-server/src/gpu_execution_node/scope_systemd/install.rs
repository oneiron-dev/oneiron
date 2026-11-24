//! `oneiron execution-node install` (root, once per machine and again after
//! a template's maximum grows; pass 33, 7.6; EM-4 = A): the one privileged
//! step. It makes the job account, writes the root-owned unit template and
//! the rule that lets the engine's account start and stop its instances and
//! nothing else, makes the state and payload directories the engine's, and
//! reloads the service manager. It is idempotent: a second run with the same
//! inputs changes nothing.

use std::path::{Path, PathBuf};

use super::super::node_settings::ExecutionNodeSettings;
use super::safe_fs::{account, require_root_owned};
use super::systemd_unit::{SYSTEMCTL_TIMEOUT, run_tool, tool_path};
use super::unit_file::{
    UnitInputs, plain_account, render_job_unit, render_polkit_rule, unit_path_word,
};
use super::{POLKIT_RULE_PATH, UNIT_TEMPLATE_PATH};

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
        job_account: settings.job_account.clone(),
        state_dir: settings.state_dir.clone(),
        work_dir: settings.work_dir.clone(),
        protected,
        runtime_max_secs,
        stop_grace_secs: settings.stop_grace_secs,
        start_timeout_secs: settings.unit_start_timeout_secs,
    };
    for path in [&inputs.binary, &inputs.node_file, &inputs.state_dir, &inputs.work_dir]
        .into_iter()
        .chain(inputs.protected.iter())
    {
        unit_path_word(path)?;
    }
    let unit = render_job_unit(&inputs);
    let rule = render_polkit_rule(&request.engine_account);
    if request.dry_run {
        println!("--- {UNIT_TEMPLATE_PATH}\n{unit}--- {POLKIT_RULE_PATH}\n{rule}");
        print_templates(&settings);
        return Ok(());
    }
    if !Path::new("/etc/polkit-1").is_dir() {
        return Err(
            "polkit is not installed: the engine's account could not start job units (install the polkit package)"
                .to_owned(),
        );
    }
    ensure_job_account(&settings.job_account)?;
    ensure_dir(&inputs.state_dir, engine_uid, engine_gid, 0o700)?;
    ensure_dir(&inputs.state_dir.join("control"), engine_uid, engine_gid, 0o700)?;
    ensure_dir(&inputs.work_dir, engine_uid, engine_gid, 0o755)?;
    let unit_changed = write_if_changed(Path::new(UNIT_TEMPLATE_PATH), &unit)?;
    let rule_changed = write_if_changed(Path::new(POLKIT_RULE_PATH), &rule)?;
    if unit_changed {
        run_tool("systemctl", &["daemon-reload"], SYSTEMCTL_TIMEOUT)?;
    }
    println!(
        "installed: {UNIT_TEMPLATE_PATH} ({}), {POLKIT_RULE_PATH} ({}), job account {}, RuntimeMaxSec {runtime_max_secs}",
        if unit_changed { "written" } else { "unchanged" },
        if rule_changed { "written" } else { "unchanged" },
        settings.job_account
    );
    print_templates(&settings);
    println!("next: `oneiron execution-node check` as root proves each bound in a probe unit");
    Ok(())
}

fn print_templates(settings: &ExecutionNodeSettings) {
    for name in settings.templates.keys() {
        if let Some(digest) = settings.template_digest(name) {
            println!("template {name} digest {digest}");
        }
    }
}

/// Makes the job account as a system account with no login and no home,
/// unless it exists.
fn ensure_job_account(name: &str) -> Result<(), String> {
    if account(name).is_ok() {
        return Ok(());
    }
    let shell = ["/usr/sbin/nologin", "/usr/bin/nologin", "/sbin/nologin"]
        .into_iter()
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

fn ensure_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            if meta.uid() != uid {
                return Err(format!(
                    "{}: owned by uid {}, not the engine's account (uid {uid})",
                    path.display(),
                    meta.uid()
                ));
            }
            Ok(())
        }
        Ok(_) => Err(format!("{}: not a directory", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(|error| format!("{}: {error}", path.display()))?;
            std::os::unix::fs::chown(path, Some(uid), Some(gid))
                .map_err(|error| format!("{}: {error}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .map_err(|error| format!("{}: {error}", path.display()))
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
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
