//! `oneiron execution-node`: this machine's execution node, at the box (pass
//! 33, `33-exec-node/DESIGN.md` section 6). The commands write and remove the
//! markers beside the node's `[execution_node]` file (`.disabled`,
//! `.paused`), clear the GPU slot table's drain file, and set a lost journal
//! aside. The running engine reads each of them fresh: a marker counts at
//! the next admission and on the next authority tick.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::cli::{ExecutionNodeCommand, ExecutionNodeFileArgs, ExecutionNodeServeArgs};
use crate::gpu_execution_node::node::{
    DISABLED_MARKER_EXTENSION, DISABLED_STOP_LINE, PAUSED_MARKER_EXTENSION, disk_free_bytes,
    execution_node_file, marker_beside,
};
use crate::gpu_execution_node::{ExecutionNodeSettings, NodeControls};

mod measure_path;

/// The journal's file in the state directory (design 5.2; row R3a's
/// `JOURNAL_FILE_NAME`).
const JOURNAL_FILE_NAME: &str = "journal";

/// The journal's epoch file in the state directory (design 5.2; row R3a's
/// `EPOCH_FILE_NAME`).
const EPOCH_FILE_NAME: &str = "epoch";

/// The directory under the state directory a reset sets an old journal
/// aside in, with the time of the reset.
const LOST_HISTORY_PREFIX: &str = "lost-history-";

/// Runs one `oneiron execution-node` command.
///
/// # Errors
///
/// A marker or file that could not be written or removed; for `check`, any
/// condition that would refuse a job.
pub fn execution_node(command: ExecutionNodeCommand) -> anyhow::Result<()> {
    let mut output = std::io::stdout().lock();
    match command {
        ExecutionNodeCommand::MeasurePath(args) => {
            // The measurement writes each report line itself, as it is taken.
            drop(output);
            measure_path::measure_path(args)
        }
        ExecutionNodeCommand::Check(args) => check(&args, &mut output),
        ExecutionNodeCommand::Enable(args) => {
            remove_marker(&marker(&args, DISABLED_MARKER_EXTENSION))?;
            writeln!(output, "enabled: the node takes new work again")?;
            Ok(())
        }
        ExecutionNodeCommand::Disable(args) => {
            let line = if args.stop {
                DISABLED_STOP_LINE
            } else {
                "disabled"
            };
            write_marker(&marker(&args.node, DISABLED_MARKER_EXTENSION), line)?;
            if args.stop {
                writeln!(
                    output,
                    "disabled: no new work; every job the node runs stops on the next tick"
                )?;
            } else {
                writeln!(output, "disabled: no new work; running jobs go on")?;
            }
            Ok(())
        }
        ExecutionNodeCommand::Pause(args) => {
            let why = args.why.trim();
            anyhow::ensure!(!why.is_empty(), "pause needs a reason");
            write_marker(&marker(&args.node, PAUSED_MARKER_EXTENSION), why)?;
            writeln!(output, "paused: no new work; running jobs go on ({why})")?;
            Ok(())
        }
        ExecutionNodeCommand::Unpause(args) => {
            remove_marker(&marker(&args, PAUSED_MARKER_EXTENSION))?;
            writeln!(output, "unpaused: the node takes new work again")?;
            Ok(())
        }
        ExecutionNodeCommand::Resume(args) => resume(&args, &mut output),
        ExecutionNodeCommand::ResetHistory(args) => {
            anyhow::ensure!(
                args.engine_stopped,
                "reset-history sets the journal aside: stop the engine on this machine, then run it again with --engine-stopped"
            );
            reset_history(&node_file(&args.node), &mut output)
        }
        ExecutionNodeCommand::Install(args) => install(&args),
        ExecutionNodeCommand::UnitName(args) => unit_name(&args.key),
        ExecutionNodeCommand::UnitControl(args) => {
            unit_control(&args.verb, &args.key, args.signal.as_deref())
        }
    }
}

/// The node's file the command names, else the default.
fn node_file(args: &ExecutionNodeFileArgs) -> PathBuf {
    execution_node_file(args.file.as_deref())
}

/// The marker with `extension` beside the command's node file.
fn marker(args: &ExecutionNodeFileArgs, extension: &str) -> PathBuf {
    marker_beside(&node_file(args), extension)
}

fn write_marker(path: &Path, line: &str) -> anyhow::Result<()> {
    std::fs::write(path, format!("{line}\n"))
        .with_context(|| format!("write the marker {}", path.display()))
}

fn remove_marker(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove the marker {}", path.display())),
    }
}

/// The server's drain file, from its `[gpu_jobs.devices]`.
fn drain_file(args: &ExecutionNodeServeArgs) -> anyhow::Result<Option<PathBuf>> {
    let config = crate::config::resolve_serve_config(&args.serve)?;
    Ok(config.gpu_jobs.devices.drain_file)
}

/// The first line of a marker or drain file, while it exists.
fn first_line(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or("")
            .to_owned(),
    )
}

fn resume(args: &ExecutionNodeServeArgs, output: &mut impl Write) -> anyhow::Result<()> {
    let Some(drain) = drain_file(args)? else {
        writeln!(
            output,
            "this machine names no [gpu_jobs.devices] drain_file: a drain lives in the engine's memory only, and a restart of the engine clears it"
        )?;
        return Ok(());
    };
    match std::fs::remove_file(&drain) {
        Ok(()) => {
            writeln!(
                output,
                "resumed: the drain at {} is cleared",
                drain.display()
            )?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            writeln!(
                output,
                "no drain file at {}: the node is not drained on disk. A drain the engine could not write is kept in its memory, and a restart of the engine clears it",
                drain.display()
            )?;
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("remove the drain {}", drain.display())),
    }
}

/// `check`: what would refuse a job here now.
fn check(args: &ExecutionNodeServeArgs, output: &mut impl Write) -> anyhow::Result<()> {
    let file = node_file(&args.node);
    writeln!(output, "file: {}", file.display())?;
    let settings = match ExecutionNodeSettings::read(&file) {
        Ok(Some(settings)) => settings,
        Ok(None) => anyhow::bail!("no node file: this machine runs no jobs"),
        Err(why) => anyhow::bail!("the node file does not validate: {why}"),
    };
    let disabled = first_line(&marker_beside(&file, DISABLED_MARKER_EXTENSION));
    let drain = drain_file(args)?;
    let controls = NodeControls {
        enabled: settings.enabled && disabled.is_none(),
        paused: first_line(&marker_beside(&file, PAUSED_MARKER_EXTENSION)),
        drained: drain.as_deref().and_then(first_line),
        stop_requested: disabled.as_deref() == Some(DISABLED_STOP_LINE),
    };
    let mut refusals: Vec<String> = controls.refusal().into_iter().collect();
    writeln!(output, "enabled in the file: {}", settings.enabled)?;
    if let Some(line) = &disabled {
        writeln!(output, "disabled at the box: {line}")?;
    }
    writeln!(
        output,
        "issuers: {}",
        settings
            .issuers
            .iter()
            .map(|issuer| issuer.to_hex())
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(output, "scopes: {:?}", settings.scopes)?;
    match settings.template_offers() {
        Ok(offers) if offers.is_empty() => refusals.push("no template".to_owned()),
        Ok(offers) => {
            for offer in offers {
                writeln!(
                    output,
                    "template {}: digest {} scopes {:?} network {:?} returnable {:?}",
                    offer.name, offer.digest, offer.scopes, offer.network, offer.returnable
                )?;
            }
        }
        Err(why) => refusals.push(why),
    }
    for (name, dir, floor_bytes) in [
        (
            "state_dir",
            &settings.state_dir,
            settings.state_floor_mib.saturating_mul(1 << 20),
        ),
        (
            "work_dir",
            &settings.work_dir,
            settings.disk_reserve_bytes(),
        ),
    ] {
        match disk_free_bytes(dir) {
            Ok(free) => {
                writeln!(
                    output,
                    "{name}: {} free {} MiB, keeps {} MiB",
                    dir.display(),
                    free >> 20,
                    floor_bytes >> 20
                )?;
                if free < floor_bytes {
                    refusals.push(format!("{name} below its floor"));
                }
            }
            Err(error) => refusals.push(format!("{name} {}: {error}", dir.display())),
        }
    }
    #[cfg(unix)]
    match work_dir_check_account() {
        Ok((access, who)) => match work_dir_chain_line(&settings.work_dir, &who, &access) {
            Ok(line) => writeln!(output, "{line}")?,
            Err(why) => {
                writeln!(output, "work_dir chain: {why}")?;
                refusals.push(why);
            }
        },
        Err(why) => refusals.push(why),
    }
    // The job unit (row R3b): each bound's strength, proved in a probe unit
    // when run as root.
    #[cfg(target_os = "linux")]
    refusals.extend(
        crate::gpu_execution_node::scope_systemd::probe_unit::check_scope(&file, &settings),
    );
    #[cfg(not(target_os = "linux"))]
    refusals.push(
        "this platform has no job scope yet (pass 34: the systemd scope is Linux's)".to_owned(),
    );
    if refusals.is_empty() {
        writeln!(
            output,
            "would refuse a job: nothing here (the issuer's grants are checked at each request)"
        )?;
        Ok(())
    } else {
        anyhow::bail!("would refuse a job: {}", refusals.join("; "))
    }
}

/// The engine account named in the installed unit, or the current account,
/// with its file access.
#[cfg(unix)]
fn work_dir_check_account() -> Result<
    (
        crate::gpu_execution_node::jobs::staging::WorkDirAccess,
        String,
    ),
    String,
> {
    use crate::gpu_execution_node::jobs::staging::WorkDirAccess;

    let this_account = WorkDirAccess::this_process()?;
    #[cfg(target_os = "linux")]
    let who = {
        use crate::gpu_execution_node::scope_systemd::{UNIT_TEMPLATE_PATH, safe_fs, unit_file};

        if let Ok(text) = std::fs::read_to_string(UNIT_TEMPLATE_PATH)
            && let Some(name) = unit_file::installed_engine_account(&text)
        {
            let (uid, gid, _) = safe_fs::account(name).map_err(|error| {
                format!("the job unit names the engine account {name}: {error}")
            })?;
            let groups = safe_fs::account_groups(name, gid)
                .map_err(|error| format!("the groups of the engine account {name}: {error}"))?;
            return Ok((
                WorkDirAccess { uid, gid, groups },
                format!("the engine account {name} (uid {uid}, from {UNIT_TEMPLATE_PATH})"),
            ));
        }
        format!(
            "this account (uid {}; no job unit names the engine account)",
            this_account.uid
        )
    };
    #[cfg(not(target_os = "linux"))]
    let who = "this account".to_owned();
    Ok((this_account, who))
}

/// Describes the work directory rule's read-only verdict for the named
/// account, judged with its own file access (review r1 of #10575).
#[cfg(unix)]
fn work_dir_chain_line(
    work_dir: &Path,
    who: &str,
    access: &crate::gpu_execution_node::jobs::staging::WorkDirAccess,
) -> Result<String, String> {
    use crate::gpu_execution_node::jobs::staging::{
        WorkDirFault, WorkDirVerdict, work_dir_verdict_for,
    };

    match work_dir_verdict_for(work_dir, access).map_err(|why| {
        format!(
            "work_dir {}: not judged for {who}: {why}",
            work_dir.display()
        )
    })? {
        WorkDirVerdict::Passes(dir) => Ok(format!(
            "work_dir chain: {} passes for {who}",
            dir.display()
        )),
        WorkDirVerdict::Missing {
            first_missing,
            engine_may_make: true,
        } => Ok(format!(
            "work_dir chain: {} is not there yet (staging makes it); the path to it passes for {who}",
            first_missing.display()
        )),
        WorkDirVerdict::Missing {
            first_missing,
            engine_may_make: false,
        } => {
            let parent = first_missing.parent().unwrap_or(Path::new("/")).display();
            Err(format!(
                "work_dir {}: {} is not there, and {who} may not make it in {} \
                 (no write and search access): staging fails every job (checkout_failed); run \
                 `execution-node install` as root to make it, or pick another work_dir",
                work_dir.display(),
                first_missing.display(),
                parent
            ))
        }
        WorkDirVerdict::Unsafe(u) => {
            let failed = matches!(&u.fault, WorkDirFault::EngineMayNotWrite);
            let outcome = if failed {
                "staging fails every job (checkout_failed)"
            } else {
                "staging refuses every job (work_dir_unsafe)"
            };
            Err(format!(
                "work_dir {}: {}, judged for {who}: {outcome}",
                u.path.display(),
                u.fault
            ))
        }
    }
}

/// `reset-history`: moves the journal and its epoch into a new
/// `lost-history-<ms>` directory of the state directory.
fn reset_history(file: &Path, output: &mut impl Write) -> anyhow::Result<()> {
    let settings = match ExecutionNodeSettings::read(file) {
        Ok(Some(settings)) => settings,
        Ok(None) => anyhow::bail!("no node file at {}", file.display()),
        Err(why) => anyhow::bail!("the node file does not validate: {why}"),
    };
    let state = &settings.state_dir;
    let present: Vec<&str> = [JOURNAL_FILE_NAME, EPOCH_FILE_NAME]
        .into_iter()
        .filter(|name| state.join(name).exists())
        .collect();
    if present.is_empty() {
        writeln!(
            output,
            "no journal in {}: nothing to reset",
            state.display()
        )?;
        return Ok(());
    }
    let at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis());
    let aside = state.join(format!("{LOST_HISTORY_PREFIX}{at_ms}"));
    std::fs::create_dir(&aside).with_context(|| format!("create {}", aside.display()))?;
    for name in present {
        std::fs::rename(state.join(name), aside.join(name))
            .with_context(|| format!("set {name} aside into {}", aside.display()))?;
    }
    writeln!(
        output,
        "the old journal is in {}: the engine's next start opens a new journal under a new epoch",
        aside.display()
    )?;
    Ok(())
}

/// `execution-node install` (row R3b): the job unit on Linux with systemd.
#[cfg(target_os = "linux")]
fn install(args: &crate::cli::ExecutionNodeInstallArgs) -> anyhow::Result<()> {
    use crate::gpu_execution_node::scope_systemd::install::{
        InstallRequest, install as install_job_unit,
    };
    install_job_unit(&InstallRequest {
        node_file: node_file(&args.node),
        engine_account: args.engine_account.clone(),
        protect: args.protect.clone(),
        dry_run: args.dry_run,
    })
    .map_err(|why| anyhow::anyhow!("install: {why}"))
}

/// `execution-node install` has a job unit on Linux with systemd only.
#[cfg(not(target_os = "linux"))]
fn install(_args: &crate::cli::ExecutionNodeInstallArgs) -> anyhow::Result<()> {
    anyhow::bail!("install: the job unit needs Linux with systemd (pass 33, EM-4)")
}

/// `execution-node unit-name`: the job unit of a key.
#[cfg(unix)]
fn unit_name(key: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    writeln!(
        std::io::stdout().lock(),
        "{}",
        crate::gpu_execution_node::jobs::JobKeyId::for_key(key).unit_name()
    )?;
    Ok(())
}

/// `execution-node unit-control`: the engine's own start or stop of a key's
/// job unit, or a checkpoint notice to it, through the job control socket.
#[cfg(target_os = "linux")]
fn unit_control(verb: &str, key: &str, signal: Option<&str>) -> anyhow::Result<()> {
    use crate::gpu_execution_node::scope_systemd::control::{self, ControlVerb};
    let verb = ControlVerb::from_words(verb, signal).map_err(|why| {
        anyhow::anyhow!("unit-control: start <key>, stop <key> or signal <key> <name>: {why}")
    })?;
    let id = crate::gpu_execution_node::jobs::JobKeyId::for_key(key);
    control::request(verb, &id)
        .map_err(|why| anyhow::anyhow!("unit-control {} {id}: {why}", verb.word()))
}

/// Job units exist on Linux only.
#[cfg(not(target_os = "linux"))]
fn unit_control(_verb: &str, _key: &str, _signal: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("unit-control: the job unit needs Linux with systemd (pass 33, EM-4)")
}

/// Job units exist on Linux only.
#[cfg(not(unix))]
fn unit_name(_key: &str) -> anyhow::Result<()> {
    anyhow::bail!("unit-name: the job unit needs Linux with systemd (pass 33, EM-4)")
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;

    use super::work_dir_chain_line;

    #[test]
    fn the_checks_work_dir_line_names_the_ancestor_others_may_rename_in() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("resolved temp dir");
        let open = root.join("open");
        let open_work = open.join("work");
        let ok = root.join("ok");
        let ok_work = ok.join("work");
        for (path, mode) in [
            (&open, 0o777),
            (&open_work, 0o755),
            (&ok, 0o755),
            (&ok_work, 0o755),
        ] {
            fs::create_dir(path).expect("make test directory");
            fs::set_permissions(path, Permissions::from_mode(mode)).expect("test directory mode");
        }
        let euid = rustix::process::geteuid().as_raw();
        let me = crate::gpu_execution_node::jobs::staging::WorkDirAccess::this_process()
            .expect("this process's file access");
        let who = format!("this account (uid {euid})");
        let text = work_dir_chain_line(&open_work, &who, &me).expect_err("the open ancestor fails");
        assert!(text.contains(open.display().to_string().as_str()), "{text}");
        assert!(text.contains("mode 777"), "{text}");
        assert!(text.contains("work_dir_unsafe"), "{text}");

        let text = work_dir_chain_line(&ok_work, &who, &me)
            .expect("the path including the temp root's ancestors passes for this account");
        assert!(text.contains("passes for"), "{text}");

        if euid != 0 {
            let shut = root.join("shut");
            fs::create_dir(&shut).expect("make shut directory");
            fs::set_permissions(&shut, Permissions::from_mode(0o555)).expect("shut directory mode");
            let missing = work_dir_chain_line(&shut.join("work"), &who, &me)
                .expect_err("the engine may not make the missing work dir");
            assert!(missing.contains("checkout_failed"), "{missing}");
            assert!(missing.contains("may not make it"), "{missing}");
            let shut_text =
                work_dir_chain_line(&shut, &who, &me).expect_err("the shut directory itself fails");
            assert!(shut_text.contains("checkout_failed"), "{shut_text}");
            fs::set_permissions(&shut, Permissions::from_mode(0o755))
                .expect("restore shut directory mode");
        }
    }
}
