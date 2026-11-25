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
            unit_control(&args.verb, &args.key, args.argument.as_deref())
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
/// job unit, a checkpoint notice to it, or root's measure of its payload
/// (printed as `bytes <n>`, `past <n>` or `unmeasurable <why>`), through the
/// job control socket.
#[cfg(target_os = "linux")]
fn unit_control(verb: &str, key: &str, argument: Option<&str>) -> anyhow::Result<()> {
    use crate::gpu_execution_node::scope_systemd::control::{self, ControlVerb};
    let verb = ControlVerb::from_words(verb, argument).map_err(|why| {
        anyhow::anyhow!(
            "unit-control: start <key>, stop <key>, signal <key> <name> or usage <key> <bytes>: {why}"
        )
    })?;
    let id = crate::gpu_execution_node::jobs::JobKeyId::for_key(key);
    let fail = |why: String| anyhow::anyhow!("unit-control {} {id}: {why}", verb.word());
    if let ControlVerb::Usage(stop_past) = verb {
        let usage = control::request_usage(&id, stop_past).map_err(fail)?;
        writeln!(std::io::stdout().lock(), "{}", usage.render())?;
        return Ok(());
    }
    control::request(verb, &id).map_err(fail)
}

/// Job units exist on Linux only.
#[cfg(not(target_os = "linux"))]
fn unit_control(_verb: &str, _key: &str, _argument: Option<&str>) -> anyhow::Result<()> {
    anyhow::bail!("unit-control: the job unit needs Linux with systemd (pass 33, EM-4)")
}

/// Job units exist on Linux only.
#[cfg(not(unix))]
fn unit_name(_key: &str) -> anyhow::Result<()> {
    anyhow::bail!("unit-name: the job unit needs Linux with systemd (pass 33, EM-4)")
}
