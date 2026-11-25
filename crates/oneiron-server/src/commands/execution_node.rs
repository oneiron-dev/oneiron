//! `oneiron execution-node`: this machine's execution node, at the box (pass
//! 33, `33-exec-node/DESIGN.md` section 6). The commands write and remove the
//! markers beside the node's `[execution_node]` file (`.disabled`,
//! `.paused`), clear the GPU slot table's drain file, and set a lost journal
//! aside. The running engine reads each of them fresh: a marker counts at
//! the next admission and on the next authority tick.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;

use crate::cli::{ExecutionNodeCommand, ExecutionNodeFileArgs, ExecutionNodeServeArgs};
use crate::gpu_execution_node::node::{
    DISABLED_MARKER_EXTENSION, DISABLED_STOP_LINE, PAUSED_MARKER_EXTENSION, disk_free_bytes,
    execution_node_file, marker_beside,
};
use crate::gpu_execution_node::{ExecutionNodeSettings, NodeControls};

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
    match command {
        ExecutionNodeCommand::Check(args) => check(&args),
        ExecutionNodeCommand::Enable(args) => {
            remove_marker(&marker(&args, DISABLED_MARKER_EXTENSION))?;
            println!("enabled: the node takes new work again");
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
                println!("disabled: no new work; every job the node runs stops on the next tick");
            } else {
                println!("disabled: no new work; running jobs go on");
            }
            Ok(())
        }
        ExecutionNodeCommand::Pause(args) => {
            let why = args.why.trim();
            anyhow::ensure!(!why.is_empty(), "pause needs a reason");
            write_marker(&marker(&args.node, PAUSED_MARKER_EXTENSION), why)?;
            println!("paused: no new work; running jobs go on ({why})");
            Ok(())
        }
        ExecutionNodeCommand::Unpause(args) => {
            remove_marker(&marker(&args, PAUSED_MARKER_EXTENSION))?;
            println!("unpaused: the node takes new work again");
            Ok(())
        }
        ExecutionNodeCommand::Resume(args) => resume(&args),
        ExecutionNodeCommand::ResetHistory(args) => {
            anyhow::ensure!(
                args.engine_stopped,
                "reset-history sets the journal aside: stop the engine on this machine, then run it again with --engine-stopped"
            );
            reset_history(&node_file(&args.node))
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

fn resume(args: &ExecutionNodeServeArgs) -> anyhow::Result<()> {
    let Some(drain) = drain_file(args)? else {
        println!(
            "this machine names no [gpu_jobs.devices] drain_file: a drain lives in the engine's memory only, and a restart of the engine clears it"
        );
        return Ok(());
    };
    match std::fs::remove_file(&drain) {
        Ok(()) => {
            println!("resumed: the drain at {} is cleared", drain.display());
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "no drain file at {}: the node is not drained on disk. A drain the engine could not write is kept in its memory, and a restart of the engine clears it",
                drain.display()
            );
            Ok(())
        }
        Err(error) => Err(error).with_context(|| format!("remove the drain {}", drain.display())),
    }
}

/// `check`: what would refuse a job here now.
fn check(args: &ExecutionNodeServeArgs) -> anyhow::Result<()> {
    let file = node_file(&args.node);
    println!("file: {}", file.display());
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
    println!("enabled in the file: {}", settings.enabled);
    if let Some(line) = &disabled {
        println!("disabled at the box: {line}");
    }
    println!(
        "issuers: {}",
        settings
            .issuers
            .iter()
            .map(|issuer| issuer.to_hex())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("scopes: {:?}", settings.scopes);
    match settings.template_offers() {
        Ok(offers) if offers.is_empty() => refusals.push("no template".to_owned()),
        Ok(offers) => {
            for offer in offers {
                println!(
                    "template {}: digest {} scopes {:?} network {:?} returnable {:?}",
                    offer.name, offer.digest, offer.scopes, offer.network, offer.returnable
                );
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
                println!(
                    "{name}: {} free {} MiB, keeps {} MiB",
                    dir.display(),
                    free >> 20,
                    floor_bytes >> 20
                );
                if free < floor_bytes {
                    refusals.push(format!("{name} below its floor"));
                }
            }
            Err(error) => refusals.push(format!("{name} {}: {error}", dir.display())),
        }
    }
    if refusals.is_empty() {
        println!(
            "would refuse a job: nothing here (the issuer's grants are checked at each request)"
        );
        Ok(())
    } else {
        anyhow::bail!("would refuse a job: {}", refusals.join("; "))
    }
}

/// `reset-history`: moves the journal and its epoch into a new
/// `lost-history-<ms>` directory of the state directory.
fn reset_history(file: &Path) -> anyhow::Result<()> {
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
        println!("no journal in {}: nothing to reset", state.display());
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
    println!(
        "the old journal is in {}: the engine's next start opens a new journal under a new epoch",
        aside.display()
    );
    Ok(())
}
