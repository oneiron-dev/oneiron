//! `oneiron execution-node`: this machine's execution node, at the box (pass
//! 33, `33-exec-node/DESIGN.md` section 6, "On the node, not verbs"). Each
//! command edits the node's root-owned `[execution_node]` file's markers, or
//! the drain and the state directory beside them; no remote party can, and
//! no verb does. The engine reads them fresh at each admission and on each
//! authority tick. `install`, `unit-name` and `unit-control` are row R3b's
//! (Linux with systemd).

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum ExecutionNodeCommand {
    /// Measure the path between the issuer and this node before the first
    /// job: the control round trip and a result fetch, as samples and byte
    /// counts (`key` and `dial` on the issuer, `listen` on the node).
    MeasurePath(super::measure_path_args::ExecutionNodeMeasurePathArgs),
    /// Print what would refuse a job here now; exit 1 when anything would.
    Check(Box<ExecutionNodeServeArgs>),
    /// Take new work again after a `disable`.
    Enable(ExecutionNodeFileArgs),
    /// Refuse new work; with `--stop`, also stop every job the node runs.
    /// Receipts stay collectable.
    Disable(ExecutionNodeDisableArgs),
    /// Refuse new work while the running jobs go on (noise, heat,
    /// maintenance), saying why.
    Pause(ExecutionNodePauseArgs),
    /// Take new work again after a `pause`.
    Unpause(ExecutionNodeFileArgs),
    /// Clear this machine's drain (its GPU slot table's): it takes new work
    /// again, and its count of failed jobs starts over.
    Resume(Box<ExecutionNodeServeArgs>),
    /// After a lost journal, or after any restore of the state directory
    /// from a copy: set the old journal and its epoch aside, so the engine's
    /// next start opens a new journal under a new epoch.
    ResetHistory(ExecutionNodeResetHistoryArgs),
    /// As root, once: make the job account, write the root-owned job unit
    /// template and the job control socket through which the engine's
    /// account starts and stops its instances and nothing else. Run it again
    /// after a template's maximum grows.
    Install(ExecutionNodeInstallArgs),
    /// Print the job unit of a job key (`oneiron-job@<id>.service`), for
    /// `systemctl` and `journalctl`.
    UnitName(ExecutionNodeUnitNameArgs),
    /// Start or stop the job unit of a job key, or send it a checkpoint
    /// notice, through the job control socket, as the engine does: as the
    /// engine's account or root.
    UnitControl(ExecutionNodeUnitControlArgs),
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeInstallArgs {
    #[command(flatten)]
    pub node: ExecutionNodeFileArgs,
    /// The account `oneiron serve` runs as: it may start and stop job units.
    #[arg(long)]
    pub engine_account: String,
    /// A path no job may open, besides the state directory and the engine
    /// account's home: the vault's trees or the keystore when they live
    /// elsewhere. Repeat for each.
    #[arg(long)]
    pub protect: Vec<PathBuf>,
    /// Print the unit template and the control socket's units, and write
    /// nothing.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeUnitNameArgs {
    /// The job key.
    pub key: String,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeUnitControlArgs {
    /// `start`, `stop`, `signal` or `usage`.
    pub verb: String,
    /// The job key.
    pub key: String,
    /// For `signal`: the checkpoint signal's name (HUP, INT, USR1, USR2 or
    /// WINCH). For `usage`: the bound in bytes past which root stops
    /// counting the payload.
    pub argument: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeFileArgs {
    /// The node's `[execution_node]` file. Default:
    /// `$ONEIRON_EXECUTION_NODE_FILE`, else
    /// `/etc/oneiron/execution-node.toml`.
    #[arg(long)]
    pub file: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeServeArgs {
    #[command(flatten)]
    pub node: ExecutionNodeFileArgs,
    /// The server's configuration, for its `[gpu_jobs.devices]` drain.
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeDisableArgs {
    #[command(flatten)]
    pub node: ExecutionNodeFileArgs,
    /// Also stop every job the node runs, on the engine's next tick.
    #[arg(long)]
    pub stop: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodePauseArgs {
    #[command(flatten)]
    pub node: ExecutionNodeFileArgs,
    /// Why the node takes no new work: the issuer and the owner read it.
    pub why: String,
}

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeResetHistoryArgs {
    #[command(flatten)]
    pub node: ExecutionNodeFileArgs,
    /// Required: the engine on this machine is stopped, so no journal is
    /// open while it is set aside.
    #[arg(long)]
    pub engine_stopped: bool,
}
