//! `oneiron execution-node`: this machine's execution node, at the box (pass
//! 33, `33-exec-node/DESIGN.md` section 6, "On the node, not verbs"). Each
//! command edits the node's root-owned `[execution_node]` file's markers, or
//! the drain and the state directory beside them; no remote party can, and
//! no verb does. The engine reads them fresh at each admission and on each
//! authority tick. `install` is row R3b's.

use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::config::ServeArgs;

#[derive(Subcommand, Clone, Debug)]
pub enum ExecutionNodeCommand {
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
