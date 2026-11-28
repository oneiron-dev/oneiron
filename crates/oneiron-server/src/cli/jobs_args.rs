//! `oneiron jobs …`: run a pinned workload on the vault's own machines the way `fleet run` runs a
//! job, as the one booker agent ([`crate::commands::jobs`]; docs/ops/jobs-booker.md).

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// `oneiron jobs`.
#[derive(Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum JobsCommand {
    /// Pin a workload, order it, follow its logs and exit with its code. TERM or INT cancels
    /// the order; HUP changes nothing.
    Run(Box<JobsRunArgs>),
    /// Follow an order made earlier (`run --detach`) to its end, and exit with its code. TERM
    /// or INT cancels it, as `run` does.
    Follow(Box<JobsFollowArgs>),
}

/// Where the issuer is, and the booker agent's credential.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct JobsConnectArgs {
    /// The issuer's origin, as `oneiron api` takes it. This command opens no listener and no
    /// bind of its own: a server that listens on its loopback only is reached through a tunnel.
    #[arg(
        long = "url",
        env = "ONEIRON_URL",
        default_value = "http://127.0.0.1:9090"
    )]
    pub base_url: String,

    /// File holding the booker agent's paired credential, as `token agent --out` writes it.
    /// Only its owner may be able to read it. Without it the slip and its seed come from the
    /// two variables below.
    #[arg(long, value_name = "FILE")]
    pub credential_file: Option<PathBuf>,

    /// Environment variable holding the booker's bearer slip, as `oneiron api` takes it.
    #[arg(long, default_value = "ONEIRON_SECRET")]
    pub secret_env: String,

    /// Environment variable with the slip's Ed25519 binding seed (64 hex).
    #[arg(long, default_value = "ONEIRON_BINDING_KEY")]
    pub binding_key_env: String,

    /// Connect to this address for the origin's host name (curl `--resolve`), as `oneiron api`
    /// takes it; repeat it for several.
    #[arg(long, value_name = "IP")]
    pub resolve_address: Vec<String>,

    /// Give one call up after this many seconds. The default, 75, is above the 60 s a log read
    /// may wait, so a waiting read is never cut.
    #[arg(
        long,
        env = "ONEIRON_API_MAX_TIME",
        value_name = "SECS",
        default_value_t = 75
    )]
    pub max_time: u64,
}

/// `oneiron jobs run`: the workload, where it may run, and how to wait.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct JobsRunArgs {
    #[command(flatten)]
    pub connect: JobsConnectArgs,

    /// The node template it runs in, e.g. `oneiron-check`.
    #[arg(long)]
    pub template: String,

    /// The code revision, 40 lower hex. It must be in the node's mirror before the order.
    #[arg(long)]
    pub commit: String,

    /// The entry, a path in the commit that the template admits.
    #[arg(long, value_name = "PATH")]
    pub entry: String,

    /// The contract file, a path in the commit; its sha256 is read from the commit in `--repo`.
    #[arg(long, value_name = "PATH")]
    pub contract: String,

    /// The git checkout that holds the commit. Default: the working directory.
    #[arg(long, value_name = "DIR")]
    pub repo: Option<PathBuf>,

    /// The PROJECT the pin works for (32 hex): the one the booker's `compute.pin` grant covers.
    #[arg(long, env = "ONEIRON_BOOKER_PROJECT")]
    pub project: Option<String>,

    /// The offer that charges it, by name.
    #[arg(long, env = "ONEIRON_BOOKER_OFFER")]
    pub offer: String,

    /// A machine it may run on, by the name the vault shows or its id (32 hex); repeat it for
    /// several. None: every machine the workload's approval names.
    #[arg(long = "host", value_name = "NAME|ID")]
    pub hosts: Vec<String>,

    /// Host memory, e.g. `28G` or `512M`.
    #[arg(long, value_name = "SIZE")]
    pub mem: String,

    /// Disk it writes on the node, e.g. `60G`.
    #[arg(long, value_name = "SIZE")]
    pub disk: String,

    /// Threads; 0 takes the template's default.
    #[arg(long, default_value_t = 0)]
    pub threads: u32,

    /// Its maximum run time, e.g. `3h`, `90m` or `600s`: the node stops it there.
    #[arg(long, value_name = "DURATION")]
    pub timeout: String,

    /// GPUs: `COUNT[:MIN-MEMORY-MIB[:FEATURE,...]]`, e.g. `1:20000:cuda`. None: a CPU-only run.
    #[arg(long = "gpu", value_name = "CLAIM")]
    pub gpus: Vec<String>,

    /// `none` (the default) or `host`: the network the run sees.
    #[arg(long, default_value = "none")]
    pub network: String,

    /// An output the run writes under its `out/`, kept on the node; repeat it for several.
    #[arg(long = "output", value_name = "NAME")]
    pub outputs: Vec<String>,

    /// An output the issuer may fetch, where the template marks the name returnable too.
    #[arg(long = "returnable-output", value_name = "NAME")]
    pub returnable_outputs: Vec<String>,

    /// `interactive`, `normal` (the default) or `background`: who goes first among runnable
    /// orders.
    #[arg(long, default_value = "normal")]
    pub class: String,

    /// An end to retry once: `exited:<code>`, `memory_limit`, `disk_limit`, `time_limit`,
    /// `lost`, `never_started` or `expired`; repeat it for several.
    #[arg(long = "retry-on", value_name = "END")]
    pub retry_on: Vec<String>,

    /// The order's intent key (1 to 128 bytes): the same key with the same input answers the
    /// order it made.
    #[arg(long)]
    pub key: Option<String>,

    /// Make the order, print its id and exit 0; `oneiron jobs follow` follows it.
    #[arg(long)]
    pub detach: bool,

    /// Refuse at once, exit 75, when it cannot run now.
    #[arg(long)]
    pub no_wait: bool,

    /// The arguments the entry is run with, after `--`; no shell reads them.
    #[arg(last = true, value_name = "ARGS")]
    pub args: Vec<String>,
}

/// `oneiron jobs follow`: one order by its id.
#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct JobsFollowArgs {
    #[command(flatten)]
    pub connect: JobsConnectArgs,

    /// The order's id (32 hex), as `run --detach` printed it.
    pub order: String,
}
