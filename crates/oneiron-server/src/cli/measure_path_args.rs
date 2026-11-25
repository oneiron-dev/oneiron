//! `oneiron execution-node measure-path`: the path measurement of the first
//! job's step 2 (pass 33, `33-exec-node/DESIGN.md` section 12, "R6 in five
//! steps"). Run `key` on the issuer, `listen` on the node with the key's
//! endpoint, then `dial` on the issuer with the listener's endpoint. Neither
//! end opens a vault or reads a grant.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand};

use crate::gpu_execution_node::wire::FETCH_MAX_BYTES;

#[derive(Args, Clone, Debug)]
pub struct ExecutionNodeMeasurePathArgs {
    #[command(subcommand)]
    pub command: MeasurePathCommand,
}

#[derive(Subcommand, Clone, Debug)]
pub enum MeasurePathCommand {
    /// Write the dialer's key to a new file (mode 0600) and print its
    /// endpoint key, for `listen --peer`.
    Key(MeasurePathKeyArgs),
    /// On the node: answer the one dialer named by `--peer`, on the direct
    /// path, until `--max-secs` pass or `--connections` connections ended.
    /// Prints this end's endpoint key first, for `dial --peer`.
    Listen(MeasurePathListenArgs),
    /// On the issuer: dial the listener, print one line per sample, then
    /// each kind's summary and the path the connection used.
    Dial(MeasurePathDialArgs),
}

#[derive(Args, Clone, Debug)]
pub struct MeasurePathKeyArgs {
    /// The key file to create; an existing file is never replaced.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Args, Clone, Debug)]
pub struct MeasurePathListenArgs {
    /// The UDP address to listen on, e.g. `0.0.0.0:7979`.
    #[arg(long)]
    pub bind: SocketAddr,
    /// The dialer's endpoint key (64 hex digits), as `key` printed it.
    #[arg(long)]
    pub peer: String,
    /// Stop after this many seconds whatever was served.
    #[arg(long, default_value_t = 600)]
    pub max_secs: u64,
    /// Stop once this many connections have ended.
    #[arg(long, default_value_t = 1)]
    pub connections: u32,
}

#[derive(Args, Clone, Debug)]
pub struct MeasurePathDialArgs {
    /// The key file `key` wrote.
    #[arg(long)]
    pub key: PathBuf,
    /// The listener's endpoint key (64 hex digits), as `listen` printed it.
    #[arg(long)]
    pub peer: String,
    /// The listener's address on the direct path, e.g. `192.168.1.20:7979`.
    #[arg(long)]
    pub addr: SocketAddr,
    /// The UDP address this end binds.
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: SocketAddr,
    /// Control round trips to take.
    #[arg(long, default_value_t = 50)]
    pub control_samples: u32,
    /// The bytes a control request stands for (a `Node` or `Status`).
    #[arg(long, default_value_t = 256)]
    pub control_request_bytes: u64,
    /// The bytes a control answer stands for.
    #[arg(long, default_value_t = 4096)]
    pub control_answer_bytes: u64,
    /// Result fetches to take.
    #[arg(long, default_value_t = 5)]
    pub fetch_samples: u32,
    /// The bytes of one fetched result: at most one `Fetch` answer.
    #[arg(long, default_value_t = FETCH_MAX_BYTES)]
    pub fetch_bytes: u64,
    /// The longest the dial or one sample may take.
    #[arg(long, default_value_t = 10)]
    pub timeout_secs: u64,
}
