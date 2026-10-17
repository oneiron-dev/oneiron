//! Host-side, per-config-directory wake delivery (OF-385).
//!
//! `mcp --wake-config <config-dir>/wake.toml` runs the adapter for the life
//! of the bridge. The TOML fields are `inbox` (default true), `helper`
//! (`program`, `args`), `tmux_target` and `boot` (`program`, `args`). An
//! enabled inbox is consumed by `wake --config <file> inbox`, optionally as
//! a Claude Code Stop hook. Set `inbox = false` for immediate helper/pane
//! delivery. Helpers take a JSON batch on stdin; exit zero acknowledges it.
//! A boot command takes that same batch as its initial stdin, not shell text.
//! Live helper/pane/boot delivery also carries coalesced STREAM frames; the
//! offline inbox stores notices only, never frame replay.
//! Nothing here selects policy for human notifications or lives in the engine.

pub(crate) mod board_stream;
mod delivery;
mod inbox;

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use oneiron::context_board::{BoardStreamFrame, WakeEnvelope};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::cli::{WakeArgs, WakeCommand};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "inbox_enabled")]
    inbox: bool,
    helper: Option<AdapterCommand>,
    tmux_target: Option<String>,
    boot: Option<AdapterCommand>,
}

fn inbox_enabled() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterCommand {
    program: PathBuf,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Serialize)]
struct WakeBatch<'a> {
    instance_key: &'a str,
    wakes: &'a [WakeEnvelope],
    frames: &'a [BoardStreamFrame],
}

pub(crate) struct Instance {
    pub(crate) key: String,
    config: Config,
    inbox: inbox::Inbox,
}

impl Instance {
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let path = std::path::absolute(path)?;
        let directory = fs::canonicalize(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("wake config has no parent directory"))?,
        )?;
        let config: Config = toml::from_str(&fs::read_to_string(&path)?)?;
        anyhow::ensure!(
            config.inbox
                || config.helper.is_some()
                || config.tmux_target.is_some()
                || config.boot.is_some(),
            "wake config must enable at least one delivery adapter"
        );
        for command in [&config.helper, &config.boot].into_iter().flatten() {
            anyhow::ensure!(
                !command.program.as_os_str().is_empty(),
                "empty wake program"
            );
        }
        if let Some(target) = &config.tmux_target {
            anyhow::ensure!(!target.trim().is_empty(), "empty wake tmux target");
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron.wake.config-directory.v1");
        hash.update(directory.as_os_str().as_encoded_bytes());
        Ok(Self {
            key: hash.finalize().to_hex().to_string(),
            config,
            inbox: inbox::Inbox::new(directory.join("oneiron-wakes")),
        })
    }
}

pub(crate) fn command(args: WakeArgs) -> anyhow::Result<()> {
    let instance = Instance::load(&args.config)?;
    // Two simultaneous lifecycle hooks must not both consume the same mail.
    let _lock = instance.inbox.lock()?;
    match args.command {
        WakeCommand::Inbox { claude_code_stop } => {
            let wakes = instance.inbox.pending()?;
            let output = if claude_code_stop {
                if wakes.is_empty() {
                    json!({})
                } else {
                    json!({
                        "decision": "block",
                        "reason": serde_json::to_string(&WakeBatch {
                            instance_key: &instance.key,
                            wakes: &wakes,
                            frames: &[],
                        })?,
                    })
                }
            } else {
                serde_json::to_value(WakeBatch {
                    instance_key: &instance.key,
                    wakes: &wakes,
                    frames: &[],
                })?
            };
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{output}")?;
            stdout.flush()?;
            for wake in wakes {
                instance.inbox.acknowledge(&wake.event_ref)?;
            }
        }
        WakeCommand::Ack { event_ref } => {
            for event_ref in event_ref {
                instance.inbox.acknowledge(&event_ref)?;
            }
        }
    }
    Ok(())
}
