//! The gate runner's command line, shared by docedit's `deck-gate-cases`
//! and the engine's `deck-gate-engine`, which passes its two-peer Loro merge.
//!
//! Exit status: 0 when every engine half passed, 1 when the run was written
//! but an engine half failed or stayed open, 2 when no complete run was
//! written (the journal keeps whatever cases finished).

use super::{PeerMerge, RunOptions, run};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: --out <new dir> [--repo <repo root>] [--corpus <dir>] [--source <full commit>] [--schemas <dir>]";

fn options(
    mut args: impl Iterator<Item = String>,
    peers: Option<PeerMerge>,
) -> Result<RunOptions, String> {
    let mut repo = PathBuf::from(".");
    let (mut out, mut corpus, mut source, mut schemas) = (None, None, None, None);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => repo = PathBuf::from(value()?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--corpus" => corpus = Some(PathBuf::from(value()?)),
            "--source" => source = Some(value()?),
            "--schemas" => schemas = Some(PathBuf::from(value()?)),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(RunOptions {
        repo,
        out: out.ok_or("--out is required")?,
        corpus,
        source,
        schemas,
        peers,
    })
}

/// Run the gate's engine half from `args` (the program name skipped) as
/// `name`, with the engine's Loro merge when the binary has one.
pub fn main_with(
    name: &str,
    args: impl Iterator<Item = String>,
    peers: Option<PeerMerge>,
) -> ExitCode {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let options = match options(args, peers) {
        Ok(options) => options,
        Err(why) => {
            let _ = writeln!(stderr, "{name}: {why}\n{name} {USAGE}");
            return ExitCode::from(2);
        }
    };
    let _ = writeln!(stderr, "{name}: writing {}", options.out.display());
    match run(&options) {
        Ok(summary) => {
            for line in &summary.lines {
                let _ = writeln!(stdout, "{line}");
            }
            let _ = writeln!(stdout, "manifest: {}", summary.manifest.display());
            if summary.engine_passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(why) => {
            let _ = writeln!(stderr, "{name}: {why}");
            ExitCode::from(2)
        }
    }
}
