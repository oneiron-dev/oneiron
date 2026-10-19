//! `deck-gate-cases`: the engine half of the OF-510 deck gate runner.
//!
//! It generates the `pptx-live-v1` candidates through the current projector
//! and runs every engine step of the eight-step check, writing the
//! candidates, their SHA-256 pins, the checks PowerPoint owes each one and
//! the run manifest to a new directory. Each case is journaled in that
//! directory's `results.jsonl` as it finishes, with one progress line on
//! stderr, so a run cut short keeps every case it finished. The Office half
//! (`office/deck_gate.py` inside that directory) runs on the Mac mini and
//! assembles the oracle receipt. docs/ops/deck-gate.md has the commands.
//!
//! Exit status: 0 when every engine half passed, 1 when the run was written
//! but an engine half failed or stayed open, 2 when no complete run was
//! written (the journal keeps whatever cases finished).

use oneiron_docedit::live::oracle_run::{RunOptions, run};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: deck-gate-cases --out <new dir> [--repo <repo root>] [--corpus <dir>] [--source <revision>]";

fn options(mut args: impl Iterator<Item = String>) -> Result<RunOptions, String> {
    let mut repo = PathBuf::from(".");
    let mut out = None;
    let mut corpus = None;
    let mut source = "unknown".to_owned();
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--repo" => repo = PathBuf::from(value()?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--corpus" => corpus = Some(PathBuf::from(value()?)),
            "--source" => source = value()?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(RunOptions {
        repo,
        out: out.ok_or("--out is required")?,
        corpus,
        source,
    })
}

fn main() -> ExitCode {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let options = match options(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(why) => {
            let _ = writeln!(stderr, "deck-gate-cases: {why}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let _ = writeln!(stderr, "deck-gate-cases: writing {}", options.out.display());
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
            let _ = writeln!(stderr, "deck-gate-cases: {why}");
            ExitCode::from(2)
        }
    }
}
