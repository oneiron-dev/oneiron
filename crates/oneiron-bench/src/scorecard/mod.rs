//! The retrieval ruler (RESEARCH-0651 Tier 0): replay a fixed query pack, grade the run.
//!
//! Three subcommands: `convert` turns the dataset into pack slices, `pack-embed`
//! fills a slice's vectors from the served embedder, and `run` replays a slice
//! into a `oneiron.retrieval_scorecard.v1`.

mod convert;
mod embed;
mod params;
mod run;

use std::collections::BTreeMap;
use std::process::ExitCode;

use oneiron_ruler::pack::Slice;

/// A scorecard failure: bad input (exit 2) or a failure while running (exit 1).
pub(crate) enum ScorecardFailure {
    /// Bad input: flags, slices, or a pack or params file that fails its contract.
    Input(String),
    /// A failure while running on valid input: vault, HTTP, or file writes.
    Run(String),
}

/// Parse `--name value` pairs into a map. An unknown name, a repeated name, a
/// bare token, or a name with no value is an input failure.
pub(crate) fn parse_flags(
    args: &[String],
    known: &[&str],
) -> Result<BTreeMap<String, String>, ScorecardFailure> {
    let mut flags = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        let Some(name) = token.strip_prefix("--") else {
            return Err(ScorecardFailure::Input(format!(
                "unexpected argument: {token}"
            )));
        };
        if !known.contains(&name) {
            return Err(ScorecardFailure::Input(format!("unknown flag: --{name}")));
        }
        if flags.contains_key(name) {
            return Err(ScorecardFailure::Input(format!("repeated flag: --{name}")));
        }
        index += 1;
        let missing = || ScorecardFailure::Input(format!("flag --{name} needs a value"));
        let Some(value) = args.get(index) else {
            return Err(missing());
        };
        if value.starts_with("--") {
            return Err(missing());
        }
        flags.insert(name.to_owned(), value.clone());
        index += 1;
    }
    Ok(flags)
}

/// Read a required flag, or fail the input when it is missing.
pub(crate) fn required_flag<'a>(
    flags: &'a BTreeMap<String, String>,
    name: &str,
) -> Result<&'a str, ScorecardFailure> {
    match flags.get(name) {
        Some(value) => Ok(value.as_str()),
        None => Err(ScorecardFailure::Input(format!("missing --{name}"))),
    }
}

/// Parse a slice name (`search`, `held_out` or `sealed`).
pub(crate) fn parse_slice(name: &str) -> Result<Slice, ScorecardFailure> {
    match name {
        "search" => Ok(Slice::Search),
        "held_out" => Ok(Slice::HeldOut),
        "sealed" => Ok(Slice::Sealed),
        other => Err(ScorecardFailure::Input(format!("unknown slice: {other}"))),
    }
}

/// Render one JSON value on one line, with a fixed fallback when it cannot serialize.
fn render(value: &serde_json::Value) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "{\"error\":\"scorecard output did not serialize\"}".to_owned())
}

/// Print the one stdout line of a subcommand and map it to its exit code:
/// the summary at 0, an `{"error": ...}` object at 2 for bad input and at 1
/// for a failure while running.
fn finish(result: Result<serde_json::Value, ScorecardFailure>) -> ExitCode {
    match result {
        Ok(summary) => {
            let line = render(&summary);
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(ScorecardFailure::Input(message)) => {
            let line = render(&serde_json::json!({ "error": message }));
            println!("{line}");
            ExitCode::from(2)
        }
        Err(ScorecardFailure::Run(message)) => {
            let line = render(&serde_json::json!({ "error": message }));
            println!("{line}");
            ExitCode::from(1)
        }
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let Some((command, rest)) = args.split_first() else {
        return finish(Err(ScorecardFailure::Input(
            "usage: oneiron-bench scorecard <convert|pack-embed|run> [flags]".to_owned(),
        )));
    };
    match command.as_str() {
        "convert" => finish(convert::run(rest)),
        "pack-embed" => finish(embed::run(rest)),
        "run" => finish(run::run(rest)),
        other => finish(Err(ScorecardFailure::Input(format!(
            "unknown scorecard subcommand: {other}"
        )))),
    }
}
