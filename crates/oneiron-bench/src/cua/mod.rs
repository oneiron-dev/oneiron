//! Synthetic browser bench: engine outcomes are not oracle passes.
mod args;
mod check;
mod config;
mod fixture;
mod measures;
mod provider_gate;
mod report;
mod rows;
mod run;
mod served;
mod taskgen;
use std::process::ExitCode;
pub(super) use crate::interface_bench::write_json_atomic as write_json;
pub(super) type Result<T> = std::result::Result<T, String>;

pub(crate) fn run(args: &[String]) -> ExitCode {
    let result = args::parse(args).and_then(|command| match command {
        args::Command::Taskgen { manifest, seed, out } => taskgen::generate(&manifest, seed, &out),
        args::Command::Run { plan, server, pins, out } => {
            tokio::runtime::Runtime::new().map_err(|e| e.to_string())?
                .block_on(run::campaign(&plan, &server, &pins, &out))
        }
        args::Command::Report { input, out } => report::generate(&input, &out),
        args::Command::Drift => Err(r#"{"cause":"not_implemented","phase":"S5","pr":2}"#.into()),
        args::Command::Help => { println!("{}", args::HELP); Ok(()) }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => { eprintln!("{error}"); ExitCode::FAILURE }
    }
}
pub(super) fn digest(bytes: &[u8]) -> String { blake3::hash(bytes).to_hex().to_string() }
pub(super) fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))
}
