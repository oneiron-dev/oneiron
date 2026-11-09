//! Builds a fixture vault from a JSONL seed, for the E2E runner's snapshot
//! fixtures (Fable's verdict, section 2): `oneiron-testkit-seed <seed.jsonl>
//! <out-dir>` writes the closed vault to `<out-dir>/vault` and its record to
//! `<out-dir>/fixture.json`, and prints `{"vault": ..., "ended_at": ...}`.
//! The runner copies `<out-dir>/vault` once per case. Every seed line runs
//! through a public verb as the vault's embedded owner (see
//! `oneiron_testkit::fixture::jsonl_seed`). Test support only; never shipped.

use std::path::PathBuf;
use std::process::ExitCode;

use oneiron_testkit::FakeClock;
use oneiron_testkit::fixture::{jsonl_seed, seed_into};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(seed), Some(out), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: oneiron-testkit-seed <seed.jsonl> <out-dir>");
        return ExitCode::from(2);
    };
    let (seed, out) = (PathBuf::from(seed), PathBuf::from(out));
    let text = match std::fs::read_to_string(&seed) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("oneiron-testkit-seed: {}: {error}", seed.display());
            return ExitCode::FAILURE;
        }
    };
    let name = seed
        .file_stem()
        .map_or_else(|| "seed".to_owned(), |stem| stem.to_string_lossy().into_owned());
    match seed_into(&out, &name, FakeClock::vault_config, jsonl_seed(&text)) {
        Ok(ended_at) => {
            println!(
                "{}",
                serde_json::json!({"vault": out.join("vault"), "ended_at": ended_at})
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("oneiron-testkit-seed: {error}");
            ExitCode::FAILURE
        }
    }
}
