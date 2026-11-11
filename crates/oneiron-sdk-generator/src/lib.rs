//! The SDK generator: a port of `scripts/sdk/generate.py` and its sibling modules (SDK-GENERATOR-RUST).
//!
//! On the same inputs the port writes the same bytes to the same paths as the Python generator, and it refuses the
//! same inputs with the same message (`GenerateError` carries the text Python prints last). Until the stack's last
//! PR (G6) removes the Python, each ported function names the Python file and lines it ports, as of main
//! `e79eb76df3e`.
//!
//! The public API (`outputs`, `write_out_dir`, `CRATES`, `INPUTS`, `Outputs`) arrives with the PRs that port it;
//! G1a brings `GenerateError` and the temporary `port-harness` entry point.

mod catalog_fragment;
mod error;
mod facade_types;
#[allow(
    dead_code,
    reason = "the module-level state; the emitters of later PRs of the port read it"
)]
mod generate;
mod harness;
#[allow(
    dead_code,
    reason = "the shared Python-behaviour helpers; later PRs of the port call the ones G1a does not"
)]
mod py;
mod uniffi_types;
mod verb_table;

pub use error::GenerateError;

/// The `port-harness` subcommand (DESIGN 6): dumps the port's state for comparison with
/// `scripts/sdk/port_harness.py`. Temporary: G6 deletes it with the Python.
#[doc(hidden)]
pub fn port_harness(args: &[String]) -> Result<(), GenerateError> {
    harness::run(args)
}
