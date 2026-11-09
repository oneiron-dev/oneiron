//! The `port-harness` subcommand (DESIGN 6; temporary, G6 deletes it with `scripts/sdk/port_harness.py`): each
//! subcommand prints the same canonical dump as the Python half, so `diff` proves the port.

mod floats;
mod replay;
mod rows;
mod unicode;

use crate::error::GenerateError;

const USAGE: &str =
    "usage: oneiron-sdk-generator port-harness (rows --root <dir> | unicode | floats) --out <file>";

/// `oneiron-sdk-generator port-harness <subcommand> ...`.
pub(crate) fn run(args: &[String]) -> Result<(), GenerateError> {
    match args.first().map(String::as_str) {
        Some("floats") => floats::run(&args[1..]),
        Some("rows") => rows::run(&args[1..]),
        Some("unicode") => unicode::run(&args[1..]),
        Some("replay") => replay::run(&args[1..]),
        _ => Err(GenerateError::exit(USAGE)),
    }
}

/// The value of `--<name> <value>` among `args`.
pub(crate) fn flag<'a>(
    args: &'a [String],
    name: &str,
    usage: &str,
) -> Result<&'a str, GenerateError> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|at| args.get(at + 1))
        .map(String::as_str)
        .ok_or_else(|| GenerateError::exit(usage))
}

/// Writes `text` to `path`, failing as Python's `Path.write_text` does.
pub(crate) fn write(path: &str, text: &str) -> Result<(), GenerateError> {
    std::fs::write(path, text)
        .map_err(|error| GenerateError::os(&error, std::path::Path::new(path)))
}
