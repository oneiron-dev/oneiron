//! The `oneiron-sdk-generator` binary: argument parsing and exit codes only; the library does the work.
//!
//! A refusal prints `GenerateError` (the line Python prints last) on stderr and exits 1, as Python does for an
//! uncaught exception and for `SystemExit(message)`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: oneiron-sdk-generator --out-dir <dir> | oneiron-sdk-generator port-harness <subcommand> ...";

/// The generator recurses as deep as the Python, which raised its own limit to 20,000 frames
/// (`facade_types.py:24`), and a JSON input may nest 50,000 levels: it runs on a thread with a 256 MiB stack, as
/// the build crate will (brief 2.2).
const STACK_BYTES: usize = 256 << 20;

/// The repository the generator reads: the current directory or the nearest directory above it that holds
/// `scripts/sdk/verbs/` (Python's `ROOT` is its own file's repository; a binary has no such file).
fn root() -> Option<PathBuf> {
    let here = std::env::current_dir().ok()?;
    here.ancestors()
        .find(|dir| dir.join("scripts/sdk/verbs").is_dir())
        .map(Path::to_path_buf)
}

/// `--out-dir <dir>` or `--out-dir=<dir>` as the only arguments (argparse's two spellings).
fn out_dir(args: &[String]) -> Option<&str> {
    match args {
        [flag, dir] if flag == "--out-dir" => Some(dir),
        [flag] => flag.strip_prefix("--out-dir="),
        _ => None,
    }
}

fn dispatch(args: &[String]) -> ExitCode {
    let result = match (args.first().map(String::as_str), out_dir(args)) {
        (Some("port-harness"), _) => oneiron_sdk_generator::port_harness(&args[1..]),
        // generate.py --out-dir (G2: the outputs ported so far; G4b: every flag of generate.py's main()).
        (_, Some(dir)) => {
            let Some(root) = root() else {
                eprintln!(
                    "oneiron-sdk-generator: no scripts/sdk/verbs/ in the current directory or above it"
                );
                return ExitCode::from(2);
            };
            oneiron_sdk_generator::write_out_dir(&root, Path::new(dir))
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Result<Vec<String>, OsString> = std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect();
    let Ok(args) = args else {
        eprintln!("oneiron-sdk-generator: the arguments must be UTF-8");
        return ExitCode::from(2);
    };
    let worker = std::thread::Builder::new()
        .name("generator".to_owned())
        .stack_size(STACK_BYTES)
        .spawn(move || dispatch(&args));
    match worker {
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
        Err(error) => {
            eprintln!("oneiron-sdk-generator: could not start the generator thread: {error}");
            ExitCode::FAILURE
        }
    }
}
