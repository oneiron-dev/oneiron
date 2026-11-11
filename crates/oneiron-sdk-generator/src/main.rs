//! The `oneiron-sdk-generator` binary: argument parsing and exit codes only; the library does the work.
//!
//! A refusal prints `GenerateError` (the line Python prints last) on stderr and exits 1, as Python does for an
//! uncaught exception and for `SystemExit(message)`.

use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "usage: oneiron-sdk-generator port-harness <subcommand> ...";

/// The generator recurses as deep as the Python, which raised its own limit to 20,000 frames
/// (`facade_types.py:24`), and a JSON input may nest 50,000 levels: it runs on a thread with a 256 MiB stack, as
/// the build crate will (brief 2.2).
const STACK_BYTES: usize = 256 << 20;

fn dispatch(args: &[String]) -> ExitCode {
    let result = match args.first().map(String::as_str) {
        Some("port-harness") => oneiron_sdk_generator::port_harness(&args[1..]),
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
