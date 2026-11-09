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

/// generate.py's option strings, argparse's `-h`/`--help` included: they decide what argparse reads as an option.
const OPTIONS: &[&str] = &["-h", "--help", "--check", "--out-dir", "--package"];

/// Whether argparse reads `arg` as an option, not as a value (Python 3.14 `ArgumentParser._parse_optional` and
/// `_get_option_tuples` over generate.py's options, `allow_abbrev` on): then `--out-dir <arg>` has no value.
fn is_option(arg: &str) -> bool {
    if !arg.starts_with('-') {
        return false;
    }
    if OPTIONS.contains(&arg) {
        return true;
    }
    if arg.len() == 1 {
        return false;
    }
    let (flag, explicit) = match arg.split_once('=') {
        Some((flag, _)) => (flag, true),
        None => (arg, false),
    };
    if explicit && OPTIONS.contains(&flag) {
        return true;
    }
    // An abbreviation of an option; a short option glued to its value (`-hx`).
    if OPTIONS.iter().any(|option| option.starts_with(flag))
        || (!arg[1..].starts_with('-') && arg.starts_with("-h"))
    {
        return true;
    }
    // A negative number is a value: Python's `-\.?\d` (`\d` is Unicode Nd in both engines).
    let negative = regex::Regex::new(r"\A-\.?\d").expect("a constant pattern");
    if negative.is_match(arg) || arg.contains(' ') {
        return false;
    }
    true
}

/// argparse's reading of `--out-dir` when it is the only option given: `--out-dir <dir>`, `--out-dir=<dir>`, or an
/// abbreviation no other option shares (`--out <dir>`, `--o=<dir>`). `Some(Err(..))` is argparse's error for an
/// `--out-dir` with no value; `None` is anything else (G4b ports the other flags and their combinations).
fn out_dir(args: &[String]) -> Option<Result<&str, &'static str>> {
    let (first, rest) = args.split_first()?;
    let (flag, explicit) = match first.split_once('=') {
        Some((flag, dir)) => (flag, Some(dir)),
        None => (first.as_str(), None),
    };
    if flag.len() < 3 || !"--out-dir".starts_with(flag) {
        return None;
    }
    match (explicit, rest) {
        (Some(dir), []) => Some(Ok(dir)),
        (None, [dir]) if !is_option(dir) => Some(Ok(dir)),
        (None, [] | [_]) => Some(Err("argument --out-dir: expected one argument")),
        _ => None,
    }
}

fn dispatch(args: &[String]) -> ExitCode {
    let result = match (args.first().map(String::as_str), out_dir(args)) {
        (Some("port-harness"), _) => oneiron_sdk_generator::port_harness(&args[1..]),
        // generate.py --out-dir (G2: the outputs ported so far; G4b: every flag of generate.py's main()).
        (_, Some(Err(message))) => {
            // argparse's error: the usage, then `<prog>: error: <message>`, exit status 2.
            eprintln!("{USAGE}\noneiron-sdk-generator: error: {message}");
            return ExitCode::from(2);
        }
        (_, Some(Ok(dir))) => {
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
