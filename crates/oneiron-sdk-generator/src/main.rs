//! The `oneiron-sdk-generator` binary: the Python generator's `main()`: its argument parsing, as Python's `argparse`
//! parses and refuses it, and its exit codes; the library does the work.
//!
//! As in Python, the generator's module level runs first (the verb rows and the type inventory), then the arguments
//! are parsed: a broken verb file fails before a bad flag. A refusal prints `GenerateError` (the line Python prints
//! last) on stderr and exits 1; a bad argument prints the usage and `<prog>: error: <message>` and exits 2;
//! `-h`/`--help` prints the help and exits 0.
//!
//! The repository root is the nearest ancestor of the current directory that holds `scripts/sdk/verbs` (Python's is
//! its script's own tree; the binary has no file in the tree).

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU32, Ordering};

use oneiron_sdk_generator::{GenerateError, Run, py_is_decimal, py_is_space, py_repr};

mod argument_parser;

use argument_parser::parse;

/// The generator recurses as deep as the Python generator, which raised its own limit to 20,000 frames, and a JSON
/// input may nest 50,000 levels: it runs on a thread with a 256 MiB stack, as the build crate does.
const STACK_BYTES: usize = 256 << 20;

/// What `parse_args` makes of the arguments.
#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// The namespace: `--check`, `--out-dir` (its text, the last one given) and `--package` (each, in order).
    Args {
        check: bool,
        out_dir: Option<String>,
        package: Vec<String>,
    },
    /// `-h`/`--help` was taken: print the help, exit 0.
    Help,
    /// `parser.error(message)`: print the usage and `<prog>: error: <message>`, exit 2.
    Error(String),
}

// ---- argparse's HelpFormatter (argparse.py:168-700), for this parser's four options

/// The usage's option parts (`_get_actions_usage_parts`).
const USAGE_PARTS: [&str; 4] = [
    "[-h]",
    "[--check]",
    "[--out-dir OUT_DIR]",
    "[--package {docs,oneiron,oneiron-client,oneiron-py}]",
];

/// Each option's invocation and help text, as `--help` lists them.
const ACTIONS: [(&str, Option<&str>); 4] = [
    ("-h, --help", Some("show this help message and exit")),
    ("--check", None),
    (
        "--out-dir OUT_DIR",
        Some("write every output under this directory (the build scripts read it)"),
    ),
    (
        "--package {docs,oneiron,oneiron-client,oneiron-py}",
        Some("write this package's outputs in the tree"),
    ),
];

/// The widest `COLUMNS` the formatter takes as it is: no usage or help line comes near it, and the formatter's
/// arithmetic (`3 * width`) stays in range.
const COLUMNS_CAP: i64 = 1 << 40;

/// The formatter's width: `shutil.get_terminal_size().columns - 2`. `COLUMNS` read as Python's `int()` reads it,
/// when positive; else 80 (Python asks the terminal on standard output first, which the port does not: a documented
/// divergence).
fn formatter_width() -> i64 {
    let columns = std::env::var("COLUMNS")
        .ok()
        .and_then(|text| python_int(&text))
        .filter(|&columns| columns > 0)
        .unwrap_or(80);
    columns.min(COLUMNS_CAP) - 2
}

/// `int(text)` (base 10), as `shutil.get_terminal_size` reads `COLUMNS`: white space around (`str.isspace()`), an
/// optional sign, decimal digits of any script (`str.isdecimal()`), single underscores between digits, at most 4,300
/// digits (`sys.int_info.default_max_str_digits`). `None` where Python raises `ValueError`; a value past `i64`
/// saturates (the caller caps it).
fn python_int(text: &str) -> Option<i64> {
    // CPython turns each non-ASCII white space into ' ' and strips ASCII white space (` \t\n\v\f\r`); the ASCII
    // separators U+001C-U+001F, white space to `str.isspace()`, stay and are refused.
    let body = text.trim_matches(|c: char| {
        if c.is_ascii() {
            matches!(c, ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r')
        } else {
            py_is_space(c)
        }
    });
    let (negative, digits) = match body.strip_prefix(['+', '-']) {
        Some(rest) => (body.starts_with('-'), rest),
        None => (false, body),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let mut value: i64 = 0;
    let mut count = 0_usize;
    for c in digits.chars().filter(|&c| c != '_') {
        let digit = decimal_value(c)?;
        count += 1;
        value = value.saturating_mul(10).saturating_add(digit);
    }
    (count <= 4300).then_some(if negative { -value } else { value })
}

/// A `str.isdecimal()` character's digit value: Unicode lays out each script's decimal digits as one run of ten from
/// zero (`unicodedata.decimal`), so it is the distance from the start of its run of decimals, modulo ten.
fn decimal_value(c: char) -> Option<i64> {
    if !py_is_decimal(c) {
        return None;
    }
    let code = u32::from(c);
    let mut start = code;
    while start > 0 && char::from_u32(start - 1).is_some_and(py_is_decimal) {
        start -= 1;
    }
    Some(i64::from((code - start) % 10))
}

/// `len(text)`: its code points.
fn text_len(text: &str) -> i64 {
    i64::try_from(text.chars().count()).unwrap_or(i64::MAX)
}

/// `_format_usage`'s `get_lines`.
fn get_lines(parts: &[&str], indent: &str, prefix: Option<&str>, text_width: i64) -> Vec<String> {
    let indent_length = text_len(indent);
    let mut lines: Vec<String> = Vec::new();
    let mut line: Vec<&str> = Vec::new();
    let mut line_len = prefix.map_or(indent_length - 1, |prefix| text_len(prefix) - 1);
    for part in parts {
        if line_len + 1 + text_len(part) > text_width && !line.is_empty() {
            lines.push(format!("{indent}{}", line.join(" ")));
            line.clear();
            line_len = indent_length - 1;
        }
        line.push(part);
        line_len += text_len(part) + 1;
    }
    if !line.is_empty() {
        lines.push(format!("{indent}{}", line.join(" ")));
    }
    if prefix.is_some()
        && let Some(first) = lines.first_mut()
    {
        *first = first.chars().skip(indent.chars().count()).collect();
    }
    lines
}

/// `parser.format_usage()`: `usage: <prog> [-h] ...`, wrapped as `_format_usage` wraps it, with one final newline.
fn format_usage(prog: &str, width: i64) -> String {
    let prefix = "usage: ";
    let text_width = width;
    let mut usage = std::iter::once(prog)
        .chain(USAGE_PARTS)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if text_len(prefix) + text_len(&usage) > text_width {
        let prog_len = text_len(prog);
        // `len(prefix) + prog_len <= 0.75 * text_width`, in integers.
        let lines = if 4 * (text_len(prefix) + prog_len) <= 3 * text_width {
            let indent = " ".repeat(usize::try_from(text_len(prefix) + prog_len + 1).unwrap_or(0));
            let mut parts = vec![prog];
            parts.extend(USAGE_PARTS);
            get_lines(&parts, &indent, Some(prefix), text_width)
        } else {
            // A long prog takes a line of its own. (With more than one line, Python wraps the optionals and the
            // positionals apart; this parser has no positionals, so the lines are the same.)
            let indent = " ".repeat(prefix.len());
            let lines = get_lines(&USAGE_PARTS, &indent, None, text_width);
            let mut all = vec![prog.to_owned()];
            all.extend(lines);
            all
        };
        usage = lines.join("\n");
    }
    format!("{prefix}{usage}\n")
}

/// `textwrap.wrap(text, width)` for a help text of single-spaced words, none longer than the narrowest help column
/// (11): greedy, a word moves to the next line when it would pass `width`.
fn wrap(text: &str, width: i64) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in text.split(' ').filter(|word| !word.is_empty()) {
        if !line.is_empty() && text_len(&line) + 1 + text_len(word) > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

fn spaces(n: i64) -> String {
    " ".repeat(usize::try_from(n).unwrap_or(0))
}

/// `parser.format_help()`: the usage, then the `options:` section, each option as `_format_action` lays it out.
fn format_help(prog: &str, width: i64) -> String {
    let indent = 2;
    let max_help_position = 24.min((width - 20).max(4));
    let action_max_length = ACTIONS
        .iter()
        .map(|(invocation, _)| text_len(invocation) + indent)
        .max()
        .unwrap_or(0);
    let help_position = (action_max_length + 2).min(max_help_position);
    let help_width = (width - help_position).max(11);
    let action_width = help_position - indent - 2;
    let mut out = format_usage(prog, width);
    out += "\noptions:\n";
    for (invocation, help) in ACTIONS {
        let Some(help) = help else {
            out += &format!("{}{invocation}\n", spaces(indent));
            continue;
        };
        let indent_first = if text_len(invocation) <= action_width {
            let pad = spaces(action_width - text_len(invocation));
            out += &format!("{}{invocation}{pad}  ", spaces(indent));
            0
        } else {
            out += &format!("{}{invocation}\n", spaces(indent));
            help_position
        };
        for (n, line) in wrap(help, help_width).iter().enumerate() {
            let at = if n == 0 { indent_first } else { help_position };
            out += &format!("{}{line}\n", spaces(at));
        }
    }
    out
}

// ---- The modes

/// The repository root: the nearest ancestor of the current directory holding `scripts/sdk/verbs`.
fn find_root() -> Result<PathBuf, String> {
    let here =
        std::env::current_dir().map_err(|error| format!("the current directory: {error}"))?;
    here.ancestors()
        .find(|dir| dir.join("scripts/sdk/verbs").is_dir())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "no directory above {} holds scripts/sdk/verbs; run the generator inside the repository",
                here.display()
            )
        })
}

/// A line on stderr; a stderr that cannot take it changes nothing (Python's traceback is lost the same way, and the
/// exit status stays).
fn print_stderr(text: &str) {
    let _ = writeln!(std::io::stderr(), "{text}");
}

/// The binary's exit: 0, Python's 1 for an uncaught exception or `SystemExit(message)`, argparse's 2.
fn failure(error: &GenerateError) -> ExitCode {
    print_stderr(&error.to_string());
    ExitCode::FAILURE
}

// ---- arguments that are not UTF-8

/// Byte `b` (0x80-0xFF) of an argument that is not UTF-8 stands as `base + b` while it is parsed: Python decodes
/// `argv` with `surrogateescape`, giving the lone surrogate `U+DC00 + b`, which a Rust `String` cannot hold. `base` is
/// chosen per command line (`choose_stand_in_base`) so that no stand-in is a character an argument really holds; 0
/// until then (no stand-ins).
static STAND_IN_BASE: AtomicU32 = AtomicU32::new(0);

/// The stand-in window for these arguments: the first `base` (a multiple of 0x100 in the private-use planes 15 and
/// 16) whose `base + 0x80 ..= base + 0xFF` holds no character of any argument. Only a command line that names a
/// character in each of the 512 windows finds none; it keeps the last window, whose characters then read as bytes.
fn choose_stand_in_base(args: &[OsString]) -> u32 {
    let held: Vec<u32> = args
        .iter()
        .flat_map(|arg| {
            arg.to_string_lossy()
                .chars()
                .map(u32::from)
                .collect::<Vec<_>>()
        })
        .filter(|&code| code >= 0x000F_0080)
        .collect();
    (0..0x200_u32)
        .map(|window| 0x000F_0000 + window * 0x100)
        .find(|base| {
            !held
                .iter()
                .any(|code| (base + 0x80..=base + 0xFF).contains(code))
        })
        .unwrap_or(0x0010_FF00)
}

/// An argument as Python's `sys.argv` holds it, with the stand-ins for its undecodable bytes.
#[cfg(unix)]
fn decode_argument(arg: &OsStr) -> String {
    use std::os::unix::ffi::OsStrExt;
    let base = STAND_IN_BASE.load(Ordering::Relaxed);
    let mut text = String::new();
    for chunk in arg.as_bytes().utf8_chunks() {
        text.push_str(chunk.valid());
        for &byte in chunk.invalid() {
            text.push(
                char::from_u32(base + u32::from(byte)).unwrap_or(char::REPLACEMENT_CHARACTER),
            );
        }
    }
    text
}

#[cfg(not(unix))]
fn decode_argument(arg: &OsStr) -> String {
    arg.to_string_lossy().into_owned()
}

/// The byte a stand-in holds.
fn escaped_byte(c: char) -> Option<u32> {
    let base = STAND_IN_BASE.load(Ordering::Relaxed);
    let code = u32::from(c);
    (base != 0 && (base + 0x80..=base + 0xFF).contains(&code)).then(|| code - base)
}

/// A message as Python's stderr writes it (`errors='backslashreplace'`): each lone surrogate as `\udcXX`.
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match escaped_byte(c) {
            Some(byte) => out.push_str(&format!("\\udc{byte:02x}")),
            None => out.push(c),
        }
    }
    out
}

/// `repr(arg)` of an argument: a lone surrogate is `\udcXX` in Python's `repr`. `py_repr` writes a stand-in as the
/// escape of a code point that is not printable (`\U000fXXXX` or `\U0010XXXX`, private use) and every real backslash
/// doubled, so such an escape of a stand-in's code point is a stand-in.
fn arg_repr(arg: &str) -> String {
    let repr = py_repr(arg);
    let mut out = String::with_capacity(repr.len());
    let mut rest = repr.as_str();
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        if let Some(after) = tail.strip_prefix("\\\\") {
            out.push_str("\\\\");
            rest = after;
            continue;
        }
        let byte = tail
            .strip_prefix("\\U")
            .and_then(|hex| hex.get(..8))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32)
            .and_then(escaped_byte);
        match byte {
            Some(byte) => {
                out.push_str(&format!("\\udc{byte:02x}"));
                rest = &tail[10..];
            }
            None => {
                out.push('\\');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// `parser.error(message)`: the usage and `<prog>: error: <message>` on stderr, exit status 2.
fn argument_refusal(prog: &str, width: i64, message: &str) -> ExitCode {
    let usage = format_usage(prog, width);
    let _ = std::io::stderr()
        .write_all(format!("{usage}{prog}: error: {}\n", shown(message)).as_bytes());
    ExitCode::from(2)
}

/// The module level, then the arguments, then one mode.
fn generate_main(prog: &str, args: &[OsString]) -> ExitCode {
    let root = match find_root() {
        Ok(root) => root,
        Err(message) => {
            print_stderr(&format!("{prog}: {message}"));
            return ExitCode::FAILURE;
        }
    };
    let mut run = match Run::new(&root) {
        Ok(run) => run,
        Err(error) => return failure(&error),
    };
    let width = formatter_width();
    STAND_IN_BASE.store(choose_stand_in_base(args), Ordering::Relaxed);
    let args: Vec<String> = args.iter().map(|arg| decode_argument(arg)).collect();
    let (check, out_dir, package) = match parse(&args) {
        Parsed::Args {
            check,
            out_dir,
            package,
        } => (check, out_dir, package),
        Parsed::Help => {
            let _ = std::io::stdout().write_all(format_help(prog, width).as_bytes());
            return ExitCode::SUCCESS;
        }
        Parsed::Error(message) => return argument_refusal(prog, width, &message),
    };
    let result = if !package.is_empty() {
        // A package build writes its own outputs in the tree; the docs mirror runs agent-docs.py --generated.
        run.write_packages(&package).and_then(|docs| {
            if docs {
                run.agent_docs(&["--generated"])
            } else {
                Ok(())
            }
        })
    } else if let Some(dir) = out_dir {
        // A directory named by bytes that are not UTF-8, in the mode that uses it: Python writes there; the port
        // refuses it, as G1a and G1b refuse such file names (coordinator ruling).
        if dir.chars().any(|c| escaped_byte(c).is_some()) {
            return argument_refusal(
                prog,
                width,
                &format!(
                    "argument --out-dir: a directory name that is not UTF-8: {}",
                    arg_repr(&dir)
                ),
            );
        }
        // Every output under the directory, and the three generated docs (SDKGEN-DOCS = A: written here, no
        // agent-docs.py).
        run.write_out_dir(Path::new(&Run::command_line_path(&dir)))
    } else {
        // The tree's package outputs written (or checked), the old homes deleted, the census printed, then
        // agent-docs.py.
        // A census stdout cannot take is Python's OSError from `print`, before agent-docs.py runs.
        run.write_tree(check).and_then(|census| {
            run.print(&census)?;
            run.agent_docs(&[if check { "--check" } else { "--generated" }])
        })
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => failure(&error),
    }
}

/// `os.path.basename(sys.argv[0])`: argparse's `prog`.
fn prog_name(argv0: Option<&OsString>) -> String {
    argv0
        .map(Path::new)
        .and_then(Path::file_name)
        .map_or_default(|name| name.to_string_lossy().into_owned())
}

fn dispatch(argv: &[OsString]) -> ExitCode {
    let prog = prog_name(argv.first());
    let args = argv.get(1..).unwrap_or_default();
    generate_main(&prog, args)
}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let worker = std::thread::Builder::new()
        .name("generator".to_owned())
        .stack_size(STACK_BYTES)
        .spawn(move || dispatch(&argv));
    match worker {
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
        Err(error) => {
            print_stderr(&format!(
                "oneiron-sdk-generator: could not start the generator thread: {error}"
            ));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn error(args: &[&str]) -> String {
        match parse(&strings(args)) {
            Parsed::Error(message) => message,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    // Expected: what the Python generator's argparse printed (main e79eb76df3e, Python 3.14.7 on nelly), one run per
    // line with the arguments shown; its last stderr line was `<prog>: error: <message>`.
    #[test]
    fn refusals_are_argparses() {
        assert_eq!(error(&["--foo"]), "unrecognized arguments: --foo");
        assert_eq!(
            error(&["--foo", "--bar", "x"]),
            "unrecognized arguments: --foo --bar x"
        );
        assert_eq!(
            error(&["--package"]),
            "argument --package: expected one argument"
        );
        assert_eq!(
            error(&["--package", "nope"]),
            "argument --package: invalid choice: 'nope' (choose from 'docs', 'oneiron', 'oneiron-client', 'oneiron-py')"
        );
        assert_eq!(
            error(&["--out-dir"]),
            "argument --out-dir: expected one argument"
        );
        assert_eq!(
            error(&["--out-dir", "--check"]),
            "argument --out-dir: expected one argument"
        );
        assert_eq!(
            error(&["--check", "--out-dir"]),
            "argument --out-dir: expected one argument"
        );
        assert_eq!(error(&["-x"]), "unrecognized arguments: -x");
        assert_eq!(
            error(&["--", "--check"]),
            "unrecognized arguments: -- --check"
        );
        assert_eq!(error(&["x"]), "unrecognized arguments: x");
        assert_eq!(
            error(&["--check=1"]),
            "argument --check: ignored explicit argument '1'"
        );
        assert_eq!(
            error(&["--package="]),
            "argument --package: invalid choice: '' (choose from 'docs', 'oneiron', 'oneiron-client', 'oneiron-py')"
        );
        assert_eq!(error(&["-"]), "unrecognized arguments: -");
        assert_eq!(
            error(&["--out-dir", "-x"]),
            "argument --out-dir: expected one argument"
        );
        assert_eq!(error(&["--"]), "unrecognized arguments: --");
        assert_eq!(
            error(&["--=x"]),
            "ambiguous option: --=x could match --help, --check, --out-dir, --package"
        );
        assert_eq!(error(&["---check"]), "unrecognized arguments: ---check");
        assert_eq!(error(&["--CHECK"]), "unrecognized arguments: --CHECK");
    }

    #[test]
    fn readings_are_argparses() {
        let args = |check: bool, out_dir: Option<&str>, package: &[&str]| Parsed::Args {
            check,
            out_dir: out_dir.map(str::to_owned),
            package: strings(package),
        };
        assert_eq!(parse(&strings(&["--ch"])), args(true, None, &[]));
        assert_eq!(parse(&strings(&["--o=x"])), args(false, Some("x"), &[]));
        assert_eq!(
            parse(&strings(&["--pack=docs", "--pack", "oneiron"])),
            args(false, None, &["docs", "oneiron"])
        );
        assert_eq!(parse(&strings(&["--out-dir="])), args(false, Some(""), &[]));
        assert_eq!(
            parse(&strings(&["--out-dir", "-1"])),
            args(false, Some("-1"), &[])
        );
        assert_eq!(
            parse(&strings(&["--out-dir", "a", "--out-dir", "b"])),
            args(false, Some("b"), &[])
        );
        assert_eq!(parse(&strings(&[])), args(false, None, &[]));
        for help in [
            &["-h"][..],
            &["--h"],
            &["--help", "--foo"],
            &["--foo", "--help"],
            &["-hx"],
        ] {
            assert_eq!(parse(&strings(help)), Parsed::Help, "{help:?}");
        }
    }

    // Expected: the help the Python generator's argparse printed for `-h` (main e79eb76df3e, Python 3.14.7 on nelly),
    // also with COLUMNS=40 and 200, and with the script copied to `oneiron-sdk-generator`.
    #[test]
    fn help_and_usage_wrap_as_argparse() {
        assert_eq!(
            format_help("generate.py", 78),
            "usage: generate.py [-h] [--check] [--out-dir OUT_DIR]\n                   [--package {docs,oneiron,oneiron-client,oneiron-py}]\n\noptions:\n  -h, --help            show this help message and exit\n  --check\n  --out-dir OUT_DIR     write every output under this directory (the build\n                        scripts read it)\n  --package {docs,oneiron,oneiron-client,oneiron-py}\n                        write this package's outputs in the tree\n"
        );
        assert_eq!(
            format_help("generate.py", 38),
            "usage: generate.py [-h] [--check]\n                   [--out-dir OUT_DIR]\n                   [--package {docs,oneiron,oneiron-client,oneiron-py}]\n\noptions:\n  -h, --help      show this help\n                  message and exit\n  --check\n  --out-dir OUT_DIR\n                  write every output\n                  under this directory\n                  (the build scripts\n                  read it)\n  --package {docs,oneiron,oneiron-client,oneiron-py}\n                  write this package's\n                  outputs in the tree\n"
        );
        assert_eq!(
            format_help("generate.py", 198),
            "usage: generate.py [-h] [--check] [--out-dir OUT_DIR] [--package {docs,oneiron,oneiron-client,oneiron-py}]\n\noptions:\n  -h, --help            show this help message and exit\n  --check\n  --out-dir OUT_DIR     write every output under this directory (the build scripts read it)\n  --package {docs,oneiron,oneiron-client,oneiron-py}\n                        write this package's outputs in the tree\n"
        );
        assert_eq!(
            format_usage("oneiron-sdk-generator", 78),
            "usage: oneiron-sdk-generator [-h] [--check] [--out-dir OUT_DIR]\n                             [--package {docs,oneiron,oneiron-client,oneiron-py}]\n"
        );
    }

    // python3 -c "print(int(T))" on nelly (3.14.7), None for a ValueError, for each T below.
    #[test]
    fn columns_are_read_as_python_int() {
        let cases: [(&str, Option<i64>); 20] = [
            (" 40 ", Some(40)),
            ("+40", Some(40)),
            ("-5", Some(-5)),
            ("4_0", Some(40)),
            ("4__0", None),
            ("_40", None),
            ("40_", None),
            ("", None),
            ("0x10", None),
            ("1e3", None),
            ("\u{664}\u{660}", Some(40)),
            ("\u{ff14}\u{ff10}", Some(40)),
            ("\u{1d7d2}\u{1d7ce}", Some(40)),
            ("\u{2003} 72\u{3000}", Some(72)),
            ("040", Some(40)),
            ("- 5", None),
            ("\x1c40\x1f", None),
            ("\u{b2}", None),
            ("4\u{6f0}", Some(40)),
            ("999999999999999999999999999999", Some(i64::MAX)),
        ];
        for (text, expected) in cases {
            assert_eq!(python_int(text), expected, "{text:?}");
        }
        assert_eq!(python_int(&"1".repeat(4300)), Some(i64::MAX));
        assert_eq!(python_int(&"1".repeat(4301)), None);
    }

    // Python: sys.argv holds '\udcff' for a byte 0xff; repr('a\udcff') is 'a\udcff'; stderr writes it as \udcff.
    #[test]
    fn undecodable_arguments_show_as_python_shows_them() {
        // The window a command line with no private-use character gets (every test that uses stand-ins sets it).
        let base = choose_stand_in_base(&[]);
        assert_eq!(base, 0x000F_0000);
        STAND_IN_BASE.store(base, Ordering::Relaxed);
        let stand_in = |byte: u32| char::from_u32(base + byte).expect("a stand-in");
        let arg = format!("a{}", stand_in(0xff));
        assert_eq!(arg_repr(&arg), r"'a\udcff'");
        assert_eq!(shown(&format!("x {arg}")), r"x a\udcff");
        assert_eq!(arg_repr(r"\U0010ffff"), r"'\\U0010ffff'");
        assert_eq!(arg_repr("it's"), "\"it's\"");
        // A real private-use character outside the window is itself (Python: repr('\U0010ff80') is '\U0010ff80').
        assert_eq!(arg_repr("\u{10ff80}"), r"'\U0010ff80'");
        assert_eq!(shown("\u{10ff80}"), "\u{10ff80}");
        // A command line that holds a character of the first window moves the stand-ins to the next.
        assert_eq!(
            choose_stand_in_base(&[OsString::from("x\u{f0080}")]),
            0x000F_0100
        );
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let decoded = decode_argument(OsStr::from_bytes(b"--package=\xffx\xc3\xa9"));
            assert_eq!(decoded, format!("--package={}x\u{e9}", stand_in(0xff)));
        }
        assert_eq!(parse(&[String::from("--help"), arg.clone()]), Parsed::Help);
        assert_eq!(
            parse(&[String::from("--package"), arg]),
            Parsed::Error(
                r"argument --package: invalid choice: 'a\udcff' (choose from 'docs', 'oneiron', 'oneiron-client', 'oneiron-py')"
                    .to_owned()
            )
        );
    }
}
