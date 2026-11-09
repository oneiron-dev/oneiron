//! The `oneiron-sdk-generator` binary: generate.py's `main()` (generate.py:2928-2984): its argument parsing, as
//! Python's `argparse` parses and refuses it, and its exit codes; the library does the work.
//!
//! As in Python, the generator's module level runs first (the verb rows and the type inventory), then the arguments
//! are parsed: a broken verb file fails before a bad flag. A refusal prints `GenerateError` (the line Python prints
//! last) on stderr and exits 1; a bad argument prints the usage and `<prog>: error: <message>` and exits 2;
//! `-h`/`--help` prints the help and exits 0.
//!
//! The repository root is the nearest ancestor of the current directory that holds `scripts/sdk/verbs` (Python's is
//! its script's own tree; the binary has no file in the tree).

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use oneiron_sdk_generator::{GenerateError, Run, py_is_decimal, py_repr};

/// The generator recurses as deep as the Python, which raised its own limit to 20,000 frames
/// (`facade_types.py:24`), and a JSON input may nest 50,000 levels: it runs on a thread with a 256 MiB stack, as
/// the build crate does (brief 2.2).
const STACK_BYTES: usize = 256 << 20;

// ---- generate.py:2930-2933, `argparse` as CPython 3.14.7 (nelly) runs it

/// One option of generate.py's parser, in `add_argument` order (`-h`/`--help` first, as `ArgumentParser` adds it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Opt {
    Help,
    Check,
    OutDir,
    Package,
}

impl Opt {
    /// `nargs`: the help and `store_true` actions take no argument, the others one.
    fn takes_argument(self) -> bool {
        matches!(self, Self::OutDir | Self::Package)
    }

    /// `_get_action_name`: the option strings joined by `/`.
    fn name(self) -> &'static str {
        match self {
            Self::Help => "-h/--help",
            Self::Check => "--check",
            Self::OutDir => "--out-dir",
            Self::Package => "--package",
        }
    }
}

/// `parser._option_string_actions`, in insertion order.
const OPTION_STRINGS: [(&str, Opt); 5] = [
    ("-h", Opt::Help),
    ("--help", Opt::Help),
    ("--check", Opt::Check),
    ("--out-dir", Opt::OutDir),
    ("--package", Opt::Package),
];

/// `choices=sorted(PACKAGE_OUTPUTS)`.
const CHOICES: [&str; 4] = ["docs", "oneiron", "oneiron-client", "oneiron-py"];

fn option_action(text: &str) -> Option<Opt> {
    OPTION_STRINGS
        .iter()
        .find(|(string, _)| *string == text)
        .map(|&(_, opt)| opt)
}

/// One reading of an argument as an option: `(action, option_string, sep, explicit_arg)`; `action` is `None` for an
/// option this parser does not have.
#[derive(Clone, Debug)]
struct OptionTuple {
    action: Option<Opt>,
    option_string: String,
    sep: Option<String>,
    explicit: Option<String>,
}

/// `str.partition('=')`.
fn partition(text: &str) -> (&str, Option<&str>) {
    match text.split_once('=') {
        Some((head, tail)) => (head, Some(tail)),
        None => (text, None),
    }
}

/// `ArgumentParser._get_option_tuples` (argparse.py:2480-2522).
fn get_option_tuples(text: &str) -> Vec<OptionTuple> {
    let mut chars = text.chars();
    let (first, second) = (chars.next(), chars.next());
    let mut result = Vec::new();
    if first == Some('-') && second == Some('-') {
        let (prefix, explicit) = partition(text);
        for (string, opt) in OPTION_STRINGS {
            if string.starts_with(prefix) {
                result.push(OptionTuple {
                    action: Some(opt),
                    option_string: string.to_owned(),
                    sep: explicit.map(|_| "=".to_owned()),
                    explicit: explicit.map(str::to_owned),
                });
            }
        }
    } else if first == Some('-') {
        let (prefix, explicit) = partition(text);
        let short_end = text
            .char_indices()
            .nth(2)
            .map_or(text.len(), |(at, _)| at);
        let (short_prefix, short_explicit) = text.split_at(short_end);
        for (string, opt) in OPTION_STRINGS {
            if string == short_prefix {
                result.push(OptionTuple {
                    action: Some(opt),
                    option_string: string.to_owned(),
                    sep: Some(String::new()),
                    explicit: Some(short_explicit.to_owned()),
                });
            } else if string.starts_with(prefix) {
                result.push(OptionTuple {
                    action: Some(opt),
                    option_string: string.to_owned(),
                    sep: explicit.map(|_| "=".to_owned()),
                    explicit: explicit.map(str::to_owned),
                });
            }
        }
    }
    result
}

/// `ArgumentParser._parse_optional` (argparse.py:2434-2478): `None` for an argument meant as a positional.
fn parse_optional(text: &str) -> Option<Vec<OptionTuple>> {
    if !text.starts_with('-') {
        return None;
    }
    if let Some(opt) = option_action(text) {
        return Some(vec![OptionTuple {
            action: Some(opt),
            option_string: text.to_owned(),
            sep: None,
            explicit: None,
        }]);
    }
    if text.chars().count() == 1 {
        return None;
    }
    if let (head, Some(explicit)) = partition(text) {
        if let Some(opt) = option_action(head) {
            return Some(vec![OptionTuple {
                action: Some(opt),
                option_string: head.to_owned(),
                sep: Some("=".to_owned()),
                explicit: Some(explicit.to_owned()),
            }]);
        }
    }
    let tuples = get_option_tuples(text);
    if !tuples.is_empty() {
        return Some(tuples);
    }
    // `_negative_number_matcher.match(text)` (`-\.?\d`, Python's `\d` a Unicode decimal digit): the parser has no
    // option that looks like a negative number, so such an argument is a positional.
    let rest = &text[1..];
    let digits = rest.strip_prefix('.').unwrap_or(rest);
    if digits.starts_with(py_is_decimal) {
        return None;
    }
    if text.contains(' ') {
        return None;
    }
    Some(vec![OptionTuple {
        action: None,
        option_string: text.to_owned(),
        sep: None,
        explicit: None,
    }])
}

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

/// `ArgumentError(action, message)`'s text.
fn argument_error(action: Option<Opt>, message: &str) -> String {
    match action {
        Some(opt) => format!("argument {}: {message}", opt.name()),
        None => message.to_owned(),
    }
}

/// The namespace `take_action` fills.
#[derive(Default)]
struct Namespace {
    check: bool,
    out_dir: Option<String>,
    package: Vec<String>,
}

impl Namespace {
    /// `take_action`: `Err` ends the parse (the help, or an `ArgumentError`).
    fn take(&mut self, action: Opt, values: &[String]) -> Result<(), Parsed> {
        match action {
            Opt::Help => return Err(Parsed::Help),
            Opt::Check => self.check = true,
            Opt::OutDir => self.out_dir = values.first().cloned(),
            Opt::Package => {
                let value = values.first().cloned().unwrap_or_default();
                if !CHOICES.contains(&value.as_str()) {
                    let choices: Vec<String> = CHOICES.iter().map(|choice| py_repr(choice)).collect();
                    return Err(Parsed::Error(argument_error(
                        Some(action),
                        &format!(
                            "invalid choice: {} (choose from {})",
                            py_repr(&value),
                            choices.join(", ")
                        ),
                    )));
                }
                self.package.push(value);
            }
        }
        Ok(())
    }
}

/// `consume_optional` (argparse.py:2125-2214) for the option at `start`; returns the index after it.
fn consume_optional(
    args: &[String],
    pattern: &[char],
    tuples: &[OptionTuple],
    start: usize,
    namespace: &mut Namespace,
    extras: &mut Vec<String>,
) -> Result<usize, Parsed> {
    if tuples.len() > 1 {
        let matches: Vec<&str> = tuples.iter().map(|tuple| tuple.option_string.as_str()).collect();
        return Err(Parsed::Error(format!(
            "ambiguous option: {} could match {}",
            args[start],
            matches.join(", ")
        )));
    }
    let Some(first) = tuples.first() else {
        return Ok(start + 1);
    };
    let OptionTuple {
        mut action,
        mut option_string,
        mut sep,
        mut explicit,
    } = first.clone();
    let mut taken: Vec<(Opt, Vec<String>)> = Vec::new();
    let stop;
    loop {
        let Some(current) = action else {
            extras.push(args[start].clone());
            return Ok(start + 1);
        };
        if let Some(arg) = explicit.clone() {
            let arg_count = usize::from(current.takes_argument());
            let second = option_string.chars().nth(1);
            if arg_count == 0 && second != Some('-') && !arg.is_empty() {
                if sep.as_deref().is_some_and(|sep| !sep.is_empty()) || arg.starts_with('-') {
                    return Err(Parsed::Error(argument_error(
                        Some(current),
                        &format!("ignored explicit argument {}", py_repr(&arg)),
                    )));
                }
                taken.push((current, Vec::new()));
                let prefix: String = option_string.chars().take(1).collect();
                let mut rest = arg.chars();
                let next = rest.next().map(String::from).unwrap_or_default();
                option_string = format!("{prefix}{next}");
                if let Some(opt) = option_action(&option_string) {
                    action = Some(opt);
                    let tail: String = rest.collect();
                    if tail.is_empty() {
                        sep = None;
                        explicit = None;
                    } else if let Some(after) = tail.strip_prefix('=') {
                        sep = Some("=".to_owned());
                        explicit = Some(after.to_owned());
                    } else {
                        sep = Some(String::new());
                        explicit = Some(tail);
                    }
                } else {
                    extras.push(format!("{prefix}{arg}"));
                    stop = start + 1;
                    break;
                }
            } else if arg_count == 1 {
                taken.push((current, vec![arg]));
                stop = start + 1;
                break;
            } else {
                return Err(Parsed::Error(argument_error(
                    Some(current),
                    &format!("ignored explicit argument {}", py_repr(&arg)),
                )));
            }
        } else {
            // `_match_argument`: `([A])` for one argument, `()` for none.
            let next = start + 1;
            let arg_count = if current.takes_argument() {
                if pattern.get(next) != Some(&'A') {
                    return Err(Parsed::Error(argument_error(
                        Some(current),
                        "expected one argument",
                    )));
                }
                1
            } else {
                0
            };
            taken.push((current, args[next..next + arg_count].to_vec()));
            stop = next + arg_count;
            break;
        }
    }
    for (opt, values) in taken {
        namespace.take(opt, &values)?;
    }
    Ok(stop)
}

/// `parser.parse_args(args)` (argparse.py:2007-2012 and `_parse_known_args`, 2057-2340) for generate.py's parser: no
/// positionals, no groups; options in any order, a long option by any unique prefix, `--opt=value`, `--` ending the
/// options. Errors and the help end the parse where Python's do; unrecognized arguments are reported at the end.
fn parse(args: &[String]) -> Parsed {
    let mut pattern: Vec<char> = Vec::with_capacity(args.len());
    let mut options: Vec<Option<Vec<OptionTuple>>> = Vec::with_capacity(args.len());
    let mut after_dashes = false;
    for arg in args {
        if after_dashes {
            pattern.push('A');
            options.push(None);
        } else if arg == "--" {
            after_dashes = true;
            pattern.push('-');
            options.push(None);
        } else {
            let tuples = parse_optional(arg);
            pattern.push(if tuples.is_some() { 'O' } else { 'A' });
            options.push(tuples);
        }
    }
    let mut namespace = Namespace::default();
    let mut extras: Vec<String> = Vec::new();
    let last_option = options.iter().rposition(Option::is_some);
    let mut start = 0;
    while last_option.is_some_and(|last| start <= last) {
        let next = (start..args.len())
            .find(|&at| options[at].is_some())
            .unwrap_or(args.len());
        extras.extend(args[start..next].iter().cloned());
        start = next;
        let tuples = options[start].clone().unwrap_or_default();
        match consume_optional(args, &pattern, &tuples, start, &mut namespace, &mut extras) {
            Ok(stop) => start = stop,
            Err(parsed) => return parsed,
        }
    }
    extras.extend(args[start.min(args.len())..].iter().cloned());
    if !extras.is_empty() {
        return Parsed::Error(format!("unrecognized arguments: {}", extras.join(" ")));
    }
    Parsed::Args {
        check: namespace.check,
        out_dir: namespace.out_dir,
        package: namespace.package,
    }
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

/// The formatter's width: `shutil.get_terminal_size().columns - 2`. `COLUMNS` when it holds a positive integer,
/// else 80 (Python asks the terminal on standard output first, which the port cannot: a documented divergence).
fn formatter_width() -> i64 {
    let columns = std::env::var("COLUMNS")
        .ok()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .filter(|&columns| columns > 0)
        .unwrap_or(80);
    columns - 2
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
    if prefix.is_some() {
        if let Some(first) = lines.first_mut() {
            *first = first.chars().skip(indent.chars().count()).collect();
        }
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

// ---- generate.py:2934-2983, the modes

/// The repository root: the nearest ancestor of the current directory holding `scripts/sdk/verbs`.
fn find_root() -> Result<PathBuf, String> {
    let here = std::env::current_dir().map_err(|error| format!("the current directory: {error}"))?;
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

/// The binary's exit: 0, Python's 1 for an uncaught exception or `SystemExit(message)`, argparse's 2.
fn failure(error: &GenerateError) -> ExitCode {
    eprintln!("{error}");
    ExitCode::FAILURE
}

/// Port of generate.py:2928-2983 (main): the module level, then the arguments, then one mode.
fn generate_main(prog: &str, args: &[OsString]) -> ExitCode {
    let root = match find_root() {
        Ok(root) => root,
        Err(message) => {
            eprintln!("{prog}: {message}");
            return ExitCode::FAILURE;
        }
    };
    let mut run = match Run::new(&root) {
        Ok(run) => run,
        Err(error) => return failure(&error),
    };
    let width = formatter_width();
    let args: Result<Vec<String>, &OsString> = args
        .iter()
        .map(|arg| arg.clone().into_string().map_err(|_| arg))
        .collect();
    let parsed = match args {
        Ok(args) => parse(&args),
        Err(arg) => Parsed::Error(format!(
            "an argument that is not UTF-8: {}",
            arg.to_string_lossy()
        )),
    };
    let (check, out_dir, package) = match parsed {
        Parsed::Args {
            check,
            out_dir,
            package,
        } => (check, out_dir, package),
        Parsed::Help => {
            let _ = std::io::stdout().write_all(format_help(prog, width).as_bytes());
            return ExitCode::SUCCESS;
        }
        Parsed::Error(message) => {
            let usage = format_usage(prog, width);
            let _ = std::io::stderr()
                .write_all(format!("{usage}{prog}: error: {message}\n").as_bytes());
            return ExitCode::from(2);
        }
    };
    let result = if !package.is_empty() {
        // generate.py:2934-2949: a package build writes its own outputs in the tree; the docs mirror runs
        // agent-docs.py --generated.
        run.write_packages(&package).and_then(|docs| {
            if docs {
                run.agent_docs(&["--generated"])
            } else {
                Ok(())
            }
        })
    } else if let Some(dir) = out_dir {
        // generate.py:2950-2958: every output under the directory, and the three generated docs (SDKGEN-DOCS = A:
        // written here, no agent-docs.py).
        run.write_out_dir(Path::new(&Run::command_line_path(&dir)))
    } else {
        // generate.py:2959-2983: the tree's package outputs written (or checked), the old homes deleted, the census
        // printed, then agent-docs.py.
        run.write_tree(check).and_then(|census| {
            let mut stdout = std::io::stdout();
            let _ = stdout.write_all(census.as_bytes());
            let _ = stdout.flush();
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
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn dispatch(argv: &[OsString]) -> ExitCode {
    let prog = prog_name(argv.first());
    let args = argv.get(1..).unwrap_or_default();
    if args.first().is_some_and(|arg| arg == "port-harness") {
        // The temporary port harness (DESIGN 6; G6 deletes it).
        let strings: Option<Vec<String>> = args[1..]
            .iter()
            .map(|arg| arg.clone().into_string().ok())
            .collect();
        let Some(strings) = strings else {
            eprintln!("{prog}: the port-harness arguments must be UTF-8");
            return ExitCode::from(2);
        };
        return match oneiron_sdk_generator::port_harness(&strings) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => failure(&error),
        };
    }
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
            eprintln!("oneiron-sdk-generator: could not start the generator thread: {error}");
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

    // The messages python3 (3.14.7, nelly) printed for generate.py's parser, one run per line:
    //   python3 generate.py <args>; its last stderr line is `generate.py: error: <message>`.
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
        assert_eq!(parse(&strings(&["--out-dir", "-1"])), args(false, Some("-1"), &[]));
        assert_eq!(
            parse(&strings(&["--out-dir", "a", "--out-dir", "b"])),
            args(false, Some("b"), &[])
        );
        assert_eq!(parse(&strings(&[])), args(false, None, &[]));
        for help in [&["-h"][..], &["--h"], &["--help", "--foo"], &["--foo", "--help"], &["-hx"]] {
            assert_eq!(parse(&strings(help)), Parsed::Help, "{help:?}");
        }
    }

    // python3 generate.py -h (and with COLUMNS=40, 200; and the script copied to `oneiron-sdk-generator`).
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
}
