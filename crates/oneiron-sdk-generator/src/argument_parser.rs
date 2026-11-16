//! The generator's argument parser: Python's `argparse` for the binary's four options, with the refusals it writes.

use oneiron_sdk_generator::{py_is_decimal, py_repr};

use super::{Parsed, arg_repr};

// ---- The generator's parser, `argparse` as CPython 3.14.7 (nelly) runs it

/// One option of the generator's parser, in `add_argument` order (`-h`/`--help` first, as `ArgumentParser` adds it).
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
        let short_end = text.char_indices().nth(2).map_or(text.len(), |(at, _)| at);
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
    if let (head, Some(explicit)) = partition(text)
        && let Some(opt) = option_action(head)
    {
        return Some(vec![OptionTuple {
            action: Some(opt),
            option_string: head.to_owned(),
            sep: Some("=".to_owned()),
            explicit: Some(explicit.to_owned()),
        }]);
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
                    let choices: Vec<String> =
                        CHOICES.iter().map(|choice| py_repr(choice)).collect();
                    return Err(Parsed::Error(argument_error(
                        Some(action),
                        &format!(
                            "invalid choice: {} (choose from {})",
                            arg_repr(&value),
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
        let matches: Vec<&str> = tuples
            .iter()
            .map(|tuple| tuple.option_string.as_str())
            .collect();
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
                        &format!("ignored explicit argument {}", arg_repr(&arg)),
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
                    &format!("ignored explicit argument {}", arg_repr(&arg)),
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

/// `parser.parse_args(args)` (argparse.py:2007-2012 and `_parse_known_args`, 2057-2340) for the generator's parser: no
/// positionals, no groups; options in any order, a long option by any unique prefix, `--opt=value`, `--` ending the
/// options. Errors and the help end the parse where Python's do; unrecognized arguments are reported at the end.
pub(super) fn parse(args: &[String]) -> Parsed {
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
