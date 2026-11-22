//! FIX-LIST [PY-SDK-GENERATED-KEYWORD-METHOD]: the generated Python facade names no method,
//! property or parameter by a Python hard keyword. The 21 Nov nightly built `_facade_verbs.py`
//! with `def continue(self)`, the property of the namespace `vault.runners.continue` (a namespace
//! because `vault.runners.continue.check` is a row): a SyntaxError, so `from oneiron import
//! Oneiron` failed. The generator runs on the repository through its public `outputs` entry.
//! `cargo test --locked -p oneiron-sdk-generator --all-features
//! --test sdk_python_keyword_identifiers`.

use std::path::{Path, PathBuf};

/// `keyword.kwlist`, printed on nelly (Python 3.14.7) by
/// `python3 -c "import keyword; print(keyword.kwlist)"`.
const HARD_KEYWORDS: [&str; 35] = [
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
    "with", "yield",
];

/// The Python facade outputs: the runtime module and its stub.
const FACADE_OUTPUTS: [&str; 2] = [
    "crates/oneiron-py/python/oneiron/_facade_verbs.py",
    "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
];

/// The repository root above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Each `def` line of a module: its line number, the method name, and the names of its parameters
/// (a type text split at a comma yields no identifier before its `:`, so it is skipped).
fn definitions(text: &str) -> Vec<(usize, String, Vec<String>)> {
    let def = regex::Regex::new(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)").expect("regex");
    let identifier = regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("regex");
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let Some(captures) = def.captures(line) else {
            continue;
        };
        let parameters = captures[2]
            .split(',')
            .filter_map(|part| {
                let name = part.split([':', '=']).next().unwrap_or_default().trim();
                identifier.is_match(name).then(|| name.to_owned())
            })
            .collect();
        found.push((index + 1, captures[1].to_owned(), parameters));
    }
    found
}

#[test]
fn generated_python_facade_names_no_method_property_or_parameter_by_a_hard_keyword() {
    let outputs =
        oneiron_sdk_generator::outputs(&repo()).expect("the generator runs on the repository");
    let mut offenders = Vec::new();
    for path in FACADE_OUTPUTS {
        let text = outputs
            .get(path)
            .unwrap_or_else(|| panic!("{path} is an output"));
        let found = definitions(text);
        // The facade holds a method or a property for each of its rows: an empty scan means the
        // pattern no longer matches the emitter's `def` lines.
        assert!(
            found.len() > 100,
            "{path}: only {} def lines found",
            found.len()
        );
        for (line, name, parameters) in found {
            if HARD_KEYWORDS.contains(&name.as_str()) {
                offenders.push(format!("{path}:{line} def {name}"));
            }
            for parameter in parameters {
                if HARD_KEYWORDS.contains(&parameter.as_str()) {
                    offenders.push(format!("{path}:{line} def {name}(... {parameter} ...)"));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the generated Python facade names a hard keyword (a SyntaxError on import): {}",
        offenders.join("; ")
    );
}
