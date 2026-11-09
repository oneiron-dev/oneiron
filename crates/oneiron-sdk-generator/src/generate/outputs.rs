//! Port of generate.py:2194-2604: `BUILD_TIME_OUTPUTS`, `PACKAGE_OUTPUTS`, `PACKAGE_PATHS` and `outputs()`, in
//! Python's call order (brief H10: the emitters share one `Inventory`, and the order they run in names its types);
//! and the file operations of generate.py:2928-2983 (`main`) and agent-docs.py's `write`, with pathlib's errors.
//!
//! Not ported, both by the lane's design (DESIGN 9.1, CHECK-4.3 C2): `FORMAT`'s rustfmt pass (generate.py:2586-2589;
//! no committed `.rs` output remains, so its text reaches no file), and the two dormant rewrites of generate.py:
//! 2533-2557 (the MCP dispatch and board catalog markers, absent on main). Their two hosts are still read, as Python
//! reads them, so a missing or undecodable host fails here as it does there.

use std::fs;
use std::io;
use std::path::Path;

use indexmap::IndexMap;

use super::emit_http::http_facade;
use super::emit_py::python_facade_module;
use super::emit_ts::{
    VerbTree, row_of, ts_facade_module, ts_native_module, ts_native_signature, verb_tree,
};
use super::row_access::context_is;
use super::{Generator, RowId};
use crate::error::GenerateError;
use crate::py::value::{Dict, Value};

/// Port of generate.py:2194-2211 (BUILD_TIME_OUTPUTS): the outputs crates/oneiron-sdk-build produces at build time
/// (untangle slice 4.3); the default run neither writes nor checks them in the tree. A set, read for membership.
pub(crate) const BUILD_TIME_OUTPUTS: &[&str] = &[
    "crates/oneiron-py/src/generated/agent_verbs.rs",
    "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs",
    "crates/oneiron-remote/src/generated/agent_verbs.rs",
    "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs",
    "crates/oneiron-server/src/api/facade/generated/dispatch.rs",
    "crates/oneiron-server/src/api/facade/generated/host_door_rows.rs",
    "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs",
    "crates/oneiron-uniffi/src/generated/facade_generated.rs",
    "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
    "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts",
    "crates/oneiron/src/verbs/generated/catalog_fragment_revision.rs",
    "crates/oneiron/src/verbs/generated/code-mode.d.ts",
    "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
    "crates/oneiron/src/verbs/generated/sdk_generated.rs",
    "crates/oneiron/src/verbs/generated/verb_catalog.rs",
    "crates/oneiron/src/generated/core_verb_names.rs",
];

/// Port of generate.py:2215-2236 (PACKAGE_OUTPUTS): each package's outputs, which its build writes in the tree
/// (`--package <name>`), by package name in the literal's order.
pub(crate) const PACKAGE_OUTPUTS: &[(&str, &[&str])] = &[
    (
        "oneiron",
        &[
            "packages/oneiron/src/facade-types.ts",
            "packages/oneiron/src/agent-verbs.ts",
            "packages/oneiron/src/facade-verbs.ts",
            "packages/oneiron/src/native-verbs.ts",
        ],
    ),
    (
        "oneiron-client",
        &[
            "packages/oneiron-client/src/facade.ts",
            "packages/oneiron-client/src/facade-types.ts",
        ],
    ),
    (
        "oneiron-py",
        &[
            "crates/oneiron-py/python/oneiron/_facade_verbs.py",
            "crates/oneiron-py/python/oneiron/_facade_verbs.pyi",
            "crates/oneiron-py/python/oneiron/facade_types.pyi",
        ],
    ),
    (
        "docs",
        &[
            "docs/agent-sdk/facade-types.md",
            "docs/agent-sdk/types.md",
            "docs/agent-sdk/verbs.md",
        ],
    ),
];

/// `PACKAGE_OUTPUTS[name]`.
pub(crate) fn package_outputs(name: &str) -> Option<&'static [&'static str]> {
    PACKAGE_OUTPUTS
        .iter()
        .find(|(package, _)| *package == name)
        .map(|(_, paths)| *paths)
}

/// Port of generate.py:2237 (PACKAGE_PATHS): every package output path (a set, read for membership).
pub(crate) fn is_package_path(path: &str) -> bool {
    PACKAGE_OUTPUTS
        .iter()
        .any(|(_, paths)| paths.contains(&path))
}

/// The outputs of one run, as generate.py's `outputs()` returns them: each repository path (`/`-separated, relative
/// to the root) with its text, or `None` for an old home the default mode deletes, in the `files` dict's order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outputs {
    files: IndexMap<String, Option<String>>,
}

impl Outputs {
    /// `files[path] = text`: a new path goes last, a present one keeps its place (Python's dict).
    pub(crate) fn insert(&mut self, path: &str, text: Option<String>) {
        self.files.insert(path.to_owned(), text);
    }

    /// Every output in order: its path, and its text or `None` for a deletion.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        self.files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_deref()))
    }

    /// The output at `path`: `None` when there is none, `Some(None)` for a deletion.
    pub fn get(&self, path: &str) -> Option<Option<&str>> {
        self.files.get(path).map(Option::as_deref)
    }

    /// How many outputs there are, deletions included.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

/// Python's `Path` of a command-line directory (`type=Path`): its text as `pathlib` normalises it, which the error
/// messages of the files under it print: repeated and trailing `/` and `.` parts dropped (but a leading `//`), and
/// the empty path is `.`.
pub(crate) fn pure_path(text: &str) -> String {
    let (anchor, rest) = if let Some(rest) = text.strip_prefix("//") {
        if rest.starts_with('/') {
            ("/", rest.trim_start_matches('/'))
        } else {
            ("//", rest)
        }
    } else if let Some(rest) = text.strip_prefix('/') {
        ("/", rest)
    } else {
        ("", text)
    };
    let parts: Vec<&str> = rest
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let joined = format!("{anchor}{}", parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `path.parent.mkdir(parents=True, exist_ok=True)` (pathlib's `mkdir`): makes the directory and any missing parent;
/// an error names the directory whose own `mkdir` failed, as Python's does.
pub(crate) fn mkdir_parents(path: &Path) -> Result<(), GenerateError> {
    match fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // `self.parent == self`: the root (or `.`) has no parent to make. A relative path's last parent is `.`.
            let parent = match path.parent() {
                Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
                Some(parent) => parent,
                None => path,
            };
            if parent == path {
                return Err(GenerateError::os(&error, path));
            }
            mkdir_parents(parent)?;
            // `self.mkdir(mode, parents=False, exist_ok=True)`.
            match fs::create_dir(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() != io::ErrorKind::NotFound && path.is_dir() => Ok(()),
                Err(error) => Err(GenerateError::os(&error, path)),
            }
        }
        // `exist_ok`: any other failure is no error when the directory is there.
        Err(_) if path.is_dir() => Ok(()),
        Err(error) => Err(GenerateError::os(&error, path)),
    }
}

/// `path.write_text(text)`: UTF-8, `\n` as it is (Python on Linux and macOS), Python's `OSError` on a failure.
pub(crate) fn write_text(path: &Path, text: &str) -> Result<(), GenerateError> {
    fs::write(path, text).map_err(|error| GenerateError::os(&error, path))
}

// ---- outputs()'s locals, and the replay entry points of the ported emitters (DESIGN 9.3)

/// generate.py:2242 `facade_rows`: `[r for r in ROWS if r.get("context", "memory") == "memory"] + BOARD_HOST_ROWS`,
/// recomputed as `outputs()` does (the same rows as `FACADE_ROWS`).
pub(crate) fn local_facade_rows(generator: &Generator) -> Vec<RowId> {
    generator
        .callable_rows
        .iter()
        .copied()
        .filter(|&id| context_is(&generator.rows[id], "memory"))
        .chain(generator.board_host_rows.iter().copied())
        .collect()
}

/// generate.py:2461: `'\n'.join(ts_native_signature(r) for r in facade_rows)`.
fn ts_native(generator: &mut Generator, facade_rows: &[RowId]) -> Result<String, GenerateError> {
    let mut signatures = Vec::new();
    for &id in facade_rows {
        signatures.push(ts_native_signature(generator, id)?);
    }
    Ok(signatures.join("\n"))
}

/// The verb tree as Python's dicts: `{name: {'row': row, 'children': {...}}}` (the replay's logged value).
fn tree_value(generator: &Generator, tree: &VerbTree) -> Value {
    let mut out = Dict::new();
    for (name, node) in tree {
        let mut entry = Dict::new();
        entry.insert(
            "row".to_owned(),
            node.row
                .map_or(Value::None, |id| Value::Dict(row_of(generator, id))),
        );
        entry.insert(
            "children".to_owned(),
            tree_value(generator, &node.children),
        );
        out.insert(name.clone(), Value::Dict(entry));
    }
    Value::Dict(out)
}

/// The replay's `ts_native_signature#n`: the nth facade row's signature (generate.py:2461).
pub(crate) fn replay_ts_native_signature(
    generator: &mut Generator,
    n: usize,
) -> Result<Value, GenerateError> {
    let facade_rows = local_facade_rows(generator);
    let id = n
        .checked_sub(1)
        .and_then(|at| facade_rows.get(at))
        .copied()
        .ok_or_else(|| {
            GenerateError::exit(format!("port-harness replay: no facade row {n}"))
        })?;
    ts_native_signature(generator, id).map(Value::Str)
}

/// The replay's `http_facade#1` (generate.py:2510).
pub(crate) fn replay_http_facade(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    http_facade(generator).map(Value::Str)
}

/// The replay's `verb_tree#n`: the first call is `http_facade`'s over `FACADE_ROWS` (generate.py:1534), the next
/// three `outputs()`'s over its `facade_rows` (2528-2530).
pub(crate) fn replay_verb_tree(generator: &mut Generator, n: usize) -> Result<Value, GenerateError> {
    let rows = if n == 1 {
        generator.facade_rows.clone()
    } else {
        local_facade_rows(generator)
    };
    let tree = verb_tree(generator, &rows)?;
    Ok(tree_value(generator, &tree))
}

/// The replay's `ts_facade_module#1` (generate.py:2528).
pub(crate) fn replay_ts_facade_module(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let tree = verb_tree(generator, &rows)?;
    ts_facade_module(generator, &tree).map(Value::Str)
}

/// The replay's `python_facade_module#n`: the runtime module first (generate.py:2529), then the stub (2530).
pub(crate) fn replay_python_facade_module(
    generator: &mut Generator,
    n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let tree = verb_tree(generator, &rows)?;
    python_facade_module(generator, &tree, n == 2).map(Value::Str)
}

/// The replay's `ts_native_module#1` (generate.py:2579). Its arguments are recomputed at the call: by then every
/// type the signatures and the census name is rooted, so neither call changes the inventory, and each gives the text
/// `outputs()` passed.
pub(crate) fn replay_ts_native_module(
    generator: &mut Generator,
    _n: usize,
) -> Result<Value, GenerateError> {
    let rows = local_facade_rows(generator);
    let signatures = ts_native(generator, &rows)?;
    let facade_rows: Vec<Dict> = generator
        .facade_rows
        .iter()
        .map(|&id| row_of(generator, id))
        .collect();
    let refs: Vec<&Dict> = facade_rows.iter().collect();
    let inventory = generator.inventory_mut()?;
    let census = inventory.census(&refs)?;
    let facade_types = inventory.typescript(&census)?;
    ts_native_module(generator, &signatures, &facade_types).map(Value::Str)
}

/// The output a `python_facade_module` value is: the stub holds its `typing` import line.
pub(crate) fn python_facade_module_path(text: &str) -> &'static str {
    if text.contains("\nfrom typing import Any, overload\n") {
        "crates/oneiron-py/python/oneiron/_facade_verbs.pyi"
    } else {
        "crates/oneiron-py/python/oneiron/_facade_verbs.py"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // python3 -c "from pathlib import Path; print([str(Path(p)) for p in P])" on nelly.
    #[test]
    fn pure_path_is_pathlibs() {
        let cases = [
            ("", "."),
            (".", "."),
            ("./", "."),
            ("out", "out"),
            ("out/", "out"),
            ("./out//x/./y/", "out/x/y"),
            ("/", "/"),
            ("/a/../b", "/a/../b"),
            ("//a", "//a"),
            ("///a", "/a"),
            ("a/./.", "a"),
            ("..", ".."),
        ];
        for (text, expected) in cases {
            assert_eq!(pure_path(text), expected, "{text:?}");
        }
    }

    #[test]
    fn package_tables() {
        assert!(is_package_path("docs/agent-sdk/types.md"));
        assert!(!is_package_path(
            "crates/oneiron/src/verbs/generated/verb_catalog.rs"
        ));
        assert_eq!(package_outputs("oneiron-client").map(<[&str]>::len), Some(2));
        assert_eq!(package_outputs("nope"), None);
        assert_eq!(BUILD_TIME_OUTPUTS.len(), 16);
    }
}
