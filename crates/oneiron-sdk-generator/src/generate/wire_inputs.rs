//! Lib split W3-GEN: the verb rows whose input checks and input schemas `oneiron-verb-wire` emits, and each one's
//! input type as that crate names it.
//!
//! A row's input type text names lib paths, read from the SDK module (`ROOT_CONTEXT`). An exact index (one that never
//! guesses by name) resolves each path to its item. Every path must name an item of `oneiron-verb-wire` that is `pub`,
//! unindented and not `cfg`-gated, at a module path whose every module is a `pub mod` that is not `cfg`-gated; the text
//! is then rewritten to those items' own `crate::` paths, which the wire crate names without the lib. One path that
//! fails keeps the row in the lib. The lookups read their own index, so they allocate no name of the shared inventory,
//! and every file they read is a dependency of the run.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use crate::error::GenerateError;
use crate::facade_types::index::{Found, Index, ItemRef};
use crate::facade_types::{PRELUDE, ROOT_CONTEXT, crate_dir};
use crate::py::re::compile;

/// The crate the rows' input checks and input schemas go down into.
pub(crate) const WIRE_CRATE: &str = "oneiron_verb_wire";

/// The wire crate's build-time output: those rows' input checks and input schemas, which its `verb_input` module
/// includes.
pub(crate) const WIRE_INPUTS_PATH: &str =
    "crates/oneiron-verb-wire/src/generated/verb_input_checks.rs";

/// The external types the wire crate names as the lib does (it depends on `serde_json`).
const EXTERNAL_TYPES: &[&str] = &["serde_json::Value"];

/// One path of a type text: `crate::a::B`, `B`, `Vec`.
static PATH: LazyLock<Regex> = LazyLock::new(|| compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*"));

/// A `cfg` gate among the attributes of an item or a module declaration.
static CFG: LazyLock<Regex> = LazyLock::new(|| compile(r"#\s*\[\s*cfg\s*\("));

/// The ownership lookups of one generator run.
pub(crate) struct WireInputs {
    index: Index,
    /// Each type text looked up, with its text in the wire crate, or `None`.
    found: IndexMap<String, Option<String>>,
}

impl WireInputs {
    /// Reads the `EAGER` crates into an exact index of this run's own.
    pub(crate) fn new(root: &Path) -> Result<Self, GenerateError> {
        Ok(Self {
            index: Index::exact(root)?,
            found: IndexMap::new(),
        })
    }

    /// The crate source files the lookups read, as paths from the repository root.
    pub(crate) fn dependencies(&self) -> BTreeSet<String> {
        self.index.dependency_paths().collect()
    }

    /// `input`, a row's input type text, as the wire crate names it; `None` when one of its paths names no item the
    /// wire crate can name.
    pub(crate) fn wire_type(&mut self, input: &str) -> Result<Option<String>, GenerateError> {
        if let Some(found) = self.found.get(input) {
            return Ok(found.clone());
        }
        let mut wire = String::new();
        let mut last = 0;
        let mut owned = true;
        for path in PATH.find_iter(input) {
            wire += &input[last..path.start()];
            last = path.end();
            let text = path.as_str();
            if PRELUDE.contains(&text) || EXTERNAL_TYPES.contains(&text) {
                wire += text;
                continue;
            }
            match self.wire_path(text)? {
                Some(path) => wire += &path,
                None => {
                    owned = false;
                    break;
                }
            }
        }
        wire += &input[last..];
        let found = owned.then_some(wire);
        self.found.insert(input.to_owned(), found.clone());
        Ok(found)
    }

    /// The wire crate's own path to the item `path` names from the SDK module, when the wire crate can name it there.
    fn wire_path(&mut self, path: &str) -> Result<Option<String>, GenerateError> {
        let (crate_name, file) = ROOT_CONTEXT;
        let file = crate_dir(crate_name)
            .and_then(|dir| file.strip_prefix(dir))
            .and_then(|file| file.strip_prefix('/'))
            .unwrap_or(file);
        let module: Vec<String> = Path::new(file)
            .parent()
            .map(|parent| {
                parent
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let segments: Vec<String> = path.split("::").map(str::to_owned).collect();
        let Some(Found::Item(item)) = self
            .index
            .resolve(&segments, crate_name, file, &module, 0)?
        else {
            return Ok(None);
        };
        if !self.nameable(&item) {
            return Ok(None);
        }
        let mut wire = vec!["crate"];
        wire.extend(item.module.iter().map(String::as_str));
        wire.push(&item.name);
        Ok(Some(wire.join("::")))
    }

    /// Whether the wire crate names `item` at its own module path: a `pub`, unindented wire item that is not
    /// `cfg`-gated, of a name no lib macro call defines (the index reads no macro-defined item, so a lib module's
    /// own macro-defined type of that name would shadow a glob-imported wire one unseen), with every module down to
    /// it a `pub mod` that is not `cfg`-gated.
    fn nameable(&mut self, item: &ItemRef) -> bool {
        if item.crate_name != WIRE_CRATE || !item.top || !item.public || CFG.is_match(&item.attrs) {
            return false;
        }
        if let Some(calls) = self.index.macro_uses.get(&item.name) {
            let files: Vec<(String, String)> = calls
                .iter()
                .map(|(crate_name, file, _)| (crate_name.clone(), file.clone()))
                .collect();
            let in_lib = files
                .iter()
                .any(|(crate_name, _)| crate_name == ROOT_CONTEXT.0);
            self.index.dependencies.extend(files);
            if in_lib {
                return false;
            }
        }
        for depth in 0..item.module.len() {
            let parent = (WIRE_CRATE.to_owned(), item.module[..depth].to_vec());
            let Some(file) = self.index.modules.get(&parent).cloned() else {
                return false;
            };
            self.index.record_dependency(WIRE_CRATE, &file);
            let Some(text) = self.index.files.get(&(WIRE_CRATE.to_owned(), file)) else {
                return false;
            };
            if !public_module(text, &item.module[depth]) {
                return false;
            }
        }
        true
    }
}

/// Whether a module file declares `name` as a `pub mod` with a file of its own that is not `cfg`-gated.
fn public_module(text: &str, name: &str) -> bool {
    let declaration = format!("pub mod {name};");
    let lines: Vec<&str> = text.lines().collect();
    lines.iter().enumerate().any(|(at, line)| {
        line.trim() == declaration && !CFG.is_match(&attributes_above(&lines[..at]))
    })
}

/// The attribute lines above a declaration, back to the previous item or a blank line, joined (as `read_item` reads
/// an item's attributes).
fn attributes_above(lines: &[&str]) -> String {
    let mut above = Vec::new();
    for line in lines.iter().rev().map(|line| line.trim()) {
        let ends_item =
            line.ends_with(['}', ';', '{']) && !(line.starts_with('#') || line.starts_with("//"));
        if line.is_empty() || ends_item {
            break;
        }
        above.push(line);
    }
    above.join(" ")
}

#[cfg(test)]
mod tests {
    use super::public_module;

    #[test]
    fn a_gated_or_private_module_is_not_public() {
        let text = "pub mod open;\nmod private;\n#[cfg(feature = \"sync\")]\npub mod gated;\n#[cfg(any(\n    \
                    feature = \"a\",\n))]\npub mod wide;\n#[doc(hidden)]\npub mod hidden;\n";
        assert!(public_module(text, "open"));
        assert!(public_module(text, "hidden"));
        assert!(!public_module(text, "private"));
        assert!(!public_module(text, "gated"));
        assert!(!public_module(text, "wide"));
        assert!(!public_module(text, "absent"));
    }
}
