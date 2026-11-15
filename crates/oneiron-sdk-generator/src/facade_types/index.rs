//! Every struct, enum and alias of the engine crates, with each file's imports, and the heuristic resolver that
//! finds the item a path names from a file.
//!
//! The index reads every file of each crate it loads, but a file's text reaches an output only through a lookup by
//! key: the items of a name (in one file, or in every loaded file for the lookup by name), a file's imports, the file
//! of a module, a file's text, the serde impls of a name, the macro calls that define a name and the macros they
//! call. Each lookup records in [`Index::dependencies`] every file that holds an entry it read or could have chosen,
//! and `oneiron-sdk-build` watches that set. An edit to a file outside it changes no output unless it adds an entry a
//! lookup would read (a new item, serde impl or macro of a name looked up) or makes the generator refuse the file, and
//! a new file is in no set at all: the limit `oneiron-sdk-build` documents.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::LazyLock;

use indexmap::{IndexMap, IndexSet};
use regex::{Captures, Regex};

use super::reader::{
    self, alias_body, close_of, find_from, next_char, prev_char, search_bounded, slice, split_top,
    strip_comments,
};
use super::{
    EAGER, EXTERNAL, Ir, ItemKey, Key, RECURSION_LIMIT, STRING, crate_dir, holds, index_error,
    lib_family, recursion_error, substring_not_found,
};
use crate::error::GenerateError;
use crate::py::re::compile;
use crate::py::text::{lstrip, strip};

/// An item's kind: Python's `'struct'`, `'enum'` or `'type'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Struct,
    Enum,
    Type,
}

/// An item's body shape: Python's `'alias'`, `'unit'`, `'named'` or `'tuple'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Shape {
    Alias,
    Unit,
    Named,
    Tuple,
}

/// One `struct`, `enum` or `type` header and what follows it.
#[derive(Debug)]
pub(crate) struct Item {
    pub(crate) crate_name: String,
    pub(crate) file: String,
    pub(crate) module: Vec<String>,
    pub(crate) name: String,
    pub(crate) kind: Kind,
    /// Not indented: the header starts its line.
    pub(crate) top: bool,
    /// Nameable outside its crate: a bare `pub`, never `pub(crate)` and the like.
    pub(crate) public: bool,
    pub(crate) attrs: String,
    pub(crate) generics: Vec<String>,
    pub(crate) body: String,
    pub(crate) shape: Shape,
    /// `Item.key()`: `(crate, file, name, module)`.
    pub(crate) key: Key,
}

/// An item from the index: shared, and compared by identity where Python writes `is`.
pub(crate) type ItemRef = Rc<Item>;

/// What `Index.resolve` finds: an item, or `("external", name)` for a path into an external crate.
#[derive(Clone, Debug)]
pub(crate) enum Found {
    Item(ItemRef),
    External(String),
}

/// A file's imports (`Index.uses`): alias -> path (first one wins), and its glob paths in order.
#[derive(Debug, Default)]
pub(crate) struct Uses {
    pub(crate) names: IndexMap<String, Vec<String>>,
    pub(crate) globs: Vec<Vec<String>>,
}

/// A file's place, `(crate, relative path)`.
pub(crate) type FileKey = (String, String);
/// A module's place, `(crate, module path)`.
pub(crate) type ModuleKey = (String, Vec<String>);

/// Python: `(?m)^([ \t]*)(pub(?:\s*\([^)]*\))?\s+)?(struct|enum|type)\s+([A-Za-z_]\w*)`
static HEADER: LazyLock<Regex> = LazyLock::new(|| {
    compile(r"(?m)^([ \t]*)(pub(?:\s*\([^)]*\))?\s+)?(struct|enum|type)\s+([A-Za-z_]\w*)")
});
/// Python: `(?m)^[ \t]*impl\b[^{;]*?\b(?:serde::)?Serialize\s+for\s+([A-Za-z_]\w*)`. The
/// two `\b`s are Python's: the part between `impl` and `Serialize` cannot be empty there, so it is one
/// non-word character, or a non-word character, any run, and a non-word character, tried shortest first.
static IMPL: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*impl(?:[^{;\w]|[^{;\w][^{;]*?[^{;\w])(?:serde::)?Serialize\s+for\s+([A-Za-z_]\w*)",
    )
});
/// Python: `(?m)^[ \t]*impl\b[^{;]*?\b(?:serde::)?Deserialize<'de>\s+for\s+([A-Za-z_]\w*)`,
/// with `\b` as in [`IMPL`].
static DE_IMPL: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*impl(?:[^{;\w]|[^{;\w][^{;]*?[^{;\w])(?:serde::)?Deserialize<'de>\s+for\s+([A-Za-z_]\w*)",
    )
});
/// Python: `(?m)^[ \t]*(?:pub\s+)?(\w+)!\s*[({]\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct\s+)?([A-Z]\w*)\b`. The
/// final `\b` always holds after a greedy run of word characters, so it is dropped.
static MACRO_USE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r"(?m)^[ \t]*(?:pub\s+)?(\w+)!\s*[({]\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct\s+)?([A-Z]\w*)",
    )
});
/// Python: `macro_rules!\s*(\w+)\s*\{`
static MACRO_RULES: LazyLock<Regex> = LazyLock::new(|| compile(r"macro_rules!\s*(\w+)\s*\{"));
/// Python: `(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);`
static USE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?use\s+([^;]+);"));
/// Python: `serialize_str|collect_str`
static SERIALIZE_STR: LazyLock<Regex> = LazyLock::new(|| compile("serialize_str|collect_str"));

/// The items, files, modules, serde impls and macros of the crates read so far, and the resolver over them.
#[derive(Debug)]
pub(crate) struct Index {
    root: PathBuf,
    /// The crates read so far (a set).
    pub(crate) loaded: IndexSet<String>,
    /// name -> every item of that name, in read order.
    pub(crate) items: IndexMap<String, Vec<ItemRef>>,
    /// (crate, file) -> text.
    pub(crate) files: IndexMap<FileKey, String>,
    /// (crate, module path) -> file; the first file of a module wins.
    pub(crate) modules: IndexMap<ModuleKey, String>,
    /// name -> each `impl Serialize for <name>` as (crate, file, offset of its line).
    pub(crate) impls: IndexMap<String, Vec<(String, String, usize)>>,
    /// name -> each `impl Deserialize<'de> for <name>`.
    pub(crate) de_impls: IndexMap<String, Vec<(String, String, usize)>>,
    /// type name -> each (crate, file, macro) that defines it with a macro call.
    pub(crate) macro_uses: IndexMap<String, Vec<(String, String, String)>>,
    /// macro name -> its `macro_rules!` text (a later definition replaces the text in place).
    pub(crate) macros: IndexMap<String, String>,
    /// macro name -> each file that defines it with `macro_rules!`, in read order (any of them can hold the text
    /// `macros` keeps).
    pub(crate) macro_files: IndexMap<String, Vec<FileKey>>,
    pub(crate) use_cache: IndexMap<FileKey, Rc<Uses>>,
    /// Names `by_name` chose among candidates of more than one file (a set).
    pub(crate) guesses: IndexSet<String>,
    /// The dependency set: every read file whose entries a lookup read (see the module doc), sorted. Nothing else of
    /// the crate sources reaches an output.
    pub(crate) dependencies: BTreeSet<FileKey>,
    /// Never guess: a name that no file's own items, imports or globs resolve stays unresolved, where the lookup by
    /// name would pick the nearest candidate (`Index::exact`).
    exact: bool,
}

impl Index {
    /// Reads the `EAGER` crates.
    pub(crate) fn new(root: &Path) -> Result<Self, GenerateError> {
        let mut index = Self {
            root: root.to_path_buf(),
            loaded: IndexSet::new(),
            items: IndexMap::new(),
            files: IndexMap::new(),
            modules: IndexMap::new(),
            impls: IndexMap::new(),
            de_impls: IndexMap::new(),
            macro_uses: IndexMap::new(),
            macros: IndexMap::new(),
            macro_files: IndexMap::new(),
            use_cache: IndexMap::new(),
            guesses: IndexSet::new(),
            dependencies: BTreeSet::new(),
            exact: false,
        };
        for crate_name in EAGER {
            index.load(crate_name)?;
        }
        Ok(index)
    }

    /// Reads the `EAGER` crates into an index that never guesses (lib split W3-GEN): the item a path resolves to is
    /// the one rustc names there, or the path is unresolved. A guess by name could name another crate's item of the
    /// same name, and a type text emitted from it would still compile.
    pub(crate) fn exact(root: &Path) -> Result<Self, GenerateError> {
        let mut index = Self::new(root)?;
        index.exact = true;
        Ok(index)
    }

    /// Every `*.rs` file under the crate's source directory but the test-like ones, in `sorted(base.rglob('*.rs'))`
    /// order.
    pub(crate) fn load(&mut self, crate_name: &str) -> Result<(), GenerateError> {
        if self.loaded.contains(crate_name) {
            return Ok(());
        }
        let Some(dir) = crate_dir(crate_name) else {
            return Ok(());
        };
        self.loaded.insert(crate_name.to_owned());
        let base = self.root.join(dir);
        let mut paths = Vec::new();
        rglob_rs(&base, &mut paths);
        // Path order compares components, as Python's does (`foo/mod.rs` before `foo.rs`).
        paths.sort();
        for path in paths {
            let relative = relative_posix(&path, &base);
            if format!("/{relative}").contains("/tests/")
                || relative.ends_with("_tests.rs")
                || relative.ends_with("/tests.rs")
                || relative == "tests.rs"
            {
                continue;
            }
            let text = crate::py::read_text_replacing(&path)?;
            let file_key = (crate_name.to_owned(), relative.clone());
            self.files.insert(file_key.clone(), text);
            let text = &self.files[&file_key];
            let mut parts: Vec<String> = relative[..relative.len() - 3]
                .split('/')
                .map(str::to_owned)
                .collect();
            if parts
                .last()
                .is_some_and(|last| matches!(last.as_str(), "mod" | "lib" | "main"))
            {
                parts.pop();
            }
            self.modules
                .entry((crate_name.to_owned(), parts.clone()))
                .or_insert_with(|| relative.clone());
            for header in HEADER.captures_iter(text) {
                let indent = header.get(1).map_or("", |m| m.as_str());
                if &header[3] == "type" && header.get(2).is_none() && !indent.is_empty() {
                    continue;
                }
                if let Some(item) = read_item(crate_name, &relative, &parts, text, &header)? {
                    self.items
                        .entry(header[4].to_owned())
                        .or_default()
                        .push(Rc::new(item));
                }
            }
            for found in IMPL.captures_iter(text) {
                let at = found.get(0).map_or(0, |m| m.start());
                self.impls.entry(found[1].to_owned()).or_default().push((
                    crate_name.to_owned(),
                    relative.clone(),
                    at,
                ));
            }
            for found in DE_IMPL.captures_iter(text) {
                let at = found.get(0).map_or(0, |m| m.start());
                self.de_impls.entry(found[1].to_owned()).or_default().push((
                    crate_name.to_owned(),
                    relative.clone(),
                    at,
                ));
            }
            if text.contains("macro_rules!") || text.contains("!(") {
                for found in MACRO_USE.captures_iter(text) {
                    if &found[1] != "macro_rules" {
                        self.macro_uses
                            .entry(found[2].to_owned())
                            .or_default()
                            .push((crate_name.to_owned(), relative.clone(), found[1].to_owned()));
                    }
                }
                for found in MACRO_RULES.captures_iter(text) {
                    let Some(whole) = found.get(0) else { continue };
                    let body =
                        slice(text, whole.start(), close_of(text, whole.end() - 1)).to_owned();
                    self.macros.insert(found[1].to_owned(), body);
                    self.macro_files
                        .entry(found[1].to_owned())
                        .or_default()
                        .push((crate_name.to_owned(), relative.clone()));
                }
            }
        }
        Ok(())
    }

    // ---- the dependency set

    /// Adds a file a lookup read to `dependencies`; a file the index did not read (no such file) is left out.
    pub(crate) fn record_dependency(&mut self, crate_name: &str, file: &str) {
        let key = (crate_name.to_owned(), file.to_owned());
        if self.files.contains_key(&key) {
            self.dependencies.insert(key);
        }
    }

    /// `dependencies` as paths from the repository root (the crate's `CRATES` directory, then the file), sorted.
    pub(crate) fn dependency_paths(&self) -> impl Iterator<Item = String> + '_ {
        self.dependencies.iter().filter_map(|(crate_name, file)| {
            crate_dir(crate_name).map(|dir| format!("{dir}/{file}"))
        })
    }

    // ---- resolution

    /// The file's imports, alias -> path, and its glob paths.
    pub(crate) fn uses(&mut self, crate_name: &str, file: &str) -> Result<Rc<Uses>, GenerateError> {
        self.record_dependency(crate_name, file);
        let key = (crate_name.to_owned(), file.to_owned());
        if let Some(found) = self.use_cache.get(&key) {
            return Ok(Rc::clone(found));
        }
        let mut uses = Uses::default();
        if let Some(text) = self.files.get(&key) {
            for found in USE.captures_iter(text) {
                for (alias, path) in expand_use(&[], &strip_comments(&found[1]), 0)? {
                    if alias == "*" {
                        uses.globs.push(path);
                    } else {
                        uses.names.entry(alias).or_insert(path);
                    }
                }
            }
        }
        let uses = Rc::new(uses);
        self.use_cache.insert(key, Rc::clone(&uses));
        Ok(uses)
    }

    /// A path's crate and module segments, from a file in (crate, module); `None` for an external crate. A path that
    /// names a `CRATES` crate reads it.
    pub(crate) fn absolute(
        &mut self,
        segments: &[String],
        crate_name: &str,
        module: &[String],
    ) -> Result<Option<(String, Vec<String>)>, GenerateError> {
        let head = segments.first().ok_or_else(index_error)?.as_str();
        Ok(Some(match head {
            "crate" => (crate_name.to_owned(), segments[1..].to_vec()),
            "self" => (crate_name.to_owned(), [module, &segments[1..]].concat()),
            "super" => {
                let up = segments
                    .iter()
                    .take_while(|segment| *segment == "super")
                    .count();
                let keep = module.len().saturating_sub(up);
                (
                    crate_name.to_owned(),
                    [&module[..keep], &segments[up..]].concat(),
                )
            }
            _ if crate_dir(head).is_some() => {
                self.load(head)?;
                (head.to_owned(), segments[1..].to_vec())
            }
            _ if holds(EXTERNAL, head) => return Ok(None),
            _ => (crate_name.to_owned(), [module, segments].concat()),
        }))
    }

    /// The item a path names from a file, an external name, or `None`; the search stops past depth 12.
    pub(crate) fn resolve(
        &mut self,
        segments: &[String],
        crate_name: &str,
        file: &str,
        module: &[String],
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        if depth > 12 {
            return Ok(None);
        }
        if segments.len() == 1 {
            return self.resolve_name(&segments[0], crate_name, file, module, depth);
        }
        let head = segments.first().ok_or_else(index_error)?;
        if !matches!(head.as_str(), "crate" | "self" | "super") && crate_dir(head).is_none() {
            let uses = self.uses(crate_name, file)?;
            if let Some(path) = uses.names.get(head) {
                let joined = [path.as_slice(), &segments[1..]].concat();
                return self.resolve(&joined, crate_name, file, module, depth + 1);
            }
        }
        let Some((target, path)) = self.absolute(segments, crate_name, module)? else {
            return Ok(Some(Found::External(segments[segments.len() - 1].clone())));
        };
        let (name, parent) = path.split_last().ok_or_else(index_error)?;
        self.resolve_in(&target, parent, name, depth + 1)
    }

    /// A module path as its file sits, through a parent's `use <module> as <name>;` (FIX 8907: `task_verb::sdk` is
    /// `crate::verbs`).
    pub(crate) fn module_place(
        &mut self,
        crate_name: &str,
        module: &[String],
        depth: usize,
    ) -> Result<(String, Vec<String>), GenerateError> {
        if module.is_empty() || depth > 12 {
            return Ok((crate_name.to_owned(), module.to_vec()));
        }
        // A module with a file of its own sits there: the file found is a dependency (its removal moves the module).
        if let Some(file) = self
            .modules
            .get(&(crate_name.to_owned(), module.to_vec()))
            .cloned()
        {
            self.record_dependency(crate_name, &file);
            return Ok((crate_name.to_owned(), module.to_vec()));
        }
        let (last, head) = module.split_last().ok_or_else(index_error)?;
        let (crate_name, parent) = self.module_place(crate_name, head, depth + 1)?;
        if let Some(file) = self
            .modules
            .get(&(crate_name.clone(), parent.clone()))
            .cloned()
        {
            let uses = self.uses(&crate_name, &file)?;
            if let Some(path) = uses.names.get(last)
                && let Some((target, place)) = self.absolute(path, &crate_name, &parent)?
            {
                return self.module_place(&target, &place, depth + 1);
            }
        }
        let mut place = parent;
        place.push(last.clone());
        Ok((crate_name, place))
    }

    /// The item `name` names in a module: the module file's own item, its import of that name, a glob's item, else
    /// the best candidate by name under the module.
    pub(crate) fn resolve_in(
        &mut self,
        crate_name: &str,
        module: &[String],
        name: &str,
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        if depth > 12 {
            return Ok(None);
        }
        let (crate_name, module) = self.module_place(crate_name, module, 0)?;
        if let Some(file) = self
            .modules
            .get(&(crate_name.clone(), module.clone()))
            .cloned()
        {
            self.record_dependency(&crate_name, &file);
            if let Some(item) = self.local(name, &crate_name, &file) {
                return Ok(Some(Found::Item(item)));
            }
            let uses = self.uses(&crate_name, &file)?;
            if let Some(path) = uses.names.get(name)
                && let Some(found) = self.resolve(path, &crate_name, &file, &module, depth + 1)?
            {
                return Ok(Some(found));
            }
            for glob in &uses.globs {
                let Some((target, place)) = self.absolute(glob, &crate_name, &module)? else {
                    continue;
                };
                if let Some(found) = self.resolve_in(&target, &place, name, depth + 1)? {
                    return Ok(Some(found));
                }
            }
        }
        if self.exact {
            return Ok(None);
        }
        Ok(self
            .by_name(name, &crate_name, &module, Some(&module))
            .map(Found::Item))
    }

    /// The item a bare name names from a file: the file's own item, its import of that name, a glob's item, else the
    /// best candidate by name.
    pub(crate) fn resolve_name(
        &mut self,
        name: &str,
        crate_name: &str,
        file: &str,
        module: &[String],
        depth: usize,
    ) -> Result<Option<Found>, GenerateError> {
        self.record_dependency(crate_name, file);
        if let Some(item) = self.local(name, crate_name, file) {
            return Ok(Some(Found::Item(item)));
        }
        let uses = self.uses(crate_name, file)?;
        if let Some(path) = uses.names.get(name)
            && let Some(found) = self.resolve(path, crate_name, file, module, depth + 1)?
        {
            return Ok(Some(found));
        }
        for glob in &uses.globs {
            let Some((target, place)) = self.absolute(glob, crate_name, module)? else {
                continue;
            };
            // A glob's external name does not count here (`not isinstance(found, tuple)`).
            if let Some(Found::Item(item)) = self.resolve_in(&target, &place, name, depth + 1)? {
                return Ok(Some(Found::Item(item)));
            }
        }
        if self.exact {
            return Ok(None);
        }
        Ok(self
            .by_name(name, crate_name, module, None)
            .map(Found::Item))
    }

    /// `min(local, key=lambda item: not item.top)` over the items of that name in one file: the first top-level
    /// one, else the first.
    fn local(&self, name: &str, crate_name: &str, file: &str) -> Option<ItemRef> {
        let items = self.items.get(name)?;
        let mut local = items
            .iter()
            .filter(|item| item.crate_name == crate_name && item.file == file);
        let first = local.clone().next()?;
        Some(Rc::clone(local.find(|item| item.top).unwrap_or(first)))
    }

    /// A type a macro defines, a string when the macro writes it with `serialize_str`. Each file that calls a macro
    /// to define `name`, and each file that defines a macro so called, is a dependency.
    pub(crate) fn macro_token(&mut self, name: &str) -> Option<Ir> {
        let uses = self.macro_uses.get(name)?;
        for (crate_name, file, macro_name) in uses {
            self.dependencies.insert((crate_name.clone(), file.clone()));
            for definition in self.macro_files.get(macro_name).into_iter().flatten() {
                self.dependencies.insert(definition.clone());
            }
        }
        uses.iter()
            .any(|(_, _, macro_name)| {
                SERIALIZE_STR.is_match(self.macros.get(macro_name).map_or("", String::as_str))
            })
            .then_some(STRING)
    }

    /// The best candidate of that name, same crate, under `within`, nearest module; ties keep the first. Every file
    /// that holds an item of that name is a dependency, a candidate or not (an edit there can make it one).
    /// "Same crate" compares `lib_family`: the crates below `oneiron` that mirror its modules count as `oneiron`.
    pub(crate) fn by_name(
        &mut self,
        name: &str,
        crate_name: &str,
        module: &[String],
        within: Option<&[String]>,
    ) -> Option<ItemRef> {
        let family = lib_family(crate_name);
        let all = self.items.get(name)?;
        self.dependencies.extend(
            all.iter()
                .map(|item| (item.crate_name.clone(), item.file.clone())),
        );
        let mut candidates: Vec<&ItemRef> = all
            .iter()
            .filter(|item| item.kind != Kind::Type || item.top)
            .collect();
        if let Some(within) = within {
            let under: Vec<&ItemRef> = candidates
                .iter()
                .copied()
                .filter(|item| {
                    lib_family(&item.crate_name) == family && item.module.starts_with(within)
                })
                .collect();
            if !under.is_empty() {
                candidates = under;
            }
        }
        let first = candidates.first()?;
        let several_files = candidates
            .iter()
            .any(|item| item.crate_name != first.crate_name || item.file != first.file);
        let rank = |item: &&ItemRef| {
            let common = item
                .module
                .iter()
                .zip(module)
                .take_while(|(a, b)| a == b)
                .count();
            (
                lib_family(&item.crate_name) != family,
                !item.top,
                std::cmp::Reverse(common),
                item.module.len(),
                item.file.clone(),
            )
        };
        let best = Rc::clone(candidates.iter().min_by_key(|item| rank(item))?);
        if several_files {
            self.guesses.insert(name.to_owned());
        }
        Some(best)
    }
}

/// A `use` tree as (alias, path) pairs; `*` for a glob.
/// `depth` counts the braces open around `tree`: Python recurses once per brace, so a tree nested as deep as its
/// recursion limit is Python's `RecursionError`, not an exhausted native stack.
fn expand_use(
    prefix: &[String],
    tree: &str,
    depth: usize,
) -> Result<Vec<(String, Vec<String>)>, GenerateError> {
    if depth >= RECURSION_LIMIT {
        return Err(recursion_error());
    }
    let tree = strip(tree).trim_start_matches(':');
    let pieces = |text: &str| -> Vec<String> {
        text.split("::")
            .filter(|piece| !strip(piece).is_empty())
            .map(|piece| strip(piece).to_owned())
            .collect()
    };
    if tree.ends_with('}') {
        let brace = tree.find('{').ok_or_else(substring_not_found)?;
        let head = [prefix, &pieces(&tree[..brace])].concat();
        let mut out = Vec::new();
        for part in split_top(slice(tree, brace + 1, tree.len() - 1), b',') {
            out.extend(expand_use(&head, part, depth + 1)?);
        }
        return Ok(out);
    }
    if let Some(glob) = tree.strip_suffix('*') {
        return Ok(vec![("*".to_owned(), [prefix, &pieces(glob)].concat())]);
    }
    let (tree, alias) = match tree.split_once(" as ") {
        Some((tree, alias)) => (strip(tree), Some(strip(alias))),
        None => (tree, None),
    };
    let mut segments = [prefix, &pieces(tree)].concat();
    if segments.last().is_some_and(|last| last == "self") {
        segments.pop();
    }
    if segments.is_empty() || alias == Some("_") {
        return Ok(Vec::new());
    }
    let alias = match alias {
        Some(alias) if !alias.is_empty() => alias.to_owned(),
        _ => segments[segments.len() - 1].clone(),
    };
    Ok(vec![(alias, segments)])
}

/// `Path.rglob('*.rs')` as Python 3.14 walks it: every entry whose name ends in `.rs` (a file, a directory, a
/// symlink, a broken one), dot names included, descending into directories but not through directory symlinks;
/// unreadable directories are passed over.
fn rglob_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if entry.file_name().as_encoded_bytes().ends_with(b".rs") {
            out.push(path.clone());
        }
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            rglob_rs(&path, out);
        }
    }
}

/// `path.relative_to(base).as_posix()`.
fn relative_posix(path: &Path, base: &Path) -> String {
    let relative = path.strip_prefix(base).unwrap_or(path);
    relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// `re.match(r'\w+', param).group(0)`; no word character is Python's `AttributeError`.
fn leading_word(param: &str) -> Result<String, GenerateError> {
    let end = param
        .find(|c: char| !crate::py::text::is_word(c))
        .unwrap_or(param.len());
    if end == 0 {
        return Err(GenerateError::attribute("NoneType", "group"));
    }
    Ok(param[..end].to_owned())
}

/// An item from its header match, with the attribute lines above it, its generics (looked for only within four
/// characters of the name) and its body (from the first `{`, `(` or `;` past any where clause); `None` when no body
/// opens.
fn read_item(
    crate_name: &str,
    file: &str,
    module: &[String],
    text: &str,
    header: &Captures<'_>,
) -> Result<Option<Item>, GenerateError> {
    let indent = header.get(1).map_or("", |m| m.as_str());
    let public = header.get(2).map(|m| m.as_str());
    let kind = match &header[3] {
        "struct" => Kind::Struct,
        "enum" => Kind::Enum,
        _ => Kind::Type,
    };
    let name = header[4].to_owned();
    let (start, end) = header.get(0).map_or((0, 0), |m| (m.start(), m.end()));
    // The attributes: the lines above the header back to the previous item.
    let mut lines = Vec::new();
    let mut start = start;
    while start > 0 {
        let line_start = text[..start - 1].rfind('\n').map_or(0, |at| at + 1);
        let line = strip(&text[line_start..start]);
        let ends_item =
            line.ends_with(['}', ';', '{']) && !(line.starts_with('#') || line.starts_with("//"));
        if line.is_empty() || ends_item {
            break;
        }
        if !line.starts_with("//") {
            lines.push(line);
        }
        start = line_start;
    }
    lines.reverse();
    let attrs = lines.join(" ");
    let mut position = end;
    let mut generics = Vec::new();
    let rest = slice(text, position, reader::advance_chars(text, position, 4));
    if lstrip(rest).starts_with('<') {
        position = find_from(text, "<", position).ok_or_else(substring_not_found)?;
        let bytes = text.as_bytes();
        let (mut depth, mut close) = (0_i64, position);
        while close < bytes.len() {
            if bytes[close..].starts_with(b"->") {
                close += 2;
                continue;
            }
            depth += i64::from(bytes[close] == b'<');
            depth -= i64::from(bytes[close] == b'>');
            close = next_char(text, close);
            if depth == 0 {
                break;
            }
        }
        for param in split_top(slice(text, position + 1, prev_char(text, close)), b',') {
            let param = strip(param);
            if param.starts_with('\'') || param.starts_with("const ") {
                continue;
            }
            generics.push(leading_word(param)?);
        }
        position = close;
    }
    let key = Rc::new(ItemKey {
        crate_name: crate_name.to_owned(),
        file: file.to_owned(),
        name: name.clone(),
        module: module.to_vec(),
    });
    let item = |body: String, shape: Shape| Item {
        crate_name: crate_name.to_owned(),
        file: file.to_owned(),
        module: module.to_vec(),
        name: name.clone(),
        kind,
        top: indent.is_empty(),
        public: public.is_some_and(|public| strip(public) == "pub"),
        attrs: attrs.clone(),
        generics: generics.clone(),
        body,
        shape,
        key: Rc::clone(&key),
    };
    if kind == Kind::Type {
        return Ok(Some(item(alias_body(text, position), Shape::Alias)));
    }
    // The body opens at the first `{`, `(` or `;` past any where clause.
    let Some(open) = text[position..]
        .find(['{', '(', ';'])
        .map(|at| at + position)
    else {
        return Ok(None);
    };
    Ok(Some(if text.as_bytes()[open] == b';' {
        item(String::new(), Shape::Unit)
    } else {
        let close = close_of(text, open);
        let shape = if text.as_bytes()[open] == b'{' {
            Shape::Named
        } else {
            Shape::Tuple
        };
        item(
            strip_comments(slice(text, open + 1, prev_char(text, close))),
            shape,
        )
    }))
}

/// `re.findall(r'\b(?:struct|enum)\s+([A-Za-z_]\w*)', text)`.
pub(crate) fn declared_names(text: &str) -> Vec<String> {
    static DECLARED: LazyLock<Regex> =
        LazyLock::new(|| compile(r"(?:struct|enum)\s+([A-Za-z_]\w*)"));
    reader::finditer_bounded(&DECLARED, text, true, false)
        .iter()
        .map(|found| found[1].to_owned())
        .collect()
}

/// `re.search(...)` with the fn-local pattern `\bfn\s+deserialize\b`; the offset past `deserialize`.
pub(crate) fn deserialize_fn_end(text: &str) -> Option<usize> {
    static FN: LazyLock<Regex> = LazyLock::new(|| compile(r"fn\s+deserialize"));
    search_bounded(&FN, text, 0, true, true)
        .and_then(|found| found.get(0))
        .map(|m| m.end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_use_reads_trees_and_refuses_nesting_past_the_recursion_limit() {
        // Python 3.14.7, Index.expand_use(index, [], t):
        // 'a::{b, c::{self, d as e}, f::*, _g as _}' -> [('b', ['a', 'b']), ('c', ['a', 'c']),
        //   ('e', ['a', 'c', 'd']), ('*', ['a', 'f'])]
        let pairs = |items: &[(&str, &[&str])]| -> Vec<(String, Vec<String>)> {
            items
                .iter()
                .map(|(alias, path)| {
                    (
                        (*alias).to_owned(),
                        path.iter().map(|s| (*s).to_owned()).collect(),
                    )
                })
                .collect()
        };
        assert_eq!(
            expand_use(&[], "a::{b, c::{self, d as e}, f::*, _g as _}", 0).ok(),
            Some(pairs(&[
                ("b", &["a", "b"]),
                ("c", &["a", "c"]),
                ("e", &["a", "c", "d"]),
                ("*", &["a", "f"]),
            ]))
        );
        // '{' * n + 'A' + '}' * n: n = 3000 gives [('A', ['A'])]; n = 20001 raises RecursionError. The port counts
        // the braces open (its recursion), so at the limit the next brace is refused.
        assert_eq!(
            expand_use(&[], "{A}", RECURSION_LIMIT - 2).ok(),
            Some(pairs(&[("A", &["A"])]))
        );
        assert_eq!(
            expand_use(&[], "{A}", RECURSION_LIMIT - 1)
                .err()
                .map(|e| e.to_string())
                .as_deref(),
            Some("RecursionError: maximum recursion depth exceeded")
        );
    }
}
