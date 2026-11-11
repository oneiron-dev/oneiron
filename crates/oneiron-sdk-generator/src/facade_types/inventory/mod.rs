//! The declarations every facade root reaches, and the census of what they read as. The walk (Rust type to IR), the
//! census, and the TypeScript and Python renderers are this module's children, split by the Python class's section
//! comments.

mod census;
mod python;
mod rust_ir;
mod typescript;

use std::path::Path;
use std::rc::Rc;

use indexmap::{IndexMap, IndexSet};

use super::index::{Index, ItemRef};
use super::reader::parse_type;
use super::{CRATES, Ir, Key, RECURSION_LIMIT, RESERVED, ROOT_CONTEXT, holds, recursion_error};
use crate::error::GenerateError;
use crate::py::value::{Dict, Value};

/// The place a type text is read from, Python's `(crate, file, module)` context tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Context {
    pub(crate) crate_name: String,
    pub(crate) file: String,
    pub(crate) module: Vec<String>,
}

impl Context {
    /// `(item.crate, item.file, item.module)`.
    pub(crate) fn of(item: &ItemRef) -> Self {
        Self {
            crate_name: item.crate_name.clone(),
            file: item.file.clone(),
            module: item.module.clone(),
        }
    }
}

/// One declaration (Python's `{'name', 'params', 'item', 'ir'}` dict). `ir` is `None` while its own body is walked.
#[derive(Clone, Debug)]
pub(crate) struct Decl {
    pub(crate) name: String,
    pub(crate) params: Vec<String>,
    pub(crate) item: ItemRef,
    pub(crate) ir: Option<Ir>,
}

impl Decl {
    /// `decl['ir']` where Python reads it as a tuple: `None` there is its `TypeError`.
    pub(crate) fn ir(&self) -> Result<&Ir, GenerateError> {
        self.ir
            .as_ref()
            .ok_or_else(|| GenerateError::type_error("'NoneType' object is not subscriptable"))
    }
}

/// A variant's payload shape: Python's `'unit'`, `'newtype'`, `'tuple'` or `'struct'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VariantShape {
    Unit,
    Newtype,
    Tuple,
    Struct,
}

/// One variant of a derived enum.
#[derive(Clone, Debug)]
pub(crate) struct VariantMeta {
    pub(crate) name: String,
    pub(crate) label: Value,
    pub(crate) untagged: bool,
    pub(crate) other: bool,
    pub(crate) shape: VariantShape,
    pub(crate) member: Ir,
}

/// A derived enum's serde tagging and variants, by declaration name.
#[derive(Clone, Debug)]
pub(crate) struct EnumMeta {
    pub(crate) tag: Option<String>,
    pub(crate) content: Option<String>,
    pub(crate) untagged: bool,
    pub(crate) variants: Vec<VariantMeta>,
}

/// The facade types' inventory. Fields keep the Python names; a Python `set` is an `IndexSet` whose order nothing
/// reads.
#[derive(Debug)]
pub(crate) struct Inventory {
    pub(crate) index: Index,
    /// item key -> declaration, in the order names were taken (a type is named when first reached).
    pub(crate) decls: IndexMap<Key, Decl>,
    /// The declarations in the order their bodies were finished (postorder).
    pub(crate) order: Vec<Key>,
    /// Every name taken: the type_names.json pins, then each allocation (a set).
    pub(crate) names: IndexSet<String>,
    /// (declaration, rust text, reason)
    pub(crate) fallbacks: Vec<(String, String, String)>,
    /// (declaration, rust text): serde_json values, opaque by design.
    pub(crate) opaques: Vec<(String, String)>,
    /// Each derived enum's serde tagging and variants, by declaration name.
    pub(crate) variants: IndexMap<String, EnumMeta>,
    /// Each named field a writer must send as `null` rather than omit, by (owner, key) (a set).
    pub(crate) null_fields: Vec<(String, Value)>,
    /// Each declaration that refuses unknown fields (a set).
    pub(crate) closed: IndexSet<String>,
    /// Each struct that derives no `Debug` (FIX 4993) (a set).
    pub(crate) redacted: IndexSet<String>,
    /// rust text -> IR, in rooting order.
    pub(crate) roots: IndexMap<String, Ir>,
    /// item key -> the name a codec module gives its mirror.
    pub(crate) preferred: IndexMap<Key, String>,
    /// `_py_erased`, `_py_erased_at`: the erased names and the `len(order)` they were found at.
    py_erased_cache: (IndexSet<String>, Option<usize>),
    pub(crate) root_context: Context,
    /// `TYPE_NAMES`: Rust path -> pinned name.
    type_names: Dict,
    /// How many `walk` and `item_ir` calls are open (Python's `ir` and `item_ir` frames): a walk as deep as
    /// Python's recursion limit (a type nested that deep, a chain of that many types, two conversions that name each
    /// other) is its `RecursionError`, not an exhausted native stack.
    depth: usize,
}

impl Inventory {
    /// `Inventory.__init__`, with `TYPE_NAMES` already read (`Generator::new` reads type_names.json first, before
    /// any verb file): the index first, then the pinned names, then each row's input and output, rooted in row
    /// order.
    pub(crate) fn with_type_names(
        root: &Path,
        rows: &[&Dict],
        pins: &Value,
    ) -> Result<Self, GenerateError> {
        let index = Index::new(root)?;
        // set(TYPE_NAMES.values())
        let Value::Dict(pins) = pins else {
            return Err(GenerateError::attribute(pins.type_name(), "values"));
        };
        // `set(TYPE_NAMES.values())`: a pin that is not hashable is Python's `TypeError`. A hashable pin that is no
        // `str` (`7`, `True`, `None`) can equal no name the inventory allocates or looks up, so only the strings are
        // kept (a pin `allocate` returns is refused there, a documented divergence).
        let mut names = IndexSet::new();
        for value in pins.values() {
            value.check_hashable("a set element")?;
            if let Value::Str(name) = value {
                names.insert(name.clone());
            }
        }
        let (crate_name, file) = ROOT_CONTEXT;
        let base = CRATES
            .iter()
            .find(|(name, _)| *name == crate_name)
            .map_or("", |(_, dir)| *dir);
        let file = &file[base.len() + 1..];
        let module = Path::new(file)
            .parent()
            .map(|parent| {
                parent
                    .iter()
                    .map(|part| part.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let mut inventory = Self {
            index,
            decls: IndexMap::new(),
            order: Vec::new(),
            names,
            fallbacks: Vec::new(),
            opaques: Vec::new(),
            variants: IndexMap::new(),
            null_fields: Vec::new(),
            closed: IndexSet::new(),
            redacted: IndexSet::new(),
            roots: IndexMap::new(),
            preferred: IndexMap::new(),
            py_erased_cache: (IndexSet::new(), None),
            root_context: Context {
                crate_name: crate_name.to_owned(),
                file: file.to_owned(),
                module,
            },
            type_names: pins.clone(),
            depth: 0,
        };
        for row in rows {
            // `(row['input'], row['output'])` is built before either is rooted.
            let input = row_field(row, "input")?;
            let output = row_field(row, "output")?;
            inventory.root_ir_value(input)?;
            inventory.root_ir_value(output)?;
        }
        Ok(inventory)
    }

    /// A row type, named as the SDK module names it.
    pub(crate) fn root_ir(&mut self, text: &str) -> Result<Ir, GenerateError> {
        if let Some(found) = self.roots.get(text) {
            return Ok(found.clone());
        }
        let context = self.root_context.clone();
        let value = self.ir(&parse_type(text)?, &context, &[], text)?;
        self.roots.insert(text.to_owned(), value.clone());
        Ok(value)
    }

    /// `root_ir` on a row's JSON value: Python hashes it as a dict key, then hands it to a regex, so a list or a
    /// dict is an unhashable `TypeError`, and any other non-string `expected string or bytes-like object`.
    pub(crate) fn root_ir_value(&mut self, text: &Value) -> Result<Ir, GenerateError> {
        self.root_ir(type_text(text)?)
    }

    /// A row type as TypeScript spells it outside the declarations module (Python's default prefix is `Facade.`).
    pub(crate) fn ts_type(&mut self, text: &str, prefix: &str) -> Result<String, GenerateError> {
        let node = self.root_ir(text)?;
        self.ts(&node, prefix)
    }

    /// A row type as the Python stubs spell it outside the declarations module (Python's default prefix is
    /// `Facade.`).
    pub(crate) fn py_type(&mut self, text: &str, prefix: &str) -> Result<String, GenerateError> {
        let node = self.root_ir(text)?;
        self.py_outer(&node, prefix)
    }

    /// Opens one of Python's `ir` or `item_ir` frames (see `depth`).
    pub(crate) fn enter(&mut self) -> Result<(), GenerateError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        self.depth += 1;
        Ok(())
    }

    /// Closes the frame `enter` opened.
    pub(crate) fn leave(&mut self) {
        self.depth -= 1;
    }

    /// `self.decls[key]`.
    pub(crate) fn decl(&self, key: &Key) -> Result<&Decl, GenerateError> {
        self.decls
            .get(key)
            .ok_or_else(|| GenerateError::exception("KeyError", key.repr()))
    }

    /// Whether `(owner, key)` is in `null_fields`.
    pub(crate) fn is_null_field(&self, owner: &str, key: &Value) -> bool {
        self.null_fields
            .iter()
            .any(|(at, field)| at == owner && field == key)
    }

    // ---- naming

    /// A pinned name, else the item's (or its codec module's) name; a name another type took is a contest the author
    /// settles in type_names.json; a reserved name takes module-suffix prefixes, shortest first, then a number.
    fn allocate(&mut self, item: &ItemRef) -> Result<String, GenerateError> {
        let path = item.key.path();
        if let Some(pin) = self.type_names.get(&path) {
            return match pin {
                Value::Str(name) => Ok(name.clone()),
                // Documented divergence: Python returns the pin as the declaration's name and fails later, with
                // whatever string operation first meets it (the UniFFI types' `name + ...` for a reached pin); the
                // port refuses it here, as a `TypeError` that names the pin.
                other => Err(GenerateError::type_error(format!(
                    "scripts/sdk/type_names.json pins {path} to {}, which is not a str",
                    other.repr()
                ))),
            };
        }
        let mut name = self
            .preferred
            .get(&item.key)
            .cloned()
            .unwrap_or_else(|| item.name.clone());
        if self.names.contains(&name) {
            return Err(GenerateError::exception(
                "ValueError",
                format!(
                    "{path}: the name {name} is contested; pin each contestant in scripts/sdk/type_names.json"
                ),
            ));
        }
        if holds(RESERVED, &name) {
            let mut taken = None;
            for size in 1..=item.module.len() {
                let prefix: String = item.module[item.module.len() - size..]
                    .iter()
                    .map(|part| crate::py::text::title(part).replace('_', ""))
                    .collect();
                let candidate = format!("{prefix}{name}");
                if !self.names.contains(&candidate) && !holds(RESERVED, &candidate) {
                    taken = Some(candidate);
                    break;
                }
            }
            name = match taken {
                Some(candidate) => candidate,
                None => {
                    let (base, mut n) = (name.clone(), 2);
                    while self.names.contains(&name) || holds(RESERVED, &name) {
                        name = format!("{base}{n}");
                        n += 1;
                    }
                    name
                }
            };
        }
        self.names.insert(name.clone());
        Ok(name)
    }

    /// Names the item when first reached, before its body is walked (so a cycle meets the placeholder), and appends
    /// it to `order` after. The item's file is a dependency (the lookup that found it recorded it already).
    pub(crate) fn declare(&mut self, item: &ItemRef) -> Result<Key, GenerateError> {
        let key = Rc::clone(&item.key);
        if !self.decls.contains_key(&key) {
            self.index.record_dependency(&item.crate_name, &item.file);
            let name = self.allocate(item)?;
            let decl = Decl {
                name: name.clone(),
                params: item.generics.clone(),
                item: Rc::clone(item),
                ir: None,
            };
            self.decls.insert(Rc::clone(&key), decl);
            let value = self.item_ir(item, &name)?;
            if let Some(decl) = self.decls.get_mut(&key) {
                decl.ir = Some(value);
            }
            self.order.push(Rc::clone(&key));
        }
        Ok(key)
    }

    /// Lists a shape the walk cannot read in the census, with its reason; it reads as `('unknown', reason)`.
    pub(crate) fn fallback(&mut self, location: &str, text: &str, reason: &str) -> Ir {
        self.fallbacks.push((
            location.to_owned(),
            crate::py::text::strip(text).to_owned(),
            reason.to_owned(),
        ));
        Ir::Unknown(reason.to_owned())
    }

    /// Adds `(owner, key)` to `null_fields`; a dict key cannot be a set element's part.
    pub(crate) fn add_null_field(&mut self, owner: &str, key: &Value) -> Result<(), GenerateError> {
        if matches!(key, Value::List(_) | Value::Dict(_)) {
            return Err(GenerateError::type_error(format!(
                "cannot use 'tuple' as a set element (unhashable type: '{}')",
                key.type_name()
            )));
        }
        if !self.is_null_field(owner, key) {
            self.null_fields.push((owner.to_owned(), key.clone()));
        }
        Ok(())
    }
}

/// `row[name]`: a missing key is Python's `KeyError`.
pub(crate) fn row_field<'r>(row: &'r Dict, name: &str) -> Result<&'r Value, GenerateError> {
    row.get(name).ok_or_else(|| GenerateError::key(name))
}

/// A row's type text as `root_ir` takes it: a list or dict fails as a dict key, any other non-string in the type
/// tokenizer's regex.
pub(crate) fn type_text(text: &Value) -> Result<&str, GenerateError> {
    text.check_hashable("a dict key")?;
    match text {
        Value::Str(text) => Ok(text),
        other => Err(GenerateError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            other.type_name()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::*;
    use crate::py::json::loads;

    /// One row rooting `Thing` (imported by the root context, re-exported by `api`, defined in `api/inner.rs`, with a
    /// field of `model::Part`) and `Loose` (imported by no file, so looked up by name: two files define it). The set
    /// holds the root context, the module chain to `Thing` and its field's file, and both files holding `Loose`;
    /// it omits the crate root (no lookup read it) and a file whose items no lookup asked for.
    #[test]
    fn the_dependency_set_holds_the_resolved_files_and_their_module_chain() {
        let root = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-dependencies-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let src = root.join("crates/oneiron/src");
        let derive = "#[derive(Debug, Serialize, Deserialize)]\n";
        for (file, text) in [
            (
                "lib.rs",
                "pub mod api;\npub mod deep;\npub mod loose_a;\npub mod model;\npub mod unrelated;\npub mod verbs;\n"
                    .to_owned(),
            ),
            ("verbs/mod.rs", "use crate::api::Thing;\n".to_owned()),
            (
                "api/mod.rs",
                "pub mod inner;\npub use self::inner::Thing;\n".to_owned(),
            ),
            (
                "api/inner.rs",
                format!("use crate::model::Part;\n\n{derive}pub struct Thing {{\n    pub part: Part,\n}}\n"),
            ),
            (
                "model.rs",
                format!("{derive}pub struct Part {{\n    pub size: u32,\n}}\n"),
            ),
            (
                "loose_a.rs",
                format!("{derive}pub struct Loose {{\n    pub size: u32,\n}}\n"),
            ),
            (
                "deep/loose_b.rs",
                format!("{derive}pub struct Loose {{\n    pub name: String,\n}}\n"),
            ),
            (
                "unrelated.rs",
                format!("{derive}pub struct Unrelated {{\n    pub size: u32,\n}}\n"),
            ),
        ] {
            let path = src.join(file);
            fs::create_dir_all(path.parent().expect("a parent")).expect("a scratch tree");
            fs::write(&path, text).expect("a source");
        }
        let row = loads(r#"{"input": "Thing", "output": "Loose"}"#).expect("a row");
        let row = row.as_dict().expect("a row object");
        let inventory = Inventory::with_type_names(&root, &[row], &Value::Dict(Dict::new()))
            .expect("an inventory over the scratch tree");
        let found: BTreeSet<String> = inventory.index.dependency_paths().collect();
        let expected: BTreeSet<String> = [
            "api/inner.rs",
            "api/mod.rs",
            "deep/loose_b.rs",
            "loose_a.rs",
            "model.rs",
            "verbs/mod.rs",
        ]
        .iter()
        .map(|file| format!("crates/oneiron/src/{file}"))
        .collect();
        assert_eq!(found, expected);
        // The walk reached all three types, and the by-name lookup chose the nearer `Loose`.
        let declared: Vec<String> = inventory.decls.keys().map(|key| key.path()).collect();
        assert_eq!(
            declared,
            [
                "oneiron::api::inner::Thing",
                "oneiron::model::Part",
                "oneiron::loose_a::Loose"
            ]
        );
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
