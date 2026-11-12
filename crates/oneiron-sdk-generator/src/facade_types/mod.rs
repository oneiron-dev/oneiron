//! The facade's wire types, read from the Rust serde types every facade row names.
//!
//! Each callable facade row in the verb table names an input and an output type. Those are the roots: the
//! [`inventory::Inventory`] walks each root's Rust definition across the engine crates' sources (indexed by
//! [`index::Index`], read by the heuristic scanner in [`reader`]), follows every type it reaches and emits one
//! declaration per Rust type, for TypeScript and for the Python stubs alike. A shape it cannot read becomes
//! `unknown` (`Any` in Python) and is listed in the census with its reason; `serde_json::Value` is opaque by
//! design and counted apart.
//!
//! The reader is a port of the Python heuristics as they are written, not a Rust parser. Text
//! offsets are byte offsets on char boundaries; every Python `i + 1` or `x - 1` steps one code point.

pub(crate) mod index;
pub(crate) mod inventory;
pub(crate) mod reader;

use std::fmt::Write as _;
use std::path::Path;
use std::rc::Rc;

use crate::error::GenerateError;
use crate::py::text::repr_str;
use crate::py::value::Value;

pub(crate) use inventory::Inventory;

/// The crates a facade type can live in, by the name a Rust path gives them, in the Python dict's order, then each
/// crate added since. A crate missing here reads as `unknown` wherever a facade type names one of its types, even
/// through a re-export in a listed crate.
pub const CRATES: &[(&str, &str)] = &[
    ("oneiron", "crates/oneiron/src"),
    ("oneiron_base", "crates/oneiron-base/src"),
    ("oneiron_store", "crates/oneiron-store/src"),
    ("oneiron_web_fetch", "crates/oneiron-web-fetch/src"),
    ("oneiron_lens_wire", "crates/oneiron-lens-wire/src"),
    (
        "oneiron_policy_vocabulary",
        "crates/oneiron-policy-vocabulary/src",
    ),
    ("oneiron_run_budget", "crates/oneiron-run-budget/src"),
    ("oneiron_code_source", "crates/oneiron-code-source/src"),
    (
        "oneiron_delivery_vocabulary",
        "crates/oneiron-delivery-vocabulary/src",
    ),
    ("oneiron_contracts", "crates/oneiron-contracts/src"),
    ("oneiron_authority", "crates/oneiron-authority/src"),
    ("oneiron_crypto", "crates/oneiron-crypto/src"),
    ("oneiron_model", "crates/oneiron-model/src"),
    ("oneiron_retrieval", "crates/oneiron-retrieval/src"),
    (
        "oneiron_vault_contract",
        "crates/oneiron-vault-contract/src",
    ),
    (
        "oneiron_sandbox_contract",
        "crates/oneiron-sandbox-contract/src",
    ),
    ("oneiron_browser", "crates/oneiron-browser/src"),
    ("oneiron_docedit", "crates/oneiron-docedit/src"),
    ("oneiron_xlsx_formula", "crates/oneiron-xlsx-formula/src"),
    ("oneiron_keystore", "crates/oneiron-keystore/src"),
    ("oneiron_code_check", "crates/oneiron-code-check/src"),
    ("oneiron_container", "crates/oneiron-container/src"),
    ("oneiron_spawn", "crates/oneiron-spawn/src"),
    ("oneiron_guest", "crates/oneiron-guest/src"),
    ("oneiron_wake_contract", "crates/oneiron-wake-contract/src"),
    ("oneiron_remote", "crates/oneiron-remote/src"),
    // Core split slice 2: core re-exports the consent state at its old paths (SDK-GEN-CRATES-MISSES-CONSENT-STATE).
    ("oneiron_consent_state", "crates/oneiron-consent-state/src"),
    // Lib split, stage A: the crates below the lib that mirror its module tree.
    ("oneiron_verb_wire", "crates/oneiron-verb-wire/src"),
    ("oneiron_records", "crates/oneiron-records/src"),
];

/// The source directory `CRATES` gives a crate name (`CRATES[crate]`), or `None` for a name it does not hold.
pub(crate) fn crate_dir(name: &str) -> Option<&'static str> {
    CRATES
        .iter()
        .find(|(crate_name, _)| *crate_name == name)
        .map(|(_, dir)| *dir)
}

/// The crates read up front; any other is read the first time a path names it.
pub(crate) const EAGER: &[&str] = &[
    "oneiron",
    "oneiron_contracts",
    "oneiron_authority",
    "oneiron_model",
    "oneiron_retrieval",
    "oneiron_verb_wire",
];

/// A bare row type is named from the SDK module, as its generated fn names it.
pub(crate) const ROOT_CONTEXT: (&str, &str) = ("oneiron", "crates/oneiron/src/verbs/mod.rs");

/// Names a Rust file uses without importing them.
pub(crate) const PRELUDE: &[&str] = &[
    "String", "Vec", "Option", "Box", "Result", "bool", "str", "char", "u8", "u16", "u32", "u64",
    "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
];
/// Wrapper types, read as their first type argument.
pub(crate) const WRAPPERS: &[&str] = &[
    "Box",
    "Arc",
    "Rc",
    "Cow",
    "Zeroizing",
    "Reverse",
    "Wrapping",
    "Cell",
    "RefCell",
];
/// Sequence types, read as an array of their first type argument.
pub(crate) const SEQUENCES: &[&str] = &[
    "Vec",
    "VecDeque",
    "HashSet",
    "BTreeSet",
    "IndexSet",
    "SmallVec",
    "ArrayVec",
    "ThinVec",
    "LinkedList",
    "BinaryHeap",
    "NonEmpty",
    "Bytes",
    "ByteBuf",
];
/// Map types, read as a map of their second type argument.
pub(crate) const MAPS: &[&str] = &[
    "HashMap",
    "BTreeMap",
    "IndexMap",
    "FxHashMap",
    "AHashMap",
    "Map",
];
/// Crates outside the engine: a path that starts with one is not resolved in the index.
pub(crate) const EXTERNAL: &[&str] = &[
    "std",
    "core",
    "alloc",
    "serde_json",
    "serde",
    "chrono",
    "uuid",
    "url",
    "bytes",
    "serde_bytes",
    "smallvec",
    "indexmap",
    "ordered_float",
    "zeroize",
    "time",
    "semver",
    "arrayvec",
    "thin_vec",
    "smol_str",
    "compact_str",
    "mime",
    "http",
    "nonempty",
];
/// Names a declaration may not take, TypeScript globals and the stub's own imports.
pub(crate) const RESERVED: &[&str] = &[
    "Record",
    "Partial",
    "Required",
    "Readonly",
    "Pick",
    "Omit",
    "Array",
    "Map",
    "Set",
    "Promise",
    "Response",
    "Request",
    "Date",
    "Error",
    "Object",
    "String",
    "Number",
    "Boolean",
    "Symbol",
    "Function",
    "RegExp",
    "JSON",
    "Math",
    "Uint8Array",
    "Headers",
    "URL",
    "Blob",
    "File",
    "Event",
    "Node",
    "Element",
    "Text",
    "Document",
    "Window",
    "Location",
    "Storage",
    "Any",
    "Literal",
    "TypedDict",
    "NotRequired",
    "Generic",
    "TypeVar",
    "Facade",
    "None",
    "Self",
];
/// The prefix `py_name` gives a declaration named as a Python builtin.
pub(crate) const PY_BUILTIN_PREFIX: &str = "Facade";

/// Membership in one of the module's name sets (a Python `frozenset`/`set` literal; only membership is read).
pub(crate) fn holds(set: &[&str], name: &str) -> bool {
    set.contains(&name)
}

/// The name Python spells a declaration with; a builtin's name takes `PY_BUILTIN_PREFIX` (FIX 6555).
pub(crate) fn py_name(name: &str) -> String {
    if crate::py::builtins::is_builtin(name) {
        format!("{PY_BUILTIN_PREFIX}{name}")
    } else {
        name.to_owned()
    }
}

// ---------------------------------------------------------------- the IR

/// The kind of a `('prim', kind)` leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Prim {
    Int,
    Float,
    String,
    Bool,
    Null,
}

impl Prim {
    /// The Python spelling (`node[1]`).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Int => "int",
            Self::Float => "float",
            Self::String => "string",
            Self::Bool => "bool",
            Self::Null => "null",
        }
    }
}

/// One `(key, IR, optional)` member of an `('object', fields, hint)` value. The key is a `Value` because
/// `serialize_case` can hand back a non-string `rename(serialize ...)` half, which Python carries until a string
/// operation refuses it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Field {
    pub(crate) key: Value,
    pub(crate) value: Ir,
    pub(crate) optional: bool,
}

impl Field {
    pub(crate) fn new(key: &str, value: Ir, optional: bool) -> Self {
        Self {
            key: Value::Str(key.to_owned()),
            value,
            optional,
        }
    }
}

/// A declaration key: Python's `Item.key()`, `(crate, file, name, module)`. Two items of one file and module with
/// one name share a key, as in Python (the first one declared wins).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ItemKey {
    pub(crate) crate_name: String,
    pub(crate) file: String,
    pub(crate) name: String,
    pub(crate) module: Vec<String>,
}

/// A shared [`ItemKey`]; equality and hashing are by value.
pub(crate) type Key = Rc<ItemKey>;

impl ItemKey {
    /// Python's `repr` of the key tuple, `('oneiron', 'verbs/mod.rs', 'Name', ('verbs',))` (the UniFFI types sort
    /// declarations by it).
    pub(crate) fn repr(&self) -> String {
        format!(
            "({}, {}, {}, {})",
            repr_str(&self.crate_name),
            repr_str(&self.file),
            repr_str(&self.name),
            tuple_repr(&self.module)
        )
    }

    /// `'::'.join((crate,) + module + (name,))`: the Rust path of the declaration.
    pub(crate) fn path(&self) -> String {
        let mut out = self.crate_name.clone();
        for part in &self.module {
            out.push_str("::");
            out.push_str(part);
        }
        out.push_str("::");
        out.push_str(&self.name);
        out
    }
}

/// A wire-shape value (Python's IR tuples).
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Ir {
    /// `('prim', kind)`, or `('prim', 'int', width)` for an integer that names its Rust width.
    Prim(Prim, Option<String>),
    /// `('opaque',)`: a `serde_json::Value`, opaque by design.
    Opaque,
    /// `('unknown', reason)`.
    Unknown(String),
    /// `('never',)`: an enum with no variants.
    Never,
    /// `('lit', label)`.
    Lit(Value),
    /// `('param', name)`: a generic parameter in scope.
    Param(String),
    /// `('array', item)`.
    Array(Box<Ir>),
    /// `('option', item)`.
    Option(Box<Ir>),
    /// `('map', value)`.
    Map(Box<Ir>),
    /// `('partial', item)`: a flattened `Option` of a record.
    Partial(Box<Ir>),
    /// `('tuple', items)`.
    Tuple(Vec<Ir>),
    /// `('union', members)`.
    Union(Vec<Ir>),
    /// `('and', members)`: flattened members, then the record itself.
    And(Vec<Ir>),
    /// `('object', fields, hint)`.
    Object(Vec<Field>, Option<String>),
    /// `('ref', key, arguments)`.
    Ref(Key, Vec<Ir>),
}

pub(crate) const INT: Ir = Ir::Prim(Prim::Int, None);
pub(crate) const FLOAT: Ir = Ir::Prim(Prim::Float, None);
pub(crate) const STRING: Ir = Ir::Prim(Prim::String, None);
pub(crate) const BOOL: Ir = Ir::Prim(Prim::Bool, None);
pub(crate) const NULL: Ir = Ir::Prim(Prim::Null, None);
pub(crate) const OPAQUE: Ir = Ir::Opaque;

/// An integer leaf that names its Rust width.
pub(crate) fn width(name: &str) -> Ir {
    Ir::Prim(Prim::Int, Some(name.to_owned()))
}

impl Ir {
    /// The Python tag, `node[0]`.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Prim(..) => "prim",
            Self::Opaque => "opaque",
            Self::Unknown(_) => "unknown",
            Self::Never => "never",
            Self::Lit(_) => "lit",
            Self::Param(_) => "param",
            Self::Array(_) => "array",
            Self::Option(_) => "option",
            Self::Map(_) => "map",
            Self::Partial(_) => "partial",
            Self::Tuple(_) => "tuple",
            Self::Union(_) => "union",
            Self::And(_) => "and",
            Self::Object(..) => "object",
            Self::Ref(..) => "ref",
        }
    }

    /// Python's `repr` of the IR tuple (`raise ValueError(node)` prints it; the UniFFI types key caches by it).
    pub(crate) fn repr(&self) -> String {
        let tag = repr_str(self.kind());
        let list = |items: &[Ir]| {
            format!(
                "[{}]",
                items.iter().map(Ir::repr).collect::<Vec<_>>().join(", ")
            )
        };
        match self {
            Self::Prim(prim, None) => format!("({tag}, {})", repr_str(prim.name())),
            Self::Prim(prim, Some(width)) => {
                format!("({tag}, {}, {})", repr_str(prim.name()), repr_str(width))
            }
            Self::Opaque | Self::Never => format!("({tag},)"),
            Self::Unknown(text) | Self::Param(text) => format!("({tag}, {})", repr_str(text)),
            Self::Lit(value) => format!("({tag}, {})", value.repr()),
            Self::Array(item) | Self::Option(item) | Self::Map(item) | Self::Partial(item) => {
                format!("({tag}, {})", item.repr())
            }
            Self::Tuple(items) | Self::Union(items) | Self::And(items) => {
                format!("({tag}, {})", list(items))
            }
            Self::Object(fields, hint) => {
                let mut out = format!("({tag}, [");
                for (n, field) in fields.iter().enumerate() {
                    if n > 0 {
                        out.push_str(", ");
                    }
                    let flag = if field.optional { "True" } else { "False" };
                    let _ = write!(
                        out,
                        "({}, {}, {flag})",
                        field.key.repr(),
                        field.value.repr()
                    );
                }
                let hint = hint.as_deref().map_or_else(|| "None".to_owned(), repr_str);
                let _ = write!(out, "], {hint})");
                out
            }
            Self::Ref(key, arguments) => format!("({tag}, {}, {})", key.repr(), list(arguments)),
        }
    }
}

/// Types of std and of external crates, by the last segment of their path.
pub(crate) fn leaf(name: &str) -> Option<Ir> {
    Some(match name {
        "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64" | "i128"
        | "isize" | "NonZeroU8" | "NonZeroU16" | "NonZeroU32" | "NonZeroU64" | "NonZeroUsize"
        | "NonZeroI64" | "NonZeroI32" => width(name),
        "f32" | "f64" | "OrderedFloat" | "NotNan" | "Number" => FLOAT,
        "String" | "str" | "char" | "PathBuf" | "Path" | "OsString" | "Uuid" | "Url"
        | "Version" | "IpAddr" | "Ipv4Addr" | "Ipv6Addr" | "SocketAddr" | "SmolStr"
        | "CompactString" | "ArcStr" | "DateTime" | "Mime" | "HeaderValue" => STRING,
        "bool" => BOOL,
        "PhantomData" => NULL,
        "Value" | "RawValue" => OPAQUE,
        "Duration" => Ir::Object(
            vec![
                Field::new("secs", width("u64"), false),
                Field::new("nanos", width("u32"), false),
            ],
            None,
        ),
        "SystemTime" => Ir::Object(
            vec![
                Field::new("secs_since_epoch", width("u64"), false),
                Field::new("nanos_since_epoch", width("u32"), false),
            ],
            None,
        ),
        _ => return None,
    })
}

/// Field codecs that write an id's 16 bytes, by the (crate, module path) a codec path resolves to; serde_json writes
/// `[u8; 16]` as an array of numbers.
pub(crate) fn byte_id_codec(crate_name: &str, module: &[String]) -> Option<Ir> {
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    let known = crate_name == "oneiron"
        && matches!(
            module.as_slice(),
            ["llm", "entity_refs"] | ["llm", "entity_refs", "list"]
        );
    known.then(|| Ir::Array(Box::new(width("u8"))))
}

// ---------------------------------------------------------------- module-level helpers

/// A wire key as a TypeScript property name.
pub(crate) fn ts_key(key: &Value) -> Result<String, GenerateError> {
    let Value::Str(text) = key else {
        // `re.fullmatch` on a non-string.
        return Err(GenerateError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            key.type_name()
        )));
    };
    // re.fullmatch(r'[A-Za-z_$][\w$]*', key)
    let mut chars = text.chars();
    let bare = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| crate::py::text::is_word(c) || c == '$');
    Ok(if bare { text.clone() } else { dumps(key) })
}

/// Whether a TypeScript type has a top-level union or intersection. Every character it tests is ASCII, so it walks
/// bytes; `text[n - 1:n + 2]` never equals `' | '` at `n == 0` in Python either.
pub(crate) fn compound(text: &str, operators: &str) -> bool {
    let bytes = text.as_bytes();
    let mut depth: i64 = 0;
    for (n, &c) in bytes.iter().enumerate() {
        if b"{[(<".contains(&c) {
            depth += 1;
        } else if b"}])>".contains(&c) {
            depth -= 1;
        } else if depth == 0
            && operators.as_bytes().contains(&c)
            && n >= 1
            && bytes.get(n - 1..n + 2) == Some(&[b' ', c, b' '][..])
        {
            return true;
        }
    }
    false
}

/// The generic parameters an IR value names (a set; callers sort it).
pub(crate) fn type_params(node: &Ir) -> indexmap::IndexSet<String> {
    let mut found = indexmap::IndexSet::new();
    let mut stack = vec![node];
    while let Some(item) = stack.pop() {
        match item {
            Ir::Param(name) => {
                found.insert(name.clone());
            }
            Ir::Array(inner) | Ir::Option(inner) | Ir::Map(inner) | Ir::Partial(inner) => {
                stack.push(inner);
            }
            Ir::Tuple(items) | Ir::Union(items) | Ir::And(items) => stack.extend(items.iter()),
            Ir::Object(fields, _) => stack.extend(fields.iter().map(|field| &field.value)),
            Ir::Ref(_, arguments) => stack.extend(arguments.iter()),
            _ => {}
        }
    }
    found
}

/// `TYPE_NAMES`: `scripts/sdk/type_names.json`, read (strict UTF-8, universal newlines) and decoded as the Python
/// import does. The Python generator imported `facade_types` before it read any verb file, so `Generator::new` calls
/// this first.
pub(crate) fn type_names(root: &Path) -> Result<Value, GenerateError> {
    let path = root.join("scripts/sdk/type_names.json");
    let text = crate::py::read_text(&path)?;
    crate::py::json::loads(&text).map_err(|error| error.into_error("scripts/sdk/type_names.json"))
}

// ---------------------------------------------------------------- shared text

/// Python's `repr` of a tuple of strs: `()`, `('a',)`, `('a', 'b')`.
pub(crate) fn tuple_repr(parts: &[String]) -> String {
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    crate::py::text::repr_str_tuple(&parts)
}

/// `json.dumps(value)` with the defaults.
pub(crate) fn dumps(value: &Value) -> String {
    crate::py::json::dumps(value, crate::py::json::DumpOptions::default())
}

/// Python's `IndexError: list index out of range`.
pub(crate) fn index_error() -> GenerateError {
    GenerateError::index("list index out of range")
}

/// Python's `ValueError: substring not found` (`str.index`).
pub(crate) fn substring_not_found() -> GenerateError {
    GenerateError::value("substring not found")
}

/// Python's `RecursionError: maximum recursion depth exceeded`, for the walks that recurse without end in Python
/// (a record that flattens itself, two conversions that name each other).
pub(crate) fn recursion_error() -> GenerateError {
    GenerateError::exception("RecursionError", "maximum recursion depth exceeded")
}

/// The depth past which a walk Python would recurse through without end stops with Python's `RecursionError`.
/// The Python generator set its limit to 20000 frames (`sys.setrecursionlimit(20000)`); the recursion limit is not
/// part of the contract, only the outcome of an endless walk is.
pub(crate) const RECURSION_LIMIT: usize = 20000;

#[cfg(test)]
mod tests {
    use super::*;

    // Expected: what the Python generator printed (Python 3.14.7 on nelly) for each call below, `f` being its
    // `facade_types` module.

    #[test]
    fn ts_key_quotes_what_is_no_identifier() {
        // f.ts_key('a$b'), f.ts_key('1x'), f.ts_key('é'), f.ts_key('') == a$b "1x" "\u00e9" ""
        let key = |text: &str| ts_key(&Value::Str(text.to_owned())).expect("a string key");
        assert_eq!(key("a$b"), "a$b");
        assert_eq!(key("1x"), "\"1x\"");
        assert_eq!(key("é"), "\"\\u00e9\"");
        assert_eq!(key(""), "\"\"");
        // f.ts_key(True) raises TypeError: expected string or bytes-like object, got 'bool'
        assert_eq!(
            ts_key(&Value::Bool(true))
                .err()
                .map(|error| error.to_string())
                .as_deref(),
            Some("TypeError: expected string or bytes-like object, got 'bool'")
        );
    }

    #[test]
    fn compound_finds_top_level_operators() {
        // f.compound('a | b'), f.compound('(a | b)'), f.compound('a|b'), f.compound('{ a: b | c }'),
        // f.compound('a & b', '&'), f.compound('a & b', '|') == True False False False True False
        assert!(compound("a | b", "|&"));
        assert!(!compound("(a | b)", "|&"));
        assert!(!compound("a|b", "|&"));
        assert!(!compound("{ a: b | c }", "|&"));
        assert!(compound("a & b", "&"));
        assert!(!compound("a & b", "|"));
    }
}
