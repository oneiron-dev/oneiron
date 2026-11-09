//! Port of uniffi_types.py (main `e79eb76df3e`): the UniFFI records and enums for the facade rows' wire types
//! (OF-237), projected from the one facade type inventory into `facade_types_generated.rs`.
//!
//! Each generated type derives serde with the engine type's wire shape. What UniFFI cannot express stays the
//! crate's `WireJson` leaf inside the record (a `serde_json::Value`, a type on a by-value cycle, a bare unit, an
//! untyped union, a 128-bit integer); a tuple of two or three is a generated record with positional fields (FIX
//! 3298). Two orders live side by side, as in Python (brief H10): a mirror's name is taken when it is first reached
//! (before its fields are rendered), and its item is appended after its body is built, so a child's item comes first.
//!
//! The fixed name lists (`WIDTHS`, `RESERVED`, `RAW_FORBIDDEN`, `KEYWORDS`) are copied from the Python literals as
//! they are (brief H5); they are no Rust keyword list.

use indexmap::{IndexMap, IndexSet};

use crate::error::GenerateError;
use crate::facade_types::inventory::{EnumMeta, VariantMeta, VariantShape};
use crate::facade_types::{Field, Inventory, Ir, Key, Prim};
use crate::generate::common::str_format;
use crate::py::json::{DumpOptions, dumps};
use crate::py::re::sub_underscore_at_case_rise;
use crate::py::text::{lower, title, upper};
use crate::py::value::Value;

/// Port of uniffi_types.py:35 (WIRE).
pub(crate) const WIRE: &str = "crate::WireJson";

/// Port of uniffi_types.py:36-51 (WIRE_LEAVES): the shapes a generated record carries as a `WireJson` field rather
/// than a typed one, each with the reason the census states (`str.format` templates with a `{name}` field).
pub(crate) const WIRE_LEAVES: &[(&str, &str)] = &[
    ("recursive", "the recursive type {name}"),
    ("wide", "a 128-bit integer"),
    ("null", "a unit value"),
    ("tuple", "a tuple"),
    ("union", "an untyped union"),
    ("never", "an enum with no variants"),
    ("large_enum", "an enum with more than 256 variants ({name})"),
    ("unknown", "a shape the inventory could not read"),
    ("inline", "an inline {name}"),
];

/// `WIRE_LEAVES[kind]`.
fn wire_leaf(kind: &str) -> Result<&'static str, GenerateError> {
    WIRE_LEAVES
        .iter()
        .find(|(name, _)| *name == kind)
        .map(|&(_, why)| why)
        .ok_or_else(|| GenerateError::key(kind))
}

/// Port of uniffi_types.py:52-54 (COLLISION_PREFIX): the prefix a generated type takes when its name is a
/// hand-written record's or a reserved name (`WireClaimView`).
pub(crate) const COLLISION_PREFIX: &str = "Wire";

/// Port of uniffi_types.py:55-62 (WIDTHS): Rust spellings of the integer widths the inventory records; UniFFI
/// carries 8 to 64 bits, signed and unsigned, and nothing wider. In the dict literal's order.
pub(crate) const WIDTHS: &[(&str, &str)] = &[
    ("u8", "u8"),
    ("u16", "u16"),
    ("u32", "u32"),
    ("u64", "u64"),
    ("usize", "u64"),
    ("i8", "i8"),
    ("i16", "i16"),
    ("i32", "i32"),
    ("i64", "i64"),
    ("isize", "i64"),
    ("NonZeroU8", "u8"),
    ("NonZeroU16", "u16"),
    ("NonZeroU32", "u32"),
    ("NonZeroU64", "u64"),
    ("NonZeroUsize", "u64"),
    ("NonZeroI32", "i32"),
    ("NonZeroI64", "i64"),
];

/// `WIDTHS.get(width)`.
fn width_of(width: &str) -> Option<&'static str> {
    WIDTHS
        .iter()
        .find(|(name, _)| *name == width)
        .map(|&(_, rust)| rust)
}

/// Port of uniffi_types.py:63-76 (RESERVED): names a generated type may not take, compared without case. A set read
/// for membership; in the literal's order.
pub(crate) const RESERVED: &[&str] = &[
    "Option",
    "Some",
    "None",
    "Result",
    "Ok",
    "Err",
    "Vec",
    "String",
    "Box",
    "HashMap",
    "Default",
    "Clone",
    "Debug",
    "PartialEq",
    "Serialize",
    "Deserialize",
    "Self",
    "Data",
    "Date",
    "Url",
    "Error",
    "Optional",
    "Array",
    "Dictionary",
    "Set",
    "Int",
    "Double",
    "Float",
    "Bool",
    "Boolean",
    "Character",
    "Type",
    "Protocol",
    "Any",
    "Unit",
    "Pair",
    "Triple",
    "List",
    "Map",
    "Duration",
    "Instant",
    "Exception",
    "Throwable",
    "Nothing",
    "Byte",
    "Short",
    "Long",
    "Enum",
    "Object",
    "RustBuffer",
    "ForeignBytes",
    "RustCallStatus",
    "Oneiron",
    "OneironError",
    "WireJson",
    "Copy",
    "Send",
    "Sync",
    "Sized",
    "Drop",
    "Fn",
    "FnMut",
    "FnOnce",
    "Iterator",
    "IntoIterator",
    "Extend",
    "ToString",
    "ToOwned",
    "PartialOrd",
    "Eq",
    "Ord",
    "AsRef",
    "AsMut",
    "Into",
    "From",
    "TryFrom",
    "TryInto",
    "FromIterator",
    "Unpin",
    "Hash",
];

/// Port of uniffi_types.py:77 (RAW_FORBIDDEN), a set read for membership.
pub(crate) const RAW_FORBIDDEN: &[&str] = &["crate", "self", "super", "Self"];

/// Port of uniffi_types.py:78-83 (KEYWORDS), a set read for membership; in the literal's order.
pub(crate) const KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "else", "enum", "extern", "false", "fn", "for", "if",
    "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static",
    "struct", "trait", "true", "type", "unsafe", "use", "where", "while", "async", "await", "dyn",
    "abstract", "become", "box", "do", "final", "macro", "override", "priv", "typeof", "unsized",
    "virtual", "yield", "try", "gen",
];

/// Port of uniffi_types.py:84 (DERIVES).
pub(crate) const DERIVES: &str = "Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize";

/// Port of uniffi_types.py:87-91 (literal): a Rust string literal, `json.dumps(text, ensure_ascii=False)` (the one
/// call that passes it, brief H1). `re.search(r'\\[ubf]', out)` runs on the dumped text, so it refuses an escaped
/// control character and also a text that holds a backslash followed by `u`, `b` or `f`; it is a text search, not a
/// check for control characters.
pub(crate) fn literal(text: &Value) -> Result<String, GenerateError> {
    let out = dumps(
        text,
        DumpOptions {
            ensure_ascii: false,
            ..DumpOptions::default()
        },
    );
    // re.search(r'\\[ubf]', out): a backslash, then `u`, `b` or `f` (all ASCII, so a byte pair is a character pair).
    if out
        .as_bytes()
        .windows(2)
        .any(|pair| pair[0] == b'\\' && matches!(pair[1], b'u' | b'b' | b'f'))
    {
        return Err(GenerateError::value(format!(
            "no Rust literal for {}",
            text.repr()
        )));
    }
    Ok(out)
}

/// Port of uniffi_types.py:94-100 (snake): a field identifier for a wire key.
///
/// `re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', key)` is `py::re::sub_underscore_at_case_rise` (brief H2), then Python's
/// Unicode `lower()`, then `re.sub(r'[^a-z0-9_]+', '_', name)` (each run of other characters becomes one `_`, written
/// out below), `.strip('_') or 'value'`. A key that is no string is `re.sub`'s `TypeError`.
pub(crate) fn snake(key: &Value) -> Result<String, GenerateError> {
    let Value::Str(key) = key else {
        return Err(GenerateError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            key.type_name()
        )));
    };
    let lowered = lower(&sub_underscore_at_case_rise(key));
    let mut cleaned = String::with_capacity(lowered.len());
    let mut in_run = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
            cleaned.push(c);
            in_run = false;
        } else if !in_run {
            cleaned.push('_');
            in_run = true;
        }
    }
    let stripped = cleaned.trim_matches('_');
    let mut name = if stripped.is_empty() {
        "value".to_owned()
    } else {
        stripped.to_owned()
    };
    // `name[0].isdigit()`: only ASCII is left.
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        name = format!("field_{name}");
    }
    if RAW_FORBIDDEN.contains(&name.as_str()) {
        return Ok(format!("{name}_"));
    }
    Ok(if KEYWORDS.contains(&name.as_str()) {
        format!("r#{name}")
    } else {
        name
    })
}

/// A struct's tag field, `(key, label)`: the `('lit', label)` field of a record (serde's `tag` on a struct).
type StructTag = (Value, Value);

/// A generic substitution (`subst`, Python's `dict` of parameter name to closed IR), read by lookup only.
type Subst = IndexMap<String, Ir>;

/// Python's `repr` of a list of IR values (`repr(members)`, `repr(args)`): the cache keys of uniffi_types.py:249 and
/// :288. `Ir::repr` spells each closed value as Python's `repr` does (tuples, and lists where `close` builds lists), so
/// two keys are equal exactly when Python's are.
fn list_repr(items: &[Ir]) -> String {
    let parts: Vec<String> = items.iter().map(Ir::repr).collect();
    format!("[{}]", parts.join(", "))
}

/// An IR value the inventory never builds at this place: Python would index it as some other tuple. Not reached by
/// any tree (each place names the Python line).
fn unexpected(place: &str, node: &Ir) -> GenerateError {
    GenerateError::exception(
        "RuntimeError",
        format!(
            "{place}: an IR value the inventory does not build here: {}",
            node.repr()
        ),
    )
}

/// The fields of an `('object', fields, hint)` value, as `record[1]` reads them.
fn object_fields<'n>(place: &str, node: &'n Ir) -> Result<&'n [Field], GenerateError> {
    match node {
        Ir::Object(fields, _) => Ok(fields),
        other => Err(unexpected(place, other)),
    }
}

/// Port of uniffi_types.py:103-419 (UniffiTypes): the UniFFI mirrors of the inventory types the facade rows reach.
/// It borrows the one `Inventory` (DESIGN 5): `root` and `root_is_empty` can root a new type in it (H10).
pub(crate) struct UniffiTypes<'i> {
    pub(crate) inv: &'i mut Inventory,
    /// Every name taken, upper-cased: the hand-written names, `RESERVED`, then each allocation (a set).
    taken: IndexSet<String>,
    /// (declaration key, `repr` of the closed arguments) -> name.
    mirrors: IndexMap<(Key, String), String>,
    /// `repr` of the closed member types -> tuple record name.
    tuples: IndexMap<String, String>,
    /// Rendered items, in first-reached order (each appended after its body).
    pub(crate) items: Vec<String>,
    /// where -> why it stays a `WireJson` leaf (the first reason kept).
    pub(crate) leaves: IndexMap<String, String>,
    /// The declarations on a by-value reference cycle (a set).
    recursive: IndexSet<Key>,
}

impl<'i> UniffiTypes<'i> {
    /// Port of uniffi_types.py:106-113 (UniffiTypes.__init__).
    pub(crate) fn new(
        inventory: &'i mut Inventory,
        taken: &IndexSet<String>,
    ) -> Result<Self, GenerateError> {
        // {name.upper() for name in set(taken) | RESERVED}
        let taken = taken
            .iter()
            .map(String::as_str)
            .chain(RESERVED.iter().copied())
            .map(upper)
            .collect();
        let mut types = Self {
            inv: inventory,
            taken,
            mirrors: IndexMap::new(),
            tuples: IndexMap::new(),
            items: Vec::new(),
            leaves: IndexMap::new(),
            recursive: IndexSet::new(),
        };
        types.recursive = types.cycles()?;
        Ok(types)
    }

    // ---- the reference graph

    /// Port of uniffi_types.py:117-165 (cycles): declarations on a by-value reference cycle; a UniFFI record cannot
    /// hold itself. A sequence or a map holds its values behind a pointer in every binding, so only a cycle of
    /// by-value edges (a field, an `Option`, a variant payload, a generic argument) counts. Tarjan's strongly
    /// connected components, iteratively, visiting keys and children in the order of their `repr`, as Python does
    /// (the set it returns does not depend on that order).
    fn cycles(&self) -> Result<IndexSet<Key>, GenerateError> {
        let mut edges: IndexMap<Key, IndexSet<Key>> = self
            .inv
            .decls
            .keys()
            .map(|key| (Key::clone(key), IndexSet::new()))
            .collect();
        for (key, decl) in &self.inv.decls {
            let mut targets = IndexSet::new();
            let mut stack: Vec<(&Ir, bool)> = vec![(decl.ir()?, false)];
            while let Some((node, boxed)) = stack.pop() {
                match node {
                    Ir::Ref(target, arguments) => {
                        if !boxed {
                            targets.insert(Key::clone(target));
                        }
                        stack.extend(arguments.iter().map(|argument| (argument, boxed)));
                    }
                    Ir::Array(inner) | Ir::Map(inner) => stack.push((inner, true)),
                    Ir::Option(inner) | Ir::Partial(inner) => stack.push((inner, boxed)),
                    Ir::Tuple(members) | Ir::Union(members) | Ir::And(members) => {
                        stack.extend(members.iter().map(|member| (member, boxed)));
                    }
                    Ir::Object(fields, _) => {
                        stack.extend(fields.iter().map(|field| (&field.value, boxed)));
                    }
                    _ => {}
                }
            }
            if let Some(slot) = edges.get_mut(key) {
                slot.extend(targets);
            }
        }
        let mut tarjan = Tarjan {
            edges: &edges,
            index: IndexMap::new(),
            low: IndexMap::new(),
            stack: Vec::new(),
            on: IndexSet::new(),
            found: IndexSet::new(),
            counter: 0,
        };
        for key in by_repr(edges.keys().cloned().collect()) {
            if !tarjan.index.contains_key(&key) {
                tarjan.visit(key)?;
            }
        }
        Ok(tarjan.found)
    }

    // ---- roots

    /// Port of uniffi_types.py:169-175 (root): the UniFFI type a row type crosses as, or `None` when it stays
    /// `WireJson` whole.
    pub(crate) fn root(&mut self, text: &str) -> Result<Option<String>, GenerateError> {
        let ir = self.inv.root_ir(text)?;
        let (unknown, _) = self.inv.reach(&ir, &mut IndexSet::new())?;
        if unknown > 0 {
            return Ok(None);
        }
        let mirror = self.rt(&ir, &Subst::new(), text)?;
        Ok(if mirror == WIRE { None } else { Some(mirror) })
    }

    /// Port of uniffi_types.py:177-179 (empty).
    fn empty(mirror_ir: &Ir) -> bool {
        matches!(mirror_ir, Ir::Object(fields, _) if fields.is_empty())
    }

    /// Port of uniffi_types.py:181-185 (root_is_empty): whether a row type is a record with no fields, so the method
    /// takes no argument.
    pub(crate) fn root_is_empty(&mut self, text: &str) -> Result<bool, GenerateError> {
        let ir = self.inv.root_ir(text)?;
        if let Ir::Ref(key, _) = &ir {
            return Ok(Self::empty(self.inv.decl(key)?.ir()?));
        }
        Ok(Self::empty(&ir))
    }

    // ---- types

    /// Port of uniffi_types.py:189-191 (leaf): the first reason for a location is kept.
    fn leaf(&mut self, place: &str, why: &str) -> String {
        if !self.leaves.contains_key(place) {
            self.leaves.insert(place.to_owned(), why.to_owned());
        }
        WIRE.to_owned()
    }

    /// Port of uniffi_types.py:193-201 (close): an IR value with the generic parameters in scope substituted.
    fn close(node: &Ir, subst: &Subst) -> Ir {
        let close = |inner: &Ir| Box::new(Self::close(inner, subst));
        let close_all = |members: &[Ir]| {
            members
                .iter()
                .map(|member| Self::close(member, subst))
                .collect()
        };
        match node {
            Ir::Param(name) => subst
                .get(name)
                .cloned()
                .unwrap_or_else(|| Ir::Unknown("unbound parameter".to_owned())),
            Ir::Array(inner) => Ir::Array(close(inner)),
            Ir::Option(inner) => Ir::Option(close(inner)),
            Ir::Map(inner) => Ir::Map(close(inner)),
            Ir::Partial(inner) => Ir::Partial(close(inner)),
            Ir::Tuple(members) => Ir::Tuple(close_all(members)),
            Ir::Union(members) => Ir::Union(close_all(members)),
            Ir::And(members) => Ir::And(close_all(members)),
            Ir::Object(fields, hint) => Ir::Object(
                fields
                    .iter()
                    .map(|field| Field {
                        key: field.key.clone(),
                        value: Self::close(&field.value, subst),
                        optional: field.optional,
                    })
                    .collect(),
                hint.clone(),
            ),
            Ir::Ref(key, arguments) => Ir::Ref(Key::clone(key), close_all(arguments)),
            other => other.clone(),
        }
    }

    /// Port of uniffi_types.py:203-216 (mangle): a type argument as part of a monomorphised name.
    fn mangle(&self, node: &Ir) -> Result<String, GenerateError> {
        Ok(match node {
            Ir::Ref(key, arguments) => {
                let mut out = self.inv.decl(key)?.name.clone();
                for argument in arguments {
                    out.push_str(&self.mangle(argument)?);
                }
                out
            }
            Ir::Array(inner) => self.mangle(inner)? + "List",
            Ir::Option(inner) => format!("Optional{}", self.mangle(inner)?),
            Ir::Map(inner) => self.mangle(inner)? + "Map",
            // WIDTHS.get(node[2] if len(node) > 2 else 'i64', 'Int').title()
            Ir::Prim(Prim::Int, width) => {
                title(width_of(width.as_deref().unwrap_or("i64")).unwrap_or("Int"))
            }
            Ir::Prim(Prim::String, _) => "String".to_owned(),
            Ir::Prim(Prim::Float, _) => "Float".to_owned(),
            Ir::Prim(Prim::Bool, _) => "Bool".to_owned(),
            Ir::Prim(Prim::Null, _) => "Unit".to_owned(),
            Ir::Opaque => "Json".to_owned(),
            Ir::Tuple(members) => {
                let mut out = "Tuple".to_owned();
                for member in members {
                    out.push_str(&self.mangle(member)?);
                }
                out
            }
            _ => "Value".to_owned(),
        })
    }

    /// Port of uniffi_types.py:218-237 (rt): the Rust spelling of an IR value in the generated module.
    fn rt(&mut self, node: &Ir, subst: &Subst, place: &str) -> Result<String, GenerateError> {
        Ok(match node {
            Ir::Prim(Prim::Int, width) => match width_of(width.as_deref().unwrap_or("i64")) {
                Some(width) => width.to_owned(),
                None => self.leaf(place, wire_leaf("wide")?),
            },
            Ir::Prim(Prim::Null, _) => self.leaf(place, wire_leaf("null")?),
            Ir::Prim(Prim::String, _) => "String".to_owned(),
            Ir::Prim(Prim::Float, _) => "f64".to_owned(),
            Ir::Prim(Prim::Bool, _) => "bool".to_owned(),
            Ir::Opaque => WIRE.to_owned(),
            Ir::Param(name) => {
                let value = subst
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| Ir::Unknown("unbound".to_owned()));
                self.rt(&value, &Subst::new(), place)?
            }
            Ir::Array(inner) => format!("Vec<{}>", self.rt(inner, subst, place)?),
            Ir::Option(inner) => {
                let inner = self.rt(inner, subst, place)?;
                if inner.starts_with("Option<") {
                    inner
                } else {
                    format!("Option<{inner}>")
                }
            }
            Ir::Map(inner) => format!(
                "std::collections::HashMap<String, {}>",
                self.rt(inner, subst, place)?
            ),
            Ir::Ref(..) => self.r#ref(node, subst, place)?,
            Ir::Tuple(members) => self.tuple(members, subst, place)?,
            Ir::Union(_) | Ir::Unknown(_) | Ir::Never => self.leaf(place, wire_leaf(node.kind())?),
            other => {
                let why = str_format(wire_leaf("inline")?, &[("name", other.kind())])?;
                self.leaf(place, &why)
            }
        })
    }

    /// Port of uniffi_types.py:239-273 (tuple): a tuple as a generated record with positional fields, crossing as
    /// one JSON array (FIX 3298). Its name is taken before its members are spelled; its item is appended after.
    fn tuple(
        &mut self,
        members: &[Ir],
        subst: &Subst,
        place: &str,
    ) -> Result<String, GenerateError> {
        let members: Vec<Ir> = members
            .iter()
            .map(|member| Self::close(member, subst))
            .collect();
        if !matches!(members.len(), 2 | 3) {
            return Ok(self.leaf(place, wire_leaf("tuple")?));
        }
        let key = list_repr(&members);
        if let Some(name) = self.tuples.get(&key) {
            return Ok(name.clone());
        }
        let mut base = "Tuple".to_owned();
        for member in &members {
            base.push_str(&self.mangle(member)?);
        }
        let name = self.allocate(&base);
        self.tuples.insert(key, name.clone());
        let mut kinds = Vec::with_capacity(members.len());
        for (i, member) in members.iter().enumerate() {
            kinds.push(self.rt(member, &Subst::new(), &format!("{place}.{i}"))?);
        }
        let arity = members.len();
        let fields: String = kinds
            .iter()
            .enumerate()
            .map(|(i, kind)| format!("    pub item{i}: {kind},\n"))
            .collect();
        let params = (0..arity)
            .map(|i| format!("&self.item{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        let made = (0..arity)
            .map(|i| format!("item{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.items.push(format!(
            "/// A tuple as UniFFI carries it: positional fields crossing as one JSON array.\n\
             #[derive(Clone, Debug, PartialEq, uniffi::Record)]\n\
             pub struct {name} {{\n{fields}}}\n\
             impl serde::Serialize for {name} {{\n    \
             fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {{\n        \
             crate::codec::ser_tuple{arity}({params}, serializer)\n    \
             }}\n\
             }}\n\
             impl<'de> serde::Deserialize<'de> for {name} {{\n    \
             fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{\n        \
             crate::codec::de_tuple{arity}(deserializer, |{made}| Self {{ {made} }})\n    \
             }}\n\
             }}\n"
        ));
        Ok(name)
    }

    /// Port of uniffi_types.py:275-300 (ref): a declaration's mirror, monomorphised by its closed arguments; a
    /// newtype, alias or hand-written codec is its wire value, inline.
    fn r#ref(&mut self, node: &Ir, subst: &Subst, place: &str) -> Result<String, GenerateError> {
        let Ir::Ref(key, arguments) = node else {
            return Err(unexpected("uniffi_types.py:276", node));
        };
        let decl = self.inv.decl(key)?;
        let (decl_name, params, item) = (decl.name.clone(), decl.params.clone(), decl.item.clone());
        let args: Vec<Ir> = arguments
            .iter()
            .map(|argument| Self::close(argument, subst))
            .collect();
        if self.recursive.contains(key) {
            let why = str_format(wire_leaf("recursive")?, &[("name", &decl_name)])?;
            return Ok(self.leaf(place, &why));
        }
        // dict(zip(decl['params'], args)): the shorter one decides; a repeated parameter keeps its first place and
        // its last value.
        let mut inner = Subst::new();
        for (param, argument) in params.iter().zip(&args) {
            inner.insert(param.clone(), argument.clone());
        }
        // `ir[0]` is read only when `meta is None` (Python's `and`), so an unfinished declaration (`ir` None) fails
        // there alone.
        let ir = self.inv.decl(key)?.ir.clone();
        let meta = self.inv.variants.get(&decl_name).cloned();
        if meta.is_none() {
            let walked = ir.as_ref().ok_or_else(|| {
                GenerateError::type_error("'NoneType' object is not subscriptable")
            })?;
            if !matches!(walked, Ir::Object(..) | Ir::And(_)) {
                // A newtype, alias or handwritten codec: its wire value, inline.
                return self.rt(walked, &inner, &decl_name);
            }
        }
        if let Some(meta) = &meta {
            if meta.variants.is_empty() {
                return Ok(self.leaf(&decl_name, wire_leaf("never")?));
            }
            if meta.variants.len() > 256 {
                let why = str_format(wire_leaf("large_enum")?, &[("name", &decl_name)])?;
                return Ok(self.leaf(place, &why));
            }
        }
        let mirror_key = (Key::clone(key), list_repr(&args));
        if let Some(name) = self.mirrors.get(&mirror_key) {
            return Ok(name.clone());
        }
        let mut base = decl_name.clone();
        for argument in &args {
            base.push_str(&self.mangle(argument)?);
        }
        let name = self.allocate(&base);
        self.mirrors.insert(mirror_key, name.clone());
        // '::'.join((item.crate,) + item.module + (item.name,))
        let mut path = vec![item.crate_name.as_str()];
        path.extend(item.module.iter().map(String::as_str));
        path.push(item.name.as_str());
        let mut doc = format!("/// `{}`", path.join("::"));
        if !args.is_empty() {
            let mut parts = Vec::new();
            for (param, argument) in params.iter().zip(&args) {
                parts.push(format!("`{param}` = `{}`", self.mangle(argument)?));
            }
            doc.push_str(" with ");
            doc.push_str(&parts.join(", "));
        }
        doc.push_str(".\n");
        let body = match (&meta, &ir) {
            (Some(meta), _) => self.r#enum(&name, &decl_name, meta, &inner)?,
            (None, Some(ir)) => self.record(&name, &decl_name, ir, &inner)?,
            (None, None) => {
                return Err(GenerateError::type_error(
                    "'NoneType' object is not subscriptable",
                ));
            }
        };
        self.items.push(doc + &body);
        Ok(name)
    }

    /// Port of uniffi_types.py:302-308 (allocate): `Base`, then `WireBase`, then `WireBase2`, ..., under Python's
    /// Unicode `upper()` (not casefold).
    fn allocate(&mut self, base: &str) -> String {
        let mut name = base.to_owned();
        let mut n = 2;
        if self.taken.contains(&upper(&name)) {
            name = format!("{COLLISION_PREFIX}{base}");
        }
        while self.taken.contains(&upper(&name)) {
            name = format!("{COLLISION_PREFIX}{base}{n}");
            n += 1;
        }
        self.taken.insert(upper(&name));
        name
    }

    // ---- items

    /// Port of uniffi_types.py:312-346 (fields): the fields of a record or a struct variant, and its struct tag, if
    /// any. One `used` set dedups identifiers across the named and the flattened fields (`_2`, `_3`, ...).
    fn fields(
        &mut self,
        owner: &str,
        body: &Ir,
        subst: &Subst,
        public: bool,
    ) -> Result<(Vec<String>, Option<StructTag>), GenerateError> {
        // (body[1][:-1], body[1][-1]) if body[0] == 'and' else ([], body)
        let (flats, record): (&[Ir], &Ir) = match body {
            Ir::And(members) => match members.split_last() {
                Some((record, flats)) => (flats, record),
                None => return Err(crate::facade_types::index_error()),
            },
            other => (&[], other),
        };
        let mut out = Vec::new();
        let mut used = IndexSet::new();
        let mut tag: Option<StructTag> = None;
        let prefix = if public { "pub " } else { "" };
        for field in object_fields("uniffi_types.py:325", record)? {
            let place = format!("{owner}.{}", field.key.str());
            if let Ir::Lit(label) = &field.value {
                if tag.is_some() {
                    return Err(GenerateError::value(format!("{owner}: two tag fields")));
                }
                tag = Some((field.key.clone(), label.clone()));
                continue;
            }
            let mut typ = self.rt(&field.value, subst, &place)?;
            let mut attrs = vec![format!("rename = {}", literal(&field.key)?)];
            if typ.starts_with("Option<") {
                attrs.push("default".to_owned());
                // (owner, key) not in self.inv.null_fields: a set of tuples, so an unhashable key is its TypeError.
                if matches!(field.key, Value::List(_) | Value::Dict(_)) {
                    return Err(GenerateError::type_error(format!(
                        "cannot use 'tuple' as a set element (unhashable type: '{}')",
                        field.key.type_name()
                    )));
                }
                if !self.inv.is_null_field(owner, &field.key) {
                    attrs.push(r#"skip_serializing_if = "Option::is_none""#.to_owned());
                }
            } else if field.optional {
                typ = format!("Option<{typ}>");
                attrs.push("default".to_owned());
                attrs.push(r#"skip_serializing_if = "Option::is_none""#.to_owned());
            }
            let attrs = attrs.join(", ");
            let ident = ident(&mut used, &field.key)?;
            out.push(format!("#[serde({attrs})]\n{prefix}{ident}: {typ},\n"));
        }
        for flat in flats {
            let partial = matches!(flat, Ir::Partial(_));
            let value = match flat {
                Ir::Partial(inner) => inner.as_ref(),
                other => other,
            };
            let mut typ = self.rt(value, subst, &format!("{owner}.(flattened)"))?;
            if partial && !typ.starts_with("Option<") {
                typ = format!("Option<{typ}>");
            }
            let label = match value {
                Ir::Ref(key, _) => self.inv.decl(key)?.name.clone(),
                _ => "flattened".to_owned(),
            };
            let ident = ident(&mut used, &Value::Str(label))?;
            out.push(format!("#[serde(flatten)]\n{prefix}{ident}: {typ},\n"));
        }
        Ok((out, tag))
    }

    /// Port of uniffi_types.py:348-364 (record). A struct whose engine `Debug` is written by hand keeps a value out
    /// of it (FIX 4993): its mirror's `Debug` names the type alone.
    fn record(
        &mut self,
        name: &str,
        owner: &str,
        ir: &Ir,
        subst: &Subst,
    ) -> Result<String, GenerateError> {
        let (fields, tag) = self.fields(owner, ir, subst, true)?;
        let redacted = self.inv.redacted.contains(owner);
        let derives = if redacted {
            DERIVES.replace("Debug, ", "")
        } else {
            DERIVES.to_owned()
        };
        let mut head = format!("#[derive({derives}, uniffi::Record)]\n");
        if let Some((key, label)) = &tag {
            head.push_str(&format!(
                "#[serde(tag = {}, rename = {})]\n",
                literal(key)?,
                literal(label)?
            ));
        }
        if self.inv.closed.contains(owner) {
            head.push_str("#[serde(deny_unknown_fields)]\n");
        }
        let mut record = head + &format!("pub struct {name} {{\n") + &fields.concat() + "}\n";
        if redacted {
            record.push_str(&format!(
                "impl std::fmt::Debug for {name} {{\n    \
                 fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        \
                 f.debug_struct({}).finish_non_exhaustive()\n    \
                 }}\n}}\n",
                literal(&Value::Str(name.to_owned()))?
            ));
        }
        Ok(record)
    }

    /// Port of uniffi_types.py:366-393 (enum).
    fn r#enum(
        &mut self,
        name: &str,
        owner: &str,
        meta: &EnumMeta,
        subst: &Subst,
    ) -> Result<String, GenerateError> {
        let (tag, content, untagged) = (
            truthy(meta.tag.as_deref()),
            truthy(meta.content.as_deref()),
            meta.untagged,
        );
        let mut head = format!("#[derive({DERIVES}, uniffi::Enum)]\n");
        if untagged {
            head.push_str("#[serde(untagged)]\n");
        } else if let (Some(tag), Some(content)) = (tag, content) {
            head.push_str(&format!(
                "#[serde(tag = {}, content = {})]\n",
                literal(&Value::Str(tag.to_owned()))?,
                literal(&Value::Str(content.to_owned()))?
            ));
        } else if let Some(tag) = tag {
            head.push_str(&format!(
                "#[serde(tag = {})]\n",
                literal(&Value::Str(tag.to_owned()))?
            ));
        }
        if self.inv.closed.contains(owner) {
            head.push_str("#[serde(deny_unknown_fields)]\n");
        }
        let mut body = String::new();
        for variant in &meta.variants {
            let vname = &variant.name;
            let place = format!("{owner}.{vname}");
            let payload = Self::payload(meta, variant)?;
            let mut attrs = if untagged {
                Vec::new()
            } else {
                vec![format!("rename = {}", literal(&variant.label)?)]
            };
            if variant.untagged && !untagged {
                attrs.push("untagged".to_owned());
            }
            if variant.other {
                attrs.push("other".to_owned());
            }
            if !attrs.is_empty() {
                body.push_str(&format!("#[serde({})]\n", attrs.join(", ")));
            }
            match (variant.shape, payload) {
                (VariantShape::Unit, _) => body.push_str(&format!("{vname},\n")),
                (VariantShape::Newtype, Some(payload)) => {
                    let typ = self.rt(&payload, subst, &place)?;
                    body.push_str(&format!("{vname}({typ}),\n"));
                }
                (VariantShape::Tuple, Some(payload)) => {
                    let Ir::Tuple(values) = &payload else {
                        return Err(unexpected("uniffi_types.py:387", &payload));
                    };
                    let mut spelled = Vec::with_capacity(values.len());
                    for value in values {
                        spelled.push(self.rt(value, subst, &place)?);
                    }
                    body.push_str(&format!("{vname}({}),\n", spelled.join(", ")));
                }
                (VariantShape::Struct, Some(mut payload)) => {
                    if let Some(tag) = tag
                        && content.is_none()
                        && !untagged
                        && !variant.untagged
                    {
                        payload = strip_marker(&payload, tag)?;
                    }
                    let (fields, _) = self.fields(&place, &payload, subst, false)?;
                    body.push_str(&format!("{vname} {{\n{}}},\n", fields.concat()));
                }
                (_, None) => return Err(unexpected("uniffi_types.py:377", &variant.member)),
            }
        }
        Ok(head + &format!("pub enum {name} {{\n") + &body + "}\n")
    }

    /// Port of uniffi_types.py:395-406 (payload): a variant's payload IR (its value, or its struct body), out of the
    /// member the inventory built (facade_types.py:944-967 builds each member; the indexing below follows those
    /// shapes).
    fn payload(meta: &EnumMeta, variant: &VariantMeta) -> Result<Option<Ir>, GenerateError> {
        let (member, shape) = (&variant.member, variant.shape);
        if shape == VariantShape::Unit {
            return Ok(None);
        }
        if meta.untagged || variant.untagged {
            return Ok(Some(member.clone()));
        }
        let (tag, content) = (truthy(meta.tag.as_deref()), truthy(meta.content.as_deref()));
        if let (Some(_), Some(content)) = (tag, content) {
            // next(value for key, value, _ in member[1] if key == content)
            return object_fields("uniffi_types.py:403", member)?
                .iter()
                .find(|field| field.key.is_str(content))
                .map(|field| Some(field.value.clone()))
                .ok_or_else(|| GenerateError::exception("StopIteration", ""));
        }
        if tag.is_some() {
            if matches!(shape, VariantShape::Newtype | VariantShape::Tuple) {
                // member[1][0]: the value of `('and', [value, marker])`.
                return match member {
                    Ir::And(members) => members
                        .first()
                        .map(|value| Some(value.clone()))
                        .ok_or_else(crate::facade_types::index_error),
                    other => Err(unexpected("uniffi_types.py:405", other)),
                };
            }
            return Ok(Some(member.clone()));
        }
        // member[1][0][1]: the value of `('object', [(label, value, False)], name)`.
        object_fields("uniffi_types.py:406", member)?
            .first()
            .map(|field| Some(field.value.clone()))
            .ok_or_else(crate::facade_types::index_error)
    }

    // ---- output

    /// Port of uniffi_types.py:410-419 (render).
    pub(crate) fn render(&self, header: &str, census: &[String]) -> String {
        let mut out = header.to_owned();
        out.push_str(
            "// UniFFI records and enums for the Rust types the facade rows reach, from the\n",
        );
        out.push_str(
            "// facade type inventory (scripts/sdk/facade_types.py). Each derives serde with\n",
        );
        out.push_str(
            "// the engine type's own wire shape; a row converts at its boundary through\n",
        );
        out.push_str("// that shape (crate::codec::lower_record / lift_record).\n");
        for line in census {
            out.push_str(&format!("// {line}\n"));
        }
        // The lints these mirrors allow sit on the `mod` that includes this file (oneiron-uniffi lib.rs).
        out.push('\n');
        out + &self.items.join("\n")
    }
}

/// A `tag`/`content` as Python's truthiness reads it: `None` and `''` are false.
fn truthy(text: Option<&str>) -> Option<&str> {
    text.filter(|text| !text.is_empty())
}

/// uniffi_types.py:317-322 (`fields`' `ident`): `snake(text)`, then `_2`, `_3`, ... until unused.
fn ident(used: &mut IndexSet<String>, text: &Value) -> Result<String, GenerateError> {
    let mut name = snake(text)?;
    let mut n = 2;
    while used.contains(&name) {
        name = format!("{}_{n}", snake(text)?);
        n += 1;
    }
    used.insert(name.clone());
    Ok(name)
}

/// Port of uniffi_types.py:422-427 (strip_marker): an internally tagged struct variant's body without its tag field.
fn strip_marker(body: &Ir, tag: &str) -> Result<Ir, GenerateError> {
    let strip = |record: &Ir| -> Result<Ir, GenerateError> {
        let Ir::Object(fields, hint) = record else {
            return Err(unexpected("uniffi_types.py:425", record));
        };
        let kept = fields
            .iter()
            .filter(|field| !(field.key.is_str(tag) && matches!(field.value, Ir::Lit(_))))
            .cloned()
            .collect();
        Ok(Ir::Object(kept, hint.clone()))
    };
    match body {
        Ir::And(members) => match members.split_last() {
            Some((record, flats)) => {
                let mut members = flats.to_vec();
                members.push(strip(record)?);
                Ok(Ir::And(members))
            }
            None => Err(crate::facade_types::index_error()),
        },
        other => strip(other),
    }
}

/// `sorted(keys, key=repr)`: by Python's `repr` of the key tuple (a stable sort; keys are unique).
fn by_repr(mut keys: Vec<Key>) -> Vec<Key> {
    keys.sort_by_cached_key(|key| key.repr());
    keys
}

/// The state of uniffi_types.py:138-161 (`cycles`' Tarjan walk).
struct Tarjan<'e> {
    edges: &'e IndexMap<Key, IndexSet<Key>>,
    index: IndexMap<Key, usize>,
    low: IndexMap<Key, usize>,
    stack: Vec<Key>,
    on: IndexSet<Key>,
    found: IndexSet<Key>,
    counter: usize,
}

impl Tarjan<'_> {
    /// `edges[key]` sorted by `repr`; a key no declaration has is Python's `KeyError`.
    fn children(&self, key: &Key) -> Result<Vec<Key>, GenerateError> {
        self.edges
            .get(key)
            .map(|children| by_repr(children.iter().cloned().collect()))
            .ok_or_else(|| GenerateError::exception("KeyError", key.repr()))
    }

    fn open(&mut self, key: &Key) {
        self.index.insert(Key::clone(key), self.counter);
        self.low.insert(Key::clone(key), self.counter);
        self.counter += 1;
        self.stack.push(Key::clone(key));
        self.on.insert(Key::clone(key));
    }

    /// uniffi_types.py:140-161 (`visit`).
    fn visit(&mut self, start: Key) -> Result<(), GenerateError> {
        let children = self.children(&start)?;
        self.open(&start);
        let mut work: Vec<(Key, Vec<Key>, usize)> = vec![(start, children, 0)];
        while let Some((node, children, at)) = work.last_mut() {
            let node = Key::clone(node);
            if let Some(child) = children.get(*at).cloned() {
                *at += 1;
                if !self.index.contains_key(&child) {
                    self.open(&child);
                    let grandchildren = self.children(&child)?;
                    work.push((child, grandchildren, 0));
                } else if self.on.contains(&child) {
                    let low = self.low[&node].min(self.index[&child]);
                    self.low.insert(node, low);
                }
                continue;
            }
            work.pop();
            if let Some((parent, _, _)) = work.last() {
                let low = self.low[parent].min(self.low[&node]);
                self.low.insert(Key::clone(parent), low);
            }
            if self.low[&node] == self.index[&node] {
                let mut component = Vec::new();
                while let Some(member) = self.stack.pop() {
                    self.on.shift_remove(&member);
                    let last = member == node;
                    component.push(member);
                    if last {
                        break;
                    }
                }
                let on_itself = self
                    .edges
                    .get(&node)
                    .is_some_and(|edges| edges.contains(&node));
                if component.len() > 1 || on_itself {
                    self.found.extend(component);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::py::value::Dict;

    /// An inventory over a tree with no sources: no declarations, no variants.
    fn empty_inventory() -> Inventory {
        let root = std::env::temp_dir().join("oneiron-sdk-generator-uniffi-types-no-tree");
        Inventory::with_type_names(&root, &[], &Value::Dict(Dict::new()))
            .expect("an inventory over no sources")
    }

    // `<workspace>/.claude/jobs/51b185fd/tmp/g3/probe_types.py`, run from the checkout on nelly (Python 3.14.7) as
    // `python3 -I - < probe_types.py`: UniffiTypes built over an inventory with no declarations, then
    //   err(t.fields, 'Owner', ('object', [('a', ('lit', 'x'), False), ('b', ('lit', 'y'), False)], None), {}, True)
    //   err(t.fields, 'Owner', ('and', []), {}, True)
    // No tree reaches the first: facade_types builds at most one `lit` field per object (facade_types.py:858, 911,
    // 957-958) and `enum` strips the internally tagged marker before `fields` (uniffi_types.py:389-390).
    #[test]
    fn fields_refuse_a_second_tag_field() {
        let mut inventory = empty_inventory();
        let mut types =
            UniffiTypes::new(&mut inventory, &IndexSet::new()).expect("no declarations");
        let lit = |label: &str| Ir::Lit(Value::Str(label.to_owned()));
        let two = Ir::Object(
            vec![
                Field::new("a", lit("x"), false),
                Field::new("b", lit("y"), false),
            ],
            None,
        );
        let refused = |body: &Ir, types: &mut UniffiTypes<'_>| {
            types
                .fields("Owner", body, &Subst::new(), true)
                .map(|_| ())
                .map_err(|error| error.to_string())
        };
        assert_eq!(
            refused(&two, &mut types),
            Err("ValueError: Owner: two tag fields".to_owned())
        );
        assert_eq!(
            refused(&Ir::And(Vec::new()), &mut types),
            Err("IndexError: list index out of range".to_owned())
        );
    }

    // probe_types.py: print(repr(node), err(t.rt, node, subst, f'W{i}')) for each case, then the leaves, the tuple
    // cache and the items in order; `mangle` of seven values; `allocate` of eight names in a row.
    #[test]
    fn rt_mangle_and_allocate_are_pythons() {
        let mut inventory = empty_inventory();
        let mut types =
            UniffiTypes::new(&mut inventory, &IndexSet::new()).expect("no declarations");
        let int = |width: Option<&str>| Ir::Prim(Prim::Int, width.map(str::to_owned));
        let prim = |kind| Ir::Prim(kind, None);
        let boxed = |node: Ir| Box::new(node);
        let cases: Vec<(Ir, &str)> = vec![
            (int(None), "i64"),
            (int(Some("u128")), WIRE),
            (int(Some("NonZeroUsize")), "u64"),
            (prim(Prim::Null), WIRE),
            (prim(Prim::String), "String"),
            (prim(Prim::Float), "f64"),
            (prim(Prim::Bool), "bool"),
            (Ir::Opaque, WIRE),
            (Ir::Param("T".to_owned()), WIRE),
            (Ir::Array(boxed(int(Some("u8")))), "Vec<u8>"),
            (
                Ir::Option(boxed(Ir::Option(boxed(prim(Prim::Bool))))),
                "Option<bool>",
            ),
            (
                Ir::Map(boxed(prim(Prim::String))),
                "std::collections::HashMap<String, String>",
            ),
            (Ir::Union(Vec::new()), WIRE),
            (Ir::Unknown("x".to_owned()), WIRE),
            (Ir::Never, WIRE),
            (Ir::Lit(Value::Str("x".to_owned())), WIRE),
            (Ir::Partial(boxed(prim(Prim::Bool))), WIRE),
            (Ir::And(Vec::new()), WIRE),
            (Ir::Object(Vec::new(), None), WIRE),
            (Ir::Tuple(vec![prim(Prim::Bool)]), WIRE),
            (
                Ir::Tuple(vec![
                    prim(Prim::Bool),
                    int(Some("i64")),
                    Ir::Opaque,
                    prim(Prim::Null),
                ]),
                WIRE,
            ),
            (
                Ir::Tuple(vec![prim(Prim::Bool), Ir::Array(boxed(int(Some("u16"))))]),
                "TupleBoolU16List",
            ),
            (
                Ir::Tuple(vec![prim(Prim::Bool), Ir::Array(boxed(int(Some("u16"))))]),
                "TupleBoolU16List",
            ),
            (
                Ir::Tuple(vec![
                    Ir::Param("T".to_owned()),
                    Ir::Option(boxed(Ir::Map(boxed(prim(Prim::Float))))),
                ]),
                "TupleStringOptionalFloatMap",
            ),
        ];
        for (i, (node, expected)) in cases.iter().enumerate() {
            let mut subst = Subst::new();
            if i == 23 {
                subst.insert("T".to_owned(), prim(Prim::String));
            }
            assert_eq!(
                types.rt(node, &subst, &format!("W{i}")).as_deref(),
                Ok(*expected),
                "case {i}"
            );
        }
        let mut leaves: Vec<(&str, &str)> = types
            .leaves
            .iter()
            .map(|(at, why)| (at.as_str(), why.as_str()))
            .collect();
        // sorted(t.leaves.items()): the keys are unique.
        leaves.sort();
        assert_eq!(
            leaves,
            [
                ("W1", "a 128-bit integer"),
                ("W12", "an untyped union"),
                ("W13", "a shape the inventory could not read"),
                ("W14", "an enum with no variants"),
                ("W15", "an inline lit"),
                ("W16", "an inline partial"),
                ("W17", "an inline and"),
                ("W18", "an inline object"),
                ("W19", "a tuple"),
                ("W20", "a tuple"),
                ("W3", "a unit value"),
                ("W8", "a shape the inventory could not read"),
            ]
        );
        let tuples: Vec<(&str, &str)> = types
            .tuples
            .iter()
            .map(|(key, name)| (key.as_str(), name.as_str()))
            .collect();
        assert_eq!(
            tuples,
            [
                (
                    "[('prim', 'bool'), ('array', ('prim', 'int', 'u16'))]",
                    "TupleBoolU16List"
                ),
                (
                    "[('prim', 'string'), ('option', ('map', ('prim', 'float')))]",
                    "TupleStringOptionalFloatMap"
                ),
            ]
        );
        assert_eq!(
            types.items,
            [
                "/// A tuple as UniFFI carries it: positional fields crossing as one JSON array.\n#[derive(Clone, Debug, PartialEq, uniffi::Record)]\npub struct TupleBoolU16List {\n    pub item0: bool,\n    pub item1: Vec<u16>,\n}\nimpl serde::Serialize for TupleBoolU16List {\n    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {\n        crate::codec::ser_tuple2(&self.item0, &self.item1, serializer)\n    }\n}\nimpl<'de> serde::Deserialize<'de> for TupleBoolU16List {\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        crate::codec::de_tuple2(deserializer, |item0, item1| Self { item0, item1 })\n    }\n}\n",
                "/// A tuple as UniFFI carries it: positional fields crossing as one JSON array.\n#[derive(Clone, Debug, PartialEq, uniffi::Record)]\npub struct TupleStringOptionalFloatMap {\n    pub item0: String,\n    pub item1: Option<std::collections::HashMap<String, f64>>,\n}\nimpl serde::Serialize for TupleStringOptionalFloatMap {\n    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {\n        crate::codec::ser_tuple2(&self.item0, &self.item1, serializer)\n    }\n}\nimpl<'de> serde::Deserialize<'de> for TupleStringOptionalFloatMap {\n    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {\n        crate::codec::de_tuple2(deserializer, |item0, item1| Self { item0, item1 })\n    }\n}\n",
            ]
        );
        let mangles: Vec<(Ir, &str)> = vec![
            (
                Ir::Array(boxed(Ir::Option(boxed(Ir::Map(boxed(int(Some("u32")))))))),
                "OptionalU32MapList",
            ),
            (int(None), "I64"),
            (int(Some("u128")), "Int"),
            (Ir::Opaque, "Json"),
            (
                Ir::Tuple(vec![prim(Prim::String), prim(Prim::Null)]),
                "TupleStringUnit",
            ),
            (Ir::Union(Vec::new()), "Value"),
            (prim(Prim::Float), "Float"),
        ];
        for (node, expected) in &mangles {
            assert_eq!(types.mangle(node).as_deref(), Ok(*expected));
        }
        let mut inventory = empty_inventory();
        let mut types =
            UniffiTypes::new(&mut inventory, &IndexSet::new()).expect("no declarations");
        let allocated: Vec<String> = [
            "Option",
            "option",
            "Thing",
            "Thing",
            "WireThing",
            "Thing",
            "straße",
            "STRASSE",
        ]
        .iter()
        .map(|base| types.allocate(base))
        .collect();
        assert_eq!(
            allocated,
            [
                "WireOption",
                "Wireoption2",
                "Thing",
                "WireThing",
                "WireWireThing",
                "WireThing2",
                "straße",
                "WireSTRASSE"
            ]
        );
    }

    // Printed by Python 3.14.7 on nelly from the uniffi_types.py definitions copied verbatim
    // (`<workspace>/.claude/jobs/51b185fd/tmp/g3/probe_uniffi.py`, `ssh nelly python3 -I - < probe_uniffi.py`):
    //   print(repr(v), err(literal, v))  /  print(repr(k), repr(snake(k)))

    #[test]
    fn literal_searches_the_dumped_text() {
        let text = |s: &str| Value::Str(s.to_owned());
        let cases: &[(Value, Result<&str, &str>)] = &[
            (text("plain"), Ok("\"plain\"")),
            (text("é😀"), Ok("\"é😀\"")),
            (
                text("a\\u"),
                Err("ValueError: no Rust literal for 'a\\\\u'"),
            ),
            (
                text("a\\b"),
                Err("ValueError: no Rust literal for 'a\\\\b'"),
            ),
            (
                text("a\\f"),
                Err("ValueError: no Rust literal for 'a\\\\f'"),
            ),
            (text("a\\n"), Ok("\"a\\\\n\"")),
            (text("a\0"), Err("ValueError: no Rust literal for 'a\\x00'")),
            (
                text("a\u{8}"),
                Err("ValueError: no Rust literal for 'a\\x08'"),
            ),
            (
                text("a\u{c}"),
                Err("ValueError: no Rust literal for 'a\\x0c'"),
            ),
            (text("a\n"), Ok("\"a\\n\"")),
            (text("a\t"), Ok("\"a\\t\"")),
            (text("a\u{7f}"), Ok("\"a\u{7f}\"")),
            (text("a\u{2028}"), Ok("\"a\u{2028}\"")),
            (text("it's"), Ok("\"it's\"")),
            (text("q\""), Ok("\"q\\\"\"")),
            (Value::Bool(true), Ok("true")),
            (Value::Int(5), Ok("5")),
            (Value::Float(1.0), Ok("1.0")),
            (Value::None, Ok("null")),
            (
                text("a\\\\u"),
                Err("ValueError: no Rust literal for 'a\\\\\\\\u'"),
            ),
            (
                text("\u{1f}"),
                Err("ValueError: no Rust literal for '\\x1f'"),
            ),
            (text("\\"), Ok("\"\\\\\"")),
        ];
        for (value, expected) in cases {
            let got = literal(value).map_err(|error| error.to_string());
            let expected = expected.map(str::to_owned).map_err(str::to_owned);
            assert_eq!(got, expected, "{value:?}");
        }
    }

    #[test]
    fn snake_is_pythons() {
        let cases: &[(&str, &str)] = &[
            ("camelCase", "camel_case"),
            ("HTTPServer", "httpserver"),
            ("a1B", "a1_b"),
            ("type", "r#type"),
            ("Self", "self_"),
            ("self", "self_"),
            ("crate", "crate_"),
            ("", "value"),
            ("___", "value"),
            ("9lives", "field_9lives"),
            ("a-b--c", "a_b_c"),
            ("é", "value"),
            ("İstanbul", "i_stanbul"),
            ("ΣΑΣ", "value"),
            ("x__y", "x__y"),
            ("_a_", "a"),
            ("fn", "r#fn"),
            ("snake_case", "snake_case"),
            ("kebab-case", "kebab_case"),
            ("with space", "with_space"),
            ("aÀb", "a_b"),
            ("ǅx", "x"),
            ("gen", "r#gen"),
            ("r#x", "r_x"),
            ("123", "field_123"),
            ("$ref", "r#ref"),
            ("Ab C", "ab_c"),
        ];
        for &(key, expected) in cases {
            assert_eq!(
                snake(&Value::Str(key.to_owned())).as_deref(),
                Ok(expected),
                "{key:?}"
            );
        }
        // print(repr(v), err(lambda v: re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', v), v))
        assert_eq!(
            snake(&Value::Bool(true)).map_err(|error| error.to_string()),
            Err("TypeError: expected string or bytes-like object, got 'bool'".to_owned())
        );
    }

    // print(w, w.title()) / print(repr(w), repr(w.upper())) of probe_uniffi.py.
    #[test]
    fn width_names_and_reservations_follow_python_case() {
        for (width, expected) in [
            ("u8", "U8"),
            ("u16", "U16"),
            ("u64", "U64"),
            ("i64", "I64"),
            ("Int", "Int"),
        ] {
            assert_eq!(title(width), expected);
        }
        assert_eq!(upper("straße"), "STRASSE");
        assert_eq!(upper("ﬁle"), "FILE");
        assert_eq!(upper("ǆ"), "Ǆ");
        assert_eq!(width_of("usize"), Some("u64"));
        assert_eq!(width_of("u128"), None);
        assert_eq!(RESERVED.len(), 80);
        assert_eq!(KEYWORDS.len(), 48);
        assert_eq!(WIDTHS.len(), 17);
    }

    #[test]
    fn strip_marker_drops_only_the_tag_literal() {
        let lit = |label: &str| Ir::Lit(Value::Str(label.to_owned()));
        let body = Ir::Object(
            vec![
                Field::new("type", lit("a"), false),
                Field::new("type", Ir::Prim(Prim::String, None), false),
                Field::new("other", lit("b"), false),
            ],
            Some("V".to_owned()),
        );
        let stripped = strip_marker(&body, "type").expect("an object");
        assert_eq!(
            stripped,
            Ir::Object(
                vec![
                    Field::new("type", Ir::Prim(Prim::String, None), false),
                    Field::new("other", lit("b"), false),
                ],
                Some("V".to_owned())
            )
        );
        assert_eq!(
            strip_marker(&Ir::And(Vec::new()), "type").map_err(|error| error.to_string()),
            Err("IndexError: list index out of range".to_owned())
        );
    }
}
