//! The TypeScript emitters: the verb tree every package emitter walks, the facade verbs
//! module (`packages/oneiron/src/facade-verbs.ts`), the native client's verb signatures and their module
//! (`native-verbs.ts`), and the Python operations on row values the TypeScript, Python and HTTP emitters need beside
//! `row_access`'s.
//!
//! The rows stay Python values: each operation keeps Python's evaluation order, so the first error a malformed row
//! meets is Python's, and every call into the shared `Inventory` happens where Python makes it (the call order names
//! its types). The Python generator's `ts_class_verbs` had no caller on main (the marked block it filled became
//! `facade-verbs.ts` in 4.3), so it is not ported.

use std::collections::BTreeSet;
use std::sync::LazyLock;

use indexmap::IndexMap;
use regex::Regex;

use super::common::{
    AGENT_VERBS_TS, argument_kind, boundary_type, js_binding_names, js_method, native_binding,
    str_receiver, ts_callable_member,
};
use super::row_access::{concat, item};
use super::uniffi::json_eq;
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::facade_types::inventory::type_text;
use crate::py::re::{compile, findall_called_words};
use crate::py::read_text;
use crate::py::text::is_word;
use crate::py::value::{Dict, Value};
use facade_verb::ts_verb;

mod facade_verb;

// ---- Python operations on row values

/// `x + '...'`: the left operand of a `str` concatenation, refused as Python refuses it.
pub(crate) fn concat_left(value: &Value) -> Result<&str, GenerateError> {
    match value {
        Value::Str(text) => Ok(text),
        Value::List(_) => Err(GenerateError::type_error(
            r#"can only concatenate list (not "str") to list"#,
        )),
        other => Err(GenerateError::type_error(format!(
            "unsupported operand type(s) for +: '{}' and 'str'",
            other.type_name()
        ))),
    }
}

/// `x.items()`: a dict's entries, Python's `AttributeError` for any other value.
pub(crate) fn dict_items(value: &Value) -> Result<&Dict, GenerateError> {
    value
        .as_dict()
        .ok_or_else(|| GenerateError::attribute(value.type_name(), "items"))
}

/// `needle in container` for a needle that may be no string. A list compares each item by identity, then equality
/// (`json_eq`: every NaN of the rows is `json.loads`' one NaN object, so it is in a list that holds a NaN).
pub(crate) fn contains(container: &Value, needle: &Value) -> Result<bool, GenerateError> {
    match (container, needle) {
        (Value::List(items), _) => Ok(items.iter().any(|item| json_eq(item, needle))),
        (Value::Dict(_), Value::List(_) | Value::Dict(_)) => {
            needle.check_hashable("a dict key").map(|()| false)
        }
        (Value::Dict(dict), _) => Ok(needle.as_str().is_some_and(|key| dict.contains_key(key))),
        (Value::Str(text), Value::Str(part)) => Ok(text.contains(part.as_str())),
        (Value::Str(_), other) => Err(GenerateError::type_error(format!(
            "'in <string>' requires string as left operand, not {}",
            other.type_name()
        ))),
        (other, _) => Err(GenerateError::type_error(format!(
            "argument of type '{}' is not a container or iterable",
            other.type_name()
        ))),
    }
}

/// `container[key]` for a key that may be no string, as Python subscripts a JSON value: a dict by its keys (`KeyError`
/// with the key's `repr`; a list or dict key is unhashable), a list by an `int` or `bool` index counted from the end
/// when negative (`IndexError` past either end, `TypeError` for any other key), a string by an `int` index only.
pub(crate) fn subscript(container: &Value, key: &Value) -> Result<Value, GenerateError> {
    // The position an `int` or `bool` key names in a sequence of `len` items, if it is in range.
    let index = |len: usize| -> Option<usize> {
        let at = match key {
            Value::Int(at) => *at,
            Value::Bool(flag) => i64::from(*flag),
            _ => return None,
        };
        let len = i64::try_from(len).unwrap_or(i64::MAX);
        let at = if at < 0 { at.saturating_add(len) } else { at };
        usize::try_from(at).ok().filter(|_| at < len)
    };
    match container {
        Value::Dict(dict) => {
            key.check_hashable("a dict key")?;
            key.as_str()
                .and_then(|name| dict.get(name))
                .cloned()
                .ok_or_else(|| GenerateError::exception("KeyError", key.repr()))
        }
        Value::List(items) if matches!(key, Value::Int(_) | Value::Bool(_)) => index(items.len())
            .and_then(|at| items.get(at).cloned())
            .ok_or_else(|| GenerateError::index("list index out of range")),
        Value::List(_) => Err(GenerateError::type_error(format!(
            "list indices must be integers or slices, not {}",
            key.type_name()
        ))),
        Value::Str(text) if matches!(key, Value::Int(_) | Value::Bool(_)) => {
            index(text.chars().count())
                .and_then(|at| text.chars().nth(at))
                .map(|c| Value::Str(c.to_string()))
                .ok_or_else(|| GenerateError::index("string index out of range"))
        }
        Value::Str(_) => Err(GenerateError::type_error(format!(
            "string indices must be integers, not '{}'",
            key.type_name()
        ))),
        other => Err(GenerateError::type_error(format!(
            "'{}' object is not subscriptable",
            other.type_name()
        ))),
    }
}

/// A row's type text as the inventory's `ts_type`/`py_type` take it (Python hashes it as a dict key first).
pub(crate) fn row_type<'r>(row: &'r Dict, key: &str) -> Result<&'r str, GenerateError> {
    type_text(item(row, key)?)
}

/// `kind[len("Option<"):-1]` of a text that starts with `Option<`: the code points between the prefix and the last
/// one (empty when nothing follows the prefix).
pub(crate) fn option_inner(kind: &str) -> &str {
    let rest = &kind["Option<".len()..];
    rest.char_indices().last().map_or("", |(at, _)| &rest[..at])
}

/// A row object, copied so the emitter can borrow the `Generator` mutably for its `Inventory` calls (no emitter
/// changes a row: the module level made its last mutation).
pub(crate) fn row_of(generator: &Generator, id: RowId) -> Dict {
    generator.rows[id].clone()
}

// ---- patterns

/// Python's `re.findall(r'\b([A-Z]\w*)\b', text)`: each word that starts with an ASCII capital.
/// By hand, because Rust's Unicode `\b` is not Python's (`py::text::is_word` is): a match starts at a capital with no
/// Python word character before it and takes the greedy run of word characters, after which Python's `\b` holds.
pub(crate) fn capitalized_words(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut at = 0;
    while let Some(c) = text[at..].chars().next() {
        let free = text[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !is_word(before));
        if c.is_ascii_uppercase() && free {
            let end = text[at..]
                .find(|next: char| !is_word(next))
                .map_or(text.len(), |len| at + len);
            found.insert(text[at..end].to_owned());
            at = end;
        } else {
            at += c.len_utf8();
        }
    }
    found
}

/// Python's `re.findall(r'^export (?:type|interface) (\w+)', text, re.M)`.
/// Rust: `(?m)^export (?:type|interface) ([\p{L}\p{N}_]+)` (`translate`; `(?m)^` matches after each `\n`, as `re.M`).
static EXPORTED_TYPE: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m)^export (?:type|interface) (\w+)"));

/// Python's `re.findall(r'^export function (\w+)', text, re.M)`.
/// Rust: `(?m)^export function ([\p{L}\p{N}_]+)`.
static EXPORTED_FUNCTION: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?m)^export function (\w+)"));

/// The first group of every match of `pattern` in `text`, as a set.
fn group_set(pattern: &Regex, text: &str) -> BTreeSet<String> {
    pattern
        .captures_iter(text)
        .filter_map(|found| found.get(1).map(|name| name.as_str().to_owned()))
        .collect()
}

/// `sorted(used & declared)`, then `used -= set(names)`.
fn take_sorted(used: &mut BTreeSet<String>, declared: &BTreeSet<String>) -> Vec<String> {
    let names: Vec<String> = used.intersection(declared).cloned().collect();
    for name in &names {
        used.remove(name);
    }
    names
}

// ---- the verb tree

/// One segment of the verb tree: the row it names, if any, and the segments under it (Python's
/// `{'row': ..., 'children': {...}}`).
#[derive(Debug, Default)]
pub(crate) struct VerbNode {
    pub(crate) row: Option<RowId>,
    pub(crate) children: VerbTree,
}

/// The verb tree: segment name to node, in insertion order (Python's dict).
pub(crate) type VerbTree = IndexMap<String, VerbNode>;

/// The rows as their path tree; a segment can name a verb and hold verbs at once.
pub(crate) fn verb_tree(generator: &Generator, rows: &[RowId]) -> Result<VerbTree, GenerateError> {
    let mut tree = VerbTree::new();
    for &id in rows {
        let name = str_receiver(item(&generator.rows[id], "name")?, "split")?;
        let parts: Vec<&str> = name.split('.').collect();
        // `str.split` yields at least one part.
        let (last, head) = parts.split_last().unwrap_or((&"", &[]));
        let mut node = &mut tree;
        for part in head {
            node = &mut node.entry((*part).to_owned()).or_default().children;
        }
        node.entry((*last).to_owned()).or_default().row = Some(id);
    }
    Ok(tree)
}

// ---- one verb as a TypeScript member

/// A TypeScript verb: its doc (a row value: a typed binding's `docs.ts` is the row's own), parameters, result type
/// and body, Python's 4-tuple.
pub(crate) struct TsVerb {
    pub(crate) doc: Value,
    pub(crate) params: String,
    pub(crate) output: String,
    pub(crate) body: String,
}

impl TsVerb {
    /// `(pad + doc + '\n' if doc else '')`.
    fn doc_line(&self, pad: &str) -> Result<String, GenerateError> {
        if self.doc.truthy() {
            Ok(format!("{pad}{}\n", concat(&self.doc)?))
        } else {
            Ok(String::new())
        }
    }
}

/// A row's description as the JSDoc of each TypeScript method that calls it.
pub(crate) fn ts_doc(row: &Dict) -> String {
    match row.get("description") {
        Some(description) if description.truthy() => format!("/** {} */", description.str()),
        _ => String::new(),
    }
}

/// A whole-input parameter, its generated type, defaulted when the input names nothing.
pub(crate) fn ts_input(generator: &mut Generator, row: &Dict) -> Result<String, GenerateError> {
    let input = item(row, "input")?;
    let typ = generator
        .inventory_mut()?
        .ts_type(type_text(input)?, "Facade.")?;
    let empty = if input.is_str("EmptyRequest") {
        " = {}"
    } else {
        ""
    };
    Ok(format!("input: {typ}{empty}"))
}

/// One object literal per namespace: an arrow per verb, a nested literal per child namespace. A node's children are
/// emitted before its own verb, as Python evaluates them.
fn ts_members(
    generator: &mut Generator,
    tree: &VerbTree,
    depth: usize,
) -> Result<String, GenerateError> {
    let pad = "  ".repeat(depth);
    let mut out = String::new();
    for (name, node) in tree {
        let inner = ts_members(generator, &node.children, depth + 1)?;
        if let Some(id) = node.row {
            let verb = ts_verb(generator, id)?;
            let mut value = format!(
                "({}): {} => this.#call(() => {})",
                verb.params, verb.output, verb.body
            );
            if !node.children.is_empty() {
                value = format!("Object.assign({value}, {{\n{inner}{pad}}})");
            }
            out += &verb.doc_line(&pad)?;
            out += &format!("{pad}{name}: {value},\n");
        } else {
            out += &format!("{pad}{name}: {{\n{inner}{pad}}},\n");
        }
    }
    Ok(out)
}

/// The head comment of `facade-verbs.ts`.
const FACADE_VERBS_TS_DOC: &str = r#"// The facade verbs of `Oneiron` (untangle slice 4.3): its verb namespaces, made per
// handle, and its top-level verbs, installed on its prototype. Both reach the
// native client through the handle's `facadeCall`, which turns a native throw
// into `OneironError`, and its `facadeClient`.
"#;

/// The module's fixed tail around its namespaces and methods.
const FACADE_CALL: &str = "\n/** A handle's guarded call: runs `operation` and turns a native throw into `OneironError`. */\nexport const facadeCall: unique symbol = Symbol(\"oneiron.facadeCall\")\n/** A handle's native client. */\nexport const facadeClient: unique symbol = Symbol(\"oneiron.facadeClient\")\n\n/** What the facade verbs need of a handle. */\nexport interface FacadeHost {\n  [facadeCall]<T>(operation: () => T): T\n  readonly [facadeClient]: NativeClient\n}\n\n/** One handle's verb namespaces, made when the handle is. */\nexport function facadeNamespaces(host: FacadeHost) {\n  return {\n";

/// The facade verbs as a module `Oneiron` imports: namespaces per handle, top-level verbs on its prototype.
pub(crate) fn ts_facade_module(
    generator: &mut Generator,
    tree: &VerbTree,
) -> Result<String, GenerateError> {
    let mut namespaces = String::new();
    let mut methods = String::new();
    for (name, node) in tree {
        let members = ts_members(generator, &node.children, 3)?;
        match node.row {
            Some(id) if node.children.is_empty() => {
                let verb = ts_verb(generator, id)?;
                let params = if verb.params.is_empty() {
                    "this: FacadeHost".to_owned()
                } else {
                    format!("this: FacadeHost, {}", verb.params)
                };
                methods += &verb.doc_line("  ")?;
                methods += &format!(
                    "  {name}({params}): {} {{ return this.#call(() => {}) }},\n",
                    verb.output, verb.body
                );
            }
            Some(id) => {
                let verb = ts_verb(generator, id)?;
                namespaces += &verb.doc_line("    ")?;
                namespaces += &format!(
                    "    {name}: Object.assign(({}): {} => this.#call(() => {}), {{\n{members}    }}),\n",
                    verb.params, verb.output, verb.body
                );
            }
            None => namespaces += &format!("    {name}: {{\n{members}    }},\n"),
        }
    }
    let namespaces = namespaces
        .replace("this.#call(", "host[facadeCall](")
        .replace("this.#client.", "host[facadeClient].");
    let methods = methods
        .replace("this.#call(", "this[facadeCall](")
        .replace("this.#client.", "this[facadeClient].");
    let body = format!("{namespaces}{methods}");
    let mut used = capitalized_words(&body);
    let mut sources: Vec<(&str, Vec<String>)> = Vec::new();
    for (module, path) in [
        ("./types.js", "packages/oneiron/src/types.ts"),
        ("./key-value.js", "packages/oneiron/src/key-value.ts"),
    ] {
        let declared = group_set(&EXPORTED_TYPE, &read_text(&generator.root.join(path))?);
        let names = take_sorted(&mut used, &declared);
        if !names.is_empty() {
            sources.push((module, names));
        }
    }
    let agent: Vec<String> = used
        .intersection(&group_set(&EXPORTED_TYPE, AGENT_VERBS_TS))
        .cloned()
        .collect();
    if !agent.is_empty() {
        sources.push(("./agent-verbs.js", agent));
    }
    let mut out = format!(
        "{HEADER}{FACADE_VERBS_TS_DOC}import type * as Facade from \"./facade-types.js\"\nimport type {{ NativeClient }} from \"./native.js\"\n"
    );
    for (module, names) in &sources {
        out += &format!("import type {{ {} }} from \"{module}\"\n", names.join(", "));
    }
    let called: BTreeSet<&str> = findall_called_words(&body).into_iter().collect();
    let exported = group_set(
        &EXPORTED_FUNCTION,
        &read_text(&generator.root.join("packages/oneiron/src/key-value.ts"))?,
    );
    let helpers: Vec<&str> = called
        .into_iter()
        .filter(|name| exported.contains(*name))
        .collect();
    if !helpers.is_empty() {
        out += &format!(
            "import {{ {} }} from \"./key-value.js\"\n",
            helpers.join(", ")
        );
    }
    out += FACADE_CALL;
    out += &namespaces;
    out += "  }\n}\n";
    out += "export type FacadeNamespaces = Readonly<ReturnType<typeof facadeNamespaces>>\n\n";
    out += "/** The top-level verbs, installed on the handle's prototype. */\nexport const facadeMethods = {\n";
    out += &methods;
    out += "}\n";
    out += "export type FacadeMethods = typeof facadeMethods\n";
    Ok(out)
}

/// The native client's generated verb signatures, as the interface `NativeClient` extends. The hand-written types
/// first, as native.ts named them; a facade type of the same name is not imported twice.
pub(crate) fn ts_native_module(
    generator: &Generator,
    signatures: &str,
    facade_types: &str,
) -> Result<String, GenerateError> {
    let mut used = capitalized_words(signatures);
    let mut out = HEADER.to_owned();
    for (module, path) in [
        ("./types.js", Some("packages/oneiron/src/types.ts")),
        ("./facade-types.js", None),
    ] {
        let text = match path {
            Some(path) => read_text(&generator.root.join(path))?,
            None => facade_types.to_owned(),
        };
        let names = take_sorted(&mut used, &group_set(&EXPORTED_TYPE, &text));
        if !names.is_empty() {
            out += &format!("import type {{ {} }} from \"{module}\"\n", names.join(", "));
        }
    }
    out += "\n/** The native client's generated verb methods, as napi-rs exposes them. */\nexport interface NativeAgentVerbs {\n";
    out += signatures;
    out += "\n}\n";
    Ok(out)
}

/// One facade row's method on the native client's interface.
pub(crate) fn ts_native_signature(
    generator: &mut Generator,
    id: RowId,
) -> Result<String, GenerateError> {
    let row = row_of(generator, id);
    let binding = native_binding(&row)?;
    let method = js_method(str_receiver(item(&row, "name")?, "replace")?);
    let Some(binding) = binding.filter(|binding| binding.truthy()) else {
        return Ok(ts_callable_member(&method, "input: unknown", "unknown"));
    };
    let wire_json = binding
        .dict_get("wire")?
        .is_some_and(|wire| wire.is_str("json"));
    let output = if wire_json {
        "string".to_owned()
    } else {
        boundary_type(
            generator,
            str_receiver(item(&row, "output")?, "startswith")?,
            "ts",
            false,
        )?
    };
    let suffix = if wire_json { "Json" } else { "" };
    let mut names = Vec::new();
    let mut kinds = Vec::new();
    for a in binding.getitem("args")?.iterate()? {
        names.push(format!("{}{suffix}", concat_left(a.getitem("name")?)?));
        kinds.push(argument_kind(a.getitem("kind")?)?.text("native_ts")?);
    }
    let args: Vec<String> = js_binding_names(&names, &[])
        .into_iter()
        .zip(kinds)
        .map(|(name, native_ts)| format!("{name}: {native_ts}"))
        .collect();
    Ok(ts_callable_member(&method, &args.join(", "), &output))
}

#[cfg(test)]
mod tests;
