//! The code-mode catalog fragment and its revision (ONE-2510 S2).
//!
//! The text declares every row code mode serves at its SDK path, with its typed input and reply, and every type they
//! reach in one namespace, read through an `Inventory` of its own over the code-mode rows (so the facade's
//! TypeScript and Python outputs keep theirs). One text goes to two paths; the revision is its SHA-256, written as a
//! Rust constant beside it. The text is read back before it is returned: it must declare exactly the code-mode rows.

use std::path::Path;

use indexmap::{IndexMap, IndexSet};
use sha2::{Digest, Sha256};

use crate::error::GenerateError;
use crate::facade_types::inventory::{row_field, type_text};
use crate::facade_types::{Inventory, Ir, compound, substring_not_found, ts_key};
use crate::py::json::dumps_str;
use crate::py::text::{splitlines, strip};
use crate::py::value::{Dict, Value};

/// The fragment's path.
pub(crate) const FRAGMENT: &str = "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts";
/// The second path the same text goes to.
pub(crate) const CODE_MODE: &str = "crates/oneiron/src/verbs/generated/code-mode.d.ts";
/// The path of the revision constant.
pub(crate) const REVISION: &str = "crates/oneiron/src/verbs/generated/catalog_fragment_revision.rs";

/// The one namespace every reached type sits in.
const NAMESPACE: &str = "Sdk";
/// The revision's digest, `sha256:<64 hex>` of the UTF-8 text.
const REVISION_ALGORITHM: &str = "sha256";
/// The head's comment lines on what a verb call resolves or rejects with.
const REPLY_DOC: &[&str] = &[
    "Every verb call resolves with its row's output itself, or with a `StoredResult` card in its place past 512 KiB of JSON.",
    "A refused call rejects with a string, the refusal's JSON: JSON.parse gives `{denied, reasonCodes}` (`denied` the outcome word,",
    r#"`reasonCodes` a string[]) or `{failed: true, error?}` (`error` a stable code, such as "finding_not_own", when the host names one)."#,
    r#"A call that parks the run, and every call after a park, rejects with "missing_host_response_field"; the host bridge's own"#,
    r#"refusals reject with a bare code too, such as "verb_input_over_budget" or "host_response_over_budget". Only an input JSON"#,
    r#"cannot carry throws at the call itself ("non_finite_verb_input", "invalid_verb_input"); the call is sent on a later microtask."#,
];
/// The rows code mode answers with the run's own coordination reply.
/// None today; Python tests membership in the tuple with `==` (no hash).
const COORDINATION: &[&str] = &[];
/// Each verb carries its row's description as its JSDoc.
const JSDOC: bool = true;
/// The interface that holds the `vault` root's members beside its verbs.
const VAULT_HOST: &str = "VaultHost";
/// `VAULT_HOST`'s JSDoc.
const VAULT_HOST_DOC: &str = "/** Members the `vault` root holds beside its verbs; another declaration file adds them by merging into this interface. */";
/// `self.fold`, the one positional verb, and its two spellings. The second is Python's
/// `f'(input: {NAMESPACE}.FoldByKind)'`.
const POSITIONAL: &[(&str, &[&str])] = &[(
    "self.fold",
    &[
        "(span: readonly [number, number], options?: { note?: string | null })",
        "(input: Sdk.FoldByKind)",
    ],
)];
/// Names no reached type may take.
const TAKEN: &[&str] = &["StoredResult", VAULT_HOST];

/// `POSITIONAL.get(name)` (and `name in POSITIONAL`): a dict lookup, so the name is hashed first.
fn positional(name: &Value) -> Result<Option<&'static [&'static str]>, GenerateError> {
    name.check_hashable("a dict key")?;
    Ok(POSITIONAL
        .iter()
        .find(|(verb, _)| name.is_str(verb))
        .map(|(_, spellings)| *spellings))
}

/// `name in COORDINATION`: tuple membership by `==`.
fn coordination(name: &Value) -> bool {
    COORDINATION.iter().any(|verb| name.is_str(verb))
}

/// `row.get('outputs_by_input', {})` read with `.items()` or `.values()` (`method`): its pairs in dict order.
fn outputs_by_input<'r>(
    row: &'r Dict,
    method: &str,
) -> Result<Vec<(&'r str, &'r Value)>, GenerateError> {
    match row.get("outputs_by_input") {
        None => Ok(Vec::new()),
        Some(Value::Dict(by_input)) => Ok(by_input
            .iter()
            .map(|(field, output)| (field.as_str(), output))
            .collect()),
        Some(other) => Err(GenerateError::attribute(other.type_name(), method)),
    }
}

/// `row['name']` where Python splits it on `.` (in `tree`): a name that is not a `str` has no `split`.
fn name_str(row: &Dict) -> Result<&str, GenerateError> {
    match row_field(row, "name")? {
        Value::Str(name) => Ok(name),
        other => Err(GenerateError::attribute(other.type_name(), "split")),
    }
}

/// `sorted(mapping)`: the keys in code-point order.
fn sorted<V>(mapping: &IndexMap<String, V>) -> Vec<&String> {
    let mut keys: Vec<&String> = mapping.keys().collect();
    keys.sort();
    keys
}

/// One segment of the verb tree (Python's `{'row': ..., 'children': {...}}`).
#[derive(Default)]
struct Node<'r> {
    row: Option<&'r Dict>,
    children: IndexMap<String, Node<'r>>,
}

impl<'r> Node<'r> {
    /// `node['row']` where Python tests its truth: a row dict is true unless empty.
    fn row(&self) -> Option<&'r Dict> {
        self.row.filter(|row| !row.is_empty())
    }
}

/// The catalog fragment over the code-mode rows, its text, census and revision.
pub(crate) struct Fragment<'r> {
    rows: Vec<&'r Dict>,
    inventory: Inventory,
}

impl<'r> Fragment<'r> {
    /// A fresh `Inventory(root, [])` (its index, then the pins of `type_names`, the `TYPE_NAMES` read from
    /// type_names.json), `TAKEN` reserved, then each row's input, its output, and each per-input reply in dict order,
    /// its field checked against the input first.
    pub(crate) fn new(
        root: &Path,
        rows: &[&'r Dict],
        type_names: &Value,
    ) -> Result<Self, GenerateError> {
        let mut fragment = Self {
            rows: rows.to_vec(),
            inventory: Inventory::with_type_names(root, &[], type_names)?,
        };
        for name in TAKEN {
            fragment.inventory.names.insert((*name).to_owned());
        }
        for &row in rows {
            fragment.inventory.root_ir_value(row_field(row, "input")?)?;
            if let Some(output) = row.get("output") {
                fragment.inventory.root_ir_value(output)?;
            }
            for (field, output) in outputs_by_input(row, "items")? {
                let name = row_field(row, "name")?;
                if positional(name)?.is_some() {
                    return Err(GenerateError::value(format!(
                        "{}: a positional verb has no input field to select its reply",
                        name.str()
                    )));
                }
                let input = row_field(row, "input")?;
                if !fragment.fields(input)?.iter().any(|key| key.is_str(field)) {
                    return Err(GenerateError::value(format!(
                        "{}: outputs_by_input names {field}, which its input {} does not carry",
                        name.str(),
                        input.str()
                    )));
                }
                fragment.inventory.root_ir_value(output)?;
            }
        }
        Ok(fragment)
    }

    /// A row type as TypeScript spells it outside the namespace.
    fn ts(&mut self, text: &Value) -> Result<String, GenerateError> {
        self.inventory
            .ts_type(type_text(text)?, &format!("{NAMESPACE}."))
    }

    /// The wire field names of an input that reads as one object (a set: every key is hashed before one is looked
    /// up).
    fn fields(&mut self, text: &Value) -> Result<Vec<Value>, GenerateError> {
        let mut node = self.inventory.root_ir_value(text)?;
        if let Ir::Ref(key, _) = &node {
            node = self.inventory.decl(key)?.ir()?.clone();
        }
        let Ir::Object(fields, _) = &node else {
            return Ok(Vec::new());
        };
        let mut keys: Vec<Value> = Vec::new();
        for field in fields {
            field.key.check_hashable("a set element")?;
            if !keys.iter().any(|key| key.py_eq(&field.key)) {
                keys.push(field.key.clone());
            }
        }
        Ok(keys)
    }

    /// A positional verb's spellings, else its one input.
    fn params(&mut self, row: &Dict) -> Result<Vec<String>, GenerateError> {
        if let Some(spellings) = positional(row_field(row, "name")?)? {
            return Ok(spellings
                .iter()
                .map(|spelling| (*spelling).to_owned())
                .collect());
        }
        Ok(vec![format!(
            "(input: {})",
            self.ts(row_field(row, "input")?)?
        )])
    }

    /// What a call resolves with; `text` is `None` when the row names no output.
    fn reply(&mut self, text: Option<&Value>) -> Result<String, GenerateError> {
        let output = match text {
            Some(text) if text.truthy() => self.ts(text)?,
            _ => "unknown".to_owned(),
        };
        // REPLY = 'Promise<{output} | StoredResult>', formatted.
        Ok(if output == "unknown" {
            "Promise<unknown>".to_owned()
        } else {
            format!("Promise<{output} | StoredResult>")
        })
    }

    /// The row's reply: `Promise<unknown>` for a coordination row, else its output's.
    fn result(&mut self, row: &Dict) -> Result<String, GenerateError> {
        if coordination(row_field(row, "name")?) {
            return Ok("Promise<unknown>".to_owned());
        }
        self.reply(row.get("output"))
    }

    /// The row's call signatures, most specific first: one per input field whose presence selects its own reply, then
    /// its own.
    fn signatures(&mut self, row: &Dict) -> Result<Vec<(String, String)>, GenerateError> {
        let mut own = Vec::new();
        for params in self.params(row)? {
            let result = self.result(row)?;
            own.push((params, result));
        }
        if !row.contains_key("outputs_by_input") {
            return Ok(own);
        }
        let mut base = self.ts(row_field(row, "input")?)?;
        if compound(&base, "|&") {
            base = format!("({base})");
        }
        let mut signatures = Vec::new();
        for (field, output) in outputs_by_input(row, "items")? {
            let key = ts_key(&Value::Str(field.to_owned()))?;
            let params = format!(
                "(input: {base} & {{ {key}: NonNullable<{base}[{}]> }})",
                dumps_str(field)
            );
            signatures.push((params, self.reply(Some(output))?));
        }
        signatures.extend(own);
        Ok(signatures)
    }

    /// The row as one call type, an arrow or a call-signature literal over its overloads.
    fn call(&mut self, row: &Dict) -> Result<String, GenerateError> {
        let signatures = self.signatures(row)?;
        if let [(params, result)] = signatures.as_slice() {
            return Ok(format!("{params} => {result}"));
        }
        let literal: Vec<String> = signatures
            .iter()
            .map(|(params, result)| format!("{params}: {result};"))
            .collect();
        Ok(format!("{{ {} }}", literal.join(" ")))
    }

    /// Whether the row's reply names its output type.
    fn typed(row: &Dict) -> Result<bool, GenerateError> {
        Ok(!coordination(row_field(row, "name")?) && row.contains_key("output"))
    }

    // ---- verbs: `self` a namespace of constants, every other root a constant, a bare verb a function, so a row
    // named by a reserved word (`vault.export`) is a valid method: a namespace's `function export` does not parse.

    /// The rows by their dotted names.
    fn tree(&self) -> Result<IndexMap<String, Node<'r>>, GenerateError> {
        let mut root = Node::default();
        for &row in &self.rows {
            let mut node = &mut root;
            for part in name_str(row)?.split('.') {
                node = node.children.entry(part.to_owned()).or_default();
            }
            node.row = Some(row);
        }
        Ok(root.children)
    }

    /// The row's description as its JSDoc line. A run row has no description; one that names its grant class shows
    /// it.
    fn doc(node: &Node<'_>, indent: &str) -> String {
        let text = match node.row() {
            Some(row) if JSDOC => match (row.get("description"), row.get("grant_class")) {
                (Some(description), _) if description.truthy() => description.str(),
                (_, Some(grant_class)) if grant_class.truthy() => {
                    format!("Grant class: {}.", grant_class.str())
                }
                _ => return String::new(),
            },
            _ => return String::new(),
        };
        format!("{indent}/** {text} */\n")
    }

    /// A path segment's type, its call signature, the members it holds, or both at once.
    fn kind(&mut self, node: &Node<'r>, depth: usize) -> Result<String, GenerateError> {
        let call = match node.row() {
            Some(row) => Some(self.call(row)?).filter(|call| !call.is_empty()),
            None => None,
        };
        if node.children.is_empty() {
            return Ok(call.unwrap_or_else(|| "{}".to_owned()));
        }
        let members = format!(
            "{{\n{}{}}}",
            self.members(&node.children, depth + 1)?,
            "  ".repeat(depth)
        );
        Ok(match call {
            Some(call) => format!("({call}) & {members}"),
            None => members,
        })
    }

    /// The members of a segment, in name order.
    fn members(
        &mut self,
        children: &IndexMap<String, Node<'r>>,
        depth: usize,
    ) -> Result<String, GenerateError> {
        let indent = "  ".repeat(depth);
        let mut out = String::new();
        for name in sorted(children) {
            let node = &children[name];
            out.push_str(&Self::doc(node, &indent));
            match node.row() {
                Some(row) if node.children.is_empty() => {
                    for (params, result) in self.signatures(row)? {
                        out.push_str(&format!("{indent}{name}{params}: {result};\n"));
                    }
                }
                _ => out.push_str(&format!("{indent}{name}: {};\n", self.kind(node, depth)?)),
            }
        }
        Ok(out)
    }

    /// The verb layout, root by root in name order.
    fn verbs(&mut self) -> Result<String, GenerateError> {
        let tree = self.tree()?;
        let mut out = String::new();
        for root in sorted(&tree) {
            let node = &tree[root];
            if root == "self" {
                out.push_str("declare namespace self {\n");
                for name in sorted(&node.children) {
                    let child = &node.children[name];
                    out.push_str(&Self::doc(child, "  "));
                    out.push_str(&format!("  const {name}: {};\n", self.kind(child, 1)?));
                }
                out.push_str("}\n");
            } else if let Some(row) = node.row().filter(|_| node.children.is_empty()) {
                out.push_str(&Self::doc(node, ""));
                for (params, result) in self.signatures(row)? {
                    out.push_str(&format!("declare function {root}{params}: {result};\n"));
                }
            } else {
                out.push_str(&Self::doc(node, ""));
                let extends = self.extends(root, node)?;
                let kind = self.kind(node, 0)?;
                out.push_str(&format!("declare const {root}: {extends}{kind};\n"));
            }
        }
        Ok(out)
    }

    /// What a root's constant extends beside its own members.
    fn extends(&mut self, root: &str, node: &Node<'r>) -> Result<String, GenerateError> {
        if root == "vault" {
            return Ok(format!("{NAMESPACE}.{VAULT_HOST} & "));
        }
        let call = node.children.get("call");
        if root == "connector"
            && let Some(row) = call.and_then(Node::row)
        {
            let result = self.result(row)?;
            // CONNECTOR_TOOLS, formatted: Rust's `{{`/`}}` are Python's.
            return Ok(format!(
                "{{ readonly [name: string]: {{ readonly [tool: string]: (args?: object) => {result} }} }} & "
            ));
        }
        Ok(String::new())
    }

    // ---- the text

    /// The four census lines of the text's head.
    fn census(&mut self) -> Result<Vec<String>, GenerateError> {
        let rows = self.rows.clone();
        let total = rows.len();
        let run = rows.iter().filter(|row| !row.contains_key("call")).count();
        let mut states: IndexMap<&str, usize> = IndexMap::new();
        for &row in &rows {
            let state = if Self::typed(row)? {
                self.inventory.root_state(row_field(row, "output")?)?
            } else {
                "unnamed"
            };
            *states.entry(state).or_insert(0) += 1;
        }
        let mut by_input: IndexMap<&str, usize> = IndexMap::new();
        for &row in &rows {
            for (_, output) in outputs_by_input(row, "values")? {
                let state = self.inventory.root_state(output)?;
                *by_input.entry(state).or_insert(0) += 1;
            }
        }
        // sorted({where for where, _, _ in self.inventory.fallbacks})
        let mut unread: Vec<&str> = self
            .inventory
            .fallbacks
            .iter()
            .map(|(at, _, _)| at.as_str())
            .collect();
        unread.sort();
        unread.dedup();
        let count =
            |counts: &IndexMap<&str, usize>, state: &str| counts.get(state).copied().unwrap_or(0);
        let by_input_total: usize = by_input.values().sum();
        Ok(vec![
            format!(
                "Census: {total} code-mode rows ({} host rows, {run} run rows), {} declarations.",
                total - run,
                self.inventory.decls.len()
            ),
            format!(
                "Replies: {} fully typed, {} typed down to an opaque serde_json::Value leaf, {} with a shape the \
                 generator could not read, {} unknown (rows whose output the table does not name, or the run's own \
                 coordination reply).",
                count(&states, "typed"),
                count(&states, "opaque"),
                count(&states, "unknown"),
                count(&states, "unnamed")
            ),
            format!(
                "Per-input replies: {by_input_total} ({} fully typed, {} typed down to an opaque serde_json::Value \
                 leaf, {} with a shape the generator could not read).",
                count(&by_input, "typed"),
                count(&by_input, "opaque"),
                count(&by_input, "unknown")
            ),
            format!(
                "Opaque serde_json::Value leaves: {}; unread shapes: {}.",
                self.inventory.opaques.len(),
                if unread.is_empty() {
                    "none".to_owned()
                } else {
                    unread.join(", ")
                }
            ),
        ])
    }

    /// The head, the census, the type namespace (every declaration in completion order), then the verb layout.
    pub(crate) fn text(&mut self) -> Result<String, GenerateError> {
        let mut out = String::from(
            "// Generated by scripts/sdk/generate.py from scripts/sdk/verbs/ and the\n",
        );
        out.push_str("// Rust types its rows name; edit the table or the types instead.\n");
        out.push_str(
            "// The code-mode catalog: every verb code mode serves, at its SDK path, with its\n",
        );
        out.push_str(&format!(
            "// typed input and reply. `{NAMESPACE}` holds every type they reach; `StoredResult` is\n"
        ));
        out.push_str("// runtime.d.ts's. The revision, the digest of this text, is\n");
        out.push_str("// `CATALOG_FRAGMENT_REVISION` (catalog_fragment_revision.rs).\n");
        for line in REPLY_DOC {
            out.push_str(&format!("// {line}\n"));
        }
        for line in self.census()? {
            out.push_str(&format!("// {line}\n"));
        }
        out.push_str(&format!("declare namespace {NAMESPACE} {{\n"));
        out.push_str(&format!(
            "  {VAULT_HOST_DOC}\n  interface {VAULT_HOST} {{}}\n"
        ));
        for key in &self.inventory.order {
            let decl = self.inventory.decl(key)?;
            let params = if decl.params.is_empty() {
                String::new()
            } else {
                format!("<{}>", decl.params.join(", "))
            };
            out.push_str(&format!(
                "  type {}{params} = {};\n",
                decl.name,
                self.inventory.ts(decl.ir()?, "")?
            ));
        }
        out.push_str("}\n");
        out.push_str(&self.verbs()?);
        Ok(out)
    }
}

/// The revision of a fragment text, its digest named by its algorithm (`sha256:` and the lowercase hex SHA-256 of the
/// text's UTF-8 bytes).
pub(crate) fn revision(text: &str) -> String {
    format!("{REVISION_ALGORITHM}:{:x}", Sha256::digest(text.as_bytes()))
}

/// For `re.match`: a line of the verb layout opens a root or a namespace, declares a verb, or both. Python's pattern:
/// `(?:declare (?:namespace|const|function) |const )?(\w+)(\(|: | \{$)`. `re.match` anchors at the start (`\A`); the
/// line is stripped, so Python's `$` (the end, or before a final newline) is the end (`\z`); `\w` is Python's
/// (`py::re::translate`).
const LAYOUT_LINE: &str = r"\A(?:declare (?:namespace|const|function) |const )?(\w+)(\(|: | \{\z)";

/// `LAYOUT_LINE.match(line)`: the verb name, the form after it, and the line past the match (`line[head.end():]`).
fn layout_match<'l>(layout: &regex::Regex, line: &'l str) -> Option<(&'l str, &'l str, &'l str)> {
    let head = layout.captures(line)?;
    let (whole, name, form) = (head.get(0)?, head.get(1)?, head.get(2)?);
    Some((name.as_str(), form.as_str(), &line[whole.end()..]))
}

/// The verb paths a fragment text declares, read back from its verb layout past the type namespace.
pub(crate) fn declared(text: &str) -> Result<IndexSet<String>, GenerateError> {
    let layout = crate::py::re::compile(LAYOUT_LINE);
    let mut names = IndexSet::new();
    let mut scope: Vec<&str> = Vec::new();
    let types = text
        .find(&format!("declare namespace {NAMESPACE} {{\n"))
        .ok_or_else(substring_not_found)?;
    let close = types
        + text[types..]
            .find("\n}\n")
            .ok_or_else(substring_not_found)?;
    for line in splitlines(&text[close + 3..]) {
        let line = strip(line);
        if line == "}" || line == "};" {
            scope
                .pop()
                .ok_or_else(|| GenerateError::index("pop from empty list"))?;
            continue;
        }
        let Some((name, form, rest)) = layout_match(&layout, line) else {
            continue;
        };
        if form == "(" || rest.starts_with('(') || rest.starts_with("{ (") {
            let mut path: Vec<&str> = scope.clone();
            path.push(name);
            names.insert(path.join("."));
        }
        if line.ends_with('{') {
            scope.push(name);
        }
    }
    Ok(names)
}

/// The fragment at both its paths and its revision constant, in Python's dict order: the files the generator writes
/// and checks. `type_names` is `TYPE_NAMES`, the parsed type_names.json, which the fragment's `Inventory` reads.
pub(crate) fn catalog_fragment(
    root: &Path,
    rows: &[&Dict],
    header: &str,
    type_names: &Value,
) -> Result<Vec<(&'static str, String)>, GenerateError> {
    let text = Fragment::new(root, rows, type_names)?.text()?;
    let declared = declared(&text)?;
    // `{row['name'] for row in rows}`: every name is a `str` once `text()` has split it.
    let mut verbs: IndexSet<&str> = IndexSet::new();
    for row in rows {
        verbs.insert(name_str(row)?);
    }
    // sorted(declared ^ verbs)
    let mut differ: Vec<&str> = declared
        .iter()
        .map(String::as_str)
        .filter(|name| !verbs.contains(name))
        .chain(
            verbs
                .iter()
                .copied()
                .filter(|name| !declared.contains(*name)),
        )
        .collect();
    differ.sort();
    if !differ.is_empty() {
        return Err(GenerateError::value(format!(
            "the catalog fragment must declare exactly the code-mode rows; it differs at {}",
            differ.join(", ")
        )));
    }
    let constant = format!(
        "{header}/// The code-mode catalog fragment's revision: `{REVISION_ALGORITHM}:` and the hex\n/// digest of \
         `catalog_fragment.d.ts`, so it changes exactly when that text does.\npub const CATALOG_FRAGMENT_REVISION: \
         &str = {};\n",
        dumps_str(&revision(&text))
    );
    Ok(vec![
        (FRAGMENT, text.clone()),
        (CODE_MODE, text),
        (REVISION, constant),
    ])
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::py::json::loads;

    // The expected values below were printed by Python 3.14.7 on nelly with the Python generator's `declared`,
    // `revision`, `catalog_fragment` and `LAYOUT_LINE` (main e79eb76df3e) and the calls each test names.

    #[test]
    fn revision_is_the_sha256_of_the_utf8_text() {
        // [print(repr(t), revision(t)) for t in ['', 'abc', 'é😀\n']]
        for (text, expected) in [
            (
                "",
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "é😀\n",
                "sha256:f26b68b6994ea006d176890661e1c0401f133bb6cffe91cecfc5bd0570921cb8",
            ),
        ] {
            assert_eq!(revision(text), expected, "{text:?}");
        }
    }

    #[test]
    fn layout_line_matches_as_python_matches() {
        // m = LAYOUT_LINE.match(line); print(json.dumps([line, m and list(m.groups()), m and line[m.end():]]))
        let layout = crate::py::re::compile(LAYOUT_LINE);
        for (line, expected) in [
            ("declare namespace self {", Some(("self", " {", ""))),
            ("declare const ai: {", Some(("ai", ": ", "{"))),
            (
                "declare function describe(input: X): Y;",
                Some(("describe", "(", "input: X): Y;")),
            ),
            (
                "const fold: (span: X) => Y;",
                Some(("fold", ": ", "(span: X) => Y;")),
            ),
            (
                "update(input: X): Y;",
                Some(("update", "(", "input: X): Y;")),
            ),
            (
                "video: ((input: X) => Y) & {",
                Some(("video", ": ", "((input: X) => Y) & {")),
            ),
            ("{ (input: X): Y; }", None),
            ("{ readonly [name: string]: X", None),
            ("const(input: X): Y;", Some(("const", "(", "input: X): Y;"))),
            ("constant: {", Some(("constant", ": ", "{"))),
            ("declare  const x: {", None),
            ("ä1(input: X): Y;", Some(("ä1", "(", "input: X): Y;"))),
            ("x {", Some(("x", " {", ""))),
            ("x: {}", Some(("x", ": ", "{}"))),
            ("", None),
        ] {
            assert_eq!(layout_match(&layout, line), expected, "{line:?}");
        }
    }

    #[test]
    fn declared_reads_the_verb_layout_back() {
        // print(json.dumps(sorted(declared(LAYOUT)), ensure_ascii=False))
        let text = "// head
declare namespace Sdk {
  interface VaultHost {}
  type A = { a: number };
}
declare const ai: {
  /** Doc. */
  chat: {
    completions(input: Sdk.A): Promise<Sdk.A | StoredResult>;
  };
  video: ((input: Sdk.A) => Promise<unknown>) & {
    poll(input: Sdk.A): Promise<unknown>;
  };
};
declare function describe(input: Sdk.A & { fold: NonNullable<Sdk.A[\"fold\"]> }): Promise<unknown>;
declare function describe(input: Sdk.A): Promise<unknown>;
declare namespace self {
  const fold: { (span: readonly [number, number]): Promise<unknown>; (input: Sdk.A): Promise<unknown>; };
  const folds: ((input: Sdk.A) => Promise<unknown>) & {
    list(input: Sdk.A): Promise<unknown>;
  };
  const group: {
    leaf(input: Sdk.A): Promise<unknown>;
  };
  const zz(x: (input: Sdk.A) => Promise<unknown>;
  const zz dash: (input: Sdk.A) => Promise<unknown>;
}
declare const vault: Sdk.VaultHost & ((input: Sdk.A) => Promise<unknown>) & {
  export(input: Sdk.A): Promise<unknown>;
};
declare const connector: { readonly [name: string]: { readonly [tool: string]: (args?: object) => Promise<unknown> } } & {
  call(input: Sdk.A): Promise<unknown>;
};
declare const ünï: {
  ä1(input: Sdk.A): Promise<unknown>;
};
";
        let mut got: Vec<String> = declared(text).expect("a layout").into_iter().collect();
        got.sort();
        assert_eq!(
            got,
            [
                "ai.chat.completions",
                "ai.video",
                "ai.video.poll",
                "connector.call",
                "describe",
                "self.fold",
                "self.folds",
                "self.folds.list",
                "self.group.leaf",
                "self.zz",
                "vault.export",
                "ünï.ä1"
            ]
        );
    }

    #[test]
    fn declared_refuses_as_python() {
        // declared(text) for each text: the exception's type and text
        for (text, expected) in [
            ("no namespace here", "ValueError: substring not found"),
            (
                "declare namespace Sdk {\n}\n};\n",
                "IndexError: pop from empty list",
            ),
            (
                "declare namespace Sdk {\n  type A = B;\n",
                "ValueError: substring not found",
            ),
        ] {
            let got = declared(text).expect_err("a refusal").to_string();
            assert_eq!(got, expected, "{text:?}");
        }
    }

    /// A scratch tree whose `oneiron` crate's `verbs/mod.rs` (the root context) holds `ZzIn { a }` and a type named
    /// `StoredResult`, the name the fragment reserves.
    fn tree(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-g2-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let verbs = root.join("crates/oneiron/src/verbs");
        fs::create_dir_all(&verbs).expect("a scratch tree");
        fs::write(
            verbs.join("mod.rs"),
            "#[derive(Debug, Serialize, Deserialize)]\npub struct ZzIn {\n    pub a: u8,\n}\n\n\
             #[derive(Debug, Serialize, Deserialize)]\npub struct StoredResult {\n    pub a: u8,\n}\n",
        )
        .expect("a source");
        root
    }

    #[test]
    fn the_fragment_refuses_as_python() {
        // catalog_fragment(root, rows, '// h\n') on the same tree, rows {'name', 'input': 'ZzIn', 'output': 'String'}
        // plus each case's keys; type_names.json pins no name these types take.
        let root = tree("refusals");
        let pins = Value::Dict(Dict::new());
        for (rows, expected) in [
            (
                r#"[{"name": "self.fold", "input": "ZzIn", "output": "String", "outputs_by_input": {"a": "String"}}]"#,
                "ValueError: self.fold: a positional verb has no input field to select its reply",
            ),
            (
                r#"[{"name": "zz.verb", "input": "ZzIn", "output": "String", "outputs_by_input": {"a": "String", "b": "String"}}]"#,
                "ValueError: zz.verb: outputs_by_input names b, which its input ZzIn does not carry",
            ),
            (
                r#"[{"name": "zz.verb", "input": "Vec<String>", "output": "String", "outputs_by_input": {"a": "String"}}]"#,
                "ValueError: zz.verb: outputs_by_input names a, which its input Vec<String> does not carry",
            ),
            (
                r#"[{"name": "zz.verb", "input": "ZzIn", "output": "String"}, {"name": "self", "input": "ZzIn", "output": "String"}]"#,
                "ValueError: the catalog fragment must declare exactly the code-mode rows; it differs at self",
            ),
            (
                r#"[{"name": "zz-dash.x", "input": "ZzIn", "output": "String"}]"#,
                "IndexError: pop from empty list",
            ),
            (
                r#"[{"name": "zz.verb", "input": "StoredResult", "output": "String"}]"#,
                "ValueError: oneiron::verbs::StoredResult: the name StoredResult is contested; pin each contestant in \
                 scripts/sdk/type_names.json",
            ),
        ] {
            let Value::List(rows) = loads(rows).expect("rows") else {
                panic!("a list of rows");
            };
            let rows: Vec<&Dict> = rows.iter().filter_map(Value::as_dict).collect();
            let got = catalog_fragment(&root, &rows, "// h\n", &pins)
                .expect_err("a refusal")
                .to_string();
            assert_eq!(got, expected);
        }
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
