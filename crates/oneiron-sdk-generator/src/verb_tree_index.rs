//! The verb-tree index (`verb_tree_index.json`): the code-mode verbs, their types, the family lines, the
//! vault capability labels, view head and base texts as one JSON object for the `verbs.tree` renderer.
//!
//! Built from the same [`Fragment`] as the catalog fragment: `catalog_fragment` calls it with its own instance
//! when the caller passes examples, and appends it last. Top-level keys in this order: `revision` (the fragment
//! revision, the same value as `CATALOG_FRAGMENT_REVISION`), `verbs` (path, sorted, to description, input,
//! output and example), `types` (name, sorted, to one-line declarations), `families` (sorted),
//! `vault_capabilities` (file order: label order matters for the view), `head` (the view head verbatim) and
//! `base` (path, sorted, to text without its trailing newline). Written with the crate's JSON writer; a verb
//! entry's keys stay in schema order, not sorted.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::catalog_fragment::{Fragment, VAULT_HOST};
use crate::error::GenerateError;
use crate::facade_types::inventory::row_field;
use crate::py::json::{DumpOptions, dumps, loads};
use crate::py::read_text;
use crate::py::value::{Dict, Value};

/// The index's path (a build-time output: `OUT_DIR` only, like the fragment; no mirror in the
/// tree).
pub(crate) const INDEX: &str = "crates/oneiron/src/verbs/generated/verb_tree_index.json";

/// `row['name']` where the fragment splits it on `.` (as `catalog_fragment`'s): a name that is not a `str`
/// has no `split`.
fn name_str(row: &Dict) -> Result<&str, GenerateError> {
    match row_field(row, "name")? {
        Value::Str(name) => Ok(name),
        other => Err(GenerateError::attribute(other.type_name(), "split")),
    }
}

/// One verb-tree JSON object file, identifying it on any read, parse, or shape error (as `verb_table`'s
/// reader).
fn read_object(path: &Path) -> Result<Dict, GenerateError> {
    let text = read_text(path)?;
    let value = loads(&text)
        .map_err(|error| GenerateError::value(format!("{}: {error}", path.display())))?;
    match value {
        Value::Dict(object) => Ok(object),
        _ => Err(GenerateError::value(format!(
            "{}: expected a JSON object",
            path.display()
        ))),
    }
}

/// The view head: it exists and holds `{TOTAL}`.
fn read_head(path: &Path) -> Result<String, GenerateError> {
    let text = read_text(path)?;
    if !text.contains("{TOTAL}") {
        return Err(GenerateError::value(format!(
            "{}: the view head holds {{TOTAL}}",
            path.display()
        )));
    }
    Ok(text)
}

/// Every base text: the file is named `<path>.txt` for a code-mode verb or tree call, and its first line
/// starts with `<path>(`. Returns path to text (trailing newline removed), sorted.
fn read_base(
    dir: &Path,
    verbs: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, GenerateError> {
    let mut names: Vec<String> = Vec::new();
    for entry in fs::read_dir(dir).map_err(|error| GenerateError::os(&error, dir))? {
        let entry = entry.map_err(|error| GenerateError::os(&error, dir))?;
        let name = entry.file_name().to_str().map(str::to_owned);
        names.push(name.ok_or_else(|| {
            GenerateError::value(format!(
                "{}: a base text is named <verb path>.txt for a code-mode verb, verbs.expand or \
                 verbs.search",
                entry.path().display()
            ))
        })?);
    }
    names.sort();
    let mut base = BTreeMap::new();
    for name in names {
        let path = dir.join(&name);
        if !path.is_file() {
            return Err(GenerateError::value(format!(
                "{}: the verb-tree base holds only files named <verb path>.txt",
                path.display()
            )));
        }
        let verb = name.strip_suffix(".txt").filter(|stem| !stem.is_empty());
        let verb = match verb {
            Some(verb)
                if matches!(verb, "verbs.expand" | "verbs.search") || verbs.contains(verb) =>
            {
                verb
            }
            _ => {
                return Err(GenerateError::value(format!(
                    "{}: a base text is named <verb path>.txt for a code-mode verb, verbs.expand or \
                     verbs.search",
                    path.display()
                )));
            }
        };
        let text = read_text(&path)?;
        let first = text.lines().next().unwrap_or("");
        if !first.starts_with(&format!("{verb}(")) {
            return Err(GenerateError::value(format!(
                "{}: a base text's first line starts with `{verb}(`",
                path.display()
            )));
        }
        base.insert(
            verb.to_owned(),
            text.strip_suffix('\n').unwrap_or(&text).to_owned(),
        );
    }
    Ok(base)
}

/// Every run of whitespace collapsed to one space (the index's one-line declarations).
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The index over the fragment's rows: `(INDEX, text)`. `revision` is the fragment revision of the same
/// rows' catalog text. `examples` is verb path to the manifest rows' authored examples: a projected row (a host
/// synthetic) carries no example of its own, so it takes its manifest row's.
pub(crate) fn verb_tree_index(
    fragment: &mut Fragment,
    root: &Path,
    rows: &[&Dict],
    revision: &str,
    examples: &BTreeMap<String, String>,
) -> Result<(&'static str, String), GenerateError> {
    let tree = root.join("scripts/sdk/verb-tree");
    let head = read_head(&tree.join("view_head.txt"))?;
    let mut paths = BTreeSet::new();
    for &row in rows {
        if let Some(Value::Str(name)) = row.get("name") {
            paths.insert(name.clone());
        }
    }
    let base = read_base(&tree.join("base"), &paths)?;
    let families = read_object(&tree.join("families.json"))?;
    let capabilities = read_object(&tree.join("vault_capabilities.json"))?;
    // The verbs, sorted by path; a repeated name keeps its last row, as the fragment's tree
    // overwrites.
    let mut verbs: BTreeMap<String, Dict> = BTreeMap::new();
    for &row in rows {
        let name = name_str(row)?;
        let (input, output) = fragment.index_input_output(row)?;
        let mut verb = Dict::new();
        verb.insert(
            "description".into(),
            Value::Str(
                row.get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            ),
        );
        verb.insert("input".into(), Value::Str(input));
        verb.insert("output".into(), Value::Str(output));
        verb.insert(
            "example".into(),
            match row.get("example") {
                Some(Value::Str(example)) => Value::Str(example.clone()),
                _ => match examples.get(name) {
                    Some(example) => Value::Str(example.clone()),
                    None => Value::None,
                },
            },
        );
        verbs.insert(name.to_owned(), verb);
    }
    // The types the fragment's namespace declares: its host interface, then every walked declaration as one
    // line.
    let mut types: BTreeMap<String, String> = BTreeMap::new();
    types.insert(VAULT_HOST.to_owned(), format!("type {VAULT_HOST} = {{}};"));
    let inventory = fragment.inventory();
    for key in &inventory.order {
        let decl = inventory.decl(key)?;
        let params = if decl.params.is_empty() {
            String::new()
        } else {
            format!("<{}>", decl.params.join(", "))
        };
        let declaration = format!(
            "type {}{params} = {};",
            decl.name,
            inventory.ts(decl.ir()?, "")?
        );
        types.insert(decl.name.clone(), one_line(&declaration));
    }
    let mut index = Dict::new();
    index.insert("revision".into(), Value::Str(revision.to_owned()));
    index.insert(
        "verbs".into(),
        Value::Dict(
            verbs
                .into_iter()
                .map(|(name, verb)| (name, Value::Dict(verb)))
                .collect(),
        ),
    );
    index.insert(
        "types".into(),
        Value::Dict(
            types
                .into_iter()
                .map(|(name, declaration)| (name, Value::Str(declaration)))
                .collect(),
        ),
    );
    let mut entries: Vec<(&String, &Value)> = families.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut sorted = Dict::new();
    for (name, value) in entries {
        sorted.insert(name.clone(), value.clone());
    }
    index.insert("families".into(), Value::Dict(sorted));
    index.insert("vault_capabilities".into(), Value::Dict(capabilities));
    index.insert("head".into(), Value::Str(head));
    index.insert(
        "base".into(),
        Value::Dict(
            base.into_iter()
                .map(|(path, text)| (path, Value::Str(text)))
                .collect(),
        ),
    );
    Ok((INDEX, dumps(&Value::Dict(index), DumpOptions::default())))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::py::json::loads;

    /// A scratch tree: `ZzIn { a }` and `ZzOut { b }` in the root context, empty pins, the verb-tree
    /// files (`head=None` omits view_head.txt), and `base` files.
    fn tree(name: &str, head: Option<&str>, base: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-verb-tree-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let verbs = root.join("crates/oneiron/src/verbs");
        fs::create_dir_all(&verbs).expect("a scratch tree");
        fs::write(
            verbs.join("mod.rs"),
            "#[derive(Debug, Serialize, Deserialize)]\npub struct ZzIn {\n    pub a: u8,\n}\n\n\
             #[derive(Debug, Serialize, Deserialize)]\npub struct ZzOut {\n    pub b: String,\n}\n",
        )
        .expect("a source");
        let sdk = root.join("scripts/sdk");
        fs::create_dir_all(sdk.join("verb-tree/base")).expect("a verb tree");
        fs::write(sdk.join("type_names.json"), "{}\n").expect("type_names.json");
        fs::write(sdk.join("verb-tree/families.json"), "{\"zz\": \"Zz.\"}\n")
            .expect("families.json");
        fs::write(
            sdk.join("verb-tree/vault_capabilities.json"),
            "{\"Second\": [], \"First\": []}\n",
        )
        .expect("vault_capabilities.json");
        if let Some(head) = head {
            fs::write(sdk.join("verb-tree/view_head.txt"), head).expect("view_head.txt");
        }
        for (file, text) in base {
            fs::write(sdk.join("verb-tree/base").join(file), text).expect("a base file");
        }
        root
    }

    /// `text` as code-mode rows.
    fn rows_of(text: &str) -> Vec<Value> {
        let Value::List(rows) = loads(text).expect("rows") else {
            panic!("a list of rows");
        };
        rows
    }

    /// The index of `rows` over `root` with `examples` and a fixed revision.
    fn index_of(
        root: &Path,
        rows: &[Value],
        examples: &BTreeMap<String, String>,
    ) -> Result<Value, GenerateError> {
        let rows: Vec<&Dict> = rows.iter().filter_map(Value::as_dict).collect();
        let mut fragment =
            Fragment::new(root, &rows, &Value::Dict(Dict::new())).expect("a fragment");
        let (path, text) = verb_tree_index(&mut fragment, root, &rows, "sha256:test", examples)?;
        assert_eq!(path, INDEX);
        let Value::Dict(index) = loads(&text).expect("JSON") else {
            panic!("an object");
        };
        Ok(Value::Dict(index))
    }

    #[test]
    fn verb_tree_index_holds_every_code_mode_row_and_its_types() {
        let root = tree(
            "holds",
            Some("HEAD {TOTAL} {BASE_COUNT}\n"),
            &[("zz.a.txt", "zz.a({ a: number })\n  -> { b }\n  Reads.\n")],
        );
        let rows = rows_of(
            r#"[{"name": "zz.b", "description": "Reads b.", "input": "ZzIn", "output": "ZzOut"},
                {"name": "zz.a", "description": "Reads a.", "input": "ZzIn", "output": "ZzOut",
                 "example": "await zz.a({ a: 1 })"},
                {"name": "zz.c", "description": "Reads c.", "input": "ZzIn"},
                {"name": "self.fold", "description": "Folds.", "input": "ZzIn", "output": "ZzOut"}]"#,
        );
        let examples = BTreeMap::from([("zz.b".to_owned(), "await zz.b({});".to_owned())]);
        let index = index_of(&root, &rows, &examples).expect("an index");
        fs::remove_dir_all(&root).expect("cleanup");
        let Value::Dict(index) = index else {
            panic!("an object");
        };
        let keys: Vec<&str> = index.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "revision",
                "verbs",
                "types",
                "families",
                "vault_capabilities",
                "head",
                "base"
            ]
        );
        assert!(index["revision"].is_str("sha256:test"));
        let Value::Dict(verbs) = &index["verbs"] else {
            panic!("verbs");
        };
        let paths: Vec<&str> = verbs.keys().map(String::as_str).collect();
        assert_eq!(paths, ["self.fold", "zz.a", "zz.b", "zz.c"]);
        for (name, verb) in verbs {
            let Value::Dict(verb) = verb else {
                panic!("a verb");
            };
            let keys: Vec<&str> = verb.keys().map(String::as_str).collect();
            assert_eq!(
                keys,
                ["description", "input", "output", "example"],
                "{name}"
            );
        }
        let Value::Dict(a) = &verbs["zz.a"] else {
            panic!("zz.a");
        };
        assert!(a["description"].is_str("Reads a."));
        assert!(a["input"].is_str("ZzIn"));
        assert!(a["output"].is_str("ZzOut"));
        assert!(a["example"].is_str("await zz.a({ a: 1 })"));
        // No example of its own: the manifest row's.
        let Value::Dict(b) = &verbs["zz.b"] else {
            panic!("zz.b");
        };
        assert!(b["example"].is_str("await zz.b({});"));
        // No output named, no example anywhere.
        let Value::Dict(c) = &verbs["zz.c"] else {
            panic!("zz.c");
        };
        assert!(c["output"].is_str("unknown"));
        assert!(matches!(c["example"], Value::None));
        // A positional row keeps its parameter text.
        let Value::Dict(fold) = &verbs["self.fold"] else {
            panic!("self.fold");
        };
        assert!(
            fold["input"]
                .is_str("(span: readonly [number, number], options?: { note?: string | null })")
        );
        assert!(fold["output"].is_str("ZzOut"));
        let Value::Dict(types) = &index["types"] else {
            panic!("types");
        };
        let names: Vec<&str> = types.keys().map(String::as_str).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(
            names.contains(&"VaultHost") && names.contains(&"ZzIn") && names.contains(&"ZzOut")
        );
        assert!(types["VaultHost"].is_str("type VaultHost = {};"));
        for name in ["ZzIn", "ZzOut"] {
            let Some(declaration) = types[name].as_str() else {
                panic!("a declaration");
            };
            assert!(!declaration.contains('\n'), "{declaration}");
            assert!(
                declaration.starts_with(&format!("type {name} = ")),
                "{declaration}"
            );
        }
        assert!(
            types["ZzIn"]
                .as_str()
                .is_some_and(|text| text.contains("a: number"))
        );
        let Value::Dict(families) = &index["families"] else {
            panic!("families");
        };
        assert!(families["zz"].is_str("Zz."));
        // Label order is the file's, not sorted.
        let Value::Dict(capabilities) = &index["vault_capabilities"] else {
            panic!("vault_capabilities");
        };
        let labels: Vec<&str> = capabilities.keys().map(String::as_str).collect();
        assert_eq!(labels, ["Second", "First"]);
        assert!(index["head"].is_str("HEAD {TOTAL} {BASE_COUNT}\n"));
        let Value::Dict(base) = &index["base"] else {
            panic!("base");
        };
        assert!(base["zz.a"].is_str("zz.a({ a: number })\n  -> { b }\n  Reads."));
    }

    #[test]
    fn rejects_a_base_text_for_no_verb() {
        let root = tree(
            "no-verb",
            Some("HEAD {TOTAL}\n"),
            &[("zz.nope.txt", "zz.nope({})\n  -> {}\n  Nope.\n")],
        );
        let rows = rows_of(
            r#"[{"name": "zz.a", "description": "Reads a.", "input": "ZzIn", "output": "ZzOut"}]"#,
        );
        let got = index_of(&root, &rows, &BTreeMap::new())
            .expect_err("a refusal")
            .to_string();
        fs::remove_dir_all(&root).expect("cleanup");
        assert!(got.contains("zz.nope.txt"), "{got}");
        assert!(got.contains("code-mode verb"), "{got}");
    }

    #[test]
    fn rejects_a_base_text_whose_first_line_names_another_verb() {
        let root = tree(
            "another-verb",
            Some("HEAD {TOTAL}\n"),
            &[("zz.a.txt", "zz.b({})\n  -> {}\n  Mismatch.\n")],
        );
        let rows = rows_of(
            r#"[{"name": "zz.a", "description": "Reads a.", "input": "ZzIn", "output": "ZzOut"}]"#,
        );
        let got = index_of(&root, &rows, &BTreeMap::new())
            .expect_err("a refusal")
            .to_string();
        fs::remove_dir_all(&root).expect("cleanup");
        assert!(got.contains("zz.a.txt"), "{got}");
        assert!(got.contains("zz.a("), "{got}");
    }

    #[test]
    fn rejects_a_missing_view_head() {
        let root = tree("no-head", None, &[]);
        let rows = rows_of(
            r#"[{"name": "zz.a", "description": "Reads a.", "input": "ZzIn", "output": "ZzOut"}]"#,
        );
        let got = index_of(&root, &rows, &BTreeMap::new())
            .expect_err("a refusal")
            .to_string();
        fs::remove_dir_all(&root).expect("cleanup");
        assert!(got.contains("view_head.txt"), "{got}");
    }
}
