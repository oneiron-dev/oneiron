//! The verb table, one JSON file per verb under `scripts/sdk/verbs/`, named by its verb, read
//! in file-name order.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::error::GenerateError;
use crate::py::json;
use crate::py::read_text;
use crate::py::text::{display_os_str, os_str_code_points};
use crate::py::value::{Dict, Value};

/// The verb table's directory, from the repository root.
pub(crate) const VERBS_DIR: &str = "scripts/sdk/verbs";

/// ARCH-0082 #act-table: every row states the act class of the act it makes (`act_class`), by the ruled names
/// (VERB-SURFACE-DESIGN 3.1, VS-CHECKIN-NAMES = A), in the order of `crate::check_in::ActClass::ALL`.
pub(crate) const ACT_CLASSES: [&str; 21] = [
    "reversible_work",
    "spawn",
    "spend_over_cap",
    "outbound_send",
    "room_add",
    "member_add",
    "member_remove",
    "legal_send",
    "sign",
    "billing",
    "delete",
    "vault_delete",
    "erase",
    "ownership_transfer",
    "key_recovery",
    "security_control_disable",
    "mass_secret_export",
    "world_widen",
    "grant_widen",
    "grant_widen_own",
    "protected_ref_rewrite_or_delete",
];
/// `read` marks a read: check-in is never asked for one, and only a Read row states it. `unstated` marks a row
/// whose effect has no proven undo class, so it holds on silence. No default fills a missing class (ARCH-0082:212).
pub(crate) const ACT_CLASS_VALUES: [&str; 23] = {
    let mut values = [""; 23];
    let mut at = 0;
    while at < ACT_CLASSES.len() {
        values[at] = ACT_CLASSES[at];
        at += 1;
    }
    values[21] = "read";
    values[22] = "unstated";
    values
};

/// Fails unless the row states one act class, and `read` only on a Read row.
fn check_act_class(row: &Dict) -> Result<(), GenerateError> {
    let value = row.get("act_class").and_then(Value::as_str);
    if !value.is_some_and(|value| ACT_CLASS_VALUES.contains(&value)) {
        return Err(GenerateError::value(format!(
            "{}: `act_class` is one of {}; no default fills a missing one",
            row["name"].str(),
            ACT_CLASS_VALUES.join(", ")
        )));
    }
    if value == Some("read") && !row.get("scope").is_some_and(|scope| scope.is_str("Read")) {
        return Err(GenerateError::value(format!(
            "{}: `act_class` is `read` on a Read row only",
            row["name"].str()
        )));
    }
    Ok(())
}

/// An optional example has one physical line and calls the exact verb path as code: the call
/// stands outside every string literal and comment, so a quoted mention is no call.
fn check_example(row: &Dict, name: &str) -> Result<(), GenerateError> {
    let Some(example) = row.get("example") else {
        return Ok(());
    };
    let valid = example.as_str().is_some_and(|text| {
        !text.trim().is_empty()
            && !text.contains(['\n', '\r'])
            && Regex::new(&format!(
                r"(?:^|[^\p{{ID_Continue}}.$\x{{200C}}\x{{200D}}])({}) *\(",
                regex::escape(name)
            ))
            .expect("an escaped verb name in the example pattern")
            .captures_iter(text)
            .filter_map(|call| call.get(1))
            .any(|path| outside_strings_and_comments(&text[..path.start()]))
    });
    if !valid {
        return Err(GenerateError::value(format!(
            "{name}: an example is one line of code that calls the row's own verb"
        )));
    }
    Ok(())
}

/// Whether code goes on after `prefix`: it leaves no string literal open (`"`, `'` or a
/// backtick, with backslash escapes) and starts no comment.
fn outside_strings_and_comments(prefix: &str) -> bool {
    let mut open: Option<char> = None;
    let mut chars = prefix.chars().peekable();
    while let Some(c) = chars.next() {
        match open {
            Some(_) if c == '\\' => {
                chars.next();
            }
            Some(quote) if c == quote => open = None,
            Some(_) => {}
            None if matches!(c, '"' | '\'' | '`') => open = Some(c),
            None if c == '/' && matches!(chars.peek(), Some('/' | '*')) => return false,
            None => {}
        }
    }
    open.is_none()
}

/// Reads one verb-tree file, identifying it on any read, parse, or shape error.
fn read_verb_tree_object(path: &Path) -> Result<Dict, GenerateError> {
    let text = fs::read_to_string(path).map_err(|error| GenerateError::os(&error, path))?;
    let value = json::loads(&text)
        .map_err(|error| GenerateError::value(format!("{}: {error}", path.display())))?;
    match value {
        Value::Dict(object) => Ok(object),
        _ => Err(GenerateError::value(format!(
            "{}: expected a JSON object",
            path.display()
        ))),
    }
}

/// Checks family lines and vault capability labels against the original verb names.
pub(crate) fn check_verb_tree<'a>(
    sdk: &Path,
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), GenerateError> {
    let mut roots = BTreeSet::new();
    let mut vault_children = BTreeSet::new();
    for name in names {
        if let Some((root, rest)) = name.split_once('.') {
            roots.insert(root);
            if root == "vault" {
                vault_children.insert(rest.split('.').next().unwrap_or_default());
            }
        }
    }

    let tree = sdk.join("verb-tree");
    let families_path = tree.join("families.json");
    let families = read_verb_tree_object(&families_path)?;
    for root in &roots {
        if !families
            .get(*root)
            .and_then(Value::as_str)
            .is_some_and(|line| !line.trim().is_empty() && !line.contains(['\n', '\r']))
        {
            return Err(GenerateError::value(format!(
                "{}: root {root:?} needs a non-blank family line of one line",
                families_path.display()
            )));
        }
    }
    for root in families.keys() {
        if !roots.contains(root.as_str()) {
            return Err(GenerateError::value(format!(
                "{}: family line {root:?} must name a root with a dotted descendant",
                families_path.display()
            )));
        }
    }

    let capabilities_path = tree.join("vault_capabilities.json");
    let capabilities = read_verb_tree_object(&capabilities_path)?;
    let mut labelled = BTreeSet::new();
    for (label, members) in &capabilities {
        let Value::List(members) = members else {
            return Err(GenerateError::value(format!(
                "{}: label {label:?} must hold an array of vault child names",
                capabilities_path.display()
            )));
        };
        for member in members {
            let Some(child) = member
                .as_str()
                .filter(|child| vault_children.contains(*child))
            else {
                return Err(GenerateError::value(format!(
                    "{}: label {label:?} member {} must be a real vault child",
                    capabilities_path.display(),
                    member.repr()
                )));
            };
            if !labelled.insert(child) {
                return Err(GenerateError::value(format!(
                    "{}: vault child {child:?} must appear exactly once across the labels (repeated in {label:?})",
                    capabilities_path.display()
                )));
            }
        }
    }
    if let Some(child) = vault_children.difference(&labelled).next() {
        return Err(GenerateError::value(format!(
            "{}: vault child {child:?} must appear exactly once across the labels (unlabelled)",
            capabilities_path.display()
        )));
    }
    Ok(())
}

/// `directory.glob('*.json')`, sorted: every entry whose name ends in `.json` (a dot file, a directory or a broken
/// link too; reading one then fails as Python's does). pathlib's glob yields nothing for a missing or unreadable
/// directory and skips an entry it cannot read. `sorted()` of paths in one directory compares their names as Python
/// strings, by code point (a byte that is not UTF-8 as its surrogate).
pub(crate) fn verb_files(directory: &Path) -> Vec<PathBuf> {
    let mut files: Vec<(Vec<u32>, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if name.as_encoded_bytes().ends_with(b".json") {
                files.push((os_str_code_points(&name), entry.path()));
            }
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.into_iter().map(|(_, path)| path).collect()
}

/// Every verb row, in verb-name order; a file is named by the verb it holds.
pub(crate) fn load_verbs(directory: &Path) -> Result<Vec<Dict>, GenerateError> {
    let mut rows = Vec::new();
    for path in verb_files(directory) {
        let file_name = path.file_name().unwrap_or_default();
        // Python: `json.loads(path.read_text())`
        let row = json::loads(&read_text(&path)?)
            .map_err(|error| error.into_error(&display_os_str(file_name)))?;
        // `row['name']` refuses a row that is no object as Python does.
        let name = row.getitem("name")?.str();
        if file_name.as_encoded_bytes() != format!("{name}.json").as_bytes() {
            return Err(GenerateError::value(format!(
                "{}: a verb file is named by its verb, {name}.json",
                display_os_str(file_name)
            )));
        }
        let Value::Dict(row) = row else {
            return Err(GenerateError::type_error("a verb row is a JSON object"));
        };
        check_act_class(&row)?;
        check_example(&row, &name)?;
        rows.push(row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system's temporary directory.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    fn names(rows: &[Dict]) -> Vec<String> {
        rows.iter()
            .map(|row| row.get("name").map_or_default(Value::str))
            .collect()
    }

    // python3 -c "from pathlib import Path; print([p.name for p in sorted(Path(D).glob('*.json'))])" over the same
    // files on nelly: ['.json', 'A.json', '_x.json', 'a.b.json', 'a.json', 'a_b.json', 'b.json', 'é.json']
    #[test]
    fn rows_come_in_python_path_order() {
        let dir = scratch("order");
        for name in ["b", "a", "", "A", "_x", "é", "a.b", "a_b"] {
            fs::write(
                dir.join(format!("{name}.json")),
                format!(r#"{{"name": "{name}", "act_class": "unstated"}}"#),
            )
            .expect("a verb file");
        }
        fs::write(dir.join("z.JSON"), "not read").expect("a file");
        fs::write(dir.join("x.json.bak"), "not read").expect("a file");
        let rows = load_verbs(&dir).expect("valid rows");
        assert_eq!(
            names(&rows),
            [
                ".json", "A.json", "_x.json", "a.b.json", "a.json", "a_b.json", "b.json", "é.json"
            ]
            .map(|file| file.trim_end_matches(".json").to_owned())
        );
        assert!(
            load_verbs(&dir.join("missing"))
                .expect("no directory, no rows")
                .is_empty()
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn invalid_act_classes_are_refused() {
        for (at, fields) in [
            "",
            r#", "act_class": """#,
            r#", "act_class": "READ""#,
            r#", "act_class": "spend_above_cap""#,
            r#", "act_class": "widen_own_grant""#,
            r#", "act_class": 7"#,
        ]
        .iter()
        .enumerate()
        {
            let dir = scratch(&format!("act-class-refusal-{at}"));
            fs::write(
                dir.join("x.json"),
                format!(r#"{{"name": "x", "scope": "Write"{fields}}}"#),
            )
            .expect("a verb file");
            let error = load_verbs(&dir).expect_err("an explicit closed-set act class is required");
            assert_eq!(
                error.to_string(),
                format!(
                    "ValueError: x: `act_class` is one of {}; no default fills a missing one",
                    ACT_CLASS_VALUES.join(", ")
                )
            );
            fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    #[test]
    fn read_act_class_is_only_for_read_rows() {
        let dir = scratch("read-act-class-on-write");
        fs::write(
            dir.join("x.json"),
            r#"{"name": "x", "scope": "Write", "act_class": "read"}"#,
        )
        .expect("a verb file");
        let error = load_verbs(&dir).expect_err("read only marks a Read row");
        assert_eq!(
            error.to_string(),
            "ValueError: x: `act_class` is `read` on a Read row only"
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn read_and_reversible_work_act_classes_load() {
        for (scope, act_class) in [("Read", "read"), ("Write", "reversible_work")] {
            let dir = scratch(&format!("act-class-{act_class}"));
            fs::write(
                dir.join("x.json"),
                format!(r#"{{"name": "x", "scope": "{scope}", "act_class": "{act_class}"}}"#),
            )
            .expect("a verb file");
            let rows = load_verbs(&dir).expect("valid act class");
            assert_eq!(rows.len(), 1);
            assert!(rows[0]["act_class"].is_str(act_class));
            fs::remove_dir_all(&dir).expect("cleanup");
        }
    }

    // The traceback's last line of the Python generator's load_verbs(D) on nelly (Python 3.14.7) for each file.
    #[test]
    fn refusals_match_python() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "x.json",
                b"{\"name\": \"y\"}",
                "ValueError: x.json: a verb file is named by its verb, y.json",
            ),
            ("5.json", b"{\"name\": 5, \"act_class\": \"unstated\"}", ""),
            (
                "None.json",
                b"{\"name\": null, \"act_class\": \"unstated\"}",
                "",
            ),
            ("x.json", b"{\"input\": 1}", "KeyError: 'name'"),
            (
                "x.json",
                b"[1]",
                "TypeError: list indices must be integers or slices, not str",
            ),
            (
                "x.json",
                b"\"x\"",
                "TypeError: string indices must be integers, not 'str'",
            ),
            (
                "x.json",
                b"5",
                "TypeError: 'int' object is not subscriptable",
            ),
            (
                "x.json",
                b"{\r\n \"name\": \"x\",\r\n}",
                "json.decoder.JSONDecodeError: Illegal trailing comma before end of object: line 2 column 13 (char 14)",
            ),
            (
                "x.json",
                b"\xef\xbb\xbf{}",
                "json.decoder.JSONDecodeError: Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
            ),
            (
                "x.json",
                b"{\n\"name\": \"\xff\"}",
                "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 11: invalid start byte",
            ),
        ];
        for (at, (file, text, expected)) in cases.iter().enumerate() {
            let dir = scratch(&format!("refusal-{at}"));
            fs::write(dir.join(file), text).expect("a verb file");
            let got = load_verbs(&dir).map_or_else(|error| error.to_string(), |_| String::new());
            assert_eq!(got, *expected, "{file} {text:?}");
            fs::remove_dir_all(&dir).expect("cleanup");
        }
        let dir = scratch("directory");
        fs::create_dir(dir.join("x.json")).expect("a directory");
        let error = load_verbs(&dir)
            .expect_err("a directory is no verb file")
            .to_string();
        assert_eq!(
            error,
            format!(
                "IsADirectoryError: [Errno 21] Is a directory: '{}'",
                dir.join("x.json").display()
            )
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    fn write_verb_tree(sdk: &Path, families: &str, vault_capabilities: &str) {
        let tree = sdk.join("verb-tree");
        fs::create_dir_all(&tree).expect("a verb tree");
        fs::write(tree.join("families.json"), families).expect("families.json");
        fs::write(tree.join("vault_capabilities.json"), vault_capabilities)
            .expect("vault_capabilities.json");
    }

    fn description_row(label: &str, text: &str) -> Result<(), GenerateError> {
        use crate::generate::Generator;

        let root = scratch(label);
        let sdk = root.join("scripts/sdk");
        let verbs = sdk.join("verbs");
        fs::create_dir_all(&verbs).expect("a scratch tree");
        fs::write(sdk.join("type_names.json"), "{}\n").expect("type_names.json");
        write_verb_tree(&sdk, "{}", "{}");
        fs::write(verbs.join("zz_fixture.json"), text).expect("a verb file");
        let result = Generator::rows_only(&root).map(drop);
        fs::remove_dir_all(&root).expect("cleanup");
        result
    }

    #[test]
    fn rejects_a_row_without_a_description() {
        let row = r#"{"name":"zz_fixture","input":"In","output":"Out","scope":"Read","act_class":"read","call":"read(memory, &input)?"}"#;
        let error = description_row("missing-description", row)
            .expect_err("a row without a description is refused")
            .to_string();
        assert!(error.contains("zz_fixture:"), "{error}");
        assert!(
            error.contains(
                "every row has a description: one printable ASCII line ending in a period"
            ),
            "{error}"
        );
    }

    #[test]
    fn accepts_a_run_row_description_without_a_call() {
        let row = r#"{"name":"zz_fixture","description":"Runs a fixture.","input":"In","scope":"Read","act_class":"read","context":"run","effect":"Effect"}"#;
        description_row("run-description", row)
            .expect("an effect-backed row can have a description");
    }

    fn example_row(label: &str, example: &str) -> Result<Vec<Dict>, GenerateError> {
        let dir = scratch(label);
        let row = format!(
            r#"{{"name":"vault.recall","description":"Recalls memories.","scope":"Read","act_class":"read","example":{example}}}"#
        );
        fs::write(dir.join("vault.recall.json"), row).expect("a verb file");
        let loaded = load_verbs(&dir);
        fs::remove_dir_all(&dir).expect("cleanup");
        loaded
    }

    fn assert_example_refusal(label: &str, example: &str) {
        let error = example_row(label, example)
            .expect_err("the example is refused")
            .to_string();
        assert!(error.contains("vault.recall:"), "{error}");
        assert!(
            error.contains("an example is one line of code that calls the row's own verb"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_multi_line_example() {
        for example in [
            r#""vault.recall({});\nnext()""#,
            r#""vault.recall({});\rnext()""#,
        ] {
            assert_example_refusal("multi-line-example", example);
        }
    }

    #[test]
    fn rejects_an_example_that_calls_another_verb() {
        for example in [
            r#""vault.remember({})""#,
            r#""vault.recall_x({})""#,
            r#""x.vault.recall({})""#,
            r#""xvault.recall({})""#,
            r#""$vault.recall({})""#,
        ] {
            assert_example_refusal("wrong-example-verb", example);
        }
    }

    #[test]
    fn rejects_an_example_that_only_names_its_verb() {
        assert_example_refusal("example-mention", r#""vault.recall""#);
    }

    #[test]
    fn rejects_an_example_that_calls_its_verb_only_inside_a_string_or_comment() {
        for example in [
            r#""const hint = \"vault.recall({})\";""#,
            r#""const hint = 'vault.recall({})';""#,
            r#""const hint = `vault.recall({})`;""#,
            r#""log(\"see vault.recall({})\")""#,
            r#""log(\"a \\\" vault.recall({})\")""#,
            r#""// vault.recall({})""#,
            r#""/* vault.recall({}) */""#,
        ] {
            assert_example_refusal("example-in-string", example);
        }
    }

    #[test]
    fn accepts_an_example_whose_call_takes_string_arguments() {
        example_row(
            "example-string-argument",
            r#""const r = await vault.recall({query: \"vault.recall(x)\", limit: 3})""#,
        )
        .expect("a call outside strings is valid whatever its arguments hold");
    }

    #[test]
    fn accepts_a_one_line_example_that_calls_its_own_verb() {
        example_row(
            "own-example-verb",
            r#""const result = await vault.recall ({})""#,
        )
        .expect("an example calling its own verb is valid");
    }

    fn verb_tree_error(label: &str, families: &str, capabilities: &str, names: &[&str]) -> String {
        let sdk = scratch(label);
        write_verb_tree(&sdk, families, capabilities);
        let result = check_verb_tree(&sdk, names.iter().copied());
        fs::remove_dir_all(&sdk).expect("cleanup");
        result.expect_err("the verb tree is refused").to_string()
    }

    #[test]
    fn rejects_a_root_without_a_family_line() {
        let error = verb_tree_error("missing-family", "{}", "{}", &["reveal", "reveal.wait"]);
        assert!(error.contains("families.json"), "{error}");
        assert!(
            error.contains(r#"root "reveal" needs a non-blank family line"#),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_family_line_of_more_than_one_line() {
        for families in [
            r#"{"vault":"Shared memory.\nMore."}"#,
            r#"{"vault":"Shared memory.\rMore."}"#,
        ] {
            let error = verb_tree_error(
                "multi-line-family",
                families,
                r#"{"Read":["recall"]}"#,
                &["vault.recall"],
            );
            assert!(error.contains("families.json"), "{error}");
            assert!(
                error.contains(r#"root "vault" needs a non-blank family line of one line"#),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_a_family_line_for_no_root() {
        let error = verb_tree_error("extra-family", r#"{"ask":"Asks."}"#, "{}", &["ask"]);
        assert!(error.contains("families.json"), "{error}");
        assert!(
            error.contains(r#"family line "ask" must name a root with a dotted descendant"#),
            "{error}"
        );
    }

    #[test]
    fn rejects_an_unlabelled_vault_child() {
        let error = verb_tree_error(
            "unlabelled-vault-child",
            r#"{"vault":"Shared memory."}"#,
            "{}",
            &["vault.claims.get"],
        );
        assert!(error.contains("vault_capabilities.json"), "{error}");
        assert!(
            error.contains(
                r#"vault child "claims" must appear exactly once across the labels (unlabelled)"#
            ),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_vault_child_in_two_labels() {
        for capabilities in [
            r#"{"Read":["recall"],"Other":["recall"]}"#,
            r#"{"Read":["recall","recall"]}"#,
        ] {
            let error = verb_tree_error(
                "repeated-vault-child",
                r#"{"vault":"Shared memory."}"#,
                capabilities,
                &["vault.recall"],
            );
            assert!(error.contains("vault_capabilities.json"), "{error}");
            assert!(
                error.contains(
                    r#"vault child "recall" must appear exactly once across the labels (repeated"#
                ),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_a_label_member_that_is_no_vault_child() {
        let error = verb_tree_error(
            "unknown-vault-child",
            r#"{"vault":"Shared memory."}"#,
            r#"{"Read":["recall","invented"]}"#,
            &["vault.recall"],
        );
        assert!(error.contains("vault_capabilities.json"), "{error}");
        assert!(
            error.contains("member 'invented' must be a real vault child"),
            "{error}"
        );
    }
}
