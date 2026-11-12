//! The verb table, one JSON file per verb under `scripts/sdk/verbs/`, named by its verb, read
//! in file-name order.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GenerateError;
use crate::py::json;
use crate::py::read_text;
use crate::py::text::{display_os_str, os_str_code_points};
use crate::py::value::{Dict, Value};

/// The verb table's directory, from the repository root.
pub(crate) const VERBS_DIR: &str = "scripts/sdk/verbs";

/// ARCH-0082 #act-table: every row states the act class of the act it makes (`act_class`), by the ruled names
/// (VERB-SURFACE-DESIGN 3.1, VS-CHECKIN-NAMES = A), in the order of `crate::check_in::ActClass::ALL`.
pub(crate) const ACT_CLASSES: [&str; 20] = [
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
];
/// `read` marks a read: check-in is never asked for one, and only a Read row states it. `unstated` marks a row
/// whose effect has no proven undo class, so it holds on silence. No default fills a missing class (ARCH-0082:212).
pub(crate) const ACT_CLASS_VALUES: [&str; 22] = {
    let mut values = [""; 22];
    let mut at = 0;
    while at < ACT_CLASSES.len() {
        values[at] = ACT_CLASSES[at];
        at += 1;
    }
    values[20] = "read";
    values[21] = "unstated";
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
            .map(|row| row.get("name").map(Value::str).unwrap_or_default())
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
}
