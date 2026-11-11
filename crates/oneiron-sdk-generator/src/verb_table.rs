//! Port of verb_table.py: the verb table, one JSON file per verb under `scripts/sdk/verbs/`, named by its verb, read
//! in file-name order.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GenerateError;
use crate::py::json;
use crate::py::read_text;
use crate::py::text::{display_os_str, os_str_code_points};
use crate::py::value::{Dict, Value};

/// `directory.glob('*.json')`, sorted: every entry whose name ends in `.json` (a dot file, a directory or a broken
/// link too; reading one then fails as Python's does). pathlib's glob yields nothing for a missing or unreadable
/// directory and skips an entry it cannot read. `sorted()` of paths in one directory compares their names as Python
/// strings, by code point (a byte that is not UTF-8 as its surrogate).
fn verb_files(directory: &Path) -> Vec<PathBuf> {
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

/// Port of verb_table.py:10-18 (load_verbs): every verb row, in verb-name order; a file is named by the verb it holds.
pub(crate) fn load_verbs(directory: &Path) -> Result<Vec<Dict>, GenerateError> {
    let mut rows = Vec::new();
    for path in verb_files(directory) {
        let file_name = path.file_name().unwrap_or_default();
        // verb_table.py:14 `json.loads(path.read_text())`
        let row = json::loads(&read_text(&path)?)
            .map_err(|error| error.into_error(&display_os_str(file_name)))?;
        // verb_table.py:15-16: `row['name']` refuses a row that is no object as Python does.
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
                format!("{{\"name\": \"{name}\"}}"),
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

    // The traceback's last line of verb_table.load_verbs(D) on nelly (Python 3.14.7) for each file.
    #[test]
    fn refusals_match_python() {
        let cases: &[(&str, &[u8], &str)] = &[
            (
                "x.json",
                b"{\"name\": \"y\"}",
                "ValueError: x.json: a verb file is named by its verb, y.json",
            ),
            ("5.json", b"{\"name\": 5}", ""),
            ("None.json", b"{\"name\": null}", ""),
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
