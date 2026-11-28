use super::*;
use std::fs;
use std::path::PathBuf;

/// A scratch tree whose verb table is `files`.
fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "oneiron-sdk-generator-rows-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let verbs = root.join("scripts/sdk/verbs");
    fs::create_dir_all(&verbs).expect("a scratch tree");
    // The `facade_types` import reads it before any verb file.
    fs::write(root.join("scripts/sdk/type_names.json"), "{}\n").expect("type_names.json");
    let verb_tree = root.join("scripts/sdk/verb-tree");
    fs::create_dir_all(&verb_tree).expect("a verb tree");
    fs::write(verb_tree.join("families.json"), "{}\n").expect("families.json");
    fs::write(verb_tree.join("vault_capabilities.json"), "{}\n").expect("vault_capabilities.json");
    for (file, text) in files {
        fs::write(verbs.join(file), text).expect("a verb file");
    }
    root
}

const BASE: &str = r#""name": "zz_fixture", "description": "Reads a fixture.", "input": "ZzInput", "output": "ZzOutput", "call": "zz_call(memory, &input)?", "scope": "Read", "act_class": "unstated", "section": false"#;

// Each expected line: the last stderr line of the Python generator's module level (Python 3.14.7 on nelly) over
// a tree whose only verb file is the row.
#[test]
fn refusals_match_python() {
    let cases: &[(&str, &str)] = &[
        (
            r#""host": {"input": "X"}, "context": "run""#,
            "ValueError: zz_fixture: a host projection names the public input and description, with optional caller, session, lists, pre-check and OpenAPI flags",
        ),
        (
            r#""session_read": "Nope""#,
            "ValueError: zz_fixture: `session_read` is one of ('Get', 'Hydrate', 'RefsResolve', 'SearchBm25', 'Receipts') on a Read row",
        ),
        (
            r#""overlay_write": 1, "scope": "Write""#,
            "ValueError: zz_fixture: `overlay_write` is `true` on a Write row",
        ),
        (
            r#""mcp_scope": "nope""#,
            "ValueError: zz_fixture: mcp_scope must be one of ['addressed', 'born', 'filtered', 'unrestricted']",
        ),
        (
            r#""mcp": "none""#,
            "ValueError: zz_fixture: only a browser or scoped-child row states \"mcp\": \"none\", and every such row does",
        ),
        (
            r#""host_door": true, "host_door_precheck": 0"#,
            "ValueError: zz_fixture: host_door_precheck is only a host door's, and only false",
        ),
        (
            r#""admission": {"require_granted_scope": true}"#,
            "ValueError: zz_fixture: require_granted_scope is only a non-Read lane_record_scope facade row's, with no other record-scope admission, and on a host door only a caller or listing one",
        ),
        (
            r#""refs": "/a""#,
            "ValueError: zz_fixture: refs are distinct JSON pointers of field names and `*`",
        ),
        (
            r#""binding": {"generic": true, "args": [{"name": "a", "type": "Wrong", "field": "$"}]}"#,
            "ValueError: zz_fixture: a whole-input parameter is the row's only one, typed as its input",
        ),
        (
            r#""description": "no period""#,
            "ValueError: zz_fixture: every row has a description: one printable ASCII line ending in a period, with no backslash, double quote or `*/`",
        ),
        (
            r#""admission": [1]"#,
            "AttributeError: 'list' object has no attribute 'get'",
        ),
        (
            r#""mcp_fields": {"a": 1}"#,
            "TypeError: argument of type 'int' is not a container or iterable",
        ),
        (
            r#""admission": {"readable": [1]}"#,
            "TypeError: expected string or bytes-like object, got 'int'",
        ),
        (
            r#""mcp_scope": ["filtered"]"#,
            "TypeError: cannot use 'list' as a set element (unhashable type: 'list')",
        ),
    ];
    for (at, (fields, expected)) in cases.iter().enumerate() {
        let root = tree(
            &format!("refusal-{at}"),
            &[("zz_fixture.json", &format!("{{{BASE}, {fields}}}"))],
        );
        let got = Generator::new(&root).map_or_else(|error| error.to_string(), |_| String::new());
        assert_eq!(got, *expected, "{fields}");
        fs::remove_dir_all(&root).expect("cleanup");
    }
    let root = tree(
        "duplicate",
        &[
            ("1.json", &BASE.replace(r#""zz_fixture""#, "1")),
            ("1.0.json", &BASE.replace(r#""zz_fixture""#, "1.0")),
        ],
    );
    for file in ["1.json", "1.0.json"] {
        let path = root.join("scripts/sdk/verbs").join(file);
        let text = fs::read_to_string(&path).expect("a verb file");
        fs::write(&path, format!("{{{text}}}")).expect("a verb file");
    }
    let error = Generator::new(&root)
        .map(drop)
        .expect_err("1 == 1.0")
        .to_string();
    assert_eq!(error, "ValueError: duplicate SDK verb");
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn grant_class_refusals_match_python() {
    // The expected lines are the ones the Python generator printed for the same rows, through both halves of the
    // port harness on G5 with main 30deae1a20e merged, before this change removed it.
    const RUN: &str = r#""name": "zz_run", "description": "Runs a fixture.", "input": "ZzInput", "output": "ZzOutput", "scope": "Write", "act_class": "reversible_work", "context": "run", "effect": "ZzEffect""#;
    let phrase = "ValueError: zz_run: a grant class is one printable ASCII phrase, with no backslash, double quote \
                  or `*/`";
    let keys = "ValueError: zz_run: a run row names its input, scope, act class, effect, output, per-input outputs, run surface \
                and grant class, and nothing else";
    let longest = format!(r#""grant_class": "{}""#, "x".repeat(120));
    let too_long = format!(r#""grant_class": "{}""#, "x".repeat(121));
    let cases: &[(&str, &str)] = &[
        (r#""grant_class": "author's slice (ARCH-0053:20)""#, ""),
        (r#""grant_class": "a/b * c /* d""#, ""),
        (longest.as_str(), ""),
        (r#""grant_class": 1"#, phrase),
        (r#""grant_class": null"#, phrase),
        (r#""grant_class": """#, phrase),
        (r#""grant_class": " padded""#, phrase),
        (r#""grant_class": "padded ""#, phrase),
        (r#""grant_class": "a \"quoted\" phrase""#, phrase),
        (r#""grant_class": "back\\slash""#, phrase),
        (r#""grant_class": "ends */ here""#, phrase),
        (r#""grant_class": "caf\u00e9""#, phrase),
        (r#""grant_class": "tab\there""#, phrase),
        (too_long.as_str(), phrase),
        (r#""grant_class": "x", "nope": 1"#, keys),
    ];
    for (fields, expected) in cases {
        let root = tree(
            "grant-class",
            &[
                ("zz_fixture.json", &format!("{{{BASE}}}")),
                ("zz_run.json", &format!("{{{RUN}, {fields}}}")),
            ],
        );
        let got = Generator::new(&root).map_or_else(|error| error.to_string(), |_| String::new());
        assert_eq!(got, *expected, "{fields}");
        fs::remove_dir_all(&root).expect("cleanup");
    }
    // Every run row's key set is checked before any run row's grant class: zz_a's bad grant class comes first in
    // the verb table, yet zz_run's extra key is the refusal.
    let root = tree(
        "grant-class-order",
        &[
            ("zz_fixture.json", &format!("{{{BASE}}}")),
            (
                "zz_a.json",
                &format!("{{{}, \"grant_class\": 1}}", RUN.replace("zz_run", "zz_a")),
            ),
            ("zz_run.json", &format!("{{{RUN}, \"nope\": 1}}")),
        ],
    );
    let got = Generator::new(&root).map_or_else(|error| error.to_string(), |_| String::new());
    assert_eq!(got, keys);
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn power_is_spawn_or_save_agent() {
    const RUN: &str = r#""name": "zz_run", "description": "Runs a fixture.", "input": "ZzInput", "output": "ZzOutput", "scope": "Write", "act_class": "reversible_work", "context": "run", "effect": "ZzEffect""#;
    let refused = "ValueError: zz_run: a power is `spawn` or `save_agent`";
    let cases: &[(&str, &str)] = &[
        (r#""power": "spawn""#, ""),
        (r#""power": "save_agent""#, ""),
        (r#""grant_class": "parent's slice", "power": "spawn""#, ""),
        (r#""power": "Spawn""#, refused),
        (r#""power": "spawn ""#, refused),
        (r#""power": "launch""#, refused),
        (r#""power": 1"#, refused),
        (r#""power": null"#, refused),
        (r#""power": ["spawn"]"#, refused),
    ];
    for (fields, expected) in cases {
        let root = tree(
            "power",
            &[
                ("zz_fixture.json", &format!("{{{BASE}}}")),
                ("zz_run.json", &format!("{{{RUN}, {fields}}}")),
            ],
        );
        let got = Generator::new(&root).map_or_else(|error| error.to_string(), |_| String::new());
        assert_eq!(got, *expected, "{fields}");
        fs::remove_dir_all(&root).expect("cleanup");
    }
}

#[test]
fn type_names_is_read_before_the_verbs() {
    // The `facade_types` import reads type_names.json before load_verbs: with both broken, the Python generator
    // stops on type_names.json, and so does the module level with or without the type inventory.
    let root = tree("type-names-first", &[("zz_fixture.json", "{")]);
    fs::write(root.join("scripts/sdk/type_names.json"), "{\n").expect("type_names.json");
    let expected = "json.decoder.JSONDecodeError: Expecting property name enclosed in double quotes: line 2 column \
                    1 (char 2)";
    for got in [
        Generator::new(&root).map(drop),
        Generator::rows_only(&root).map(drop),
    ] {
        assert_eq!(
            got.expect_err("type_names.json is broken").to_string(),
            expected
        );
    }
    fs::remove_dir_all(&root).expect("cleanup");
}

#[test]
fn sets_share_rows_and_bindings_move() {
    let host =
        r#""context": "board", "scope": "Write", "host": {"input": "HostIn", "description": "D."}"#;
    let generic = r#""handle_args": "old", "binding": {"generic": true, "args": [{"name": "text", "type": "String"}]}"#;
    let root = tree(
        "sets",
        &[
            (
                "a.json",
                &format!("{{{}, {host}}}", BASE.replace("zz_fixture", "a")),
            ),
            (
                "b.json",
                &format!("{{{}, {generic}}}", BASE.replace("zz_fixture", "b")),
            ),
        ],
    );
    let generator = Generator::new(&root).expect("valid rows");
    assert_eq!(generator.manifest, [RowId(0), RowId(1)]);
    assert_eq!(generator.board_host_rows, [RowId(2)]);
    assert_eq!(generator.callable_rows, [RowId(0), RowId(1)]);
    assert_eq!(generator.facade_rows, [RowId(1), RowId(2)]);
    assert_eq!(generator.code_mode_rows, [RowId(1), RowId(0)]);
    let board = &generator.rows[RowId(2)];
    let keys: Vec<&str> = board.keys().map(String::as_str).collect();
    assert_eq!(keys.last(), Some(&"board_input"));
    assert!(board["act_class"].is_str("unstated"));
    assert!(board["call"].is_str("crate::task_verb::sdk::host_only(memory, \"a\", &input)?"));
    // The setdefault defaults land on the shared row; the binding moves to `handle_args`, which keeps its place.
    let b = &generator.rows[RowId(1)];
    assert!(b["mcp_scope"].is_str("unrestricted"));
    let keys: Vec<&str> = b.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "name",
            "description",
            "input",
            "output",
            "call",
            "scope",
            "act_class",
            "section",
            "handle_args",
            "mcp_fields",
            "mcp_scope"
        ]
    );
    fs::remove_dir_all(&root).expect("cleanup");
}
