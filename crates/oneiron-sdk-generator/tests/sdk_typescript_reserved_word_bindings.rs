//! FIX-LIST [SDK-TS-RESERVED-WORD-IDENTIFIERS]: the generated TypeScript binds no name that is a
//! JavaScript reserved word, and no callable member of an interface or type literal is named
//! `new` (a construct signature there). A verb row's argument and field names become parameters
//! and destructured bindings in `facade-verbs.ts` and `native-verbs.ts`, and a code-mode root,
//! bare verb or `self` member becomes a `const`, `function` or `namespace` in the catalog
//! fragment; a reserved word there does not parse, and no PR-time job parses these files (the
//! 21 Nov nightly e2e found the Python twin, `def continue`). The generator runs on the repository
//! through its public `outputs` entry. Today's table names no reserved word at these positions,
//! so this test guards the emitters' escape and refusal.
//! `cargo test --locked -p oneiron-sdk-generator --all-features
//! --test sdk_typescript_reserved_word_bindings`.

use std::path::{Path, PathBuf};

/// ECMAScript's reserved words, the ones strict (module) code adds, and `arguments` and `eval`,
/// which strict code does not bind (ECMA-262, 13.1.1).
const JS_RESERVED_WORDS: [&str; 48] = [
    "arguments",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "eval",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "interface",
    "let",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "var",
    "void",
    "while",
    "with",
    "yield",
];

/// The form of a callable member `name(params): result` in the scan's report.
const CALLABLE_MEMBER: &str = "callable member (`new(` is a construct signature)";

const FACADE_VERBS: &str = "packages/oneiron/src/facade-verbs.ts";
const NATIVE_VERBS: &str = "packages/oneiron/src/native-verbs.ts";
const CATALOG_FRAGMENT: &str = "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts";

/// The repository root above this crate.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// One step of a scan that skips double-quoted strings (a JSON default) whole: whether `byte` is
/// outside a string, given the state before it, which the step updates.
fn outside_string(byte: u8, quoted: &mut bool, escaped: &mut bool) -> bool {
    if *quoted {
        if *escaped {
            *escaped = false;
        } else if byte == b'\\' {
            *escaped = true;
        } else if byte == b'"' {
            *quoted = false;
        }
        return false;
    }
    if byte == b'"' {
        *quoted = true;
        return false;
    }
    true
}

/// The text inside the bracket at byte `open` and its match, or `None` when it does not close.
fn enclosed(text: &str, open: usize) -> Option<&str> {
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for (index, &byte) in text.as_bytes().iter().enumerate().skip(open) {
        if !outside_string(byte, &mut quoted, &mut escaped) {
            continue;
        }
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(&text[open + 1..index]);
                }
            }
            _ => {}
        }
    }
    None
}

/// A list split at its top-level commas (none inside brackets, type arguments or strings).
fn top_level_parts(list: &str) -> Vec<&str> {
    let bytes = list.as_bytes();
    let (mut depth, mut start, mut quoted, mut escaped) = (0_i32, 0, false, false);
    let mut parts = Vec::new();
    for (index, &byte) in bytes.iter().enumerate() {
        if !outside_string(byte, &mut quoted, &mut escaped) {
            continue;
        }
        match byte {
            b'(' | b'[' | b'{' | b'<' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b'>' if index == 0 || bytes[index - 1] != b'=' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(&list[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&list[start..]);
    parts
}

/// A part's leading identifier (past a `...`) and the text after it.
fn leading_identifier(part: &str) -> Option<(&str, &str)> {
    let part = part.trim_start();
    let part = part.strip_prefix("...").unwrap_or(part);
    let end = part
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
        .unwrap_or(part.len());
    if end == 0 || part.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((&part[..end], &part[end..]))
}

/// The names a parameter list binds: each part's leading identifier where a `?`, `:`, `=` or the
/// part's end follows it. The facade methods' `this: FacadeHost` is TypeScript's `this` parameter,
/// no binding.
fn parameter_bindings(list: &str) -> Vec<&str> {
    top_level_parts(list)
        .into_iter()
        .filter(|part| part.trim() != "this: FacadeHost")
        .filter_map(|part| {
            let (name, rest) = leading_identifier(part)?;
            let rest = rest.trim_start();
            (rest.is_empty() || rest.starts_with(['?', ':', '='])).then_some(name)
        })
        .collect()
}

/// The names an object destructure binds: `field: binding` binds the name after the colon, any
/// other entry its leading identifier.
fn destructure_bindings(list: &str) -> Vec<&str> {
    top_level_parts(list)
        .into_iter()
        .filter_map(|part| {
            let (name, rest) = leading_identifier(part)?;
            match rest.trim_start().strip_prefix(':') {
                Some(renamed) => leading_identifier(renamed).map(|(binding, _)| binding),
                None => Some(name),
            }
        })
        .collect()
}

#[test]
fn generated_typescript_binds_no_javascript_reserved_word() {
    let outputs =
        oneiron_sdk_generator::outputs(&repo()).expect("the generator runs on the repository");
    let text_of = |path: &str| {
        outputs
            .get(path)
            .unwrap_or_else(|| panic!("{path} is an output"))
    };
    let mut offenders = Vec::new();
    // A binding must not be a reserved word; a callable member of an interface or type literal
    // must not be `new`, which there opens a construct signature.
    let mut check = |path: &str, line: usize, form: &str, name: &str| {
        let bad = if form == CALLABLE_MEMBER {
            name == "new"
        } else {
            JS_RESERVED_WORDS.contains(&name)
        };
        if bad {
            offenders.push(format!("{path}:{line} {form} {name}"));
        }
    };

    // facade-verbs.ts: a namespace member `name: (params): T => ...` (or `Object.assign((params)`),
    // a top-level method `name(this: FacadeHost, params): T { ... }`, and a JSON-wire body's
    // `const { fields, ...rest } = request`.
    let member =
        regex::Regex::new(r"^\s*[A-Za-z_$][\w$]*(?:: (?:Object\.assign\()?)?\(").expect("regex");
    let (mut parameter_lists, mut destructures) = (0, 0);
    for (index, line) in text_of(FACADE_VERBS).lines().enumerate() {
        if let Some(found) = member.find(line) {
            let list = enclosed(line, found.end() - 1)
                .unwrap_or_else(|| panic!("{FACADE_VERBS}:{}: an unclosed list", index + 1));
            parameter_lists += 1;
            for name in parameter_bindings(list) {
                check(FACADE_VERBS, index + 1, "parameter", name);
            }
        }
        for (at, _) in line.match_indices("const { ") {
            let list = enclosed(line, at + "const ".len())
                .unwrap_or_else(|| panic!("{FACADE_VERBS}:{}: an unclosed destructure", index + 1));
            destructures += 1;
            for name in destructure_bindings(list) {
                check(FACADE_VERBS, index + 1, "destructured", name);
            }
        }
    }
    // One member per facade row, and the JSON-wire rows with input fields (vault.kv.put,
    // vault.kv.namespaces, vault.kv.search): an empty scan means the patterns no longer match.
    assert!(
        parameter_lists > 100,
        "{FACADE_VERBS}: only {parameter_lists} parameter lists found"
    );
    assert!(
        destructures > 0,
        "{FACADE_VERBS}: no `const {{` destructure found"
    );

    // native-verbs.ts: `name(params): T`, one line per facade row inside `NativeAgentVerbs`.
    let native = text_of(NATIVE_VERBS);
    let open = "export interface NativeAgentVerbs {\n";
    let body = &native[native.find(open).expect("the NativeAgentVerbs interface") + open.len()..];
    let body = &body[..body.find("\n}").expect("its close")];
    let signature = regex::Regex::new(r"^[A-Za-z_$][\w$]*\(").expect("regex");
    let mut signatures = 0;
    for (index, line) in body.lines().enumerate() {
        let Some(found) = signature.find(line) else {
            continue;
        };
        let list = enclosed(line, found.end() - 1).unwrap_or_else(|| {
            panic!(
                "{NATIVE_VERBS}: interface line {}: an unclosed list",
                index + 1
            )
        });
        signatures += 1;
        check(
            NATIVE_VERBS,
            index + 1,
            CALLABLE_MEMBER,
            &line[..found.end() - 1],
        );
        for name in parameter_bindings(list) {
            check(NATIVE_VERBS, index + 1, "parameter", name);
        }
    }
    assert!(
        signatures > 100,
        "{NATIVE_VERBS}: only {signatures} signatures found"
    );

    // The catalog fragment: `declare const|function|namespace <root>` and, inside a namespace,
    // `const|function|namespace <member>`; members of a constant's type are not bindings.
    let declaration =
        regex::Regex::new(r"^\s*(?:declare\s+)?(?:const|function|namespace)\s+([A-Za-z_$][\w$]*)")
            .expect("regex");
    let callable = regex::Regex::new(r"^\s*([A-Za-z_$][\w$]*)\(").expect("regex");
    let mut declarations = 0;
    for (index, line) in text_of(CATALOG_FRAGMENT).lines().enumerate() {
        if let Some(captures) = declaration.captures(line) {
            declarations += 1;
            check(CATALOG_FRAGMENT, index + 1, "declaration", &captures[1]);
        }
        if let Some(captures) = callable.captures(line) {
            check(CATALOG_FRAGMENT, index + 1, CALLABLE_MEMBER, &captures[1]);
        }
    }
    // At least the type namespace `Sdk`, the `self` namespace and the `vault` root.
    assert!(
        declarations > 2,
        "{CATALOG_FRAGMENT}: only {declarations} declarations found"
    );

    assert!(
        offenders.is_empty(),
        "the generated TypeScript binds a JavaScript reserved word (it does not parse): {}",
        offenders.join("; ")
    );
}

#[test]
fn the_scan_reads_each_binding_form() {
    // The scan's own pins, so a green whole-table run means the forms were read.
    let list = [
        "this: FacadeHost",
        "input: Facade.X = {}",
        "limit?: number",
        r#"opts: { a: [1, "x,)"], b: Map<string, number> } = {}"#,
        "run: (at: number) => void",
        "delete_ = 2",
        "...args: [spec: A] | [who: B, what: C]",
    ]
    .join(", ");
    assert_eq!(
        parameter_bindings(&list),
        ["input", "limit", "opts", "run", "delete_", "args"]
    );
    assert_eq!(
        parameter_bindings("default: string, newJson: string"),
        ["default", "newJson"]
    );
    assert_eq!(
        destructure_bindings(
            r#" requestId, namespacePrefix = [], default: default_ = {"a": 1}, ...rest "#
        ),
        ["requestId", "namespacePrefix", "default_", "rest"]
    );
    let line = concat!(
        "      put: (request: Facade.KvPut): Facade.Out => host[facadeCall](() => ",
        "{ const { requestId, ...rest } = request; })"
    );
    let open = line.find('(').expect("a list");
    assert_eq!(enclosed(line, open), Some("request: Facade.KvPut"));
    let at = line.find("const { ").expect("a destructure") + "const ".len();
    assert_eq!(enclosed(line, at), Some(" requestId, ...rest "));
    assert_eq!(enclosed("(a, (b)", 0), None);
}
