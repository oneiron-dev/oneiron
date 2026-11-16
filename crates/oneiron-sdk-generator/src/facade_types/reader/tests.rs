use super::*;

// Every expected value is what the Python generator printed (main, Python 3.14.7 on nelly) for the call in the
// comment above it; `f.` prefixes the generator's own functions.
// Python's offsets count code points; the port's are UTF-8 bytes, so each is converted with
// len(t[:i].encode()).

#[test]
fn skip_reads_strings_comments_and_char_literals() {
    // f._skip(t, 0) for each t (then len(t[:i].encode()))
    assert_eq!(skip(r#""a\"b" x"#, 0), 6);
    assert_eq!(skip("\"unclosed", 0), 9);
    assert_eq!(skip("// c\nx", 0), 4);
    assert_eq!(skip("/* a /* b */ c */x", 0), 17);
    // An unclosed block comment runs to the end (a Python branch no corpus run reaches): 12, 4, 3.
    assert_eq!(skip("/* a /* b */", 0), 12);
    assert_eq!(skip("/* …", 0), 6);
    assert_eq!(skip("/*/", 0), 3);
    assert_eq!(skip("'…' x", 0), 5);
    assert_eq!(skip("'a x", 0), 1);
    assert_eq!(skip(r"'\n' x", 0), 4);
    assert_eq!(skip(r##"r#"a"# x"##, 0), 6);
    assert_eq!(skip("br\"a\" x", 0), 5);
    // f._skip('xr"a"', 1) == 1: a word character before `r` is no raw string
    assert_eq!(skip("xr\"a\"", 1), 1);
}

#[test]
fn close_of_counts_brackets_without_kinds() {
    // f.close_of('(a]b)', 0) == 3; f.close_of('{ "}" }x', 0) == 7; f.close_of('(é', 0) == 2 code points
    assert_eq!(close_of("(a]b)", 0), 3);
    assert_eq!(close_of("{ \"}\" }x", 0), 7);
    assert_eq!(close_of("(é", 0), 3);
}

#[test]
fn split_top_and_leading_attrs() {
    // f.split_top('a<b, c>, d -> e, (f, g),') == ['a<b, c>', 'd -> e', '(f, g)']
    assert_eq!(
        split_top("a<b, c>, d -> e, (f, g),", b','),
        vec!["a<b, c>", "d -> e", "(f, g)"]
    );
    // f.leading_attrs(' #[a] #[b(c)] x: u8 ') == ('#[a] #[b(c)]', 'x: u8')
    assert_eq!(
        leading_attrs(" #[a] #[b(c)] x: u8 "),
        ("#[a] #[b(c)]".to_owned(), "x: u8")
    );
}

#[test]
fn attr_args_merges_and_derives_take_last_segments() {
    // f.attr_args('#[serde(rename = "a", default, with = crate::x, rename_all(serialize = "camelCase"), tag)]
    //   #[serde(default = "f")]', 'serde')
    // == {'rename': 'a', 'default': 'f', 'with': 'crate::x', 'rename_all': {'serialize': 'camelCase'}, 'tag': True}
    let attrs = r#"#[serde(rename = "a", default, with = crate::x, rename_all(serialize = "camelCase"), tag)] #[serde(default = "f")]"#;
    let found = attr_args(attrs, "serde").expect("attributes read");
    assert_eq!(
        found.keys().collect::<Vec<_>>(),
        ["rename", "default", "with", "rename_all", "tag"]
    );
    assert_eq!(found["default"].as_str(), Some("f"));
    assert_eq!(found["with"].as_str(), Some("crate::x"));
    assert_eq!(
        found["rename_all"]
            .as_dict()
            .and_then(|d| d.get("serialize"))
            .and_then(Value::as_str),
        Some("camelCase")
    );
    assert!(found["tag"].is_true());
    // sorted(f.derives('#[derive(Debug, serde::Serialize)] #[cfg_attr(x, derive(Deserialize))]'))
    // == ['Debug', 'Deserialize', 'Serialize']
    let mut names: Vec<String> =
        derives("#[derive(Debug, serde::Serialize)] #[cfg_attr(x, derive(Deserialize))]")
            .into_iter()
            .collect();
    names.sort();
    assert_eq!(names, ["Debug", "Deserialize", "Serialize"]);
}

#[test]
fn rename_follows_serde_cases() {
    // f.rename(name, case, variant) for each row
    let cases: &[(&str, Option<&str>, bool, &str)] = &[
        ("HTTPServer", Some("snake_case"), true, "h_t_t_p_server"),
        ("field_name", Some("camelCase"), false, "fieldName"),
        ("MyVariant", Some("kebab-case"), true, "my-variant"),
        ("x_y", Some("PascalCase"), false, "XY"),
        ("Ab", Some("SCREAMING_SNAKE_CASE"), true, "AB"),
        ("ab_c", Some("lowercase"), false, "ab_c"),
        ("ÀbÇ", Some("lowercase"), true, "àbç"),
        ("a", None, true, "a"),
        ("a_b", Some("unknown"), false, "a_b"),
    ];
    for (name, case, variant, expected) in cases {
        let case = case.map(|case| Value::Str(case.to_owned()));
        assert_eq!(
            rename(name, case.as_ref(), *variant),
            *expected,
            "{name} {case:?}"
        );
    }
}

#[test]
fn parse_type_trees() {
    let path = |segments: &[&str], args: Vec<Ast>| {
        Ast::Path(segments.iter().map(|s| (*s).to_owned()).collect(), args)
    };
    // f.parse_type('Vec<Option<crate::a::B>>')
    // == ('path', ['Vec'], [('path', ['Option'], [('path', ['crate', 'a', 'B'], [])])])
    assert_eq!(
        parse_type("Vec<Option<crate::a::B>>").ok(),
        Some(path(
            &["Vec"],
            vec![path(&["Option"], vec![path(&["crate", "a", "B"], vec![])])]
        ))
    );
    // f.parse_type("&'a mut [u8; 16]") == ('ref', ('array', ('path', ['u8'], [])))
    assert_eq!(
        parse_type("&'a mut [u8; 16]").ok(),
        Some(Ast::Ref(Box::new(Ast::Array(Box::new(path(
            &["u8"],
            vec![]
        ))))))
    );
    // f.parse_type('u8 u8') == ('raw', 'u8 u8'): leftover tokens
    assert_eq!(parse_type("u8 u8").ok(), Some(Ast::Raw("u8 u8".to_owned())));
    // f.parse_type('Foo<A>::Bar') == ('path', ['Foo', 'Bar'], [('path', ['A'], [])])
    assert_eq!(
        parse_type("Foo<A>::Bar").ok(),
        Some(path(&["Foo", "Bar"], vec![path(&["A"], vec![])]))
    );
    // f.parse_type('::') raises IndexError: list index out of range
    assert_eq!(
        parse_type("::")
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("IndexError: list index out of range")
    );
}

/// The outcome of `run` on a thread with the binary's 256 MiB stack (a test thread has 2 MiB).
fn on_big_stack<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(run)
        .expect("a test thread")
        .join()
        .expect("the test thread returns")
}

#[test]
fn nesting_past_the_recursion_limit_is_python_recursion_error() {
    // The Python generator's f.parse_type("&" * n + "u8"): n = 19990 parses, n = 20001 raises
    // RecursionError: maximum recursion depth exceeded (the exact cut-off depends on the frames below it and is
    // not part of the contract; the outcome past it is).
    let outcomes = on_big_stack(|| {
        let message = |result: Result<Ast, GenerateError>| result.err().map(|e| e.to_string());
        (
            message(parse_type(&format!("{}u8", "&".repeat(19_990)))),
            message(parse_type(&format!("{}u8", "&".repeat(20_001)))),
            message(parse_type(&format!(
                "{}u8{}",
                "Vec<".repeat(10_001),
                ">".repeat(10_001)
            ))),
        )
    });
    let refused = Some("RecursionError: maximum recursion depth exceeded".to_owned());
    assert_eq!(outcomes, (None, refused.clone(), refused.clone()));
    // attr_args recurses once per nested `key(...)`: at the limit the next level is refused.
    let nested = "serde(x(default))";
    assert!(attr_args_at_depth(nested, "serde", RECURSION_LIMIT - 2).is_ok());
    assert_eq!(
        attr_args_at_depth(nested, "serde", RECURSION_LIMIT - 1)
            .err()
            .map(|e| e.to_string()),
        refused
    );
}
