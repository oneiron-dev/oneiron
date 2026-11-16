use super::*;

// Each row: python3 -c "import re; print(re.sub(r'(?<!^)(?=[A-Z])', '_', NAME))" on nelly (Python 3.14.7).
#[test]
fn underscore_before_capitals_matches_python() {
    let cases: &[(&str, &str)] = &[
        ("HTTPServer", "H_T_T_P_Server"),
        ("agentVerb", "agent_Verb"),
        ("A", "A"),
        ("", ""),
        ("aB", "a_B"),
        ("ABC", "A_B_C"),
        ("snake_case", "snake_case"),
        ("\u{c9}a", "\u{c9}a"),
        ("a\u{c9}B", "a\u{c9}_B"),
        ("X1Y", "X1_Y"),
        ("_A", "__A"),
    ];
    for (input, expected) in cases {
        assert_eq!(
            sub_underscore_before_capitals(input),
            *expected,
            "{input:?}"
        );
    }
}

// Each row: python3 -c "import re; print(re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', KEY))".
#[test]
fn underscore_at_case_rise_matches_python() {
    let cases: &[(&str, &str)] = &[
        ("fooBar", "foo_Bar"),
        ("foo1Bar", "foo1_Bar"),
        ("FOOBar", "FOOBar"),
        ("fooBAR", "foo_BAR"),
        ("a_B", "a_B"),
        ("a\u{c9}", "a\u{c9}"),
        ("\u{e9}B", "\u{e9}B"),
        ("", ""),
        ("A", "A"),
        ("x9Y", "x9_Y"),
        ("aBcD", "a_Bc_D"),
    ];
    for (input, expected) in cases {
        assert_eq!(sub_underscore_at_case_rise(input), *expected, "{input:?}");
    }
}

// Each row: python3 -c "import re; print(re.findall(r'(?<![\w.])(\w+)\(', BODY))".
#[test]
fn called_words_match_python() {
    let cases: &[(&str, &[&str])] = &[
        (
            "foo(bar(x)) .baz(y) a.b(c) obj.method() fn2 (x) _u8(z)",
            &["foo", "bar", "_u8"],
        ),
        ("\u{e9}(x)", &["\u{e9}"]),
        ("x.\u{e9}(y)", &[]),
        ("\u{b2}(a)", &["\u{b2}"]),
        ("abc", &[]),
        ("(x)", &[]),
        ("a(b(c(d)))", &["a", "b", "c"]),
        ("isRecord(x) && !isText(y)", &["isRecord", "isText"]),
        ("\"q\"(x)", &[]),
        ("a\u{203f}b(x)", &["b"]),
        ("ab(x)", &["ab"]),
        ("x(", &["x"]),
        ("1(2)", &["1"]),
    ];
    for (input, expected) in cases {
        assert_eq!(findall_called_words(input), *expected, "{input:?}");
    }
}

// Each row: python3 -c "import re; print(re.search(r'(?<![\w\"])invalid(?![\w\"])', BODY) is not None)".
#[test]
fn bare_invalid_matches_python() {
    let cases: &[(&str, bool)] = &[
        ("invalid", true),
        ("invalid()", true),
        ("let x = invalid;", true),
        ("\"invalid\"", false),
        ("invalids", false),
        ("_invalid", false),
        ("xinvalid", false),
        ("invalid_x", false),
        ("(invalid)", true),
        ("Err(invalid())", true),
        ("\u{e9} invalid", true),
        ("invalid\u{e9}", false),
        ("invalid\u{b2}", false),
        ("ainvalid", false),
        ("", false),
        ("invalid\"", false),
        ("x\"invalid", false),
        ("invalidinvalid invalid", true),
    ];
    for (input, expected) in cases {
        assert_eq!(search_bare_invalid(input), *expected, "{input:?}");
    }
}

// Each row: python3 -c "import re; print(re.sub(r'&\binput\b(?!\.)', VALUE, CHECKS)); print(re.sub(r'\binput\b', VALUE, CHECKS))".
#[test]
fn input_substitutions_match_python() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "input.validate()?; check(&input)?;",
            "text",
            "input.validate()?; check(text)?;",
            "text.validate()?; check(&text)?;",
        ),
        ("&input", "spec", "spec", "&spec"),
        (
            "&input.x &input_x &inputs &input",
            "v",
            "&input.x &input_x &inputs v",
            "&v.x &input_x &inputs &v",
        ),
        (
            "(input) input_x xinput input",
            "t",
            "(input) input_x xinput input",
            "(t) input_x xinput t",
        ),
        ("&input, &input", "a", "a, a", "&a, &a"),
        (
            "\u{e9}input input\u{b2} input\u{203f} input",
            "q",
            "\u{e9}input input\u{b2} input\u{203f} input",
            "\u{e9}input input\u{b2} q\u{203f} q",
        ),
        ("", "x", "", ""),
        ("&&input", "y", "&y", "&&y"),
    ];
    for (checks, value, borrow, word) in cases {
        assert_eq!(
            sub_whole_input_borrow(checks, value).expect("a template"),
            *borrow,
            "{checks:?}"
        );
        assert_eq!(
            sub_input_word(checks, value).expect("a template"),
            *word,
            "{checks:?}"
        );
    }
}

// Each row: python3 -c "import re; print(re.sub(r'&\binput\b(?!\.)', TEMPLATE, 'a &input b'))", or the
// traceback's last line.
#[test]
fn templates_match_python() {
    let cases: &[(&str, &str)] = &[
        ("v", "OK a v b"),
        ("\\\\", "OK a \\ b"),
        ("\\n", "OK a \u{a} b"),
        ("\\q", "ERR re.PatternError: bad escape \\q at position 0"),
        (
            "\\",
            "ERR re.PatternError: bad escape (end of pattern) at position 0",
        ),
        (
            "x\\",
            "ERR re.PatternError: bad escape (end of pattern) at position 1",
        ),
        ("\\g<0>", "OK a &input b"),
        ("[\\g<0>]", "OK a [&input] b"),
        (
            "\\g<1>",
            "ERR re.PatternError: invalid group reference 1 at position 3",
        ),
        ("\\g<a>", "ERR IndexError: unknown group name 'a'"),
        (
            "\\g<1a>",
            "ERR re.PatternError: bad character in group name '1a' at position 3",
        ),
        (
            "\\g<>",
            "ERR re.PatternError: missing group name at position 3",
        ),
        (
            "\\g<0",
            "ERR re.PatternError: missing >, unterminated name at position 3",
        ),
        ("\\g", "ERR re.PatternError: missing < at position 2"),
        ("\\g0", "ERR re.PatternError: missing < at position 2"),
        (
            "\\1",
            "ERR re.PatternError: invalid group reference 1 at position 1",
        ),
        (
            "\\12",
            "ERR re.PatternError: invalid group reference 12 at position 1",
        ),
        ("\\0", "OK a \u{0} b"),
        ("\\07", "OK a \u{7} b"),
        ("\\077", "OK a ? b"),
        ("\\08", "OK a \u{0}8 b"),
        ("\\177", "OK a \u{7f} b"),
        (
            "\\400",
            "ERR re.PatternError: octal escape value \\400 outside of range 0-0o377 at position 0",
        ),
        ("\\377", "OK a \u{ff} b"),
        ("\\&", "OK a \\& b"),
        ("\\.", "OK a \\. b"),
        (
            "\\a\\b\\f\\r\\t\\v",
            "OK a \u{7}\u{8}\u{c}\u{d}\u{9}\u{b} b",
        ),
        (
            "a\u{a}b\\q",
            "ERR re.PatternError: bad escape \\q at position 3 (line 2, column 2)",
        ),
        ("\\g<00>", "OK a &input b"),
        (
            "\\g<\u{ff11}>",
            "ERR re.PatternError: bad character in group name '\u{ff11}' at position 3",
        ),
        ("\\g<\u{e9}>", "ERR IndexError: unknown group name '\u{e9}'"),
        ("\\\u{e9}", "OK a \\\u{e9} b"),
        (
            "\\q\\",
            "ERR re.PatternError: bad escape (end of pattern) at position 2",
        ),
        (
            "\\g<0\\>>",
            "ERR re.PatternError: bad character in group name '0\\\\>' at position 3",
        ),
        (
            "x\u{a}y\\1",
            "ERR re.PatternError: invalid group reference 1 at position 4 (line 2, column 3)",
        ),
        (
            "\\9",
            "ERR re.PatternError: invalid group reference 9 at position 1",
        ),
        (
            "\\19",
            "ERR re.PatternError: invalid group reference 19 at position 1",
        ),
        (
            "\\g<99999999999>",
            "ERR re.PatternError: invalid group reference 99999999999 at position 3",
        ),
        (
            "\\g<a b>",
            "ERR re.PatternError: bad character in group name 'a b' at position 3",
        ),
    ];
    for (template, expected) in cases {
        let got = match sub_whole_input_borrow("a &input b", template) {
            Ok(text) => format!("OK {text}"),
            Err(error) => format!("ERR {error}"),
        };
        assert_eq!(got, *expected, "{template:?}");
    }
}

// Each row: python3 -c "import re; print(re.fullmatch(PATTERN, TEXT) is not None)"; the Rust side translates the
// pattern.
#[test]
fn translated_classes_match_python() {
    let cases: &[(&str, &str, bool)] = &[
        ("\\w+", "abc", true),
        ("\\w+", "a\u{b2}", true),
        ("\\w+", "\u{e1}", true),
        ("\\w+", "a\u{203f}", false),
        ("[\\w.]+", "a.b", true),
        ("[^\\w]", "\u{e9}", false),
        ("[^\\w]", "\u{203f}", true),
        ("\\s+", "\u{1c}\u{1d}", true),
        ("\\s", "\u{180e}", false),
        ("\\S+", "ab", true),
        ("\\W", "\u{b2}", false),
        ("[\\s,]+", " ,\u{1f}", true),
        ("\\d+", "\u{661}\u{662}", true),
        ("\\d", "\u{b2}", false),
        ("[A-Za-z_]\\w*", "ZWNJ\u{200c}", false),
        ("[\\W]", "_", false),
        ("[^\\s]+", "a b", false),
    ];
    for (pattern, text, expected) in cases {
        assert_eq!(
            compile_fullmatch(pattern).is_match(text),
            *expected,
            "{pattern:?} {text:?}"
        );
    }
    assert_eq!(translate(r"[^\w:]"), format!("[^{WORD_CLASS}:]"));
    assert_eq!(translate(r"(?m)a\.b\d$"), r"(?m)a\.b\d$");
    assert_eq!(translate(r"[[&]"), r"[\[\&]");
    assert_eq!(translate(r"\<a\>[\<]"), "<a>[<]");
}

// What `translate` refuses: escapes of no ASCII character or Python class, patterns that can match empty (Python's
// finditer gives (0, 0), (0, 1), (1, 1) for `\b|a` in "a", and (0, 1), (1, 1) for `\w*\b`), and syntax the subset
// does not take.
#[test]
fn syntax_violations_are_refused() {
    let escape = "an escape that names no ASCII character";
    let cases: &[(&str, &str)] = &[
        (r"a\b[\u0300-\u036f]", escape),
        (r"\b\xB2", escape),
        (r"a\b\u0301", escape),
        (r"\b\x{b2}", escape),
        (r"\p{Mn}\b", escape),
        (r"\b\N{DIGIT TWO}", escape),
        (r"(a)\1\b", escape),
        (r"\w*\b", "a pattern that can match empty"),
        (r"\b|a", "a pattern that can match empty"),
        (r"\b", "a pattern that can match empty"),
        (r"(?m)^", "a pattern that can match empty"),
        (r"(?:a|)*\b", "a quantifier of a part that can match empty"),
        (r"\b*a", "a quantifier of a part that can match empty"),
        (r"a\b$", "`$` without `(?m)`"),
        (r"(?i)a\b", "a group other than"),
        (r"(?=a)a\b", "a group other than"),
        (r"a(?m)\b", "a group other than"),
        (r"(?ms:a)\b", "flags other than"),
        (r"a{,2}\b", "a `{` that is not"),
        (r"a{3,2}\b", "a `{` that is not"),
        (r"a{2\b", "a `{` that is not"),
        (r"a++\b", "a quantifier of a quantifier"),
        (r"*a", "a quantifier with nothing to repeat"),
        (r"a]\b", "an unescaped `]`"),
        (r"[+--]a", "`--` in a class"),
        (r"(a\b", "an unclosed group"),
        (r"a)\b", "a `)` that closes no group"),
        (r"[a\b", "an unclosed class"),
        (r"(?P<1a>a)", "a group name"),
    ];
    for (pattern, reason) in cases {
        let why = syntax_violation(pattern).unwrap_or_default();
        assert!(why.starts_with(reason), "{pattern:?}: {why:?}");
    }
    for pattern in [
        r"(?ms)^a$",
        r"(?P<word>\w+)\b",
        r"[]a]\b",
        r"a{2}b{1,}c{0,3}?\b",
        r"\x41\b\.\-",
    ] {
        assert_eq!(syntax_violation(pattern), None, "{pattern:?}");
    }
}

#[test]
#[should_panic(expected = "regex does not share with Python")]
fn translate_refuses_boundaries() {
    let _ = translate(r"\bfn\b");
}

#[test]
#[should_panic(expected = "py::re does not take `$` without `(?m)`")]
fn compile_refuses_outside_the_syntax() {
    let _ = compile(r"a$");
}

#[test]
#[should_panic(expected = "py::re does not take a pattern that can match empty")]
fn compile_fullmatch_refuses_an_empty_match() {
    let _ = compile_fullmatch(r"\w*");
}

/// The literal at `rest`'s start (white space skipped): a raw string (`r"..."`, `r#"..."#`) or a plain one,
/// unescaped; `None` for anything else (a name, an expression).
fn literal_at(rest: &str) -> Option<String> {
    let rest = rest.trim_start();
    if rest.starts_with("r\"") || rest.starts_with("r#") {
        let raw = &rest[1..];
        let hashes = raw.len() - raw.trim_start_matches('#').len();
        let body = raw[hashes..].strip_prefix('"')?;
        let end = body.find(&format!("\"{}", "#".repeat(hashes)))?;
        return Some(body[..end].to_owned());
    }
    let mut chars = rest.strip_prefix('"')?.chars();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().skip(1).take_while(|&c| c != '}').collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                other => out.push(other),
            },
            _ => out.push(c),
        }
    }
    None
}

/// Every Python pattern the generator builds, read from the crate's source (this file's tests aside, which build
/// refused patterns on purpose): each literal passed to `compile`, `compile_fullmatch` or `translate` outside a
/// comment, or the `const` such a call names. Each is built as its
/// call builds it, so a pattern outside the subset fails here, naming its file. The one pattern made at run time
/// is `the_run_time_mod_pattern_is_taken_for_any_name`'s.
#[test]
fn every_generator_pattern_is_in_the_subset() {
    const CALLS: [&str; 3] = ["compile(", "compile_fullmatch(", "translate("];
    let mut files = Vec::new();
    let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("a source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && !path.ends_with("py/re.rs")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut built = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file");
        for call in CALLS {
            for (at, _) in text.match_indices(call) {
                let before = text[..at].chars().next_back();
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '.') {
                    continue;
                }
                let line_start = text[..at].rfind('\n').map_or(0, |newline| newline + 1);
                if text[line_start..at].trim_start().starts_with("//") {
                    continue;
                }
                let rest = &text[at + call.len()..];
                let pattern = literal_at(rest).or_else(|| {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if name.is_empty() {
                        return None;
                    }
                    let declared = format!("const {name}: &str =");
                    let value = text.find(&declared)? + declared.len();
                    literal_at(&text[value..])
                });
                let Some(pattern) = pattern else { continue };
                let fullmatch = call.contains("fullmatch");
                let outcome = std::panic::catch_unwind(|| {
                    if fullmatch {
                        let _ = compile_fullmatch(&pattern);
                    } else {
                        let _ = compile(&pattern);
                    }
                });
                assert!(
                    outcome.is_ok(),
                    "{}: {call}{pattern:?}) is refused",
                    file.display()
                );
                built.push(pattern);
            }
        }
    }
    // Today's count (the reader, the index, the inventory, the rows, common, the emitters, uniffi, the catalog
    // fragment): a scan that finds fewer has lost its way.
    assert!(built.len() >= 42, "{} patterns: {built:#?}", built.len());
}

// rust_ir.rs: `(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+{re.escape(last)}\s*\{`, made at run time from a
// module name: no name makes `translate` refuse it (a non-ASCII literal is taken; `regex::escape` writes only
// escapes of ASCII punctuation).
#[test]
fn the_run_time_mod_pattern_is_taken_for_any_name() {
    for name in [
        "walk",
        "r#type",
        "modul\u{e9}",
        "a-b~c#d&e.f",
        "\u{4e00}",
        "",
    ] {
        let pattern = format!(
            r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+{}\s*\{{",
            regex::escape(name)
        );
        assert!(Regex::new(&translate(&pattern)).is_ok(), "{name:?}");
    }
}

// python3 -c "import re; re.sub(r'\binput\b', r'\g<' + '0' * 4301 + '>', 'input')": the traceback's last line;
// with 4,300 zeros it prints `input`.
#[test]
fn template_group_numbers_keep_python_s_digit_limit() {
    let error =
        sub_input_word("input", &format!(r"\g<{}>", "0".repeat(4301))).expect_err("digit limit");
    assert_eq!(
        error.to_string(),
        "ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use \
         sys.set_int_max_str_digits() to increase the limit"
    );
    let error =
        sub_input_word("input", &format!(r"\g<{}>", "9".repeat(4301))).expect_err("digit limit");
    assert!(
        error
            .to_string()
            .starts_with("ValueError: Exceeds the limit")
    );
    assert_eq!(
        sub_input_word("input", &format!(r"\g<{}>", "0".repeat(4300))).expect("group 0"),
        "input"
    );
}
