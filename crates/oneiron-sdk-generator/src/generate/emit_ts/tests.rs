use super::*;

// python3 -c "import re; print(re.findall(r'\b([A-Z]\w*)\b', T))" on nelly (3.14.7), T below.
#[test]
fn capitalized_words_are_pythons_findall() {
    let text = "Foo bar(Baz) aQux _Q x.Y Z9_a é Éa Ab\u{301}c \u{301}Bd ①Ce X";
    assert_eq!(
        capitalized_words(text).into_iter().collect::<Vec<_>>(),
        ["Ab", "Baz", "Bd", "Foo", "X", "Y", "Z9_a"]
    );
}

// python3 -c "print(repr('Option<'[7:-1]), repr('Option<T>'[7:-1]), repr('Option<é>'[7:-1]))"
#[test]
fn option_inner_drops_the_prefix_and_the_last_code_point() {
    assert_eq!(option_inner("Option<"), "");
    assert_eq!(option_inner("Option<T>"), "T");
    assert_eq!(option_inner("Option<é>"), "é");
    assert_eq!(option_inner("Option<a::B>"), "a::B");
    assert_eq!(option_inner("Option<ab"), "a");
}

// python3 -c "print(err(lambda: 5 + 'a'), err(lambda: [1] + 'a'), err(lambda: 'a' + None), ...)"
#[test]
fn concatenation_refusals_are_pythons() {
    fn text(result: Result<&str, GenerateError>) -> Result<String, String> {
        result.map(str::to_owned).map_err(|error| error.to_string())
    }
    assert_eq!(
        text(concat_left(&Value::Int(5))),
        Err("TypeError: unsupported operand type(s) for +: 'int' and 'str'".to_owned())
    );
    assert_eq!(
        text(concat_left(&Value::List(Vec::new()))),
        Err(r#"TypeError: can only concatenate list (not "str") to list"#.to_owned())
    );
    assert_eq!(
        text(concat_left(&Value::None)),
        Err("TypeError: unsupported operand type(s) for +: 'NoneType' and 'str'".to_owned())
    );
    assert_eq!(
        text(concat(&Value::None)),
        Err(r#"TypeError: can only concatenate str (not "NoneType") to str"#.to_owned())
    );
    assert_eq!(
        text(concat(&Value::Dict(Dict::new()))),
        Err(r#"TypeError: can only concatenate str (not "dict") to str"#.to_owned())
    );
    assert_eq!(
        text(concat_left(&Value::Str("a".to_owned()))),
        Ok("a".to_owned())
    );
}

// python3 -c "import json; print(json.dumps(C[K]))" on nelly (3.14.7), or the exception's last line.
#[test]
fn subscripts_are_pythons() {
    let parse = |text: &str| crate::py::json::loads(text).expect("a JSON value");
    let cases = [
        (
            "[0.0, 1.0]",
            "1.0",
            "TypeError: list indices must be integers or slices, not float",
        ),
        (
            "[[], 1]",
            "[]",
            "TypeError: list indices must be integers or slices, not list",
        ),
        (
            "[{}, 1]",
            "{}",
            "TypeError: list indices must be integers or slices, not dict",
        ),
        (
            "[null]",
            "null",
            "TypeError: list indices must be integers or slices, not NoneType",
        ),
        ("[5]", "5", "IndexError: list index out of range"),
        ("[true]", "true", "IndexError: list index out of range"),
        ("[1, 2]", "-1", "2"),
        ("[1, 2]", "false", "1"),
        (
            "[NaN]",
            "NaN",
            "TypeError: list indices must be integers or slices, not float",
        ),
        (r#"{"a": 1}"#, r#""a""#, "1"),
        (
            r#""abc""#,
            r#""b""#,
            "TypeError: string indices must be integers, not 'str'",
        ),
    ];
    for (container, key, expected) in cases {
        let got = match subscript(&parse(container), &parse(key)) {
            Ok(value) => json(&value),
            Err(error) => error.to_string(),
        };
        assert_eq!(got, expected, "{container}[{key}]");
    }
}

// python3 -c "import json; print(json.loads(K) in json.loads(C))" on nelly (3.14.7): json.loads returns one NaN
// object, and `in` compares by identity first.
#[test]
fn membership_is_pythons() {
    let parse = |text: &str| crate::py::json::loads(text).expect("a JSON value");
    for (container, key, expected) in [
        ("[NaN]", "NaN", true),
        ("[[NaN]]", "[NaN]", true),
        (r#"[{"a": NaN}]"#, r#"{"a": NaN}"#, true),
        ("[1.0]", "NaN", false),
        ("[1, 2]", "true", true),
        ("[0.0, 1.0]", "1", true),
    ] {
        let found = contains(&parse(container), &parse(key)).expect("a list");
        assert_eq!(found, expected, "{key} in {container}");
    }
}
