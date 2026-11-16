use super::*;

// Each row: python3 -c "import json; print(json.loads(TEXT))" on nelly (Python 3.14.7), the decoded value's
// repr or the JSONDecodeError's str().
const LOADS_CASES: &[(&str, &str)] = &[
    ("", "ERR Expecting value: line 1 column 1 (char 0)"),
    (" ", "ERR Expecting value: line 1 column 2 (char 1)"),
    (
        "{",
        "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
    ),
    ("[", "ERR Expecting value: line 1 column 2 (char 1)"),
    (
        "{\"a\"",
        "ERR Expecting ':' delimiter: line 1 column 5 (char 4)",
    ),
    ("{\"a\":", "ERR Expecting value: line 1 column 6 (char 5)"),
    ("{\"a\": }", "ERR Expecting value: line 1 column 7 (char 6)"),
    (
        "{\"a\" 1}",
        "ERR Expecting ':' delimiter: line 1 column 6 (char 5)",
    ),
    (
        "{\"a\": 1",
        "ERR Expecting ',' delimiter: line 1 column 8 (char 7)",
    ),
    (
        "{\"a\": 1 \"b\": 2}",
        "ERR Expecting ',' delimiter: line 1 column 9 (char 8)",
    ),
    (
        "{\"a\": 1,}",
        "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
    ),
    (
        "[1,]",
        "ERR Illegal trailing comma before end of array: line 1 column 3 (char 2)",
    ),
    (
        "[1 2]",
        "ERR Expecting ',' delimiter: line 1 column 4 (char 3)",
    ),
    (
        "[1",
        "ERR Expecting ',' delimiter: line 1 column 3 (char 2)",
    ),
    (
        "{1: 2}",
        "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
    ),
    (
        "{\"a\": 1,  }",
        "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
    ),
    (
        "[1,  ]",
        "ERR Illegal trailing comma before end of array: line 1 column 3 (char 2)",
    ),
    (
        "\"abc",
        "ERR Unterminated string starting at: line 1 column 1 (char 0)",
    ),
    (
        "\"a\\",
        "ERR Unterminated string starting at: line 1 column 1 (char 0)",
    ),
    ("\"a\\x\"", "ERR Invalid \\escape: line 1 column 3 (char 2)"),
    (
        "\"\\u12\"",
        "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
    ),
    (
        "\"\\u12",
        "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
    ),
    (
        "\"\\u123\"",
        "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
    ),
    (
        "\"\\u1234",
        "ERR Unterminated string starting at: line 1 column 1 (char 0)",
    ),
    (
        "\"\\uZZZZ\"",
        "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
    ),
    (
        "\"\\ud800\\uZZZZ\"",
        "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
    ),
    ("\"\\ud800\\udc00\"", "OK '\u{10000}'"),
    (
        "\"\\ud800\\udc00",
        "ERR Unterminated string starting at: line 1 column 1 (char 0)",
    ),
    (
        "\"\\ud800\\u",
        "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
    ),
    (
        "\"\\ud800\\x\"",
        "ERR Invalid \\escape: line 1 column 8 (char 7)",
    ),
    (
        "\"\\uDC00\\uZZZZ\"",
        "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
    ),
    (
        "\"a\u{1}b\"",
        "ERR Invalid control character at: line 1 column 3 (char 2)",
    ),
    (
        "\"a\u{a}b\"",
        "ERR Invalid control character at: line 1 column 3 (char 2)",
    ),
    ("\"\u{7f}\"", "OK '\\x7f'"),
    ("nul", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("null", "OK None"),
    ("nulll", "ERR Extra data: line 1 column 5 (char 4)"),
    ("tru", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("True", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("NaN", "OK nan"),
    ("Nan", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("Infinity", "OK inf"),
    ("-Infinity", "OK -inf"),
    ("-Inf", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("-", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("-a", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("01", "ERR Extra data: line 1 column 2 (char 1)"),
    ("1.", "ERR Extra data: line 1 column 2 (char 1)"),
    ("1.e5", "ERR Extra data: line 1 column 2 (char 1)"),
    ("1e", "ERR Extra data: line 1 column 2 (char 1)"),
    ("1e+", "ERR Extra data: line 1 column 2 (char 1)"),
    ("1E5", "OK 100000.0"),
    ("1e-7", "OK 1e-07"),
    ("-0", "OK 0"),
    ("-0.0", "OK -0.0"),
    ("1e999", "OK inf"),
    (".5", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("+1", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("{\"a\": 1}x", "ERR Extra data: line 1 column 9 (char 8)"),
    ("{\"a\": 1} ", "OK {'a': 1}"),
    (
        "{\"a\": 1}\u{a}\u{a} x",
        "ERR Extra data: line 3 column 2 (char 11)",
    ),
    (
        "\u{feff}{}",
        "ERR Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
    ),
    (
        "\u{a}\u{a}  {\"a\": [1, 2,\u{a}  ]}",
        "ERR Illegal trailing comma before end of array: line 3 column 14 (char 15)",
    ),
    (
        "{\"a\": 1,\u{a} \"b\"\u{a} 2}",
        "ERR Expecting ':' delimiter: line 3 column 2 (char 15)",
    ),
    ("{\"a\":1,\"b\":2,\"a\":3}", "OK {'a': 3, 'b': 2}"),
    (
        "[\u{a}\u{a}\u{a}  \"\\q\"]",
        "ERR Invalid \\escape: line 4 column 4 (char 7)",
    ),
    (
        "{\u{a}\"\u{e9}\": \"\\u00e9\u{1f600}\", \"x\": tru}",
        "ERR Expecting value: line 2 column 22 (char 23)",
    ),
    (
        "\"\u{9}\"",
        "ERR Invalid control character at: line 1 column 2 (char 1)",
    ),
    (
        "[1,\u{a}2,,]",
        "ERR Expecting value: line 2 column 3 (char 6)",
    ),
    ("{\"a\":1}{", "ERR Extra data: line 1 column 8 (char 7)"),
    ("[] []", "ERR Extra data: line 1 column 4 (char 3)"),
    ("123abc", "ERR Extra data: line 1 column 4 (char 3)"),
    ("1 2", "ERR Extra data: line 1 column 3 (char 2)"),
    ("nan", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("[NaN, Infinity, -Infinity]", "OK [nan, inf, -inf]"),
    (
        "{\"a\": {\"b\": [1, {\"c\": nul}]}}",
        "ERR Expecting value: line 1 column 23 (char 22)",
    ),
    ("[-]", "ERR Expecting value: line 1 column 2 (char 1)"),
    ("[-0]", "OK [0]"),
    (
        "\"\\/\\b\\f\\n\\r\\t\\\"\\\\\"",
        "OK '/\\x08\\x0c\\n\\r\\t\"\\\\'",
    ),
    ("\"\u{1f600}\"", "OK '\u{1f600}'"),
    ("\"\\uD83D\\uDE00\"", "OK '\u{1f600}'"),
    (
        " \u{9}\u{d}\u{a}[ \u{9}\u{d}\u{a}1 \u{9}\u{d}\u{a}] \u{9}\u{d}\u{a}",
        "OK [1]",
    ),
    ("\u{a0}[]", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("[1]\u{a0}", "ERR Extra data: line 1 column 4 (char 3)"),
    ("{\"a\" : 1 , \"b\":[ ] }", "OK {'a': 1, 'b': []}"),
    ("\"\\u00e9\\u4e00\"", "OK '\u{e9}\u{4e00}'"),
    ("1.5e+3", "OK 1500.0"),
    ("1.5E-3", "OK 0.0015"),
    ("-12.5e2", "OK -1250.0"),
    ("0.1", "OK 0.1"),
    ("1e400", "OK inf"),
    ("-1e400", "OK -inf"),
    (
        "[1e5,]",
        "ERR Illegal trailing comma before end of array: line 1 column 5 (char 4)",
    ),
    (
        "{\"\u{e9}\u{1f600}\": \"\u{1f600}\"}\u{a}\u{1f600}",
        "ERR Extra data: line 2 column 1 (char 12)",
    ),
    (
        "\"\u{1f600}\u{a}\"",
        "ERR Invalid control character at: line 1 column 3 (char 2)",
    ),
    ("[true,false,null]", "OK [True, False, None]"),
    (
        "[truex]",
        "ERR Expecting ',' delimiter: line 1 column 6 (char 5)",
    ),
    ("fals", "ERR Expecting value: line 1 column 1 (char 0)"),
    ("falsey", "ERR Extra data: line 1 column 6 (char 5)"),
    (
        "{\"a\":1,}",
        "ERR Illegal trailing comma before end of object: line 1 column 7 (char 6)",
    ),
    (
        "{,}",
        "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
    ),
    ("[,]", "ERR Expecting value: line 1 column 2 (char 1)"),
    (
        "{\"a\":1 , }",
        "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
    ),
];

#[test]
fn loads_matches_python() {
    for (text, expected) in LOADS_CASES {
        let got = match loads(text) {
            Ok(value) => format!("OK {}", value.repr()),
            Err(error) => format!("ERR {error}"),
        };
        assert_eq!(got, *expected, "{text:?}");
    }
}

// python3 -c "import json; print(json.loads('{\"a\":1,\"b\":2,\"a\":3}'), repr(json.loads('[1, 1.0, 1e3, -0, -0.0]')))"
// prints: {'a': 3, 'b': 2} [1, 1.0, 1000.0, 0, -0.0]
#[test]
fn loads_keeps_python_types_and_order() {
    let value = loads(r#"{"a":1,"b":2,"a":3}"#).expect("valid");
    let keys: Vec<&String> = value.as_dict().expect("a dict").keys().collect();
    assert_eq!(keys, ["a", "b"]);
    assert_eq!(value.repr(), "{'a': 3, 'b': 2}");
    assert_eq!(
        loads("[1, 1.0, 1e3, -0, -0.0]").expect("valid").repr(),
        "[1, 1.0, 1000.0, 0, -0.0]"
    );
    assert!(matches!(loads("1").expect("valid"), Value::Int(1)));
    assert!(matches!(loads("1.0").expect("valid"), Value::Float(_)));
}

#[test]
fn loads_refuses_what_rust_cannot_hold() {
    let error = loads("[\n 99999999999999999999]").expect_err("outside i64");
    assert_eq!(
        error.into_error("x.json").to_string(),
        "ValueError: x.json: the integer 99999999999999999999 at line 2 column 2 (char 3) is outside the 64-bit \
         range the Rust SDK generator reads"
    );
    assert!(matches!(
        loads("-9223372036854775808").expect("i64::MIN"),
        Value::Int(i64::MIN)
    ));
    let error = loads(r#""\ud800""#).expect_err("lone surrogate");
    assert_eq!(
        error.into_error("x.json").to_string(),
        "ValueError: x.json: the escape \\ud800 at line 1 column 2 (char 1) is a lone surrogate, which the Rust \
         SDK generator cannot hold in a string"
    );
    assert!(
        matches!(loads(r#""\ud800\udc00""#).expect("a pair"), Value::Str(s) if s == "\u{10000}")
    );
}

// Python 3.14.7 on nelly: json.loads of each text (Sol's G1a review, P1-2 and P1-3). A text Python refuses fails
// with Python's error first; a value a duplicate key drops is not refused; past 4,300 digits Python's own
// ValueError comes at once, before a later syntax error.
#[test]
fn unheld_values_are_refused_only_when_they_survive() {
    let error = loads(r#"{"name":"x","extra":9223372036854775808,}"#).expect_err("trailing comma");
    assert_eq!(
        error.to_string(),
        "Illegal trailing comma before end of object: line 1 column 40 (char 39)"
    );
    let error = loads(r#"{"name":"x","extra":"\ud800",}"#).expect_err("trailing comma");
    assert_eq!(
        error.to_string(),
        "Illegal trailing comma before end of object: line 1 column 29 (char 28)"
    );
    // python3 -c "import json; print(json.loads('{\"name\":\"x\",\"discard\":\"\\\\ud800\",\"discard\":\"ok\"}'))"
    // prints: {'name': 'x', 'discard': 'ok'}
    let value = loads(r#"{"name":"x","discard":"\ud800","discard":"ok"}"#).expect("dropped");
    assert_eq!(value.repr(), "{'name': 'x', 'discard': 'ok'}");
    let value = loads(r#"{"a": {"b": [99999999999999999999]}, "c": 1, "a": 2}"#).expect("dropped");
    assert_eq!(value.repr(), "{'a': 2, 'c': 1}");
    let error = loads(r#"{"a": 1, "a": 99999999999999999999, "b": "\udc00"}"#).expect_err("kept");
    assert!(
        matches!(error, JsonError::IntOutOfRange { pos: 14, .. }),
        "{error:?}"
    );
    let error = loads(r#"{"\ud800": 1, "a": 1, "a": 2}"#).expect_err("a key survives");
    assert!(
        matches!(error, JsonError::LoneSurrogate { pos: 2, .. }),
        "{error:?}"
    );
    // python3 -c "import json; json.loads('[' + '1' * 4301 + ',]')": the traceback's last line.
    let error = loads(&format!("[{},]", "1".repeat(4301))).expect_err("digit limit");
    assert_eq!(
        error.into_error("x.json").to_string(),
        "ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use \
         sys.set_int_max_str_digits() to increase the limit"
    );
    let error = loads(&format!("-{}", "1".repeat(4301))).expect_err("digit limit");
    assert!(matches!(error, JsonError::IntDigitLimit { digits: 4301 }));
    assert!(matches!(
        loads(&"1".repeat(4300)).expect_err("outside i64"),
        JsonError::IntOutOfRange { .. }
    ));
    assert!(
        matches!(loads(&format!("{}.5", "1".repeat(4301))).expect("a float"), Value::Float(f) if f.is_infinite())
    );
}

#[test]
fn loads_refuses_nesting_past_max_depth() {
    let deep = std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            let ok = loads(&format!(
                "{}{}",
                "[".repeat(MAX_DEPTH),
                "]".repeat(MAX_DEPTH)
            ))
            .is_ok();
            let error = loads(&format!(
                "{}{}",
                "[".repeat(MAX_DEPTH + 1),
                "]".repeat(MAX_DEPTH + 1)
            ))
            .expect_err("too deep")
            .into_error("x.json")
            .to_string();
            (ok, error)
        })
        .expect("a thread")
        .join()
        .expect("no panic");
    assert!(deep.0);
    assert_eq!(
        deep.1,
        "RecursionError: maximum recursion depth exceeded while decoding a JSON array from a unicode string"
    );
}

fn sample() -> Value {
    loads(DUMPS_SAMPLE).expect("valid sample")
}

const DUMPS_SAMPLE: &str = r#"{"z": 1, "a": [1.0, 1e16, 1e-7, -0.0, NaN, Infinity, -Infinity, true, false, null],
        "s": "é\u0000\b\t\n\f\r\u001f/\\\"😀 \u007f<>&'", "e": {}, "l": [], "n": {"b": [[]], "a": {"c": "x"}}}"#;

// python3 -c "import json; v = json.loads(SAMPLE); print(json.dumps(v)); print(json.dumps(v, ensure_ascii=False))"
// with SAMPLE the text of DUMPS_SAMPLE.
#[test]
fn dumps_matches_python() {
    let value = sample();
    assert_eq!(dumps(&value, DumpOptions::default()), DUMPS_DEFAULT);
    assert_eq!(
        dumps(
            &value,
            DumpOptions {
                ensure_ascii: false,
            }
        ),
        DUMPS_UNICODE
    );
    // python3 -c "import json; print(json.dumps('café \U0001f600 \x7f'))"
    assert_eq!(
        dumps_str("café 😀 \u{7f}"),
        "\"caf\\u00e9 \\ud83d\\ude00 \\u007f\""
    );
}

const DUMPS_DEFAULT: &str = "{\"z\": 1, \"a\": [1.0, 1e+16, 1e-07, -0.0, NaN, Infinity, -Infinity, true, false, null], \"s\": \"\\u00e9\\u0000\\b\\t\\n\\f\\r\\u001f/\\\\\\\"\\ud83d\\ude00\\u2028\\u007f<>&'\", \"e\": {}, \"l\": [], \"n\": {\"b\": [[]], \"a\": {\"c\": \"x\"}}}";
const DUMPS_UNICODE: &str = "{\"z\": 1, \"a\": [1.0, 1e+16, 1e-07, -0.0, NaN, Infinity, -Infinity, true, false, null], \"s\": \"\u{e9}\\u0000\\b\\t\\n\\f\\r\\u001f/\\\\\\\"\u{1f600}\u{2028}\u{7f}<>&'\", \"e\": {}, \"l\": [], \"n\": {\"b\": [[]], \"a\": {\"c\": \"x\"}}}";
