//! `port-harness unicode --out <file>`: every character property and case mapping `py::text` ports, for every code
//! point, as `scripts/sdk/port_harness.py unicode` prints them from Python.

use crate::error::GenerateError;
use crate::py::re::PyRegex;
use crate::py::text;

const USAGE: &str = "usage: oneiron-sdk-generator port-harness unicode --out <file>";

fn ranges(name: &str, chars: &[char], predicate: impl Fn(char) -> bool) -> String {
    let mut line = name.to_owned();
    let mut start: Option<char> = None;
    let mut previous = '\0';
    for &c in chars {
        if predicate(c) {
            if start.is_none() {
                start = Some(c);
            }
        } else if let Some(first) = start.take() {
            line.push_str(&format!(
                " {:X}-{:X}",
                u32::from(first),
                u32::from(previous)
            ));
        }
        previous = c;
    }
    if let Some(first) = start {
        line.push_str(&format!(
            " {:X}-{:X}",
            u32::from(first),
            u32::from(previous)
        ));
    }
    line.push('\n');
    line
}

fn mappings(name: &str, chars: &[char], map: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for &c in chars {
        let mapped = map(&c.to_string());
        if mapped != c.to_string() {
            let code_points: Vec<String> = mapped
                .chars()
                .map(|m| format!("{:X}", u32::from(m)))
                .collect();
            out.push_str(&format!(
                "{name} {:X} {}\n",
                u32::from(c),
                code_points.join(" ")
            ));
        }
    }
    out
}

pub(crate) fn run(args: &[String]) -> Result<(), GenerateError> {
    let out = super::flag(args, "--out", USAGE)?;
    let chars: Vec<char> = (0..=0x10_FFFF).filter_map(char::from_u32).collect();
    let mut dump = String::new();
    dump.push_str(&ranges("alnum", &chars, text::is_alnum));
    dump.push_str(&ranges("word", &chars, text::is_word));
    dump.push_str(&ranges("space", &chars, text::is_space));
    dump.push_str(&ranges("decimal", &chars, text::is_decimal));
    dump.push_str(&ranges("digit", &chars, text::is_digit));
    dump.push_str(&ranges("printable", &chars, text::is_printable));
    dump.push_str(&ranges("cased", &chars, text::is_cased));
    dump.push_str(&ranges("case_ignorable", &chars, text::is_case_ignorable));
    dump.push_str(&ranges("id_start", &chars, |c| {
        text::isidentifier(&c.to_string())
    }));
    dump.push_str(&ranges("id_continue", &chars, |c| {
        text::isidentifier(&format!("a{c}"))
    }));
    dump.push_str(&mappings("upper", &chars, text::upper));
    dump.push_str(&mappings("lower", &chars, text::lower));
    dump.push_str(&mappings("title", &chars, text::title));
    dump.push_str(&ranges("repr_plain", &chars, |c| {
        text::repr_str(&c.to_string()) == format!("'{c}'")
    }));
    // Python's `\b` through `PyRegex` (Sol's G1a review, P1-6): after a word character, before one, and around a
    // capitalised word.
    let after = PyRegex::new(r"a\b");
    let before = PyRegex::new(r"\ba");
    let capitalised = PyRegex::new(r"\b([A-Z]\w*)\b");
    dump.push_str(&ranges("boundary_after", &chars, |c| {
        after.is_match(&format!("a{c}"))
    }));
    dump.push_str(&ranges("boundary_before", &chars, |c| {
        before.is_match(&format!("{c}a"))
    }));
    dump.push_str(&ranges("capitalised_word", &chars, |c| {
        let text = format!("A{c}");
        let found: Vec<&str> = capitalised
            .captures_iter(&text)
            .iter()
            .filter_map(|groups| groups[1].map(|(start, end)| &text[start..end]))
            .collect();
        found == [text.as_str()]
    }));
    super::write(out, &dump)
}
