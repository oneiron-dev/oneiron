//! The shared boundary helpers every emitter calls, and `AGENT_VERBS_TS`, which `hand_declared('ts')` reads.
//!
//! `boundary_type` and `hand_declared` take the `Generator`: the first can root a new type in the shared `Inventory`,
//! and the second keeps `functools.cache`'s memo on it (`Generator::hand_declared_cache`).
//!
//! The helpers take a `&str` where Python's argument is a string; a row value that may be no string is turned into
//! one by `str_receiver`, with the `AttributeError` Python raises at the first `str` method it calls.

use indexmap::{IndexMap, IndexSet};
use regex::Regex;

use super::Generator;
use crate::error::GenerateError;
use crate::facade_types::Inventory;
use crate::py::re::translate;
use crate::py::text::title;
use crate::py::value::{Dict, Value};

impl Generator {
    /// `INVENTORY`, for an emitter's call into it. Only `Generator::rows_only` (the refusal tests' module level) has no
    /// inventory; no emitter runs on that one.
    pub(crate) fn inventory_mut(&mut self) -> Result<&mut Inventory, GenerateError> {
        self.inventory.as_mut().ok_or_else(|| {
            GenerateError::exception(
                "RuntimeError",
                "INVENTORY is not built (Generator::rows_only)",
            )
        })
    }
}

/// Clippy caps a function at seven parameters, its receiver included; a verb with more SDK arguments says why it may
/// pass them one by one.
pub(crate) const LONG_SIGNATURE: &str =
    r#"expect(clippy::too_many_arguments, reason = "one parameter per SDK argument of the verb")"#;

/// The `LONG_SIGNATURE` attribute for a function of more than seven parameters, else nothing.
pub(crate) fn long_signature(params: usize) -> String {
    if params > 7 {
        format!("#[{LONG_SIGNATURE}] ")
    } else {
        String::new()
    }
}

/// The Rust primitives a row may name bare (OF-495: no crate path prefixes them). A frozenset read for membership
/// only, in the literal's order.
pub(crate) const RUST_PRIMITIVES: &[&str] = &[
    "bool", "char", "String", "f32", "f64", "u8", "u16", "u32", "u64", "u128", "usize", "i8",
    "i16", "i32", "i64", "i128", "isize", "()",
];

/// A row type outside the engine: primitives and JSON values as is, engine paths under `oneiron::`, other names from
/// the SDK module.
///
/// `value in RUST_PRIMITIVES` refuses a list or dict (unhashable); any other value that is no string passes the two
/// tests and meets `value.startswith`.
pub(crate) fn rust_type(value: &Value) -> Result<String, GenerateError> {
    value.check_hashable("a set element")?;
    let text = str_receiver(value, "startswith")?;
    if RUST_PRIMITIVES.contains(&text) || text == "serde_json::Value" {
        return Ok(text.to_owned());
    }
    Ok(if text.starts_with("crate::") {
        text.replace("crate::", "oneiron::")
    } else {
        format!("oneiron::task_verb::sdk::{text}")
    })
}

/// One value of an `ARGUMENTS` entry: a text (a type spelling or a `str.format` template), or `'json': True`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArgumentValue {
    Text(&'static str),
    Flag(bool),
}

/// One `ARGUMENTS` entry: the dict of one binding argument kind, its keys in the literal's order.
#[derive(Debug)]
pub(crate) struct ArgumentKind {
    pub(crate) kind: &'static str,
    pub(crate) fields: &'static [(&'static str, ArgumentValue)],
}

impl ArgumentKind {
    /// `ARGUMENTS[kind].get(key)`.
    pub(crate) fn get(&self, key: &str) -> Option<ArgumentValue> {
        self.fields
            .iter()
            .find(|(name, _)| *name == key)
            .map(|&(_, value)| value)
    }

    /// `ARGUMENTS[kind][key]` read as a text: an absent key is Python's `KeyError`.
    pub(crate) fn text(&self, key: &str) -> Result<&'static str, GenerateError> {
        match self.get(key) {
            Some(ArgumentValue::Text(text)) => Ok(text),
            // Only `json` holds a flag, and no emitter reads it as a text.
            Some(ArgumentValue::Flag(_)) => Err(GenerateError::type_error(format!(
                "ARGUMENTS[{:?}][{key:?}] is a bool, not a str",
                self.kind
            ))),
            None => Err(GenerateError::key(key)),
        }
    }

    /// `ARGUMENTS[kind].get(key, default)` read as a text.
    pub(crate) fn text_or(&self, key: &str, default: &'static str) -> &'static str {
        match self.get(key) {
            Some(ArgumentValue::Text(text)) => text,
            _ => default,
        }
    }

    /// `bool(ARGUMENTS[kind].get(key))`: Python's truthiness of the value, `False` when absent.
    pub(crate) fn flag(&self, key: &str) -> bool {
        match self.get(key) {
            Some(ArgumentValue::Flag(flag)) => flag,
            Some(ArgumentValue::Text(text)) => !text.is_empty(),
            None => false,
        }
    }
}

/// Boundary codecs are selected by argument/result type, never by verb name. In the dict literal's order, each
/// entry's keys in theirs (copied from the literal by its AST).
pub(crate) const ARGUMENTS: &[ArgumentKind] = &[
    ArgumentKind {
        kind: "witness",
        fields: &[
            ("rust", ArgumentValue::Text("&oneiron::memory::WitnessTurn")),
            ("napi", ArgumentValue::Text("NapiWitnessTurnInput")),
            ("native_ts", ArgumentValue::Text("WitnessTurn")),
            ("py", ArgumentValue::Text("dict[str, Any]")),
            ("stub", ArgumentValue::Text("WitnessTurn")),
            ("native_py", ArgumentValue::Text("&str")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text("let {name} = {name}.into_engine()?;"),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    r#"let {name} = decode::<WitnessTurnInput>({name}, "witness turn")?.into_engine().map_err(raise)?;"#,
                ),
            ),
            ("borrow", ArgumentValue::Text("&")),
        ],
    },
    ArgumentKind {
        kind: "claim",
        fields: &[
            ("rust", ArgumentValue::Text("&oneiron::memory::ClaimInput")),
            ("napi", ArgumentValue::Text("NapiClaimInput")),
            ("native_ts", ArgumentValue::Text("ClaimInput")),
            ("py", ArgumentValue::Text("dict[str, Any]")),
            ("stub", ArgumentValue::Text("ClaimInput")),
            ("native_py", ArgumentValue::Text("&str")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = claim_input_to_engine(&{name}).map_err(facade_error)?;",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text(r#"let {name}: ClaimInput = decode({name}, "claim")?;"#),
            ),
            ("borrow", ArgumentValue::Text("&")),
        ],
    },
    ArgumentKind {
        kind: "text",
        fields: &[
            ("rust", ArgumentValue::Text("&str")),
            ("napi", ArgumentValue::Text("String")),
            ("native_ts", ArgumentValue::Text("string")),
            ("py", ArgumentValue::Text("str")),
            ("stub", ArgumentValue::Text("str")),
            ("native_py", ArgumentValue::Text("String")),
            ("borrow", ArgumentValue::Text("&")),
            ("field", ArgumentValue::Text("{name}.to_owned()")),
        ],
    },
    ArgumentKind {
        kind: "effort",
        fields: &[
            ("rust", ArgumentValue::Text("oneiron::memory::RecallEffort")),
            ("napi", ArgumentValue::Text("Option<String>")),
            ("native_ts", ArgumentValue::Text("string | undefined")),
            ("py", ArgumentValue::Text("str")),
            ("stub", ArgumentValue::Text("Effort")),
            ("native_py", ArgumentValue::Text("Option<&str>")),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = oneiron_remote::parse_effort({name}.as_deref().unwrap_or({default})).map_err(facade_error)?;",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    "let {name} = oneiron_remote::parse_effort({name}.unwrap_or({default})).map_err(raise)?;",
                ),
            ),
            ("field", ArgumentValue::Text("Some({name})")),
        ],
    },
    ArgumentKind {
        kind: "scope",
        fields: &[
            ("rust", ArgumentValue::Text("&oneiron::memory::RecallScope")),
            ("napi", ArgumentValue::Text("Option<NapiRecallScope>")),
            ("native_ts", ArgumentValue::Text("RecallScope | undefined")),
            ("py", ArgumentValue::Text("dict[str, Any] | None")),
            ("stub", ArgumentValue::Text("RecallScope | None")),
            ("native_py", ArgumentValue::Text("Option<&str>")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = recall_scope_to_engine({name}).map_err(facade_error)?;",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    r#"let {name} = match {name} {{ Some(value) => decode(value, "recall scope")?, None => oneiron::memory::RecallScope::default() }};"#,
                ),
            ),
            ("borrow", ArgumentValue::Text("&")),
            ("field", ArgumentValue::Text("Some({name}.clone())")),
        ],
    },
    ArgumentKind {
        kind: "limit",
        fields: &[
            ("rust", ArgumentValue::Text("usize")),
            ("napi", ArgumentValue::Text("Option<f64>")),
            ("native_ts", ArgumentValue::Text("number | undefined")),
            ("py", ArgumentValue::Text("int")),
            ("stub", ArgumentValue::Text("int")),
            ("native_py", ArgumentValue::Text("Option<usize>")),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = {name}.map(limit_to_engine).transpose().map_err(facade_error)?.unwrap_or({default});",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text("let {name} = {name}.unwrap_or({default});"),
            ),
            ("field", ArgumentValue::Text("Some({name})")),
        ],
    },
    ArgumentKind {
        kind: "format",
        fields: &[
            ("rust", ArgumentValue::Text("Option<&str>")),
            ("napi", ArgumentValue::Text("Option<String>")),
            ("native_ts", ArgumentValue::Text("string | undefined")),
            ("py", ArgumentValue::Text("str | None")),
            ("stub", ArgumentValue::Text("PackFormat | None")),
            ("native_py", ArgumentValue::Text("Option<String>")),
            ("borrow", ArgumentValue::Text("")),
            ("suffix", ArgumentValue::Text(".as_deref()")),
            ("field", ArgumentValue::Text("{name}.map(str::to_owned)")),
        ],
    },
    ArgumentKind {
        kind: "as_of",
        fields: &[
            ("rust", ArgumentValue::Text("Option<u64>")),
            ("napi", ArgumentValue::Text("Option<f64>")),
            ("native_ts", ArgumentValue::Text("number | undefined")),
            ("py", ArgumentValue::Text("int | None")),
            ("stub", ArgumentValue::Text("int | None")),
            ("native_py", ArgumentValue::Text("Option<u64>")),
            (
                "napi_convert",
                ArgumentValue::Text(
                    r#"let {name} = {name}.map(|value| oneiron_remote::check_unix_seconds("as_of", value)).transpose().map_err(facade_error)?;"#,
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "deadline_ms",
        fields: &[
            ("rust", ArgumentValue::Text("Option<u64>")),
            ("napi", ArgumentValue::Text("Option<f64>")),
            ("native_ts", ArgumentValue::Text("number | undefined")),
            ("py", ArgumentValue::Text("int | None")),
            ("stub", ArgumentValue::Text("int | None")),
            ("native_py", ArgumentValue::Text("Option<u64>")),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = {name}.map(oneiron_remote::check_deadline_ms_number).transpose().map_err(facade_error)?;",
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "token_budget",
        fields: &[
            ("rust", ArgumentValue::Text("Option<u64>")),
            ("napi", ArgumentValue::Text("Option<f64>")),
            ("native_ts", ArgumentValue::Text("number | undefined")),
            ("py", ArgumentValue::Text("int | None")),
            ("stub", ArgumentValue::Text("int | None")),
            ("native_py", ArgumentValue::Text("Option<u64>")),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = {name}.map(oneiron_remote::check_token_budget_number).transpose().map_err(facade_error)?;",
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "media",
        fields: &[
            (
                "rust",
                ArgumentValue::Text("Option<oneiron::code_run::vault_read::ContextPackMediaQuery>"),
            ),
            ("napi", ArgumentValue::Text("Option<NapiRecallMedia>")),
            ("native_ts", ArgumentValue::Text("RecallMedia | undefined")),
            ("py", ArgumentValue::Text("dict[str, Any] | None")),
            ("stub", ArgumentValue::Text("RecallMedia | None")),
            ("native_py", ArgumentValue::Text("Option<&str>")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = {name}.map(recall_media_to_engine).transpose().map_err(facade_error)?;",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    r#"let {name}: Option<oneiron::code_run::vault_read::ContextPackMediaQuery> = {name}.map(|value| decode(value, "recall media")).transpose()?;"#,
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "query_affect",
        fields: &[
            (
                "rust",
                ArgumentValue::Text("Option<oneiron::task_verb::sdk::QueryAffect>"),
            ),
            ("napi", ArgumentValue::Text("Option<NapiQueryAffect>")),
            ("native_ts", ArgumentValue::Text("QueryAffect | undefined")),
            ("py", ArgumentValue::Text("dict[str, Any] | None")),
            ("stub", ArgumentValue::Text("QueryAffect | None")),
            ("native_py", ArgumentValue::Text("Option<&str>")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text("let {name} = {name}.map(query_affect_to_engine);"),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    r#"let {name}: Option<oneiron::task_verb::sdk::QueryAffect> = {name}.map(|value| decode(value, "recall query affect")).transpose()?;"#,
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "ref",
        fields: &[
            ("rust", ArgumentValue::Text("Option<&str>")),
            ("napi", ArgumentValue::Text("Option<String>")),
            ("native_ts", ArgumentValue::Text("string | undefined")),
            ("py", ArgumentValue::Text("str | None")),
            ("stub", ArgumentValue::Text("str | None")),
            ("native_py", ArgumentValue::Text("Option<String>")),
            ("borrow", ArgumentValue::Text("")),
            ("suffix", ArgumentValue::Text(".as_deref()")),
            ("field", ArgumentValue::Text("{name}.map(str::to_owned)")),
        ],
    },
    ArgumentKind {
        kind: "read_filter",
        fields: &[
            (
                "rust",
                ArgumentValue::Text("Option<oneiron::memory::ReadFilterInput>"),
            ),
            ("napi", ArgumentValue::Text("Option<serde_json::Value>")),
            (
                "native_ts",
                ArgumentValue::Text("ReadFilterInput | undefined"),
            ),
            ("py", ArgumentValue::Text("dict[str, Any] | None")),
            ("stub", ArgumentValue::Text("Facade.ReadFilterInput | None")),
            ("native_py", ArgumentValue::Text("Option<&str>")),
            ("json", ArgumentValue::Flag(true)),
            (
                "napi_convert",
                ArgumentValue::Text(
                    "let {name} = {name}.map(|value| read_filter_to_engine(js_json(value))).transpose().map_err(facade_error)?;",
                ),
            ),
            (
                "py_convert",
                ArgumentValue::Text(
                    r#"let {name}: Option<oneiron::memory::ReadFilterInput> = {name}.map(|value| decode(value, "recall filter")).transpose()?;"#,
                ),
            ),
            ("field", ArgumentValue::Text("{name}")),
        ],
    },
    ArgumentKind {
        kind: "kinds",
        fields: &[
            ("rust", ArgumentValue::Text("&[String]")),
            ("napi", ArgumentValue::Text("Option<Vec<String>>")),
            ("native_ts", ArgumentValue::Text("string[] | undefined")),
            ("py", ArgumentValue::Text("list[str] | None")),
            ("stub", ArgumentValue::Text("list[str] | None")),
            ("native_py", ArgumentValue::Text("Option<Vec<String>>")),
            (
                "napi_convert",
                ArgumentValue::Text("let {name} = {name}.unwrap_or_default();"),
            ),
            (
                "py_convert",
                ArgumentValue::Text("let {name} = {name}.unwrap_or_default();"),
            ),
            ("borrow", ArgumentValue::Text("&")),
            ("field", ArgumentValue::Text("Some({name}.to_vec())")),
        ],
    },
    ArgumentKind {
        kind: "json",
        fields: &[
            ("napi", ArgumentValue::Text("String")),
            ("native_ts", ArgumentValue::Text("string")),
            ("py", ArgumentValue::Text("dict[str, Any]")),
            ("native_py", ArgumentValue::Text("&str")),
            ("json", ArgumentValue::Flag(true)),
        ],
    },
];

/// `ARGUMENTS[kind]` for a row's `kind` value: a list or dict is Python's unhashable `TypeError`, an unknown kind its
/// `KeyError` (which prints the key's `repr`).
pub(crate) fn argument_kind(kind: &Value) -> Result<&'static ArgumentKind, GenerateError> {
    kind.check_hashable("a dict key")?;
    kind.as_str()
        .and_then(|kind| ARGUMENTS.iter().find(|entry| entry.kind == kind))
        .ok_or_else(|| GenerateError::exception("KeyError", kind.repr()))
}

/// One `RESULTS` entry: `(napi type, conversion function, error mapping or None)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResultCodec {
    pub(crate) napi: &'static str,
    pub(crate) convert: &'static str,
    pub(crate) error: Option<&'static str>,
}

/// The result codecs by result type, in the dict literal's order.
pub(crate) const RESULTS: &[(&str, ResultCodec)] = &[
    (
        "WitnessReceipt",
        ResultCodec {
            napi: "NapiWitnessReceipt",
            convert: "witness_receipt_from_engine",
            error: None,
        },
    ),
    (
        "CommitReceipt",
        ResultCodec {
            napi: "NapiCommitReceipt",
            convert: "commit_receipt_from_engine",
            error: None,
        },
    ),
    (
        "MemoryPack",
        ResultCodec {
            napi: "NapiMemoryPack",
            convert: "memory_pack_from_engine",
            error: Some("boundary_error"),
        },
    ),
    (
        "MemoryReceipt",
        ResultCodec {
            napi: "NapiGateReceipt",
            convert: "gate_receipt_from_engine",
            error: Some("boundary_error"),
        },
    ),
];

/// `RESULTS[inner]`: an unknown type is Python's `KeyError`.
pub(crate) fn result_codec(inner: &str) -> Result<&'static ResultCodec, GenerateError> {
    RESULTS
        .iter()
        .find(|(name, _)| *name == inner)
        .map(|(_, codec)| codec)
        .ok_or_else(|| GenerateError::key(inner))
}

/// The binding the native layer types, or `None` when it is the generic agent-verb door. Python returns the row's
/// `binding` value itself otherwise; an absent binding and a JSON `null` are both `None`. A truthy binding that is no
/// dict meets `binding.get`.
pub(crate) fn native_binding(row: &Dict) -> Result<Option<&Value>, GenerateError> {
    let binding = match row.get("binding") {
        None | Some(Value::None) => return Ok(None),
        Some(binding) => binding,
    };
    if binding.truthy()
        && binding
            .dict_get("native")?
            .is_some_and(|native| native.is_str("agent_verb"))
    {
        return Ok(None);
    }
    Ok(Some(binding))
}

/// The first segment unchanged, then each later one `str.title()`d: `v2beta.html5parser` is `v2betaHtml5Parser`.
pub(crate) fn js_method(name: &str) -> String {
    let joined = name.replace('.', "_");
    let mut parts = joined.split('_');
    let mut out = parts.next().unwrap_or_default().to_owned();
    for part in parts {
        out.push_str(&title(part));
    }
    out
}

/// `('Option' | 'Vec', inner)` for a text that starts with `<container><` and ends with `>`, else
/// `(None, the last `::` segment)`.
pub(crate) fn container_type(value: &str) -> (Option<&'static str>, &str) {
    for container in ["Option", "Vec"] {
        if let Some(inner) = value
            .strip_prefix(container)
            .and_then(|rest| rest.strip_prefix('<'))
            .and_then(|rest| rest.strip_suffix('>'))
        {
            return (Some(container), inner);
        }
    }
    (
        None,
        value.rsplit_once("::").map_or(value, |(_, last)| last),
    )
}

/// A row type as one boundary spells it (`language`: `napi`, `py`, `py_stub`, `ts`). A type the package declares by
/// hand is the shape its native conversion returns; any other is the generated wire declaration, which
/// `ts_type`/`py_type` can root in the shared `Inventory`. `hand_declared` is read only when the built-in names do not
/// answer, as Python's `or` does.
pub(crate) fn boundary_type(
    generator: &mut Generator,
    value: &str,
    language: &str,
    wire: bool,
) -> Result<String, GenerateError> {
    let (container, inner) = container_type(value);
    if let Some(container) = container {
        let item = boundary_type(generator, inner, language, wire)?;
        if language == "napi" {
            return Ok(format!("{container}<{item}>"));
        }
        if container == "Option" {
            let none = if language.starts_with("py") {
                " | None"
            } else {
                " | null"
            };
            return Ok(format!("{item}{none}"));
        }
        return Ok(if language.starts_with("py") {
            format!("list[{item}]")
        } else if item.contains(" | ") {
            format!("({item})[]")
        } else {
            format!("{item}[]")
        });
    }
    if language == "napi" {
        return Ok(result_codec(inner)?.napi.to_owned());
    }
    if language == "py" {
        return Ok(match inner {
            "String" => "str",
            "bool" => "bool",
            _ => "dict[str, Any]",
        }
        .to_owned());
    }
    if language == "py_stub" {
        let name = match inner {
            "String" => "str",
            "bool" => "bool",
            "MemoryReceipt" => "FacadeReceipt",
            "MemoryExport" => "dict[str, Any]",
            _ => inner,
        };
        if matches!(name, "str" | "bool" | "dict[str, Any]")
            || hand_declared(generator, "py")?.contains(name)
        {
            return Ok(name.to_owned());
        }
        return generator.inventory_mut()?.py_type(value, "Facade.");
    }
    let name = match inner {
        "String" => "string",
        "bool" => "boolean",
        "MemoryReceipt" => "FacadeReceipt",
        "KeyValueItem" if wire => "WireItem",
        _ => inner,
    };
    if matches!(name, "string" | "boolean") || hand_declared(generator, "ts")?.contains(name) {
        return Ok(name.to_owned());
    }
    generator.inventory_mut()?.ts_type(value, "Facade.")
}

/// `functools.cache`'s memo of `hand_declared`, by language (a field on `Generator`, DESIGN 5). A failed read is not
/// kept, as Python caches only a returned value.
pub(crate) type HandDeclaredCache = IndexMap<String, IndexSet<String>>;

/// The type names a package declares by hand: its TypeScript type modules and agent-verbs template, or the stub's top
/// level. A frozenset, read for membership (and through `sorted`).
pub(crate) fn hand_declared<'g>(
    generator: &'g mut Generator,
    language: &str,
) -> Result<&'g IndexSet<String>, GenerateError> {
    if !generator.hand_declared_cache.contains_key(language) {
        let names = if language == "ts" {
            // Python evaluates the `+` left to right: types.ts is read (and can fail) first.
            let mut text =
                crate::py::read_text(&generator.root.join("packages/oneiron/src/types.ts"))?;
            text.push_str(&crate::py::read_text(
                &generator.root.join("packages/oneiron/src/key-value.ts"),
            )?);
            text.push_str(AGENT_VERBS_TS);
            ts_declared_names(&text)
        } else {
            let text = crate::py::read_text(
                &generator
                    .root
                    .join("crates/oneiron-py/python/oneiron/__init__.pyi"),
            )?;
            py_declared_names(&text)
        };
        generator
            .hand_declared_cache
            .insert(language.to_owned(), names);
    }
    Ok(&generator.hand_declared_cache[language])
}

/// Python: `re.findall(r'^export (?:type|interface) (\w+)', text, re.M)`: the one group of each match.
/// Rust: `(?m)^export (?:type|interface) ([\p{L}\p{N}_]+)` (`translate`); `(?m)^` matches at the start and after each
/// `\n`, as Python's `re.M` does (the text has universal newlines).
fn ts_declared_names(text: &str) -> IndexSet<String> {
    let pattern = Regex::new(&format!(
        "(?m){}",
        translate(r"^export (?:type|interface) (\w+)")
    ))
    .expect("a constant pattern");
    pattern
        .captures_iter(text)
        .filter_map(|found| found.get(1).map(|name| name.as_str().to_owned()))
        .collect()
}

/// Python: `frozenset(a or b for a, b in re.findall(r'^(?:class (\w+)\b|(\w+) = )', text, re.M))`.
/// Rust: `(?m)^(?:class ([\p{L}\p{N}_]+)|([\p{L}\p{N}_]+) = )`. The `\b` is dropped: after a greedy run of Python word
/// characters the next one is no word character to Python (or the text ends), so Python's `\b` always holds there,
/// while Rust's Unicode `\b` would fail before a combining mark (`class X\u{301}y` is `X` to Python).
fn py_declared_names(text: &str) -> IndexSet<String> {
    let pattern = Regex::new(&format!("(?m){}", translate(r"^(?:class (\w+)|(\w+) = )")))
        .expect("a constant pattern");
    pattern
        .captures_iter(text)
        .map(|found| {
            found
                .get(1)
                .or_else(|| found.get(2))
                .map_or_else(String::new, |name| name.as_str().to_owned())
        })
        .collect()
}

/// A row value a `str` method is called on: the text of a `str`, else Python's
/// `AttributeError: '<type>' object has no attribute '<method>'`.
pub(crate) fn str_receiver<'v>(value: &'v Value, method: &str) -> Result<&'v str, GenerateError> {
    value
        .as_str()
        .ok_or_else(|| GenerateError::attribute(value.type_name(), method))
}

/// Python's `template.format(**fields)` for the generator's constant templates (`ARGUMENTS`, `UNIFFI_ARGUMENTS`,
/// `uniffi_types::WIRE_LEAVES`): `{{` and `}}` are one brace, `{name}` is the field's text, never parsed again; a
/// missing field is Python's `KeyError`, an unpaired brace its `ValueError`. Every constant template uses plain
/// `{name}` fields only; a conversion, a format spec, an index or a positional field is refused (no template has one).
pub(crate) fn str_format(template: &str, fields: &[(&str, &str)]) -> Result<String, GenerateError> {
    let mut out = String::with_capacity(template.len() + 16);
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        match c {
            '{' => {
                let rest = chars.as_str();
                if let Some(after) = rest.strip_prefix('{') {
                    out.push('{');
                    chars = after.chars();
                    continue;
                }
                let Some(end) = rest.find('}') else {
                    return Err(GenerateError::value("expected '}' before end of string"));
                };
                let field = &rest[..end];
                if field.is_empty()
                    || field.contains(['!', ':', '.', '[', '{'])
                    || field.chars().all(|c| c.is_ascii_digit())
                {
                    return Err(GenerateError::value(format!(
                        "str_format supports only named fields, not {{{field}}}"
                    )));
                }
                let value = fields
                    .iter()
                    .find(|(name, _)| *name == field)
                    .map(|&(_, value)| value)
                    .ok_or_else(|| GenerateError::key(field))?;
                out.push_str(value);
                chars = rest[end + 1..].chars();
            }
            '}' => {
                let rest = chars.as_str();
                let Some(after) = rest.strip_prefix('}') else {
                    return Err(GenerateError::value(
                        "Single '}' encountered in format string",
                    ));
                };
                out.push('}');
                chars = after.chars();
            }
            other => out.push(other),
        }
    }
    Ok(out)
}

/// The task and ask declarations `packages/oneiron/src/agent-verbs.ts` carries (copied from the literal by its AST;
/// ASCII, no backslash). The emitters read it from here.
pub(crate) const AGENT_VERBS_TS: &str = r#"import type { RecordRef, TaskDescription as FacadeTaskDescription } from "./facade-types.js";
export interface OutcomeBinding { source: {kind: "claim" | "event"; predicate: string} | {kind: "edge"; relation: string} | {kind: "stage"; campaign: string}; horizon: number; mapping: Record<string, boolean>; noise_weight: number; linked_by?: string | null }
export interface CalibrationPair { prediction: unknown; probability: number; outcome: {answer: string; fact: string; fact_value_hash: number[]; label: boolean; noise_weight: number; occurred_at: number} }
export type TaskAssignee = "dreamer" | {agent_def: {agent_def_ref: string}} | {peer: {actor_ref: string}} | {child: {actor_ref: string}} | {human: {actor_ref: string}};
export type ConsultPayloadRef = {claim: string} | {turn: string};
export type TaskAskOptionId = string;
export type TaskAskTarget = {responder: TaskAssignee} | {people: string[]} | {authority: {class: string; selectors: string[]; target: string | null; budget: number | null; receipt_required: boolean}};
export interface TaskAskLadderPrediction { option: TaskAskOptionId; rung: "rule" | "system_one" | "precision" | "escalation"; probability: number | null }
export interface TaskAskQuestion { reference: ConsultPayloadRef; revision: number; options: Record<TaskAskOptionId, string>; context_refs: ConsultPayloadRef[]; label?: string | null; outcome_binding?: OutcomeBinding | null; ladder_answer?: TaskAskLadderPrediction | null; class_key?: string | null }
export type TaskAskElectorate = "any" | {people: string[]};
export interface TaskAskNeed {count: number; of?: TaskAskElectorate}
export type TaskAskDecide = "first" | {all: {of: TaskAskElectorate; answer: TaskAskOptionId}} | {at_least: {count: number; of: TaskAskElectorate; answer: TaskAskOptionId}};
export type TaskAskDefault = "proceed" | "hold" | "ask_me";
export interface TaskAskDisagree {branch: "hold" | "proceed"; surface: "card" | "none"}
export interface TaskAskClass {key: string; version: number; governance: boolean; deadline_seconds: number; allowed_recipients: string[]; required_people: string[]; minimum_responses: number; required_sources: ConsultPayloadRef[]; decision: TaskAskDecide | null; disclosure: Record<string, ConsultPayloadRef[]>; fallback: TaskAskDefault[]; remind: number[]}
export type TaskAskWho = TaskAskTarget | string | string[] | null;
export interface TaskAskShort {who?: TaskAskTarget | null; what: TaskAskQuestion; until?: number | null; default?: TaskAskDefault}
export interface TaskAskSpec { intent_key: string; task_ref?: string | null; class?: TaskAskClass | null; who?: TaskAskTarget | null; what: TaskAskQuestion; until?: number | null; default?: TaskAskDefault; need?: TaskAskNeed; decide?: TaskAskDecide | null; provisional?: "inform"; on_disagree?: TaskAskDisagree; remind?: number[] | null }
export interface TaskCanAskRequest { ask: TaskAskSpec }
export interface TaskAskPreflightRecipient { who: string; face: string | null; channel: string | null; word_required: boolean }
export interface TaskAskPreflight { recipients: TaskAskPreflightRecipient[] }
export type TaskAskPersonKind = "word" | "companion" | "default" | "unknown";
export interface TaskAskPersonEvidence {who: string; answer: TaskAskWord | null; kind: TaskAskPersonKind; at: number; source: string | null}
export interface TaskAskHandle { group_ref: string }
export interface TaskAskReceipt { handle: TaskAskHandle; task_refs: string[]; hold: "NoLiveRoute" | null; idempotent_replay: boolean; task_records: RecordRef[] }
export interface TaskAskWord {result_ref: string; option?: TaskAskOptionId | null; inform_for?: string | null; provenance_refs?: ConsultPayloadRef[]}
export interface TaskAskAnswer { task_ref: string; actor_ref: string; result_ref: string; word_ref: string; task_record: RecordRef; actor_record: RecordRef; result_record: RecordRef; word_record: RecordRef }
export interface TaskAskCoverage {met: boolean; required: number; responded: string[]; unknown: string[]; unmet_people: string[]}
export type TaskAskDecision = "collected" | {first: TaskAskAnswer} | {answer: TaskAskOptionId} | "no" | "conflict" | "unknown";
export interface TaskAskFallback {branch: TaskAskDefault; surface: "card" | "none"}
export interface TaskAskEvidence {answer: TaskAskAnswer; word: TaskAskWord; source: "human" | "foreign_stated" | "inform" | "executor"; person_ref: string; order: number; reason: "counted" | "inform" | "human_dominates" | "executor" | "superseded" | "outside_electorate" | "missing_source" | "late"; ladder_changed: boolean | null}
export interface TaskAskSettlement {group_ref: string; reference: string; revision: number; at: number; cutoff_order: number; reason: "first_word" | "all_responded" | "deadline" | "stale"; requested: TaskAskSpec; effective: TaskAskSpec; base_policy_version: number; electorate: string[]; question_digest: number[]; unmet_sources: ConsultPayloadRef[]; outcome_answer_ref: string | null; link_result_proof?: number[]}
export type TaskAskEffectAuthorization = "not_evaluated_by_ask";
export interface TaskAskResult {effect_authorization: TaskAskEffectAuthorization; coverage: TaskAskCoverage; decision: TaskAskDecision; fallback: TaskAskFallback | null; evidence: TaskAskEvidence[]; settlement: TaskAskSettlement}
export type TaskAskStatus = {Pending: {hold: "NoLiveRoute" | null}} | {Changed: {voided: string[]; generation: number}} | {Settled: TaskAskResult};
export type TaskAskWait = { Pending: {trap_ref: string} } | { Changed: {voided: string[]; generation: number} } | { Ready: TaskAskResult } | {Park: {wait_id: string; effect: string; reason: string; prompt: string | null}};
export type TaskDescription = FacadeTaskDescription;
export interface TaskCancelReceipt {approval: "auto" | "proposed" | "approved" | "rejected"; effected: boolean; proposal_ref: string | null; gate_decision_ref: string | null; status: "queued" | "running" | "paused" | "completed" | "failed" | "cancelled" | "abandoned" | null; cancel_requested: boolean; forced: boolean}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    // The expected values below were printed by Python 3.14.7 on nelly with the Python generator's definitions
    // copied verbatim into a probe (main e79eb76df3e):
    //   print(repr(n), repr(js_method(n)))  /  print(repr(v), repr(container_type(v)))  /  ... rust_type(v) ...

    #[test]
    fn js_method_titles_every_later_segment() {
        let cases: &[(&str, &str)] = &[
            ("vault.recall", "vaultRecall"),
            ("tasks.create", "tasksCreate"),
            ("self.browser.library.run", "selfBrowserLibraryRun"),
            ("a..b", "aB"),
            ("x_y.z", "xYZ"),
            ("v2beta.html5parser", "v2betaHtml5Parser"),
            ("_lead", "Lead"),
            ("trail_", "trail"),
            ("émile.ßtraße", "émileSstraße"),
            ("a.ǆb", "aǅb"),
            ("a.1st", "a1St"),
            ("", ""),
            ("é.ǅx", "éǅx"),
            ("one.two_three.FOUR", "oneTwoThreeFour"),
        ];
        for &(name, expected) in cases {
            assert_eq!(js_method(name), expected, "{name:?}");
        }
    }

    #[test]
    fn container_type_takes_option_and_vec_whole_else_the_last_segment() {
        let cases: &[(&str, (Option<&str>, &str))] = &[
            ("Option<String>", (Some("Option"), "String")),
            ("Vec<crate::a::B>", (Some("Vec"), "crate::a::B")),
            ("Option<>", (Some("Option"), "")),
            ("Vec<Option<u8>>", (Some("Vec"), "Option<u8>")),
            ("Option<Vec<T>", (Some("Option"), "Vec<T")),
            ("Vecx<T>", (None, "Vecx<T>")),
            ("crate::a::b::C", (None, "C")),
            ("C", (None, "C")),
            ("a:::b", (None, "b")),
            ("::", (None, "")),
            ("Option<T>>", (Some("Option"), "T>")),
            ("Box<T>", (None, "Box<T>")),
            ("a::b<c::D>", (None, "D>")),
        ];
        for &(value, expected) in cases {
            assert_eq!(container_type(value), expected, "{value:?}");
        }
    }

    #[test]
    fn rust_type_keeps_primitives_and_places_paths() {
        let cases: &[(&str, &str)] = &[
            ("bool", "bool"),
            ("()", "()"),
            ("serde_json::Value", "serde_json::Value"),
            ("crate::memory::X", "oneiron::memory::X"),
            ("crate::a::crate::b", "oneiron::a::oneiron::b"),
            ("Foo", "oneiron::task_verb::sdk::Foo"),
            (
                "Vec<crate::a::B>",
                "oneiron::task_verb::sdk::Vec<crate::a::B>",
            ),
            ("xcrate::a", "oneiron::task_verb::sdk::xcrate::a"),
            ("", "oneiron::task_verb::sdk::"),
            ("u128", "u128"),
        ];
        for &(value, expected) in cases {
            assert_eq!(
                rust_type(&Value::Str(value.to_owned())),
                Ok(expected.to_owned()),
                "{value:?}"
            );
        }
        let refusals: &[(Value, &str)] = &[
            (
                Value::List(vec![Value::Int(1)]),
                "TypeError: cannot use 'list' as a set element (unhashable type: 'list')",
            ),
            (
                Value::Dict(Dict::new()),
                "TypeError: cannot use 'dict' as a set element (unhashable type: 'dict')",
            ),
            (
                Value::Int(5),
                "AttributeError: 'int' object has no attribute 'startswith'",
            ),
            (
                Value::None,
                "AttributeError: 'NoneType' object has no attribute 'startswith'",
            ),
            (
                Value::Bool(true),
                "AttributeError: 'bool' object has no attribute 'startswith'",
            ),
            (
                Value::Float(1.5),
                "AttributeError: 'float' object has no attribute 'startswith'",
            ),
        ];
        for (value, expected) in refusals {
            assert_eq!(
                rust_type(value).map_err(|error| error.to_string()),
                Err((*expected).to_owned())
            );
        }
    }

    // print(repr(k), err(lambda k: D[k], k)) for a dict D; print(repr(v), err(js_method, v)).
    #[test]
    fn argument_kind_and_str_receiver_refuse_as_python() {
        assert_eq!(
            argument_kind(&Value::Str("limit".to_owned())).map(|kind| kind.kind),
            Ok("limit")
        );
        let refusals: &[(Value, &str)] = &[
            (Value::Str("nope".to_owned()), "KeyError: 'nope'"),
            (Value::Int(5), "KeyError: 5"),
            (Value::None, "KeyError: None"),
            (Value::Bool(true), "KeyError: True"),
            (Value::Float(1.0), "KeyError: 1.0"),
            (
                Value::List(vec![Value::Int(1)]),
                "TypeError: cannot use 'list' as a dict key (unhashable type: 'list')",
            ),
            (
                Value::Dict(Dict::new()),
                "TypeError: cannot use 'dict' as a dict key (unhashable type: 'dict')",
            ),
        ];
        for (kind, expected) in refusals {
            assert_eq!(
                argument_kind(kind)
                    .map(|kind| kind.kind)
                    .map_err(|error| error.to_string()),
                Err((*expected).to_owned())
            );
        }
        assert_eq!(
            str_receiver(&Value::Int(5), "replace").map_err(|error| error.to_string()),
            Err("AttributeError: 'int' object has no attribute 'replace'".to_owned())
        );
        assert_eq!(
            str_receiver(&Value::Str("a".to_owned()), "replace"),
            Ok("a")
        );
    }

    #[test]
    fn argument_tables_read_as_python_dicts() {
        let json = argument_kind(&Value::Str("json".to_owned())).expect("json");
        assert!(json.flag("json"));
        assert_eq!(
            json.text("rust").map_err(|error| error.to_string()),
            Err("KeyError: 'rust'".to_owned())
        );
        let format = argument_kind(&Value::Str("format".to_owned())).expect("format");
        assert_eq!(format.text_or("borrow", "&"), "");
        assert!(!format.flag("json"));
        assert_eq!(format.text_or("napi_convert", ""), "");
        assert_eq!(ARGUMENTS.len(), 16);
        assert_eq!(
            result_codec("MemoryPack").map(|codec| codec.error),
            Ok(Some("boundary_error"))
        );
        assert_eq!(
            result_codec("Nope").map_err(|error| error.to_string()),
            Err("KeyError: 'Nope'".to_owned())
        );
    }

    #[test]
    fn long_signature_from_eight_parameters() {
        assert_eq!(long_signature(0), "");
        assert_eq!(long_signature(7), "");
        assert_eq!(long_signature(8), format!("#[{LONG_SIGNATURE}] "));
    }

    #[test]
    fn native_binding_drops_the_agent_verb_door() {
        let row = |text: &str| match crate::py::json::loads(text) {
            Ok(Value::Dict(row)) => row,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            native_binding(&row(r#"{"name": "a"}"#)).map(|binding| binding.is_none()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": null}"#)).map(|binding| binding.is_none()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": {"native": "agent_verb"}}"#))
                .map(|binding| binding.is_none()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": {"native": "x"}}"#))
                .map(|binding| binding.is_some()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": {}}"#)).map(|binding| binding.is_some()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": []}"#)).map(|binding| binding.is_some()),
            Ok(true)
        );
        assert_eq!(
            native_binding(&row(r#"{"binding": [1]}"#))
                .map(|binding| binding.is_some())
                .map_err(|error| error.to_string()),
            Err("AttributeError: 'list' object has no attribute 'get'".to_owned())
        );
    }

    // print(re.findall(r'^export (?:type|interface) (\w+)', ts, re.M)) and the `class`/`=` findall of the same probe.
    #[test]
    fn hand_declared_names_match_pythons_findall() {
        let ts = "export type A = 1;\nexport interface B { }\nexport  type C = 2;\nexport type D<T> = T;\n  export type E = 3;\nexport typeF = 1;\nexport interface Ģé_9 {}\nexport type X\u{301}y = 1;\nexport class K {}\nexport type\n";
        assert_eq!(
            ts_declared_names(ts).into_iter().collect::<Vec<_>>(),
            ["A", "B", "D", "Ģé_9", "X"]
        );
        let py = "class Foo:\nclass Bar(Base):\nBaz = int\nclass = 5\nQux=1\n  Ind = 2\nclass Ünï(x):\nclass X\u{301}y: pass\nA_b = c = d\nclass  Two:\n_x = 1\n";
        assert_eq!(
            py_declared_names(py).into_iter().collect::<Vec<_>>(),
            ["Foo", "Bar", "Baz", "class", "Ünï", "X", "A_b", "_x"]
        );
    }

    // print(repr(t.format(**kw))) and print(repr(t), err(lambda t: t.format(name='v'), t)) of the same probe.
    #[test]
    fn str_format_is_pythons_for_named_fields() {
        assert_eq!(
            str_format("let {name} = {name}.into_engine()?;", &[("name", "x{y}")]),
            Ok("let x{y} = x{y}.into_engine()?;".to_owned())
        );
        assert_eq!(
            str_format(
                r#"let {name} = match {name} {{ Some(value) => decode(value, "recall scope")?, None => oneiron::memory::RecallScope::default() }};"#,
                &[("name", "scope")]
            ),
            Ok(r#"let scope = match scope { Some(value) => decode(value, "recall scope")?, None => oneiron::memory::RecallScope::default() };"#.to_owned())
        );
        assert_eq!(
            str_format("{name}.to_owned()", &[("name", "a}")]),
            Ok("a}.to_owned()".to_owned())
        );
        assert_eq!(str_format("{{", &[]), Ok("{".to_owned()));
        assert_eq!(str_format("}}", &[]), Ok("}".to_owned()));
        let refusals: &[(&str, &str)] = &[
            ("{name", "ValueError: expected '}' before end of string"),
            ("a}b", "ValueError: Single '}' encountered in format string"),
            ("{other}", "KeyError: 'other'"),
            ("{ name}", "KeyError: ' name'"),
        ];
        for &(template, expected) in refusals {
            assert_eq!(
                str_format(template, &[("name", "v")]).map_err(|error| error.to_string()),
                Err(expected.to_owned()),
                "{template:?}"
            );
        }
    }

    // python3 -I -c "import ast; ...": len(AGENT_VERBS_TS) == 5987, 38 newlines, the last character a newline.
    #[test]
    fn agent_verbs_ts_is_the_python_literal() {
        assert_eq!(AGENT_VERBS_TS.chars().count(), 5987);
        assert_eq!(AGENT_VERBS_TS.matches('\n').count(), 38);
        assert!(
            AGENT_VERBS_TS
                .starts_with("import type { RecordRef, TaskDescription as FacadeTaskDescription }")
        );
        assert!(AGENT_VERBS_TS.ends_with('\n'));
    }
}
