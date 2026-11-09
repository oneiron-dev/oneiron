//! `port-harness replay <log> --root <dir> --out-dir <dir> [--until-marker]` (brief 8.3): replays the call log
//! `scripts/sdk/port_harness.py record` wrote while `outputs()` ran, on the Rust `Inventory`, and writes the same
//! dump as the Python half: each inventory's state, its source index, its census, its TypeScript and Python
//! declarations, and every logged call's result. `diff -r` of the two directories proves the inventory port.
//!
//! The log's emitter markers (`enter` and `leave` lines, DESIGN 9.3) are no Inventory call: this replay passes over
//! them, and `--until <name>[#<n>]` replays to them and runs the Rust port there (`emitters.rs`).

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::GenerateError;
use crate::facade_types::Inventory;
use crate::facade_types::index::Index;
use crate::facade_types::{ItemKey, strings_value};
use crate::harness::flag;
use crate::py::json::{DumpOptions, dumps, loads};
use crate::py::value::{Dict, Value};

const USAGE: &str = "usage: oneiron-sdk-generator port-harness replay <log> --root <dir> --out-dir <dir> [--until-marker | --until <name>[#<n>] [--out-files <dir>]]";

/// One replayed inventory and the rows it was built over.
pub(super) struct Replayed {
    pub(super) inventory: Inventory,
    pub(super) rows: Vec<Dict>,
}

/// `port-harness replay`.
pub(crate) fn run(args: &[String]) -> Result<(), GenerateError> {
    let log = args
        .first()
        .filter(|arg| !arg.starts_with("--"))
        .ok_or_else(|| GenerateError::exit(USAGE))?;
    let root = flag(args, "--root", USAGE)?;
    let out = PathBuf::from(flag(args, "--out-dir", USAGE)?);
    let until_marker = args.iter().any(|arg| arg == "--until-marker");
    // Python's ROOT is `Path(__file__).resolve().parents[2]`: absolute, its symlinks resolved.
    let root =
        fs::canonicalize(root).map_err(|error| GenerateError::os(&error, Path::new(root)))?;
    if let Some(at) = args.iter().position(|arg| arg == "--until") {
        let target = args.get(at + 1).ok_or_else(|| GenerateError::exit(USAGE))?;
        let out_files = args
            .iter()
            .position(|arg| arg == "--out-files")
            .map(|at| {
                args.get(at + 1)
                    .map(PathBuf::from)
                    .ok_or_else(|| GenerateError::exit(USAGE))
            })
            .transpose()?;
        return super::emitters::until(log, &root, &out, target, out_files.as_deref());
    }
    let text = crate::py::read_text(Path::new(log))?;
    let mut replayed: Vec<Replayed> = Vec::new();
    let mut calls = Vec::new();
    for line in text.lines() {
        let entry = loads(line).map_err(|error| error.into_error(log))?;
        let (method, call) = match entry.as_list() {
            Some([Value::Str(method), call]) => (method.as_str(), call),
            Some([Value::Str(method), ..]) if method == "enter" || method == "leave" => continue,
            _ => return Err(malformed(line)),
        };
        if method == "marker" {
            if until_marker {
                break;
            }
            continue;
        }
        let call = call.as_list().ok_or_else(|| malformed(line))?;
        let id = match call.first() {
            Some(Value::Int(id)) => usize::try_from(*id).map_err(|_| malformed(line))?,
            _ => return Err(malformed(line)),
        };
        let argument = |n: usize| call.get(n).ok_or_else(|| malformed(line));
        let result = if method == "Inventory" {
            let rows = rows(argument(1)?, line)?;
            let refs: Vec<&Dict> = rows.iter().collect();
            let inventory = Inventory::new(&root, &refs)?;
            replayed.push(Replayed { inventory, rows });
            Value::None
        } else {
            let inventory = replayed
                .get_mut(id.wrapping_sub(1))
                .map(|r| &mut r.inventory)
                .ok_or_else(|| malformed(line))?;
            apply(inventory, method, call, line)?
        };
        calls.push(Value::List(vec![
            Value::Str(method.to_owned()),
            Value::Int(i64::try_from(id).unwrap_or(0)),
            result,
        ]));
    }
    dump(&out, &mut replayed, &calls)
}

/// Replays one logged call (`[method, [inventory, args...]]`) other than `Inventory` on its inventory, and returns
/// its result as the dump's `calls.jsonl` logs it.
pub(super) fn apply(
    inventory: &mut Inventory,
    method: &str,
    call: &[Value],
    line: &str,
) -> Result<Value, GenerateError> {
    let argument = |n: usize| call.get(n).ok_or_else(|| malformed(line));
    Ok(match method {
        "names.update" => {
            // catalog_fragment's `names.update(TAKEN)`: strings only; anything else is no log the
            // recorder writes.
            for name in argument(1)?.as_list().ok_or_else(|| malformed(line))? {
                inventory.names.insert(text_of(name, line)?.to_owned());
            }
            Value::None
        }
        "root_ir" => inventory.root_ir_value(argument(1)?)?.to_value(),
        "ts_type" => {
            let text = crate::facade_types::inventory::type_text(argument(1)?)?.to_owned();
            Value::Str(inventory.ts_type(&text, text_of(argument(2)?, line)?)?)
        }
        "py_type" => {
            let text = crate::facade_types::inventory::type_text(argument(1)?)?.to_owned();
            Value::Str(inventory.py_type(&text, text_of(argument(2)?, line)?)?)
        }
        "census" => {
            let rows = rows(argument(1)?, line)?;
            let refs: Vec<&Dict> = rows.iter().collect();
            strings_value(&inventory.census(&refs)?)
        }
        "typescript" => Value::Str(inventory.typescript(&lines(argument(1)?, line)?)?),
        "python" => Value::Str(inventory.python(&lines(argument(1)?, line)?)?),
        // The UniFFI projection reads the inventory without changing it; G3 replays it.
        "UniffiTypes" => Value::None,
        _ => return Err(malformed(line)),
    })
}

pub(super) fn malformed(line: &str) -> GenerateError {
    GenerateError::exit(format!(
        "port-harness replay: a log line it cannot read: {line}"
    ))
}

fn text_of<'v>(value: &'v Value, line: &str) -> Result<&'v str, GenerateError> {
    value.as_str().ok_or_else(|| malformed(line))
}

/// The logged rows: each row's `input` and `output`, a key absent where the row has none (Python's `row['output']`
/// on such a row is its `KeyError`, which a `None` would hide).
pub(super) fn rows(value: &Value, line: &str) -> Result<Vec<Dict>, GenerateError> {
    let rows = value.as_list().ok_or_else(|| malformed(line))?;
    rows.iter()
        .map(|row| match row {
            Value::Dict(row) if row.keys().all(|key| key == "input" || key == "output") => {
                Ok(row.clone())
            }
            _ => Err(malformed(line)),
        })
        .collect()
}

fn lines(value: &Value, line: &str) -> Result<Vec<String>, GenerateError> {
    let items = value.as_list().ok_or_else(|| malformed(line))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| malformed(line))
        })
        .collect()
}

// ---------------------------------------------------------------- the dump (port_harness.py `dump`)

fn write(path: &Path, text: &str) -> Result<(), GenerateError> {
    fs::write(path, text).map_err(|error| GenerateError::os(&error, path))
}

fn canonical(value: &Value) -> String {
    dumps(
        value,
        DumpOptions {
            ensure_ascii: true,
            sort_keys: true,
            indent: Some(1),
        },
    ) + "\n"
}

pub(super) fn dump(
    out: &Path,
    replayed: &mut [Replayed],
    calls: &[Value],
) -> Result<(), GenerateError> {
    fs::create_dir_all(out).map_err(|error| GenerateError::os(&error, out))?;
    for (n, entry) in replayed.iter_mut().enumerate() {
        let place = out.join(format!("inventory-{}", n + 1));
        fs::create_dir_all(&place).map_err(|error| GenerateError::os(&error, &place))?;
        write(
            &place.join("state.json"),
            &canonical(&state_dump(&mut entry.inventory)?),
        )?;
        write(
            &place.join("index.json"),
            &canonical(&index_dump(&entry.inventory.index)),
        )?;
        let refs: Vec<&Dict> = entry.rows.iter().collect();
        let census = entry.inventory.census(&refs)?;
        write(
            &place.join("census.txt"),
            &census
                .iter()
                .map(|line| format!("{line}\n"))
                .collect::<String>(),
        )?;
        write(
            &place.join("typescript.ts"),
            &entry.inventory.typescript(&census)?,
        )?;
        write(&place.join("python.pyi"), &entry.inventory.python(&census)?)?;
    }
    let calls: String = calls
        .iter()
        .map(|call| dumps(call, DumpOptions::default()) + "\n")
        .collect();
    write(&out.join("calls.jsonl"), &calls)
}

fn dict(entries: Vec<(&str, Value)>) -> Value {
    Value::Dict(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn list<T>(items: impl IntoIterator<Item = T>, each: impl Fn(T) -> Value) -> Value {
    Value::List(items.into_iter().map(each).collect())
}

fn text(value: &str) -> Value {
    Value::Str(value.to_owned())
}

fn sorted<S: AsRef<str>>(items: impl IntoIterator<Item = S>) -> Value {
    let mut items: Vec<String> = items
        .into_iter()
        .map(|item| item.as_ref().to_owned())
        .collect();
    items.sort();
    list(items, Value::Str)
}

/// `sorted(values, key=lambda v: (type(v).__name__, json.dumps(v)))`.
fn sorted_values(values: &[Value]) -> Value {
    let mut values: Vec<&Value> = values.iter().collect();
    values.sort_by_cached_key(|value| (value.type_name(), crate::facade_types::dumps(value)));
    list(values, Value::clone)
}

fn key_value(key: &ItemKey) -> Value {
    key.to_value()
}

fn count(n: usize) -> Value {
    Value::Int(i64::try_from(n).unwrap_or(i64::MAX))
}

/// The CRC-32 (zlib's) of a text's UTF-8 bytes, as eight lowercase hex digits.
fn crc(text: &str) -> Value {
    let mut table = [0_u32; 256];
    for (n, slot) in table.iter_mut().enumerate() {
        let mut c = u32::try_from(n).unwrap_or(0);
        for _ in 0..8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in text.as_bytes() {
        crc = table[usize::from(u8::try_from((crc ^ u32::from(byte)) & 0xFF).unwrap_or(0))]
            ^ (crc >> 8);
    }
    Value::Str(format!("{:08x}", crc ^ 0xFFFF_FFFF))
}

/// `len(text)`: code points.
fn length(text: &str) -> Value {
    count(text.chars().count())
}

fn state_dump(inventory: &mut Inventory) -> Result<Value, GenerateError> {
    let erased = inventory.py_erased()?;
    let mut decls = Vec::new();
    for (key, decl) in &inventory.decls {
        decls.push(Value::List(vec![
            key_value(key),
            text(&decl.name),
            strings_value(&decl.params),
            decl.ir
                .as_ref()
                .map_or(Value::None, crate::facade_types::Ir::to_value),
        ]));
    }
    let mut null_fields: Vec<&(String, Value)> = inventory.null_fields.iter().collect();
    null_fields.sort_by(|a, b| {
        (&a.0, dumps(&a.1, DumpOptions::default()))
            .cmp(&(&b.0, dumps(&b.1, DumpOptions::default())))
    });
    let variants = list(&inventory.variants, |(name, meta)| {
        Value::List(vec![
            text(name),
            dict(vec![
                ("tag", meta.tag.as_deref().map_or(Value::None, text)),
                ("content", meta.content.as_deref().map_or(Value::None, text)),
                ("untagged", Value::Bool(meta.untagged)),
                (
                    "variants",
                    list(&meta.variants, |variant| {
                        dict(vec![
                            ("name", text(&variant.name)),
                            ("label", variant.label.clone()),
                            ("untagged", Value::Bool(variant.untagged)),
                            ("other", Value::Bool(variant.other)),
                            ("shape", text(variant.shape.name())),
                            ("member", variant.member.to_value()),
                        ])
                    }),
                ),
            ]),
        ])
    });
    let context = &inventory.root_context;
    Ok(dict(vec![
        ("decls", Value::List(decls)),
        ("order", list(&inventory.order, |key| key_value(key))),
        ("names", sorted(&inventory.names)),
        ("names_not_str", sorted_values(&inventory.names_not_str)),
        (
            "fallbacks",
            list(&inventory.fallbacks, |(at, rust, reason)| {
                Value::List(vec![text(at), text(rust), text(reason)])
            }),
        ),
        (
            "opaques",
            list(&inventory.opaques, |(at, rust)| {
                Value::List(vec![text(at), text(rust)])
            }),
        ),
        ("variants", variants),
        (
            "null_fields",
            list(null_fields, |(owner, key)| {
                Value::List(vec![text(owner), key.clone()])
            }),
        ),
        ("closed", sorted(&inventory.closed)),
        ("redacted", sorted(&inventory.redacted)),
        (
            "roots",
            list(&inventory.roots, |(rust, ir)| {
                Value::List(vec![text(rust), ir.to_value()])
            }),
        ),
        (
            "preferred",
            list(&inventory.preferred, |(key, name)| {
                Value::List(vec![key_value(key), text(name)])
            }),
        ),
        (
            "root_context",
            Value::List(vec![
                text(&context.crate_name),
                text(&context.file),
                strings_value(&context.module),
            ]),
        ),
        ("py_erased", sorted(&erased)),
    ]))
}

/// A code-point offset from a byte offset into a file the index holds.
fn code_points(index: &Index, crate_name: &str, file: &str, at: usize) -> Value {
    let text = index
        .files
        .get(&(crate_name.to_owned(), file.to_owned()))
        .map_or("", String::as_str);
    count(text.get(..at).map_or(0, |head| head.chars().count()))
}

fn index_dump(index: &Index) -> Value {
    let item = |item: &crate::facade_types::index::ItemRef| {
        Value::List(vec![
            text(&item.crate_name),
            text(&item.file),
            strings_value(&item.module),
            text(item.kind.name()),
            Value::Bool(item.top),
            Value::Bool(item.public),
            text(&item.attrs),
            strings_value(&item.generics),
            crc(&item.body),
            length(&item.body),
            text(item.shape.name()),
        ])
    };
    let impls = |map: &indexmap::IndexMap<String, Vec<(String, String, usize)>>| {
        list(map, |(name, entries)| {
            Value::List(vec![
                text(name),
                list(entries, |(crate_name, file, at)| {
                    Value::List(vec![
                        text(crate_name),
                        text(file),
                        code_points(index, crate_name, file, *at),
                    ])
                }),
            ])
        })
    };
    dict(vec![
        ("loaded", sorted(&index.loaded)),
        (
            "files",
            list(&index.files, |((crate_name, file), body)| {
                Value::List(vec![text(crate_name), text(file), crc(body), length(body)])
            }),
        ),
        (
            "modules",
            list(&index.modules, |((crate_name, module), file)| {
                Value::List(vec![text(crate_name), strings_value(module), text(file)])
            }),
        ),
        (
            "items",
            list(&index.items, |(name, items)| {
                Value::List(vec![text(name), list(items, item)])
            }),
        ),
        ("impls", impls(&index.impls)),
        ("de_impls", impls(&index.de_impls)),
        (
            "macro_uses",
            list(&index.macro_uses, |(name, entries)| {
                Value::List(vec![
                    text(name),
                    list(entries, |(crate_name, file, macro_name)| {
                        Value::List(vec![text(crate_name), text(file), text(macro_name)])
                    }),
                ])
            }),
        ),
        (
            "macros",
            list(&index.macros, |(name, body)| {
                Value::List(vec![text(name), crc(body), length(body)])
            }),
        ),
        (
            "use_cache",
            list(&index.use_cache, |((crate_name, file), uses)| {
                Value::List(vec![
                    Value::List(vec![text(crate_name), text(file)]),
                    dict(vec![
                        (
                            "names",
                            list(&uses.names, |(alias, path)| {
                                Value::List(vec![text(alias), strings_value(path)])
                            }),
                        ),
                        ("globs", list(&uses.globs, |path| strings_value(path))),
                    ]),
                ])
            }),
        ),
        ("guesses", sorted(&index.guesses)),
    ])
}
