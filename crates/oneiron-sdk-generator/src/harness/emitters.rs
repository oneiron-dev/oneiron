//! `port-harness replay <log> --root <dir> --out-dir <dir> --until <name>[#<n>] [--out-files <dir>]` (DESIGN 9.3):
//! proves one emitter or inline segment of `outputs()` without the rest of the tree.
//!
//! `scripts/sdk/port_harness.py record` marks each emitter call in the log: `["enter", name, n]` before it runs and
//! `["leave", name, n, <its return value>]` after (n counts the calls of that name from 1). This replay builds the
//! `Generator` (generate.py's module level, which builds `INVENTORY`: the log's first `Inventory` line), replays
//! the log's Inventory calls in order, and at the enter line of `<name>` runs the Rust port registered for it here
//! (`EMITTERS`) on the replayed state:
//! - `--until <name>#<n>`: the nth call only. Its return value must equal the logged one. The state after the port
//!   is dumped to `<out-dir>/port`, and the state at the leave line, replayed from the log (the Python state there,
//!   as the replay proves), to `<out-dir>/log`; the driver diffs the two (and Python's own `record --dump-at`).
//! - `--until <name>`: every call of `<name>`, each port in place of the logged calls it made, then the rest of the
//!   log; the state at the end is dumped to `<out-dir>` for a diff with Python's final dump.
//!
//! A call Python raised in has an enter line and no leave line: the port must raise too, and its error is this
//! command's (the error fixtures compare it with `generate.py`'s last stderr line). `--out-files <dir>` writes the
//! outputs each checked value is, by repo path, for a diff with `generate.py --out-dir`'s files.
//!
//! The dumps leave out what the logged calls returned (`calls.jsonl` holds the replayed calls only): a port's own
//! Inventory calls are its own, and their effect is the state.

use std::fs;
use std::path::Path;

use super::replay::{Replayed, apply, dump, malformed, rows};
use crate::error::GenerateError;
use crate::generate::Generator;
use crate::py::json::{DumpOptions, dumps, loads};
use crate::py::value::{Dict, Value};

/// One ported emitter or inline segment, as the log's markers name it.
pub(crate) struct Emitter {
    /// The name the enter and leave lines carry.
    pub(crate) name: &'static str,
    /// The port, run for the nth call (from 1) on the generator replayed to that call's enter line. Its arguments
    /// are the ones `outputs()` passes on that call; it returns what the leave line logs (a tuple as a list).
    pub(crate) run: fn(&mut Generator, usize) -> Result<Value, GenerateError>,
    /// The outputs that value is, as `(repo path, text)`: none for a value that is no whole output file.
    pub(crate) files: fn(&Value) -> Vec<(&'static str, String)>,
}

/// Every port the replay can run at its marker (G4a's; G4b adds its own entries).
pub(crate) const EMITTERS: &[Emitter] = &[
    Emitter {
        name: "run_catalog",
        run: |generator, _| crate::generate::emit_core::run_catalog(generator).map(Value::Str),
        files: |value| {
            text_file(
                "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
                value,
            )
        },
    },
    Emitter {
        name: "core_verb_names",
        run: |generator, _| {
            let custody = crate::generate::emit_core::custody_rows(generator);
            crate::generate::emit_core::core_verb_names(generator, &custody).map(Value::Str)
        },
        files: |value| text_file(crate::generate::CORE_VERB_NAMES_PATH, value),
    },
    Emitter {
        name: "core",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            crate::generate::emit_core::core(generator, &facade_rows).map(Value::Str)
        },
        files: |value| text_file("crates/oneiron/src/verbs/generated/sdk_generated.rs", value),
    },
    Emitter {
        name: "catalog",
        run: |generator, _| {
            let catalog = crate::generate::emit_core::catalog(generator)?;
            // As the leave line logs `custody`: its rows' positions in ROWS.
            let positions = catalog
                .custody
                .iter()
                .filter_map(|id| generator.callable_rows.iter().position(|row| row == id))
                .map(|at| Value::Int(i64::try_from(at).unwrap_or(-1)))
                .collect();
            Ok(Value::List(vec![
                Value::Str(catalog.text),
                Value::List(positions),
            ]))
        },
        files: |value| {
            item_file(
                "crates/oneiron/src/verbs/generated/verb_catalog.rs",
                value,
                0,
            )
        },
    },
    Emitter {
        name: "host_door_rows",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            crate::generate::emit_server::host_door_rows(generator, &facade_rows).map(Value::Str)
        },
        files: |value| {
            text_file(
                "crates/oneiron-server/src/api/facade/generated/host_door_rows.rs",
                value,
            )
        },
    },
    Emitter {
        name: "facade_dispatch",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            let texts = crate::generate::emit_server::facade_dispatch(generator, &facade_rows)?;
            Ok(Value::List(vec![
                Value::Str(texts.routes),
                Value::Str(texts.dispatch),
            ]))
        },
        files: |value| {
            let mut files = item_file(
                "crates/oneiron-server/src/api/facade/generated/agent_verbs.rs",
                value,
                0,
            );
            files.extend(item_file(
                "crates/oneiron-server/src/api/facade/generated/dispatch.rs",
                value,
                1,
            ));
            files
        },
    },
    Emitter {
        name: "mcp_dispatch",
        run: |generator, _| crate::generate::emit_mcp::mcp_dispatch(generator).map(Value::Str),
        // generate.py:2525: the file is HEADER, `use super::*;` and the dispatch.
        files: |value| {
            value
                .as_str()
                .map(|text| {
                    vec![(
                        "crates/oneiron-server/src/api/mcp_gateway/generated/agent_verb_dispatch.rs",
                        format!("{}use super::*;\n{text}", crate::generate::HEADER),
                    )]
                })
                .unwrap_or_default()
        },
    },
    Emitter {
        name: "remote",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            crate::generate::emit_remote::remote(generator, &facade_rows).map(Value::Str)
        },
        files: |value| text_file("crates/oneiron-remote/src/generated/agent_verbs.rs", value),
    },
    Emitter {
        name: "remote_boundary",
        run: |generator, n| {
            let id = facade_row(generator, n.wrapping_sub(1))?;
            let boundary = crate::generate::emit_remote::remote_boundary(&generator.rows[id])?;
            Ok(Value::List(vec![
                Value::Str(boundary.declaration),
                Value::Str(boundary.setup),
                boundary.value,
            ]))
        },
        files: |_| Vec::new(),
    },
    Emitter {
        name: "napi_py",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            let texts = crate::generate::emit_native::napi_py(generator, &facade_rows)?;
            Ok(Value::List(vec![
                Value::Str(texts.napi),
                Value::Str(texts.py),
            ]))
        },
        files: |value| {
            let mut files = item_file(
                "crates/oneiron-napi/src/facade/client/generated/agent_verbs.rs",
                value,
                0,
            );
            // generate.py:2531: the PyO3 file wraps the methods.
            if let Some(py) = value
                .as_list()
                .and_then(|items| items.get(1))
                .and_then(Value::as_str)
            {
                files.push((
                    "crates/oneiron-py/src/generated/agent_verbs.rs",
                    format!(
                        "{}#[pymethods]\nimpl NativeClient {{\n{py}}}\n",
                        crate::generate::HEADER
                    ),
                ));
            }
            files
        },
    },
    Emitter {
        name: "native_boundary",
        // outputs() calls it twice per facade row: napi, then py.
        run: |generator, n| {
            let id = facade_row(generator, n.wrapping_sub(1) / 2)?;
            let language = if n % 2 == 1 { "napi" } else { "py" };
            crate::generate::emit_native::native_boundary(generator, id, language).map(Value::Str)
        },
        files: |_| Vec::new(),
    },
    // G3: generate.py:2902-2926. outputs()'s `facade_rows` (generate.py:2242) is FACADE_ROWS's expression
    // (generate.py:339) over the same rows, so it is `Generator::facade_rows`.
    Emitter {
        name: "uniffi_facade",
        run: |generator, _| {
            let facade_rows = generator.facade_rows.clone();
            let (arms, types) = crate::generate::uniffi::uniffi_facade(generator, &facade_rows)?;
            Ok(Value::List(vec![Value::Str(arms), Value::Str(types)]))
        },
        files: |value| match value.as_list() {
            Some([Value::Str(arms), Value::Str(types)]) => vec![
                (
                    "crates/oneiron-uniffi/src/generated/facade_generated.rs",
                    arms.clone(),
                ),
                (
                    "crates/oneiron-uniffi/src/generated/facade_types_generated.rs",
                    types.clone(),
                ),
            ],
            _ => Vec::new(),
        },
    },
];

/// The facade row at `at` (`facade_rows[at]` in outputs()), for a port called once per row.
fn facade_row(generator: &Generator, at: usize) -> Result<crate::generate::RowId, GenerateError> {
    generator
        .facade_rows
        .get(at)
        .copied()
        .ok_or_else(|| GenerateError::exit(format!("port-harness replay: no facade row {at}")))
}

/// `port-harness emitters`: the registered names, one per line.
pub(crate) fn list() {
    for emitter in EMITTERS {
        println!("{}", emitter.name);
    }
}

/// A value that is one whole output file.
fn text_file(path: &'static str, value: &Value) -> Vec<(&'static str, String)> {
    value
        .as_str()
        .map(|text| vec![(path, text.to_owned())])
        .unwrap_or_default()
}

/// Item `at` of a list value, as one whole output file.
fn item_file(path: &'static str, value: &Value, at: usize) -> Vec<(&'static str, String)> {
    value
        .as_list()
        .and_then(|items| items.get(at))
        .map(|item| text_file(path, item))
        .unwrap_or_default()
}

/// One line of the log.
enum Entry {
    /// `["marker", ...]` (G1b's, before `uniffi_facade`).
    Marker,
    /// `["enter", name, n]`.
    Enter(String, usize),
    /// `["leave", name, n, value]`.
    Leave(String, usize, Value),
    /// `[method, [inventory, args...]]`: one Inventory call.
    Call(String, usize, Vec<Value>),
}

fn read_log(log: &str) -> Result<Vec<(Entry, String)>, GenerateError> {
    let text = crate::py::read_text(Path::new(log))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        let entry = loads(line).map_err(|error| error.into_error(log))?;
        let count = |value: &Value| match value {
            Value::Int(n) => usize::try_from(*n).map_err(|_| malformed(line)),
            _ => Err(malformed(line)),
        };
        let parsed = match entry.as_list() {
            Some([Value::Str(kind), ..]) if kind == "marker" => Entry::Marker,
            Some([Value::Str(kind), Value::Str(name), n]) if kind == "enter" => {
                Entry::Enter(name.clone(), count(n)?)
            }
            Some([Value::Str(kind), Value::Str(name), n, value]) if kind == "leave" => {
                Entry::Leave(name.clone(), count(n)?, value.clone())
            }
            Some([Value::Str(method), Value::List(call)]) => {
                let id = call
                    .first()
                    .ok_or_else(|| malformed(line))
                    .and_then(count)?;
                Entry::Call(method.clone(), id, call.clone())
            }
            _ => return Err(malformed(line)),
        };
        entries.push((parsed, line.to_owned()));
    }
    Ok(entries)
}

/// The replayed state: the generator (whose `inventory` is the log's inventory 1) and the inventories built after it
/// (catalog_fragment's), with the rows each was built over and the calls replayed so far.
struct Replay {
    generator: Generator,
    first_rows: Vec<Dict>,
    later: Vec<Replayed>,
    calls: Vec<Value>,
}

impl Replay {
    fn new(root: &Path) -> Result<Self, GenerateError> {
        Ok(Self {
            generator: Generator::new(root)?,
            first_rows: Vec::new(),
            later: Vec::new(),
            calls: Vec::new(),
        })
    }

    /// Replays one Inventory call line.
    fn call(
        &mut self,
        root: &Path,
        method: &str,
        id: usize,
        call: &[Value],
        line: &str,
    ) -> Result<(), GenerateError> {
        let result = if method == "Inventory" {
            let logged = rows(call.get(1).ok_or_else(|| malformed(line))?, line)?;
            if id == 1 {
                // generate.py:343 `INVENTORY = Inventory(ROOT, FACADE_ROWS)`: `Generator::new` built it.
                self.first_rows = logged;
            } else {
                let refs: Vec<&Dict> = logged.iter().collect();
                let inventory = crate::facade_types::Inventory::new(root, &refs)?;
                self.later.push(Replayed {
                    inventory,
                    rows: logged,
                });
            }
            Value::None
        } else {
            let inventory = match id {
                1 => self.generator.inventory_mut()?,
                n => self
                    .later
                    .get_mut(n.wrapping_sub(2))
                    .map(|replayed| &mut replayed.inventory)
                    .ok_or_else(|| malformed(line))?,
            };
            apply(inventory, method, call, line)?
        };
        self.calls.push(Value::List(vec![
            Value::Str(method.to_owned()),
            Value::Int(i64::try_from(id).unwrap_or(0)),
            result,
        ]));
        Ok(())
    }

    /// The dump of `port-harness replay` (and `port_harness.py record`), of every inventory replayed so far.
    fn dump(&mut self, out: &Path) -> Result<(), GenerateError> {
        let inventory = self.generator.inventory.take().ok_or_else(|| {
            GenerateError::exit("port-harness replay: the generator holds no inventory")
        })?;
        let mut all = vec![Replayed {
            inventory,
            rows: self.first_rows.clone(),
        }];
        all.append(&mut self.later);
        let written = dump(out, &mut all, &self.calls);
        let mut all = all.into_iter();
        self.generator.inventory = all.next().map(|first| first.inventory);
        self.later = all.collect();
        written
    }
}

/// `--until <name>[#<n>]`.
pub(crate) fn until(
    log: &str,
    root: &Path,
    out: &Path,
    target: &str,
    out_files: Option<&Path>,
) -> Result<(), GenerateError> {
    let (name, only) = match target.split_once('#') {
        Some((name, n)) => (
            name,
            Some(n.parse::<usize>().map_err(|_| {
                GenerateError::exit(format!(
                    "port-harness replay: --until {target}: no call number"
                ))
            })?),
        ),
        None => (target, None),
    };
    let emitter = EMITTERS
        .iter()
        .find(|emitter| emitter.name == name)
        .ok_or_else(|| {
            GenerateError::exit(format!(
                "port-harness replay: no Rust port is registered for {name}"
            ))
        })?;
    let entries = read_log(log)?;
    let mut replay = Replay::new(root)?;
    let (mut checked, mut leave_at) = (0_usize, None);
    let mut at = 0;
    while at < entries.len() {
        let (entry, line) = &entries[at];
        match entry {
            Entry::Call(method, id, call) => replay.call(root, method, *id, call, line)?,
            Entry::Enter(entered, n) if entered == name && only.is_none_or(|only| only == *n) => {
                let leave = entries[at + 1..]
                    .iter()
                    .position(|(entry, _)| matches!(entry, Entry::Leave(left, k, _) if left == name && k == n))
                    .map(|offset| at + 1 + offset);
                // Python raised in this call: the port must raise too, and its error is this command's.
                let value = (emitter.run)(&mut replay.generator, *n)?;
                let Some(leave) = leave else {
                    return Err(GenerateError::exit(format!(
                        "port-harness replay: {name}#{n} returned where Python raised (its enter line has no leave line)"
                    )));
                };
                let Entry::Leave(_, _, logged) = &entries[leave].0 else {
                    return Err(malformed(&entries[leave].1));
                };
                compare(name, *n, &value, logged, out)?;
                if let Some(dir) = out_files {
                    write_files(dir, &(emitter.files)(&value))?;
                }
                checked += 1;
                if only.is_some() {
                    leave_at = Some(leave);
                    break;
                }
                // The port made this call's Inventory calls itself.
                at = leave + 1;
                continue;
            }
            Entry::Marker | Entry::Enter(..) | Entry::Leave(..) => {}
        }
        at += 1;
    }
    if checked == 0 {
        return Err(GenerateError::exit(format!(
            "port-harness replay: the log has no call of {target}"
        )));
    }
    match leave_at {
        None => {
            replay.dump(out)?;
        }
        Some(leave) => {
            replay.dump(&out.join("port"))?;
            // The state at the leave line, replayed from the log.
            let mut logged = Replay::new(root)?;
            for (entry, line) in &entries[..leave] {
                if let Entry::Call(method, id, call) = entry {
                    logged.call(root, method, *id, call, line)?;
                }
            }
            logged.dump(&out.join("log"))?;
        }
    }
    println!("## UNTIL {target} calls={checked} returns=same");
    Ok(())
}

/// The canonical text of a value: `json.dumps` with Python's defaults.
fn canonical(value: &Value) -> String {
    dumps(value, DumpOptions::default())
}

/// Fails unless the port's value is the logged one; on a difference, writes both under `out` (`<name>-<n>.port` and
/// `.log`, a text as itself and a list as one file per item) for a `diff`.
fn compare(
    name: &str,
    n: usize,
    port: &Value,
    logged: &Value,
    out: &Path,
) -> Result<(), GenerateError> {
    if canonical(port) == canonical(logged) {
        return Ok(());
    }
    fs::create_dir_all(out).map_err(|error| GenerateError::os(&error, out))?;
    for (side, value) in [("port", port), ("log", logged)] {
        let items: Vec<(String, &Value)> = match value {
            Value::List(items) => items
                .iter()
                .enumerate()
                .map(|(k, item)| (format!("{name}-{n}.{side}.{k}"), item))
                .collect(),
            _ => vec![(format!("{name}-{n}.{side}"), value)],
        };
        for (file, item) in items {
            let text = item.as_str().map_or_else(|| canonical(item), str::to_owned);
            let path = out.join(file);
            fs::write(&path, text).map_err(|error| GenerateError::os(&error, &path))?;
        }
    }
    Err(GenerateError::exit(format!(
        "port-harness replay: {name}#{n} returned another value than Python's (both under {})",
        out.display()
    )))
}

fn write_files(dir: &Path, files: &[(&str, String)]) -> Result<(), GenerateError> {
    for (path, text) in files {
        let target = dir.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| GenerateError::os(&error, parent))?;
        }
        fs::write(&target, text).map_err(|error| GenerateError::os(&error, &target))?;
    }
    Ok(())
}
