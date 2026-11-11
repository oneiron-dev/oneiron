//! `port-harness rows --root <dir> --out <file>`: generate.py's module-level row sets and constants, as
//! `scripts/sdk/port_harness.py rows` dumps them from Python (`json.dumps(dump, indent=1)`, insertion order).
//!
//! `ROW_OBJECTS` holds every row object once, after the module-level mutations, in the order the store keeps them
//! (the verb rows, then the synthetic host rows); each set is the list of its rows' indexes there, so the dump also
//! proves which sets share an object.

use std::path::Path;

use crate::error::GenerateError;
use crate::generate::{
    CORE_COUNT_DEFAULTS, CORE_VERB_NAMES, CORE_VERB_NAMES_PATH, Generator, HEADER,
    MCP_NONE_CONTEXTS, MCP_SCOPES, RowId, SESSION_READS,
};
use crate::py::json::{DumpOptions, dumps};
use crate::py::value::{Dict, Value};

const USAGE: &str = "usage: oneiron-sdk-generator port-harness rows --root <dir> --out <file>";

fn ids(ids: &[RowId]) -> Value {
    Value::List(
        ids.iter()
            .map(|id| Value::Int(i64::try_from(id.0).unwrap_or(i64::MAX)))
            .collect(),
    )
}

fn strs(texts: &[&str]) -> Value {
    Value::List(
        texts
            .iter()
            .map(|text| Value::Str((*text).to_owned()))
            .collect(),
    )
}

/// The dump, in generate.py's module order.
fn rows_dump(generator: &Generator) -> Value {
    let mut dump = Dict::new();
    let mut put = |key: &str, value: Value| {
        dump.insert(key.to_owned(), value);
    };
    put(
        "ROW_OBJECTS",
        Value::List(generator.rows.iter().cloned().map(Value::Dict).collect()),
    );
    let mut manifest = Dict::new();
    manifest.insert("verbs".to_owned(), ids(&generator.manifest));
    put("MANIFEST", Value::Dict(manifest));
    put("HOST_ROWS", ids(&generator.host_rows));
    put("HOST_RUN_ROWS", ids(&generator.host_run_rows));
    put("HOST_BROWSER_ROWS", ids(&generator.host_browser_rows));
    put("HOST_BOARD_ROWS", ids(&generator.host_board_rows));
    put("BROWSER_ROWS", ids(&generator.browser_rows));
    put("ROWS", ids(&generator.callable_rows));
    put("BOARD_HOST_ROWS", ids(&generator.board_host_rows));
    let mut names = generator.board_host_names.clone();
    names.sort_by_key(Value::repr);
    put("BOARD_HOST_NAMES", Value::List(names));
    put("DEFINITIONS", ids(&generator.definitions));
    put("RUN_ROWS", ids(&generator.run_rows));
    put("SESSION_READS", strs(SESSION_READS));
    put("CODE_MODE_ROWS", ids(&generator.code_mode_rows));
    put("SCHEMA_ROWS", ids(&generator.schema_rows));
    put("MCP_NONE_CONTEXTS", strs(MCP_NONE_CONTEXTS));
    put("MCP_SCOPES", strs(MCP_SCOPES));
    put("HEADER", Value::Str(HEADER.to_owned()));
    put("FACADE_ROWS", ids(&generator.facade_rows));
    // The rows handed to `Inventory(ROOT, FACADE_ROWS)`, one list per call.
    put("INVENTORY", Value::List(vec![ids(&generator.facade_rows)]));
    put("mcp_rows()", ids(&generator.mcp_rows()));
    put("CORE_VERB_NAMES", strs(CORE_VERB_NAMES));
    put("CORE_COUNT_DEFAULTS", strs(CORE_COUNT_DEFAULTS));
    put(
        "CORE_VERB_NAMES_PATH",
        Value::Str(CORE_VERB_NAMES_PATH.to_owned()),
    );
    Value::Dict(dump)
}

pub(crate) fn run(args: &[String]) -> Result<(), GenerateError> {
    let root = super::flag(args, "--root", USAGE)?;
    let out = super::flag(args, "--out", USAGE)?;
    let generator = Generator::new(Path::new(root))?;
    let text = dumps(
        &rows_dump(&generator),
        DumpOptions {
            indent: Some(1),
            ..DumpOptions::default()
        },
    );
    super::write(out, &format!("{text}\n"))
}
