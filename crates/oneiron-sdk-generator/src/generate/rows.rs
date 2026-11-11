//! Port of generate.py's module level, lines 16-343: the verb rows' validation and the row sets, in source order
//! (Sol's map 1.7). Each check keeps Python's evaluation order and short-circuits, its truthiness and `is True`, and
//! the error Python raises when a malformed row meets an operation of the wrong type.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::{Generator, MCP_NONE_CONTEXTS, MCP_SCOPES, RowId, RowStore, SESSION_READS};
use crate::error::GenerateError;
use crate::facade_types::{Inventory, type_names};
use crate::py::re::compile_fullmatch;
use crate::py::text::{repr_str, repr_str_tuple, strip};
use crate::py::value::{Dict, Value, set_add};
use crate::verb_table::load_verbs;

// The `re.fullmatch` patterns, each beside the Python one (all ASCII classes, so Python's and Rust's agree).
/// generate.py:93 `[A-Za-z_][A-Za-z0-9_]*`
static FIELD_NAME: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[A-Za-z_][A-Za-z0-9_]*"));
/// generate.py:215 `[A-Za-z0-9][A-Za-z0-9._-]*`
static ATTACHMENT: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*"));
/// generate.py:262 `(crate|super|self)(::[A-Za-z_][A-Za-z0-9_]*)+`
static REFS_CHECK: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"(crate|super|self)(::[A-Za-z_][A-Za-z0-9_]*)+"));
/// generate.py:268 `(/(\*|[a-z_][a-z0-9_]*))+`
static REF_POINTER: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"(/(\*|[a-z_][a-z0-9_]*))+"));
/// generate.py:288 `[a-z_][a-z0-9_]*(\[\*\])?(\.[a-z_][a-z0-9_]*(\[\*\])?)*`
static READABLE: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"[a-z_][a-z0-9_]*(\[\*\])?(\.[a-z_][a-z0-9_]*(\[\*\])?)*"));
/// generate.py:302 `(/(\*(\[[a-z_][a-z0-9_]*=[a-z0-9_]+\])?|[a-z_][a-z0-9_]*))+`
static PROSE_POINTER: LazyLock<Regex> = LazyLock::new(|| {
    compile_fullmatch(r"(/(\*(\[[a-z_][a-z0-9_]*=[a-z0-9_]+\])?|[a-z_][a-z0-9_]*))+")
});
/// generate.py:321 `[a-z_][a-z0-9_]*`
static ARG_NAME: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[a-z_][a-z0-9_]*"));
/// generate.py:333 `[ -~]{1,240}\.`
static DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[ -~]{1,240}\."));

/// generate.py:32: the keys a host projection may hold.
const HOST_KEYS: &[&str] = &[
    "input",
    "output",
    "description",
    "host_door_caller",
    "host_door_session",
    "host_door_lists",
    "host_door_precheck",
    "host_door_proof",
    "openapi",
];
/// generate.py:34: the host projection's flags, each a bool.
const HOST_FLAGS: &[&str] = &[
    "host_door_caller",
    "host_door_session",
    "host_door_lists",
    "host_door_precheck",
    "openapi",
];
/// generate.py:80: the keys a run row may hold beside its required ones, and the required ones.
const RUN_OPTIONAL: &[&str] = &["output", "outputs_by_input", "host", "run_surface"];
const RUN_REQUIRED: &[&str] = &["name", "input", "scope", "context", "effect"];
/// generate.py:113: a scoped-child row's keys, `description` aside.
const SCOPED_CHILD_KEYS: &[&str] = &[
    "name", "input", "output", "call", "scope", "context", "mcp", "section",
];
/// generate.py:239: the record-scope admissions `require_granted_scope` excludes.
const OTHER_RECORD_SCOPES: &[&str] = &[
    "owner_grade",
    "claim_record_scope",
    "credential_record_scope",
    "scoped_export",
    "born_record_scope",
];

/// `row[key]`.
fn item<'a>(row: &'a Dict, key: &str) -> Result<&'a Value, GenerateError> {
    row.get(key).ok_or_else(|| GenerateError::key(key))
}

/// `row.get(key)`, truthy.
fn flag(row: &Dict, key: &str) -> bool {
    row.get(key).is_some_and(Value::truthy)
}

/// `row.get(key) == text`.
fn is(row: &Dict, key: &str, text: &str) -> bool {
    row.get(key).is_some_and(|value| value.is_str(text))
}

/// `row[key] in (texts...)`.
fn item_in(row: &Dict, key: &str, texts: &[&str]) -> Result<bool, GenerateError> {
    let value = item(row, key)?;
    Ok(texts.iter().any(|text| value.is_str(text)))
}

/// `row.get('context', 'memory') != 'memory'`.
fn not_memory(row: &Dict) -> bool {
    row.get("context")
        .is_some_and(|context| !context.is_str("memory"))
}

/// `row.get('admission', {}).get(key)`, truthy; a row's `admission` that is no dict has no `get`.
fn admission_flag(row: &Dict, key: &str) -> Result<bool, GenerateError> {
    match row.get("admission") {
        None => Ok(false),
        Some(admission) => Ok(admission.dict_get(key)?.is_some_and(Value::truthy)),
    }
}

/// `ValueError(f'{row["name"]}: {message}')`.
fn refuse(row: &Dict, message: &str) -> GenerateError {
    match row.get("name") {
        Some(name) => GenerateError::value(format!("{}: {message}", name.str())),
        None => GenerateError::key("name"),
    }
}

/// `set(keys) == {texts...}` for a dict's keys.
fn keys_are(keys: &BTreeSet<&str>, texts: &[&str]) -> bool {
    keys.len() == texts.len() && texts.iter().all(|text| keys.contains(text))
}

/// `a == b` between two row names in `x in {names}`, where Python also takes an object as equal to itself: a NaN
/// name (one file, `nan.json`, can hold one) is the same object wherever it is compared, so it equals itself here.
fn same_name(a: &Value, b: &Value) -> bool {
    a.py_eq(b) || matches!((a, b), (Value::Float(x), Value::Float(y)) if x.is_nan() && y.is_nan())
}

/// `isinstance(x, str) and re.fullmatch(pattern, x)` over every item: generate.py:268 and :302 (`refs`,
/// `prose_links`): `not pointers or len(set(pointers)) != len(pointers) or not all(...)`, negated.
fn distinct_pointers(pointers: &Value, pattern: &Regex) -> Result<bool, GenerateError> {
    if !pointers.truthy() {
        return Ok(false);
    }
    if pointers.to_set()?.len() != pointers.py_len()? {
        return Ok(false);
    }
    Ok(pointers
        .iterate()?
        .iter()
        .all(|p| p.as_str().is_some_and(|p| pattern.is_match(p))))
}

/// `re.fullmatch(pattern, value)` of a value that may be no string: Python's `TypeError` then.
fn fullmatch(pattern: &Regex, value: &Value) -> Result<bool, GenerateError> {
    match value {
        Value::Str(text) => Ok(pattern.is_match(text)),
        _ => Err(GenerateError::type_error(format!(
            "expected string or bytes-like object, got '{}'",
            value.type_name()
        ))),
    }
}

/// Port of generate.py:36-50 (host_synthetic): a run, browser or board row's facade-only host projection. Python
/// evaluates the dict literal left to right, so `row['output']` is read before the host's own `output`.
fn host_synthetic(row: &Dict) -> Result<Dict, GenerateError> {
    let name = item(row, "name")?;
    let mut out = Dict::new();
    out.insert("name".into(), name.clone());
    out.insert("input".into(), item(row, "host")?.getitem("input")?.clone());
    let row_output = item(row, "output")?;
    let host = item(row, "host")?;
    out.insert(
        "output".into(),
        host.dict_get("output")?.unwrap_or(row_output).clone(),
    );
    out.insert("description".into(), host.getitem("description")?.clone());
    out.insert("scope".into(), item(row, "scope")?.clone());
    let call = format!(
        "crate::task_verb::sdk::host_only(memory, \"{}\", &input)?",
        name.str()
    );
    out.insert("call".into(), Value::Str(call));
    out.insert("host_door".into(), Value::Bool(true));
    let host_get = |key: &str, default: bool| -> Result<Value, GenerateError> {
        Ok(host.dict_get(key)?.cloned().unwrap_or(Value::Bool(default)))
    };
    out.insert(
        "host_door_session".into(),
        host_get("host_door_session", true)?,
    );
    out.insert(
        "host_door_caller".into(),
        host_get("host_door_caller", false)?,
    );
    // `row.get('context') == 'browser' or row['host'].get('host_door_lists', False)`: `or` returns an operand.
    let lists = if is(row, "context", "browser") {
        Value::Bool(true)
    } else {
        host_get("host_door_lists", false)?
    };
    out.insert("host_door_lists".into(), lists);
    out.insert(
        "host_door_precheck".into(),
        host_get("host_door_precheck", true)?,
    );
    if host.contains_str("host_door_proof")? {
        out.insert(
            "host_door_proof".into(),
            host.getitem("host_door_proof")?.clone(),
        );
    }
    out.insert("openapi".into(), host_get("openapi", false)?);
    let mut admission = Dict::new();
    admission.insert("unrestricted_record_scope".into(), Value::Bool(true));
    out.insert("admission".into(), Value::Dict(admission));
    out.insert("section".into(), Value::Bool(false));
    Ok(out)
}

/// Port of generate.py:29-35: a host projection names the public input and description, with optional flags.
fn check_host(row: &Dict) -> Result<(), GenerateError> {
    let host = item(row, "host")?;
    let context = row.get("context");
    let in_set = |set: &[Value], text: &str| set.iter().any(|item| item.is_str(text));
    let bad = !context.is_some_and(|c| ["run", "browser", "board"].iter().any(|k| c.is_str(k)))
        || {
            let keys = host.to_set()?;
            !(in_set(&keys, "input") && in_set(&keys, "description"))
        }
        || host
            .to_set()?
            .iter()
            .any(|key| !key.as_str().is_some_and(|key| HOST_KEYS.contains(&key)))
        || (host.contains_str("output")? && !context.is_some_and(|c| c.is_str("board")))
        || {
            let mut not_bool = false;
            for key in HOST_FLAGS {
                if host.contains_str(key)? && !matches!(host.getitem(key)?, Value::Bool(_)) {
                    not_bool = true;
                    break;
                }
            }
            not_bool
        };
    if bad {
        return Err(refuse(
            row,
            "a host projection names the public input and description, with optional caller, session, lists, \
             pre-check and OpenAPI flags",
        ));
    }
    Ok(())
}

/// Port of generate.py:67-75: the role fields (custody, overlay_write, session_read, run_surface).
fn check_metadata(row: &Dict) -> Result<(), GenerateError> {
    if let Some(custody) = row.get("custody")
        && (!is(row, "scope", "Write") || !matches!(custody, Value::Str(_)))
    {
        return Err(refuse(
            row,
            "`custody` names the input member of a Write row",
        ));
    }
    if let Some(overlay_write) = row.get("overlay_write")
        && (!overlay_write.is_true() || !is(row, "scope", "Write"))
    {
        return Err(refuse(row, "`overlay_write` is `true` on a Write row"));
    }
    if let Some(session_read) = row.get("session_read")
        && (!SESSION_READS.iter().any(|read| session_read.is_str(read))
            || !is(row, "scope", "Read"))
    {
        let message = format!(
            "`session_read` is one of {} on a Read row",
            repr_str_tuple(SESSION_READS)
        );
        return Err(refuse(row, &message));
    }
    if let Some(run_surface) = row.get("run_surface")
        && (!(run_surface.is_str("memory") || run_surface.is_str("live"))
            || !is(row, "context", "run"))
    {
        return Err(refuse(
            row,
            "`run_surface` is `memory` or `live` on a run row",
        ));
    }
    Ok(())
}

/// Port of generate.py:79-81: a run row's key set.
fn check_run_row(row: &Dict) -> Result<(), GenerateError> {
    let keys: BTreeSet<&str> = row
        .keys()
        .map(String::as_str)
        .filter(|key| !RUN_OPTIONAL.contains(key))
        .collect();
    if !keys_are(&keys, RUN_REQUIRED) || !item_in(row, "scope", &["Read", "Write"])? {
        return Err(refuse(
            row,
            "a run row names its input, scope, effect, output, per-input outputs and run surface, and nothing else",
        ));
    }
    Ok(())
}

/// Port of generate.py:89-95: `outputs_by_input` maps input field names to non-empty output types.
fn check_outputs_by_input(row: &Dict) -> Result<(), GenerateError> {
    let Some(by_input) = row.get("outputs_by_input") else {
        return Ok(());
    };
    let valid = |dict: &Dict| {
        dict.iter().all(|(field, output)| {
            FIELD_NAME.is_match(field)
                && output
                    .as_str()
                    .is_some_and(|output| !strip(output).is_empty())
        })
    };
    if !row.contains_key("output")
        || !by_input
            .as_dict()
            .is_some_and(|dict| !dict.is_empty() && valid(dict))
    {
        return Err(refuse(
            row,
            "outputs_by_input maps input field names to non-empty output types, beside the row's own output",
        ));
    }
    Ok(())
}

/// Port of generate.py:111-116: a scoped-child row's shape.
fn check_scoped_child(row: &Dict) -> Result<(), GenerateError> {
    if !is(row, "context", "scoped_child") {
        return Ok(());
    }
    let keys: BTreeSet<&str> = row
        .keys()
        .map(String::as_str)
        .filter(|&key| key != "description")
        .collect();
    let bad = !keys_are(&keys, SCOPED_CHILD_KEYS)
        || !item_in(row, "scope", &["Read", "Write"])?
        || item(row, "section")?.truthy()
        || {
            let call = format!(
                "crate::task_verb::sdk::host_only(memory, \"{}\", &input)?",
                item(row, "name")?.str()
            );
            !item(row, "call")?.is_str(&call)
        };
    if bad {
        return Err(refuse(
            row,
            "a scoped-child row names its input, output, scope and description, calls the host-only refusal, and \
             nothing else",
        ));
    }
    Ok(())
}

/// Port of generate.py:123-124: the row's MCP scope and fields, after their defaults.
fn check_mcp(row: &Dict) -> Result<(), GenerateError> {
    let scope = item(row, "mcp_scope")?;
    scope.check_hashable("a set element")?;
    if !MCP_SCOPES.iter().any(|known| scope.is_str(known)) {
        let sorted: Vec<String> = MCP_SCOPES.iter().map(|known| repr_str(known)).collect();
        return Err(refuse(
            row,
            &format!("mcp_scope must be one of [{}]", sorted.join(", ")),
        ));
    }
    for path in item(row, "mcp_fields")?.dict_values()? {
        if path.contains_str(".")? {
            return Err(refuse(
                row,
                "an MCP field maps onto one top-level input field",
            ));
        }
    }
    Ok(())
}

/// Port of generate.py:128-233: the door flags of one row.
fn check_doors(row: &Dict) -> Result<(), GenerateError> {
    if flag(row, "proposes") && !item(row, "scope")?.is_str("Write") {
        return Err(refuse(row, "only a Write row proposes"));
    }
    if flag(row, "lands_turn") && !item(row, "scope")?.is_str("Write") {
        return Err(refuse(row, "only a Write row lands a turn"));
    }
    if flag(row, "lands_turn") && is(row, "context", "board") {
        return Err(refuse(row, "a board verb lands no turn"));
    }
    let host_door = flag(row, "host_door");
    if host_door
        && (flag(row, "server_door") || admission_flag(row, "owner_grade")? || not_memory(row))
    {
        return Err(refuse(
            row,
            "a host door is a memory row with no other server door",
        ));
    }
    for (key, message) in [
        ("host_door_caller", "only a host door takes its caller"),
        ("host_door_session", "only a host door takes its session"),
        ("host_door_lists", "only a host door lists its rows"),
    ] {
        if flag(row, key) && !host_door {
            return Err(refuse(row, message));
        }
    }
    if let Some(precheck) = row.get("host_door_precheck")
        && !precheck.is_true()
        && (!precheck.is_false() || !host_door)
    {
        return Err(refuse(
            row,
            "host_door_precheck is only a host door's, and only false",
        ));
    }
    for (key, message) in [
        ("host_door_paced", "only a host door takes a paced context"),
        (
            "host_door_lens_owner",
            "only a host door takes a lens owner",
        ),
        (
            "host_door_client_surface",
            "only a host door takes a client surface",
        ),
        ("host_door_surface", "only a host door takes an act surface"),
    ] {
        if flag(row, key) && !host_door {
            return Err(refuse(row, message));
        }
    }
    if flag(row, "task_work")
        && (host_door
            || flag(row, "server_door")
            || admission_flag(row, "owner_grade")?
            || readable_has_rows(row)?
            || not_memory(row))
    {
        return Err(refuse(row, "task work is a plain memory row"));
    }
    if flag(row, "openapi") && not_memory(row) {
        return Err(refuse(row, "only a facade row is published in OpenAPI"));
    }
    if let Some(attachment) = row.get("attachment")
        && (not_memory(row)
            || !attachment
                .as_str()
                .is_some_and(|name| ATTACHMENT.is_match(name)))
    {
        return Err(refuse(
            row,
            "an attachment names a facade JSON response file",
        ));
    }
    if flag(row, "no_record") && (not_memory(row) || !host_door) {
        return Err(refuse(
            row,
            "only a host-door facade row keeps no call receipt",
        ));
    }
    Ok(())
}

/// generate.py:203 `'rows' in row.get('admission', {}).get('readable', [])`.
fn readable_has_rows(row: &Dict) -> Result<bool, GenerateError> {
    let Some(admission) = row.get("admission") else {
        return Ok(false);
    };
    match admission.dict_get("readable")? {
        None => Ok(false),
        Some(readable) => readable.contains_str("rows"),
    }
}

/// Port of generate.py:234-252: `require_granted_scope` and `mcp_off_runtime`.
fn check_admission(row: &Dict) -> Result<(), GenerateError> {
    // `admission = row.get('admission', {})`, then `admission.get(...)`: always read, so an admission that is no
    // dict fails here whatever it holds.
    let admission = row.get("admission");
    let admission_get = |key: &str| -> Result<bool, GenerateError> {
        match admission {
            None => Ok(false),
            Some(admission) => Ok(admission.dict_get(key)?.is_some_and(Value::truthy)),
        }
    };
    if admission_get("require_granted_scope")?
        && (!admission_get("lane_record_scope")?
            || is(row, "scope", "Read")
            || (flag(row, "host_door")
                && !(flag(row, "host_door_caller") || flag(row, "host_door_lists")))
            || not_memory(row)
            || {
                let mut any = false;
                for other in OTHER_RECORD_SCOPES {
                    if admission_get(other)? {
                        any = true;
                        break;
                    }
                }
                any
            })
    {
        return Err(refuse(
            row,
            "require_granted_scope is only a non-Read lane_record_scope facade row's, with no other record-scope \
             admission, and on a host door only a caller or listing one",
        ));
    }
    if flag(row, "mcp_off_runtime")
        && (flag(row, "task_decisions")
            || flag(row, "task_work")
            || flag(row, "host_door")
            || flag(row, "server_door")
            || not_memory(row)
            || admission_flag(row, "owner_grade")?)
    {
        return Err(refuse(
            row,
            "mcp_off_runtime is only a plain memory row's, with no ladder, turn or door",
        ));
    }
    Ok(())
}

/// Port of generate.py:260-269: `refs_check` and `refs`.
fn check_refs(row: &Dict) -> Result<(), GenerateError> {
    if let Some(refs_check) = row.get("refs_check")
        && (!row.contains_key("refs")
            || !refs_check
                .as_str()
                .is_some_and(|path| REFS_CHECK.is_match(path)))
    {
        return Err(refuse(
            row,
            "refs_check is a Rust fn path (crate::...), and only beside refs",
        ));
    }
    let Some(pointers) = row.get("refs") else {
        return Ok(());
    };
    if not_memory(row)
        || flag(row, "host_door")
        || flag(row, "server_door")
        || admission_flag(row, "owner_grade")?
    {
        return Err(refuse(
            row,
            "only a plain memory row checks its record refs in its engine fn",
        ));
    }
    if !distinct_pointers(pointers, &REF_POINTER)? {
        return Err(refuse(
            row,
            "refs are distinct JSON pointers of field names and `*`",
        ));
    }
    Ok(())
}

/// Port of generate.py:273-277: `file_call`.
fn check_file_call(row: &Dict) -> Result<(), GenerateError> {
    let Some(file_call) = row.get("file_call") else {
        return Ok(());
    };
    if !matches!(file_call, Value::Str(_))
        || not_memory(row)
        || flag(row, "host_door")
        || flag(row, "server_door")
        || row.contains_key("prose_links")
        || !file_call.contains_str("body")?
    {
        return Err(refuse(
            row,
            "file_call is a plain memory row's engine call on `body`",
        ));
    }
    Ok(())
}

/// Port of generate.py:286-289: each `readable` entry.
fn check_readable(row: &Dict) -> Result<(), GenerateError> {
    let Some(admission) = row.get("admission") else {
        return Ok(());
    };
    let Some(readable) = admission.dict_get("readable")? else {
        return Ok(());
    };
    for entry in readable.iterate()? {
        if !entry.is_str("rows") && !fullmatch(&READABLE, &entry)? {
            return Err(refuse(
                row,
                "readable entries are `rows` or field paths of `.` and `[*]`",
            ));
        }
    }
    Ok(())
}

/// Port of generate.py:297-303: `prose_links`.
fn check_prose_links(row: &Dict) -> Result<(), GenerateError> {
    let Some(pointers) = row.get("prose_links") else {
        return Ok(());
    };
    if not_memory(row)
        || flag(row, "host_door")
        || flag(row, "server_door")
        || admission_flag(row, "owner_grade")?
    {
        return Err(refuse(
            row,
            "only a plain memory row reads its prose links in its engine fn",
        ));
    }
    if !distinct_pointers(pointers, &PROSE_POINTER)? {
        return Err(refuse(
            row,
            "prose_links are distinct JSON pointers of field names, `*` and `*[key=value]`",
        ));
    }
    Ok(())
}

/// generate.py:320-322: one generic binding argument's shape.
fn valid_generic_arg(arg: &Value) -> Result<bool, GenerateError> {
    let Some(arg) = arg.as_dict() else {
        return Ok(false);
    };
    let named = arg.contains_key("name") && arg.contains_key("type");
    if !named
        || arg
            .keys()
            .any(|key| !["name", "type", "field", "default"].contains(&key.as_str()))
    {
        return Ok(false);
    }
    if !fullmatch(&ARG_NAME, item(arg, "name")?)? {
        return Ok(false);
    }
    let Value::Str(ty) = item(arg, "type")? else {
        return Ok(false);
    };
    Ok(match arg.get("default") {
        None => true,
        Some(default) => matches!(default, Value::Str(_)) && !ty.starts_with("Option<"),
    })
}

/// Port of generate.py:314-325: a generic binding's shape; whether the row has one to move.
fn check_generic_binding(row: &Dict) -> Result<bool, GenerateError> {
    let Some(binding) = row.get("binding") else {
        return Ok(false);
    };
    if !binding.truthy() || !binding.dict_get("generic")?.is_some_and(Value::truthy) {
        return Ok(false);
    }
    let args = binding.dict_get("args")?;
    let keys = binding.to_set()?;
    let shape = keys.len() == 2
        && keys
            .iter()
            .all(|key| key.is_str("generic") || key.is_str("args"));
    let args = match args {
        Some(Value::List(args)) if shape && !not_memory(row) && !row.contains_key("uniffi") => args,
        _ => {
            return Err(refuse(
                row,
                "a generic binding is a memory row's `generic` and `args`, with no uniffi signature",
            ));
        }
    };
    for arg in args {
        if !valid_generic_arg(arg)? {
            return Err(refuse(
                row,
                "a generic binding arg names its parameter and Rust type, and may name its field and a string \
                 default of a type that is no Option",
            ));
        }
        // A valid argument is a dict.
        let Some(arg) = arg.as_dict() else { continue };
        if is(arg, "field", "$")
            && (args.len() != 1
                || !item(arg, "type")?.py_eq(item(row, "input")?)
                || arg.contains_key("default"))
        {
            return Err(refuse(
                row,
                "a whole-input parameter is the row's only one, typed as its input",
            ));
        }
    }
    Ok(true)
}

/// Port of generate.py:330-334: a callable row's one-line description.
fn check_description(row: &Dict) -> Result<(), GenerateError> {
    let Some(text) = row.get("description") else {
        return Ok(());
    };
    let valid = text.as_str().is_some_and(|text| {
        DESCRIPTION.is_match(text) && !["\\", "\"", "*/"].iter().any(|bad| text.contains(bad))
    });
    if !row.contains_key("call") || !valid {
        return Err(refuse(
            row,
            "a description is one printable ASCII line of a callable row, ending in a period, with no backslash, \
             double quote or `*/`",
        ));
    }
    Ok(())
}

/// Port of generate.py:283-285 (nested_readable): whether a `readable` entry is a nested path rather than a
/// top-level field.
pub(crate) fn nested_readable(readable: &str) -> bool {
    readable.contains('.') || readable.contains('[')
}

/// The rows of `ids` that `keep` takes.
fn filter(rows: &RowStore, ids: &[RowId], keep: impl Fn(&Dict) -> bool) -> Vec<RowId> {
    ids.iter().copied().filter(|&id| keep(&rows[id])).collect()
}

impl Generator {
    /// Port of generate.py:4-343, the module level, in source order: the first failure wins, with Python's message.
    pub(crate) fn new(root: &Path) -> Result<Self, GenerateError> {
        Self::module_level(root, true)
    }

    /// The module level as `scripts/sdk/port_harness.py rows` runs it: facade_types.py's import still reads
    /// type_names.json, but the stubbed `Inventory` reads no Rust source and builds nothing (`inventory` is `None`).
    pub(crate) fn rows_only(root: &Path) -> Result<Self, GenerateError> {
        Self::module_level(root, false)
    }

    fn module_level(root: &Path, build_inventory: bool) -> Result<Self, GenerateError> {
        // generate.py:4-15, the imports. facade_types.py's module level runs here, before any verb file is read: it
        // reads type_names.json (facade_types.py:372), beside the resolved scripts/sdk (its `__file__`), so it is
        // read below once that directory is known. catalog_fragment.py and uniffi_types.py read nothing at import.
        //
        // generate.py:16 `ROOT = Path(__file__).resolve().parents[2]`, and verb_table.py:7's `VERBS_DIR` beside
        // the resolved scripts/sdk.
        let sdk_dir = root.join("scripts/sdk");
        let sdk = sdk_dir
            .canonicalize()
            .map_err(|error| GenerateError::os(&error, &sdk_dir))?;
        let root = sdk
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&sdk)
            .to_path_buf();
        // facade_types.py:372 `TYPE_NAMES = json.loads(...)` (the import, generate.py:12).
        let type_names = type_names(&root)?;
        // generate.py:17 `MANIFEST = {'verbs': load_verbs()}`
        let mut rows = RowStore::default();
        let manifest: Vec<RowId> = load_verbs(&sdk.join("verbs"))?
            .into_iter()
            .map(|row| rows.push(row))
            .collect();
        let mut generator = Self {
            root,
            hand_declared_cache: super::common::HandDeclaredCache::new(),
            rows,
            manifest,
            host_rows: Vec::new(),
            host_run_rows: Vec::new(),
            host_browser_rows: Vec::new(),
            host_board_rows: Vec::new(),
            browser_rows: Vec::new(),
            callable_rows: Vec::new(),
            board_host_rows: Vec::new(),
            board_host_names: Vec::new(),
            definitions: Vec::new(),
            run_rows: Vec::new(),
            code_mode_rows: Vec::new(),
            schema_rows: Vec::new(),
            facade_rows: Vec::new(),
            type_names,
            inventory: None,
        };
        generator.host_sets()?;
        generator.callable_sets()?;
        generator.checked_sets()?;
        generator.check_callable_rows()?;
        generator.move_generic_bindings()?;
        for &id in &generator.manifest {
            check_description(&generator.rows[id])?;
        }
        // generate.py:338 HEADER is `super::HEADER`; generate.py:339 FACADE_ROWS.
        let memory = filter(&generator.rows, &generator.callable_rows, |row| {
            !not_memory(row)
        });
        generator.facade_rows = memory
            .into_iter()
            .chain(generator.board_host_rows.iter().copied())
            .collect();
        // generate.py:343 `INVENTORY = Inventory(ROOT, FACADE_ROWS)`. The module level after it binds constant
        // tables only (left to the PRs that port their emitters) and CORE_VERB_NAMES and CORE_COUNT_DEFAULTS
        // (`super`); it checks no row.
        if build_inventory {
            let facade_rows = generator.rows.select(&generator.facade_rows);
            let inventory =
                Inventory::with_type_names(&generator.root, &facade_rows, &generator.type_names)?;
            generator.inventory = Some(inventory);
        }
        Ok(generator)
    }

    /// Port of generate.py:21-35: the host sets, then each host projection's shape.
    fn host_sets(&mut self) -> Result<(), GenerateError> {
        let rows = &self.rows;
        self.host_rows = filter(rows, &self.manifest, |row| row.contains_key("host"));
        self.host_run_rows = filter(rows, &self.host_rows, |row| is(row, "context", "run"));
        self.host_browser_rows = filter(rows, &self.host_rows, |row| is(row, "context", "browser"));
        self.host_board_rows = filter(rows, &self.host_rows, |row| is(row, "context", "board"));
        self.browser_rows = filter(rows, &self.manifest, |row| is(row, "context", "browser"));
        for &id in &self.host_rows {
            check_host(&self.rows[id])?;
        }
        Ok(())
    }

    /// Port of generate.py:51-59: ROWS, BOARD_HOST_ROWS, BOARD_HOST_NAMES, DEFINITIONS, the duplicate check and
    /// RUN_ROWS.
    fn callable_sets(&mut self) -> Result<(), GenerateError> {
        // `row not in HOST_BROWSER_ROWS` compares rows by value in Python. A manifest row equal to a host-browser
        // row holds `host` and `context: "browser"` itself, so it is one of them: comparing ids is the same test.
        let mut callable: Vec<RowId> = self
            .manifest
            .iter()
            .copied()
            .filter(|id| {
                self.rows[*id].contains_key("call") && !self.host_browser_rows.contains(id)
            })
            .collect();
        for id in self.host_rows.clone() {
            if !is(&self.rows[id], "context", "board") {
                let synthetic = host_synthetic(&self.rows[id])?;
                callable.push(self.rows.push(synthetic));
            }
        }
        self.callable_rows = callable;
        for id in self.host_board_rows.clone() {
            // `dict(host_synthetic(row), board_host=True, board_input=row['input'])`
            let mut synthetic = host_synthetic(&self.rows[id])?;
            let input = item(&self.rows[id], "input")?.clone();
            synthetic.insert("board_host".into(), Value::Bool(true));
            synthetic.insert("board_input".into(), input);
            let synthetic = self.rows.push(synthetic);
            self.board_host_rows.push(synthetic);
        }
        let mut names = Vec::new();
        for &id in &self.board_host_rows {
            set_add(&mut names, item(&self.rows[id], "name")?.clone())?;
        }
        self.board_host_names = names;
        self.definitions = filter(&self.rows, &self.manifest, |row| {
            !row.contains_key("call") && !row.contains_key("host")
        });
        let mut names = Vec::new();
        for &id in &self.manifest {
            set_add(&mut names, item(&self.rows[id], "name")?.clone())?;
        }
        if names.len() != self.manifest.len() {
            return Err(GenerateError::value("duplicate SDK verb"));
        }
        self.run_rows = filter(&self.rows, &self.manifest, |row| is(row, "context", "run"));
        Ok(())
    }

    /// Port of generate.py:66-116: the role fields, CODE_MODE_ROWS and SCHEMA_ROWS, the run rows' shape,
    /// `outputs_by_input` and the scoped-child rows.
    fn checked_sets(&mut self) -> Result<(), GenerateError> {
        for &id in &self.manifest {
            check_metadata(&self.rows[id])?;
        }
        // generate.py:77; Python makes the set of host names again for each row.
        let mut host_names = Vec::new();
        for &id in &self.host_rows {
            host_names.push(item(&self.rows[id], "name")?.clone());
        }
        let mut code_mode = Vec::new();
        for &id in &self.callable_rows {
            let name = item(&self.rows[id], "name")?;
            if !host_names
                .iter()
                .any(|host_name| same_name(name, host_name))
            {
                code_mode.push(id);
            }
        }
        code_mode.extend(&self.host_browser_rows);
        code_mode.extend(&self.host_board_rows);
        code_mode.extend(&self.run_rows);
        self.code_mode_rows = code_mode;
        // generate.py:78
        let hostless_runs = filter(&self.rows, &self.run_rows, |row| !row.contains_key("host"));
        self.schema_rows = self
            .callable_rows
            .iter()
            .copied()
            .chain(hostless_runs)
            .collect();
        for &id in &self.run_rows {
            check_run_row(&self.rows[id])?;
        }
        for &id in &self.manifest {
            check_outputs_by_input(&self.rows[id])?;
        }
        for &id in &self.manifest {
            check_scoped_child(&self.rows[id])?;
        }
        Ok(())
    }

    /// Port of generate.py:117-303: each callable row's MCP shape (with its two defaults), door flags and
    /// admission, then the record refs, file calls, readable paths and prose links, loop by loop.
    fn check_callable_rows(&mut self) -> Result<(), GenerateError> {
        for id in self.callable_rows.clone() {
            let row = &self.rows[id];
            let context_none = row
                .get("context")
                .is_some_and(|c| MCP_NONE_CONTEXTS.iter().any(|k| c.is_str(k)));
            let mcp_none = row.get("mcp").is_some_and(|mcp| mcp.is_str("none"));
            if context_none != mcp_none {
                return Err(refuse(
                    row,
                    "only a browser or scoped-child row states \"mcp\": \"none\", and every such row does",
                ));
            }
            // generate.py:121-122: `setdefault` mutates the row object, which every set shares.
            let row = self.rows.get_mut(id);
            row.entry("mcp_fields".into()).or_insert_with(|| {
                let mut spec = Dict::new();
                spec.insert("spec".into(), Value::Str("$".into()));
                Value::Dict(spec)
            });
            row.entry("mcp_scope".into())
                .or_insert_with(|| Value::Str("unrestricted".into()));
            let row = &self.rows[id];
            check_mcp(row)?;
            check_doors(row)?;
            check_admission(row)?;
        }
        for check in [
            check_refs,
            check_file_call,
            check_readable,
            check_prose_links,
        ] {
            for &id in &self.callable_rows {
                check(&self.rows[id])?;
            }
        }
        Ok(())
    }

    /// Port of generate.py:313-326: each generic binding, checked, then moved off its row:
    /// `row['handle_args'] = row.pop('binding')['args']` (the other keys keep their order).
    fn move_generic_bindings(&mut self) -> Result<(), GenerateError> {
        for id in self.callable_rows.clone() {
            if !check_generic_binding(&self.rows[id])? {
                continue;
            }
            let row = self.rows.get_mut(id);
            let args = match row.shift_remove("binding") {
                Some(binding) => binding.getitem("args")?.clone(),
                None => return Err(GenerateError::key("binding")),
            };
            row.insert("handle_args".into(), args);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// A scratch tree whose verb table is `files`.
    fn tree(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oneiron-sdk-generator-rows-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let verbs = root.join("scripts/sdk/verbs");
        fs::create_dir_all(&verbs).expect("a scratch tree");
        // facade_types.py's import reads it before any verb file.
        fs::write(root.join("scripts/sdk/type_names.json"), "{}\n").expect("type_names.json");
        for (file, text) in files {
            fs::write(verbs.join(file), text).expect("a verb file");
        }
        root
    }

    const BASE: &str = r#""name": "zz_fixture", "input": "ZzInput", "output": "ZzOutput", "call": "zz_call(memory, &input)?", "scope": "Read", "section": false"#;

    // Each expected line: the last stderr line of `python3 scripts/sdk/port_harness.py rows` on nelly (Python
    // 3.14.7) over a tree whose only verb file is the row (tools/sdk_port_fixtures.py makes the same trees).
    #[test]
    fn refusals_match_python() {
        let cases: &[(&str, &str)] = &[
            (
                r#""host": {"input": "X"}, "context": "run""#,
                "ValueError: zz_fixture: a host projection names the public input and description, with optional caller, session, lists, pre-check and OpenAPI flags",
            ),
            (
                r#""session_read": "Nope""#,
                "ValueError: zz_fixture: `session_read` is one of ('Get', 'Hydrate', 'RefsResolve', 'SearchBm25', 'Receipts') on a Read row",
            ),
            (
                r#""overlay_write": 1, "scope": "Write""#,
                "ValueError: zz_fixture: `overlay_write` is `true` on a Write row",
            ),
            (
                r#""mcp_scope": "nope""#,
                "ValueError: zz_fixture: mcp_scope must be one of ['addressed', 'born', 'filtered', 'unrestricted']",
            ),
            (
                r#""mcp": "none""#,
                "ValueError: zz_fixture: only a browser or scoped-child row states \"mcp\": \"none\", and every such row does",
            ),
            (
                r#""host_door": true, "host_door_precheck": 0"#,
                "ValueError: zz_fixture: host_door_precheck is only a host door's, and only false",
            ),
            (
                r#""admission": {"require_granted_scope": true}"#,
                "ValueError: zz_fixture: require_granted_scope is only a non-Read lane_record_scope facade row's, with no other record-scope admission, and on a host door only a caller or listing one",
            ),
            (
                r#""refs": "/a""#,
                "ValueError: zz_fixture: refs are distinct JSON pointers of field names and `*`",
            ),
            (
                r#""binding": {"generic": true, "args": [{"name": "a", "type": "Wrong", "field": "$"}]}"#,
                "ValueError: zz_fixture: a whole-input parameter is the row's only one, typed as its input",
            ),
            (
                r#""description": "no period""#,
                "ValueError: zz_fixture: a description is one printable ASCII line of a callable row, ending in a period, with no backslash, double quote or `*/`",
            ),
            (
                r#""admission": [1]"#,
                "AttributeError: 'list' object has no attribute 'get'",
            ),
            (
                r#""mcp_fields": {"a": 1}"#,
                "TypeError: argument of type 'int' is not a container or iterable",
            ),
            (
                r#""admission": {"readable": [1]}"#,
                "TypeError: expected string or bytes-like object, got 'int'",
            ),
            (
                r#""mcp_scope": ["filtered"]"#,
                "TypeError: cannot use 'list' as a set element (unhashable type: 'list')",
            ),
        ];
        for (at, (fields, expected)) in cases.iter().enumerate() {
            let root = tree(
                &format!("refusal-{at}"),
                &[("zz_fixture.json", &format!("{{{BASE}, {fields}}}"))],
            );
            let got =
                Generator::new(&root).map_or_else(|error| error.to_string(), |_| String::new());
            assert_eq!(got, *expected, "{fields}");
            fs::remove_dir_all(&root).expect("cleanup");
        }
        let root = tree(
            "duplicate",
            &[
                ("1.json", &BASE.replace(r#""zz_fixture""#, "1")),
                ("1.0.json", &BASE.replace(r#""zz_fixture""#, "1.0")),
            ],
        );
        for file in ["1.json", "1.0.json"] {
            let path = root.join("scripts/sdk/verbs").join(file);
            let text = fs::read_to_string(&path).expect("a verb file");
            fs::write(&path, format!("{{{text}}}")).expect("a verb file");
        }
        let error = Generator::new(&root)
            .map(drop)
            .expect_err("1 == 1.0")
            .to_string();
        assert_eq!(error, "ValueError: duplicate SDK verb");
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn type_names_is_read_before_the_verbs() {
        // facade_types.py's import reads type_names.json (generate.py:12) before load_verbs (generate.py:17): with
        // both broken, Python's `generate.py` and `port_harness.py rows` stop on type_names.json.
        let root = tree("type-names-first", &[("zz_fixture.json", "{")]);
        fs::write(root.join("scripts/sdk/type_names.json"), "{\n").expect("type_names.json");
        let expected = "json.decoder.JSONDecodeError: Expecting property name enclosed in double quotes: line 2 column \
                        1 (char 2)";
        for got in [
            Generator::new(&root).map(drop),
            Generator::rows_only(&root).map(drop),
        ] {
            assert_eq!(
                got.expect_err("type_names.json is broken").to_string(),
                expected
            );
        }
        fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn sets_share_rows_and_bindings_move() {
        let host = r#""context": "board", "scope": "Write", "host": {"input": "HostIn", "description": "D."}"#;
        let generic = r#""handle_args": "old", "binding": {"generic": true, "args": [{"name": "text", "type": "String"}]}"#;
        let root = tree(
            "sets",
            &[
                (
                    "a.json",
                    &format!("{{{}, {host}}}", BASE.replace("zz_fixture", "a")),
                ),
                (
                    "b.json",
                    &format!("{{{}, {generic}}}", BASE.replace("zz_fixture", "b")),
                ),
            ],
        );
        let generator = Generator::new(&root).expect("valid rows");
        assert_eq!(generator.manifest, [RowId(0), RowId(1)]);
        assert_eq!(generator.board_host_rows, [RowId(2)]);
        assert_eq!(generator.callable_rows, [RowId(0), RowId(1)]);
        assert_eq!(generator.facade_rows, [RowId(1), RowId(2)]);
        assert_eq!(generator.code_mode_rows, [RowId(1), RowId(0)]);
        let board = &generator.rows[RowId(2)];
        let keys: Vec<&str> = board.keys().map(String::as_str).collect();
        assert_eq!(keys.last(), Some(&"board_input"));
        assert!(board["call"].is_str("crate::task_verb::sdk::host_only(memory, \"a\", &input)?"));
        // The setdefault defaults land on the shared row; the binding moves to `handle_args`, which keeps its place.
        let b = &generator.rows[RowId(1)];
        assert!(b["mcp_scope"].is_str("unrestricted"));
        let keys: Vec<&str> = b.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "name",
                "input",
                "output",
                "call",
                "scope",
                "section",
                "handle_args",
                "mcp_fields",
                "mcp_scope"
            ]
        );
        assert!(nested_readable("a.b") && nested_readable("a[*]") && !nested_readable("rows"));
        fs::remove_dir_all(&root).expect("cleanup");
    }
}
