//! The Python generator's module level: the verb rows' validation and the row sets, in source order. Each check
//! keeps Python's evaluation order and short-circuits, its truthiness and `is True`, and the error Python raises when
//! a malformed row meets an operation of the wrong type.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::row_access::has_door;
use super::{Generator, MCP_NONE_CONTEXTS, MCP_SCOPES, RowId, RowStore};
use crate::error::GenerateError;
use crate::facade_types::{Inventory, type_names};
use crate::py::re::compile_fullmatch;
use crate::py::text::repr_str;
use crate::py::value::{Dict, Value};
use crate::verb_table::load_verbs;

mod sets;

// The `re.fullmatch` patterns, each beside the Python one (all ASCII classes, so Python's and Rust's agree).
/// An `outputs_by_input` field name: `[A-Za-z_][A-Za-z0-9_]*`
static FIELD_NAME: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[A-Za-z_][A-Za-z0-9_]*"));
/// A run row's grant class: one to 120 printable ASCII characters, `[ -~]{1,120}`
static GRANT_CLASS: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[ -~]{1,120}"));
/// An attachment's file name: `[A-Za-z0-9][A-Za-z0-9._-]*`
static ATTACHMENT: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*"));
/// A `refs_check` fn path: `(crate|super|self)(::[A-Za-z_][A-Za-z0-9_]*)+`
static REFS_CHECK: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"(crate|super|self)(::[A-Za-z_][A-Za-z0-9_]*)+"));
/// A `refs` pointer: `(/(\*|[a-z_][a-z0-9_]*))+`
static REF_POINTER: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"(/(\*|[a-z_][a-z0-9_]*))+"));
/// A `readable` field path: `[a-z_][a-z0-9_]*(\[\*\])?(\.[a-z_][a-z0-9_]*(\[\*\])?)*`
static READABLE: LazyLock<Regex> =
    LazyLock::new(|| compile_fullmatch(r"[a-z_][a-z0-9_]*(\[\*\])?(\.[a-z_][a-z0-9_]*(\[\*\])?)*"));
/// A `prose_links` pointer: `(/(\*(\[[a-z_][a-z0-9_]*=[a-z0-9_]+\])?|[a-z_][a-z0-9_]*))+`
static PROSE_POINTER: LazyLock<Regex> = LazyLock::new(|| {
    compile_fullmatch(r"(/(\*(\[[a-z_][a-z0-9_]*=[a-z0-9_]+\])?|[a-z_][a-z0-9_]*))+")
});
/// A generic binding argument's name: `[a-z_][a-z0-9_]*`
static ARG_NAME: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[a-z_][a-z0-9_]*"));
/// A row's description: `[ -~]{1,240}\.`
static DESCRIPTION: LazyLock<Regex> = LazyLock::new(|| compile_fullmatch(r"[ -~]{1,240}\."));

/// The proof rules of `host_doors/proofs.rs` a host-door row may name in `proof` (UC-01 PR 0a), each the snake case
/// of its rule's type.
pub(crate) const PROOF_RULES: &[&str] = &[
    "owner",
    "person",
    "member",
    "owner_or_holder",
    "owner_or_caller",
    "caller",
    "lane_caller",
    "owner_grade",
    "usage_repair",
    "off_record",
    "off_record_room",
    "voice_bank",
    "booking_owner_act",
    "packs_setup",
    "decision_holder",
    "hyde_caller",
    "guest_document_reader",
    "tradeoff_picker",
    "artifact_publisher",
    "model_step_caller",
    "policy_power",
    "ramp_power",
    "grants_answer",
    "credential_holder",
    "foreign_code",
    "verdict_asker",
    "eval_authoring",
    "training_run_executor",
    "saved_query",
    "lens_person",
];
/// The `proof` of a door that proves its caller itself, after the row's hooks: it names no rule, and the facade
/// checks nothing before the hooks.
pub(crate) const IN_DOOR: &str = "in_door";
/// The rules that admit only the owner or a person, so the dispatch refuses an agent's call before the door runs
/// (FIX-LIST TAKES-PERSON-PROOF-MISSES-THREE-KINDS).
pub(crate) const PERSON_RULES: &[&str] = &["owner", "person", "member"];
/// The host-door fields UC-01 PR 0a replaced, each with what replaced it.
const REPLACED_DOOR_FIELDS: &[(&str, &str)] = &[
    ("host_door", "`\"proof\": <rule>` with `\"door\": \"hand\"`"),
    (
        "host_door_proof",
        "`proof`, naming a rule of host_doors/proofs.rs",
    ),
    ("host_door_precheck", "`\"proof\": \"in_door\"`"),
    ("host_door_lists", "`lists`"),
];

/// The record-scope admissions `require_granted_scope` excludes.
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

/// `isinstance(x, str) and re.fullmatch(pattern, x)` over every item of `refs` or `prose_links`:
/// `not pointers or len(set(pointers)) != len(pointers) or not all(...)`, negated.
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

/// The row's MCP scope and fields, after their defaults.
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

/// The door flags of one row.
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
    for &(field, now) in REPLACED_DOOR_FIELDS {
        if row.contains_key(field) {
            return Err(refuse(
                row,
                &format!(
                    "`{field}` is now {now} (UC-01 PR 0a; scripts/refactor/tools/door_rule_rows.py rewrites the row)"
                ),
            ));
        }
    }
    let host_door = has_door(row);
    if let Some(proof) = row.get("proof")
        && !proof
            .as_str()
            .is_some_and(|rule| rule == IN_DOOR || PROOF_RULES.contains(&rule))
    {
        return Err(refuse(
            row,
            "`proof` names a rule of host_doors/proofs.rs, or `in_door`",
        ));
    }
    if row.get("door").is_some_and(|door| !door.is_str("hand"))
        || host_door != row.contains_key("door")
    {
        return Err(refuse(
            row,
            "a host door's row says \"door\": \"hand\" (its door fn is hand-written), and only a host door's",
        ));
    }
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
        ("lists", "only a host door lists its rows"),
    ] {
        if flag(row, key) && !host_door {
            return Err(refuse(row, message));
        }
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

/// `'rows' in row.get('admission', {}).get('readable', [])`.
fn readable_has_rows(row: &Dict) -> Result<bool, GenerateError> {
    let Some(admission) = row.get("admission") else {
        return Ok(false);
    };
    match admission.dict_get("readable")? {
        None => Ok(false),
        Some(readable) => readable.contains_str("rows"),
    }
}

/// `require_granted_scope` and `mcp_off_runtime`.
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
            || (has_door(row) && !(flag(row, "host_door_caller") || flag(row, "lists")))
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
            || has_door(row)
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

/// `refs_check` and `refs`.
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
        || has_door(row)
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

/// `file_call`.
fn check_file_call(row: &Dict) -> Result<(), GenerateError> {
    let Some(file_call) = row.get("file_call") else {
        return Ok(());
    };
    if !matches!(file_call, Value::Str(_))
        || not_memory(row)
        || has_door(row)
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

/// Each `readable` entry.
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

/// `prose_links`.
fn check_prose_links(row: &Dict) -> Result<(), GenerateError> {
    let Some(pointers) = row.get("prose_links") else {
        return Ok(());
    };
    if not_memory(row)
        || has_door(row)
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

/// One generic binding argument's shape.
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

/// A generic binding's shape; whether the row has one to move.
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

/// A callable row's one-line description.
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

/// The rows of `ids` that `keep` takes.
fn filter(rows: &RowStore, ids: &[RowId], keep: impl Fn(&Dict) -> bool) -> Vec<RowId> {
    ids.iter().copied().filter(|&id| keep(&rows[id])).collect()
}

impl Generator {
    /// The Python generator's module level, in source order: the first failure wins, with Python's message.
    pub(crate) fn new(root: &Path) -> Result<Self, GenerateError> {
        Self::module_level(root, true)
    }

    /// The module level without the type inventory, for the refusal tests: type_names.json and the verb rows are
    /// read and checked, but no Rust source is read and `inventory` is `None`.
    #[cfg(test)]
    pub(crate) fn rows_only(root: &Path) -> Result<Self, GenerateError> {
        Self::module_level(root, false)
    }

    fn module_level(root: &Path, build_inventory: bool) -> Result<Self, GenerateError> {
        // The imports. `facade_types`'s module level runs here, before any verb file is read: it reads
        // type_names.json beside the resolved scripts/sdk (its `__file__`), so it is read below once that directory
        // is known. `catalog_fragment` and `uniffi_types` read nothing at import.
        //
        // `ROOT = Path(__file__).resolve().parents[2]`, and the verb table's `VERBS_DIR` beside the resolved
        // scripts/sdk.
        let sdk_dir = root.join("scripts/sdk");
        let sdk = sdk_dir
            .canonicalize()
            .map_err(|error| GenerateError::os(&error, &sdk_dir))?;
        let root = sdk
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&sdk)
            .to_path_buf();
        // `TYPE_NAMES = json.loads(...)` (the `facade_types` import).
        let type_names = type_names(&root)?;
        // `MANIFEST = {'verbs': load_verbs()}`
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
            fragment_dependencies: BTreeSet::new(),
            wire_input_dependencies: BTreeSet::new(),
        };
        generator.host_sets()?;
        generator.callable_sets()?;
        generator.checked_sets()?;
        generator.check_callable_rows()?;
        generator.move_generic_bindings()?;
        for &id in &generator.manifest {
            check_description(&generator.rows[id])?;
        }
        // HEADER is `super::HEADER`; then FACADE_ROWS.
        let memory = filter(&generator.rows, &generator.callable_rows, |row| {
            !not_memory(row)
        });
        generator.facade_rows = memory
            .into_iter()
            .chain(generator.board_host_rows.iter().copied())
            .collect();
        // `INVENTORY = Inventory(ROOT, FACADE_ROWS)`. The module level after it binds constant tables only
        // (CORE_VERB_NAMES and CORE_COUNT_DEFAULTS are `super`'s); it checks no row.
        if build_inventory {
            let facade_rows = generator.rows.select(&generator.facade_rows);
            let inventory =
                Inventory::with_type_names(&generator.root, &facade_rows, &generator.type_names)?;
            generator.inventory = Some(inventory);
        }
        Ok(generator)
    }

    /// Each callable row's MCP shape (with its two defaults), door flags and admission, then the record refs, file
    /// calls, readable paths and prose links, loop by loop.
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
            // `setdefault` mutates the row object, which every set shares.
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

    /// Each generic binding, checked, then moved off its row:
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
mod tests;
