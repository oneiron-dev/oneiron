//! The row sets of the module level: the host sets, the callable sets and the checked sets, each made by one method
//! of `Generator`, with the checks of a set's rows (a host projection, the role fields, a run row, `outputs_by_input`,
//! a scoped-child row).

use std::collections::BTreeSet;

use super::super::{Generator, RowId, SESSION_READS, facade_only_row};
use super::{FIELD_NAME, GRANT_CLASS, filter, is, item, item_in, keys_are, refuse, same_name};
use crate::error::GenerateError;
use crate::py::text::{repr_str_tuple, strip};
use crate::py::value::{Dict, Value, set_add};

/// The keys a host projection may hold.
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
/// The host projection's flags, each a bool.
const HOST_FLAGS: &[&str] = &[
    "host_door_caller",
    "host_door_session",
    "host_door_lists",
    "host_door_precheck",
    "openapi",
];
/// The keys a run row may hold beside its required ones, and the required ones.
const RUN_OPTIONAL: &[&str] = &[
    "description",
    "example",
    "output",
    "outputs_by_input",
    "host",
    "run_surface",
    "grant_class",
    "power",
];
/// The agent powers a run row may name as its requirement.
const POWERS: &[&str] = &["spawn", "save_agent"];
const RUN_REQUIRED: &[&str] = &["name", "input", "scope", "context", "effect", "act_class"];
/// A scoped-child row's keys, `description` and `example` aside.
const SCOPED_CHILD_KEYS: &[&str] = &[
    "name",
    "input",
    "output",
    "call",
    "scope",
    "act_class",
    "context",
    "mcp",
    "section",
];

/// A run, browser or board row's facade-only host projection. Python evaluates the dict literal left to right, so
/// `row['output']` is read before the host's own `output`.
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
    out.insert("act_class".into(), item(row, "act_class")?.clone());
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

/// A host projection names the public input and description, with optional flags.
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

/// The role fields (custody, overlay_write, session_read, run_surface).
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

/// A run row's key set.
fn check_run_row(row: &Dict) -> Result<(), GenerateError> {
    let keys: BTreeSet<&str> = row
        .keys()
        .map(String::as_str)
        .filter(|key| !RUN_OPTIONAL.contains(key))
        .collect();
    if !keys_are(&keys, RUN_REQUIRED) || !item_in(row, "scope", &["Read", "Write"])? {
        return Err(refuse(
            row,
            "a run row names its input, scope, act class, effect, output, per-input outputs, run surface and grant class, and nothing \
             else",
        ));
    }
    Ok(())
}

/// A run row's `grant_class` names the authority rule its writer applies (`vault.agents.put`: the author's slice,
/// ARCH-0053:20). Code mode shows it as the method's JSDoc. It describes the writer's own check; nothing reads it as a
/// second one. Every run row's key set is checked before any grant class.
fn check_grant_class(row: &Dict) -> Result<(), GenerateError> {
    let Some(grant_class) = row.get("grant_class") else {
        return Ok(());
    };
    let phrase = grant_class.as_str().is_some_and(|text| {
        GRANT_CLASS.is_match(text)
            && strip(text) == text
            && !["\\", "\"", "*/"]
                .into_iter()
                .any(|mark| text.contains(mark))
    });
    if !phrase {
        return Err(refuse(
            row,
            "a grant class is one printable ASCII phrase, with no backslash, double quote or `*/`",
        ));
    }
    Ok(())
}

/// A run row's `power` names the agent power its writer checks before the act (`spawn` for the two spawn spellings,
/// `save_agent` for `vault.agents.put`). Like the grant class it describes the writer's own check; nothing reads it as
/// a second one.
fn check_power(row: &Dict) -> Result<(), GenerateError> {
    let Some(power) = row.get("power") else {
        return Ok(());
    };
    if !power.as_str().is_some_and(|text| POWERS.contains(&text)) {
        return Err(refuse(row, "a power is `spawn` or `save_agent`"));
    }
    Ok(())
}

/// `outputs_by_input` maps input field names to non-empty output types.
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

/// A scoped-child row's shape.
fn check_scoped_child(row: &Dict) -> Result<(), GenerateError> {
    if !is(row, "context", "scoped_child") {
        return Ok(());
    }
    let keys: BTreeSet<&str> = row
        .keys()
        .map(String::as_str)
        .filter(|&key| !matches!(key, "description" | "example"))
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
            "a scoped-child row names its input, output, scope, act class and description, calls the host-only refusal, and \
             nothing else",
        ));
    }
    Ok(())
}

impl Generator {
    /// The host sets, then each host projection's shape.
    pub(super) fn host_sets(&mut self) -> Result<(), GenerateError> {
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

    /// ROWS, BOARD_HOST_ROWS, BOARD_HOST_NAMES, DEFINITIONS, the duplicate check and RUN_ROWS.
    pub(super) fn callable_sets(&mut self) -> Result<(), GenerateError> {
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

    /// The role fields, CODE_MODE_ROWS and SCHEMA_ROWS, the run rows' shape, `outputs_by_input` and the scoped-child
    /// rows.
    pub(super) fn checked_sets(&mut self) -> Result<(), GenerateError> {
        for &id in &self.manifest {
            check_metadata(&self.rows[id])?;
        }
        // Python makes the set of host names again for each row.
        let mut host_names = Vec::new();
        for &id in &self.host_rows {
            host_names.push(item(&self.rows[id], "name")?.clone());
        }
        // A row served by its HTTP facade door only is no code-mode verb (FIX EXECUTE-CALLER-CODE).
        let mut code_mode = Vec::new();
        for &id in &self.callable_rows {
            let name = item(&self.rows[id], "name")?;
            if !facade_only_row(&self.rows[id])
                && !host_names
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
        for &id in &self.run_rows {
            check_grant_class(&self.rows[id])?;
            check_power(&self.rows[id])?;
        }
        for &id in &self.manifest {
            check_outputs_by_input(&self.rows[id])?;
        }
        for &id in &self.manifest {
            check_scoped_child(&self.rows[id])?;
        }
        Ok(())
    }
}
