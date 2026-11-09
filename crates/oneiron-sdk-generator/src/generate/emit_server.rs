//! Port of generate.py: the server's facade outputs (G4a): `agent_verbs.rs` and `dispatch.rs` (`facade_dispatch`),
//! `host_door_rows.rs` (`host_door_rows`), and the door tables both they and the MCP dispatch read
//! (generate.py:357-375).

use super::row_access::{flag, flag_in, get_is, item, json, variant_name};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::value::{Value, set_add};

/// Port of generate.py:2123-2128 (HOST_DOOR_ROWS_DOC).
pub(crate) const HOST_DOOR_ROWS_DOC: &str = "// The host-door rows whose door checks its caller before the row's verb
// hooks run (FIX 1763), one variant each, named as `AgentVerb` names it, and
// the proof each names (`host_door_proof`), which `host_doors::door_admits`
// matches with no catch-all arm. A row whose table entry says
// `\"host_door_precheck\": false` checks nothing before its hooks; those rows:
";

/// generate.py:2132 `variant`: a row's `AgentVerb` variant.
fn row_variant(row: &crate::py::value::Dict) -> Result<String, GenerateError> {
    Ok(variant_name(super::row_access::text(row, "name", "replace")?))
}

/// generate.py:2148 `proof_variant`: `''.join(part.title() for part in kind.split('_'))`.
fn proof_variant(kind: &Value) -> Result<String, GenerateError> {
    Ok(super::common::str_receiver(kind, "split")?
        .split('_')
        .map(crate::py::text::title)
        .collect())
}

/// Port of generate.py:2130-2178 (host_door_rows): the `HostDoorRow` enum `door_admits` matches, and the host doors
/// it leaves out.
pub(crate) fn host_door_rows(
    generator: &Generator,
    facade_rows: &[RowId],
) -> Result<String, GenerateError> {
    let rows = &generator.rows;
    let doors: Vec<RowId> = facade_rows
        .iter()
        .copied()
        .filter(|&id| flag(&rows[id], "host_door"))
        .collect();
    // `r.get('host_door_precheck', True)`.
    let checked: Vec<RowId> = doors
        .iter()
        .copied()
        .filter(|&id| rows[id].get("host_door_precheck").is_none_or(Value::truthy))
        .collect();
    let mut out = HEADER.to_owned() + HOST_DOOR_ROWS_DOC;
    // `r not in checked` compares rows by value; facade rows are distinct by name, so by identity here.
    for &id in &doors {
        if !checked.contains(&id) {
            out += &format!("// - `{}`\n", item(&rows[id], "name")?.str());
        }
    }
    out += "/// A host-door row whose door checks its caller first.\n";
    out += "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(in crate::api::facade) enum HostDoorRow {\n";
    for &id in &checked {
        out += &format!("    {},\n", row_variant(&rows[id])?);
    }
    out += "}\n";
    out += "impl HostDoorRow {\n    /// The row `verb` names, when it is one.\n";
    out += "    pub(in crate::api::facade) fn from_verb(verb: &str) -> Option<Self> {\n        Some(match verb {\n";
    for &id in &checked {
        out += &format!(
            "            {} => Self::{},\n",
            json(item(&rows[id], "name")?),
            row_variant(&rows[id])?
        );
    }
    out += "            _ => return None,\n        })\n    }\n}\n";
    // VERB-METADATA (untangle slice 4.1): every checked row names the proof its door runs first.
    let mut unnamed = Vec::new();
    for &id in &checked {
        if !flag(&rows[id], "host_door_proof") {
            unnamed.push(item(&rows[id], "name")?.clone());
        }
    }
    if !unnamed.is_empty() {
        return Err(GenerateError::value(format!(
            "checked host doors without `host_door_proof`: {}",
            Value::List(unnamed).repr()
        )));
    }
    // `list(dict.fromkeys(r['host_door_proof'] for r in checked))`: first-seen order, equal kinds once.
    let mut kinds: Vec<Value> = Vec::new();
    for &id in &checked {
        let kind = item(&rows[id], "host_door_proof")?.clone();
        kind.check_hashable("a dict key")?;
        set_add(&mut kinds, kind)?;
    }
    out += "/// The proof a checked host door runs before its hooks (`host_door_proof` on the row).\n";
    out += "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub(in crate::api::facade) enum HostDoorProof {\n";
    for kind in &kinds {
        out += &format!("    {},\n", proof_variant(kind)?);
    }
    out += "}\n";
    out += "impl HostDoorRow {\n    /// The proof this row's door runs first.\n";
    out += "    pub(in crate::api::facade) const fn proof(self) -> HostDoorProof {\n        match self {\n";
    for &id in &checked {
        out += &format!(
            "            Self::{} => HostDoorProof::{},\n",
            row_variant(&rows[id])?,
            proof_variant(item(&rows[id], "host_door_proof")?)?
        );
    }
    out += "        }\n    }\n}\n";
    // FIX 4794: the MCP rows whose handler takes the caller's credential before it runs.
    let mut credential = Vec::new();
    for id in generator.mcp_rows() {
        let row = &rows[id];
        let name = item(row, "name")?;
        if !name.is_str("ai.anonymous_chat")
            && !get_is(row, "context", "board")
            && (flag_in(row, "admission", "owner_grade")? || flag(row, "host_door"))
        {
            credential.push(name.clone());
        }
    }
    let mut checked_names = Vec::new();
    for &id in &checked {
        checked_names.push(item(&rows[id], "name")?.clone());
    }
    let added: Vec<&Value> = credential
        .iter()
        .filter(|name| !checked_names.iter().any(|checked| checked.py_eq(name)))
        .collect();
    let removed: Vec<&Value> = checked_names
        .iter()
        .filter(|name| !credential.iter().any(|credential| credential.py_eq(name)))
        .collect();
    let alternatives =
        |names: &[&Value]| names.iter().map(|name| json(name)).collect::<Vec<_>>().join(" | ");
    out += "/// Whether `verb` is an MCP row whose handler takes the caller's credential\n/// before it runs: every host door and every owner-grade row. A call that\n/// carries none is refused before the row's pre hooks (FIX 4794).\n";
    out += "#[must_use]\npub(in crate::api) fn needs_caller_credential(verb: &str) -> bool {\n";
    let mut test = "HostDoorRow::from_verb(verb).is_some()".to_owned();
    if !removed.is_empty() {
        test = format!("({test} && !matches!(verb, {}))", alternatives(&removed));
    }
    if !added.is_empty() {
        test += &format!(" || matches!(verb, {})", alternatives(&added));
    }
    out += &format!("    {test}\n}}\n");
    Ok(out)
}
