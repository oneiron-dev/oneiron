//! Port of generate.py: the Rust core outputs (G4a): `run_verb_catalog.rs` (`run_catalog`), `core_verb_names.rs`
//! (untangle slice 5.0a: `core_verb_names` and its checks), and the inline segments of `outputs()` that build
//! `sdk_generated.rs` (`core`) and `verb_catalog.rs` (`catalog`), with the row helpers they call.
//!
//! None of these reads the `Inventory`: each is text over the module-level row sets, in Python's order.

use super::row_access::{
    ByName, concat, context_is, flag, get_is, item, json, json_item, repr_list, shown, text,
    variant_of, variants,
};
use super::{CORE_COUNT_DEFAULTS, CORE_VERB_NAMES, Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::json::dumps_str;
use crate::py::text::upper;
use crate::py::value::{Dict, Value, set_add};

/// Port of generate.py:1587-1607 (run_catalog): `RunVerb`, the rows code mode serves that the run answers itself.
pub(crate) fn run_catalog(generator: &Generator) -> Result<String, GenerateError> {
    let rows = generator.rows.select(&generator.run_rows);
    let variants = variants(&rows)?;
    let mut out = HEADER.to_owned()
        + "/// The verb-table rows a code run answers itself, as the typed `self.*` call\n";
    out += "/// each names. A row with a host projection also has a typed door bound to\n";
    out += "/// its caller's credential and live-run attachment.\n";
    out += "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum RunVerb { ";
    out += &variants.values().cloned().collect::<Vec<_>>().join(",");
    out += " }\nimpl RunVerb {\n";
    out += "pub const ALL: &[Self] = &[";
    out += &variants
        .values()
        .map(|variant| format!("Self::{variant}"))
        .collect::<Vec<_>>()
        .join(",");
    out += "];\n";
    out += "pub fn from_name(name: &str) -> Option<Self> { Self::ALL.iter().copied().find(|verb| verb.as_str() == name) }\n";
    out += "pub const fn as_str(self) -> &'static str { match self {\n";
    for row in &rows {
        out += &format!(
            "Self::{} => {},\n",
            variant_of(&variants, row)?,
            json_item(row, "name")?
        );
    }
    out += "} }\n";
    let mut writes = Vec::new();
    for row in &rows {
        if item(row, "scope")?.is_str("Write") {
            writes.push(format!("Self::{}", variant_of(&variants, row)?));
        }
    }
    out += "pub const fn writes(self) -> bool { matches!(self, ";
    out += &if writes.is_empty() {
        "_ if false".to_owned()
    } else {
        writes.join(" | ")
    };
    out += ") }\n";
    for (constant, surface, doc) in [
        (
            "MEMORY_RUN",
            "memory",
            "The run rows the action registry serves on ordinary storage: they need no live run.",
        ),
        (
            "LIVE_RUN",
            "live",
            "The run rows that act on their caller's live agent run, served only under that run's lease.",
        ),
    ] {
        let mut selected = Vec::new();
        for row in &rows {
            if row
                .get("run_surface")
                .is_some_and(|value| value.is_str(surface))
            {
                selected.push(format!("Self::{}", variant_of(&variants, row)?));
            }
        }
        out += &format!(
            "/// {doc} (`run_surface: \"{surface}\"` on the row.)\npub const {constant}: [Self; {}] = [",
            selected.len()
        );
        out += &selected.join(",");
        out += "];\n";
    }
    out += "pub const fn effect(self) -> crate::code_run::SelfEffect { match self {\n";
    for row in &rows {
        out += &format!(
            "Self::{} => crate::code_run::SelfEffect::{},\n",
            variant_of(&variants, row)?,
            concat(item(row, "effect")?)?
        );
    }
    out += "} }\n";
    Ok(out + "}\n")
}

/// Port of generate.py:1629-1631 (default_const): the engine constant that carries one binding default the manifest
/// states.
pub(crate) fn default_const(row: &Dict, arg: &Value) -> Result<String, GenerateError> {
    let name = text(row, "name", "replace")?.replace('.', "_");
    Ok(upper(&format!(
        "{name}_{}_default",
        arg.getitem("name")?.str()
    )))
}

/// generate.py:1661 and 2249: `'default' in a and ARGUMENTS[a['kind']]['rust'] == 'usize'`, the binding argument
/// that states a count default.
pub(crate) fn states_usize_default(arg: &Value) -> Result<bool, GenerateError> {
    Ok(arg.contains_str("default")?
        && super::common::argument_kind(arg.getitem("kind")?)?.text("rust")? == "usize")
}

/// Port of generate.py:1654-1656 (core_name_const): the core constant that holds one row name.
pub(crate) fn core_name_const(name: &str) -> String {
    upper(&name.replace('.', "_"))
}

/// Port of generate.py:1658-1661 (count_defaults): every usize binding default the verb table states, by its engine
/// constant (a dict: a constant stated twice keeps its first place and its last row).
pub(crate) fn count_defaults(
    generator: &Generator,
) -> Result<ByName<(RowId, Value)>, GenerateError> {
    let mut defaults = ByName::default();
    for &id in &generator.callable_rows {
        let row = &generator.rows[id];
        for arg in super::row_access::binding_args(row)? {
            if states_usize_default(&arg)? {
                defaults.insert(&default_const(row, &arg)?, (id, arg));
            }
        }
    }
    Ok(defaults)
}

/// Port of generate.py:1663-1673 (check_core_verb_names): fails the run when core's table lists a row or a default
/// the verb table does not have.
pub(crate) fn check_core_verb_names(
    generator: &Generator,
) -> Result<ByName<(RowId, Value)>, GenerateError> {
    // `{r['name'] for r in ROWS}`: only a `str` name equals a `CORE_VERB_NAMES` entry.
    let names: Vec<&str> = generator
        .callable_rows
        .iter()
        .filter_map(|&id| generator.rows[id].get("name").and_then(Value::as_str))
        .collect();
    let missing: Vec<&str> = CORE_VERB_NAMES
        .iter()
        .copied()
        .filter(|name| !names.contains(name))
        .collect();
    if !missing.is_empty() {
        return Err(GenerateError::exit(format!(
            "CORE_VERB_NAMES names rows the verb table does not have: {}",
            repr_list(&missing)
        )));
    }
    let defaults = count_defaults(generator)?;
    let missing: Vec<&str> = CORE_COUNT_DEFAULTS
        .iter()
        .copied()
        .filter(|constant| !defaults.contains(constant))
        .collect();
    if !missing.is_empty() {
        return Err(GenerateError::exit(format!(
            "CORE_COUNT_DEFAULTS names defaults the verb table does not state: {}",
            repr_list(&missing)
        )));
    }
    Ok(defaults)
}

/// generate.py:2497 `custody = [r for r in ROWS if 'custody' in r]`.
pub(crate) fn custody_rows(generator: &Generator) -> Vec<RowId> {
    generator
        .callable_rows
        .iter()
        .copied()
        .filter(|&id| generator.rows[id].contains_key("custody"))
        .collect()
}

/// generate.py:1684 and 1699: the rows of `ROWS` whose `section` is true (`r['section']`, a `KeyError` without one).
fn section_rows(generator: &Generator) -> Result<Vec<&Dict>, GenerateError> {
    let mut section = Vec::new();
    for &id in &generator.callable_rows {
        let row = &generator.rows[id];
        if item(row, "section")?.truthy() {
            section.push(row);
        }
    }
    Ok(section)
}

/// Port of generate.py:1675-1694 (core_verb_names): core's table, `crate::verb_names`, included from OUT_DIR.
pub(crate) fn core_verb_names(
    generator: &Generator,
    custody: &[RowId],
) -> Result<String, GenerateError> {
    let defaults = check_core_verb_names(generator)?;
    let mut text = HEADER.to_owned();
    for name in CORE_VERB_NAMES {
        text += &format!(
            "/// The `{name}` row.\npub const {}: &str = {};\n",
            core_name_const(name),
            dumps_str(name)
        );
    }
    for constant in CORE_COUNT_DEFAULTS {
        let (id, arg) = defaults.get(constant)?;
        text += &format!(
            "/// `{}`'s `{}` when a caller names none.\npub const {constant}: usize = {};\n",
            shown(&generator.rows[*id], "name")?,
            arg.getitem("name")?.str(),
            arg.getitem("default")?.str()
        );
    }
    let section: Vec<String> = section_rows(generator)?
        .iter()
        .map(|row| json_item(row, "name"))
        .collect::<Result<_, _>>()?;
    text += "/// The rows a context board section may advertise (`section` on the row), in catalog order.\n";
    text += &format!(
        "pub const SECTION_VERBS: [&str; {}] = [{}];\n",
        section.len(),
        section.join(", ")
    );
    text += "/// The custody rows, whose input carries a secret's value or its sealed input. The action registry\n/// offers none of them: an action keeps its whole input in its replay record.\n";
    let rows = generator.rows.select(custody);
    let names: Vec<String> = rows
        .iter()
        .map(|row| json_item(row, "name"))
        .collect::<Result<_, _>>()?;
    text += &format!(
        "pub const CUSTODY_VALUE_ROWS: [&str; {}] = [{}];\n",
        custody.len(),
        names.join(", ")
    );
    text += "/// The member of each [`CUSTODY_VALUE_ROWS`] row's input that holds the secret's value or its sealed\n/// input (`custody` on the row), in the same order.\n";
    let members: Vec<String> = rows
        .iter()
        .map(|row| json_item(row, "custody"))
        .collect::<Result<_, _>>()?;
    text += &format!(
        "pub const CUSTODY_VALUE_MEMBERS: [&str; {}] = [{}];\n",
        custody.len(),
        members.join(", ")
    );
    text += "/// The member of custody row `verb`'s input that holds the secret's value or its sealed input; `None`\n/// for any other row.\n";
    text += "#[must_use]\npub fn custody_member(verb: &str) -> Option<&'static str> {\n";
    text += "    CUSTODY_VALUE_ROWS.iter().position(|row| *row == verb).map(|at| CUSTODY_VALUE_MEMBERS[at])\n}\n";
    Ok(text)
}

/// Port of generate.py:1696-1720 (core_verb_names_check): the catalog's compile-time check that core's table
/// (`crate::verb_names`) holds its own rows.
pub(crate) fn core_verb_names_check(
    generator: &Generator,
    variants: &ByName<String>,
    custody: &[RowId],
) -> Result<String, GenerateError> {
    check_core_verb_names(generator)?;
    let section = section_rows(generator)?;
    let mut text = "// Core reads these rows by name from `crate::verb_names` (untangle slice 5.0a). A name, section verb\n".to_owned();
    text += "// or custody member there that is not this catalog's does not compile.\n";
    text += "const _: () = {\n";
    text += "const fn same(left: &str, right: &str) -> bool {\n";
    text += "let (left, right) = (left.as_bytes(), right.as_bytes());\n";
    text += "if left.len() != right.len() { return false; }\n";
    text += "let mut at = 0;\nwhile at < left.len() { if left[at] != right[at] { return false; } at += 1; }\ntrue\n}\n";
    for name in CORE_VERB_NAMES {
        text += &format!(
            "assert!(same(crate::verb_names::{}, AgentVerb::{}.as_str()));\n",
            core_name_const(name),
            variants.get(name)?
        );
    }
    text += "let mut sections = 0;\nlet mut at = 0;\n";
    text += "while at < AgentVerb::ALL.len() { if AgentVerb::ALL[at].is_section() { sections += 1; } at += 1; }\n";
    text += "assert!(sections == crate::verb_names::SECTION_VERBS.len());\n";
    for (at, row) in section.iter().enumerate() {
        let variant = variant_of(variants, row)?;
        text += &format!(
            "assert!(AgentVerb::{variant}.is_section() && same(crate::verb_names::SECTION_VERBS[{at}], AgentVerb::{variant}.as_str()));\n"
        );
    }
    for (at, row) in generator.rows.select(custody).iter().enumerate() {
        let variant = variant_of(variants, row)?;
        text += &format!(
            "assert!(same(crate::verb_names::CUSTODY_VALUE_ROWS[{at}], AgentVerb::{variant}.as_str()));\n"
        );
        text += &format!(
            "assert!(matches!(AgentVerb::{variant}.custody_member(), Some(member) if same(member, crate::verb_names::CUSTODY_VALUE_MEMBERS[{at}])));\n"
        );
    }
    text += "};\n";
    Ok(text)
}

/// The `catalog` segment's result: `verb_catalog.rs`'s text and the custody rows, which `core_verb_names` reads later
/// (generate.py:2518).
pub(crate) struct Catalog {
    pub(crate) text: String,
    pub(crate) custody: Vec<RowId>,
}

/// Port of generate.py:2462-2508 (outputs: the `catalog` segment): `verb_catalog.rs`, the `AgentVerb` enum over
/// `ROWS` with each role a row states, and its compile-time check of core's table.
pub(crate) fn catalog(generator: &Generator) -> Result<Catalog, GenerateError> {
    let rows = generator.rows.select(&generator.callable_rows);
    let variants = variants(&rows)?;
    let mut catalog = HEADER.to_owned()
        + "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum AgentVerb { ";
    catalog += &variants.values().cloned().collect::<Vec<_>>().join(",");
    catalog += " }\nimpl AgentVerb {\n";
    catalog += "pub const ALL: &[Self] = &[";
    catalog += &variants
        .values()
        .map(|variant| format!("Self::{variant}"))
        .collect::<Vec<_>>()
        .join(",");
    catalog += "];\n";
    catalog += "pub fn from_name(name: &str) -> Option<Self> { Self::ALL.iter().copied().find(|verb| verb.as_str() == name) }\n";
    catalog += "pub const fn as_str(self) -> &'static str { match self {\n";
    for row in &rows {
        catalog += &format!(
            "Self::{} => {},\n",
            variant_of(&variants, row)?,
            json_item(row, "name")?
        );
    }
    catalog += "} }\n";
    for (method, select) in CATALOG_ROLES {
        let mut selected = Vec::new();
        for row in &rows {
            if select(generator, row)? {
                selected.push(format!("Self::{}", variant_of(&variants, row)?));
            }
        }
        catalog += &format!(
            "pub const fn {method}(self) -> bool {{ matches!(self, {}) }}\n",
            if selected.is_empty() {
                "_ if false".to_owned()
            } else {
                selected.join(" | ")
            }
        );
    }
    for (method, field) in [
        ("argument_fields", "mcp_fields"),
        ("required_fields", "mcp_required_fields"),
    ] {
        catalog += &format!(
            "pub const fn {method}(self) -> &'static [&'static str] {{ match self {{\n"
        );
        for row in &rows {
            // `r.get(field, r['mcp_fields'])`: the default is read first, as Python evaluates it.
            let fields = item(row, "mcp_fields")?;
            let fields = row.get(field).unwrap_or(fields).iterate()?;
            catalog += &format!(
                "Self::{} => &{},\n",
                variant_of(&variants, row)?,
                json(&Value::List(fields))
            );
        }
        catalog += "} }\n";
    }
    catalog += "/// The row's one-line description, as the verb table states it.\n";
    catalog += "pub const fn description(self) -> &'static str { match self {\n";
    for row in &rows {
        let description = row
            .get("description")
            .map_or_else(|| json(&Value::Str(String::new())), json);
        catalog += &format!(
            "Self::{} => {description},\n",
            variant_of(&variants, row)?
        );
    }
    catalog += "} }\n";
    let custody = custody_rows(generator);
    catalog += "/// The member of a custody row's input that holds the secret's value or its sealed input (`custody` on the row).\n";
    catalog += "pub const fn custody_member(self) -> Option<&'static str> { match self {\n";
    for row in generator.rows.select(&custody) {
        catalog += &format!(
            "Self::{} => Some({}),\n",
            variant_of(&variants, row)?,
            json_item(row, "custody")?
        );
    }
    catalog += "_ => None,\n} }\n";
    catalog += "/// The read a run bound to a session serves through its room's view (`session_read` on the row).\n";
    catalog += "pub(crate) const fn session_read(self) -> Option<crate::memory::SessionRead> { match self {\n";
    for row in &rows {
        if row.contains_key("session_read") {
            catalog += &format!(
                "Self::{} => Some(crate::memory::SessionRead::{}),\n",
                variant_of(&variants, row)?,
                concat(item(row, "session_read")?)?
            );
        }
    }
    catalog += "_ => None,\n} }\n";
    catalog += "}\n";
    catalog += "pub use crate::verb_names::CUSTODY_VALUE_ROWS;\n";
    catalog += &core_verb_names_check(generator, &variants, &custody)?;
    Ok(Catalog {
        text: catalog,
        custody,
    })
}

/// A role predicate of generate.py:2469-2483, over one row of `ROWS`.
type CatalogRole = fn(&Generator, &Dict) -> Result<bool, GenerateError>;

/// generate.py:2469-2483: each `AgentVerb` role method and the rows it selects, in the list's order.
const CATALOG_ROLES: &[(&str, CatalogRole)] = &[
    ("is_facade", |generator, row| {
        // `r.get('context', 'memory') == 'memory' or r['name'] in BOARD_HOST_NAMES`
        Ok(context_is(row, "memory") || {
            let name = item(row, "name")?;
            generator
                .board_host_names
                .iter()
                .any(|board| board.py_eq(name))
        })
    }),
    ("is_browser", |generator, row| {
        // `r['name'] in {row['name'] for row in BROWSER_ROWS}`
        let name = item(row, "name")?;
        let mut browser = Vec::new();
        for &id in &generator.browser_rows {
            set_add(&mut browser, item(&generator.rows[id], "name")?.clone())?;
        }
        name.check_hashable("a set element")?;
        Ok(browser.iter().any(|browser| browser.py_eq(name)))
    }),
    ("is_mcp", |_, row| Ok(!get_is(row, "mcp", "none"))),
    ("is_section", |_, row| Ok(item(row, "section")?.truthy())),
    ("continuable", |_, row| {
        // `r.get('mcp_page', 'page' in r or r['output'].startswith('Vec<'))`: the default is evaluated first.
        let default = row.contains_key("page")
            || text(row, "output", "startswith")?.starts_with("Vec<");
        Ok(row.get("mcp_page").map_or(default, Value::truthy))
    }),
    ("filtered_read", |_, row| {
        Ok(item(row, "mcp_scope")?.is_str("filtered"))
    }),
    ("requires_unscoped", |_, row| {
        Ok(item(row, "mcp_scope")?.is_str("unrestricted"))
    }),
    ("born_in_scope", |_, row| {
        Ok(item(row, "mcp_scope")?.is_str("born"))
    }),
    ("writes", |_, row| Ok(item(row, "scope")?.is_str("Write"))),
    ("proposes", |_, row| Ok(flag(row, "proposes"))),
    ("is_task_work", |_, row| Ok(flag(row, "task_work"))),
    ("takes_task_decisions", |_, row| {
        Ok(super::emit_mcp::takes_task_decisions(row))
    }),
    ("overlay_write", |_, row| Ok(flag(row, "overlay_write"))),
];
