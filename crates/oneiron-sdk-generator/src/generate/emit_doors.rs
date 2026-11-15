//! The server doors the generator writes from their verb rows (UC-01 PR 1; fable/19 DESIGN sections 1.3 and 1.5):
//! the server's `generated/doors.rs`, one door fn for each host-door row without `"door": "hand"`, and the lib's
//! `mod calls`, the engine half each such door runs. A row's `call` is written once over the bound names of
//! [`BOUND_NAMES`], and each transport binds them: the embedded SDK fn from its handle, the server door from the
//! rule's proof and the dispatch.
//!
//! A door is generated only for a row whose rule is in [`GENERATED_RULES`]. Any other door row keeps
//! `"door": "hand"`, and [`check_door_row`] refuses, naming the row, a generated row that its rule or its transport
//! cannot serve.

use std::collections::BTreeSet;

use super::row_access::{flag, get_is, has_door, item, json_item, method_name, shown};
use super::rows::{IN_DOOR, refuse};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::value::{Dict, Value};

/// The names a row's `call` may use, in the order a `calls` fn takes them (DESIGN section 1.3). `server` (a host
/// call, which needs `runs: host`, UC-01 PR 5.1) and `answer` (bound only in `rows`) are names too, so a call that
/// says either is refused rather than read as a free variable.
pub(crate) const BOUND_NAMES: &[&str] = &[
    "memory", "vault", "owner", "surface", "input", "server", "answer",
];

/// The rules a door is generated for, each with its type in `host_doors::proofs`. Each one proves the owner's
/// `AuthenticatedOwner`, and says which actor the credential's handle reads as (`proofs::HandleRule`). A rule joins
/// when its door PR writes that.
const GENERATED_RULES: &[(&str, &str)] = &[("owner", "Owner")];

/// The dispatch arguments a generated door does not take: a row with one keeps its hand door.
const HAND_DOOR_FLAGS: &[(&str, &str)] = &[
    ("host_door_caller", "caller"),
    ("host_door_session", "session"),
    ("host_door_paced", "paced context"),
    ("host_door_lens_owner", "lens owner"),
    ("host_door_client_surface", "client surface"),
];

/// `text` with the inside of each string literal blanked, so a verb name in a call (`"vault.x"`) names nothing.
fn blank_strings(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
                out.push(' ');
            } else if ch == '\\' {
                escaped = true;
                out.push(' ');
            } else if ch == '"' {
                in_string = false;
                out.push('"');
            } else {
                out.push(' ');
            }
        } else {
            in_string = ch == '"';
            out.push(ch);
        }
    }
    out
}

/// Each identifier of `text` with its byte span.
fn identifiers(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let start = at;
        if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                at += 1;
            }
            // An identifier glued to a digit run before it is part of a literal (`1u8`), never a name.
            if start == 0 || !bytes[start - 1].is_ascii_digit() {
                spans.push((start, at));
            }
        } else {
            at += 1;
        }
    }
    spans
}

/// The names `text` binds itself: those in a `let` pattern (up to its `=`) and in a closure's parameter list
/// (a `|...|` opened after `move`, `(`, `,`, `=` or at the start).
fn self_bound(text: &str) -> BTreeSet<String> {
    let mut bound = BTreeSet::new();
    let mut name_spans = |span: &str| {
        for (start, end) in identifiers(span) {
            bound.insert(span[start..end].to_owned());
        }
    };
    for (start, end) in identifiers(text) {
        if &text[start..end] == "let" {
            let rest = &text[end..];
            let pattern = rest.find('=').map_or(rest, |at| &rest[..at]);
            name_spans(pattern);
        }
    }
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'|' {
            let before = text[..at].trim_end();
            let opens =
                before.is_empty() || before.ends_with("move") || before.ends_with(['(', ',', '=']);
            if let Some(close) = text[at + 1..].find('|').filter(|_| opens) {
                name_spans(&text[at + 1..at + 1 + close]);
                at += close + 2;
                continue;
            }
        }
        at += 1;
    }
    bound
}

/// The bound names `expr` uses: each one standing alone outside a string literal, that is not a path segment
/// (`crate::memory::X`), a field or method (`.vault`), a path head (`owner::X`), a lifetime (`'memory`) or a struct
/// literal's field name (`Foo { owner: x }`), and that `expr` does not bind itself (`let owner = ...`, `|owner|`).
/// A generator reads text, not Rust: a call that shadows a bound name any other way is the row writer's to rename.
pub(crate) fn free_names(expr: &str) -> BTreeSet<&'static str> {
    let text = blank_strings(expr);
    let own = self_bound(&text);
    let mut used = BTreeSet::new();
    for (start, end) in identifiers(&text) {
        let Some(&name) = BOUND_NAMES.iter().find(|&&name| name == &text[start..end]) else {
            continue;
        };
        let before = text[..start].trim_end();
        let after = text[end..].trim_start();
        let segment =
            before.ends_with("::") || before.ends_with('.') || text[..start].ends_with('\'');
        let head = after.starts_with("::");
        let field = after.starts_with(':') && !head;
        if !(segment || head || field || own.contains(name)) {
            used.insert(name);
        }
    }
    used
}

/// The inside of each string literal of `text`.
fn string_literals(text: &str) -> Vec<&str> {
    let mut literals = Vec::new();
    let mut open: Option<usize> = None;
    let mut escaped = false;
    for (at, ch) in text.char_indices() {
        let Some(start) = open else {
            if ch == '"' {
                open = Some(at + 1);
            }
            continue;
        };
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            literals.push(&text[start..at]);
            open = None;
        }
    }
    literals
}

/// The bound names a string literal of `expr` names inside its braces: a format string's implicit capture
/// (`format!("{input}")`, `{input:?}`, the width in `{:>surface$}`). [`free_names`] blanks every string, so
/// [`check_names`] refuses such a call rather than miss the name (Astra review of UC-01 PR 1, F1). `{{` is a brace.
fn format_captures(expr: &str) -> BTreeSet<&'static str> {
    let mut captured = BTreeSet::new();
    for literal in string_literals(expr) {
        for group in literal.replace("{{", "").split('{').skip(1) {
            let group = group.split_once('}').map_or(group, |(head, _)| head);
            for (start, end) in identifiers(group) {
                if let Some(&name) = BOUND_NAMES.iter().find(|&&name| name == &group[start..end]) {
                    captured.insert(name);
                }
            }
        }
    }
    captured
}

/// Whether `row` gets a generated door: a host-door row that does not say `"door": "hand"`.
pub(crate) fn generated(row: &Dict) -> bool {
    has_door(row) && !row.contains_key("door")
}

/// The type of `rule` in `host_doors::proofs`, when a door is generated for it.
fn rule_type(rule: &Value) -> Option<&'static str> {
    GENERATED_RULES
        .iter()
        .find(|(name, _)| rule.is_str(name))
        .map(|&(_, rule_type)| rule_type)
}

/// The text of `row[key]`, refused when it is no string.
fn expression<'r>(row: &'r Dict, key: &str, what: &str) -> Result<&'r str, GenerateError> {
    item(row, key)?
        .as_str()
        .ok_or_else(|| refuse(row, &format!("`{key}` is {what}, one Rust expression")))
}

/// The checks of a row's bound names, for every row (DESIGN section 1.3): no string literal names one (a format
/// capture, which [`free_names`] cannot see), an embedded SDK fn binds no `server` and no `answer`, and `rows` belongs
/// to a generated door, over `answer` or `input`.
pub(crate) fn check_names(row: &Dict) -> Result<(), GenerateError> {
    for key in ["call", "file_call", "rows"] {
        let Some(text) = row.get(key).and_then(Value::as_str) else {
            continue;
        };
        if let Some(name) = format_captures(text).first() {
            return Err(refuse(
                row,
                &format!(
                    "`{key}` names `{name}` inside a string (`{{{name}}}`): the generator reads no format string, so \
                     pass it as an argument (`format!(\"{{}}\", {name})`)"
                ),
            ));
        }
    }
    for key in ["call", "file_call"] {
        let Some(call) = row.get(key).and_then(Value::as_str) else {
            continue;
        };
        let names = free_names(call);
        if names.contains("server") {
            return Err(refuse(
                row,
                &format!(
                    "`{key}` uses `server`, which only a host call binds (`runs: host`, UC-01 PR 5.1); keep the host \
                     work in the hand door"
                ),
            ));
        }
        if names.contains("answer") {
            return Err(refuse(
                row,
                &format!("`{key}` uses `answer`, which only `rows` binds"),
            ));
        }
    }
    if row.contains_key("rows") {
        if !generated(row) {
            return Err(refuse(
                row,
                "`rows` names the rows a generated door's answer or input names; a hand door lists its own",
            ));
        }
        let names = free_names(expression(row, "rows", "the rows a door names")?);
        let other: Vec<&str> = names
            .iter()
            .copied()
            .filter(|name| !matches!(*name, "answer" | "input"))
            .collect();
        if !other.is_empty() {
            return Err(refuse(
                row,
                &format!(
                    "`rows` uses `{}`; it binds only `answer` and `input`",
                    other.join("`, `")
                ),
            ));
        }
        if names.contains("answer") && names.contains("input") {
            return Err(refuse(
                row,
                "`rows` reads `answer` or `input`, not both: the call moves `input` before `answer` exists",
            ));
        }
    }
    Ok(())
}

/// The checks of a host-door row whose door is generated (DESIGN sections 1.3 and 2.4): its rule has a generated
/// door, its `call` is one expression over names its rule and transport bind, the dispatch hands it only what its
/// call uses, and it lists its rows.
pub(crate) fn check_door_row(row: &Dict) -> Result<(), GenerateError> {
    if !generated(row) {
        return Ok(());
    }
    let keep = "; keep \"door\": \"hand\"";
    let rule = item(row, "proof")?;
    if rule.is_str(IN_DOOR) {
        return Err(refuse(
            row,
            "`\"proof\": \"in_door\"` is a hand door's: its door proves its caller itself, so the row says \
             \"door\": \"hand\"",
        ));
    }
    if rule_type(rule).is_none() {
        return Err(refuse(
            row,
            &format!(
                "rule `{}` has no generated door yet (generated: {}){keep}",
                rule.str(),
                GENERATED_RULES
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    let call = expression(row, "call", "a generated door's engine call")?;
    for &(key, what) in HAND_DOOR_FLAGS {
        if flag(row, key) {
            return Err(refuse(
                row,
                &format!("a generated door takes no {what} from the dispatch (`{key}`){keep}"),
            ));
        }
    }
    let uses_surface = free_names(call).contains("surface");
    if uses_surface != flag(row, "host_door_surface") {
        return Err(refuse(
            row,
            "a generated door takes the act surface (`host_door_surface`) exactly when its call uses `surface`",
        ));
    }
    if !flag(row, "lists") {
        return Err(refuse(
            row,
            &format!("a generated door answers beside the rows it read (`lists`){keep}"),
        ));
    }
    for key in ["rust_feature", "file_call"] {
        if row.contains_key(key) {
            return Err(refuse(
                row,
                &format!("a generated door's row has no `{key}`{keep}"),
            ));
        }
    }
    if get_is(row, "name", "self.fold") {
        return Err(refuse(
            row,
            &format!("the fold's door takes its pre hooks{keep}"),
        ));
    }
    Ok(())
}

/// `call[:-1] if call.endswith('?') else f'Ok({call})'`: an engine call's own result, or its value wrapped.
pub(crate) fn call_result(call: &str) -> String {
    match call.strip_suffix('?') {
        Some(head) => head.to_owned(),
        None => format!("Ok({call})"),
    }
}

/// The `let` lines with which an embedded SDK fn binds the names `call` uses beyond its parameters `memory` and
/// `input`: the handle's vault, the owner the handle proves for the verb, and this install as the act surface.
pub(crate) fn embedded_bindings(row: &Dict, call: &str) -> Result<String, GenerateError> {
    let names = free_names(call);
    let mut lines = String::new();
    if names.contains("vault") {
        lines += "let vault = memory.vault(); ";
    }
    if names.contains("owner") {
        lines += &format!(
            "let owner = &memory.embedded_owner({})?; ",
            json_item(row, "name")?
        );
    }
    if names.contains("surface") {
        lines += "let surface = crate::authority::ActSurface::ThisInstall; ";
    }
    Ok(lines)
}

/// The lib's `mod calls` (DESIGN section 1.5): for each generated door's row, its call as a fn of the bound names
/// it uses, in [`BOUND_NAMES`] order, which the server door runs under the rule's proof. The embedded SDK fn keeps
/// its own copy of the call with the names bound from its handle (`embedded_bindings`), so its checks and its call
/// read as before.
pub(crate) fn calls_module(
    generator: &Generator,
    facade_rows: &[RowId],
) -> Result<String, GenerateError> {
    let mut fns = String::new();
    for row in generator.rows.select(facade_rows) {
        if generated(row) {
            fns += &calls_fn(row)?;
        }
    }
    if fns.is_empty() {
        return Ok(String::new());
    }
    Ok(format!(
        "/// The engine calls of the rows whose server door is generated (UC-01 PR 1): each row's `call` over the\n/// names it uses, bound by the door from the rule's proof.\npub mod calls {{\nuse super::*;\n{fns}}}\n"
    ))
}

/// One row's engine call as a `calls` fn of the bound names it uses.
fn calls_fn(row: &Dict) -> Result<String, GenerateError> {
    let call = expression(row, "call", "a generated door's engine call")?;
    let names = free_names(call);
    let mut params = Vec::new();
    for name in BOUND_NAMES.iter().filter(|name| names.contains(*name)) {
        params.push(match *name {
            "memory" => "memory: &Memory<'_>".to_owned(),
            "vault" => "vault: &crate::Vault".to_owned(),
            "owner" => "owner: &crate::consent::AuthenticatedOwner".to_owned(),
            "surface" => "surface: crate::authority::ActSurface".to_owned(),
            _ => format!("input: {}", shown(row, "input")?),
        });
    }
    Ok(format!(
        "/// `{}`'s engine call, which its generated server door runs.\npub fn {}({}) -> MemoryResult<{}> {{ {} }}\n",
        shown(row, "name")?,
        method_name(row)?,
        params.join(", "),
        shown(row, "output")?,
        call_result(call)
    ))
}

/// A row type as the server names it: a bare name is the SDK module's, an engine path is under `oneiron::`.
fn server_type(text: &str) -> String {
    let bare = text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if bare && !super::common::RUST_PRIMITIVES.contains(&text) {
        format!("oneiron::task_verb::sdk::{text}")
    } else {
        text.replace("crate::", "oneiron::")
    }
}

/// The server's `generated/doors.rs` (DESIGN section 1.5): for each host-door row without `"door": "hand"`, the door
/// the facade and MCP dispatch call by the row's name (`host_doors::<verb>`), with the arguments they hand a hand
/// door. It runs the row's call through `host_doors::door`: off the runtime under the rule's proof, on the
/// credential's handle when the call uses `memory`, beside the rows that handle listed and those `rows` names.
pub(crate) fn doors(generator: &Generator, facade_rows: &[RowId]) -> Result<String, GenerateError> {
    let mut out = HEADER.to_owned();
    out += "// The host doors generated from their verb rows (UC-01 PR 1): each runs its row's engine call\n// (`oneiron::task_verb::sdk::calls`) under the proof rule its row names. Edit the row, not this file.\n";
    for row in generator.rows.select(facade_rows) {
        if generated(row) {
            out += &door_fn(row)?;
        }
    }
    Ok(out)
}

/// One generated door: the helper of its handle (`door_on_handle` when the call uses `memory`, else `door`) under its
/// rule, the call's names bound from the closure's server, handle and proof, then the rows `rows` names.
fn door_fn(row: &Dict) -> Result<String, GenerateError> {
    let rule = item(row, "proof")?;
    let rule_type = rule_type(rule)
        .ok_or_else(|| refuse(row, "a generated door's rule has no generated door"))?;
    let call = expression(row, "call", "a generated door's engine call")?;
    let names = free_names(call);
    let verb = json_item(row, "name")?;
    let method = method_name(row)?;
    let server_name = if names.contains("vault") {
        "server"
    } else {
        "_"
    };
    let owner_name = if names.contains("owner") {
        "owner"
    } else {
        "_"
    };
    let (helper, params) = if names.contains("memory") {
        (
            "door_on_handle",
            format!("{server_name}, memory, {owner_name}"),
        )
    } else {
        ("door", format!("{server_name}, {owner_name}"))
    };
    let args: Vec<&str> = BOUND_NAMES
        .iter()
        .filter(|name| names.contains(*name))
        .map(|name| {
            if *name == "vault" {
                "server.vault()"
            } else {
                name
            }
        })
        .collect();
    let surface_param = if names.contains("surface") {
        "surface: oneiron::authority::ActSurface,\n    "
    } else {
        ""
    };
    let rows = row
        .contains_key("rows")
        .then(|| expression(row, "rows", "the rows a door names"))
        .transpose()?;
    let rows_read_input = rows.is_some_and(|rows| free_names(rows).contains("input"));
    let input_param = if names.contains("input") || rows_read_input {
        "input"
    } else {
        "_input"
    };
    let door = format!(
        "super::door::{helper}::<super::proofs::{rule_type}, _>(server, auth, {verb}, move |{params}| {{\n        oneiron::task_verb::sdk::calls::{method}({})\n    }})\n    .await",
        args.join(", ")
    );
    // `rows` adds to a success the rows its answer or its input names; `input` is read before the call moves it.
    let body = match rows {
        None => door,
        Some(rows) if rows_read_input => format!(
            "let named = {rows};\n    let (answer, mut listed) = {door};\n    if answer.is_ok() {{\n        listed.extend(named);\n    }}\n    (answer, listed)"
        ),
        Some(rows) => format!(
            "let (answer, mut listed) = {door};\n    if let Ok(answer) = &answer {{\n        listed.extend({rows});\n    }}\n    (answer, listed)"
        ),
    };
    Ok(format!(
        "\n/// `{}`'s door, generated from its row: its call under rule `{}`.\npub(crate) async fn {method}(\n    server: &std::sync::Arc<crate::server::SyncServer>,\n    auth: &crate::auth::CoreAuth,\n    {surface_param}{input_param}: {},\n) -> super::support::Listed<{}> {{\n    {body}\n}}\n",
        shown(row, "name")?,
        rule.str(),
        server_type(&shown(row, "input")?),
        server_type(&shown(row, "output")?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(expr: &str) -> Vec<&'static str> {
        free_names(expr).into_iter().collect()
    }

    #[test]
    fn free_names_reads_only_standalone_unbound_names() {
        let cases: &[(&str, &[&str])] = &[
            (
                "memory.commitments_create_as(owner, input)?",
                &["input", "memory", "owner"],
            ),
            (
                "crate::dreamer_runner::free_time_policy_as_owner(vault, owner, &input).map_err(crate::memory::MemoryError::from)?",
                &["input", "owner", "vault"],
            ),
            // The old form: the verb name is a string, `memory.vault()` a method.
            (
                "f(memory.vault(), &memory.embedded_owner(\"vault.owner.get\")?, &input)?",
                &["input", "memory"],
            ),
            ("crate::authority::ActSurface::ThisInstall", &[]),
            ("crate::server::x(input)", &["input"]),
            ("owner::Kind::A", &[]),
            ("Foo { owner: input.a, vault }", &["input", "vault"]),
            // The four cluster rows bind `owner` themselves.
            (
                "{ let owner = if input.grant_ref.is_none() { Some(memory.embedded_owner(\"v\")?) } else { None }; memory.cluster_merge(owner, input)? }",
                &["input", "memory"],
            ),
            ("items.iter().map(|answer| answer.id)", &[]),
            (
                "f(move |server, owner| g(server, owner), input)",
                &["input"],
            ),
            ("vec![answer.skill, answer.proposal]", &["answer"]),
            ("x.server_vault(serverless, 'memory)", &[]),
        ];
        for &(expr, expected) in cases {
            assert_eq!(names(expr), expected, "{expr}");
        }
    }

    #[test]
    fn format_captures_read_bound_names_in_braces() {
        let cases: &[(&str, &[&str])] = &[
            ("format!(\"{input}\")", &["input"]),
            ("format!(\"{input:?} for {owner}\")", &["input", "owner"]),
            ("format!(\"{:>surface$}\", x)", &["surface"]),
            ("format!(\"{{{input}}}\")", &["input"]),
            ("format!(\"{{input}}\")", &[]),
            ("format!(\"{0} {x:?}\", input)", &[]),
            (
                "f(\"vault.owner.get\", \"a \\\"{memory}\\\"\")",
                &["memory"],
            ),
            ("memory.f(owner, input)?", &[]),
        ];
        for &(expr, expected) in cases {
            let got: Vec<&str> = format_captures(expr).into_iter().collect();
            assert_eq!(got, expected, "{expr}");
        }
    }

    fn row(text: &str) -> Dict {
        crate::py::json::loads(text)
            .expect("a row")
            .as_dict()
            .expect("a dict")
            .clone()
    }

    #[test]
    fn doors_bind_the_names_their_call_uses() {
        let get = row(
            r#"{"name": "vault.free_time.policy.get", "input": "crate::dreamer_runner::FreeTimePolicyRequest", "output": "crate::dreamer_runner::FreeTimePolicyView", "proof": "owner", "lists": true, "call": "crate::dreamer_runner::free_time_policy_as_owner(vault, owner, &input).map_err(crate::memory::MemoryError::from)?"}"#,
        );
        let door = door_fn(&get).unwrap();
        assert!(door.contains("    input: oneiron::dreamer_runner::FreeTimePolicyRequest,\n) -> super::support::Listed<oneiron::dreamer_runner::FreeTimePolicyView> {"), "{door}");
        assert!(door.contains("super::door::door::<super::proofs::Owner, _>(server, auth, \"vault.free_time.policy.get\", move |server, owner| {"), "{door}");
        assert!(door.contains("oneiron::task_verb::sdk::calls::vault_free_time_policy_get(server.vault(), owner, input)"), "{door}");
        assert_eq!(
            calls_fn(&get).unwrap(),
            "/// `vault.free_time.policy.get`'s engine call, which its generated server door runs.\npub fn vault_free_time_policy_get(vault: &crate::Vault, owner: &crate::consent::AuthenticatedOwner, input: crate::dreamer_runner::FreeTimePolicyRequest) -> MemoryResult<crate::dreamer_runner::FreeTimePolicyView> { crate::dreamer_runner::free_time_policy_as_owner(vault, owner, &input).map_err(crate::memory::MemoryError::from) }\n"
        );
        assert_eq!(
            embedded_bindings(&get, &shown(&get, "call").unwrap()).unwrap(),
            "let vault = memory.vault(); let owner = &memory.embedded_owner(\"vault.free_time.policy.get\")?; "
        );
        let route = row(
            r#"{"name": "vault.commitments.reminder_route.get", "input": "EmptyRequest", "output": "crate::memory::commitment_doors::CommitmentReminderRouteReply", "proof": "owner", "lists": true, "call": "memory.commitments_reminder_route_get_as(owner)?"}"#,
        );
        let door = door_fn(&route).unwrap();
        assert!(
            door.contains("    _input: oneiron::task_verb::sdk::EmptyRequest,\n"),
            "{door}"
        );
        assert!(door.contains("super::door::door_on_handle::<super::proofs::Owner, _>(server, auth, \"vault.commitments.reminder_route.get\", move |_, memory, owner| {"), "{door}");
        assert!(
            door.contains("calls::vault_commitments_reminder_route_get(memory, owner)\n"),
            "{door}"
        );
        let set = row(
            r#"{"name": "vault.x.set", "input": "crate::x::SetRequest", "output": "crate::x::View", "proof": "owner", "lists": true, "host_door_surface": true, "call": "crate::x::set(vault, owner, surface, &input)?", "rows": "vec![input.binding]"}"#,
        );
        let door = door_fn(&set).unwrap();
        assert!(
            door.contains(
                "    surface: oneiron::authority::ActSurface,\n    input: oneiron::x::SetRequest,\n"
            ),
            "{door}"
        );
        assert!(
            door.contains("calls::vault_x_set(server.vault(), owner, surface, input)"),
            "{door}"
        );
        assert!(door.contains("    let named = vec![input.binding];\n    let (answer, mut listed) = super::door::door::<"), "{door}");
        assert!(door.contains("    if answer.is_ok() {\n        listed.extend(named);\n    }\n    (answer, listed)\n}"), "{door}");
    }

    #[test]
    fn server_type_places_bare_and_engine_names() {
        for (text, expected) in [
            ("EmptyRequest", "oneiron::task_verb::sdk::EmptyRequest"),
            ("crate::a::B", "oneiron::a::B"),
            ("Option<crate::a::B>", "Option<oneiron::a::B>"),
            ("Vec<crate::a::B>", "Vec<oneiron::a::B>"),
            ("bool", "bool"),
        ] {
            assert_eq!(server_type(text), expected, "{text}");
        }
    }
}
