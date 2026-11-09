//! Port of generate.py:853-1417: the MCP dispatch (`agent_verb_dispatch.rs`, which `outputs()` prefixes with
//! `HEADER` and `use super::*;`), its argument projections and the task-work rules the server's doors share (G4a).

use super::common::{rust_type, str_receiver};
use super::emit_server::{CALL_HOME_DOORS, HOME_SERVER_DOORS, SOURCE_FEEDBACK_DOORS};
use super::row_access::{flag, flag_in, get_is, item, json, method_name, shown, text};
use super::{Generator, RowId};
use crate::error::GenerateError;
use crate::py::json::dumps_str;
use crate::py::re::search_bare_invalid;
use crate::py::value::{Dict, Value};

/// Port of generate.py:853 (MCP_ARGUMENT_FIELDS): an MCP argument whose Rust field is named apart.
pub(crate) const MCP_ARGUMENT_FIELDS: &[(&str, &str)] = &[("self", "self_target")];

/// `row['mcp_fields']`, a dict (the module level read its `.values()`).
fn mcp_fields(row: &Dict) -> Result<&crate::py::value::Dict, GenerateError> {
    let fields = item(row, "mcp_fields")?;
    fields
        .as_dict()
        .ok_or_else(|| GenerateError::attribute(fields.type_name(), "items"))
}

/// Port of generate.py:855-880 (mcp_input_projection): one row of the tools/call projection, its arguments
/// assembled into the typed input.
pub(crate) fn mcp_input_projection(row: &Dict) -> Result<String, GenerateError> {
    let fields = mcp_fields(row)?;
    let all = item(row, "mcp_fields")?;
    let required = row.get("mcp_required_fields").unwrap_or(all);
    let root: Vec<&str> = fields
        .iter()
        .filter(|(_, path)| path.is_str("$"))
        .map(|(field, _)| field.as_str())
        .collect();
    let others: Vec<(&str, &Value)> = fields
        .iter()
        .filter(|(_, path)| !path.is_str("$"))
        .map(|(field, path)| (field.as_str(), path))
        .collect();
    let name = json_item_name(row)?;
    if others.is_empty() {
        let head = match root.first() {
            Some(root) => format!("a.{root}.clone().ok_or_else(invalid)"),
            None => "Ok(Value::Object(serde_json::Map::new()))".to_owned(),
        };
        return Ok(format!("{name} => {head},\n"));
    }
    let mut lines = match root.first() {
        Some(root) => vec![
            format!("let mut input = a.{root}.clone().ok_or_else(invalid)?;"),
            "let map = input.as_object_mut().ok_or_else(invalid)?;".to_owned(),
        ],
        None => vec!["let mut map = serde_json::Map::new();".to_owned()],
    };
    let mut equalities = Vec::new();
    for (field, path) in others {
        let member = format!(
            "a.{}",
            MCP_ARGUMENT_FIELDS
                .iter()
                .find(|(argument, _)| *argument == field)
                .map_or(field, |(_, member)| member)
        );
        let path_text = str_receiver(path, "startswith")?;
        if let Some(rest) = path_text.strip_prefix('=') {
            // A redundant envelope field must name what the input names.
            equalities.push(format!(
                "if {member}.as_deref() != map.get({}).and_then(Value::as_str) {{ return Err(invalid()); }}",
                dumps_str(rest)
            ));
        } else if required.contains_str(field)? {
            lines.push(format!(
                "map.insert({}.to_owned(), json!({member}.as_ref().ok_or_else(invalid)?));",
                json(path)
            ));
        } else {
            lines.push(format!(
                "if let Some(value) = &{member} {{ map.insert({}.to_owned(), json!(value)); }}",
                json(path)
            ));
        }
    }
    lines.extend(equalities);
    lines.push(if root.is_empty() {
        "Ok(Value::Object(map))".to_owned()
    } else {
        "Ok(input)".to_owned()
    });
    Ok(format!("{name} => {{\n{}\n}},\n", lines.join("\n")))
}

/// `json.dumps(row["name"])`.
fn json_item_name(row: &Dict) -> Result<String, GenerateError> {
    Ok(json(item(row, "name")?))
}

/// Port of generate.py:882-890 (mcp_argument_projection): the inverse, the tools/call arguments one code-mode input
/// projects onto.
pub(crate) fn mcp_argument_projection(row: &Dict) -> Result<String, GenerateError> {
    let mut lines = Vec::new();
    for (field, path) in mcp_fields(row)? {
        if path.is_str("$") {
            lines.push(format!(
                "arguments.insert({}.to_owned(), input.clone());",
                dumps_str(field)
            ));
        } else {
            let path = str_receiver(path, "removeprefix")?;
            lines.push(format!(
                "if let Some(value) = input.get({}) {{ arguments.insert({}.to_owned(), value.clone()); }}",
                dumps_str(path.strip_prefix('=').unwrap_or(path)),
                dumps_str(field)
            ));
        }
    }
    Ok(format!(
        "{} => {{\n{}\n}},\n",
        json_item_name(row)?,
        lines.join("\n")
    ))
}

/// Port of generate.py:899-901 (takes_task_decisions): whether the served doors run this row on a worker with the
/// decision ladder bound (OF-533, FIX 2762). Absent is false.
pub(crate) fn takes_task_decisions(row: &Dict) -> bool {
    flag(row, "task_decisions")
}

/// Port of generate.py:909-910 (TASK_PRODUCER_ROWS): Rule 5 (FIX 2166), plain memory rows whose engine call is a
/// task-work producer.
pub(crate) const TASK_PRODUCER_ROWS: &[&str] = &[
    "tasks.accept",
    "vault.projects.route_tradeoff",
    "vault.artifacts.body.fork.merge",
    "vault.artifacts.body.proposal.settle",
];

/// Port of generate.py:917 (TASK_PRODUCER_BRANCHES): rows one branch of whose engine call is a task-work producer,
/// each keyed to the predicate over the request that says it takes that branch.
pub(crate) const TASK_PRODUCER_BRANCHES: &[(&str, &str)] = &[(
    "describe",
    "oneiron::task_verb::sdk::describe_takes_task_work_turn",
)];

/// Port of generate.py:919-922 (task_producer_branch_turns): the MCP turn test for each producer branch, over the
/// args its pre hooks left.
pub(crate) fn task_producer_branch_turns(args: &str) -> String {
    let turns: Vec<String> = TASK_PRODUCER_BRANCHES
        .iter()
        .map(|(name, predicate)| format!("(tool == {} && {predicate}(&{args}))", dumps_str(name)))
        .collect();
    if turns.is_empty() {
        "false".to_owned()
    } else {
        turns.join(" || ")
    }
}

/// Port of generate.py:924-932 (takes_task_work_turn): whether the served doors await a task-work turn for this row
/// and bind it.
pub(crate) fn takes_task_work_turn(row: &Dict) -> Result<bool, GenerateError> {
    let name = item(row, "name")?;
    if !TASK_PRODUCER_ROWS
        .iter()
        .any(|producer| name.is_str(producer))
    {
        return Ok(flag(row, "task_work"));
    }
    if flag(row, "host_door")
        || flag(row, "server_door")
        || !super::row_access::context_is(row, "memory")
        || flag_in(row, "admission", "born_record_scope")?
        || readable_contains(row, "rows")?
        || takes_task_decisions(row)
    {
        return Err(GenerateError::value(format!(
            "{}: a task-work producer row is a plain memory row",
            name.str()
        )));
    }
    Ok(true)
}

/// `needle in row.get('admission', {}).get('readable', [])`.
pub(crate) fn readable_contains(row: &Dict, needle: &str) -> Result<bool, GenerateError> {
    match super::row_access::get_in(row, "admission", "readable")? {
        None => Ok(false),
        Some(readable) => readable.contains_str(needle),
    }
}

/// Port of generate.py:937-1119 (mcp_input_dispatch): one row of the input dispatcher every MCP door shares.
pub(crate) fn mcp_input_dispatch(row: &Dict) -> Result<String, GenerateError> {
    let name_value = item(row, "name")?;
    let method = method_name(row)?;
    let name = json(name_value);
    let decode = format!(
        "let input: {} = serde_json::from_value(input).map_err(|_| invalid())?;\n",
        rust_type(item(row, "input")?)?
    );
    if get_is(row, "context", "board") {
        return Ok(format!(
            "{name} => {{\n{decode}Box::pin(execute_mcp_board_verb(server, actor, served, board_hooks, |context| oneiron::task_verb::sdk::{method}(context, input))).await }},\n"
        ));
    }
    let mut body = String::new();
    if name_value.is_str("describe") {
        // One target per describe (FIX 3256), on the args the pre hooks left, before the self, card-key and
        // TASKS-section paths.
        body += &format!(
            "oneiron::task_verb::sdk::validate_input({name}, &input).map_err(mcp_facade_error)?;\n"
        );
        // describe(self) renders the connection's own brief (FIX 17594).
        body += DESCRIBE_SELF;
    }
    let admission = row.get("admission");
    let admits = |key: &str| -> Result<bool, GenerateError> {
        Ok(match admission {
            None => false,
            Some(admission) => admission.dict_get(key)?.is_some_and(Value::truthy),
        })
    };
    if admits("owner_grade")? {
        // A full-vault result needs verifier-produced owner proof, as on REST.
        body += &format!(
            "let auth = actor.auth.as_ref().ok_or_else(invalid)?;\nif !auth.is_owner_grade() {{ return Err(McpGatewayError::new(-32020, \"forbidden\", \"full-vault export requires owner authority\")); }}\noneiron::task_verb::sdk::validate_input({name}, &input).map_err(mcp_facade_error)?;\n"
        );
        body += &decode;
        body += OWNER_GRADE_EXPORT;
    } else if flag(row, "host_door") {
        // A host door answers from the server's own state, under the same credential the REST facade passes it.
        let session_arg = if flag(row, "host_door_session") {
            "actor.off_record_session.as_deref().map(oneiron::EntityId::from_hex).transpose().map_err(|_| invalid())?, "
        } else {
            ""
        };
        let lens_arg = if flag(row, "host_door_lens_owner") {
            "owner, "
        } else {
            ""
        };
        let client_surface_arg = if flag(row, "host_door_client_surface") {
            "actor.client_surface.clone(), "
        } else {
            ""
        };
        let surface_arg = if flag(row, "host_door_surface") {
            "crate::api::facade::owner_binding::act_surface(auth), "
        } else {
            ""
        };
        // A caller door keeps the invocation its call hands it in its own rows (FIX 5381).
        let caller_arg = format!(
            "(actor.actor_ref, actor.actor_class), oneiron::task_verb::verb_hook_boundary::door_invocation_of(&memory, &oneiron::verbs::VERB_TABLE, {name}), "
        );
        let fold_hooks_arg = if name_value.is_str("self.fold") {
            ", pre_hooked_fold"
        } else {
            ""
        };
        let paced_arg = if flag(row, "host_door_paced") {
            "super::mcp_paced_call(actor, &memory), "
        } else {
            ""
        };
        let caller = if flag(row, "host_door_caller") {
            caller_arg.as_str()
        } else {
            ""
        };
        let door = format!(
            "Box::pin(crate::api::facade::host_doors::{method}(server, auth, {session_arg}{caller}{lens_arg}{client_surface_arg}{surface_arg}{paced_arg}input{fold_hooks_arg})).await"
        );
        // The card's owner names the request as the row runs it, before it decodes.
        let lens_owner = if flag(row, "host_door_lens_owner") {
            format!("let owner = surface.lens_owner({name}, &input);\n")
        } else {
            String::new()
        };
        // A source door's failure keeps its program's feedback beside its refusal (FIX 10389).
        let door_error = if SOURCE_FEEDBACK_DOORS
            .iter()
            .any(|door| name_value.is_str(door))
        {
            "|failure| crate::api::mcp_gateway::type_feedback_release::source_run_error(server, actor, served.rows(), failure)"
        } else {
            "mcp_facade_error"
        };
        body += &format!(
            "let auth = actor.auth.as_ref().ok_or_else(invalid)?;\noneiron::task_verb::sdk::validate_input({name}, &input).map_err(mcp_facade_error)?;\n"
        );
        body += &lens_owner;
        body += &decode;
        body += &if flag(row, "host_door_lists") {
            format!(
                "let (output, listed) = {door};\n// Derived from the rows its reads listed: unknown when its path lists none (FIX 5988).\nserved.listed(crate::api::facade::host_doors::support::ListedRows::rows(listed));\nlet output = output.map_err({door_error})?;\n"
            )
        } else {
            format!("let output = {door}.map_err(mcp_facade_error)?;\n")
        };
    } else if flag(row, "server_door") {
        // A server door runs the verb with the host's execution inputs, as on REST.
        let door_call = match name_value
            .as_str()
            .and_then(|name| HOME_SERVER_DOORS.iter().find(|(row, _)| *row == name))
        {
            Some((_, home_door)) => format!(
                "{home_door}(actor.actor_ref, actor.actor_class, proof, actor.destination(), None, input, actor.home_caller())"
            ),
            None => format!(
                "{}_listing(actor.actor_ref, actor.actor_class, proof, actor.locality(), None, input)",
                shown(row, "server_door")?
            ),
        };
        body += &format!(
            "oneiron::task_verb::sdk::validate_input({name}, &input).map_err(mcp_facade_error)?;\n"
        );
        body += &decode;
        body += &format!(
            "let proof = actor.auth.as_ref().and_then(crate::auth::CoreAuth::verified_slip).cloned();\nlet (output, listed) = Box::pin(server.{door_call}).await;\n// Derived from these rows too, though it names none of them.\nserved.extend(listed);\nlet output = output.map_err(mcp_facade_error)?;\n"
        );
    } else {
        body += &decode;
        if name_value.is_str("vault.artifacts.view") || name_value.is_str("vault.artifacts.export")
        {
            body += OWNER_AUTHORSHIP;
        }
        if name_value.is_str("describe") {
            // describe(card key) expands a board card, under the board's own scope and frame-epoch checks.
            body += DESCRIBE_CARD_KEY;
            // The TASKS section reaches MCP as rows, narrowed to the credential before its render cap.
            body += DESCRIBE_TASKS_SECTION;
        }
        if row.contains_key("mcp_served") {
            // The rows the verb reads by name: a continuation of its result is released only while they may leave.
            body += &format!("served.extend({});\n", shown(row, "mcp_served")?);
        }
        let call_home = name_value
            .as_str()
            .and_then(|name| CALL_HOME_DOORS.iter().find(|(row, _, _)| *row == name));
        if takes_task_decisions(row) {
            // Its hooks stay here; the typed row alone crosses to the worker.
            body += &format!(
                "let (output, listed) = Box::pin(mcp_task_row(server, tool, actor, surface, move |memory| oneiron::task_verb::sdk::{method}(memory, input))).await?;\n// Derived from the rows its reads listed, on a refusal too.\nserved.extend(listed);\nlet output = output.map_err(mcp_facade_error)?;\n"
            );
        } else if flag(row, "mcp_off_runtime") {
            // Its blocking host call stays off the runtime; the typed row alone crosses to the worker, on a surface
            // rebuilt there.
            body += &format!(
                "let (output, listed) = Box::pin(mcp_off_runtime_row(server, tool, actor, surface, move |memory| oneiron::task_verb::sdk::{method}(memory, input))).await?;\n// Derived from the rows its reads listed, on a refusal too.\nserved.extend(listed);\nlet output = output.map_err(mcp_facade_error)?;\n"
            );
        } else if let Some((_, _, complete)) = call_home {
            // Its page as the plain arm reads it, then the home's references. The caller's own filter rides the
            // home ask too (FIX 3977).
            body += &format!(
                "let asked = (input.query.clone(), input.limit, input.filter.clone());\nlet output = oneiron::task_verb::sdk::{method}(&memory, input).map_err(mcp_facade_error)?;\nlet (output, listed) = Box::pin({complete}(server.vault(), output, &asked.0, asked.1, asked.2.as_ref(), &actor.home_caller())).await;\n// The home's references, found under the caller's own proof.\nserved.extend(listed);\n"
            );
        } else {
            body += &format!(
                "let output = oneiron::task_verb::sdk::{method}(&memory, input).map_err(mcp_facade_error)?;\n"
            );
        }
        if row.contains_key("mcp_served_output") {
            body += &format!("served.extend({});\n", shown(row, "mcp_served_output")?);
        }
    }
    if flag(row, "lands_turn") {
        if name_value.is_str("self.inbox.concern.move") {
            body += CONCERN_MOVE_LANDED;
        } else {
            body +=
                "server.ai.turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);\n";
        }
    }
    if row.contains_key("mcp_result") {
        body += &format!(
            "let (value, source) = {}; Ok((value, source, McpCarrierPolicy::Drain, None))",
            shown(row, "mcp_result")?
        );
        return Ok(format!("{name} => {{\n{body} }},\n"));
    }
    if let Some(page) = row.get("page") {
        // The engine's own cursor ends its page; the MCP cap counts the rows key named here, and `resume` names
        // the argument the cursor goes back as.
        let mut source = format!(
            "crate::mcp::McpPageSource::scoped_window(output.{}.len(), 0, usize::from(output.{}.is_some()), true).rows_at({})",
            page.getitem("rows")?.str(),
            page.getitem("cursor")?.str(),
            json(page.getitem("rows")?)
        );
        if page.contains_str("resume")? {
            let resume = page.getitem("resume")?;
            resume.check_hashable("a dict key")?;
            let fields = mcp_fields(row)?;
            let carried = resume.as_str().and_then(|resume| fields.get(resume));
            if carried.is_none() {
                return Err(GenerateError::assertion(format!(
                    "{}: page.resume names no MCP argument",
                    name_value.str()
                )));
            }
            if page.contains_str("within")? {
                // The cursor goes back inside the argument that carries the whole input, as its `within` key
                // (FIX 9175, FIX 10186).
                if !carried.is_some_and(|path| path.is_str("$")) {
                    return Err(GenerateError::assertion(format!(
                        "{}: page.within needs page.resume to carry the whole input",
                        name_value.str()
                    )));
                }
                source += &format!(
                    ".resumed_within({}, {}, {})",
                    json(page.getitem("cursor")?),
                    json(page.getitem("resume")?),
                    json(page.getitem("within")?)
                );
            } else {
                source += &format!(
                    ".resumed_by({}, {})",
                    json(page.getitem("cursor")?),
                    json(page.getitem("resume")?)
                );
            }
        }
        body += &format!("let source = {source};\n");
    } else {
        let count = if text(row, "output", "startswith")?.starts_with("Vec<") {
            "output.len()"
        } else {
            "1"
        };
        body += &format!("let source = crate::mcp::McpPageSource::complete({count});\n");
    }
    body += "mcp_agent_verb_output(output, source)";
    Ok(format!("{name} => {{\n{body} }},\n"))
}

/// Port of generate.py:1121-1151 (held_content_rows): FIX 22074, the rows with a `file_call`, run on content an
/// HTTP body held as a file.
pub(crate) fn held_content_rows(generator: &Generator) -> Result<String, GenerateError> {
    let rows: Vec<RowId> = generator
        .mcp_rows()
        .into_iter()
        .filter(|&id| generator.rows[id].contains_key("file_call"))
        .collect();
    for &id in &rows {
        let row = &generator.rows[id];
        let call_home = item(row, "name")?
            .as_str()
            .is_some_and(|name| CALL_HOME_DOORS.iter().any(|(row, _, _)| *row == name));
        if !super::row_access::context_is(row, "memory")
            || takes_task_decisions(row)
            || flag(row, "mcp_off_runtime")
            || call_home
            || flag(row, "lands_turn")
            || row.contains_key("page")
            || row.contains_key("mcp_result")
            || row.contains_key("mcp_served")
            || row.contains_key("mcp_served_output")
            || text(row, "output", "startswith")?.starts_with("Vec<")
        {
            return Err(GenerateError::value(format!(
                "{}: a file_call row is a plain one-result MCP row",
                shown(row, "name")?
            )));
        }
    }
    let mut out = EXECUTE_HELD_CONTENT_ROW.to_owned();
    out += INVALID;
    out += HELD_MEASURED;
    out += "match tool {\n";
    for &id in &rows {
        let row = &generator.rows[id];
        let method = method_name(row)?;
        out += &format!(
            "{} => {{\nlet input: {} = serde_json::from_value(input).map_err(|_| invalid())?;\nlet body = measured()?;\nlet output = oneiron::task_verb::sdk::{method}_file(memory, input, &body).map_err(mcp_facade_error)?;\nmcp_agent_verb_output(output, crate::mcp::McpPageSource::complete(1))\n}}\n",
            json_item_name(row)?,
            rust_type(item(row, "input")?)?
        );
    }
    out += "_ => Err(invalid()),\n}\n}\n";
    Ok(out)
}

/// Port of generate.py:1153-1417 (mcp_dispatch): the MCP dispatcher, its argument projections and one boxed arm per
/// row.
pub(crate) fn mcp_dispatch(generator: &Generator) -> Result<String, GenerateError> {
    let mcp_rows = generator.mcp_rows();
    let mut result = EXECUTE_MCP_AGENT_VERB.to_owned();
    result += INVALID;
    result += "match tool {\n";
    for &id in &mcp_rows {
        result += &mcp_input_projection(&generator.rows[id])?;
    }
    result += "_ => Err(invalid()), } }\n";
    result += MCP_AGENT_VERB_ARGUMENTS;
    result += INVALID;
    result += "let mut arguments = serde_json::Map::new();\nmatch tool {\n";
    for &id in &mcp_rows {
        result += &mcp_argument_projection(&generator.rows[id])?;
    }
    result += "_ => return Err(invalid()), }\nserde_json::from_value(Value::Object(arguments)).map_err(|_| invalid())\n}\n";
    result += EXECUTE_AGENT_VERB_INPUT;
    result += INVALID;
    result += VERB_LISTING_HEAD;
    result += &TASK_PRODUCER_ROWS
        .iter()
        .map(|name| dumps_str(name))
        .collect::<Vec<_>>()
        .join(" | ");
    result += VERB_LISTING_PRODUCERS;
    result += &task_producer_branch_turns("hooks.args");
    result += VERB_LISTING_TAIL;
    result += &held_content_rows(generator)?;
    result += EXECUTE_AGENT_VERB_ROW;
    result += INVALID;
    result += "let row = McpVerbRow { server, tool, input, actor, memory, surface, served, board_hooks, pre_hooked_fold };\nmatch tool {\n";
    let mut helpers = String::new();
    for &id in &mcp_rows {
        let row = &generator.rows[id];
        if item(row, "name")?.is_str("ai.anonymous_chat") {
            continue;
        }
        let name = item(row, "name")?;
        let method = method_name(row)?;
        let arm = mcp_input_dispatch(row)?;
        let prefix = format!("{} => {{\n", json(name));
        let suffix = " },\n";
        let body = arm
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_suffix(suffix))
            .ok_or_else(|| {
                GenerateError::assertion(format!("{}: an MCP arm is not one block", name.str()))
            })?;
        result += &format!(
            "{} => boxed_mcp_verb_row_{method}(row).await,\n",
            json(name)
        );
        // The row's body is unchanged; it runs in its own function on the same arguments, the ones it does not
        // read named once (FIX 19837).
        let uses_invalid = search_bare_invalid(body);
        helpers += &format!(
            "#[inline(never)]\nfn boxed_mcp_verb_row_{method}<'a>(row: McpVerbRow<'a>) -> McpVerbRowFuture<'a> {{\nBox::pin(mcp_verb_row_{method}(row))\n}}\n"
        );
        helpers += &format!(
            "async fn mcp_verb_row_{method}(row: McpVerbRow<'_>) -> McpVerbRowResult {{\n"
        );
        helpers += "let McpVerbRow { server, tool, input, actor, memory, surface, served, board_hooks, pre_hooked_fold } = row;\n";
        helpers += "let _ = (&server, &tool, &input, &actor, &memory, &surface, &served, &board_hooks, &pre_hooked_fold);\n";
        if uses_invalid {
            helpers += INVALID;
        }
        helpers += &format!("{body} }}\n");
    }
    result += "_ => Err(invalid()), } }\n";
    result += MCP_VERB_ROW_TYPES;
    result += &helpers;
    result += MCP_AGENT_VERB_OUTPUT;
    Ok(result)
}
/// generate.py:1154-1154.
const INVALID: &str = "let invalid = || McpGatewayError::new(-32602, \"tool_args_invalid\", \"invalid typed agent-verb argument\");\n";

/// generate.py:1155-1172.
const EXECUTE_MCP_AGENT_VERB: &str = "/// A `tools/call` of one generated verb: its arguments assemble the verb's typed
/// input, which then takes the one dispatcher every MCP door shares.
pub(super) async fn execute_mcp_agent_verb(
        server: &Arc<SyncServer>,
        args: &McpVerbToolArgs,
        actor: &McpCallContext,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>, Option<String>), McpGatewayError> {
        let input = mcp_agent_verb_input(args.tool.name, &args.payload.arguments)?;
        execute_agent_verb_input_held(server, args.tool.name, input, actor, None, served, board_hooks, args.held.as_ref()).await
    }

/// The typed input a `tools/call` of `tool` assembles from its arguments: the
/// one projection the call runs on, and the one the binding door classifies
/// a call over a damaged authority clock floor by (FIX 11201).
pub(crate) fn mcp_agent_verb_input(tool: &str, a: &crate::mcp::McpVerbArguments) -> Result<Value, McpGatewayError> {
";

/// generate.py:1174-1177.
const MCP_AGENT_VERB_ARGUMENTS: &str = "/// The `tools/call` arguments one verb input projects onto, so a call that
/// arrives as a whole input meets the admission a tool call of that verb meets.
pub(crate) fn mcp_agent_verb_arguments(tool: &str, input: &Value) -> Result<crate::mcp::McpVerbArguments, McpGatewayError> {
";

/// generate.py:1180-1244.
const EXECUTE_AGENT_VERB_INPUT: &str = "/// Runs one verb from its whole typed input, with the actor ceiling and
/// gate every other door applies. Every MCP door reaches the verb table here.
/// The input names only fields the verb's advertised closed schema lists, and
/// a code-mode call's claims are written under its `run`'s host origin, the
/// live lens cards it renders held for that run.
/// Every row the result was derived from is listed in `served`: those its
/// input names, and those the verb's reads picked themselves. A board read
/// leaves the hook blocks its answer shows in `board_hooks`; the caller spends
/// them once the answer is out (OF-579).
pub(crate) async fn execute_agent_verb_input(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        run: Option<McpCodeRun>,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>, Option<String>), McpGatewayError> {
        execute_agent_verb_input_held(server, tool, input, actor, run, served, board_hooks, None).await
    }

/// [`execute_agent_verb_input`] for a call whose `content_base64` its HTTP
/// body held as a file (FIX 22074): `held`, which only the tool it arrived
/// for reads.
async fn execute_agent_verb_input_held(
        server: &Arc<SyncServer>,
        tool: &str,
        mut input: Value,
        actor: &McpCallContext,
        run: Option<McpCodeRun>,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
        held: Option<&crate::mcp::McpHeldContent>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>, Option<String>), McpGatewayError> {
        let producers = oneiron::memory::ProducerRows::default();
        // An owner's erase or revoke reads the restriction-only clock through
        // its hooks and door, as the engine classifies it (FIX 11201).
        let restrictive = crate::api::clock_ingress::restrictive_call(server, tool, Some(&input));
        // A custody row's value leaves the args before its hooks read them,
        // and rides to its door scoped, as an HTTP body's does (FIX 11665).
        let secret = crate::api::facade::lift_custody_secret(tool, &mut input);
        // The drain's run of a held call runs as its turn in every poll of
        // its row, its retry lookup included (FIX 19034).
        let listed = super::skill_execution::CALLER.scope(actor.clone(), super::mcp_drain_polls(actor, execute_agent_verb_listing(server, tool, input, actor, run, &producers, served, board_hooks, held)));
        let produced = crate::api::clock_ingress::scoped(restrictive, crate::api::facade::with_custody_secret(secret, listed)).await;
        served.extend(producers.take());
        produced
    }

/// [`execute_agent_verb_input`], its surface listing in `producers` the rows
/// its reads pick. Every MCP and code-mode row crosses its verb hooks here,
/// once (ARCH-0080 §3), under the invocation the call carried or a fresh
/// one: the pre chain before the row, the post chain over its result.
async fn execute_agent_verb_listing(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        run: Option<McpCodeRun>,
        producers: &oneiron::memory::ProducerRows,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
        held: Option<&crate::mcp::McpHeldContent>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>, Option<String>), McpGatewayError> {
";

/// generate.py:1245-1273.
const VERB_LISTING_HEAD: &str = "if let Some(field) = crate::mcp::verb_input_unknown_field(tool, &input) {
        return Err(McpGatewayError::new(-32602, \"tool_args_invalid\", format!(\"{tool} input names unknown field `{field}`\")));
    }
    if !oneiron::task_verb::sdk::AgentVerb::from_name(tool).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_mcp) {
        return Err(invalid());
    }
    // G10: MCP and code mode retain envelopes and results. Do not run a
    // memory-free turn on either, or fire a hook that could retain its text.
    if tool == \"ai.anonymous_chat\" {
        return Err(McpGatewayError::new(-32020, \"model_unavailable\",
            \"anonymous chat requires its standalone HTTP SDK route\"));
    }
    // A narrowed connector's TASKs are born in its own world and in the
    // facet its writes land in (its session's, or its own write facet).
    let mut position = actor.scope.birth_position();
    if let Ok(Some(facet)) = actor.landing {
        position.facet = Some(facet);
    }
    let invocation = actor.invocation.unwrap_or_else(oneiron::runtime_hooks::InvocationId::mint);
    // describe names one target (FIX 3256): a conflict is refused before its
    // hooks see it, as on REST, and again on the args they leave.
    if tool == \"describe\" {
        oneiron::task_verb::sdk::validate_input(tool, &input).map_err(mcp_facade_error)?;
    }
    // Rule 5: a task-work row, or a row whose engine call produces task work,
    // takes its one turn here, for MCP and code mode alike, binds it on the
    // surface its row runs on and holds it through its hooks and its row.
    let task_work_turn = if oneiron::task_verb::sdk::AgentVerb::from_name(tool).is_some_and(oneiron::task_verb::sdk::AgentVerb::is_task_work)
        || matches!(tool, ";

/// generate.py:1273-1303.
const VERB_LISTING_PRODUCERS: &str = ") {
        Some(Arc::new(server.admit_task_work(actor.actor_ref).await))
    } else {
        None
    };
    let mut surface = McpRowSurface { position, invocation, run, task_work_turn: task_work_turn.clone() };
    // The direct caller's own proof, on the rows whose HTTP door binds it
    // outside a room turn (OF-417, OF-365).
    let memory = mcp_direct_authorship(server, tool, actor, surface.memory(server, actor, producers))?;
    // A retry of a call its budget window paced meets the paced line here,
    // before its hooks or its row run again: still held, or the saved answer
    // of the drain's turn (FIX 19034).
    if let Some((output, producers)) = super::verb_hooks::mcp_row_paced_reply(server, tool, actor, &memory)? {
        // Released by the rows the saved answer was derived from (FIX 22259).
        served.listed(producers);
        return Ok((output, crate::mcp::McpPageSource::complete(1), McpCarrierPolicy::Drain, None, None));
    }
    // Content its HTTP body held as a file is this tool's call's alone, and
    // its pre chain puts the string back before any hook reads the args
    // (FIX 22074).
    let held = held.filter(|held| held.tool() == tool);
    let held_file = match held {
        Some(held) => Some(held.file().try_clone().map_err(|error| McpGatewayError::new(-32603, \"engine_error\", error.to_string()))?),
        None => None,
    };
    let hooks = super::verb_hooks::mcp_row_hooks_pre(server, tool, actor, &memory, input, held_file).await?;
    // Rule 5 (FIX 4445): a row one branch of whose engine call produces task
    // work takes its turn on the args its pre hooks left, as the served
    // facade does, so a rewrite into that branch runs on an awaited turn.
    // The row holds one turn only, bound on its surface and its memory alike.
    let (memory, task_work_turn) = if task_work_turn.is_none() && (";

/// generate.py:1303-1334.
const VERB_LISTING_TAIL: &str = ") {
        let turn = Arc::new(server.admit_task_work(actor.actor_ref).await);
        surface.task_work_turn = Some(Arc::clone(&turn));
        (memory.with_task_work_turn(Arc::clone(&turn)), Some(turn))
    } else {
        (memory, task_work_turn)
    };
    let pre_hooked_fold = oneiron::code_run::actions::PreHookedFold::from_pre(&hooks);
    let ran = match held.filter(|_| hooks.passed_through()) {
        // The args passed the chain as the caller sent them: the row reads
        // the content from the file.
        Some(held) => execute_held_content_row(tool, hooks.args.clone(), &memory, held),
        None => execute_agent_verb_row(server, tool, hooks.args.clone(), actor, memory, surface, served, board_hooks, pre_hooked_fold).await,
    };
    // A row that fails after its pre chain ran keeps a session-only call's
    // pre hook records and runs no post chain (FIX 5527).
    let (output, source, carrier, epoch) = match ran {
        Ok(ran) => ran,
        Err(error) => {
            crate::api::facade::row_hooks_abort(server, hooks).await;
            return Err(error);
        }
    };
    let hook_notice = oneiron::task_verb::revoke_lands::caller_notice(&hooks);
    let output = crate::api::facade::row_hooks_post(server, hooks, output).await
        .map_err(|error| mcp_facade_error(error).with_hook_notice(hook_notice.clone()))?;
    // The row's turn ends after its post hooks.
    drop(task_work_turn);
    Ok((output, source, carrier, epoch, hook_notice))
    }

";

/// generate.py:1334-1370.
const EXECUTE_AGENT_VERB_ROW: &str = "
/// One row of [`execute_agent_verb_listing`], on the args its pre chain left,
/// on `memory`, the caller's surface `surface` built. A task row that may ask
/// the host's decision ladder builds its own from `surface`, off the runtime.
/// A code-mode call's engine call writes for the leased run its origin seals
/// in every poll of the row, as a blocking hop writes for it (FIX 11698).
async fn execute_agent_verb_row(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        memory: oneiron::Memory<'_>,
        surface: McpRowSurface,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
        pre_hooked_fold: Option<oneiron::code_run::actions::PreHookedFold>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
        let run_writes = surface.run.as_ref().and_then(|run| oneiron::skill_attribution::run_write_token_of_origin(&run.origin));
        crate::api::facade::run_write_polls::scoped(run_writes, execute_agent_verb_row_on(server, tool, input, actor, memory, surface, served, board_hooks, pre_hooked_fold)).await
    }

/// [`execute_agent_verb_row`]'s row, inside the run's write envelope. Each
/// row's arm is its own async function, constructed and boxed in its own
/// non-inlined function (FIX 19837); this match holds only that boxed handle,
/// so its frame stays small however large any one row is.
async fn execute_agent_verb_row_on(
        server: &Arc<SyncServer>,
        tool: &str,
        input: Value,
        actor: &McpCallContext,
        memory: oneiron::Memory<'_>,
        surface: McpRowSurface,
        served: &mut McpServed,
        board_hooks: &mut Option<super::board_setup::McpBoardHooks>,
        pre_hooked_fold: Option<oneiron::code_run::actions::PreHookedFold>,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
";

/// generate.py:1391-1407.
const MCP_VERB_ROW_TYPES: &str = "/// What one MCP row's arm returns.
type McpVerbRowResult = Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError>;
/// One MCP row's arm, boxed by its own function (FIX 19837).
type McpVerbRowFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = McpVerbRowResult> + Send + 'a>>;
/// [`execute_agent_verb_row_on`]'s arguments, moved whole into the one row's arm.
struct McpVerbRow<'a> {
    server: &'a Arc<SyncServer>,
    tool: &'a str,
    input: Value,
    actor: &'a McpCallContext,
    memory: oneiron::Memory<'a>,
    surface: McpRowSurface,
    served: &'a mut McpServed,
    board_hooks: &'a mut Option<super::board_setup::McpBoardHooks>,
    pre_hooked_fold: Option<oneiron::code_run::actions::PreHookedFold>,
}
";

/// generate.py:1408-1416.
const MCP_AGENT_VERB_OUTPUT: &str = "/// One typed verb result, drained in a single frame.
fn mcp_agent_verb_output(
        output: impl serde::Serialize,
        source: crate::mcp::McpPageSource,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
        let value = serde_json::to_value(output).map_err(|_| McpGatewayError::new(-32603, \"engine_error\", \"typed agent result cannot be encoded\"))?;
        Ok((value, source, McpCarrierPolicy::Drain, None))
    }
";

/// generate.py:956-965.
const DESCRIBE_SELF: &str = "if input.get(\"self\").and_then(Value::as_bool) == Some(true) {
    // A code-mode call names its trusted durable run; a direct call names none.
    let run = surface.run.as_ref().map(|run| run.run_id);
    let (value, listed) = Box::pin(crate::api::context_board::describe_self_for_mcp(server, actor, run, &input)).await.map_err(|_| invalid())?;
    // Derived from the rows its card lists, the roster it read among them.
    served.extend(listed);
    let output: oneiron::task_verb::TaskDescription = serde_json::from_value(value).map_err(|_| invalid())?;
    let (value, source) = mcp_describe_result(output)?;
    return Ok((value, source, McpCarrierPolicy::Drain, None));
}
";

/// generate.py:972-995.
const OWNER_GRADE_EXPORT: &str = "// An export a code run calls follows the world settings as before owner ruling 1-EXPORT = B (FIX 9591): the run's dispatch says so, never the request.
let input = oneiron::memory::ExportOptions { in_code_run: crate::api::facade::host_doors::support::in_code_run(), ..input };
// A host credential resolves first (FIX 2222): a hosted operator root gets the typed refusal, and a self-hosted root or the explicit dev mode exports as the owner it acts as.
let action = crate::api::host_action::host_action_of(server.vault(), auth).transpose().map_err(|error| mcp_engine_error(\"host action failed\", error))?;
// The person path lists through its surface; the host paths beside their archive. A slip keeps its own path; a host action with no slip (the dev mode) takes the host-action export.
// Each arm records the owner act with where he spoke from: an MCP row carries no request headers (FIX 4625, 4626).
let surface = crate::api::facade::owner_binding::act_surface(auth);
// A transfer is kept on the server, as on REST, and read through vault.export.transfer.read (FIX 11176).
if input.delivery.unwrap_or_default() == oneiron::memory::ExportDelivery::Transfer {
    let (transfer, listed) = crate::api::facade::mcp_export_transfer(server, auth, surface, &actor.destination(), &input, action).map_err(mcp_facade_error)?;
    served.extend(listed);
    return mcp_agent_verb_output(transfer, crate::mcp::McpPageSource::complete(1));
}
let output = match (auth.verified_slip(), action) {
    (Some(proof), _) if proof.claims().holder_ref == \"host\" => server.vault.export_with_verified_host_owner_listing(&input, proof, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output }),
    (Some(proof), _) => memory.export_with_verified_owner(&input, proof, surface),
    (None, Some(action)) => server.vault.export_with_host_action_listing(&input, &action, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output }),
    // A managed vault's attested owner carries no slip: the request's own owner proof, which the export revalidates in its snapshot, as the facade takes it (FIX 5202).
    (None, None) if auth.managed_owner().is_some() => {
        let owner = crate::api::owner_routes::owner(auth, server).map_err(|_| McpGatewayError::new(-32020, \"forbidden\", \"full-vault export requires verified owner authority\"))?;
        server.vault.export_with_authenticated_owner_listing(&input, &owner, surface, actor.destination()).map(|(output, listed)| { served.extend(listed); output })
    }
    (None, None) => return Err(McpGatewayError::new(-32020, \"forbidden\", \"full-vault export requires verified owner authority\")),
}.map_err(mcp_facade_error)?;
";

/// generate.py:1036-1040.
const OWNER_AUTHORSHIP: &str = "let owner = actor.auth.as_ref().and_then(|auth| crate::api::owner_routes::owner(auth, server).ok());
let memory = match owner {
    Some(owner) => memory.with_owner_authorship(&owner),
    None => memory,
};
";

/// generate.py:1044-1047.
const DESCRIBE_CARD_KEY: &str = "if let Some(key) = input.key.clone() {
    let frame_epoch = input.frame_epoch;
    return Box::pin(execute_mcp_board_verb(server, actor, served, board_hooks, |context| oneiron::board_verb::dispatch_board_verb(context, oneiron::board_verb::BoardVerbCall::Expand { key, frame_epoch }))).await;
}
";

/// generate.py:1049-1055.
const DESCRIBE_TASKS_SECTION: &str = "if input.task_ref.is_none() && input.handle.is_none() && input.after.is_none() && !input.self_target && !input.vault {
    // The section is narrowed to this credential before its
    // render cap, so its counts are the credential's rows alone.
    let rows = memory.describe_rows().map_err(mcp_facade_error)?;
    let (value, source) = mcp_tasks_section(server, actor, rows, served)?;
    return Ok((value, source, McpCarrierPolicy::Drain, None));
}
";

/// generate.py:1086-1090.
const CONCERN_MOVE_LANDED: &str = "if matches!(&output, oneiron::dreamer_runner::maintenance::agent_health::ConcernMoveOutcome::Applied { receipt, .. } if matches!(receipt.link, oneiron::dreamer_runner::maintenance::agent_health::ConcernMoveLink::Note { .. })) {
server.ai.turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
}
";

/// generate.py:1129-1138.
const EXECUTE_HELD_CONTENT_ROW: &str = "/// One row whose `content_base64` its HTTP body held as a file (FIX 22074),
/// on args its pre chain left as the caller sent them: its `_file` engine fn
/// reads the content there, behind the checks its plain fn runs.
fn execute_held_content_row(
        tool: &str,
        input: Value,
        memory: &oneiron::Memory<'_>,
        held: &crate::mcp::McpHeldContent,
    ) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, Option<u64>), McpGatewayError> {
";

/// generate.py:1140-1140.
const HELD_MEASURED: &str = "let measured = || oneiron::blob_artifact::BlobBodyFile::measure(held.file()).map_err(|error| mcp_facade_error(error.into()));\n";

#[cfg(test)]
mod tests {
    use super::takes_task_work_turn;
    use crate::py::json::loads;
    use crate::py::value::Value;

    #[test]
    fn a_task_work_producer_row_is_a_plain_memory_row() {
        // generate.py:931, Python's `ValueError` text.
        let refused = [
            r#"{"name": "tasks.accept", "task_decisions": true}"#,
            r#"{"name": "tasks.accept", "server_door": "accept"}"#,
            r#"{"name": "tasks.accept", "context": "board"}"#,
            r#"{"name": "tasks.accept", "admission": {"readable": ["rows"]}}"#,
        ];
        for text in refused {
            let Ok(Value::Dict(row)) = loads(text) else {
                panic!("a row")
            };
            assert_eq!(
                takes_task_work_turn(&row)
                    .err()
                    .map(|error| error.to_string()),
                Some(
                    "ValueError: tasks.accept: a task-work producer row is a plain memory row"
                        .to_owned()
                ),
                "{text}"
            );
        }
        let Ok(Value::Dict(plain)) = loads(r#"{"name": "describe", "task_work": 1}"#) else {
            panic!("a row")
        };
        assert_eq!(takes_task_work_turn(&plain).ok(), Some(true));
    }
}
