//! Port of generate.py: the server's facade outputs (G4a): `agent_verbs.rs` and `dispatch.rs` (`facade_dispatch`),
//! `host_door_rows.rs` (`host_door_rows`), and the door tables both they and the MCP dispatch read
//! (generate.py:357-375).

use super::emit_mcp::{TASK_PRODUCER_BRANCHES, takes_task_decisions, takes_task_work_turn};
use super::row_access::{flag, flag_in, get_in, get_is, item, json, method_name, variant_name};
use super::{Generator, HEADER, RowId};
use crate::error::GenerateError;
use crate::py::json::dumps_str;
use crate::py::value::{Dict, Value, set_add};

/// Port of generate.py:2123-2128 (HOST_DOOR_ROWS_DOC).
pub(crate) const HOST_DOOR_ROWS_DOC: &str =
    "// The host-door rows whose door checks its caller before the row's verb
// hooks run (FIX 1763), one variant each, named as `AgentVerb` names it, and
// the proof each names (`host_door_proof`), which `host_doors::door_admits`
// matches with no catch-all arm. A row whose table entry says
// `\"host_door_precheck\": false` checks nothing before its hooks; those rows:
";

/// generate.py:2132 `variant`: a row's `AgentVerb` variant.
fn row_variant(row: &crate::py::value::Dict) -> Result<String, GenerateError> {
    Ok(variant_name(super::row_access::text(
        row, "name", "replace",
    )?))
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
    out +=
        "/// The proof a checked host door runs before its hooks (`host_door_proof` on the row).\n";
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
    let alternatives = |names: &[&Value]| {
        names
            .iter()
            .map(|name| json(name))
            .collect::<Vec<_>>()
            .join(" | ")
    };
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

/// Port of generate.py:357 (SERVER_RECALL_DOC): the doc comment of the server's `vault.recall` door.
pub(crate) const SERVER_RECALL_DOC: &str =
    "/// `vault.recall` → `SyncServer::recall_home_listing`, the recall door
/// every server transport shares (`POST /v1/core/facade/vault.recall`, and
/// the held socket's `rpc.req`): it embeds the query whenever the vault's
/// embedder is serving.
///
/// The lease is not a client input, and a bearer slip is not one. At high,
/// xhigh and max the door admits the recall on a line of its own and
/// reranks on the `[models]` reranker; its refusals (`BUDGET_SPENT`,
/// `MODEL_UNAVAILABLE`) are forwarded as those exact codes. With no
/// reranker route the recall runs unreranked and reports
/// `skipped / no_reranker` in `retrieval_meta.rerank`.
///
/// On a device that syncs only what it opened, the door then asks the home
/// under the call's own caller (FIX 2905): its references ride in
/// `residence`, apart from the local items; without them the pack is
/// local-only and `partial`.
";

/// Port of generate.py:360 (HOME_SERVER_DOORS): FIX 2905, the server doors that also ask an opened device's home, by
/// row, with the caller the call (or the MCP actor) admitted as the last argument.
pub(crate) const HOME_SERVER_DOORS: &[(&str, &str)] = &[("vault.recall", "recall_home_listing")];

/// Port of generate.py:366-367 (CALL_HOME_DOORS): FIX 3876, the rows whose page is read on the transport's own caller
/// surface, then completed by the opened device's home: `(row, its facade door, its MCP home step)`.
pub(crate) const CALL_HOME_DOORS: &[(&str, &str, &str)] = &[(
    "vault.search.bm25",
    "super::search_home_doors::vault_search_bm25",
    "crate::api::search::complete_bm25_with_home",
)];

/// Port of generate.py:370 (HOOK_DECISION_ROWS): FIX 10425, the facade host-door rows whose answer counts its hooks'
/// verdict decisions among its own (`model_free`). A set, read for membership.
pub(crate) const HOOK_DECISION_ROWS: &[&str] = &["self.browser.batch", "self.browser.library.run"];

/// Port of generate.py:375 (SOURCE_FEEDBACK_DOORS): FIX 10389, a host door that runs its caller's program answers a
/// failure that keeps the program's type feedback beside its typed refusal. A set, read for membership.
pub(crate) const SOURCE_FEEDBACK_DOORS: &[&str] = &["execute_code"];

/// Port of generate.py:1732-1738 (DISPATCH_DOC).
pub(crate) const DISPATCH_DOC: &str =
    "// The facade's one admission and typed call per verb-table row (OF-489).
// Every server transport runs a facade verb here: each HTTP route through
// `facade_route`, the held socket's `rpc.req` through [`call_verb`]. A
// transport hands a row its [`FacadeCall`] and the input as it decoded it;
// the row admits the call and runs it, and its answer names the rows it was
// derived from.
";

/// Port of generate.py:1739 (DISPATCH_SIGNATURE).
pub(crate) const DISPATCH_SIGNATURE: &str = "server: &Arc<SyncServer>, call: &FacadeCall<'_>, input: Result<serde_json::Value, FacadeApiError>";

/// generate.py:1807-1813: the anonymous-chat row's socket door, which refuses.
const ANONYMOUS_CHAT_BODY: &str = "let _ = (server, auth, input);
                Err(oneiron::memory::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE,
                    \"anonymous chat requires its standalone HTTP SDK route\",
                    &[\"Call POST /v1/ai/anonymous-chat or the HTTP SDK ai.anonymous_chat method.\"],
                ).into())
            }
";

/// The facade's routes (`agent_verbs.rs`) and its dispatch (`dispatch.rs`).
pub(crate) struct FacadeDispatch {
    pub(crate) routes: String,
    pub(crate) dispatch: String,
}

/// `r.get('admission', {}).get(key)`, truthy.
fn admits(row: &Dict, key: &str) -> Result<bool, GenerateError> {
    flag_in(row, "admission", key)
}

/// Port of generate.py:1748-1772 (facade_dispatch's record_scope_guard): a raw door refuses any narrowed record
/// capability; a door that reads only through the credential's lane serves a facet narrowing (owner ruling
/// FACET-READ); a door that births records lands them in the credential's landing facet.
fn record_scope_guard(row: &Dict) -> Result<&'static str, GenerateError> {
    Ok(if admits(row, "claim_record_scope")? {
        "let position = facade_claim_position(server, call)?;"
    } else if admits(row, "credential_record_scope")? {
        "facade_scoped_credential(auth)?;"
    } else if admits(row, "scoped_export")? {
        "facade_scoped_export_credential(auth)?;"
    } else if admits(row, "born_record_scope")? {
        "let position = facade_landing(server, call)?;"
    } else if admits(row, "lane_record_scope")? {
        "auth.require_lane_record_scope()?;"
    } else if admits(row, "projection_record_scope")? {
        // A read whose engine door filters its projection row by row through the credential's own scoped read
        // carries the credential's worlds and facets (OF-250).
        "{ let (worlds, facets) = auth.verified_slip().map_or((oneiron::federation::ScopeAxis::All, oneiron::federation::ScopeAxis::All), |proof| (proof.scope().worlds.clone(), proof.scope().facets.clone())); auth.require_record_scope_carried(worlds, facets)?; }"
    } else if admits(row, "unrestricted_record_scope")? {
        "auth.require_unrestricted_record_scope()?;"
    } else {
        // Any other door reads or writes around the lane, so it refuses a facet narrowing.
        "auth.require_unnarrowed_facets()?;"
    })
}

/// `name in <a set of row names>`.
fn named_in(name: &Value, names: &[&str]) -> bool {
    names.iter().any(|row| name.is_str(row))
}

/// Port of generate.py:1741-2121 (facade_dispatch): the facade routes, every one onto the shared adapter, and the
/// dispatch both transports run.
pub(crate) fn facade_dispatch(
    generator: &Generator,
    facade_rows: &[RowId],
) -> Result<FacadeDispatch, GenerateError> {
    let store = &generator.rows;
    let rows = store.select(facade_rows);
    let mut routes = HEADER.to_owned()
        + "use super::*;\npub(super) fn routes() -> Router<Arc<SyncServer>> { Router::new()\n";
    // G10: anonymous chat uses the existing standalone handler.
    for row in &rows {
        if item(row, "name")?.is_str("ai.anonymous_chat") {
            continue;
        }
        let handler = if row.contains_key("attachment") {
            method_name(row)? + "_attachment"
        } else {
            "facade_route".to_owned()
        };
        routes += &format!(
            ".route(\"/{}\", post({handler}))\n",
            item(row, "name")?.str()
        );
    }
    routes += "}\n";
    for row in &rows {
        if !row.contains_key("attachment") {
            continue;
        }
        let handler = method_name(row)? + "_attachment";
        let disposition = dumps_str(&format!(
            "attachment; filename=\"{}\"",
            item(row, "attachment")?.str()
        ));
        // The route's answer, encoded inside its answer scope (FIX 8238); only an answer, never a refusal, is
        // named an attachment.
        routes += &format!(
            "async fn {handler}(
            caller: super::clock_ingress::FacadeCaller, State(server): State<Arc<SyncServer>>, uri: axum::http::Uri,
            headers: HeaderMap, extensions: axum::http::Extensions,
            payload: Result<Json<serde_json::Value>, JsonRejection>,
        ) -> Response {{
            let mut answer = facade_route(caller, State(server), uri, headers, extensions, payload).await;
            if answer.extensions().get::<FacadeApiError>().is_none() {{
                answer.headers_mut().insert(axum::http::header::CONTENT_DISPOSITION, HeaderValue::from_static({disposition}));
            }}
            answer
        }}
"
        );
    }
    routes += "pub(super) fn anonymous_chat_routes() -> Router<Arc<SyncServer>> { Router::new().route(\"/v1/core/facade/ai.anonymous_chat\", post(crate::api::anonymous_chat::chat)) }\n";
    let mut dispatch = HEADER.to_owned() + DISPATCH_DOC + "use super::*;\n";
    for row in &rows {
        let method = method_name(row)?;
        let name_value = item(row, "name")?;
        let mut head = format!(
            "async fn {method}({DISPATCH_SIGNATURE}) -> Result<FacadeCallOutput, FacadeApiError> {{\nlet auth = call.auth();\n"
        );
        if name_value.is_str("vault.recall") {
            dispatch += SERVER_RECALL_DOC;
        }
        if name_value.is_str("ai.anonymous_chat") {
            // Socket/RPC calls retain their envelope. Only the standalone HTTP registration above can execute a
            // traceless turn.
            dispatch += &head;
            dispatch += ANONYMOUS_CHAT_BODY;
            continue;
        }
        if admits(row, "owner_grade")? {
            dispatch += &head;
            dispatch += &owner_grade_door(row)?;
            continue;
        }
        if flag(row, "host_door") {
            dispatch += &head;
            dispatch += &host_door(row, &method)?;
            continue;
        }
        let name = name_value.str();
        // `readable` names the credential read checks: each caller-named ref is refused before the engine call, and
        // `rows` filters the typed result.
        let (mut room_guard, mut ref_guard) = (String::new(), String::new());
        // A task-decision row invokes on its worker's own server and call.
        let on = if takes_task_decisions(row) {
            "&server, &call"
        } else {
            "server, call"
        };
        let mut invoke = "facade_invoke";
        let mut invoke_args = format!("{on}, actor, class, \"{name}\", value, &producers");
        if takes_task_work_turn(row)? {
            // Rule 5: the engine call runs on the turn the dispatch awaited.
            invoke = "facade_invoke_in_turn";
            invoke_args += ", Some(turn)";
        }
        if admits(row, "born_record_scope")? || admits(row, "claim_record_scope")? {
            invoke = "facade_invoke_born";
            invoke_args = format!("{on}, actor, class, \"{name}\", value, position, &producers");
        }
        let mut result = format!("{invoke}({invoke_args})?;");
        let mut notice_result = Some(format!("{invoke}_with_notice({invoke_args})?;"));
        let readables = get_in(row, "admission", "readable")?;
        let readables_value = readables.cloned().unwrap_or(Value::List(Vec::new()));
        // A room turn refuses an unserved verb before any credential lookup.
        if readables_value.contains_str("rows")? {
            room_guard += &format!("facade_outside_room_turn(call, \"{name}\")?;");
        } else if readables_value.truthy() {
            room_guard += &format!(
                "facade_room_turn_serves(call, \"{name}\", oneiron::memory::RoomTurnHandle::serves(\"{name}\"))?;"
            );
        }
        let mut branch_turn = String::new();
        // FIX 1210: a row that declares record refs refuses a ref the caller cannot read with the same NOT_FOUND,
        // its row's own ref check receipting it first, as its engine fn would have.
        let entries = readables_value.iterate()?;
        let receipted: Vec<Value> = if row.contains_key("refs") {
            entries
                .iter()
                .filter(|readable| !readable.is_str("rows"))
                .cloned()
                .collect()
        } else {
            Vec::new()
        };
        for readable in &entries {
            if receipted.iter().any(|seen| seen.py_eq(readable)) {
                continue;
            }
            if readable.is_str("rows") {
                let memory = "credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()).listing_producers(&producers)";
                result = format!(
                    "facade_readable_task_rows(&server.vault, auth, oneiron::task_verb::sdk::{method}(&{memory}, facade_input(value)?)?)?;\nlet rows = Some(producers.take());"
                );
                if let Some((_, predicate)) = TASK_PRODUCER_BRANCHES
                    .iter()
                    .find(|(producer, _)| name_value.is_str(producer))
                {
                    // Rule 5 (FIX 2166): a request taking the producer branch runs on the turn the dispatch
                    // awaited, held until its engine call returns.
                    branch_turn = format!(
                        "let turn = if {predicate}(&value) {{ Some(Arc::new(server.admit_task_work(actor).await)) }} else {{ None }};\n"
                    );
                    result = format!(
                        "{{ let memory = {memory}; let memory = match turn {{ Some(turn) => memory.with_task_work_turn(turn), None => memory }};\nfacade_readable_task_rows(&server.vault, auth, oneiron::task_verb::sdk::{method}(&memory, facade_input(value)?)?)? }};\nlet rows = Some(producers.take());"
                    );
                }
            } else if readable.contains_str(".")? || readable.contains_str("[")? {
                // 2690: a nested path walks to each ref it names.
                ref_guard += &format!(
                    "facade_admit_readable_path(&server.vault, auth, &value, \"{}\")?;",
                    readable.str()
                );
            } else {
                ref_guard += &format!(
                    "facade_admit_readable_ref(&server.vault, auth, &value, \"{}\")?;",
                    readable.str()
                );
            }
        }
        if !receipted.is_empty() {
            let fields = receipted.iter().map(json).collect::<Vec<_>>().join(", ");
            ref_guard += &format!(
                "facade_admit_receipted(server, call, actor, class, \"{name}\", &value, &[{fields}])?;"
            );
        }
        let call_home = name_value
            .as_str()
            .and_then(|name| CALL_HOME_DOORS.iter().find(|(row, _, _)| *row == name));
        // A server door runs the verb with the host's execution inputs, off the runtime, inside the room turn the
        // call names, if any, and lists the rows its answer is derived from without naming them.
        if flag(row, "server_door") {
            let door_call = match name_value
                .as_str()
                .and_then(|name| HOME_SERVER_DOORS.iter().find(|(row, _)| *row == name))
            {
                Some((_, home_door)) => format!(
                    "{home_door}(actor, class, auth.verified_slip().cloned(), auth.destination(), call.room_turn()?, facade_input(value)?, call.home_caller())"
                ),
                None => format!(
                    "{}_listing(actor, class, auth.verified_slip().cloned(), auth.locality(), call.room_turn()?, facade_input(value)?)",
                    item(row, "server_door")?.str()
                ),
            };
            result = format!(
                "let (output, listed) = server.{door_call}.await;\nlet output = facade_output(output?)?;\nlet rows = Some(listed);"
            );
        } else if let Some((_, door, _)) = call_home {
            result = format!(
                "let (output, listed) = {door}(server, call, actor, class, facade_input(value)?).await;\nlet output = facade_output(output?)?;\nlet rows = Some(listed);"
            );
        }
        let mut landed = "";
        if flag(row, "lands_turn") {
            if name_value.is_str("self.inbox.concern.move") {
                // P1 REVIEW-4395: the wake reads the COMMITTED result through facade_invoke_concern_move's
                // row_tapped tap BEFORE post-hook redaction.
                result = "{ let (output, wake) = facade_invoke_concern_move(server, call, actor, class, value, &producers)?; if wake { server.ai.turn_landed_by(server.vault(), actor, class); } output };".to_owned();
                notice_result = None;
            } else {
                landed = "server.ai.turn_landed_by(server.vault(), actor, class);";
            }
        }
        // A born door's landing judges its record bounds, so only the grant is left to check; so does a lane door
        // whose engine door judges the credential's lane in each snapshot (`require_granted_scope`).
        let require = if admits(row, "born_record_scope")?
            || admits(row, "claim_record_scope")?
            || admits(row, "require_granted_scope")?
        {
            "require_granted"
        } else {
            "require"
        };
        head += &format!(
            "auth.{require}(CoreScope::{})?;
        {}
        let value = input?;\n",
            item(row, "scope")?.str(),
            record_scope_guard(row)?
        );
        // A row that runs itself, not through `invoke`, crosses its verb hooks here (ARCH-0080 §3).
        let rows_read = readables_value.contains_str("rows")?;
        if rows_read || flag(row, "server_door") || call_home.is_some() {
            let mut actor = "let (actor, class) = facade_actor(server, auth)?;";
            let mut self_branch = String::new();
            if name_value.is_str("describe") {
                // describe(self) renders the authenticated run brief, under no actor, and lists the rows its card
                // is derived from. The one target check meets the args the hooks left (FIX 3256).
                self_branch = "oneiron::task_verb::sdk::validate_input(\"describe\", &value)?; if value.get(\"self\").and_then(serde_json::Value::as_bool) == Some(true) { let (output, rows) = crate::api::context_board::describe_self_for_auth(server, auth, &value).await?; return Ok((output, Some(rows))); } ".to_owned()
                    + actor;
                actor = "";
            }
            let door = flag(row, "server_door") || call_home.is_some();
            let producers = if door {
                ""
            } else {
                "let producers = oneiron::memory::ProducerRows::default();\n"
            };
            let output = if door {
                result.clone()
            } else {
                format!("let output = {result}")
            };
            // A row that fails after its pre chain ran keeps a session-only call's pre hook records and runs no
            // post chain (FIX 5651), as a host door does (FIX 5527).
            dispatch += &head;
            dispatch += &format!(
                "oneiron::task_verb::sdk::validate_input(\"{name}\", &value)?;
        {room_guard}{actor}
        let hooks = facade_hooks_pre(server, call, \"{name}\", value).await?;
        let value = hooks.args.clone();
        let ran = async {{ {self_branch}{ref_guard}
        {branch_turn}{producers}{output}{landed}
        Ok::<_, FacadeApiError>((output, rows))
        }}.await;
        let hook_notice = oneiron::task_verb::revoke_lands::caller_notice(&hooks).is_some();
        let (output, rows) = match ran {{ Ok(ran) => ran, Err(error) => {{ row_hooks_abort(server, hooks).await; return Err(error.with_hook_notice(hook_notice)); }} }};
        Ok(FacadeCallOutput {{ value: facade_hooks_post(server, hooks, output).await.map_err(|error| error.with_hook_notice(hook_notice))?, rows, hook_notice }})
        }}
"
            );
            continue;
        }
        let (output_binding, call_output) = match notice_result {
            Some(notice) => {
                result = notice;
                (
                    "(output, hook_notice)",
                    "FacadeCallOutput::listed(output, &producers).with_hook_notice(hook_notice == Some(true))",
                )
            }
            None => ("output", "FacadeCallOutput::listed(output, &producers)"),
        };
        // Rule 5: a task-work row's turn, bound on the surface its engine call runs on and held until that call
        // returns.
        let turn = if takes_task_work_turn(row)? {
            "\nlet turn = Arc::new(server.admit_task_work(actor).await);"
        } else {
            ""
        };
        dispatch += &head;
        if takes_task_decisions(row) {
            // OF-533: after the call's own refusals, the whole invoke runs on a blocking thread (FIX 11698).
            dispatch += &format!(
                "let (actor, class) = facade_actor(server, auth)?;{room_guard}{ref_guard}{turn}
        let (server, owned) = (Arc::clone(server), call.owned());
        super::clock_ingress::run_blocking(move || -> Result<FacadeCallOutput, FacadeApiError> {{
        let call = owned.call();
        let producers = oneiron::memory::ProducerRows::default();
        let {output_binding} = {result}{landed}
        Ok({call_output})
        }})
        .await
        .map_err(|_| FacadeApiError::from(super::host_doors::support::internal(\"{name}\")))?
        }}
"
            );
            continue;
        }
        dispatch += &format!(
            "let (actor, class) = facade_actor(server, auth)?;{room_guard}{ref_guard}{turn}
        let producers = oneiron::memory::ProducerRows::default();
        let {output_binding} = {result}{landed}
        Ok({call_output})
        }}
"
        );
    }
    // 2690: each row's nested readable paths, which a hook's rewrite meets again (`facade_admit_rewritten_paths`).
    let mut nested = Vec::new();
    for row in &rows {
        let mut paths = Vec::new();
        for readable in super::row_access::items_in(row, "admission", "readable")? {
            if readable.contains_str(".")? || readable.contains_str("[")? {
                paths.push(readable);
            }
        }
        nested.push((item(row, "name")?, paths));
    }
    dispatch += "/// The nested `readable` paths of each facade row that declares one (2690):\n/// a hook's rewrite of one meets its credential read check again.\nconst NESTED_READABLE: &[(&str, &[&str])] = &[";
    for (verb, paths) in &nested {
        if !paths.is_empty() {
            dispatch += &format!(
                "({}, &[{}]),",
                json(verb),
                paths.iter().map(json).collect::<Vec<_>>().join(", ")
            );
        }
    }
    dispatch += "];\n/// [`NESTED_READABLE`]'s paths for `verb`; none for a row that declares none.\npub(super) fn nested_readable_paths(verb: &str) -> &'static [&'static str] {\nmatch NESTED_READABLE.iter().find(|(row, _)| *row == verb) { Some((_, paths)) => *paths, None => &[] }\n}\n";
    dispatch += "type FacadeRowFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<FacadeCallOutput, FacadeApiError>> + Send + 'a>>;\n";
    for row in &rows {
        let method = method_name(row)?;
        dispatch += &format!(
            "#[inline(never)]
fn boxed_{method}<'a>(server: &'a Arc<SyncServer>, call: &'a FacadeCall<'a>, input: Result<serde_json::Value, FacadeApiError>) -> FacadeRowFuture<'a> {{
Box::pin({method}(server, call, input))
}}
"
        );
    }
    dispatch += CALL_VERB;
    for row in &rows {
        dispatch += &format!(
            "{} => boxed_{}(server, call, input).await,\n",
            json(item(row, "name")?),
            method_name(row)?
        );
    }
    let board: Vec<RowId> = generator
        .callable_rows
        .iter()
        .copied()
        .filter(|&id| get_is(&store[id], "context", "board") && !store[id].contains_key("host"))
        .collect();
    let without_host = |ids: &[RowId]| -> Vec<RowId> {
        ids.iter()
            .copied()
            .filter(|&id| !store[id].contains_key("host"))
            .collect()
    };
    for (context, ids) in [
        ("Board", board),
        ("Browser", without_host(&generator.browser_rows)),
        ("Run", without_host(&generator.run_rows)),
    ] {
        if !ids.is_empty() {
            let names: Vec<String> = ids
                .iter()
                .map(|&id| item(&store[id], "name").map(json))
                .collect::<Result<_, _>>()?;
            dispatch += &format!(
                "{} => Err(context_required(verb, VerbContext::{context})),\n",
                names.join(" | ")
            );
        }
    }
    dispatch += "_ => Err(unknown_verb(verb)),\n}\n}\n";
    Ok(FacadeDispatch { routes, dispatch })
}

/// generate.py:1815-1861: an owner-grade row's door (a full-vault result must carry verifier-produced owner proof
/// into same-snapshot engine admission, never generic actor-only invoke).
fn owner_grade_door(row: &Dict) -> Result<String, GenerateError> {
    let scope = item(row, "scope")?.str();
    let name = json(item(row, "name")?);
    Ok(format!(
        "auth.require(CoreScope::{scope})?;
                auth.require_unrestricted_record_scope()?;
                facade_outside_room_turn(call, {name})?;
                if !auth.is_owner_grade() {{
                    return Err(FacadeApiError::forbidden(\"full-vault export requires owner authority\", [\"Present a verified, unattenuated owner credential.\"]));
                }}
                let value = input?;
                oneiron::task_verb::sdk::validate_input({name}, &value)?;
                // A host credential resolves first (FIX 2222): a hosted
                // operator root gets the typed refusal, and a self-hosted root
                // or the explicit dev mode exports as the owner it acts as.
                let action = crate::api::host_action::facade_host_action(server, auth)?;
                let proof = auth.verified_slip();
                // A managed vault's attested owner (`ManagedOwnerAction`)
                // presents neither: the request's own owner proof, which the
                // export revalidates in its snapshot. Never the hosted root.
                let owner = match (proof, &action) {{
                    (None, None) if auth.managed_owner().is_some() => Some(super::host_doors::support::owner_proof(auth, server, {name})?),
                    _ => None,
                }};
                if proof.is_none() && action.is_none() && owner.is_none() {{
                    return Err(FacadeApiError::forbidden(\"full-vault export requires verified owner authority\", [\"Present a verified owner credential.\"]));
                }}
                let hooks = facade_hooks_pre(server, call, {name}, value).await?;
                // An export that fails after its pre chain ran keeps a
                // session-only call's pre hook records and runs no post chain
                // (FIX 5651), as a host door does (FIX 5527).
                let args = hooks.args.clone();
                let ran = async {{
                let input: oneiron::memory::ExportOptions = facade_input(args)?;
                // Beside the answer, the rows its snapshot read past where
                // the caller's rows go (its locality, with the machine its
                // connection proved; FIX 4937): every owner path lists them.
                // The answer is the archive inline, or kept on the server and
                // named by a transfer, as the caller's `delivery` asks (FIX
                // 3676); the leaf runs all four owner paths for both.
                let (output, rows) = super::export_transfer::vault_export_answer(server, call, &input, proof, action, owner)?;
                Ok::<_, FacadeApiError>((output, rows))
                }}.await;
                let hook_notice = oneiron::task_verb::revoke_lands::caller_notice(&hooks).is_some();
                let (output, rows) = match ran {{ Ok(ran) => ran, Err(error) => {{ row_hooks_abort(server, hooks).await; return Err(error.with_hook_notice(hook_notice)); }} }};
                Ok(FacadeCallOutput {{ value: facade_hooks_post(server, hooks, output).await.map_err(|error| error.with_hook_notice(hook_notice))?, rows: Some(rows), hook_notice }})
            }}
"
    ))
}

/// generate.py:1862-1924: a host door's dispatch. It answers from the server's own state, outside any room turn,
/// under the credential the call presented; a restrictive call's args that do not decode as the door's typed input
/// give way to the caller's own (`facade_door_input`, FIX 5076).
fn host_door(row: &Dict, method: &str) -> Result<String, GenerateError> {
    let name_value = item(row, "name")?;
    let lands = flag(row, "lands_turn");
    let landed = if lands {
        " server.ai.turn_landed_by(server.vault(), landed_by.0, landed_by.1);"
    } else {
        ""
    };
    let session_arg = if flag(row, "host_door_session") {
        "call.session()?, "
    } else {
        ""
    };
    let lens_arg = if flag(row, "host_door_lens_owner") {
        "call.lens_owner(), "
    } else {
        ""
    };
    let client_surface_arg = if flag(row, "host_door_client_surface") {
        "None, "
    } else {
        ""
    };
    let surface_arg = if flag(row, "host_door_surface") {
        "call.surface(), "
    } else {
        ""
    };
    // A caller door keeps the invocation its call hands it in its own rows (FIX 5381).
    let caller_arg = "caller, Some(oneiron::task_verb::verb_hook_boundary::door_invocation(&server.vault, &hooks)), ";
    // Only the public fold's Mark action repeats this same hook name.
    let fold_hooks_arg = if name_value.is_str("self.fold") {
        ", oneiron::code_run::actions::PreHookedFold::from_pre(&hooks)"
    } else {
        ""
    };
    let paced_arg = if flag(row, "host_door_paced") {
        "Some(super::FacadePacedCall::of(call)?), "
    } else {
        ""
    };
    let caller = if flag(row, "host_door_caller") {
        caller_arg
    } else {
        ""
    };
    let door = format!(
        "super::host_doors::{method}(server, auth, {session_arg}{caller}{lens_arg}{client_surface_arg}{surface_arg}{paced_arg}facade_door_input(&mut hooks)?{fold_hooks_arg}).await"
    );
    // A door that fails after the pre chain ran keeps a session-only call's pre hook records and runs no post chain
    // (FIX 5527).
    let failed = "Err(error) => { row_hooks_abort(server, hooks).await; return Err(error.with_hook_notice(hook_notice)); }";
    // FIX 10425: a browser batch's or library run's answer counts the decisions its hooks' verdicts answered.
    name_value.check_hashable("a set element")?;
    let counted = named_in(name_value, HOOK_DECISION_ROWS);
    let name = json(name_value);
    let pre_hooks = if counted {
        format!(
            "let (mut hooks, decided) = facade_hooks_pre_counted(server, call, {name}, value).await?;"
        )
    } else {
        format!("let mut hooks = facade_hooks_pre(server, call, {name}, value).await?;")
    };
    let post_hooks = if counted {
        format!("facade_hooks_post_counted(server, hooks, {name}, output, decided)")
    } else {
        "facade_hooks_post(server, hooks, output)".to_owned()
    };
    // A source door's failure keeps its program's feedback beside its refusal (FIX 10389).
    let door_output = if named_in(name_value, SOURCE_FEEDBACK_DOORS) {
        "output.map_err(|failure| super::host_doors::support::source_run_refusal(server, auth, Some(listed.as_slice()), failure))?"
    } else {
        "output?"
    };
    let answer = if flag(row, "host_door_lists") {
        format!(
            "let ran = async {{
                    let (output, listed) = {door};
                    Ok::<_, FacadeApiError>((facade_output({door_output})?, listed))
                }}.await;
                let hook_notice = oneiron::task_verb::revoke_lands::caller_notice(&hooks).is_some();
                let (output, listed) = match ran {{ Ok(ran) => ran, {failed} }};{landed}
                Ok(FacadeCallOutput {{ value: {post_hooks}.await.map_err(|error| error.with_hook_notice(hook_notice))?, rows: super::host_doors::support::ListedRows::rows(listed), hook_notice }})"
        )
    } else {
        format!(
            "let ran = async {{ Ok::<_, FacadeApiError>(facade_output({door}?)?) }}.await;
                let hook_notice = oneiron::task_verb::revoke_lands::caller_notice(&hooks).is_some();
                let output = match ran {{ Ok(output) => output, {failed} }};{landed}
                Ok(FacadeCallOutput::unlisted({post_hooks}.await.map_err(|error| error.with_hook_notice(hook_notice))?).with_hook_notice(hook_notice))"
        )
    };
    let scope_guard = if flag(row, "proposes") && admits(row, "credential_record_scope")? {
        "auth.require_granted(CoreScope::Write).or_else(|_| auth.require_granted(CoreScope::Propose))?;"
            .to_owned()
    } else if admits(row, "require_granted_scope")? {
        // FIX 6867: a lane door judges its records in its engine door.
        format!(
            "auth.require_granted(CoreScope::{})?;",
            item(row, "scope")?.str()
        )
    } else {
        format!("auth.require(CoreScope::{})?;", item(row, "scope")?.str())
    };
    let record_scope = record_scope_guard(row)?;
    let caller_line = if flag(row, "host_door_caller") {
        " let caller = facade_actor(server, auth)?;"
    } else {
        ""
    };
    let landed_by_line = if lands {
        " let landed_by = facade_actor(server, auth)?;"
    } else {
        ""
    };
    Ok(format!(
        "{scope_guard}
                {record_scope}
                facade_outside_room_turn(call, {name})?;{caller_line}{landed_by_line}
                let value = input?;
                oneiron::task_verb::sdk::validate_input({name}, &value)?;
                {pre_hooks}
                {answer}
            }}
"
    ))
}

/// generate.py:2100-2116: `call_verb`, the one verb table every server transport serves, and the head of its row
/// match.
const CALL_VERB: &str = "/// Runs facade verb `verb` for `call` over `input`, as its row admits it:
/// the one verb table every server transport serves. A board, browser or run
/// row is refused by the context it needs, which no facade call carries; any
/// other name is refused as an unknown verb, with its correction when it is a
/// canonical verb under the wrong root. An owner's erase or revoke, as the
/// engine classifies the verb and its own input, reads the restriction-only
/// clock through its owner proof, hooks and door (FIX 11201).
pub(crate) async fn call_verb(server: &Arc<SyncServer>, call: &FacadeCall<'_>, verb: &str, input: Result<serde_json::Value, FacadeApiError>) -> Result<FacadeCallOutput, FacadeApiError> {
let restrictive = super::clock_ingress::restrictive_call(server, verb, input.as_ref().ok());
super::clock_ingress::scoped(restrictive, call_verb_row(server, call, verb, input)).await
}
/// [`call_verb`]'s row for `verb`. Each row's concrete future is constructed
/// and boxed in its own non-inlined function (FIX 19837); this match receives
/// only its boxed handle.
async fn call_verb_row(server: &Arc<SyncServer>, call: &FacadeCall<'_>, verb: &str, input: Result<serde_json::Value, FacadeApiError>) -> Result<FacadeCallOutput, FacadeApiError> {
match verb {
";
