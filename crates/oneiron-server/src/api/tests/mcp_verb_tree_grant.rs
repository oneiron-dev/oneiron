//! Parity at the code-mode guards, without dispatching a verb or starting a guest.

use super::*;
use crate::api::mcp_gateway::static_admission::{
    GrantBounds, NarrowAxis, StaticCaller, StaticCheck, StaticRefusal, host_trigger_row,
    owner_agent_exception_row, owner_fallback_row, static_admission,
};
use crate::api::mcp_gateway::{
    McpCodeModeVerbs, McpGatewayError, RunAuthor, admit_outer_skill_call_for_test,
    admit_recorded_verb_for_test, admit_run_call_on_door_for_test, admit_run_row_for_test,
    admit_session_read_for_test, mcp_admit_bound_tool, mcp_admit_host_verb, mcp_admit_run_verb,
    mcp_admit_scoped_verb, mcp_admit_unscoped_execution_for_test, mcp_browser_guest_gate_for_test,
    mcp_error_response, mcp_hooks_admitted_for_test, mcp_run_call_gate_for_test, mcp_verb_gate,
};
use crate::auth::{CoreAuth, CoreScope};
use crate::mcp::{
    McpConnectorActorRecord, McpConnectorScope, McpEndpointTool, McpGeneratedVerbTool,
    McpSurfaceMode, McpVerbArguments, try_registered_surface,
};
use oneiron::authority::SlipCaveat;
use oneiron::code_run::{AgentVerbRefusal, RunCall, SelfEffect};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};
use oneiron::{EdgeActorClass, EntityId};
use serde_json::json;
use std::collections::BTreeSet;

fn tool(name: &str) -> McpGeneratedVerbTool {
    let surface = try_registered_surface(McpSurfaceMode::ToolFirst).unwrap();
    let Some(McpEndpointTool::Verb(tool)) = surface.resolve(name) else {
        panic!("{name} should resolve to a ToolFirst verb");
    };
    tool
}

fn install_proposed_ceiling(
    server: &SyncServer,
    id: EntityId,
    actor: EntityId,
    class: EdgeActorClass,
) {
    let vault = server.vault();
    let owner_ref = vault.ensure_embedded_owner_actor().unwrap();
    let owner = vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    let manifest = rmp_serde::to_vec_named(&json!({
        "schema_version": "1.2", "pack_id": "tree-parity-propose", "pack_version": "v1",
        "min_engine_version": "0.0.0", "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [], "actor_ceilings": [{"actor_class": class.gate_actor_class(),
            "actor_ref": actor.to_hex(), "ceiling": "proposed"}],
    })).unwrap();
    vault
        .install_owner_policy_manifest(&owner, id, manifest, 1)
        .unwrap();
}

fn door(server: &Arc<SyncServer>, context: &McpCallContext, author: RunAuthor) -> McpCodeModeVerbs {
    let door = McpCodeModeVerbs::new(server, context, seeded_test_entity_id(0x6000));
    match author {
        RunAuthor::Caller => door.authored_by_caller(),
        RunAuthor::EngineModel => door.authored_by_engine_model(),
    }
}

fn assert_gate_error(
    actual: Result<(), McpGatewayError>,
    code: i64,
    kind: &str,
    message: &str,
    field: Option<&str>,
    required_scope: Option<&str>,
    reason_codes: &[&str],
) {
    let response = mcp_error_response(json!("parity"), actual.expect_err(kind));
    let error = &response["error"];
    let data = &error["data"];
    assert_eq!(error["code"].as_i64(), Some(code), "{response}");
    assert_eq!(error["message"].as_str(), Some(message), "{response}");
    assert_eq!(data["human_message"].as_str(), Some(message), "{response}");
    assert_eq!(data["kind"].as_str(), Some(kind), "{response}");
    assert_eq!(data["error_code"].as_str(), Some(kind), "{response}");
    assert_eq!(
        data.get("field"),
        field.map(Value::from).as_ref(),
        "{response}"
    );
    assert_eq!(
        data.get("required_scope"),
        required_scope.map(Value::from).as_ref(),
        "{response}"
    );
    if reason_codes.is_empty() {
        assert!(data.get("reason_codes").is_none(), "{response}");
    } else {
        assert_eq!(data["reason_codes"], json!(reason_codes), "{response}");
    }
}

fn assert_guest_error<T>(actual: Result<T, AgentVerbRefusal>, code: &str, reasons: &[&str]) {
    let refusal = actual.err().expect(code);
    assert_eq!(refusal.code, code);
    let actual: Vec<_> = refusal.reason_codes.iter().map(String::as_str).collect();
    assert_eq!(actual.as_slice(), reasons);
    assert!(refusal.hook_notice.is_none());
}

fn assert_bound(actual: Result<(), McpGatewayError>, name: &str, bound: bool) {
    if bound {
        actual.unwrap();
    } else {
        assert_gate_error(
            actual,
            -32020,
            "mcp_verb_not_bound",
            &format!("{name} is not bound to this connector credential"),
            Some("name"),
            None,
            &[],
        );
    }
}

fn assert_scope(
    actual: Result<(), McpGatewayError>,
    name: &str,
    field: &str,
    axis: Option<(NarrowAxis, &str)>,
) {
    if let Some((_, text)) = axis {
        assert_gate_error(
            actual,
            -32020,
            "mcp_scope_refused",
            &format!(
                "{name} executes outside this credential's {text} ceiling and is refused: this \
                 release carries no scope through that execution"
            ),
            Some(field),
            None,
            &[],
        );
    } else {
        actual.unwrap();
    }
}

fn assert_author<T>(
    actual: Result<T, AgentVerbRefusal>,
    static_result: Result<(), StaticRefusal>,
    reason: Option<&'static str>,
) {
    assert_eq!(
        static_result,
        reason.map_or(Ok(()), |r| Err(StaticRefusal::CallerCode(r)))
    );
    let veto = actual
        .err()
        .filter(|refusal| refusal.code == "caller_code_refused");
    if let Some(reason) = reason {
        assert_guest_error::<()>(
            Err(veto.expect("caller-code veto")),
            "caller_code_refused",
            &[reason],
        );
    } else {
        assert!(veto.is_none(), "unexpected caller-code veto");
    }
}

/// Red: in `admission.rs`, replace the `if` condition testing `BoundName` with `true`.
#[tokio::test]
async fn generated_code_mode_rows_match_static_admission_at_each_guard() {
    let (_dir, server) = test_server();
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    register_mcp_actor(&server, "tree-owner", owner, EdgeActorClass::Human).await;
    let agent = seeded_test_entity_id(0x6001);
    register_mcp_actor(&server, "tree-agent", agent, EdgeActorClass::Agent).await;
    install_proposed_ceiling(
        &server,
        seeded_test_entity_id(0x6008),
        agent,
        EdgeActorClass::Agent,
    );
    register_bound_verb_mcp_actor(
        &server,
        "tree-bound",
        seeded_test_entity_id(0x6002),
        &["execute", "vault.recall"],
    )
    .await;
    let world = seeded_test_entity_id(0x6003);
    let facet = seeded_test_entity_id(0x6004);
    for (label, id, world, facet) in [
        ("tree-world", 0x6005, Some(world), None),
        ("tree-facet", 0x6006, None, Some(facet)),
        ("tree-both", 0x6007, Some(world), Some(facet)),
    ] {
        register_scoped_mcp_actor(
            &server,
            label,
            seeded_test_entity_id(id),
            McpConnectorScope::scoped(world, facet),
        )
        .await;
    }
    // Independent fixture table: exact binding (None = all) and the two registration axes.
    let expected = [
        ("tree-owner", None, None),
        ("tree-agent", None, None),
        ("tree-bound", Some(["execute", "vault.recall"]), None),
        ("tree-world", None, Some((NarrowAxis::World, "world"))),
        ("tree-facet", None, Some((NarrowAxis::Facet, "facet"))),
        (
            "tree-both",
            None,
            Some((NarrowAxis::WorldAndFacet, "world and facet")),
        ),
    ];
    let surface = try_registered_surface(McpSurfaceMode::ToolFirst).unwrap();
    let args = McpVerbArguments::default(); // No argument-selected scope branches at this seam.
    let mut binding = [0; 2];
    let mut scope = [0; 2];
    let mut authors = [0; 2];
    let mut agent_rows = 0;
    for (label, names, axis) in expected {
        let context = mcp_test_context(&server, label, "tree-matrix").await;
        let bound = |name| names.is_none_or(|names| names.contains(&name));
        let scope_verdict = axis.map_or(Ok(()), |(axis, _)| {
            Err(StaticRefusal::NarrowRegistration(axis))
        });
        for author in [RunAuthor::Caller, RunAuthor::EngineModel] {
            let door = door(&server, &context, author);
            let caller = StaticCaller::connector(&context).authored(author);
            for name in oneiron::verbs::code_mode_verb_names() {
                if RunVerb::from_name(name).is_some() {
                    continue; // Run names take precedence; covered below.
                }
                let verb = AgentVerb::from_name(name).expect(name);
                agent_rows += 1;
                assert_bound(mcp_admit_bound_tool(&context, name), name, bound(name));
                assert_eq!(
                    static_admission(caller, StaticCheck::BoundName(name)),
                    if bound(name) {
                        Ok(())
                    } else {
                        Err(StaticRefusal::NotBound)
                    },
                    "{label}: {name}",
                );
                binding[usize::from(bound(name))] += 1;
                // The pre-extraction route table: host paths use `name`; ordinary tools
                // select either the memory method's field or the unscoped row's field.
                let stage = if verb.is_browser() || verb == AgentVerb::VaultRunsReadResult {
                    Some((mcp_admit_host_verb(&context, verb), Some("name")))
                } else if let Some(McpEndpointTool::Verb(tool)) = surface.resolve(name) {
                    let field = if tool.memory_method().is_some() {
                        Some("arguments.request")
                    } else if tool.requires_unscoped() {
                        Some("arguments.spec")
                    } else {
                        None
                    };
                    Some((mcp_admit_scoped_verb(&server, tool, &args, &context), field))
                } else {
                    None // The actual ToolFirst route has no scope stage.
                };
                if let Some((actual, field)) = stage {
                    let scope_result = if bound(name) {
                        actual
                    } else {
                        assert_bound(actual, name, false);
                        // A binding refusal wins in the composed gate. Check the
                        // unscoped stage separately when the route has one.
                        field.map_or(Ok(()), |field| {
                            mcp_admit_unscoped_execution_for_test(&context, name, field)
                        })
                    };
                    if let Some(field) = field {
                        assert_scope(scope_result, name, field, axis);
                        assert_eq!(
                            static_admission(caller, StaticCheck::UnscopedExecution),
                            scope_verdict
                        );
                        scope[usize::from(axis.is_none())] += 1;
                    } else {
                        scope_result.unwrap();
                    }
                }
                let reason = match (author, verb.is_browser(), verb.refused_to_caller_code()) {
                    (RunAuthor::Caller, true, _) => Some("caller_code.host_guest"),
                    (RunAuthor::Caller, false, true) => Some("caller_code.credential_answer"),
                    _ => None,
                };
                assert_author(
                    admit_recorded_verb_for_test(&door, verb),
                    static_admission(caller, StaticCheck::CallerCodeAgentRow(verb)),
                    reason,
                );
                authors[usize::from(reason.is_none())] += 1;
            }
            for &verb in RunVerb::ALL {
                let name = verb.as_str();
                let call = RunCall::Bridge(verb.effect());
                assert_bound(mcp_admit_run_verb(&context, verb), name, bound(name));
                assert_eq!(
                    static_admission(caller, StaticCheck::BoundName(name)),
                    if bound(name) {
                        Ok(())
                    } else {
                        Err(StaticRefusal::NotBound)
                    },
                    "{label}: {name}",
                );
                binding[usize::from(bound(name))] += 1;
                // Run rows have no per-row registration-scope guard: their run entry
                // takes this check on `execute`, independently of the exact row gate.
                assert_scope(
                    mcp_admit_unscoped_execution_for_test(&context, "execute", "name"),
                    "execute",
                    "name",
                    axis,
                );
                assert_eq!(
                    static_admission(caller, StaticCheck::UnscopedExecution),
                    scope_verdict
                );
                scope[usize::from(axis.is_none())] += 1;
                let reason = match (author, verb.effect()) {
                    (RunAuthor::Caller, SelfEffect::ReaderSpawn) => {
                        Some("caller_code.reader_child")
                    }
                    (RunAuthor::Caller, SelfEffect::Summarize) => Some("caller_code.summary_job"),
                    (
                        RunAuthor::Caller,
                        SelfEffect::RepoSnapshotsRead
                        | SelfEffect::RepoViewsRead
                        | SelfEffect::SkillsCall
                        | SelfEffect::ConnectorAnswer
                        | SelfEffect::Leader,
                    ) => Some("caller_code.credential_answer"),
                    _ => None,
                };
                assert_author(
                    admit_run_call_on_door_for_test(&door, call),
                    static_admission(caller, StaticCheck::CallerCodeRunCall(call)),
                    reason,
                );
                authors[usize::from(reason.is_none())] += 1;
            }
        }
    }
    assert!(agent_rows > 0 && !RunVerb::ALL.is_empty());
    for witnesses in [binding, scope, authors] {
        assert!(witnesses[0] > 0 && witnesses[1] > 0, "{witnesses:?}");
    }
}

/// Red: replace `mcp_admit_run_verb(&self.actor, verb)` in `admit_run_row` with
/// `Ok::<(), McpGatewayError>(())`, leaving the refusal mapping in place.
#[tokio::test]
async fn shared_run_effect_keeps_exact_binding_and_author_order() {
    let (_dir, server) = test_server();
    register_bound_verb_mcp_actor(
        &server,
        "fold",
        seeded_test_entity_id(0x6010),
        &["self.fold"],
    )
    .await;
    register_bound_verb_mcp_actor(
        &server,
        "advice",
        seeded_test_entity_id(0x6011),
        &["self.leader.advice", "self.skills.call"],
    )
    .await;
    let fold = mcp_test_context(&server, "fold", "fold-parity").await;
    let advice = mcp_test_context(&server, "advice", "advice-parity").await;
    for (context, row, exact) in [
        (&fold, "self.fold", true),
        (&fold, "self.folds", false),
        (&fold, "self.leader.advice", false),
        (&advice, "self.leader.advice", true),
    ] {
        let door = door(&server, context, RunAuthor::Caller);
        let result = admit_run_row_for_test(&door, row);
        assert_eq!(
            static_admission(
                StaticCaller::connector(context),
                StaticCheck::BoundName(row)
            ),
            if exact {
                Ok(())
            } else {
                Err(StaticRefusal::NotBound)
            },
        );
        if exact {
            result.unwrap();
        } else {
            assert_guest_error(result, "mcp_verb_not_bound", &[]);
        }
    }
    assert_eq!(
        RunVerb::from_name("self.fold").unwrap().effect(),
        SelfEffect::Fold
    );
    assert_eq!(
        RunVerb::from_name("self.folds").unwrap().effect(),
        SelfEffect::Fold
    );
    let caller = door(&server, &fold, RunAuthor::Caller);
    let fold_call = RunCall::Bridge(SelfEffect::Fold);
    assert!(admit_run_call_on_door_for_test(&caller, fold_call).is_ok());
    assert_eq!(
        static_admission(
            StaticCaller::connector(&fold).authored(RunAuthor::Caller),
            StaticCheck::CallerCodeRunCall(fold_call)
        ),
        Ok(()),
    );
    let leader = RunCall::Bridge(SelfEffect::Leader);
    let skill = RunCall::Bridge(SelfEffect::SkillsCall);
    let reason = "caller_code.credential_answer";
    assert_guest_error(
        admit_run_row_for_test(&caller, "self.leader.advice")
            .and_then(|()| admit_run_call_on_door_for_test(&caller, leader)),
        "mcp_verb_not_bound",
        &[],
    );
    for author in [RunAuthor::Caller, RunAuthor::EngineModel] {
        let door = door(&server, &advice, author);
        let caller = StaticCaller::connector(&advice).authored(author);
        for (row, call) in [("self.leader.advice", leader), ("self.skills.call", skill)] {
            let actual = admit_run_row_for_test(&door, row)
                .and_then(|()| admit_run_call_on_door_for_test(&door, call));
            let static_result = static_admission(caller, StaticCheck::CallerCodeRunCall(call));
            if author == RunAuthor::Caller {
                assert_eq!(static_result, Err(StaticRefusal::CallerCode(reason)));
                assert_guest_error(actual, "caller_code_refused", &[reason]);
            } else {
                assert_eq!(static_result, Ok(()));
                assert!(actual.is_ok());
            }
        }
        // The outer skill path uses binding but does not consult CallerCodeRunCall.
        assert_eq!(
            static_admission(caller, StaticCheck::BoundName("self.skills.call")),
            Ok(())
        );
        assert!(admit_outer_skill_call_for_test(&door).is_ok());
    }
}

async fn attenuated_context(
    server: &Arc<SyncServer>,
    label: &str,
    id: EntityId,
    class: EdgeActorClass,
    verbs: &[&str],
    bound: Option<&[&'static str]>,
    channels: Option<BTreeSet<String>>,
) -> McpCallContext {
    register_mcp_actor(server, label, id, class).await;
    let token = attenuate_mcp_credential(
        server,
        label,
        SlipCaveat {
            scope: Some(Scope {
                verbs: ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect()),
                ..Scope::top()
            }),
            channels,
            ..Default::default()
        },
    );
    let mut record = McpConnectorActorRecord::new(id, class, McpConnectorScope::vault_wide());
    if let Some(verbs) = bound {
        record = record.with_bound_verbs(verbs.iter().copied());
    }
    server
        .mcp_registry
        .lock()
        .await
        .register(&token, record)
        .unwrap();
    mcp_test_context(server, label, "tree-tier").await
}

fn assert_missing_grant(actual: Result<(), McpGatewayError>, scope: &str) {
    assert_gate_error(
        actual,
        -32020,
        "mcp_grant_missing",
        &format!("this connector's credential does not hold the {scope} grant this call needs"),
        None,
        Some(scope),
        &[],
    );
}

/// Red: change `McpCallEffect::Commits` to `McpCallEffect::Reads` in `mcp_browser_guest_gate`.
#[tokio::test]
async fn browser_keeps_author_binding_and_write_in_that_order() {
    let (_dir, server) = test_server();
    let browser = AgentVerb::from_name("self.browser.observe").unwrap();
    let desktop = AgentVerb::from_name("self.desktop.observe").unwrap();
    let expected = [
        (
            "browser-unbound",
            &["execute"][..],
            &["core:read"][..],
            RunAuthor::Caller,
            browser,
            Some(("caller_code_refused", &["caller_code.host_guest"][..])),
        ),
        (
            "browser-unbound",
            &["execute"][..],
            &["core:read"][..],
            RunAuthor::EngineModel,
            browser,
            Some(("mcp_verb_not_bound", &[][..])),
        ),
        (
            "browser-read",
            &["self.browser.observe", "self.desktop.observe"][..],
            &["core:read"][..],
            RunAuthor::EngineModel,
            browser,
            Some(("mcp_grant_missing", &[][..])),
        ),
        (
            "browser-write",
            &["self.browser.observe"][..],
            &["core:read", "core:write"][..],
            RunAuthor::EngineModel,
            browser,
            None,
        ),
        (
            "browser-read",
            &["self.browser.observe", "self.desktop.observe"][..],
            &["core:read"][..],
            RunAuthor::EngineModel,
            desktop,
            Some(("mcp_desktop_refused", &[][..])),
        ),
    ];
    let mut contexts = std::collections::BTreeMap::new();
    for (label, names, tier, author, row, refusal) in expected {
        if !contexts.contains_key(label) {
            let id = seeded_test_entity_id(0x6020 + contexts.len() as u128);
            let context = attenuated_context(
                &server,
                label,
                id,
                EdgeActorClass::Human,
                tier,
                Some(names),
                None,
            )
            .await;
            contexts.insert(label, context);
        }
        let context = &contexts[label];
        let door = door(&server, context, author);
        let caller = StaticCaller::connector(context).authored(author);
        let result = admit_recorded_verb_for_test(&door, row);
        if let Some((code, reasons)) = refusal {
            assert_guest_error(result, code, reasons);
        } else {
            result.unwrap();
        }
        let author_veto = (author == RunAuthor::Caller)
            .then_some(StaticRefusal::CallerCode("caller_code.host_guest"));
        assert_eq!(
            static_admission(caller, StaticCheck::CallerCodeAgentRow(row)),
            author_veto.map_or(Ok(()), Err),
        );
        let bound = names.contains(&row.as_str());
        assert_bound(mcp_admit_host_verb(context, row), row.as_str(), bound);
        assert_eq!(
            static_admission(caller, StaticCheck::BoundName(row.as_str())),
            if bound {
                Ok(())
            } else {
                Err(StaticRefusal::NotBound)
            },
        );
        assert_eq!(
            static_admission(caller, StaticCheck::DesktopRow(row)),
            if row == desktop {
                Err(StaticRefusal::Desktop)
            } else {
                Ok(())
            },
        );
        if row == browser && bound {
            let actual = mcp_browser_guest_gate_for_test(&server, context);
            let static_result = static_admission(
                caller,
                StaticCheck::Grant {
                    scope: CoreScope::Write,
                    bounds: GrantBounds::Checked,
                },
            );
            if label == "browser-read" {
                assert_missing_grant(actual, "core:write");
                assert_eq!(static_result, Err(StaticRefusal::Grant(CoreScope::Write)));
            } else {
                actual.unwrap();
                assert_eq!(static_result, Ok(()));
            }
        }
    }
    let context = &contexts["browser-unbound"];
    let row = AgentVerb::VaultRunsReadResult;
    assert_guest_error(
        admit_session_read_for_test(&door(&server, context, RunAuthor::EngineModel), row),
        "mcp_verb_not_bound",
        &[],
    );
    assert_eq!(
        static_admission(
            StaticCaller::connector(context),
            StaticCheck::BoundName(row.as_str())
        ),
        Err(StaticRefusal::NotBound),
    );
}

fn assert_auth_required(actual: Result<(), McpGatewayError>) {
    assert_gate_error(
        actual,
        -32001,
        "mcp_auth_required",
        "the registered connector requires its live paired holder proof",
        None,
        None,
        &[],
    );
}

/// Red: replace the `LaneRecordScope` decision in `mcp_verb_gate` with
/// `Ok::<(), ()>(())`, leaving its error mapping in place.
#[tokio::test]
async fn record_bounds_and_live_ceiling_keep_the_first_refusal() {
    let (_dir, server) = test_server();
    let lane_tool = tool("self.actor");
    let args = McpVerbArguments::default(); // self.actor has an empty input at the guard.
    let caveated = attenuated_context(
        &server,
        "channel",
        seeded_test_entity_id(0x6030),
        EdgeActorClass::Human,
        &["core:read", "core:write"],
        None,
        Some(["proposal".to_owned()].into()),
    )
    .await;
    let proposer = seeded_test_entity_id(0x6031);
    let proposed = attenuated_context(
        &server,
        "proposer",
        proposer,
        EdgeActorClass::Human,
        &["core:read", "core:propose"],
        None,
        None,
    )
    .await;
    // The wire itself refuses a no-Read registration. Use a real verified no-Read
    // proof on a resolved context to isolate the later gate's own error mapping.
    register_mcp_actor(
        &server,
        "no-read",
        seeded_test_entity_id(0x6034),
        EdgeActorClass::Human,
    )
    .await;
    let mut no_read = mcp_test_context(&server, "no-read", "tree-no-read").await;
    attenuate_mcp_credential(
        &server,
        "no-read",
        SlipCaveat {
            scope: Some(Scope {
                verbs: ScopeAxis::Some(["core:write".to_owned()].into()),
                ..Scope::top()
            }),
            ..Default::default()
        },
    );
    no_read.actor.auth = Some(
        CoreAuth::from_headers(
            &mcp_credential_headers(&server, "no-read"),
            &server.config,
            server.vault().as_ref(),
        )
        .unwrap(),
    );
    assert_eq!(
        static_admission(
            StaticCaller::connector(&no_read),
            StaticCheck::Grant {
                scope: CoreScope::Read,
                bounds: GrantBounds::Carried,
            }
        ),
        Err(StaticRefusal::Grant(CoreScope::Read)),
    );
    assert_auth_required(mcp_verb_gate(&server, lane_tool, &args, &no_read));

    let claim_tool = tool("vault.claims.upsert");
    let mut draft = McpVerbArguments {
        spec: Some(
            json!({ "subject_ref": proposer.to_hex(), "predicate": "test.tree",
            "value": "draft", "confidence": 0.9, "source": "observed" }),
        ),
        ..Default::default()
    };
    let caller = StaticCaller::connector(&proposed);
    assert_eq!(
        static_admission(caller, StaticCheck::UnrestrictedRecordScope),
        Ok(())
    );
    let assert_grant = |scope, expected| {
        assert_eq!(
            static_admission(
                caller,
                StaticCheck::Grant {
                    scope,
                    bounds: GrantBounds::Carried,
                }
            ),
            expected
        );
    };
    assert_grant(
        CoreScope::Write,
        Err(StaticRefusal::Grant(CoreScope::Write)),
    );
    assert!(
        !server
            .vault()
            .gate_actor_ceiling_is_proposed("human", &proposer.to_hex())
            .unwrap()
    );
    assert_missing_grant(
        mcp_verb_gate(&server, claim_tool, &draft, &proposed),
        "core:write",
    );

    install_proposed_ceiling(
        &server,
        seeded_test_entity_id(0x6032),
        proposer,
        EdgeActorClass::Human,
    );
    assert!(
        server
            .vault()
            .gate_actor_ceiling_is_proposed("human", &proposer.to_hex())
            .unwrap()
    );
    assert_grant(CoreScope::Propose, Ok(()));
    mcp_verb_gate(&server, claim_tool, &draft, &proposed).unwrap();
    draft.spec.as_mut().unwrap()["id"] = json!(seeded_test_entity_id(0x6033).to_hex());
    assert_missing_grant(
        mcp_verb_gate(&server, claim_tool, &draft, &proposed),
        "core:write",
    );

    let assert_channel_refusal = || {
        let caller = StaticCaller::connector(&caveated);
        assert_eq!(
            static_admission(caller, StaticCheck::LaneRecordScope),
            Err(StaticRefusal::RecordScope)
        );
        assert_eq!(
            static_admission(caller, StaticCheck::UnrestrictedRecordScope),
            Err(StaticRefusal::RecordScope)
        );
        assert_gate_error(
            mcp_verb_gate(&server, lane_tool, &args, &caveated),
            -32020,
            "mcp_scope_unprojectable",
            "this facade cannot project the credential's record bounds",
            None,
            None,
            &[],
        );
    };
    assert_channel_refusal();
    assert_gate_error(
        mcp_run_call_gate_for_test(&server, &caveated, RunCall::RecordedOutput),
        -32020,
        "mcp_scope_unprojectable",
        "this facade cannot project the credential's record bounds",
        None,
        None,
        &[],
    );

    let facet = seeded_test_entity_id(0x6035);
    register_scoped_mcp_actor(
        &server,
        "tree-born",
        seeded_test_entity_id(0x6036),
        McpConnectorScope::scoped(None, Some(facet)),
    )
    .await;
    let born = mcp_test_context(&server, "tree-born", "tree-born-parity").await;
    let task = tool("tasks.create");
    assert_eq!(born.landing.unwrap(), Some(facet));
    assert_eq!(
        static_admission(
            StaticCaller::connector(&born),
            StaticCheck::Grant {
                scope: CoreScope::Write,
                bounds: GrantBounds::Carried,
            }
        ),
        Ok(()),
    );
    mcp_verb_gate(&server, task, &args, &born).unwrap();
    let mut misplaced = born.clone();
    misplaced.landing = Err(crate::api::write_facet::LandingRefused);
    assert_gate_error(
        mcp_verb_gate(&server, task, &args, &misplaced),
        -32020,
        "mcp_scope_refused",
        "the session this request names does not place this connector's writes",
        None,
        None,
        &[],
    );

    for context in [&caveated, &proposed] {
        let auth = context.auth.as_ref().unwrap();
        let slip_id = auth.verified_slip().unwrap().claims().slip_id;
        server
            .vault()
            .revoke_capability_slip(&crate::test_credentials::host_issuer(&server), slip_id)
            .unwrap();
        assert!(!auth.credential_is_live(server.vault()));
    }
    assert_channel_refusal(); // A dead proof does not move the lane check behind liveness.
    assert_auth_required(mcp_run_call_gate_for_test(
        &server,
        &caveated,
        RunCall::RecordedOutput,
    ));
    assert_auth_required(mcp_verb_gate(&server, lane_tool, &args, &proposed));
    assert_eq!(
        static_admission(caller, StaticCheck::LaneRecordScope),
        Ok(())
    );
    let world_privacy = RunCall::Bridge(SelfEffect::WorldPrivacySet);
    let reason = "world_privacy.set_by_holder_directly";
    for author in [RunAuthor::Caller, RunAuthor::EngineModel] {
        let caller = StaticCaller::connector(&proposed).authored(author);
        assert_eq!(
            static_admission(caller, StaticCheck::CallerCodeRunCall(world_privacy)),
            Ok(())
        );
        assert_eq!(
            static_admission(caller, StaticCheck::ConnectorRunCall(world_privacy)),
            Err(StaticRefusal::WorldPrivacy)
        );
        assert_guest_error(
            admit_run_call_on_door_for_test(&door(&server, &proposed, author), world_privacy),
            "mcp_world_privacy_refused",
            &[reason],
        );
        assert_gate_error(
            mcp_run_call_gate_for_test(&server, &proposed, world_privacy),
            -32020,
            "mcp_world_privacy_refused",
            "a world's privacy is set by its holder directly, not by a connector's run",
            None,
            None,
            &[reason],
        );
    }
}

/// Red: drop `auth.actor_class() == Some("agent") &&` in `StaticCheck::NonOwnerAgent`.
#[tokio::test]
async fn owner_preflight_keeps_agent_exception_and_owner_grade_separate() {
    let (_dir, server) = test_server();
    let owner = server.vault().ensure_embedded_owner_actor().unwrap();
    register_mcp_actor(&server, "owner-doors", owner, EdgeActorClass::Human).await;
    let owner = mcp_test_context(&server, "owner-doors", "owner-doors-parity").await;
    let agent_id = seeded_test_entity_id(0x6040);
    install_proposed_ceiling(
        &server,
        seeded_test_entity_id(0x6042),
        agent_id,
        EdgeActorClass::Agent,
    );
    let agent = attenuated_context(
        &server,
        "agent-doors",
        agent_id,
        EdgeActorClass::Agent,
        &["core:read"],
        None,
        None,
    )
    .await;
    let human = attenuated_context(
        &server,
        "human-doors",
        seeded_test_entity_id(0x6041),
        EdgeActorClass::Human,
        &["core:read"],
        None,
        None,
    )
    .await;
    let fallback = [
        "vault.artifacts.live_preview.revoke_invite",
        "vault.artifacts.live_preview.revoke_share",
        "vault.authority.handoff_alarms.acknowledge",
        "vault.coach.training_offers.candidates.prepare",
        "vault.coach.training_offers.pilots.complete",
        "vault.coach.training_offers.pilots.prepare",
        "vault.federation.connect.world_privacy.export",
        "vault.federation.connect.world_privacy.receive",
        "vault.federation.coreference.share_consent",
        "vault.skills.attribution.evidence.record",
        "vault.skills.attribution.positive.retire",
    ];
    let exceptions = [
        "vault.runs.review",
        "vault.runs.settlement",
        "vault.runs.changes.get",
        "vault.hooks.regen.due",
        "vault.hooks.regen.get",
        "vault.hooks.regen.adopt",
    ];
    let triggers = ["host.compact", "host.wake", "host.budget.hit"];
    let delegate = "vault.tasks.cancel.force";
    let export = "vault.export";
    let rows = AgentVerb::ALL
        .iter()
        .map(|v| v.as_str())
        .chain(RunVerb::ALL.iter().map(|v| v.as_str()))
        .chain(fallback)
        .chain(exceptions)
        .chain(triggers)
        .chain([delegate, export, "unknown.row"])
        .collect::<BTreeSet<_>>();
    for (classify, expected) in [
        (owner_fallback_row as fn(&str) -> bool, &fallback[..]),
        (owner_agent_exception_row, &exceptions[..]),
        (host_trigger_row, &triggers[..]),
    ] {
        let actual: BTreeSet<_> = rows.iter().copied().filter(|name| classify(name)).collect();
        let expected: BTreeSet<_> = expected.iter().copied().collect();
        assert_eq!(actual, expected);
    }

    // The listed fallback name also has a generated Owner door on this pin.
    // The real preflight reaches Owner; the dormant fallback list is pinned above.
    for (context, grade, non_owner_agent) in [
        (&owner, true, false),
        (&agent, false, true),
        (&human, false, false),
    ] {
        let auth = context.auth.as_ref().unwrap();
        let caller = StaticCaller::facade(auth);
        for (row, admits, setting_refusal) in [
            (fallback[0], grade, false),
            (exceptions[0], grade || non_owner_agent, false),
            (delegate, grade, non_owner_agent),
        ] {
            let actual = crate::api::facade::row_door_admits(&server, auth, row);
            if admits {
                actual.unwrap();
            } else {
                let refused = actual.unwrap_err();
                assert_eq!(refused.code, "FORBIDDEN");
                assert_eq!(refused.message, format!("{row} is the vault owner's"));
                let mut expected =
                    vec!["Present the owner's own verified, unattenuated credential."];
                if setting_refusal {
                    expected.push("The owner lets an agent do this with the setting `attempt_queue.agent_may_force_cancel`.");
                }
                assert_eq!(
                    refused
                        .suggestions
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    expected
                );
            }
        }
        let memory = crate::api::mcp_credential_memory(
            server.vault(),
            Some(auth),
            context.actor_ref,
            context.actor_class,
        );
        let actual = mcp_hooks_admitted_for_test(&server, export, context, &memory);
        if grade {
            actual.unwrap();
        } else {
            assert_gate_error(
                actual,
                -32020,
                "forbidden",
                "full-vault export requires owner authority",
                None,
                None,
                &[],
            );
        }
        assert_eq!(
            static_admission(caller, StaticCheck::OwnerGrade),
            if grade {
                Ok(())
            } else {
                Err(StaticRefusal::OwnerGrade)
            }
        );
        assert_eq!(
            static_admission(caller, StaticCheck::NonOwnerAgent),
            if non_owner_agent {
                Ok(())
            } else {
                Err(StaticRefusal::NotNonOwnerAgent)
            }
        );
    }
    let mut no_auth = owner.clone();
    no_auth.actor.auth = None;
    let caller = StaticCaller::connector(&no_auth);
    let memory = crate::api::mcp_credential_memory(
        server.vault(),
        None,
        no_auth.actor_ref,
        no_auth.actor_class,
    );
    for trigger in triggers {
        assert_eq!(
            static_admission(caller, StaticCheck::HostTriggerCredential(trigger)),
            Err(StaticRefusal::HostTriggerCredential)
        );
        assert_gate_error(
            mcp_hooks_admitted_for_test(&server, trigger, &no_auth, &memory),
            -32020,
            "forbidden",
            "a host trigger requires the owner's verified credential",
            None,
            None,
            &[],
        );
    }
    assert_eq!(
        static_admission(caller, StaticCheck::OwnerGrade),
        Err(StaticRefusal::NoCredential)
    );
    assert_eq!(
        static_admission(caller, StaticCheck::HandlerCredential(export)),
        Err(StaticRefusal::HandlerCredential)
    );
    assert_gate_error(
        mcp_hooks_admitted_for_test(&server, export, &no_auth, &memory),
        -32602,
        "tool_args_invalid",
        "invalid typed agent-verb argument",
        None,
        None,
        &[],
    );
}

/// Red: let the non-owner path pass `NoteKindAudience::Owner` to the projection.
#[tokio::test]
async fn note_kind_discovery_lists_installed_kinds_to_the_owner_only() {
    use crate::api::mcp_gateway::mcp_discovery_view;
    use oneiron::note::{ContextDefault, ExtractionDefault, NoteKindDescriptor, RetentionDefault};

    let (_dir, server) = test_server();
    let owner_ref = server.vault().ensure_embedded_owner_actor().unwrap();
    let installed = "tree-private/therapy";
    server
        .vault()
        .register_note_kind(&NoteKindDescriptor {
            pack: "tree-private".to_owned(),
            kind: installed.to_owned(),
            extraction: ExtractionDefault::Disabled,
            context: ContextDefault::OwnerOnly,
            retention: RetentionDefault::Durable,
            archive_after_days: None,
        })
        .unwrap();
    register_mcp_actor(&server, "tree-kind-owner", owner_ref, EdgeActorClass::Human).await;
    let owner = mcp_test_context(&server, "tree-kind-owner", "tree-kind-owner-run").await;
    let agent = attenuated_context(
        &server,
        "tree-kind-agent",
        seeded_test_entity_id(0x6050),
        EdgeActorClass::Agent,
        &["core:read", "core:write"],
        None,
        None,
    )
    .await;

    for (actor, sees_installed) in [(&owner, true), (&agent, false)] {
        let view = mcp_discovery_view(&server, actor, RunAuthor::Caller).unwrap();
        let create = view
            .expand("vault.notes.create")
            .expect("the caller can create notes");
        let kinds = create
            .lines()
            .find(|line| line.contains("kind is one of"))
            .unwrap();
        assert!(kinds.contains("\"research\""), "{create}");
        assert_eq!(kinds.contains(installed), sees_installed, "{create}");
        assert_eq!(create.contains(installed), sees_installed, "{create}");
    }
}

/// Red: bypass the `mcp_admit_scoped_verb` gate in discovery (it checks `BoundName`).
#[tokio::test]
async fn bound_credential_discovery_view_admits_only_its_rows() {
    use crate::api::mcp_gateway::mcp_discovery_view;

    let (_dir, server) = test_server();
    register_bound_verb_mcp_actor(
        &server,
        "tree-discovery-bound",
        seeded_test_entity_id(0x6051),
        &["execute", "vault.recall"],
    )
    .await;
    let actor = mcp_test_context(&server, "tree-discovery-bound", "tree-discovery-bound-run").await;
    let view = mcp_discovery_view(&server, &actor, RunAuthor::Caller).unwrap();
    let recall = view.expand("vault.recall").unwrap();
    assert!(recall.starts_with("vault.recall("), "{recall}");
    let branch = view.expand("vault").unwrap();
    assert_eq!(branch.lines().count(), 2, "{branch}");
    assert_eq!(
        branch.lines().next(),
        Some("vault · 1 verbs · a line per child")
    );
    let omitted = view.expand("vault.notes.create").unwrap_err();
    assert_eq!(omitted, view.expand("not.a.real.verb").unwrap_err());
    assert_eq!(
        view.search("vault.notes.create", None, None),
        view.search("not.a.real.verb", None, None),
    );
}
