//! The real session endpoint cannot fill context before a registered standing floor.
use super::*;

/// A trusted host installs the live run snapshot; the request never carries
/// grant, class or budget values. Exercise the actual HTTP context assembly.
#[tokio::test]
async fn host_bound_self_brief_opens_updates_tail_and_folds_prefix() {
    use oneiron::context_board::{
        BriefClassSource, BriefClassVerdict, BriefClassVerdicts, BriefDefaultRule,
        BriefWorkingSet, CommunicationLimits, SelfBriefState,
    };
    use oneiron::llm::{BudgetExhaustionPolicy, BudgetRead};
    use oneiron::memory::CanEffectVerdict;
    let (_dir, server) = test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".into()),
        ..Default::default()
    });
    let actor = seeded_test_entity_id(0x2631_0001);
    server
        .vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .unwrap();
    let world = seeded_test_entity_id(0x2631_0002);
    server
        .vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    server
        .vault
        .open_standing_block(&owner, actor, world, "identity", 64)
        .unwrap();
    // The brief's shapes since 4094ec063a6 (#6647, FIX 17594, Engine ruling
    // 21:47): no cast, grant revision, scope or message count; a class line
    // is a dated per-class verdict; a field no host produced is None.
    let mut state = SelfBriefState {
        self_ref: actor,
        principal: Some(actor),
        grants: None,
        run_ceiling: None,
        credential_ceiling: None,
        parent_ceiling: None,
        communication: CommunicationLimits {
            reach: None,
            credential_ceiling: None,
        },
        ceilings: None,
        class_verdicts: Some(BriefClassVerdicts {
            as_of_secs: 1,
            policy_frontier: "0".repeat(64),
            verdicts: vec![BriefClassVerdict {
                class: "send".into(),
                source: BriefClassSource::Default {
                    rule: BriefDefaultRule::DestructiveOutboundOrCritical,
                },
                inside: CanEffectVerdict::WouldAsk,
                reasons: vec![],
                holds: vec![],
                outside: None,
                per_act: vec![],
            }],
        }),
        budget_lease_id: Some("lease".into()),
        budget: Some(BudgetRead {
            attempt_id: "run".into(),
            limit_units: 100,
            cap_units: 100,
            used_units: 20,
            reserved_units: 10,
            remaining_units: 70,
            on_budget_exhausted: BudgetExhaustionPolicy::Suspend,
            fired_thresholds: vec![],
        }),
        clock_ms: 123,
        skill_index: vec![],
        working_set: BriefWorkingSet {
            scratchpad: Some(vec![]),
            pins: Some(vec![]),
            replay: Some(vec![]),
        },
    };
    server
        .install_self_brief_session(actor, "brief-session".into(), 1, state.clone())
        .await
        .unwrap();
    let with_budget = |describe_self, token_budget| {
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                actor.to_hex()
            )),
            Some(&json!({"session":{"session_id":"brief-session"},
                "standing":{"world_ref":world.to_hex(),"token_budget":token_budget},
                "describe_self":describe_self})),
        )
    };
    let request = |describe_self| with_budget(describe_self, 65_536);
    let (status, rejected_open) = route_json(server.clone(), with_budget(false, 64)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected_open}");
    let (status, open) = route_json(server.clone(), request(false)).await;
    assert_eq!(status, StatusCode::OK, "{open}");
    let cached = open["self_brief"]["prefix"].as_str().unwrap().to_owned();
    assert!(cached.contains("\"remaining_units\":70"));
    assert!(cached.contains("\"would_ask\""));
    let budget = state.budget.as_mut().expect("budget");
    budget.remaining_units = 20;
    budget.reserved_units = 15;
    state.class_verdicts.as_mut().expect("class verdicts").verdicts[0].inside =
        CanEffectVerdict::Deny;
    server
        .install_self_brief_session(actor, "brief-session".into(), 1, state.clone())
        .await
        .unwrap();
    let (status, mid) = route_json(server.clone(), request(true)).await;
    assert_eq!(status, StatusCode::OK, "{mid}");
    assert!(mid["self_brief"]["prefix"].is_null());
    let tail = mid["self_brief"]["tail"].as_str().unwrap();
    assert!(tail.contains("\"remaining_units\":20"));
    assert!(tail.contains("\"deny\""));
    let (status, stable) = route_json(server.clone(), request(false)).await;
    assert_eq!(status, StatusCode::OK, "{stable}");
    assert!(
        stable.get("self_brief").is_none(),
        "no prefix rewrite mid-epoch"
    );
    assert_ne!(tail, cached);
    let (status, described) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/facade/describe",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                actor.to_hex()
            )),
            Some(&json!({"self":true,"session_id":"brief-session"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{described}");
    assert_eq!(described["kind"], "self_card");
    assert_eq!(described["tail"].as_str(), Some(tail));
    let decoded: oneiron::task_verb::TaskDescription = serde_json::from_value(described).unwrap();
    assert_eq!(
        decoded,
        oneiron::task_verb::TaskDescription::SelfCard {
            tail: tail.to_owned()
        }
    );

    // The shipped SDK must decode the *live* authenticated facade response,
    // not merely the route's raw JSON. Bind a real holder key and socket.
    let (slip, holder) = crate::test_credentials::credential(
        &server,
        &format!(
            "scope=core:read;principal_ref={};actor_class=agent",
            actor.to_hex()
        ),
    );
    let credential = format!(
        "v2.cred.{}.{}",
        slip.to_token().unwrap().strip_prefix("v2.slip.").unwrap(),
        holder
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let host = server.clone();
    let serving =
        tokio::spawn(async move { axum::serve(listener, crate::build_app(host)).await.unwrap() });
    let result = tokio::task::spawn_blocking(move || {
        let client = oneiron_remote::OneironClient::connect(&url, &credential).unwrap();
        client.agent_verb(
            "describe",
            json!({"self":true,"session_id":"brief-session"}),
        )
    })
    .await
    .unwrap()
    .unwrap();
    serving.abort();
    let sdk_card: oneiron::task_verb::TaskDescription = serde_json::from_value(result).unwrap();
    assert_eq!(
        sdk_card,
        oneiron::task_verb::TaskDescription::SelfCard {
            tail: tail.to_owned()
        }
    );
    server
        .install_self_brief_session(actor, "brief-session".into(), 2, state)
        .await
        .unwrap();
    let (status, rejected_fold) = route_json(server.clone(), with_budget(false, 64)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected_fold}");
    let (status, folded) = route_json(server.clone(), request(false)).await;
    assert_eq!(status, StatusCode::OK, "{folded}");
    assert_eq!(folded["self_brief"]["prefix"].as_str(), Some(tail));
    assert!(folded["self_brief"]["tail"].is_null());
}

async fn register_agent_connector(
    server: &Arc<SyncServer>,
    label: &str,
    actor: oneiron::EntityId,
    slip_scope: &crate::mcp::McpConnectorScope,
    registered: crate::mcp::McpConnectorScope,
    records: Option<std::collections::BTreeSet<String>>,
) {
    let mut token = pair_mcp_credential(
        server,
        label,
        actor,
        oneiron::EdgeActorClass::Agent,
        slip_scope,
    );
    if records.is_some() {
        token = attenuate_mcp_credential(
            server,
            label,
            oneiron::authority::SlipCaveat {
                records,
                ..Default::default()
            },
        );
    }
    server
        .mcp_registry
        .lock()
        .await
        .register(
            &token,
            crate::mcp::McpConnectorActorRecord::new(
                actor,
                oneiron::EdgeActorClass::Agent,
                registered,
            ),
        )
        .expect("register agent connector");
}

/// MCP `describe(self)` renders the whole run brief, so every ceiling on the
/// calling credential applies before rendering. Narrowed world, facet and
/// record credentials, and a broad credential under a narrower registration,
/// are refused without naming the hidden world; their filtered task list is not.
#[tokio::test]
async fn mcp_describe_self_refuses_every_narrowed_ceiling() {
    use crate::mcp::McpConnectorScope;
    use oneiron::context_board::{
        BriefCredentialCeiling, BriefWorkingSet, CommunicationLimits, SelfBriefState,
    };
    use oneiron::federation::{Scope, ScopeAxis, ScopeId};
    use oneiron::llm::{BudgetExhaustionPolicy, BudgetRead};
    let (_dir, server) = auth_test_server();
    // The seeded manifest's agent ceiling names the first-party connector actor.
    let actor = oneiron::EntityId::from_bytes([0xE1; 16]).unwrap();
    server
        .vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .unwrap();
    let world_a = seeded_test_entity_id(0x2631_0101);
    let hidden_world = seeded_test_entity_id(0x2631_0102);
    let facet_a = seeded_test_entity_id(0x2631_0103);
    let mut effective_scope = Scope::top();
    effective_scope.worlds =
        ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(hidden_world)]));
    server
        .install_self_brief_session(
            actor,
            "wide-run".into(),
            1,
            // The run's scope rides the brief's credential ceiling since
            // 4094ec063a6 (#6647, FIX 17594): the effective scope is gone.
            SelfBriefState {
                self_ref: actor,
                principal: Some(actor),
                grants: None,
                run_ceiling: None,
                credential_ceiling: Some(BriefCredentialCeiling {
                    scope: effective_scope,
                    records: std::collections::BTreeSet::new(),
                    channels: std::collections::BTreeSet::new(),
                    read_scope: None,
                    connector: None,
                }),
                parent_ceiling: None,
                communication: CommunicationLimits {
                    reach: None,
                    credential_ceiling: None,
                },
                ceilings: None,
                class_verdicts: None,
                budget_lease_id: Some("lease".into()),
                budget: Some(BudgetRead {
                    attempt_id: "run".into(),
                    limit_units: 10,
                    cap_units: 10,
                    used_units: 0,
                    reserved_units: 0,
                    remaining_units: 10,
                    on_budget_exhausted: BudgetExhaustionPolicy::Suspend,
                    fired_thresholds: vec![],
                }),
                clock_ms: 1,
                skill_index: vec![],
                working_set: BriefWorkingSet {
                    scratchpad: Some(vec![]),
                    pins: Some(vec![]),
                    replay: Some(vec![]),
                },
            },
        )
        .await
        .unwrap();
    // The run opens in the hidden world, so turn one has rendered its prefix.
    server
        .vault
        .put_entity(
            &hidden_world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"world",
        )
        .unwrap();
    let owner_ref = server.vault.ensure_embedded_owner_actor().unwrap();
    let owner = server
        .vault
        .authenticate_owner(
            owner_ref,
            &owner_ref.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .unwrap();
    server
        .vault
        .open_standing_block(&owner, actor, hidden_world, "identity", 64)
        .unwrap();
    let (status, open) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-board",
            test_bearer(&format!(
                "scope=core:read;principal_ref={};actor_class=agent",
                actor.to_hex()
            )),
            Some(&json!({"session":{"session_id":"wide-run"},
                "standing":{"world_ref":hidden_world.to_hex(),"token_budget":65_536}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{open}");
    let envelope = |scope: &McpConnectorScope| {
        let mut envelope = mcp_scoped_envelope(actor, "read_tasks", scope);
        envelope["actor"]["actor_class"] = json!("agent");
        envelope["actor"]["gate_actor_class"] = json!("agent");
        envelope
    };
    let describe_self = |label: &str, scope: &McpConnectorScope| {
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            label,
            label,
            "describe",
            mcp_merge_args(
                envelope(scope),
                json!({"arguments": {"self": true, "session_id": "wide-run"}}),
            ),
        )
    };
    let hidden = hidden_world.to_hex();

    let wide = McpConnectorScope::vault_wide();
    register_agent_connector(&server, "brief-wide", actor, &wide, wide.clone(), None).await;
    let (status, body) = route_json(server.clone(), describe_self("brief-wide", &wide)).await;
    assert_eq!(status, StatusCode::OK);
    let output = &body["result"]["structuredContent"]["output"];
    assert_eq!(output["kind"], "self_card", "{body}");
    assert!(output["tail"].as_str().unwrap().contains(&hidden), "{body}");

    let world_only = McpConnectorScope::scoped(Some(world_a), None);
    let facet_only = McpConnectorScope::scoped(None, Some(facet_a));
    let records = Some(std::collections::BTreeSet::from([actor.to_hex()]));
    for (label, slip_scope, registered, records, code) in [
        (
            "brief-world",
            &world_only,
            &world_only,
            None,
            "mcp_scope_refused",
        ),
        (
            "brief-facet",
            &facet_only,
            &facet_only,
            None,
            "mcp_scope_refused",
        ),
        (
            "brief-record",
            &wide,
            &wide,
            records,
            "mcp_scope_unprojectable",
        ),
        (
            "brief-wide-slip-world",
            &wide,
            &world_only,
            None,
            "mcp_scope_refused",
        ),
        (
            "brief-wide-slip-facet",
            &wide,
            &facet_only,
            None,
            "mcp_scope_refused",
        ),
    ] {
        register_agent_connector(
            &server,
            label,
            actor,
            slip_scope,
            registered.clone(),
            records,
        )
        .await;
        let refused = mcp_refusal(&server, describe_self(label, registered)).await;
        assert_mcp_structured_error(&refused, code);
        assert!(!refused.to_string().contains(&hidden), "{label}: {refused}");
        let (status, listed) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                label,
                label,
                "describe",
                envelope(registered),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            listed["result"]["structuredContent"]["output"]["kind"], "tasks_section",
            "{label}: {listed}"
        );
    }
}
