//! Memory tool projections exercise the same scoped reads as native clients.
use super::*;

#[tokio::test]
async fn mcp_memory_reads_use_native_clamps_and_keep_runtime_refusals_typed() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0x0024_8601);
    let visible = seeded_test_entity_id(0x0024_8602);
    let hidden = seeded_test_entity_id(0x0024_8603);
    let missing = seeded_test_entity_id(0x0024_8604);
    let credential = "memory-read-wide";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    let occurred = oneiron::TimeRange { start: 10, end: 10 };
    for (id, approval) in [
        (visible, oneiron::ClaimApprovalStatus::Auto),
        (hidden, oneiron::ClaimApprovalStatus::Proposed),
    ] {
        let mut claim = oneiron::ClaimBody::new(
            "profile.note",
            oneiron::ClaimSubject::Entity(actor),
            rmpv::Value::from("wirememoryneedle"),
            1.0,
            approval,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap();
        claim.source = Some(oneiron::ClaimSource::UserStated);
        server.vault.put_claim(&id, &claim, occurred, 10).unwrap();
        server
            .vault
            .batch()
            .text(&id, &[("body", "wirememoryneedle")])
            .commit()
            .unwrap();
    }
    let args = |request| {
        mcp_merge_args(
            mcp_endpoint_envelope(actor, "memory_read"),
            json!({"arguments": {"request": request}}),
        )
    };
    let (_, query) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "memory-query",
            "memory.query",
            args(json!({"query": "wirememoryneedle", "view": "full", "limit": 10})),
        ),
    )
    .await;
    assert!(query.get("error").is_none(), "{query:?}");
    let response = &query["result"]["structuredContent"]["output"]["response"];
    assert_eq!(response["items"].as_array().unwrap().len(), 1);
    assert_eq!(response["items"][0]["id"], visible.to_hex());
    assert_eq!(response["meta"]["countMode"], "estimate");
    for id in [visible, hidden, missing] {
        let (_, reply) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                "memory-timeline",
                "memory.memory_timeline",
                args(json!({"id": id.to_hex()})),
            ),
        )
        .await;
        if id == visible {
            assert_eq!(
                reply["result"]["structuredContent"]["output"]["response"]["anchor_id"],
                visible.to_hex()
            );
        } else {
            assert_mcp_structured_error(&reply, "entity_not_found");
            assert_eq!(
                reply["error"]["data"]["vault_read"]["engine_code"],
                "NOT_FOUND"
            );
        }
    }
    let (_, ask) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            "memory-ask",
            "memory.ask",
            args(Value::Null),
        ),
    )
    .await;
    assert_mcp_structured_error(&ask, "runtime_unavailable");
    assert_eq!(ask["error"]["data"]["vault_read"]["method"], "ask");

    // A credential's narrower ceiling is not the principal's broader grants.
    for (name, scope) in [
        (
            "memory-world",
            crate::mcp::McpConnectorScope::scoped(Some(missing), None),
        ),
        (
            "memory-facet",
            crate::mcp::McpConnectorScope::scoped(None, Some(missing)),
        ),
    ] {
        register_scoped_mcp_actor(&server, name, actor, scope.clone()).await;
        let (_, reply) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                name,
                "memory-narrow",
                "memory.query",
                mcp_merge_args(
                    mcp_scoped_envelope(actor, "memory_read", &scope),
                    json!({"arguments":{"request":{"query":"wirememoryneedle"}}}),
                ),
            ),
        )
        .await;
        assert_mcp_structured_error(&reply, "mcp_scope_refused");
    }
}
