//! Legacy MCP adapter read/edit/ask verbs, actor-scoped idempotency, spoof rejection, stale-edit/attest successor refs.

use super::*;

#[tokio::test]
async fn mcp_edit_idempotency_is_actor_scoped_and_replays_without_mutation() {
    let (_dir, server) = auth_test_server();
    let actor_a = seeded_test_entity_id(0x1222_0601);
    let actor_b = seeded_test_entity_id(0x1222_0602);
    let credential_a = "one-1222-idem-a";
    let credential_b = "one-1222-idem-b";
    register_mcp_actor(
        &server,
        credential_a,
        actor_a,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    register_mcp_actor(
        &server,
        credential_b,
        actor_b,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0603);
    server
        .vault
        .put_entity(
            &subject_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange {
                start: 600,
                end: 600,
            },
            600,
            b"MCP idempotency subject",
        )
        .expect("seed MCP idempotency subject");

    let shared_key = "one-1222-shared-idempotency-key";
    let (status, first) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_a,
            "mcp-write-idem-a-1",
            "oneiron.edit",
            mcp_propose_claim_args(actor_a, subject_ref, shared_key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        first.get("error").is_none(),
        "unexpected MCP error: {first:?}"
    );
    let first_id = oneiron::EntityId::from_hex(
        first["result"]["structuredContent"]["id"]
            .as_str()
            .expect("first MCP id"),
    )
    .expect("first MCP id parses");

    let mut replay_args = mcp_propose_claim_args(actor_a, subject_ref, shared_key);
    replay_args["value"] = Value::from("changed replay payload");
    let (status, replay) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_a,
            "mcp-write-idem-a-2",
            "oneiron.edit",
            replay_args,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        replay.get("error").is_none(),
        "unexpected MCP error: {replay:?}"
    );
    assert_eq!(
        replay["result"]["structuredContent"]["status"],
        Value::from("replayed")
    );
    assert_eq!(
        replay["result"]["structuredContent"]["id"],
        Value::from(first_id.to_hex())
    );

    let (status, second_actor) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential_b,
            "mcp-write-idem-b",
            "oneiron.edit",
            mcp_propose_claim_args(actor_b, subject_ref, shared_key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        second_actor.get("error").is_none(),
        "unexpected MCP error: {second_actor:?}"
    );
    let second_actor_id = oneiron::EntityId::from_hex(
        second_actor["result"]["structuredContent"]["id"]
            .as_str()
            .expect("second actor MCP id"),
    )
    .expect("second actor MCP id parses");
    assert_ne!(
        first_id, second_actor_id,
        "same idempotency key must be scoped by the resolved actor"
    );

    let decisions = server
        .vault
        .gate_decisions(10)
        .expect("gate decisions after idempotency replay");
    assert_eq!(
        decisions.len(),
        2,
        "same-actor replay must not emit a second Gate decision"
    );
}

#[tokio::test]
async fn mcp_edit_rejects_source_approval_spoofing_without_partial_mutation() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0201);
    let credential = "one-1222-denied-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject_ref = seeded_test_entity_id(0x1222_0202);
    server
        .vault
        .put_entity(
            &subject_ref,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange {
                start: 300,
                end: 300,
            },
            300,
            b"MCP denied subject",
        )
        .expect("seed MCP denied subject");

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-write-denied",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "propose_claim",
                "idempotency_key": "one-1222-spoof-source-approval",
                "subject": { "entity": subject_ref.to_hex() },
                "predicate": "profile.mcp_gateway",
                "value": "MCP gateway write",
                "confidence": 0.8,
                "source": "generated",
                "approval": "auto"
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["error"]["code"], Value::from(-32602));
    assert_eq!(
        body["error"]["data"]["kind"],
        Value::from("tool_args_invalid")
    );

    let decisions = server
        .vault
        .gate_decisions(10)
        .expect("gate decisions after rejected MCP write");
    assert!(
        decisions.is_empty(),
        "schema-rejected MCP write must not emit a Gate decision"
    );
}

#[tokio::test]
async fn mcp_malformed_call_returns_stable_json_rpc_error() {
    let (_dir, server) = auth_test_server();
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{"))
        .expect("malformed MCP request");

    let (status, body) = route_json(server, request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["jsonrpc"], Value::from("2.0"));
    assert_eq!(body["id"], Value::Null);
    assert_eq!(body["error"]["code"], Value::from(-32700));
    assert_eq!(body["error"]["data"]["kind"], Value::from("parse_error"));
}

#[tokio::test]
async fn mcp_stale_edit_rejected_before_proposal() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1936_0101);
    let credential = "one-1936-stale-edit-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let subject = seeded_test_entity_id(0x1936_0102);
    let old = seeded_test_entity_id(0x1936_0103);
    let new = seeded_test_entity_id(0x1936_0104);
    seed_superseded_claim_pair(&server, subject, old, new);
    // The seeding supersession itself emits gate decisions; the guard's
    // evidence is that NOTHING is added on top of this baseline.
    let baseline_decisions = server
        .vault
        .gate_decisions(100)
        .expect("baseline gate decisions")
        .len();

    let supersede_args = |dry_run: bool| {
        json!({
            "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": mcp_actor_json(actor_ref, "human"),
            "consent": mcp_consent_json("write_memory", false),
            "verb": "supersede_claim",
            "idempotency_key": "one-1936-stale-supersede",
            "dry_run": dry_run,
            "old_claim_id": old.to_hex(),
            "predicate": "profile.route_test",
            "value": "later",
            "confidence": 0.8,
            "reason": "user_correction"
        })
    };

    // supersede_claim: typed kind + the successor as DATA, not prose.
    let error = mcp_edit_error(&server, credential, supersede_args(false)).await;
    assert_eq!(error["code"], Value::from(-32020), "{error:#}");
    assert_eq!(
        error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    let head_ref = error["data"]["successor_short_id"]
        .as_str()
        .expect("successor travels as typed data, not prose")
        .to_owned();
    assert_eq!(
        resolve_short_ref(&server, &head_ref),
        new,
        "the reported ref must resolve to the current head"
    );
    assert_ne!(head_ref, new.to_hex(), "never a hex fallback");

    // Dry run reports the SAME condition — it never green-lights an edit the
    // real call will refuse.
    let dry_error = mcp_edit_error(&server, credential, supersede_args(true)).await;
    assert_eq!(
        dry_error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    assert_eq!(
        dry_error["data"]["successor_short_id"],
        Value::from(head_ref.clone())
    );
    assert_eq!(
        server
            .vault
            .gate_decisions(100)
            .expect("gate decisions")
            .len(),
        baseline_decisions,
        "a dry run must report without writing"
    );

    // retract_claim maps its target from `claim_id`, and refuses the same way.
    let error = mcp_edit_error(
        &server,
        credential,
        json!({
            "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
            "actor": mcp_actor_json(actor_ref, "human"),
            "consent": mcp_consent_json("write_memory", false),
            "verb": "retract_claim",
            "idempotency_key": "one-1936-stale-retract",
            "claim_id": old.to_hex(),
            "reason": "user_retraction"
        }),
    )
    .await;
    assert_eq!(
        error["data"]["kind"],
        Value::from("write_verb_target_stale")
    );
    assert_eq!(error["data"]["successor_short_id"], Value::from(head_ref));

    // Nothing committed: no proposal Claim, so no Gate decision, and the
    // targets are exactly as the refusal found them.
    assert_eq!(
        server
            .vault
            .gate_decisions(100)
            .expect("gate decisions")
            .len(),
        baseline_decisions,
        "a stale-target edit must not emit a Gate decision"
    );
    assert_eq!(
        server
            .vault
            .get_claim(&old)
            .expect("read old")
            .expect("old claim")
            .lifecycle,
        oneiron::ClaimLifecycleStatus::Superseded
    );
    assert_eq!(
        server
            .vault
            .get_claim(&new)
            .expect("read new")
            .expect("new claim")
            .lifecycle,
        oneiron::ClaimLifecycleStatus::Active,
        "the verb must never be applied to the successor"
    );

    // …and no idempotency row committed either: re-issuing the SAME
    // idempotency key against the live head proposes fresh rather than
    // replaying a phantom.
    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-stale-edit-retry",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "supersede_claim",
                "idempotency_key": "one-1936-stale-supersede",
                "old_claim_id": new.to_hex(),
                "predicate": "profile.route_test",
                "value": "later",
                "confidence": 0.8,
                "reason": "user_correction"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["result"]["structuredContent"]["status"],
        Value::from("proposed"),
        "a refused edit must leave no idempotency row behind: {body:#}"
    );
}

#[tokio::test]
async fn mcp_stale_attest_returns_current_provenance_head() {
    let (_dir, server) = auth_test_server();
    let actor_ref = seeded_test_entity_id(0x1936_0201);
    let credential = "one-1936-stale-attest-credential";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    let source = seeded_test_entity_id(0x1936_0202);
    let target = seeded_test_entity_id(0x1936_0203);
    for id in [source, target] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::TimeRange { start: 1, end: 1 },
                1,
                b"attest fixture",
            )
            .expect("seed entity");
    }
    server
        .vault
        .put_edge(&source, oneiron::EdgeKind::Mentions, &target, 0.5)
        .expect("seed semantic edge");

    let subject = oneiron::provenance::EdgeRef::new(source, oneiron::EdgeKind::Mentions, target);
    let prior = seeded_test_entity_id(0x1936_0204);
    let winner = seeded_test_entity_id(0x1936_0205);
    server
        .vault
        .put_edge_provenance(
            &prior,
            &subject,
            &oneiron::provenance::EdgeProvenanceClaimBody::new(
                actor_ref,
                0.5,
                oneiron::provenance::SupersessionStatus::Proposed,
            ),
            oneiron::EdgeActorClass::Human,
            100,
        )
        .expect("seed prior attestation");
    server
        .vault
        .supersede_edge_provenance(
            &prior,
            &winner,
            &subject,
            &oneiron::provenance::EdgeProvenanceClaimBody::new(
                actor_ref,
                0.9,
                oneiron::provenance::SupersessionStatus::Confirmed,
            ),
            oneiron::EdgeActorClass::Human,
            200,
        )
        .expect("supersede the prior attestation");

    let (status, body) = mcp_legacy_adapter_json(
        server.clone(),
        mcp_call_request(
            credential,
            "mcp-stale-attest",
            "oneiron.edit",
            json!({
                "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
                "actor": mcp_actor_json(actor_ref, "human"),
                "consent": mcp_consent_json("write_memory", false),
                "verb": "attest_edge_provenance",
                "idempotency_key": "one-1936-stale-attest",
                "subject": {
                    "edge": {
                        "source": source.to_hex(),
                        "kind": oneiron::EdgeKind::Mentions as u8,
                        "target": target.to_hex()
                    }
                },
                "old_claim_id": prior.to_hex(),
                "confidence": 0.8
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["error"]["data"]["kind"],
        Value::from("write_verb_target_stale"),
        "{body:#}"
    );
    // The head comes from the D14 COHORT winner, not from an invented
    // provenance Supersedes edge.
    let head_ref = body["error"]["data"]["successor_short_id"]
        .as_str()
        .expect("successor travels as typed data");
    assert_eq!(resolve_short_ref(&server, head_ref), winner);
}
