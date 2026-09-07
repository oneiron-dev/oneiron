use super::*;

fn assert_tool_output_proposal_gate(
    vault: &oneiron::Vault,
    claim_id: oneiron::EntityId,
    expected_pending: bool,
) {
    let stored = vault
        .get_claim(&claim_id)
        .expect("read proposal")
        .expect("proposed claim must be stored");
    assert_eq!(stored.source, Some(oneiron::ClaimSource::ToolOutput));
    assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Proposed);

    let decisions = vault.gate_decisions(20).expect("read gate decisions");
    let decisions: Vec<_> = decisions
        .iter()
        .filter(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
        .collect();
    assert_eq!(decisions.len(), 1, "one preflight receipt per claim");
    let decision = decisions[0];
    let (outcome, reason) = if expected_pending {
        ("pending", "gate.pending.source_trust")
    } else {
        ("allow", "gate.allow")
    };
    assert_eq!(decision.outcome, outcome);
    assert_eq!(decision.reason_codes, vec![reason]);

    let pending = vault
        .pending_gate_consents(20)
        .expect("read pending consent");
    let pending: Vec<_> = pending
        .iter()
        .filter(|pending| pending.claim_id == *claim_id.as_bytes())
        .collect();
    if expected_pending {
        assert_eq!(pending.len(), 1, "apply must persist the pending proposal");
        assert_eq!(pending[0].decision_id, decision.decision_id);
        assert_eq!(pending[0].reason_codes, decision.reason_codes);
    } else {
        assert!(pending.is_empty(), "apply must agree with preflight allow");
    }
}

#[tokio::test]
async fn mcp_edit_propose_claim_unstamped_and_above_cap_stay_pending() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0901);
    let credential = "mcp-source-gate-pending";
    register_mcp_actor(
        &server,
        credential,
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;

    for (key, scope) in [
        ("mcp-source-unstamped", None),
        ("mcp-source-above-cap", Some(json!({ "sensitivity": 1 }))),
    ] {
        let mut args = mcp_propose_claim_args(actor_ref, actor_ref, key);
        if let Some(scope) = scope {
            args["scope"] = scope;
        }
        let (status, body) = mcp_legacy_adapter_json(
            server.clone(),
            mcp_call_request(credential, key, "oneiron.edit", args),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert!(
            body.get("error").is_none(),
            "unexpected MCP error: {body:?}"
        );
        assert_eq!(body["result"]["isError"], Value::Bool(false));
        assert_eq!(
            body["result"]["structuredContent"]["forced_source"],
            Value::from("tool_output")
        );
        assert_eq!(
            body["result"]["structuredContent"]["forced_approval"],
            Value::from("proposed")
        );
        let claim_id = oneiron::EntityId::from_hex(
            body["result"]["structuredContent"]["id"]
                .as_str()
                .expect("MCP proposed claim id"),
        )
        .expect("MCP proposed claim id parses");
        assert_tool_output_proposal_gate(&server.vault, claim_id, true);
    }
}

#[tokio::test]
async fn public_batch_lineage_source_gate_is_consistent() {
    let (_dir, server) = test_server();
    let actor_ref = seeded_test_entity_id(0x1222_0902);
    register_mcp_actor(
        &server,
        "batch-source-gate",
        actor_ref,
        oneiron::EdgeActorClass::Human,
    )
    .await;
    let envelope = oneiron::WriteEnvelope::new(
        oneiron::WriteActor::new(actor_ref, oneiron::EdgeActorClass::Human),
        oneiron::ClaimSource::ToolOutput,
        oneiron::WriteProvenance::new(rmpv::Value::from("source gate fixture"))
            .expect("write provenance"),
        oneiron::ClaimApprovalStatus::Proposed,
    );
    let occurred = oneiron::TimeRange {
        start: 200,
        end: 200,
    };
    let raw_claim_id = oneiron::EntityId::now();
    let above_cap_claim_id = oneiron::EntityId::now();
    let unstamped_claim_id = oneiron::EntityId::now();
    // Proposed raw puts cannot carry a source stamp. Keep a valid source-less
    // raw claim in the mixed batch and write the sourced proposal via its envelope.
    let raw_body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("pred"),
            rmpv::Value::from("profile.batch_source_gate"),
        ),
        (
            rmpv::Value::from("subj"),
            rmpv::Value::Binary(actor_ref.as_bytes().to_vec()),
        ),
        (
            rmpv::Value::from("val"),
            rmpv::Value::from("source-less raw proposal"),
        ),
        (rmpv::Value::from("conf"), rmpv::Value::F32(0.8)),
        (rmpv::Value::from("appr"), rmpv::Value::from("proposed")),
        (rmpv::Value::from("life"), rmpv::Value::from("active")),
        (
            rmpv::Value::from("scope"),
            oneiron::companion_value_from_json(&json!({ "sensitivity": 1 }))
                .expect("above-cap scope"),
        ),
    ]);
    let mut raw_data = Vec::new();
    rmpv::encode::write_value(&mut raw_data, &raw_body).expect("encode raw claim");

    // Lineage makes every ordinary public batch consult the source permit.
    // The public stamp stays within its band-0 cap, before and after a mixed batch.
    for mixed_batch in [false, true, false] {
        let claim_id = oneiron::EntityId::now();
        let candidate = oneiron::ClaimCandidate::new(
            "profile.batch_source_gate",
            oneiron::ClaimSubject::Entity(actor_ref),
            rmpv::Value::from("public proposal"),
            0.8,
        )
        .with_scope(
            oneiron::companion_value_from_json(&json!({ "sensitivity": "public" }))
                .expect("public scope"),
        );
        let mut batch = server.vault.batch();
        if mixed_batch {
            // Mix a valid raw put with public, above-cap and unstamped envelope writes.
            // Each preflight receipt must agree with its applied claim.
            let above_cap_candidate = oneiron::ClaimCandidate::new(
                "profile.batch_source_gate",
                oneiron::ClaimSubject::Entity(actor_ref),
                rmpv::Value::from("above-cap proposal"),
                0.8,
            )
            .with_scope(
                oneiron::companion_value_from_json(&json!({ "sensitivity": 1 }))
                    .expect("above-cap scope"),
            );
            let unstamped_candidate = oneiron::ClaimCandidate::new(
                "profile.batch_source_gate",
                oneiron::ClaimSubject::Entity(actor_ref),
                rmpv::Value::from("unstamped proposal"),
                0.8,
            );
            batch = batch
                .put(
                    &raw_claim_id,
                    oneiron::registry::ENTITY_TYPE_CLAIM,
                    occurred,
                    200,
                    &raw_data,
                )
                .claim_candidate(
                    &above_cap_claim_id,
                    above_cap_candidate,
                    &envelope,
                    occurred,
                    200,
                )
                .claim_candidate(
                    &unstamped_claim_id,
                    unstamped_candidate,
                    &envelope,
                    occurred,
                    200,
                );
        }
        batch
            .claim_candidate(&claim_id, candidate, &envelope, occurred, 200)
            .commit()
            .expect("store public proposal");
        assert_tool_output_proposal_gate(&server.vault, claim_id, false);
        if mixed_batch {
            assert_tool_output_proposal_gate(&server.vault, above_cap_claim_id, true);
            assert_tool_output_proposal_gate(&server.vault, unstamped_claim_id, true);
            let stored = server
                .vault
                .get_claim(&raw_claim_id)
                .expect("read raw proposal")
                .expect("raw proposal must be stored");
            assert_eq!(stored.source, None);
            assert_eq!(stored.approval, oneiron::ClaimApprovalStatus::Proposed);
            let decisions = server
                .vault
                .gate_decisions(20)
                .expect("read gate decisions");
            let decisions: Vec<_> = decisions
                .iter()
                .filter(|decision| decision.claim_id == Some(*raw_claim_id.as_bytes()))
                .collect();
            assert_eq!(
                decisions.len(),
                1,
                "one preflight receipt for the raw claim"
            );
            assert_eq!(decisions[0].outcome, "allow");
            assert_eq!(decisions[0].reason_codes, vec!["gate.allow"]);
            assert!(
                server
                    .vault
                    .pending_gate_consents(20)
                    .expect("read pending consent")
                    .iter()
                    .all(|pending| pending.claim_id != *raw_claim_id.as_bytes()),
                "raw apply must agree with preflight allow"
            );
        }
    }
}
