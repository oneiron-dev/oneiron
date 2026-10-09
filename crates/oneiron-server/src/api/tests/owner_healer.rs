//! `/v1/owner` safety and repair: the owner rotates a secret (ARCH-0069 S6),
//! reads the three signed healer oversight receipts the host emits, and
//! reviews the custom-agent dispatches the failure ladder ended (ARCH-0066).
use super::owner_routes::{call, owner_recipe, refused_recipes};
use super::*;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent, HealerSlot,
};
use oneiron::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptResultRef, ClaimAttempt, ClaimOutcome,
    InterveneAttempt, SetAttemptResult,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::failure_ladder::{
    FailureEscalationMode, FailureLadderOutcome, FailureScope, FailureScopePolicy,
    FailureSignalClass, HandleAttemptFailure, TypedFailureEvidence, TypedFailureVerdict,
};
use oneiron::secret_custody::{CustodyTier, SecretBinding};
use oneiron::{DreamerRunnerStore, TimeRange};

#[tokio::test]
async fn owner_rotates_a_secret_and_nobody_else_can() {
    let (_dir, server) = auth_test_server();
    let binding = SecretBinding {
        effector: "deploy".to_owned(),
        tier_ceiling: CustodyTier::T1Leased,
        scopes: vec!["read".to_owned()],
    };
    let id = server
        .vault()
        .register_test_secret("deploy-token", b"first value", vec![binding], 1)
        .unwrap();
    let new_value = "c2Vjb25kIHZhbHVl"; // "second value"
    let body = json!({ "name": "deploy-token", "value_base64": new_value });

    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "POST",
            "/v1/owner/secrets/rotate",
            recipe,
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let generation = |server: &SyncServer| {
        server
            .vault()
            .get_secret_metadata(&id)
            .unwrap()
            .unwrap()
            .rotation_generation
    };
    assert_eq!(generation(&server), 0);

    let owner = owner_recipe(&server);
    let (status, rotated) = call(
        &server,
        "POST",
        "/v1/owner/secrets/rotate",
        owner.clone(),
        Some(&body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(rotated["name"], "deploy-token");
    assert_eq!(rotated["from_generation"], 0);
    assert_eq!(rotated["to_generation"], 1);
    // The receipt says the value moved, never what it moved to.
    let reply = rotated.to_string();
    assert!(!reply.contains(new_value) && !reply.contains("second value"));
    assert_eq!(generation(&server), 1);
    // The refused callers' bodies were never read; the owner's frame and the
    // buffer it was copied into were both wiped.
    assert_eq!(
        crate::owner::secrets::wiped::count(body.to_string().as_bytes()),
        2
    );

    let (status, _) = call(
        &server,
        "POST",
        "/v1/owner/secrets/rotate",
        owner,
        Some(&json!({ "name": "no-such-secret", "value_base64": new_value })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(generation(&server), 1);
}

/// A body the parser refuses inside the value (Astra on #1339). The literal
/// backslash makes the escape fail after the parser has passed the whole
/// recoverable encoding. Read through `Json`, that encoding was left in the
/// extractor's body copy and in the parser's scratch, both freed unwiped.
#[tokio::test]
async fn a_rotation_refused_inside_the_value_wipes_the_body_that_carried_it() {
    let (_dir, server) = auth_test_server();
    let body: &[u8] = br#"{"name":"deploy-token","value_base64":"c2VjcmV0\uZZZZ"}"#;
    let request = Request::builder()
        .method("POST")
        .uri("/v1/owner/secrets/rotate")
        .header(AUTHORIZATION, owner_recipe(&server))
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_vec()))
        .unwrap();
    let (status, reply) = route_json(server.clone(), request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{reply}");
    assert!(!reply.to_string().contains("c2VjcmV0"), "{reply}");
    // The frame the body handed over and the one buffer it was copied into;
    // the parser borrowed from the second and copied nothing.
    assert_eq!(crate::owner::secrets::wiped::count(body), 2);
}

#[tokio::test]
async fn host_emits_signed_oversight_receipts_the_owner_reads() {
    let (_dir, server) = auth_test_server();
    let owner = owner_recipe(&server);
    let (status, before) = call(
        &server,
        "GET",
        "/v1/owner/healer/oversight",
        owner.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert_eq!(before, json!([]));

    // The same call the serve loop's cadence makes.
    server.emit_healer_oversight_once().unwrap();
    for recipe in refused_recipes(&server) {
        let (status, _) = call(&server, "GET", "/v1/owner/healer/oversight", recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let (status, receipts) = call(&server, "GET", "/v1/owner/healer/oversight", owner, None).await;
    assert_eq!(status, StatusCode::OK, "{receipts}");
    let receipts = receipts.as_array().unwrap();
    let kinds: Vec<_> = receipts.iter().map(|r| r["kind"].clone()).collect();
    assert_eq!(
        kinds,
        vec![
            json!("coverage"),
            json!("review_latency"),
            json!("escalation_rate")
        ]
    );
    for receipt in receipts {
        assert_eq!(receipt["verified"], true, "{receipt}");
        // Empty denominators stay explicit counts, never a NaN rate.
        assert_eq!(receipt["proposed"], 0);
        assert_eq!(receipt["reviewed"], 0);
    }
}

/// A custom AGENT_DEF the ladder's scope can bind to.
fn custom_agent(server: &SyncServer) -> oneiron::EntityId {
    let id = oneiron::EntityId::now();
    let definition = AgentDefinition::new(
        "custom.reviewed",
        "Failure review fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("fixture"),
            rmpv::Value::from("custom.reviewed"),
        )]),
        None,
        true,
        None,
    );
    let now = server.vault().now_recorded_at();
    server
        .vault()
        .put_agent_definition(
            &id,
            &definition,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .unwrap();
    id
}

#[tokio::test]
async fn owner_reviews_a_custom_agent_failure_the_ladder_ended() {
    const WORKER: &str = "owner-review-worker";
    let (_dir, server) = auth_test_server();
    let vault = server.vault();
    let agent = custom_agent(&server);
    let AgentDispatchOutcome::Dispatched(dispatched) = AgentDispatcher::new(vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            // No run id, so no run-tree read reaches this attempt: the drill
            // has to carry its evidence itself.
            run_id: None,
            now: 10,
        })
        .unwrap()
    else {
        panic!("expected a fresh dispatch");
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault)
        .claim(ClaimAttempt {
            lease_owner: WORKER.to_owned(),
            now: 11,
        })
        .unwrap()
    else {
        panic!("expected a claim");
    };
    assert_eq!(leased.id, dispatched.attempt.id);
    // An operator note on the live try, then the output it made durable before
    // it failed.
    AttemptQueue::new(vault)
        .intervene(InterveneAttempt {
            id: leased.id,
            kind: AttemptInterventionKind::Interrupt,
            actor: "operator".to_owned(),
            note: Some("stalled on the deploy step".to_owned()),
            now: 11,
        })
        .unwrap();
    AttemptQueue::new(vault)
        .set_result(SetAttemptResult {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            result_ref: AttemptResultRef::new("artifact:owner-review-output@1").unwrap(),
            now: 11,
        })
        .unwrap();

    // The door a host's failed step goes through: the typed failure ladder.
    let outcome = DreamerRunnerStore::new(vault)
        .fail_agent_dispatch_with_evidence(
            HandleAttemptFailure {
                attempt_id: leased.id,
                lease_owner: WORKER.to_owned(),
                attempt_count: leased.attempt_count,
                evidence: TypedFailureEvidence {
                    evidence_ref: None,
                    verdict: TypedFailureVerdict::Indeterminate,
                    tier: None,
                    stable_reason: "step_failed".to_owned(),
                },
                blocked_reports: Vec::new(),
                pre_fail_checkpoint_ref: agent,
                qa_thread_ref: agent,
                retry_at: 20,
                now: 12,
            },
            FailureScopePolicy {
                scope: FailureScope {
                    agent_ref: agent.to_hex(),
                    skill_ref: None,
                },
                max_consecutive_transients: std::num::NonZeroU16::MIN,
                escalation_mode: FailureEscalationMode::Human,
                healer_slot: HealerSlot::Reserved,
            },
        )
        .unwrap();
    assert!(matches!(outcome, FailureLadderOutcome::Human(_)));
    vault
        .record_custom_agent_failure(leased.id, FailureSignalClass::TaskFailure)
        .unwrap();

    let attempt = crate::owner::healer::attempt_hex(&leased.id);
    let drill_path =
        format!("/v1/owner/healer/failures/drill?class=task_failure&attempt={attempt}");
    for recipe in refused_recipes(&server) {
        let (status, _) = call(
            &server,
            "GET",
            "/v1/owner/healer/failures",
            recipe.clone(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(&server, "GET", &drill_path, recipe, None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let owner = owner_recipe(&server);
    let (status, groups) = call(
        &server,
        "GET",
        "/v1/owner/healer/failures",
        owner.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{groups}");
    assert_eq!(
        groups,
        json!([{ "class": "task_failure", "count": 1, "attempts": [attempt.clone()] }])
    );

    let (status, drill) = call(&server, "GET", &drill_path, owner.clone(), None).await;
    assert_eq!(status, StatusCode::OK, "{drill}");
    assert_eq!(drill["attempt"], attempt);
    assert_eq!(drill["state"], "Failed");
    assert_eq!(drill["last_error"], "step_failed");
    // The stored evidence, as stored.
    assert_eq!(drill["result_ref"], "artifact:owner-review-output@1");
    assert_eq!(
        drill["events"],
        json!([{
            "sequence": 1,
            "at": 11,
            "actor": "operator",
            "kind": "interrupt",
            "note": "stalled on the deploy step",
        }])
    );

    // A member is only reachable under the class it is listed in.
    let (status, _) = call(
        &server,
        "GET",
        &format!("/v1/owner/healer/failures/drill?class=memory_miss&attempt={attempt}"),
        owner,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
