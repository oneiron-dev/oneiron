//! Search count-modes, context-pack budgets/response controls, text-search shape, snapshot/sort unit tests.

use super::*;

#[test]
fn search_response_rechecks_projected_claim_body() {
    #[derive(serde::Serialize)]
    struct ClaimSeed<'a> {
        pred: &'a str,
        val: &'a str,
        conf: f32,
        #[serde(with = "serde_bytes")]
        subj: &'a [u8],
        appr: &'static str,
        life: &'static str,
        #[serde(with = "serde_bytes", rename = "worldId")]
        world: &'a [u8],
        #[serde(rename = "scopeRelationshipId")]
        rel: &'a str,
        #[serde(with = "serde_bytes", rename = "scopeFacetId")]
        facet: &'a [u8],
        #[serde(with = "serde_bytes", rename = "scopeProjectId")]
        project: &'a [u8],
        #[serde(rename = "scopeVersion")]
        version: u64,
    }

    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let claim_id = seeded_test_entity_id(0x0012_6901);
    let subject = seeded_test_entity_id(0x0012_6902);
    let world = oneiron::claim::base_world_id();
    let facet = oneiron::claim::substrate_facet_id(subject).unwrap();
    let project = oneiron::claim::default_project_id();
    let body = rmp_serde::to_vec_named(&ClaimSeed {
        pred: "profile.projected",
        val: "hidden after update",
        conf: 0.9,
        subj: subject.as_bytes(),
        appr: "proposed",
        life: "active",
        world: world.as_bytes(),
        rel: "all",
        facet: facet.as_bytes(),
        project: project.as_bytes(),
        version: 2,
    })
    .expect("encode proposed claim");
    vault
        .put_entity(
            &claim_id,
            oneiron::registry::ENTITY_TYPE_CLAIM,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("seed proposed claim");

    let scoped_read = vault
        .scoped_read(oneiron::claim::ScopedReadActorKey::new("test-reader").expect("actor key"));
    let stale_hit = oneiron::ScoredEntity {
        id: claim_id,
        score: 0.75,
    };

    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped_read, vec![stale_hit], view, 10).unwrap();
        assert!(
            response.is_empty(),
            "{view:?} should re-check the exact projected body through ScopedRead"
        );
    }
}

#[tokio::test]
async fn context_pack_route_projects_json_response_controls() {
    let (_dir, server) = auth_test_server();
    let long_text = format!("projection budget needle {}", "x".repeat(800));
    let (batch_status, batch_body) = route_json_auth(
        server.clone(),
        json_request(
            "POST",
            "/v1/core/batch",
            json!({
                "entities": [{
                    "entity_type": ENTITY_TYPE_TURN,
                    "learned_at": 510_u64,
                    "occurred_start": 510_u64,
                    "occurred_end": 510_u64,
                    "body": {
                        "txt": long_text,
                        "spkr": "user",
                        "at": 510_u64,
                        "sess": "session-alpha",
                        "debug": "private"
                    },
                    "text": [{ "field": "body", "value": "projection budget needle" }]
                }]
            }),
        ),
    )
    .await;
    assert_eq!(batch_status, StatusCode::OK);
    let id = batch_body["entities"][0]["id"]
        .as_str()
        .expect("written id")
        .to_owned();

    let (summary_status, summary_body) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "summary" }
            })),
        ),
    )
    .await;
    assert_eq!(summary_status, StatusCode::OK);
    assert_eq!(summary_body["results"][0]["id"], Value::from(id.clone()));
    let fields = summary_body["results"][0]["fields"]
        .as_object()
        .expect("projected fields");
    assert!(fields.contains_key("txt"));
    assert!(!fields.contains_key("spkr"));
    assert!(!fields.contains_key("at"));
    assert!(!fields.contains_key("sess"));
    assert!(!fields.contains_key("debug"));

    let (budget_status, budget_body) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 96 }
            })),
        ),
    )
    .await;
    assert_eq!(budget_status, StatusCode::OK);
    assert_eq!(budget_body["results"][0]["id"], Value::from(id.clone()));
    let truncated = budget_body["results"][0]["fields"]["txt"]
        .as_str()
        .expect("truncated text field");
    assert!(!truncated.is_empty());
    assert!(truncated.len() < long_text.len());
    assert_eq!(
        budget_body["stats"]["items_truncated"]["count"],
        Value::from(1)
    );
    assert_eq!(
        budget_body["evidence"]["result_ids"],
        Value::Array(vec![Value::from(id.clone())])
    );

    let (token_budget_status, token_budget_body) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "tokenBudget": 16 }
            })),
        ),
    )
    .await;
    assert_eq!(token_budget_status, StatusCode::OK);
    assert_eq!(token_budget_body["results"], Value::Array(Vec::new()));
    assert_eq!(token_budget_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        token_budget_body["stats"]["items_dropped"]["reason"],
        Value::from("token_budget")
    );
    assert_eq!(
        token_budget_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert_eq!(
        token_budget_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(
        token_budget_body["evidence"]["scores"],
        Value::Array(Vec::new())
    );

    let (dropped_status, dropped_body) = route_json_auth(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/context-pack",
            owner_bearer(),
            Some(&json!({
                "query": "projection budget needle",
                "limit": 5,
                "policy": { "view": "full" },
                "budget": { "max_item_tokens": 1 }
            })),
        ),
    )
    .await;
    assert_eq!(dropped_status, StatusCode::OK);
    assert_eq!(dropped_body["results"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["neighbors"], Value::Array(Vec::new()));
    assert_eq!(dropped_body["state"]["kind"], Value::from("missing_data"));
    assert_eq!(
        dropped_body["state"]["reason"],
        Value::from("filter_matched_none")
    );
    assert_eq!(
        dropped_body["empty"]["reason"],
        Value::from("filter_matched_none")
    );
    assert_eq!(
        dropped_body["stats"]["items_dropped"]["count"],
        Value::from(1)
    );
    assert_eq!(
        dropped_body["evidence"]["result_ids"],
        Value::Array(Vec::new())
    );
    assert_eq!(dropped_body["evidence"]["scores"], Value::Array(Vec::new()));

    let runs = server.vault.retrieval_runs(1).expect("retrieval runs");
    assert_eq!(runs.len(), 1);
    assert!(runs[0].result_ids.is_empty());
    assert!(runs[0].score_breakdown.is_empty());
    assert_eq!(runs[0].empty_reason.as_deref(), Some("ItemBudget"));
}

#[test]
fn search_summary_and_full_project_the_revision_that_produced_the_hit() {
    let dir = tempfile::tempdir().unwrap();
    let vault = oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap();
    let id = oneiron::EntityId::now();
    let subject = oneiron::EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .unwrap();
    // A claim revision carries its own record scope. An edited non-claim
    // revision has no digest-bound stamp left to prove its historical read.
    let claim = |predicate: &str| {
        oneiron::ClaimBody::new(
            predicate,
            oneiron::ClaimSubject::Entity(subject),
            rmpv::Value::from(predicate),
            1.0,
            oneiron::ClaimApprovalStatus::Auto,
            oneiron::ClaimLifecycleStatus::Active,
        )
        .unwrap()
    };
    let at = |second| oneiron::TimeRange {
        start: second,
        end: second,
    };
    vault
        .put_claim(&id, &claim("searchanchor.original"), at(1), 1)
        .unwrap();
    vault
        .batch()
        .text(&id, &[("name", "searchanchor original")])
        .commit()
        .unwrap();
    vault
        .put_claim(&id, &claim("unmatched.replacement"), at(2), 2)
        .unwrap();
    let scoped = vault.scoped_read(crate::test_credentials::host_reader(&vault));
    let hits = vault.query().search_text("searchanchor", 10).run().unwrap();
    assert_eq!(hits.len(), 1);
    for view in [View::Summary, View::Full] {
        let response = search_response(&scoped, hits.clone(), view, 10).unwrap();
        assert_eq!(response.len(), 1);
        assert_eq!(response[0]["label"], "searchanchor.original");
    }
}
