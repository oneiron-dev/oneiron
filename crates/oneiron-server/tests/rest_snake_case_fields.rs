//! The server's HTTP JSON bodies use the engine's snake_case field names, and
//! no camelCase spelling of a renamed field is read on input
//! (UC-02-TS-FIELD-NAMES = A; RULING UC02-REST-SNAKE-SCOPE = A).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --features oneiron/test-support --test
//! rest_snake_case_fields`.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use axum::{Extension, Router};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

#[path = "support/engine_stack.rs"]
mod engine_stack;

use engine_stack::run_on_engine_stack;

/// Renamed types the OpenAPI registry lists in its components (each must be
/// in the document), with the camelCase wire names each had and the
/// snake_case names it has now.
const REGISTERED_RENAMED_SCHEMAS: &[&str] = &[
    "ResponseMeta",
    "MemoryReasonRequest",
    "MemoryReasonResponse",
    "MemoryReasonTrace",
    "SemanticSearchRequest",
    "CoreQueryRequest",
    "RuntimeRoute",
];

/// Every renamed type the document may name: the registered ones above and
/// the ones it reaches as nested schemas, checked when present.
const RENAMED_SCHEMAS: &[(&str, &[(&str, &str)])] = &[
    (
        "ResponseMeta",
        &[
            ("countMode", "count_mode"),
            ("confidenceAdjustment", "confidence_adjustment"),
            ("limitClamped", "limit_clamped"),
        ],
    ),
    ("ApiErrorEnvelopeBody", &[("requestId", "request_id")]),
    (
        "MemoryErrorBodySchema",
        &[
            ("requestId", "request_id"),
            ("receiptRef", "receipt_ref"),
            ("retryAfter", "retry_after"),
            ("resetsAt", "resets_at"),
            ("reasonCodes", "reason_codes"),
            ("programSteps", "program_steps"),
        ],
    ),
    (
        "GrantedDataSchema",
        &[
            ("grantedData", "granted_data"),
            ("accessLimited", "access_limited"),
        ],
    ),
    (
        "AccessLimitedSchema",
        &[
            ("suppressedCount", "suppressed_count"),
            ("requiredAction", "required_action"),
        ],
    ),
    (
        "MemoryReasonRequest",
        &[
            ("tokenBudget", "token_budget"),
            ("sessionContext", "session_context"),
        ],
    ),
    (
        "MemoryReasonResponse",
        &[
            ("tokensUsed", "tokens_used"),
            ("tokensUsageComplete", "tokens_usage_complete"),
            ("confidenceAdjustment", "confidence_adjustment"),
            ("limitClamped", "limit_clamped"),
            ("evidenceOmitted", "evidence_omitted"),
            ("compositionRefusal", "composition_refusal"),
        ],
    ),
    (
        "MemoryReasonTrace",
        &[
            ("queriesRun", "queries_run"),
            ("signalsUsed", "signals_used"),
            ("candidatesScanned", "candidates_scanned"),
        ],
    ),
    (
        "SemanticSearchRequest",
        &[("countMode", "count_mode"), ("deadlineMs", "deadline_ms")],
    ),
    ("CoreQueryRequest", &[("countMode", "count_mode")]),
    (
        "ConversationListRow",
        &[("lastMessageSnippet", "last_message_snippet")],
    ),
    (
        "RuntimeHealthStatus",
        &[("oneironSpendMetered", "oneiron_spend_metered")],
    ),
    (
        "RuntimeRoute",
        &[
            ("providerKind", "provider_kind"),
            ("oneironSpendMetered", "oneiron_spend_metered"),
        ],
    ),
];

/// Query parameters of the two GET search routes, before and after.
const RENAMED_SEARCH_PARAMETERS: &[(&str, &[(&str, &str)])] = &[
    (
        "/api/search/vector",
        &[
            ("countMode", "count_mode"),
            ("queryText", "query_text"),
            ("deadlineMs", "deadline_ms"),
            ("queryKind", "query_kind"),
        ],
    ),
    (
        "/api/search/text",
        &[("countMode", "count_mode"), ("deadlineMs", "deadline_ms")],
    ),
];

fn app() -> (tempfile::TempDir, Router) {
    let dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
    );
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                allow_unauthenticated: true,
                ..Default::default()
            },
        )
        .expect("sync server"),
    );
    // A hatch server answers only callers on this device: each request
    // comes from a loopback peer.
    let loopback = ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0)));
    (dir, build_app(server).layer(Extension(loopback)))
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, Value, String) {
    let response = app.clone().oneshot(request).await.expect("serve request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value, text)
}

async fn get(app: &Router, uri: &str) -> (StatusCode, Value, String) {
    send(
        app,
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("GET request"),
    )
    .await
}

/// Every key of `schema`'s `properties`, through `allOf`, `oneOf` and
/// `anyOf` members.
fn property_names(schema: &Value, names: &mut BTreeSet<String>) {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        names.extend(properties.keys().cloned());
    }
    for combinator in ["allOf", "oneOf", "anyOf"] {
        for member in schema
            .get(combinator)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            property_names(member, names);
        }
    }
}

#[tokio::test]
async fn openapi_document_names_renamed_fields_in_snake_case() {
    let (_dir, app) = app();
    let (status, spec, text) = get(&app, "/api/openapi.json").await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let schemas = spec["components"]["schemas"]
        .as_object()
        .expect("components.schemas");
    for schema in REGISTERED_RENAMED_SCHEMAS {
        assert!(
            schemas.contains_key(*schema),
            "the OpenAPI document names schema {schema}"
        );
    }
    for &(schema, renamed) in RENAMED_SCHEMAS {
        let Some(body) = schemas.get(schema) else {
            continue;
        };
        let mut names = BTreeSet::new();
        property_names(body, &mut names);
        for &(camel, snake) in renamed {
            assert!(
                !names.contains(camel),
                "{schema} still names `{camel}`: {names:?}"
            );
            assert!(names.contains(snake), "{schema} names `{snake}`: {names:?}");
        }
    }
    for &(path, renamed) in RENAMED_SEARCH_PARAMETERS {
        let names: BTreeSet<&str> = spec["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap_or_else(|| panic!("{path} documents its query parameters"))
            .iter()
            .filter_map(|parameter| parameter["name"].as_str())
            .collect();
        for &(camel, snake) in renamed {
            assert!(
                !names.contains(camel),
                "{path} still documents `{camel}`: {names:?}"
            );
            assert!(
                names.contains(snake),
                "{path} documents `{snake}`: {names:?}"
            );
        }
    }
}

#[test]
fn text_search_meta_reads_and_names_count_mode_in_snake_case() {
    run_on_engine_stack("text-search-count-mode", || async {
        let (_dir, app) = app();
        let (status, page, text) = get(
            &app,
            "/api/search/text?query=hallway&limit=1&count_mode=exact",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let meta = page["meta"].as_object().expect("page meta");
        assert_eq!(meta.get("count_mode"), Some(&json!("exact")), "{text}");
        assert!(!meta.contains_key("countMode"), "{text}");

        // The camelCase spelling is no longer read: the default holds.
        let (status, page, text) = get(
            &app,
            "/api/search/text?query=hallway&limit=1&countMode=exact",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert_eq!(page["meta"]["count_mode"], json!("estimate"), "{text}");
    });
}

#[test]
fn memory_reason_refuses_a_camel_case_field_in_a_snake_case_error_envelope() {
    run_on_engine_stack("memory-reason-camel-field", || async {
        let (_dir, app) = app();
        let body =
            json!({ "query": "what did we decide about the launch date", "tokenBudget": 4000 });
        let (status, reply, text) = send(
            &app,
            Request::builder()
                .method(Method::POST)
                .uri("/v1/companion/memory/reason")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("reason request"),
        )
        .await;
        assert!(status.is_client_error(), "{status} {text}");
        assert!(text.contains("unknown field `tokenBudget`"), "{text}");
        let error = reply["error"].as_object().expect("error envelope");
        assert!(
            error.get("request_id").is_some_and(Value::is_string),
            "{text}"
        );
        assert!(!error.contains_key("requestId"), "{text}");
    });
}

/// The read-grant projection that the core query and context-pack replies
/// flatten in (oneiron-records `GrantedData`) writes the snake_case names its
/// OpenAPI mirror `GrantedDataSchema` documents.
#[test]
fn granted_data_projection_names_its_fields_in_snake_case() {
    let projected = serde_json::to_value(oneiron::access_grant::GrantedData::new(
        vec!["7e000000000000000000000000000001".to_owned()],
        2,
    ))
    .expect("serialize the projection");
    assert_eq!(
        projected,
        json!({
            "granted_data": ["7e000000000000000000000000000001"],
            "access_limited": { "suppressed_count": 2, "required_action": "request_access" },
        })
    );
}

#[tokio::test]
async fn health_names_runtime_fields_in_snake_case() {
    let (_dir, app) = app();
    let (status, health, text) = get(&app, "/api/health").await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let runtime = health["runtime"].as_object().expect("health runtime");
    assert!(
        runtime
            .get("oneiron_spend_metered")
            .is_some_and(Value::is_boolean),
        "{text}"
    );
    assert!(!runtime.contains_key("oneironSpendMetered"), "{text}");
}
