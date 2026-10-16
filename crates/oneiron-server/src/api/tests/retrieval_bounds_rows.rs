//! The `[limits]` query row each retrieval door reads, and the OF-520
//! question a crossing raises (F21(a): H301, A1).

use super::retrieval_bounds::{SHIPPED_BODY_ROW, SHIPPED_QUERY_ROW, too_large};
use super::*;

fn bounded_server(query_bytes: usize) -> (tempfile::TempDir, Arc<SyncServer>) {
    test_server_with_config(SyncServerConfig {
        auth_secret: Some("secret".to_owned()),
        limits: crate::config::LimitsConfig {
            retrieval_query_bytes: query_bytes,
            ..Default::default()
        },
        ..Default::default()
    })
}

/// `text` as a URL query value.
fn percent(text: &str) -> String {
    text.bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Every REST query door: method, URI, body, the door's closed code and the
/// field it names.
fn rest_doors(
    query: &str,
) -> Vec<(
    &'static str,
    String,
    Option<Value>,
    &'static str,
    &'static str,
)> {
    vec![
        (
            "POST",
            "/v1/core/context-pack".to_owned(),
            Some(json!({"query": query})),
            "context_pack",
            "query",
        ),
        (
            "POST",
            "/v1/core/context-board".to_owned(),
            Some(json!({"retrieval": {"query": query}})),
            "context_board",
            "retrieval.query",
        ),
        (
            "POST",
            "/v1/core/query".to_owned(),
            Some(json!({"query": query})),
            "core_query",
            "query",
        ),
        (
            "POST",
            "/v1/companion/memory/reason".to_owned(),
            Some(json!({"query": query})),
            "memory_reason",
            "query",
        ),
        (
            "GET",
            format!("/api/search/text?query={}", percent(query)),
            None,
            "search_text",
            "query",
        ),
        (
            "GET",
            format!(
                "/api/search/vector?query=0.1,0.2,0.3&queryText={}",
                percent(query)
            ),
            None,
            "search_vector",
            "queryText",
        ),
        (
            "POST",
            "/api/search/semantic".to_owned(),
            Some(json!({"text": query})),
            "search_semantic",
            "text",
        ),
    ]
}

/// Done-means (H301, A1, OF-520): the shipped rows are the ruled 1 MiB and
/// 4 MiB. With the query row configured, every query door, GET ones
/// included, serves a query at the bound (bytes as sent: a multibyte
/// character and trailing padding count) and refuses one byte past it with
/// the typed 413. Each crossing raises one question per (principal, door,
/// field, bound), which keeps its latest crossing's size; a query at the
/// bound raises none, and the question holds no query text.
#[tokio::test]
async fn a_query_crossing_its_row_asks_once_per_door_and_field() {
    const ROW: usize = 64;
    let shipped = crate::config::LimitsConfig::default();
    assert_eq!(shipped.retrieval_query_bytes, SHIPPED_QUERY_ROW);
    assert_eq!(shipped.projection_body_bytes, SHIPPED_BODY_ROW);
    let (_dir, server) = bounded_server(ROW);
    // 62 ASCII bytes and one two-byte character: 64 bytes in 63 characters.
    let at = format!("{}é", "q".repeat(ROW - 2));
    assert_eq!(at.len(), ROW);
    let past = format!("{at} ");
    let further = format!("{at}   ");

    for (method, uri, body, _, _) in rest_doors(&at) {
        let (status, reply) = route_json(
            server.clone(),
            core_request_with_authz(method, &uri, owner_bearer(), body.as_ref()),
        )
        .await;
        assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}: {reply}");
    }
    assert!(server.retrieval_query_checks().is_empty());

    for query in [&past, &further] {
        for (method, uri, body, _, field) in rest_doors(query) {
            let (status, reply) = route_json(
                server.clone(),
                core_request_with_authz(method, &uri, owner_bearer(), body.as_ref()),
            )
            .await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}: {reply}");
            let details = too_large(&reply);
            assert_eq!(details["field"], field, "{uri}");
            assert_eq!(details["maxBytes"], ROW, "{uri}");
            assert_eq!(details["receivedBytes"], query.len(), "{uri}");
        }
        let checks = server.retrieval_query_checks();
        let doors = rest_doors(query);
        assert_eq!(checks.len(), doors.len(), "{checks:?}");
        for (_, uri, _, door, field) in doors {
            let check = checks
                .iter()
                .find(|check| check.door == door)
                .unwrap_or_else(|| panic!("{uri}: {checks:?}"));
            assert_eq!(check.field, field, "{uri}");
            assert_eq!(check.bound, ROW, "{uri}");
            assert_eq!(check.bytes, query.len(), "{uri}");
        }
    }
    let recorded = format!("{:?}", server.retrieval_query_checks());
    assert!(!recorded.contains(&"q".repeat(8)), "{recorded}");

    let actor = seeded_test_entity_id(0x0F21_0003);
    let credential = "f21-mcp-query-row";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    for (tool, door) in [
        ("memory.query", "mcp_memory_query"),
        ("memory.context_pack", "mcp_memory_context_pack"),
    ] {
        let request = |query: &str, id: &str| {
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                id,
                tool,
                mcp_merge_args(
                    mcp_endpoint_envelope(actor, "memory_read"),
                    json!({"arguments": {"request": {"query": query}}}),
                ),
            )
        };
        let (_, served) = route_json(server.clone(), request(&at, "f21-at")).await;
        assert!(served.get("error").is_none(), "{tool}: {served}");
        let refused = mcp_refusal(&server, request(&past, "f21-past")).await;
        let data = &refused["error"]["data"];
        assert_eq!(data["error_code"], "payload_too_large", "{tool}: {data}");
        assert_eq!(data["max_bytes"], ROW, "{tool}");
        assert_eq!(data["received_bytes"], past.len(), "{tool}");
        let checks = server.retrieval_query_checks();
        let check = checks
            .iter()
            .find(|check| check.door == door)
            .unwrap_or_else(|| panic!("{tool}: {checks:?}"));
        assert_eq!(check.field, "arguments.request.query");
        assert_eq!(check.bound, ROW);
    }
}
