//! Retrieval doors bound one request's shape and never refuse its work for a
//! count (F21(a): H46, H301, H27; rule 5): an over-large `limit` is served at
//! the ceiling and says so, a query past `[limits].retrieval_query_bytes` is
//! a typed 413, and a multi-row read past `[limits].projection_body_bytes`
//! leaves the rest of its bodies out, each with a marker.

use super::*;
use oneiron::memory::caps::MAX_SEARCH_LIMIT;

/// The shipped `[limits].retrieval_query_bytes` row.
pub(super) const SHIPPED_QUERY_ROW: usize = 1 << 20;
/// The shipped `[limits].projection_body_bytes` row.
pub(super) const SHIPPED_BODY_ROW: usize = 4 << 20;

/// The flat legacy error or the `/v1` envelope's error, asserted to be the
/// typed 413, and its details.
pub(super) fn too_large(body: &Value) -> &Value {
    let error = body
        .get("error")
        .filter(|error| error.is_object())
        .unwrap_or(body);
    assert_eq!(error["code"], "PAYLOAD_TOO_LARGE", "{body}");
    &error["details"]
}

/// A credential naming the vault's owner, the one the facade's recall door
/// reads under.
fn owner_reader(server: &SyncServer) -> String {
    let owner = server
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    test_bearer(&format!(
        "scope=core:read;principal_ref={};actor_class=human",
        owner.to_hex()
    ))
}

/// Done-means (H46): an over-large `limit` is served at MAX_SEARCH_LIMIT and
/// the response says so, at every ranked retrieval door; a limit at the
/// ceiling carries no flag. On main the pack, board, query and raw search
/// doors ran it unbounded and silently, reason refused past 100 and recall
/// past 1,000.
#[tokio::test]
async fn an_over_large_limit_is_served_at_the_ceiling_and_says_so() {
    let (_dir, server) = auth_test_server();
    seed_turn(&server, "The lantern room opens at dusk.");
    let reader = owner_reader(&server);
    for (limit, clamped) in [
        (MAX_SEARCH_LIMIT, false),
        (MAX_SEARCH_LIMIT + 1, true),
        (usize::MAX, true),
    ] {
        let doors = [
            (
                "POST",
                "/v1/core/context-pack".to_owned(),
                Some(json!({"query": "lantern", "limit": limit})),
                "/limit_clamped",
            ),
            (
                "POST",
                "/v1/core/context-board".to_owned(),
                Some(json!({"retrieval": {"query": "lantern", "limit": limit}})),
                "/pack/limit_clamped",
            ),
            (
                "POST",
                "/v1/core/query".to_owned(),
                Some(json!({"query": "lantern", "limit": limit})),
                "/meta/limitClamped",
            ),
            (
                "POST",
                "/v1/companion/memory/reason".to_owned(),
                Some(json!({"query": "lantern", "limit": limit})),
                "/limitClamped",
            ),
            (
                "GET",
                format!("/api/search/text?query=lantern&limit={limit}"),
                None,
                "/meta/limitClamped",
            ),
            (
                "GET",
                format!("/api/search/vector?query=0.1,0.2,0.3&limit={limit}"),
                None,
                "/meta/limitClamped",
            ),
            (
                "POST",
                "/v1/core/facade/recall".to_owned(),
                Some(json!({"query": "lantern", "limit": limit})),
                "/retrieval_meta/limit_clamped",
            ),
        ];
        for (method, uri, body, flag) in doors {
            let authz = if uri.contains("/facade/") {
                reader.clone()
            } else {
                owner_bearer()
            };
            let (status, reply) = route_json(
                server.clone(),
                core_request_with_authz(method, &uri, authz, body.as_ref()),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{uri} limit {limit}: {reply}");
            assert_eq!(
                reply
                    .pointer(flag)
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                clamped,
                "{uri} limit {limit}: {reply}"
            );
        }
    }
}

/// Done-means (H46, A3): the native MCP `memory.query` and
/// `memory.context_pack` and the MCP `recall` tool serve an over-large limit
/// at the ceiling and say so in their typed responses.
#[tokio::test]
async fn an_over_large_limit_is_served_at_the_ceiling_through_mcp() {
    let (_dir, server) = auth_test_server();
    let actor = seeded_test_entity_id(0x0F21_0001);
    let credential = "f21-mcp-limit";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    for (limit, clamped) in [(MAX_SEARCH_LIMIT, false), (usize::MAX, true)] {
        for (tool, envelope, arguments, flag) in [
            (
                "memory.query",
                "memory_read",
                json!({"request": {"query": "lantern", "limit": limit}}),
                "/response/meta/limitClamped",
            ),
            (
                "memory.context_pack",
                "memory_read",
                json!({"request": {"query": "lantern", "limit": limit}}),
                "/response/limit_clamped",
            ),
            (
                "recall",
                "read_memory",
                json!({"spec": {"query": "lantern", "limit": limit}}),
                "/retrieval_meta/limit_clamped",
            ),
        ] {
            let (status, reply) = route_json(
                server.clone(),
                mcp_endpoint_call_request(
                    MCP_TOOL_FIRST_PATH,
                    credential,
                    &format!("f21-{tool}-{limit}"),
                    tool,
                    mcp_merge_args(
                        mcp_endpoint_envelope(actor, envelope),
                        json!({ "arguments": arguments }),
                    ),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{tool} limit {limit}: {reply}");
            assert!(
                reply.get("error").is_none(),
                "{tool} limit {limit}: {reply}"
            );
            let output = &reply["result"]["structuredContent"]["output"];
            assert_eq!(
                output
                    .pointer(flag)
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                clamped,
                "{tool} limit {limit}: {reply}"
            );
        }
    }
}

/// Bug repro (H301): a query one byte past the shipped
/// `[limits].retrieval_query_bytes` row is refused at every POST query door
/// with the typed 413 naming the field, the bound and the bytes received.
/// On main only semantic search had a check (a fixed 8 KiB one) and the rest
/// ran the query.
#[tokio::test]
async fn a_query_past_the_shipped_row_is_refused_typed_at_every_query_door() {
    let (_dir, server) = auth_test_server();
    let past = "q".repeat(SHIPPED_QUERY_ROW + 1);
    for (uri, body, field) in [
        ("/v1/core/context-pack", json!({"query": past}), "query"),
        (
            "/v1/core/context-board",
            json!({"retrieval": {"query": past}}),
            "retrieval.query",
        ),
        ("/v1/core/query", json!({"query": past}), "query"),
        (
            "/v1/companion/memory/reason",
            json!({"query": past}),
            "query",
        ),
        ("/api/search/semantic", json!({"text": past}), "text"),
    ] {
        let (status, reply) = route_json(
            server.clone(),
            core_request_with_authz("POST", uri, owner_bearer(), Some(&body)),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{uri}");
        let details = too_large(&reply);
        assert_eq!(details["field"], field, "{uri}");
        assert_eq!(details["maxBytes"], SHIPPED_QUERY_ROW, "{uri}");
        assert_eq!(details["receivedBytes"], SHIPPED_QUERY_ROW + 1, "{uri}");
    }

    // The native MCP doors answer the same shape with the MCP typed tool
    // error, never an HTTP 413 (A3).
    let actor = seeded_test_entity_id(0x0F21_0002);
    let credential = "f21-mcp-query-bytes";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    for tool in ["memory.query", "memory.context_pack"] {
        let reply = mcp_refusal(
            &server,
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                &format!("f21-{tool}-bytes"),
                tool,
                mcp_merge_args(
                    mcp_endpoint_envelope(actor, "memory_read"),
                    json!({"arguments": {"request": {"query": past}}}),
                ),
            ),
        )
        .await;
        let data = &reply["error"]["data"];
        assert_eq!(data["error_code"], "payload_too_large", "{tool}: {data}");
        assert_eq!(data["field"], "arguments.request.query", "{tool}");
        assert_eq!(data["max_bytes"], SHIPPED_QUERY_ROW, "{tool}");
        assert_eq!(data["received_bytes"], SHIPPED_QUERY_ROW + 1, "{tool}");
    }
}

/// Seeds one TURN whose body carries `txt`, indexed under `needle`.
fn indexed_turn(server: &SyncServer, txt: &str, needle: &str) -> (oneiron::EntityId, usize) {
    let id = oneiron::EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({"txt": txt, "spkr": "user", "at": 100_u64}))
        .expect("encode turn body");
    server
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            &body,
        )
        .expect("put turn");
    server
        .vault
        .batch()
        .text(&id, &[("body", needle)])
        .commit()
        .expect("index turn");
    (id, body.len())
}

/// The item of `items` with `id`.
fn item<'a>(items: &'a Value, id: &oneiron::EntityId) -> &'a Value {
    items
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == id.to_hex()))
        .unwrap_or_else(|| panic!("{} among {items}", id.to_hex()))
}

/// Bug repro and done-means (H27, A5, A6): a multi-row read decodes bodies
/// only up to the shipped `[limits].projection_body_bytes` budget; a row past
/// it keeps its id, kind and time and carries a typed `bodyOmitted` marker in
/// place of its body (never a per-byte array), its summary label falling
/// back to its id. The single-entity `view=full` read still returns that
/// body whole. On main every body was decoded, whatever its size.
#[tokio::test]
async fn a_multi_row_read_omits_bodies_past_its_budget_and_one_read_returns_them_whole() {
    let (_dir, server) = auth_test_server();
    let small_txt = "omission needle, the short row";
    let (small, _) = indexed_turn(&server, small_txt, "omission needle");
    let large_txt = "x".repeat(SHIPPED_BODY_ROW + 1);
    let (large, large_bytes) = indexed_turn(&server, &large_txt, "omission needle");

    let (status, query) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/query",
            owner_bearer(),
            Some(&json!({"query": "omission needle", "view": "full", "limit": 10})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{query}");
    let shown = item(&query["items"], &small);
    assert_eq!(shown["txt"], small_txt);
    assert!(shown.get("bodyOmitted").is_none(), "{shown}");
    let omitted = item(&query["items"], &large);
    assert!(omitted.get("txt").is_none(), "the body stays out");
    assert!(omitted.get("bodyBytes").is_none(), "no per-byte array");
    assert_eq!(omitted["kind"], shown["kind"]);
    let marker = &omitted["bodyOmitted"];
    assert_eq!(marker["code"], "PROJECTION_BYTES_EXCEEDED", "{omitted}");
    assert_eq!(marker["maxBytes"], SHIPPED_BODY_ROW);
    assert_eq!(marker["bodyBytes"], large_bytes);
    assert!(marker["ref"].as_str().is_some_and(|r| !r.is_empty()));

    let (status, summary) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            "/api/search/text?query=omission%20needle&view=summary",
            owner_bearer(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    let omitted = item(&summary["items"], &large);
    assert_eq!(omitted["label"], large.to_hex(), "{omitted}");
    assert_eq!(omitted["bodyOmitted"]["code"], "PROJECTION_BYTES_EXCEEDED");
    assert_eq!(item(&summary["items"], &small)["label"], small_txt);

    let (status, whole) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            &format!("/api/entity/{}?view=full", large.to_hex()),
            owner_bearer(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(whole["txt"].as_str().map(str::len), Some(large_txt.len()));
    assert!(whole.get("bodyOmitted").is_none());

    // The marker's ref hydrates the very body the row left out, and a pinned
    // one still does after the row is edited (round 1, Sol F2 = Astra F2).
    let hydrate = |reference: &Value| {
        core_request_with_authz(
            "POST",
            "/v1/core/hydrate",
            owner_bearer(),
            Some(&json!({"ref": reference, "view": "full"})),
        )
    };
    let (status, hydrated) = route_json(server.clone(), hydrate(&marker["ref"])).await;
    assert_eq!(status, StatusCode::OK, "{hydrated}");
    assert_eq!(
        hydrated["item"]["txt"].as_str().map(str::len),
        Some(large_txt.len())
    );
    let pinned = omitted["bodyOmitted"]["ref"].clone();
    let edited = rmp_serde::to_vec_named(&json!({"txt": "edited", "spkr": "user", "at": 101_u64}))
        .expect("encode edit");
    server
        .vault
        .put_entity(
            &large,
            ENTITY_TYPE_TURN,
            oneiron::TimeRange {
                start: 100,
                end: 100,
            },
            101,
            &edited,
        )
        .expect("edit turn");
    let (status, hydrated) = route_json(server.clone(), hydrate(&pinned)).await;
    assert_eq!(status, StatusCode::OK, "{pinned}: {hydrated}");
    assert_eq!(
        hydrated["item"]["txt"].as_str().map(str::len),
        Some(large_txt.len()),
        "{pinned} names the omitted revision"
    );
}
