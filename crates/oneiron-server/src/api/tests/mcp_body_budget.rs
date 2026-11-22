//! Native MCP `memory.query` and `memory.hydrate_many` decode bodies under
//! the `/v1` doors' one `[limits].projection_body_bytes` budget (H27; the
//! open follow-up of ARCH-0044's retrieval note, census row L3-29). A body
//! the rest of the budget cannot hold is not decoded: its row keeps its id,
//! kind and time and carries a `bodyOmitted` marker whose ref a single
//! `memory.hydrate` reads whole.

use super::*;

const NEEDLE: &str = "bodybudgetneedle";

/// One active CLAIM about `subject` holding `value`, indexed under
/// [`NEEDLE`]; the length of its stored body.
fn seed_claim(
    server: &SyncServer,
    id: oneiron::EntityId,
    subject: oneiron::EntityId,
    value: &str,
) -> usize {
    let mut claim = oneiron::ClaimBody::new(
        "profile.note",
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    claim.source = Some(oneiron::ClaimSource::UserStated);
    server
        .vault
        .put_claim(&id, &claim, oneiron::TimeRange { start: 10, end: 10 }, 10)
        .expect("put claim");
    server
        .vault
        .batch()
        .text(&id, &[("body", NEEDLE)])
        .commit()
        .expect("index claim");
    server
        .vault
        .get(&id)
        .expect("read claim")
        .expect("claim stored")
        .len()
}

/// The item of `items` with `id`.
fn item<'a>(items: &'a Value, id: &oneiron::EntityId) -> &'a Value {
    items
        .as_array()
        .and_then(|items| items.iter().find(|item| item["id"] == id.to_hex()))
        .unwrap_or_else(|| panic!("{} among {items}", id.to_hex()))
}

/// Bug repro and done-means (H27 on native MCP): with a budget that holds
/// the small claim's body and not the large one's, `memory.query` (view
/// full) and `memory.hydrate_many` serve the small body and leave the large
/// one out with the typed marker, in either order; the marker's ref, read by
/// a single `memory.hydrate`, returns that body whole. On main both reads
/// decoded every admitted body, whatever its size.
#[tokio::test]
async fn native_mcp_reads_omit_a_body_past_the_budget_and_one_hydrate_reads_it_whole() {
    let (_dir, mut server) = auth_test_server();
    let actor = seeded_test_entity_id(0x0032_9001);
    let small = seeded_test_entity_id(0x0032_9002);
    let large = seeded_test_entity_id(0x0032_9003);
    let small_value = format!("{NEEDLE} the short note");
    let large_value = format!("{NEEDLE} {}", "x".repeat(4096));
    let small_bytes = seed_claim(&server, small, actor, &small_value);
    let large_bytes = seed_claim(&server, large, actor, &large_value);
    assert!(large_bytes > 2 * small_bytes, "{small_bytes} {large_bytes}");
    // The small body fits whether it is charged first or second; the large
    // one never does, and a body left out keeps the budget's credit.
    let bound = (small_bytes + large_bytes) / 2;
    Arc::get_mut(&mut server)
        .expect("the test holds the only server handle")
        .config
        .limits
        .projection_body_bytes = bound;
    let short_ref = |id: &oneiron::EntityId| {
        let reference =
            oneiron::retrieval_depth::short_ref_or_hex(&server.vault, id).expect("short ref");
        assert!(reference.contains(':'), "{reference} has a short ref");
        reference
    };
    let (small_ref, large_ref) = (short_ref(&small), short_ref(&large));

    let credential = "mcp-body-budget";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    let call = |tool: &'static str, request: Value| {
        route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                tool,
                tool,
                mcp_merge_args(
                    mcp_endpoint_envelope(actor, "memory_read"),
                    json!({ "arguments": { "request": request } }),
                ),
            ),
        )
    };
    let assert_omitted = |row: &Value| {
        assert!(row.get("body").is_none(), "the body stays out: {row}");
        let marker = &row["bodyOmitted"];
        assert_eq!(marker["code"], "PROJECTION_BYTES_EXCEEDED", "{row}");
        assert_eq!(marker["maxBytes"], bound, "{row}");
        let body_bytes = marker["bodyBytes"].as_u64().expect("bodyBytes");
        assert!(
            body_bytes > 4096 && body_bytes > (bound - small_bytes) as u64,
            "{row}"
        );
        assert_eq!(marker["ref"], large_ref, "{row}");
    };
    let assert_served = |row: &Value| {
        assert!(row.get("bodyOmitted").is_none(), "{row}");
        assert!(row["body"].is_object() || row["body"].is_array(), "{row}");
        assert!(row["body"].to_string().contains("the short note"), "{row}");
    };

    let (status, query) = call(
        "memory.query",
        json!({ "query": NEEDLE, "view": "full", "limit": 10 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{query}");
    assert!(query.get("error").is_none(), "{query}");
    let items = &query["result"]["structuredContent"]["output"]["response"]["items"];
    assert_served(item(items, &small));
    let omitted = item(items, &large);
    assert_omitted(omitted);
    assert_eq!(omitted["entity_type"], item(items, &small)["entity_type"]);

    for refs in [[&small_ref, &large_ref], [&large_ref, &small_ref]] {
        let (status, batch) = call("memory.hydrate_many", json!({ "refs": refs })).await;
        assert_eq!(status, StatusCode::OK, "{batch}");
        assert!(batch.get("error").is_none(), "{batch}");
        let results = &batch["result"]["structuredContent"]["output"]["response"]["results"];
        for (index, reference) in refs.into_iter().enumerate() {
            let result = &results[index];
            assert_eq!(result["outcome"], "live", "{batch}");
            let row = &result["result"]["item"];
            if *reference == large_ref {
                assert_omitted(row);
            } else {
                assert_served(row);
            }
        }
    }

    // A single hydrate takes no budget: the marker's ref reads the body whole.
    let (status, single) = call("memory.hydrate", json!({ "ref": large_ref })).await;
    assert_eq!(status, StatusCode::OK, "{single}");
    assert!(single.get("error").is_none(), "{single}");
    let row = &single["result"]["structuredContent"]["output"]["response"]["item"];
    assert!(row.get("bodyOmitted").is_none(), "{single}");
    assert!(
        row["body"].to_string().contains(&"x".repeat(4096)),
        "the whole body: {single}"
    );
}

/// A token-shaped secret the release rule never lets a reader that is not
/// the owner read (credential_filter.rs's own test token).
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// REVIEW2 #7571 P2-1: a reader that is not the owner is charged for, and
/// told the length of, only the body it reads (ruling EXPORTDOORS Q4 = A). A
/// claim whose value holds a token reaches it withheld, or rewritten with
/// that whole value nulled (a string that fails `safe_text` is nil), never as
/// stored; either way its released body is shorter than the stored one by
/// more than the small body. Under a budget that would hold the stored body
/// alone, the token's row takes only what its released body takes, a body
/// read before or after it is served, and no row carries a marker: a marker's
/// `bodyBytes` would give away the stored length of a body the reader may not
/// read. Charged at its stored length, the token's row either left the next
/// body out or carried that length.
#[tokio::test]
async fn a_body_released_without_its_secret_is_charged_and_told_as_released() {
    let (_dir, mut server) = auth_test_server();
    let actor = seeded_test_entity_id(0x0032_9011);
    let small = seeded_test_entity_id(0x0032_9012);
    let secret = seeded_test_entity_id(0x0032_9013);
    let small_bytes = seed_claim(&server, small, actor, &format!("{NEEDLE} the short note"));
    let secret_bytes = seed_claim(
        &server,
        secret,
        actor,
        &format!("{NEEDLE} my token is {TOKEN} {}", "x".repeat(4096)),
    );
    assert!(
        secret_bytes > 2 * small_bytes,
        "{small_bytes} {secret_bytes}"
    );
    let stored = server
        .vault
        .get(&secret)
        .expect("read the secret claim")
        .expect("secret claim stored");
    assert!(
        stored
            .windows(TOKEN.len())
            .any(|window| window == TOKEN.as_bytes()),
        "the stored body keeps the token"
    );
    // At its stored length the secret's body fits the budget alone and then
    // leaves too little for the small one; after the small one it does not
    // fit.
    let bound = secret_bytes + small_bytes / 2;
    Arc::get_mut(&mut server)
        .expect("the test holds the only server handle")
        .config
        .limits
        .projection_body_bytes = bound;
    let short_ref = |id: &oneiron::EntityId| {
        let reference =
            oneiron::retrieval_depth::short_ref_or_hex(&server.vault, id).expect("short ref");
        assert!(reference.contains(':'), "{reference} has a short ref");
        reference
    };
    let (small_ref, secret_ref) = (short_ref(&small), short_ref(&secret));

    // A person who is not the vault's owner.
    let credential = "mcp-body-budget-secret";
    register_mcp_actor(&server, credential, actor, oneiron::EdgeActorClass::Human).await;
    let call = |tool: &'static str, request: Value| {
        route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                credential,
                tool,
                tool,
                mcp_merge_args(
                    mcp_endpoint_envelope(actor, "memory_read"),
                    json!({ "arguments": { "request": request } }),
                ),
            ),
        )
    };

    // A single hydrate takes no budget: the row as this reader reads it.
    let (status, single) = call("memory.hydrate", json!({ "ref": secret_ref })).await;
    assert_eq!(status, StatusCode::OK, "{single}");
    assert!(single.get("error").is_none(), "{single}");
    let released = &single["result"]["structuredContent"]["output"]["response"]["item"];
    assert!(
        !released.to_string().contains(TOKEN),
        "this reader never reads the token: {single}"
    );
    let released_has_body = released.get("body").is_some();

    let assert_secret = |row: &Value| {
        assert!(
            row.get("bodyOmitted").is_none(),
            "no marker tells the stored length {secret_bytes}: {row}"
        );
        assert!(!row.to_string().contains(TOKEN), "{row}");
        assert_eq!(row.get("body").is_some(), released_has_body, "{row}");
    };
    let assert_served = |row: &Value| {
        assert!(row.get("bodyOmitted").is_none(), "{row}");
        assert!(row["body"].to_string().contains("the short note"), "{row}");
    };

    let (status, query) = call(
        "memory.query",
        json!({ "query": NEEDLE, "view": "full", "limit": 10 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{query}");
    assert!(query.get("error").is_none(), "{query}");
    let items = &query["result"]["structuredContent"]["output"]["response"]["items"];
    assert_served(item(items, &small));
    assert_secret(item(items, &secret));

    for refs in [[&small_ref, &secret_ref], [&secret_ref, &small_ref]] {
        let (status, batch) = call("memory.hydrate_many", json!({ "refs": refs })).await;
        assert_eq!(status, StatusCode::OK, "{batch}");
        assert!(batch.get("error").is_none(), "{batch}");
        let results = &batch["result"]["structuredContent"]["output"]["response"]["results"];
        for (index, reference) in refs.into_iter().enumerate() {
            let result = &results[index];
            assert_eq!(result["outcome"], "live", "{batch}");
            let row = &result["result"]["item"];
            if *reference == secret_ref {
                assert_secret(row);
            } else {
                assert_served(row);
            }
        }
    }
}
