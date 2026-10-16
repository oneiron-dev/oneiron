use super::*;
use crate::livequery::{production_tests, test_wire};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::sync::{SyncSelectorWorld, encode_sync_selector};
use oneiron::temporal::TimeRange;

fn reply(server: &SyncServer, auth: &CoreAuth, method: &str, params: Value) -> Value {
    reply_with_cache(server, auth, method, params, &mut None)
}

fn reply_with_cache(
    server: &SyncServer,
    auth: &CoreAuth,
    method: &str,
    params: Value,
    cache: &mut Option<ResidenceIndexCache>,
) -> Value {
    let answer = run(
        server,
        auth,
        RpcRequest {
            request_id: 7,
            method: method.into(),
            params,
        },
        cache,
    )
    .unwrap();
    test_wire::reply(&answer.queued(0))
}

/// A window holding two PERSON rows, `[item, other]`, whose bodies carry an unsynced canary, and
/// the actor's credential and encoded selector under a member grant on it.
async fn granted_window(server: &SyncServer) -> (CoreAuth, WindowKey, String, [EntityId; 2]) {
    let actor = EntityId::from_hex(production_tests::ACTOR).unwrap();
    let item = EntityId::now();
    let other = EntityId::now();
    let grant_id = EntityId::now();
    let scope = crate::handler::selector_grant_scope();
    let grant = FederationGrant::new(
        scope,
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(
        &server.vault,
        &grant_id,
        &grant,
        production_tests::AT,
    )
    .unwrap();
    let body =
        rmp_serde::to_vec_named(&json!({"title":"Window title", "content":"unsynced canary"}))
            .unwrap();
    for id in [item, other] {
        server
            .vault
            .put_entity(
                &id,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange {
                    start: production_tests::AT,
                    end: production_tests::AT,
                },
                production_tests::AT,
                &body,
            )
            .unwrap();
    }
    let window = WindowKey::from_timestamp(production_tests::AT);
    server.get_or_create_window(&window).await.unwrap();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let auth = crate::test_credentials::authenticate(server, &production_tests::token("human"));
    (auth, window, encoded, [item, other])
}

#[tokio::test]
async fn first_join_index_is_thin_and_first_touch_returns_only_the_selected_item() {
    let (_dir, server) = production_tests::server();
    let (auth, window, encoded, [item, other]) = granted_window(&server).await;
    let index = reply(
        &server,
        &auth,
        "residence.index",
        json!({
            "window": window.as_str(), "selector": encoded, "limit": 256
        }),
    );
    let items = index["result"]["items"].as_array().unwrap();
    assert!(items.iter().any(|row| row["entity_id"] == item.to_hex()
        && row["title"] == "Window title"
        && row["learned_at"] == production_tests::AT));
    assert!(!index.to_string().contains("unsynced canary"));
    let touch = reply(
        &server,
        &auth,
        "residence.touch",
        json!({
            "window": window.as_str(), "selector": encoded, "entityId": item.to_hex()
        }),
    );
    let blob = base64::engine::general_purpose::STANDARD
        .decode(touch["result"]["blob"].as_str().unwrap())
        .unwrap();
    assert_eq!(Some(blob), server.vault.get_raw(&item).unwrap());
    assert_ne!(item, other);
    let document = base64::engine::general_purpose::STANDARD
        .decode(touch["result"]["document"].as_str().unwrap())
        .unwrap();
    let frame = oneiron::sync::transport::decode_document(&document[1..]).unwrap();
    assert_eq!(frame.entity, item);
    let promotion = reply(
        &server,
        &auth,
        "residence.promote",
        json!({
            "window": window.as_str(), "selector": encoded, "entityId": item.to_hex()
        }),
    );
    assert_eq!(
        promotion["error"]["code"], "NOT_FOUND",
        "a mixed window is not wholly granted"
    );
    let denied = reply(
        &server,
        &auth,
        "residence.touch",
        json!({
            "window": window.as_str(), "selector": encoded, "entityId": EntityId::now().to_hex()
        }),
    );
    assert!(denied.get("error").is_some());
}

/// Bug repro (rule 5, found beside Bugbot's on #1483): a touch whose document export waited past
/// the live-document row to its deadline was answered a 500 "item document unavailable", after
/// waiting on the runtime worker. Done-means: it is answered the typed WAITED_OUT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_touch_past_the_live_document_row_is_waited_out() {
    let (_dir, server) = production_tests::server_with_limits(crate::config::LimitsConfig {
        live_documents: 1,
        queue_wait_timeout_ms: 200,
        ..crate::config::LimitsConfig::default()
    });
    let (auth, window, encoded, [item, other]) = granted_window(&server).await;
    // Another opener holds the vault's one live document past the wait.
    let _held = server
        .reassert_manager
        .documents()
        .open_for(other, b"another opener")
        .unwrap();
    let touch = reply(
        &server,
        &auth,
        "residence.touch",
        json!({
            "window": window.as_str(), "selector": encoded, "entityId": item.to_hex()
        }),
    );
    assert_eq!(touch["error"]["code"], "WAITED_OUT", "{touch}");
}

#[tokio::test]
async fn home_search_requires_a_bound_grant_and_never_claims_local_completeness() {
    let (_dir, server) = production_tests::server();
    production_tests::witness(&server, "residencecanary unique search text");
    let principal = EntityId::from_hex(production_tests::ACTOR).unwrap();
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        crate::handler::selector_grant_scope(),
        principal,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(
        &server.vault,
        &grant_id,
        &grant,
        production_tests::AT,
    )
    .unwrap();
    server
        .get_or_create_window(&WindowKey::from_timestamp(production_tests::AT))
        .await
        .unwrap();
    let selector = SyncSelector::new(grant_id, principal, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let actor = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
    let request = |selector: &str| {
        json!({
            "query":"residencecanary", "limit":10, "selector":selector,
        })
    };
    let result = reply(&server, &actor, "residence.search", request(&encoded));
    assert_eq!(result["result"]["source"], "home");
    assert_eq!(result["result"]["complete"], true);
    assert!(
        !result["result"]["hits"].as_array().unwrap().is_empty(),
        "{result:?}"
    );

    // The SAME actor slip permits the MESSAGE hit; this residence grant does not.
    let narrow_id = EntityId::now();
    let mut narrow_grant = grant.clone();
    narrow_grant.authority_scope.bands =
        oneiron::federation::ScopeAxis::Some(std::collections::BTreeSet::from([
            oneiron::registry::ENTITY_TYPE_CLAIM,
        ]));
    oneiron::sync::put_selector_test_federation_grant(
        &server.vault,
        &narrow_id,
        &narrow_grant,
        production_tests::AT,
    )
    .unwrap();
    let narrow = SyncSelector::new(narrow_id, principal, SyncSelectorWorld::All, vec![], vec![]);
    let narrow_encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&narrow).unwrap());
    let scoped = reply(
        &server,
        &actor,
        "residence.search",
        request(&narrow_encoded),
    );
    assert_eq!(scoped["result"]["hits"], json!([]), "{scoped:?}");

    // An owner-grade slip names no actor, so it is not an actor grant.
    let owner = crate::test_credentials::authenticate(&server, "jti=residence-search-owner");
    let denied = reply(&server, &owner, "residence.search", request(&encoded));
    assert!(
        denied.get("error").is_some(),
        "owner credential alone is not an actor grant"
    );

    // Revocation of the residence grant invalidates search even while the
    // actor slip and its full indexed corpus remain live.
    server.vault.delete_entity(&grant_id).unwrap();
    let revoked = reply(&server, &actor, "residence.search", request(&encoded));
    assert!(revoked.get("error").is_some(), "{revoked:?}");
}

/// Crosses a residence index row (rule 5, rows 22 and 23): budgets of one
/// page of one entry and one byte of projection, read `callers` pages deep.
/// Every page is served, charged to the retained-memory line.
pub(crate) async fn cross_the_index(
    row: crate::wire_telemetry::LimitRow,
    callers: usize,
) -> crate::admission::Crossing {
    let (_dir, server) = production_tests::server();
    let actor = EntityId::from_hex(production_tests::ACTOR).unwrap();
    let grant_id = EntityId::now();
    oneiron::sync::put_selector_test_federation_grant(
        &server.vault,
        &grant_id,
        &FederationGrant::new(
            crate::handler::selector_grant_scope(),
            actor,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        ),
        production_tests::AT,
    )
    .unwrap();
    let body = rmp_serde::to_vec_named(&json!({"title":"Window title"})).unwrap();
    for _ in 0..=callers {
        let at = TimeRange {
            start: production_tests::AT,
            end: production_tests::AT,
        };
        server
            .vault
            .put_entity(
                &EntityId::now(),
                oneiron::registry::ENTITY_TYPE_PERSON,
                at,
                production_tests::AT,
                &body,
            )
            .unwrap();
    }
    let window = WindowKey::from_timestamp(production_tests::AT);
    server.get_or_create_window(&window).await.unwrap();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let auth = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
    let budgets = ResidenceOperationBudgets {
        index_page_limit: 1,
        max_index_pages: 1,
        index_cache_bytes: 1,
        ..ResidenceOperationBudgets::default()
    };
    let (mut cache, mut after, mut revision) = (None, Value::Null, Value::Null);
    let mut refused = 0;
    for _ in 0..callers {
        let params = json!({
            "window": window.as_str(), "selector": encoded, "limit": 1,
            "after": after, "revision": revision,
        });
        match index(&server, &auth, params, &mut cache, budgets) {
            Ok((page, _)) => {
                after = page["nextCursor"].clone();
                revision = page["revision"].clone();
            }
            Err(_) => refused += 1,
        }
    }
    crate::admission::Crossing {
        refused,
        asked: server
            .wire_telemetry
            .limit_questions()
            .latest(row)
            .is_some(),
    }
}

/// Bug repro (rule 5, rows 22 and 23): a socket's index read was refused
/// past 1,024 pages and past its projection's byte row. Done-means: every
/// page is served and each row asks.
#[tokio::test]
async fn an_index_read_past_its_rows_is_served_and_asks() {
    use crate::wire_telemetry::LimitRow;
    for row in [LimitRow::ResidenceIndexPages, LimitRow::ResidenceIndexBytes] {
        assert_eq!(
            cross_the_index(row, 4).await,
            crate::admission::Crossing {
                refused: 0,
                asked: true
            },
            "{}",
            row.key()
        );
    }
}
