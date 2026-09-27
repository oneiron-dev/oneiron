#![expect(
    clippy::unwrap_used,
    reason = "test fixture failures should panic immediately"
)]
use super::*;
use crate::livequery::{production_tests, test_wire};
use oneiron::federation::{FederationGrant, FederationGrantPreset, FederationGrantRole};
use oneiron::sync::{SyncSelectorWorld, encode_sync_selector};
use oneiron::temporal::TimeRange;

fn reply(server: &SyncServer, auth: &CoreAuth, method: &str, params: Value) -> Value {
    let frames = run(
        server,
        auth,
        RpcRequest {
            request_id: 7,
            method: method.into(),
            params,
        },
    )
    .unwrap();
    test_wire::reply(&frames)
}

#[tokio::test]
async fn first_join_index_is_thin_and_first_touch_returns_only_the_selected_item() {
    let (_dir, server) = production_tests::server();
    let actor = EntityId::from_hex(production_tests::ACTOR).unwrap();
    let item = EntityId::from_hex("55555555555555555555555555555555").unwrap();
    let other = EntityId::from_hex("66666666666666666666666666666666").unwrap();
    let grant_id = EntityId::from_hex("77777777777777777777777777777777").unwrap();
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
    let auth = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
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

#[tokio::test]
async fn home_search_requires_a_bound_actor_and_never_claims_local_completeness() {
    let (_dir, server) = production_tests::server();
    production_tests::witness(&server, "residencecanary unique search text");
    let actor = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
    let result = reply(
        &server,
        &actor,
        "residence.search",
        json!({
            "query":"residencecanary", "limit":10
        }),
    );
    assert_eq!(result["result"]["source"], "home");
    assert_eq!(result["result"]["complete"], true);
    assert!(!result["result"]["hits"].as_array().unwrap().is_empty());
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", production_tests::SECRET)
            .parse()
            .unwrap(),
    );
    let owner = CoreAuth::from_headers(&headers, &server.config, server.vault.as_ref()).unwrap();
    let denied = reply(
        &server,
        &owner,
        "residence.search",
        json!({"query":"residencecanary", "limit":10}),
    );
    assert!(
        denied.get("error").is_some(),
        "owner bearer alone is not an actor grant"
    );
}

#[tokio::test]
async fn full_window_promotion_returns_the_home_frontier_when_every_row_is_granted() {
    let dir = tempfile::tempdir().unwrap();
    let vault = std::sync::Arc::new(
        oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap(),
    );
    let actor = EntityId::from_hex("12121212121212121212121212121212").unwrap();
    let grant_id = EntityId::from_hex("34343434343434343434343434343434").unwrap();
    let item = EntityId::from_hex("56565656565656565656565656565656").unwrap();
    let now = oneiron_vault_contract::now_ts();
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )
        .unwrap();
    vault
        .put_entity(
            &item,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            &rmp_serde::to_vec_named(&json!({"title":"promotable"})).unwrap(),
        )
        .unwrap();
    let grant = FederationGrant::new(
        crate::handler::selector_grant_scope(),
        actor,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    oneiron::sync::put_selector_test_federation_grant(&vault, &grant_id, &grant, 1).unwrap();
    let server = SyncServer::new(
        vault.clone(),
        crate::config::SyncServerConfig {
            auth_secret: Some("promote-test-root".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let window = WindowKey::from_timestamp(now);
    let source = server.get_or_create_window(&window).await.unwrap();
    let selector = SyncSelector::new(grant_id, actor, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let auth = crate::test_credentials::authenticate(
        &server,
        &format!(
            "scope=core:read;principal_ref={};actor_class=human",
            actor.to_hex()
        ),
    );
    let promotion = reply(
        &server,
        &auth,
        "residence.promote",
        json!({
            "window": window.as_str(), "selector": encoded, "entityId": item.to_hex()
        }),
    );
    let selected = oneiron::sync::filtered_window_doc(
        &vault,
        &source,
        &window,
        crate::handler::selector_grant_scope(),
        &selector,
    )
    .unwrap();
    assert!(
        promotion["result"]["snapshot"].is_string(),
        "{promotion:?}; source_entities={:?}; selected_entities={:?}",
        {
            let mut ids = Vec::new();
            source
                .get_map("entities")
                .for_each(|id, _| ids.push(id.to_string()));
            ids
        },
        {
            let mut ids = Vec::new();
            selected
                .get_map("entities")
                .for_each(|id, _| ids.push(id.to_string()));
            ids
        }
    );
    let snapshot = base64::engine::general_purpose::STANDARD
        .decode(promotion["result"]["snapshot"].as_str().unwrap())
        .unwrap();
    let device = loro::LoroDoc::new();
    device.import(&snapshot).unwrap();
    assert!(device.get_map("entities").get(&item.to_hex()).is_some());
}
