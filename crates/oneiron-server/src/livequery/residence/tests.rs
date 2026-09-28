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
    let frames = run(
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
    test_wire::reply(&frames)
}

#[tokio::test]
async fn first_join_index_is_thin_and_first_touch_returns_only_the_selected_item() {
    let (_dir, server) = production_tests::server();
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

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", production_tests::SECRET)
            .parse()
            .unwrap(),
    );
    let owner = CoreAuth::from_headers(&headers, &server.config, server.vault.as_ref()).unwrap();
    let denied = reply(&server, &owner, "residence.search", request(&encoded));
    assert!(
        denied.get("error").is_some(),
        "owner bearer alone is not an actor grant"
    );

    // Revocation of the residence grant invalidates search even while the
    // actor slip and its full indexed corpus remain live.
    server.vault.delete_entity(&grant_id).unwrap();
    let revoked = reply(&server, &actor, "residence.search", request(&encoded));
    assert!(revoked.get("error").is_some(), "{revoked:?}");
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

#[tokio::test]
async fn large_index_pages_are_thin_ordered_and_revision_bound() {
    let (_dir, server) = production_tests::server();
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
    let mut batch = server.vault.batch();
    let mut expected = std::collections::BTreeSet::new();
    for n in 0..520 {
        let id = EntityId::now();
        expected.insert(id.to_hex());
        let body = rmp_serde::to_vec_named(&json!({
            "title":format!("Index entry {n}"), "content":"body-not-on-index-wire".repeat(128),
        }))
        .unwrap();
        batch = batch.put(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: production_tests::AT,
                end: production_tests::AT,
            },
            production_tests::AT,
            &body,
        );
    }
    batch.commit().unwrap();
    let window = WindowKey::from_timestamp(production_tests::AT);
    let doc = server.get_or_create_window(&window).await.unwrap();
    let selector = SyncSelector::new(grant_id, principal, SyncSelectorWorld::All, vec![], vec![]);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(&selector).unwrap());
    let actor = crate::test_credentials::authenticate(&server, &production_tests::token("human"));
    let mut cache = None;
    let mut cursor: Option<String> = None;
    let mut revision: Option<String> = None;
    let mut seen = std::collections::BTreeSet::new();
    let mut pages = 0;
    loop {
        let page = reply_with_cache(
            &server,
            &actor,
            "residence.index",
            json!({
                "window":window.as_str(), "selector":encoded,
                "after":cursor, "revision":revision, "limit":256,
            }),
            &mut cache,
        );
        assert!(page.get("error").is_none(), "{page:?}");
        assert!(
            serde_json::to_vec(&page).unwrap().len() < 64 * 1024,
            "page must not ship 520 large bodies"
        );
        assert!(!page.to_string().contains("body-not-on-index-wire"));
        let current = page["result"]["revision"].as_str().unwrap().to_owned();
        if let Some(previous) = &revision {
            assert_eq!(&current, previous);
        }
        revision = Some(current);
        for entry in page["result"]["items"].as_array().unwrap() {
            let id = entry["entity_id"].as_str().unwrap().to_owned();
            assert!(seen.insert(id), "index cursor repeated a row");
        }
        pages += 1;
        cursor = page["result"]["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
        assert!(pages < 8, "large month should finish in bounded pages");
    }
    assert!(pages >= 3, "520 items require several bounded pages");
    assert!(expected.iter().all(|id| seen.contains(id)));

    // Any canonical window mutation invalidates a retained cursor. The
    // client restarts instead of combining two revisions in one local index.
    let first = reply_with_cache(
        &server,
        &actor,
        "residence.index",
        json!({
            "window":window.as_str(), "selector":encoded, "limit":256,
        }),
        &mut cache,
    );
    let cursor = first["result"]["nextCursor"].as_str().unwrap();
    let revision = first["result"]["revision"].as_str().unwrap();
    let extra = EntityId::now();
    let extra_body = rmp_serde::to_vec_named(&json!({"title":"late"})).unwrap();
    server
        .vault
        .put_entity(
            &extra,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: production_tests::AT,
                end: production_tests::AT,
            },
            production_tests::AT,
            &extra_body,
        )
        .unwrap();
    let raw = server.vault.get_raw(&extra).unwrap().unwrap();
    doc.get_map("entities")
        .insert(&extra.to_hex(), raw.as_slice())
        .unwrap();
    doc.commit();
    let stale = reply_with_cache(
        &server,
        &actor,
        "residence.index",
        json!({
            "window":window.as_str(), "selector":encoded,
            "after":cursor, "revision":revision, "limit":256,
        }),
        &mut cache,
    );
    assert_eq!(
        stale["error"]["code"], "INDEX_REVISION_CHANGED",
        "{stale:?}"
    );
    let restart = reply_with_cache(
        &server,
        &actor,
        "residence.index",
        json!({
            "window":window.as_str(), "selector":encoded, "limit":256,
        }),
        &mut cache,
    );
    let cursor = restart["result"]["nextCursor"].as_str().unwrap();
    let revision = restart["result"]["revision"].as_str().unwrap();
    // The LMDB row changed but Loro has not mirrored that body yet. A
    // digest-bound birth-scope write still advances the projection generation;
    // page two must not reuse cached titles from the old read revision.
    let edited_id = EntityId::from_hex(&expected.iter().nth(400).unwrap().clone()).unwrap();
    let edited_body = rmp_serde::to_vec_named(&json!({"title":"scope revision changed"})).unwrap();
    server
        .vault
        .put_entity(
            &edited_id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: production_tests::AT,
                end: production_tests::AT,
            },
            production_tests::AT,
            &edited_body,
        )
        .unwrap();
    let stale_scope = reply_with_cache(
        &server,
        &actor,
        "residence.index",
        json!({
            "window":window.as_str(), "selector":encoded,
            "after":cursor, "revision":revision, "limit":256,
        }),
        &mut cache,
    );
    assert_eq!(
        stale_scope["error"]["code"], "INDEX_REVISION_CHANGED",
        "{stale_scope:?}"
    );
}
