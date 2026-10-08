#![allow(clippy::unwrap_used)]
//! Real vault, verified slips and production facade/source; no injected read source.
use super::source::BoundSource;
use super::subscriptions::LiveQuerySource;
use super::*;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::memory::{
    ClaimInput, ClaimListFilter, NeighborOpts, WitnessAuthor, WitnessMessage, WitnessReceipt,
    WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use std::sync::Arc;

pub(super) const SECRET: &str = "production-app-tier-owner";
pub(super) const ACTOR: &str = "11111111111111111111111111111111";
pub(super) const JTI: &str = "22222222222222222222222222222222";
const MACHINE: &str = "33333333333333333333333333333333";
const CONVERSATION: &str = "44444444444444444444444444444444";
const SPACE: &str = "55555555555555555555555555555555";
const READ_GRANT: &str = "66666666666666666666666666666666";
pub(super) const AT: u64 = 1_772_000_000;

pub(super) fn server() -> (tempfile::TempDir, Arc<SyncServer>) {
    server_with_config(oneiron::VaultConfig::device())
}

fn server_with_config(config: oneiron::VaultConfig) -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), config).unwrap());
    for (id, kind) in [
        (ACTOR, oneiron::registry::ENTITY_TYPE_PERSON),
        (MACHINE, oneiron::registry::ENTITY_TYPE_MACHINE),
    ] {
        vault
            .put_entity(
                &EntityId::from_hex(id).unwrap(),
                kind,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                b"fixture actor",
            )
            .unwrap();
    }
    let actor = EntityId::from_hex(ACTOR).unwrap();
    vault
        .install_read_permit_for_test(WriteActor::new(actor, EdgeActorClass::Human))
        .unwrap();
    vault
        .create_access_grant(
            &EntityId::from_hex(READ_GRANT).unwrap(),
            &AccessGrant {
                authority_scope: oneiron::federation::Scope::top(),
                principal_ref: actor,
                scope: AccessGrantScope::Messages {
                    space_ref: EntityId::from_hex(SPACE).unwrap(),
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: AT,
                revoked_at: None,
                expires_at: None,
            },
        )
        .unwrap();
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                max_messages_per_sec: 10000,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    (dir, server)
}

fn revision_event(
    server: &SyncServer,
    entity: EntityId,
    previous_revision: Option<oneiron::memory::RevisionRef>,
) -> oneiron::sync::bridge::RevisionEvent {
    oneiron::sync::bridge::RevisionEvent::Original(oneiron::memory::EntityRevisionChange {
        entity,
        previous_revision,
        revision: Some(server.vault().pin_entity_revision(&entity).unwrap()),
        indexed_revision: server.vault().indexed_revision(&entity).unwrap(),
    })
}

fn publish_indexed(
    hub: &connection::Hub,
    report: &oneiron::memory::IndexedRefreshReport,
    id: EntityId,
    previous_indexed: oneiron::memory::RevisionRef,
) {
    let indexed = report
        .refreshed
        .iter()
        .find(|(entity, _)| *entity == id)
        .unwrap()
        .1;
    hub.indexed_published(&[oneiron::memory::IndexedPublication {
        entity: id,
        previous_indexed,
        indexed,
    }]);
}

pub(super) fn token(class: &str) -> String {
    let actor = if class == "system" { MACHINE } else { ACTOR };
    format!("scope=core:read;principal_ref={actor};actor_class={class};jti={JTI}-{class}")
}
fn auth(server: &SyncServer, class: &str) -> CoreAuth {
    crate::test_credentials::authenticate(server, &token(class))
}

pub(super) fn witness(server: &SyncServer, text: &str) -> WitnessReceipt {
    server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: CONVERSATION.to_owned(),
            turn_ref: None,
            messages: vec![WitnessMessage {
                id: None,
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: text.to_owned(),
                metadata: Some(json!({"rel": SPACE})),
                is_visible: true,
                order: 0,
            }],
            occurred_at: AT,
        })
        .unwrap()
}

pub(super) fn claim(server: &SyncServer) -> oneiron::memory::CommitReceipt {
    server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: ACTOR.to_owned(),
            value: json!("Imported name"),
            confidence: 1.0,
            source: "imported".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(AT),
            learned_at: Some(AT),
            salience: None,
        })
        .unwrap()
}

fn rpc(server: &SyncServer, auth: &CoreAuth, method: &str, params: Value) -> Value {
    let frame = bound_rpc(
        server,
        auth,
        RpcRequest {
            request_id: 7,
            method: method.to_owned(),
            params,
        },
    )
    .unwrap();
    assert_eq!(frame[0][0], TAG_RPC);
    let reply = test_wire::reply(&frame);
    assert_eq!(reply["requestId"], 7);
    assert_eq!(reply["last"], true);
    reply
}

fn error_body(error: AppError) -> Value {
    serde_json::to_value(error).unwrap()
}

fn assert_error(reply: &Value, code: &str) {
    let body = &reply["error"];
    assert_eq!(body["code"], code, "{reply}");
    assert!(body["message"].is_string());
    assert!(body["requestId"].is_string());
    assert!(!body["suggestions"].as_array().unwrap().is_empty());
    assert_eq!(body.as_object().unwrap().len(), 4);
    assert!(reply.get("result").is_none());
}

#[tokio::test]
async fn verified_actor_classes_are_mapped_exactly_and_missing_class_is_forbidden() {
    let (_dir, server) = server();
    for (class, expected) in [
        ("human", EdgeActorClass::Human),
        ("agent", EdgeActorClass::Agent),
        ("system", EdgeActorClass::System),
    ] {
        let auth = auth(&server, class);
        assert_eq!(auth.actor_class(), Some(class));
        assert_eq!(bound_actor_class(&auth).unwrap(), expected);
        let reply = rpc(&server, &auth, "hydrate", json!({"refs":[]}));
        assert_eq!(reply["result"]["value"], json!([]));
        assert!(reply["result"]["narrowing"].is_object());
    }
    let classless = format!("scope=core:read;principal_ref={ACTOR}");
    let auth = crate::test_credentials::authenticate(&server, &classless);
    let reply = rpc(&server, &auth, "hydrate", json!({"refs":[]}));
    assert_error(&reply, "FORBIDDEN");
    assert_eq!(
        reply["error"]["message"],
        "facade routes bind writes to a declared actor class"
    );
    assert_eq!(
        reply["error"]["suggestions"],
        json!([
            "Present a slip minted with --actor-class <human|agent|system>.",
            "Reconnect with a differently scoped slip to act as another actor.",
        ])
    );
    let payload_actor = rpc(
        &server,
        &auth,
        "recall",
        json!({
            "query":"solar", "actor_class":"human", "principal_ref":ACTOR,
        }),
    );
    assert_error(&payload_actor, "FORBIDDEN");
    let owner = crate::test_credentials::authenticate(&server, "jti=production-unregistered-host");
    let reply = rpc(&server, &owner, "receipts", json!({}));
    assert_error(&reply, "FORBIDDEN");
    assert_eq!(
        reply["error"]["message"],
        "facade routes bind writes to an authenticated principal"
    );
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let template = server.vault().ensure_host_root_slip(&issuer).unwrap();
    for (index, class) in ["Human", "owner", ""].iter().enumerate() {
        let mut claims = template.claims.clone();
        claims.slip_id = [100 + index as u8; 32];
        claims.actor_class = Some((*class).into());
        assert!(
            server
                .vault()
                .mint_capability_slip(&issuer, claims)
                .is_err()
        );
    }
}

#[tokio::test]
async fn all_eight_production_rpc_reads_return_the_engine_dtos() {
    let (_dir, server) = server();
    let witnessed = witness(&server, "solar panel maintenance");
    let committed = claim(&server);
    let auth = auth(&server, "human");
    // The engine side of each case reads under the same credential the RPC
    // presents, so both answers carry the same receipt.
    let memory = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .with_read_proof(auth.verified_slip().unwrap());
    let refs = witnessed.message_short_ids;
    let filter = ClaimListFilter {
        subject_ref: Some(ACTOR.to_owned()),
        predicate: None,
        lifecycle: None,
        limit: 100,
    };
    let opts = NeighborOpts {
        limit: 100,
        ..Default::default()
    };
    let expected_pending = serde_json::to_value(memory.pending_writes(100).unwrap()).unwrap();
    assert!(!expected_pending.as_array().unwrap().is_empty());
    // The first recall observes a PPR cache miss and reports it in
    // retrieval_meta. Warm the shared cache once so the snapshot below and the
    // RPC read observe the same execution report.
    memory
        .recall(
            "solar",
            Effort::Medium,
            &RecallScope::default(),
            10,
            None,
            None,
        )
        .unwrap();
    let cases = [
        (
            "hydrate",
            json!({"refs": refs}),
            serde_json::to_value(memory.hydrate(&refs).unwrap()).unwrap(),
        ),
        (
            "queryBm25",
            json!({"query":"solar","limit":10}),
            serde_json::to_value(memory.query_bm25("solar", 10).unwrap()).unwrap(),
        ),
        (
            "neighbors",
            json!({"entityRef":ACTOR,"opts":opts}),
            serde_json::to_value(memory.neighbors(ACTOR, &opts).unwrap()).unwrap(),
        ),
        ("pendingWrites", json!({"limit":100}), expected_pending),
        (
            "receipts",
            json!({}),
            serde_json::to_value(memory.receipts(100).unwrap()).unwrap(),
        ),
        (
            "claimList",
            serde_json::to_value(&filter).unwrap(),
            serde_json::to_value(memory.claim_list(&filter).unwrap()).unwrap(),
        ),
        (
            "claimHistory",
            json!({"claimRef":committed.claim_short_id}),
            serde_json::to_value(memory.claim_history(&committed.claim_short_id).unwrap()).unwrap(),
        ),
        (
            "recall",
            json!({"query":"solar"}),
            serde_json::to_value(
                memory
                    .recall(
                        "solar",
                        Effort::Medium,
                        &RecallScope::default(),
                        10,
                        None,
                        None,
                    )
                    .unwrap(),
            )
            .unwrap(),
        ),
    ];
    for (method, params, expected) in cases {
        let reply = rpc(&server, &auth, method, params);
        assert!(reply.get("error").is_none(), "{method}: {reply}");
        assert_eq!(reply["result"], expected, "{method}");
    }
}

#[tokio::test]
async fn http_recall_and_receipts_defaults_limits_and_error_order_are_preserved() {
    let (_dir, server) = server();
    let auth = auth(&server, "human");
    for value in [
        json!({"query":"solar"}),
        json!({"query":"solar","effort":null,"scope":null,
        "limit":null,"format":null,"ignored":true}),
    ] {
        let reply = rpc(&server, &auth, "recall", value);
        assert_eq!(reply["result"]["pack_version"], 1);
        assert!(reply.get("error").is_none());
    }
    for value in [
        json!({}),
        json!({"limit":null,"ignored":true}),
        json!({"limit":1000}),
    ] {
        assert_eq!(rpc(&server, &auth, "receipts", value)["result"], json!([]));
    }
    for method in ["recall", "receipts"] {
        for limit in [0, 1001] {
            let reply = rpc(
                &server,
                &auth,
                method,
                json!({"query":"solar","limit":limit}),
            );
            assert_error(&reply, "BAD_REQUEST");
            assert_eq!(
                reply["error"]["message"],
                "limit must be between 1 and 1000"
            );
            assert_eq!(
                reply["error"]["suggestions"],
                json!(["Request a smaller page and paginate."])
            );
        }
    }
    for value in [
        Value::Null,
        json!({}),
        json!({"query":3}),
        json!({"query":"x","limit":-1}),
    ] {
        let reply = rpc(&server, &auth, "recall", value);
        assert_error(&reply, "BAD_REQUEST");
        assert_eq!(reply["error"]["message"], "invalid JSON request body");
        assert_eq!(
            reply["error"]["suggestions"],
            json!(["Send a JSON body matching this verb's documented input."])
        );
    }
    let classless = crate::test_credentials::authenticate(
        &server,
        &format!("scope=core:read;principal_ref={ACTOR}"),
    );
    assert_error(
        &rpc(&server, &classless, "recall", json!({})),
        "BAD_REQUEST",
    );
    let write_only = crate::test_credentials::authenticate(
        &server,
        &format!("scope=core:write;principal_ref={ACTOR};actor_class=human"),
    );
    assert_error(&rpc(&server, &write_only, "recall", json!({})), "FORBIDDEN");
}

#[tokio::test]
async fn rpc_engine_failures_keep_exact_codes_messages_and_suggestions() {
    let (_dir, server) = server();
    let auth = auth(&server, "human");
    let memory = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human);
    let missing = "ffffffffffffffffffffffffffffffff".to_owned();
    let cases = [
        (
            "recall",
            json!({"query":"solar","effort":"high"}),
            memory
                .recall(
                    "solar",
                    Effort::High,
                    &RecallScope::default(),
                    10,
                    None,
                    None,
                )
                .unwrap_err(),
        ),
        (
            "hydrate",
            json!({"refs":[missing]}),
            memory.hydrate(&[missing]).unwrap_err(),
        ),
        (
            "neighbors",
            json!({"entityRef":ACTOR,"opts":{"limit":1,"edge_kind":"not-a-kind"}}),
            memory
                .neighbors(
                    ACTOR,
                    &NeighborOpts {
                        limit: 1,
                        edge_kind: Some("not-a-kind".to_owned()),
                        min_weight: None,
                    },
                )
                .unwrap_err(),
        ),
    ];
    for (method, params, expected) in cases {
        let reply = rpc(&server, &auth, method, params);
        assert_error(&reply, &expected.code);
        assert_eq!(reply["error"]["message"], expected.message);
        assert_eq!(reply["error"]["suggestions"], json!(expected.suggestions));
    }
    // Future engine codes are forwarded, not collapsed into a closed server enum.
    let future: oneiron::memory::MemoryError = serde_json::from_value(json!({
        "code":"FUTURE_ENGINE_REFUSAL","message":"future refusal","suggestions":["retry later"]
    }))
    .unwrap();
    let body = error_body(future.into());
    assert_eq!(body["code"], "FUTURE_ENGINE_REFUSAL");
    assert_eq!(body["message"], "future refusal");
    assert_eq!(body["suggestions"], json!(["retry later"]));
}

#[tokio::test]
async fn production_source_derives_real_channels_and_rechecks_revocation_before_resume() {
    let (_dir, server) = server();
    witness(&server, "solar panel source snapshot");
    claim(&server);
    let auth = auth(&server, "human");
    let proof = auth.verified_slip().unwrap().clone();
    let source = BoundSource::new(
        Arc::downgrade(&server),
        auth,
        "production-source".to_owned(),
    );
    let view = ScopedView {
        query: Some("solar".to_owned()),
        ..Default::default()
    };
    let derived = source.derive(&view, Channel::View).unwrap();
    let memory = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human)
        .with_read_proof(&proof);
    let expected = memory
        .recall(
            "solar",
            Effort::Light,
            &RecallScope::default(),
            100,
            None,
            None,
        )
        .unwrap();
    assert!(!expected.items.is_empty());
    assert_eq!(derived.value, serde_json::to_value(expected.items).unwrap());
    assert!(source.can_resume(&derived.cursor).unwrap());
    for channel in [Channel::Receipts, Channel::PendingConsent] {
        let rows = source.derive(&ScopedView::default(), channel).unwrap();
        assert!(!rows.value.as_array().unwrap().is_empty(), "{channel:?}");
    }
    let missing_facet = ScopedView {
        facet: Some("zz999:ff".to_owned()),
        ..view
    };
    let expected_error = memory
        .recall(
            "solar",
            Effort::Light,
            &RecallScope {
                world_ref: None,
                facet: missing_facet.facet.clone(),
                kinds: None,
            },
            100,
            None,
            None,
        )
        .unwrap_err();
    let Err(error) = source.derive(&missing_facet, Channel::View) else {
        panic!("missing facet must fail")
    };
    let body = error_body(error);
    assert_eq!(body["code"], expected_error.code);
    assert_eq!(body["message"], expected_error.message);
    assert_eq!(body["suggestions"], json!(expected_error.suggestions));
    crate::test_credentials::revoke(&server, &token("human"));
    for channel in [Channel::View, Channel::Receipts, Channel::PendingConsent] {
        let Err(error) = source.derive(&ScopedView::default(), channel) else {
            panic!("revoked derive must fail")
        };
        assert_eq!(error_body(error)["code"], "UNAUTHORIZED");
    }
    assert_eq!(
        error_body(source.can_resume(&derived.cursor).unwrap_err())["code"],
        "UNAUTHORIZED"
    );
}

#[tokio::test]
async fn receipt_limit_is_applied_after_actor_scoping() {
    let (_dir, server) = server();
    claim(&server);
    let other = EntityId::from_hex("55555555555555555555555555555555").unwrap();
    server
        .vault()
        .put_entity(
            &other,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::temporal::TimeRange { start: AT, end: AT },
            AT,
            b"fixture actor",
        )
        .unwrap();
    server
        .vault()
        .memory(other, EdgeActorClass::Human)
        .claim_upsert(&ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: other.to_hex(),
            value: json!("Newer unrelated actor"),
            confidence: 1.0,
            source: "imported".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: None,
            valid_from: None,
            valid_to: None,
            occurred_at: Some(AT),
            learned_at: Some(AT),
            salience: None,
        })
        .unwrap();
    let source = BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "fixture".into(),
    );
    let derived = source
        .derive(
            &ScopedView {
                filter: Some(json!({"limit":1})),
                ..Default::default()
            },
            Channel::Receipts,
        )
        .unwrap();
    let rows = derived.value.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["actor_ref"], ACTOR);
}

#[tokio::test]
async fn view_filters_before_top_k_past_one_thousand_unrelated_records() {
    let (_dir, server) = server();
    let memory = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human);
    let other_world = "66666666666666666666666666666666";
    let make_id = |n: u64| {
        let mut bytes = [0x71; 16];
        bytes[8..].copy_from_slice(&n.to_be_bytes());
        EntityId::from_bytes(bytes).unwrap()
    };
    for n in 0..1030 {
        let subject = make_id(n);
        server
            .vault()
            .put_entity(
                &subject,
                oneiron::registry::ENTITY_TYPE_PERSON,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"name":"fixture subject"})).unwrap(),
            )
            .unwrap();
        let id = if n % 3 == 0 {
            subject
        } else {
            let id = make_id(2000 + n);
            let receipt = memory
                .claim_upsert(&ClaimInput {
                    id: Some(id.to_hex()),
                    predicate: if n == 2 { "view.target" } else { "view.other" }.into(),
                    subject_ref: subject.to_hex(),
                    value: json!("unrelated"),
                    confidence: 1.0,
                    source: "user_stated".into(),
                    world_ref: (n == 2).then(|| other_world.into()),
                    relationship_ref: None,
                    scope: None,
                    valid_from: None,
                    valid_to: None,
                    occurred_at: Some(AT),
                    learned_at: Some(AT),
                    salience: Some(0.9),
                })
                .unwrap();
            assert_eq!(receipt.approval, "auto");
            id
        };
        server
            .vault()
            .batch()
            .text(&id, &[("body", "viewneedle")])
            .commit()
            .unwrap();
    }
    let mut expected = Vec::new();
    for (n, subject, text) in [
        (
            5000,
            ACTOR,
            "viewneedle extra words make this result less relevant",
        ),
        (
            5001,
            MACHINE,
            "viewneedle extra words make this result much less relevant than the first",
        ),
    ] {
        let id = make_id(n);
        let receipt = memory
            .claim_upsert(&ClaimInput {
                id: Some(id.to_hex()),
                predicate: "view.target".into(),
                subject_ref: subject.into(),
                value: json!(text),
                confidence: 1.0,
                source: "user_stated".into(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: Some(AT),
                learned_at: Some(AT),
                salience: None,
            })
            .unwrap();
        assert_eq!(receipt.approval, "auto");
        server
            .vault()
            .batch()
            .text(&id, &[("body", text)])
            .commit()
            .unwrap();
        let revision = server.vault().indexed_revision(&id).unwrap().unwrap();
        expected.push((receipt.claim_short_id, revision.to_hex()));
    }
    // More than 1,000 base-scope decoys outrank both targets even when
    // Light widens lexical admission for its temporal anchor and blends
    // recency, salience and confidence. One world-scoped target-predicate
    // decoy separately proves that the filtered view excludes other worlds.
    let old = memory
        .recall(
            "viewneedle",
            Effort::Light,
            &RecallScope::default(),
            1000,
            None,
            None,
        )
        .unwrap();
    assert!(
        !old.items
            .iter()
            .any(|item| expected.iter().any(|(id, _)| *id == item.short_id)),
        "unfiltered recall returned a filtered match among {} items ({} candidates)",
        old.items.len(),
        old.retrieval_meta.total_candidates,
    );
    let source = BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "scoped-top-k".into(),
    );
    for limit in [1, 2, 10] {
        let derived = source
            .derive(
                &ScopedView {
                    query: Some("viewneedle".into()),
                    filter: Some(json!({"kind":"CLAIM", "predicate":"view.target", "limit":limit})),
                    ..Default::default()
                },
                Channel::View,
            )
            .unwrap();
        let rows = derived.value.as_array().unwrap();
        let ids: Vec<_> = rows
            .iter()
            .map(|row| {
                (
                    row["short_id"].as_str().unwrap(),
                    row["source_revision_ref"].as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            ids,
            expected
                .iter()
                .take(limit)
                .map(|(id, revision)| (id.as_str(), revision.as_str()))
                .collect::<Vec<_>>()
        );
        assert!(rows.iter().all(|row| row["world"].is_null()));
    }
}

#[tokio::test]
async fn disjoint_entity_document_subscriptions_only_push_the_changed_view() {
    use oneiron::sync::bridge::LiveQueryTee;
    let (_dir, server) = server();
    let window_key = oneiron::sync::WindowKey::from_timestamp(AT);
    let window = server.get_or_create_window(&window_key).await.unwrap();
    let auth = auth(&server, "human");
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth,
        "entity-read-set".into(),
    ));
    let queries = Arc::new(subscriptions::LiveQueries::new(1, source.clone()));
    let tee: Arc<dyn LiveQueryTee> = queries.clone();
    server
        .reassert_manager
        .materializer()
        .attach_live_query_tee(&tee);
    let author = EntityId::from_hex(ACTOR).unwrap();
    let a = EntityId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let b = EntityId::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let put = |id: EntityId, subject: &str, predicate: &str, value: &str| {
        server
            .vault()
            .memory(author, EdgeActorClass::Human)
            .claim_upsert(&ClaimInput {
                id: Some(id.to_hex()),
                predicate: predicate.into(),
                subject_ref: subject.into(),
                value: json!(value),
                confidence: 1.0,
                source: "user_stated".into(),
                world_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: Some(AT),
                learned_at: Some(AT),
                salience: None,
                relationship_ref: None,
            })
            .unwrap();
        server
            .vault()
            .batch()
            .text(&id, &[("body", &format!("readsetneedle {value}"))])
            .commit()
            .unwrap();
        oneiron::sync::window::reverse_rematerialize(server.vault(), &window, &window_key).unwrap();
    };
    let view = |predicate: &str| ScopedView {
        query: Some("readsetneedle".into()),
        filter: Some(json!({"kind":"CLAIM", "predicate":predicate})),
        ..Default::default()
    };
    put(a, ACTOR, "profile.alpha", "first");
    put(b, ACTOR, "profile.beta", "second");
    for (id, predicate, entity) in [(1, "profile.alpha", a), (2, "profile.beta", b)] {
        let derived = source.derive(&view(predicate), Channel::View).unwrap();
        assert!(
            derived
                .dependencies
                .contains(&format!("e:{}", entity.to_hex()))
        );
        assert!(
            derived
                .dependencies
                .iter()
                .all(|dependency| !dependency.starts_with("w:"))
        );
        let frames = queries
            .open(id, view(predicate), Channel::View, None, None)
            .unwrap();
        assert!(
            !frames[0]
                .result
                .as_ref()
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
        queries.ack(id, &frames[0].cursor).unwrap();
    }
    queries.refresh().unwrap();
    let a_next = EntityId::from_hex("cccccccccccccccccccccccccccccccc").unwrap();
    // Another subject: a second value for one subject and predicate is a
    // Proposed supersession, which no view surfaces until it is confirmed.
    put(a_next, MACHINE, "profile.alpha", "new first");
    queries.refresh().unwrap();
    assert_eq!(queries.pending(1).unwrap().len(), 1);
    assert!(queries.pending(2).unwrap().is_empty());
    // A third, initially empty view learns a new member without a window wildcard.
    let frames = queries
        .open(3, view("profile.gamma"), Channel::View, None, None)
        .unwrap();
    queries.ack(3, &frames[0].cursor).unwrap();
    put(
        EntityId::from_hex("dddddddddddddddddddddddddddddddd").unwrap(),
        ACTOR,
        "profile.gamma",
        "third",
    );
    queries.refresh().unwrap();
    assert_eq!(queries.pending(3).unwrap().len(), 1);
    assert!(queries.pending(2).unwrap().is_empty());
}

#[tokio::test]
async fn subscription_resumes_at_indexed_position_while_editor_reads_live() {
    let (_dir, server) = server();
    let id = EntityId::from_hex("abababababababababababababababab").unwrap();
    let actor = EntityId::from_hex(ACTOR).unwrap();
    let put = |text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put("indexedcursor old");
    let indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "indexed-subscription".into(),
    ));
    let queries = subscriptions::LiveQueries::new(1, source.clone());
    let view = ScopedView {
        query: Some("indexedcursor".into()),
        ..Default::default()
    };
    let opened = queries
        .open(7, view.clone(), Channel::View, None, None)
        .unwrap();
    let cursor = opened[0].cursor.clone();
    assert!(
        opened[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("old")
    );
    let editor = server.vault().memory(actor, EdgeActorClass::Human);
    put("indexedcursor live");
    assert_ne!(server.vault().pin_entity_revision(&id).unwrap(), indexed);
    assert_eq!(
        editor
            .get_entity(&id.to_hex())
            .unwrap()
            .value
            .unwrap()
            .body
            .unwrap()["content"],
        "indexedcursor live"
    );
    assert_eq!(server.vault().indexed_revision(&id).unwrap(), Some(indexed));
    // Journal writes, editor reads, and an unindexed edit cannot move a sub VV.
    assert_eq!(
        source
            .derive(&view, Channel::View)
            .unwrap()
            .cursor
            .version_vector,
        cursor.version_vector
    );
    let resumed = queries
        .open(7, view.clone(), Channel::View, Some(&cursor), None)
        .unwrap();
    assert!(
        resumed.is_empty(),
        "the live edit must not appear in catch-up"
    );
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    assert!(
        report
            .refreshed
            .contains(&(id, server.vault().indexed_revision(&id).unwrap().unwrap()))
    );
    // Keep the logical session and ring across the index publication. A
    // reconnect before the hub timer runs must still derive the indexed tail.
    queries.reconnect(2).unwrap();
    let resumed = queries
        .open(7, view.clone(), Channel::View, Some(&cursor), None)
        .unwrap();
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].kind, "data");
    assert!(
        resumed[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("live")
    );
    assert_ne!(resumed[0].cursor.version_vector, cursor.version_vector);
    assert!(source.can_resume(&cursor).unwrap());

    // A metadata-only index publication changes the indexed position while
    // the body text stays unchanged. The pinned short ref and cursor move.
    let before = source.derive(&view, Channel::View).unwrap();
    let indexed_before = server.vault().indexed_revision(&id).unwrap();
    server
        .vault()
        .batch()
        .put(
            &id,
            oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
            oneiron::temporal::TimeRange {
                start: AT + 1,
                end: AT + 1,
            },
            AT + 1,
            &rmp_serde::to_vec_named(&json!({"content": "indexedcursor live"})).unwrap(),
        )
        .commit()
        .unwrap();
    assert_ne!(
        server.vault().indexed_revision(&id).unwrap(),
        indexed_before
    );
    let after = source.derive(&view, Channel::View).unwrap();
    assert_eq!(after.value[0]["value_text"], before.value[0]["value_text"]);
    assert_ne!(after.cursor.version_vector, before.cursor.version_vector);
}

#[tokio::test]
async fn indexed_publication_wakes_an_open_entity_subscription() {
    use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};

    let (_dir, server) = server();
    let id = EntityId::from_hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
    let put = |text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put("indexwake old");
    let indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let hub = connection::Hub::for_server(&server);
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "indexed-wake".into(),
    ));
    let queries = hub.install_source(auth(&server, "human"), "indexed-wake".into(), source);
    let tee: Arc<dyn LiveQueryTee> = queries.clone();
    server
        .reassert_manager
        .materializer()
        .attach_live_query_tee(&tee);
    let view = ScopedView {
        query: Some("indexwake".into()),
        ..Default::default()
    };
    let opened = queries.open(7, view, Channel::View, None, None).unwrap();
    let cursor = opened[0].cursor.clone();
    queries.ack(7, &cursor).unwrap();

    put("indexwake new");
    assert_eq!(server.vault().indexed_revision(&id).unwrap(), Some(indexed));
    let path = format!("e:{}", id.to_hex());
    tee.on_materialized(
        &path,
        &MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 0,

            revision_events: vec![revision_event(&server, id, Some(indexed))],
        },
        &OriginMark::default(),
    );
    queries.refresh().unwrap();
    assert!(
        queries.pending(7).unwrap().is_empty(),
        "live-only edit cannot push"
    );

    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    assert!(report.refreshed.iter().any(|(entity, _)| *entity == id));
    publish_indexed(&hub, &report, id, indexed);
    queries.refresh().unwrap();
    let pending = queries.pending(7).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].kind, "data");
    assert_ne!(pending[0].cursor.version_vector, cursor.version_vector);
    assert!(
        pending[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("indexwake new")
    );
}

#[tokio::test]
async fn earlier_index_commit_wakes_its_subscriber_when_later_provider_fails() {
    use oneiron::memory::{IndexedRevisionEmbedder, IndexedRevisionInput};

    struct FailsSecond(EntityId);
    impl IndexedRevisionEmbedder for FailsSecond {
        fn embed_revision(&self, input: &IndexedRevisionInput) -> oneiron::Result<Vec<f32>> {
            if input.entity == self.0 {
                Err(oneiron::Error::UpstreamToolFailure {
                    tool: "indexed test provider",
                    code: "unavailable".into(),
                })
            } else {
                {
                    let mut vector = vec![0.0; 1024];
                    vector[0] = 1.0;
                    Ok(vector)
                }
            }
        }
    }

    let mut config = oneiron::VaultConfig::device();
    config.embedding_model = Some("test/indexed-publication@v1".into());
    let (_dir, server) = server_with_config(config);
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    let a = EntityId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let b = EntityId::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let put = |id: EntityId, text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put(a, "firstpartial old");
    put(b, "secondpartial old");
    let indexed_b = server.vault().indexed_revision(&b).unwrap();
    let hub = connection::Hub::for_server(&server);
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "partial-index".into(),
    ));
    let queries = hub.install_source(auth(&server, "human"), "partial-index".into(), source);
    let view = |query: &str| ScopedView {
        query: Some(query.into()),
        ..Default::default()
    };
    for (sub, query) in [(1, "firstpartial"), (2, "secondpartial")] {
        let opened = queries
            .open(sub, view(query), Channel::View, None, None)
            .unwrap();
        assert_eq!(
            opened[0].result.as_ref().unwrap().as_array().unwrap().len(),
            1
        );
        queries.ack(sub, &opened[0].cursor).unwrap();
    }
    let indexed_a = server.vault().indexed_revision(&a).unwrap().unwrap();
    put(a, "firstpartial new");
    put(b, "secondpartial new");
    for id in [a, b] {
        let path = format!("e:{}", id.to_hex());
        oneiron::sync::bridge::LiveQueryTee::on_materialized(
            queries.as_ref(),
            &path,
            &oneiron::sync::bridge::MaterializedDiffSummary {
                containers: vec![path.clone()],
                bytes: 0,

                revision_events: vec![revision_event(
                    &server,
                    id,
                    Some(if id == a {
                        indexed_a
                    } else {
                        indexed_b.unwrap()
                    }),
                )],
            },
            &oneiron::sync::bridge::OriginMark::default(),
        );
    }
    queries.refresh().unwrap();
    assert!(queries.pending(1).unwrap().is_empty());
    assert!(queries.pending(2).unwrap().is_empty());
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    let outcome = server.vault().refresh_indexed_at_idle_with_publication(
        u64::MAX,
        &FailsSecond(b),
        |publication| hub.indexed_published(&[publication]),
    );
    assert!(
        matches!(outcome, Err(oneiron::Error::UpstreamToolFailure { .. })),
        "{outcome:?}"
    );
    assert_eq!(server.vault().indexed_revision(&b).unwrap(), indexed_b);
    queries.refresh().unwrap();
    let a_tail = queries.pending(1).unwrap();
    assert_eq!(a_tail.len(), 1);
    assert!(
        a_tail[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("firstpartial new")
    );
    assert!(queries.pending(2).unwrap().is_empty());
}

#[tokio::test]
async fn delayed_index_publication_filters_own_echo_but_delivers_foreign_and_mixed_writes() {
    use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};

    let (_dir, server) = server();
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    let id = EntityId::from_hex("cececececececececececececececece").unwrap();
    let put = |text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put("originwake old");
    let hub = connection::Hub::for_server(&server);
    let mut clients = Vec::new();
    for (conn, document) in [(1, "origin-one"), (2, "origin-two")] {
        let source = Arc::new(BoundSource::new(
            Arc::downgrade(&server),
            auth(&server, "human"),
            document.into(),
        ));
        let queries = hub.install_source(auth(&server, "human"), document.into(), source);
        queries.reconnect(conn).unwrap();
        let opened = queries
            .open(
                7,
                ScopedView {
                    query: Some("originwake".into()),
                    ..Default::default()
                },
                Channel::View,
                None,
                Some(format!("conn:{conn}")),
            )
            .unwrap();
        queries.ack(7, &opened[0].cursor).unwrap();
        clients.push(queries);
    }
    let path = format!("e:{}", id.to_hex());
    let last = std::cell::Cell::new(server.vault().indexed_revision(&id).unwrap().unwrap());
    let blob_hash = || *blake3::hash(&server.vault().get_raw(&id).unwrap().unwrap()).as_bytes();
    let notify = |by: OriginMark, _hash: [u8; 32]| {
        let live = server.vault().pin_entity_revision(&id).unwrap();
        let previous = last.replace(live);
        let event = if by.origin.as_deref() == Some(oneiron::sync::bridge::BRIDGE_ORIGIN) {
            oneiron::sync::bridge::RevisionEvent::Mirror {
                entity: id,
                source_revision: Some(live),
            }
        } else {
            oneiron::sync::bridge::RevisionEvent::Original(oneiron::memory::EntityRevisionChange {
                entity: id,
                previous_revision: Some(previous),
                revision: Some(live),
                indexed_revision: server.vault().indexed_revision(&id).unwrap(),
            })
        };
        let diff = MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 0,
            revision_events: vec![event],
        };
        for client in &clients {
            client.on_materialized(&path, &diff, &by);
        }
    };
    put("originwake writer");
    let writer_hash = blob_hash();
    notify(
        OriginMark {
            conn_id: Some(1),
            origin: Some("conn:1".into()),
        },
        writer_hash,
    );
    // Publish before the timer drains either the original edit or its mirror.
    notify(
        OriginMark {
            conn_id: None,
            origin: Some(oneiron::sync::bridge::BRIDGE_ORIGIN.into()),
        },
        writer_hash,
    );
    let previous_indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report, id, previous_indexed);
    for client in &clients {
        client.refresh().unwrap();
    }
    assert!(
        clients[0].pending(7).unwrap().is_empty(),
        "no coalesced writer echo"
    );
    let foreign = clients[1].pending(7).unwrap();
    assert_eq!(foreign.len(), 1);
    assert!(
        foreign[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("originwake writer")
    );
    clients[1].ack(7, &foreign[0].cursor).unwrap();

    // A distinct bridge-only LMDB commit is foreign, not a duplicate mirror.
    put("originwake independent");
    let independent_hash = blob_hash();
    assert_ne!(independent_hash, writer_hash);
    notify(
        OriginMark {
            conn_id: None,
            origin: Some(oneiron::sync::bridge::BRIDGE_ORIGIN.into()),
        },
        independent_hash,
    );
    for client in &clients {
        client.refresh().unwrap();
        assert!(
            client.pending(7).unwrap().is_empty(),
            "bridge-only live edit cannot push before index"
        );
    }
    let previous_indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report, id, previous_indexed);
    for client in &clients {
        client.refresh().unwrap();
        let tail = client.pending(7).unwrap();
        assert_eq!(tail.len(), 1);
        assert!(
            tail[0]
                .result
                .as_ref()
                .unwrap()
                .to_string()
                .contains("originwake independent")
        );
        client.ack(7, &tail[0].cursor).unwrap();
    }

    // Mixed clients in one indexed batch remain foreign to both writers.
    put("originwake interim");
    notify(
        OriginMark {
            conn_id: Some(1),
            origin: Some("conn:1".into()),
        },
        blob_hash(),
    );
    put("originwake foreign");
    notify(
        OriginMark {
            conn_id: Some(2),
            origin: Some("conn:2".into()),
        },
        blob_hash(),
    );
    for client in &clients {
        client.refresh().unwrap();
        assert!(client.pending(7).unwrap().is_empty());
    }
    let previous_indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report, id, previous_indexed);
    for client in &clients {
        client.refresh().unwrap();
        let tail = client.pending(7).unwrap();
        assert_eq!(tail.len(), 1);
        assert!(
            tail[0]
                .result
                .as_ref()
                .unwrap()
                .to_string()
                .contains("originwake foreign")
        );
    }
}

#[tokio::test]
async fn settled_out_of_view_births_do_not_exhaust_lag_origin_retention() {
    use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};

    let (_dir, server) = server();
    let hub = connection::Hub::for_server(&server);
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "bounded-lag-origins".into(),
    ));
    let queries = hub.install_source(auth(&server, "human"), "bounded-lag-origins".into(), source);
    let watched = EntityId::from_hex("dededededededededededededededede").unwrap();
    let put = |id: EntityId, text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put(watched, "lagcachemarker first");
    let opened = queries
        .open(
            9,
            ScopedView {
                query: Some("lagcachemarker".into()),
                ..Default::default()
            },
            Channel::View,
            None,
            None,
        )
        .unwrap();
    queries.ack(9, &opened[0].cursor).unwrap();
    for number in 0_u64..700 {
        let mut bytes = [0x73_u8; 16];
        bytes[8..].copy_from_slice(&number.to_be_bytes());
        let id = EntityId::from_bytes(bytes).unwrap();
        put(id, "unrelated birth");
        assert!(server.vault().indexed_revision(&id).unwrap().is_some());
        let path = format!("e:{}", id.to_hex());
        queries.on_materialized(
            &path,
            &MaterializedDiffSummary {
                containers: vec![path.clone()],
                bytes: 0,

                revision_events: Vec::new(),
            },
            &OriginMark {
                conn_id: Some(1),
                origin: Some("conn:1".into()),
            },
        );
        queries.refresh().unwrap();
        assert!(
            queries.pending(9).unwrap().is_empty(),
            "unrelated settled birth {number} caused a gap"
        );
    }
    let prior = server.vault().indexed_revision(&watched).unwrap().unwrap();
    put(watched, "lagcachemarker second");
    let path = format!("e:{}", watched.to_hex());
    queries.on_materialized(
        &path,
        &MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 0,

            revision_events: vec![revision_event(&server, watched, Some(prior))],
        },
        &OriginMark::default(),
    );
    queries.refresh().unwrap();
    // Until idle publication, the indexed view is unchanged.
    assert!(queries.pending(9).unwrap().is_empty());
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    let previous_indexed = server.vault().indexed_revision(&watched).unwrap().unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report, watched, previous_indexed);
    queries.refresh().unwrap();
    let tail = queries.pending(9).unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].kind, "data");
    assert!(
        tail[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("lagcachemarker second")
    );
}

#[tokio::test]
async fn a_session_opened_after_live_edit_resyncs_when_its_missing_revision_is_indexed() {
    let (_dir, server) = server();
    let id = EntityId::from_hex("edededededededededededededededed").unwrap();
    let put = |text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put("latejoincursor old");
    let indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    put("latejoincursor new"); // the subscription owner does not exist yet
    assert_eq!(server.vault().indexed_revision(&id).unwrap(), Some(indexed));
    let hub = connection::Hub::for_server(&server);
    let source = Arc::new(BoundSource::new(
        Arc::downgrade(&server),
        auth(&server, "human"),
        "latejoin".into(),
    ));
    let queries = hub.install_source(auth(&server, "human"), "latejoin".into(), source);
    let view = ScopedView {
        query: Some("latejoincursor".into()),
        ..Default::default()
    };
    let opened = queries
        .open(7, view.clone(), Channel::View, None, None)
        .unwrap();
    assert!(
        opened[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("old")
    );
    let old_cursor = opened[0].cursor.clone();
    queries.ack(7, &old_cursor).unwrap();
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    let report = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report, id, indexed);
    queries.refresh().unwrap();
    let gap = queries.pending(7).unwrap();
    assert_eq!(gap.len(), 1);
    assert_eq!(gap[0].kind, "gap");
    let replay = queries
        .open(7, view, Channel::View, Some(&old_cursor), None)
        .unwrap();
    assert!(replay.iter().any(|push| {
        push.result
            .as_ref()
            .is_some_and(|value| value.to_string().contains("new"))
    }));
}

#[tokio::test]
async fn newer_unindexed_writer_does_not_poison_older_indexed_publication_echo() {
    use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark, RevisionEvent};
    let (_dir, server) = server();
    server.vault().set_indexed_idle_delay_ms(0).unwrap();
    server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    let id = EntityId::from_hex("fefefefefefefefefefefefefefefefe").unwrap();
    let put = |text: &str| {
        server
            .vault()
            .batch()
            .put(
                &id,
                oneiron::registry::ENTITY_TYPE_ASSET_TEXT,
                oneiron::temporal::TimeRange { start: AT, end: AT },
                AT,
                &rmp_serde::to_vec_named(&json!({"content": text})).unwrap(),
            )
            .text(&id, &[("content", text)])
            .commit()
            .unwrap();
    };
    put("twoadvance old");
    let indexed = server.vault().indexed_revision(&id).unwrap().unwrap();
    let hub = connection::Hub::for_server(&server);
    let mut clients = Vec::new();
    for conn in [1, 2] {
        let document = format!("twoadvance-{conn}");
        let source = Arc::new(BoundSource::new(
            Arc::downgrade(&server),
            auth(&server, "human"),
            document.clone(),
        ));
        let queries = hub.install_source(auth(&server, "human"), document, source);
        queries.reconnect(conn).unwrap();
        let opened = queries
            .open(
                7,
                ScopedView {
                    query: Some("twoadvance".into()),
                    ..Default::default()
                },
                Channel::View,
                None,
                Some(format!("conn:{conn}")),
            )
            .unwrap();
        queries.ack(7, &opened[0].cursor).unwrap();
        clients.push(queries);
    }
    let notify = |previous, revision, indexed_revision, conn| {
        let path = format!("e:{}", id.to_hex());
        let diff = MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 0,
            revision_events: vec![RevisionEvent::Original(
                oneiron::memory::EntityRevisionChange {
                    entity: id,
                    previous_revision: Some(previous),
                    revision: Some(revision),
                    indexed_revision: Some(indexed_revision),
                },
            )],
        };
        for client in &clients {
            client.on_materialized(
                &path,
                &diff,
                &OriginMark {
                    conn_id: Some(conn),
                    origin: Some(format!("conn:{conn}")),
                },
            );
        }
    };
    put("twoadvance first");
    let r1 = server.vault().pin_entity_revision(&id).unwrap();
    notify(indexed, r1, indexed, 1);
    for client in &clients {
        client.refresh().unwrap();
        assert!(client.pending(7).unwrap().is_empty());
    }
    let report1 = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    // The index committed R1 but its callback is delayed behind writer 2.
    put("twoadvance second");
    let r2 = server.vault().pin_entity_revision(&id).unwrap();
    notify(r1, r2, r1, 2);
    publish_indexed(&hub, &report1, id, indexed);
    for client in &clients {
        client.refresh().unwrap();
    }
    assert!(
        clients[0].pending(7).unwrap().is_empty(),
        "writer 1 must not receive R1 echo"
    );
    let first = clients[1].pending(7).unwrap();
    assert_eq!(first.len(), 1);
    assert!(
        first[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("twoadvance first")
    );
    clients[1].ack(7, &first[0].cursor).unwrap();
    let report2 = server
        .vault()
        .refresh_staged_indexed_at_idle(u64::MAX)
        .unwrap();
    publish_indexed(&hub, &report2, id, r1);
    for client in &clients {
        client.refresh().unwrap();
    }
    assert!(
        clients[1].pending(7).unwrap().is_empty(),
        "writer 2 must not receive R2 echo"
    );
    let second = clients[0].pending(7).unwrap();
    assert_eq!(second.len(), 1);
    assert!(
        second[0]
            .result
            .as_ref()
            .unwrap()
            .to_string()
            .contains("twoadvance second")
    );
}

fn owner_feed_fixture() -> (
    tempfile::TempDir,
    Arc<SyncServer>,
    EntityId,
    EntityId,
    CoreAuth,
) {
    let (_dir, server) = server();
    oneiron::campaign::register_crm_pack(
        server.vault(),
        107,
        108,
        oneiron::registry::TypeByteFamily::Productivity,
    )
    .unwrap();
    let actor = EntityId::from_hex(ACTOR).unwrap();
    let anchor = EntityId::now();
    let body = oneiron::ClaimBody::new(
        "profile.name",
        oneiron::ClaimSubject::Entity(actor),
        rmpv::Value::from("Original name"),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    server
        .vault()
        .put_claim(
            &anchor,
            &body,
            oneiron::TimeRange { start: AT, end: AT },
            AT,
        )
        .unwrap();
    crate::test_credentials::bind_owner(server.vault(), SECRET, actor);
    let owner_recipe = format!("principal_ref={ACTOR};actor_class=human;jti=watch-owner");
    let owner = crate::test_credentials::authenticate(&server, &owner_recipe);
    assert!(owner.is_owner_grade());
    (_dir, server, actor, anchor, owner)
}

#[tokio::test]
async fn owner_feed_uses_persisted_watches_and_refuses_agent_subscribers() {
    let (_dir, server, actor, anchor, owner) = owner_feed_fixture();
    let source = BoundSource::new(Arc::downgrade(&server), owner.clone(), "watch-doc".into());
    let initial = source
        .derive(&ScopedView::default(), Channel::OwnerFeed)
        .unwrap();
    assert_eq!(initial.value, json!([]));
    let subscribed = subscriptions::LiveQueries::new(
        17,
        Arc::new(BoundSource::new(
            Arc::downgrade(&server),
            owner,
            "watch-subscribed".into(),
        )),
    );
    subscribed
        .open(3, ScopedView::default(), Channel::OwnerFeed, None, None)
        .unwrap();
    let watch = oneiron::saved_query::set_memory_watch(server.vault(), actor, anchor, true, AT + 1)
        .unwrap()
        .unwrap();
    // A local LMDB write has no Loro tee event. The bounded poll still
    // generates a normal retained sub.data push without an explicit mirror.
    subscribed.owner_feed_poll_now();
    subscribed.refresh().unwrap();
    let active = source
        .derive(&ScopedView::default(), Channel::OwnerFeed)
        .unwrap();
    let buffered = subscribed.buffered().unwrap();
    assert!(
        buffered.iter().any(|push| {
            push.kind == "data"
                && push
                    .result
                    .as_ref()
                    .is_some_and(|result| result[0]["query_ref"] == watch.query_ref.to_hex())
        }),
        "buffered={buffered:?}; direct={:?}",
        active.value
    );
    assert_eq!(active.value[0]["query_ref"], watch.query_ref.to_hex());
    assert_eq!(active.value[0]["timeline"]["anchor_id"], anchor.to_hex());
    let next = EntityId::now();
    let mut successor = server.vault().get_claim(&anchor).unwrap().unwrap();
    successor.value = rmpv::Value::from("Updated name");
    server
        .vault()
        .put_claim(
            &next,
            &successor,
            oneiron::TimeRange {
                start: AT + 2,
                end: AT + 2,
            },
            AT + 2,
        )
        .unwrap();
    server
        .vault()
        .supersede_claim(&next, &anchor, AT + 3)
        .unwrap();
    subscribed.owner_feed_poll_now();
    subscribed.refresh().unwrap();
    assert!(subscribed.buffered().unwrap().iter().any(|push| {
        push.kind == "data"
            && push.result.as_ref().is_some_and(|result| {
                result[0]["timeline"]["records"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 2)
            })
    }));
    // A live credential does not imply that an old queued body is still
    // readable. Narrow the row while an update is retained and test all
    // three exits: socket delivery, same-ID reconnect and new-ID replay.
    let acked = subscribed
        .buffered()
        .unwrap()
        .last()
        .unwrap()
        .cursor
        .clone();
    subscribed.ack(3, &acked).unwrap();
    let mut hidden = server.vault().get_claim(&next).unwrap().unwrap();
    hidden.stale = true;
    server
        .vault()
        .put_claim(
            &next,
            &hidden,
            oneiron::TimeRange {
                start: AT + 2,
                end: AT + 2,
            },
            AT + 2,
        )
        .unwrap();
    let queued = subscribed.buffered().unwrap();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].kind, "data", "{queued:?}");
    assert!(
        !serde_json::to_string(&queued)
            .unwrap()
            .contains("Updated name")
    );
    let assert_scrubbed = |pushes: &[subscriptions::Push]| {
        let wire = serde_json::to_string(pushes).unwrap();
        assert!(!wire.contains("Updated name"), "retained secret: {wire}");
        assert_eq!(pushes[0].kind, "gap", "{wire}");
        assert!(pushes.iter().any(|push| push.kind == "snapshot"));
    };
    let same = subscribed
        .open(
            3,
            ScopedView::default(),
            Channel::OwnerFeed,
            Some(&acked),
            None,
        )
        .unwrap();
    assert_scrubbed(&same);
    let other = subscribed
        .open(
            4,
            ScopedView::default(),
            Channel::OwnerFeed,
            Some(&acked),
            None,
        )
        .unwrap();
    assert_scrubbed(&other);
    let agent = crate::test_credentials::authenticate(
        &server,
        &format!("principal_ref={ACTOR};actor_class=agent;jti=watch-agent"),
    );
    let Err(denied) = BoundSource::new(Arc::downgrade(&server), agent, "agent-doc".into())
        .derive(&ScopedView::default(), Channel::OwnerFeed)
    else {
        panic!("agent must not subscribe to owner feed")
    };
    assert_eq!(error_body(denied)["code"], "FORBIDDEN");
    let false_human = crate::test_credentials::authenticate(
        &server,
        &format!("principal_ref={MACHINE};actor_class=human;jti=watch-false-human"),
    );
    let Err(denied) = BoundSource::new(Arc::downgrade(&server), false_human, "machine-doc".into())
        .derive(&ScopedView::default(), Channel::OwnerFeed)
    else {
        panic!("human claim on a MACHINE must not grant owner feed")
    };
    assert_eq!(error_body(denied)["code"], "FORBIDDEN");
    oneiron::saved_query::set_memory_watch(server.vault(), actor, anchor, false, AT + 2).unwrap();
    assert_eq!(
        source
            .derive(&ScopedView::default(), Channel::OwnerFeed)
            .unwrap()
            .value,
        json!([])
    );
}

#[tokio::test]
async fn owner_feed_socket_delivers_two_local_changes_without_reopen_or_poll() {
    let (_dir, server, actor, anchor, owner) = owner_feed_fixture();
    let hub = connection::Hub::for_server(&server);
    let mut socket = connection::Connection::new(hub, 31);
    let opened = socket
        .control(
            &owner,
            SubRequest::Open {
                subscription_id: 9,
                scoped_view: ScopedView::default(),
                channel: Channel::OwnerFeed,
                cursor: None,
                origin: None,
            },
        )
        .unwrap();
    let snapshot = test_wire::reply(&opened);
    assert_eq!(snapshot["result"], json!([]));
    socket
        .control(
            &owner,
            SubRequest::Ack {
                subscription_id: 9,
                cursor: serde_json::from_value(snapshot["cursor"].clone()).unwrap(),
            },
        )
        .unwrap();

    // No forced owner_feed_poll_now() and no materializer notification:
    // delivery happens before the one-second synthetic poll can run.
    oneiron::saved_query::set_memory_watch(server.vault(), actor, anchor, true, AT + 1).unwrap();
    let first = test_wire::reply(&socket.delivery().unwrap());
    assert_eq!(first["kind"], "data", "{first:#}");
    assert_eq!(
        first["result"][0]["timeline"]["records"][0]["item"]["val"],
        "Original name"
    );

    let mut changed = server.vault().get_claim(&anchor).unwrap().unwrap();
    changed.value = rmpv::Value::from("Second name");
    server
        .vault()
        .put_claim(
            &anchor,
            &changed,
            oneiron::TimeRange { start: AT, end: AT },
            AT,
        )
        .unwrap();
    let second = test_wire::reply(&socket.delivery().unwrap());
    assert_eq!(second["kind"], "data", "{second:#}");
    assert_eq!(
        second["result"][0]["timeline"]["records"][0]["item"]["val"],
        "Second name"
    );

    // C1's body was coalesced away by C2, but its delayed ACK is still
    // valid and must not consume C2. Replay after transport lag is the
    // observable proof that C2 remains pending.
    let c1: Cursor = serde_json::from_value(first["cursor"].clone()).unwrap();
    let c2: Cursor = serde_json::from_value(second["cursor"].clone()).unwrap();
    assert!(
        socket
            .control(
                &owner,
                SubRequest::Ack {
                    subscription_id: 9,
                    cursor: c1,
                }
            )
            .unwrap()
            .is_empty()
    );
    socket.replay_after_lag();
    let pending = test_wire::reply(&socket.delivery().unwrap());
    assert_eq!(pending["cursor"], second["cursor"]);
    assert_eq!(pending["result"], second["result"]);
    assert!(
        socket
            .control(
                &owner,
                SubRequest::Ack {
                    subscription_id: 9,
                    cursor: c2.clone(),
                }
            )
            .unwrap()
            .is_empty()
    );
    let mut invented = c2;
    invented.batch += 1_000;
    let refused = socket
        .control(
            &owner,
            SubRequest::Ack {
                subscription_id: 9,
                cursor: invented,
            },
        )
        .unwrap();
    assert_eq!(test_wire::reply(&refused)["error"]["code"], "BAD_REQUEST");

    let next = EntityId::now();
    changed.value = rmpv::Value::from("Third name");
    server
        .vault()
        .put_claim(
            &next,
            &changed,
            oneiron::TimeRange {
                start: AT + 2,
                end: AT + 2,
            },
            AT + 2,
        )
        .unwrap();
    server
        .vault()
        .supersede_claim(&next, &anchor, AT + 3)
        .unwrap();
    let third = test_wire::reply(&socket.delivery().unwrap());
    assert_eq!(third["kind"], "data", "{third:#}");
    assert_eq!(
        third["result"][0]["timeline"]["records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(socket.has_active_subscriptions());
}
