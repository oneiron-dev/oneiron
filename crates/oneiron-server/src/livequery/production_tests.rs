#![allow(clippy::unwrap_used)]
//! Real vault, verified slips and production facade/source; no injected read source.
use super::source::BoundSource;
use super::subscriptions::LiveQuerySource;
use super::*;
use crate::auth::{mint_core_token_v2, revoke_token_jti};
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use oneiron::memory::{
    ClaimInput, ClaimListFilter, NeighborOpts, WitnessAuthor, WitnessMessage, WitnessReceipt,
    WitnessTurn,
};
use oneiron::{EdgeActorClass, EntityId};
use std::sync::Arc;

pub(super) const SECRET: &str = "production-app-tier-owner";
pub(super) const ACTOR: &str = "11111111111111111111111111111111";
pub(super) const JTI: &str = "22222222222222222222222222222222";
const MACHINE: &str = "33333333333333333333333333333333";
const CONVERSATION: &str = "44444444444444444444444444444444";
pub(super) const AT: u64 = 1_772_000_000;

pub(super) fn server() -> (tempfile::TempDir, Arc<SyncServer>) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
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

pub(super) fn token(class: &str) -> String {
    let actor = if class == "system" { MACHINE } else { ACTOR };
    mint_core_token_v2(
        SECRET,
        &format!("scope=core:read;principal_ref={actor};actor_class={class};jti={JTI}"),
    )
}

fn auth(server: &SyncServer, class: &str) -> CoreAuth {
    CoreAuth::from_bind_token(&token(class), &server.config, server.vault().as_ref()).unwrap()
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
                metadata: None,
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
        server.vault(),
        auth,
        RpcRequest {
            request_id: 7,
            method: method.to_owned(),
            params,
        },
    )
    .unwrap();
    assert_eq!(frame[0], TAG_RPC);
    let reply: Value = serde_json::from_slice(&frame[1..]).unwrap();
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
        assert_eq!(
            rpc(&server, &auth, "hydrate", json!({"refs":[]}))["result"],
            json!([])
        );
    }
    let classless = mint_core_token_v2(SECRET, &format!("scope=core:read;principal_ref={ACTOR}"));
    let auth =
        CoreAuth::from_bind_token(&classless, &server.config, server.vault().as_ref()).unwrap();
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
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("authorization", format!("Bearer {SECRET}").parse().unwrap());
    let owner = CoreAuth::from_headers(&headers, &server.config, server.vault().as_ref()).unwrap();
    let reply = rpc(&server, &owner, "receipts", json!({}));
    assert_error(&reply, "FORBIDDEN");
    assert_eq!(
        reply["error"]["message"],
        "facade routes bind writes to an authenticated principal"
    );
    for class in ["Human", "owner", ""] {
        assert!(
            CoreAuth::from_bind_token(&token(class), &server.config, server.vault().as_ref())
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
    let memory = server
        .vault()
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human);
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
                        Effort::Standard,
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
    let classless = mint_core_token_v2(SECRET, &format!("scope=core:read;principal_ref={ACTOR}"));
    let classless =
        CoreAuth::from_bind_token(&classless, &server.config, server.vault().as_ref()).unwrap();
    assert_error(
        &rpc(&server, &classless, "recall", json!({})),
        "BAD_REQUEST",
    );
    let write_only = mint_core_token_v2(
        SECRET,
        &format!("scope=core:write;principal_ref={ACTOR};actor_class=human"),
    );
    let write_only =
        CoreAuth::from_bind_token(&write_only, &server.config, server.vault().as_ref()).unwrap();
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
            json!({"query":"solar","effort":"deep"}),
            memory
                .recall(
                    "solar",
                    Effort::Deep,
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
        .memory(EntityId::from_hex(ACTOR).unwrap(), EdgeActorClass::Human);
    let expected = memory
        .recall(
            "solar",
            Effort::Minimal,
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
            Effort::Minimal,
            &RecallScope {
                world_ref: None,
                facet: missing_facet.facet.clone(),
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
    revoke_token_jti(server.vault(), JTI).unwrap();
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
