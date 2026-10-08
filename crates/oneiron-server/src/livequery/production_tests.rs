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
use oneiron::memory::{ClaimInput, WitnessAuthor, WitnessMessage, WitnessReceipt, WitnessTurn};
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
        server.vault(),
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
