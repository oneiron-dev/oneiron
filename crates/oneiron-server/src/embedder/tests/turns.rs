//! Turns are the embedding unit (ARCH-0004): a witnessed conversation is
//! found by what it meant, through the shipped doors — the facade witness,
//! the embedding worker and the facade recall — with the concept mock
//! standing in for a model.

use axum::body::{Body, to_bytes};
use axum::http::Request;
use oneiron::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
use tower::ServiceExt;

use super::*;

const SECRET: &str = "turn-embedding-secret";
/// 2026-01-01T00:00:00Z.
const DAY0: u64 = 1_767_225_600;

/// A served vault with an embedder and a running worker.
struct Served {
    server: Arc<crate::server::SyncServer>,
    vault: Arc<oneiron::Vault>,
    owner: oneiron::EntityId,
    slip: String,
    key: String,
    _mock: MockEndpoint,
    _dir: tempfile::TempDir,
}

impl Served {
    fn start() -> Self {
        let mock = MockEndpoint::start(MockBehaviour::Concepts);
        let dir = tempfile::tempdir().unwrap();
        let vault = test_vault(dir.path());
        let owner = vault.ensure_embedded_owner_actor().unwrap();
        let config = EmbedderConfig {
            idle_interval_ms: 20,
            ..endpoint_config(&mock.base)
        };
        let slot = EmbedderSlot::from_config(&config).unwrap().unwrap();
        let server = Arc::new(
            crate::server::SyncServer::new(
                Arc::clone(&vault),
                crate::config::SyncServerConfig {
                    auth_secret: Some(SECRET.to_owned()),
                    ..Default::default()
                },
            )
            .unwrap()
            .with_embedder(Some(slot)),
        );
        let (slip, key) = crate::test_credentials::credential(
            &server,
            &format!(
                "scope=core:read,core:write;principal_ref={};actor_class=human",
                owner.to_hex()
            ),
        );
        Self {
            server,
            vault,
            owner,
            slip,
            key,
            _mock: mock,
            _dir: dir,
        }
    }

    async fn post(&self, verb: &str, payload: Value) -> Value {
        let request = crate::test_credentials::bind_slip_request(
            &self.server,
            &self.slip,
            &self.key,
            Request::builder()
                .method("POST")
                .uri(format!("/v1/core/facade/{verb}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        );
        let response = crate::build_app(Arc::clone(&self.server))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
        assert_eq!(status, StatusCode::OK, "{verb}: {bytes:?}");
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Witnesses one turn of `author`'s messages; returns the receipt.
    async fn witness(&self, conversation: &str, at: u64, author: &str, texts: &[&str]) -> Value {
        let messages = texts
            .iter()
            .enumerate()
            .map(|(order, text)| {
                json!({"author": author, "message_type": "text", "content": text,
                       "is_visible": true, "order": order})
            })
            .collect::<Vec<_>>();
        self.post(
            "witness",
            json!({"conversation_ref": conversation, "occurred_at": at, "messages": messages}),
        )
        .await
    }

    /// Recalls `query` until `done` holds or 30 s pass, while the worker fills
    /// vectors; returns the last pack.
    async fn recall_until(&self, query: &str, limit: u32, done: impl Fn(&Value) -> bool) -> Value {
        let mut pack = Value::Null;
        for _ in 0..600 {
            pack = self
                .post("recall", json!({"query": query, "limit": limit}))
                .await;
            if done(&pack) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        pack
    }

    /// A short conversation about the car, and others about other things.
    /// Returns the car turn's receipt.
    async fn witness_conversations(&self) -> Value {
        let car = self
            .witness(
                &"21".repeat(16),
                DAY0,
                "user",
                &["ok", "The mechanic says the automobile needs new brakes."],
            )
            .await;
        self.witness(
            &"21".repeat(16),
            DAY0 + 60,
            "assistant",
            &["Thanks, I will book it for Thursday."],
        )
        .await;
        for (index, text) in [
            "Bring the vehicle to the shop.",
            "The quarterly report is due on the fifth.",
            "Remember to water the basil on the balcony.",
        ]
        .into_iter()
        .enumerate()
        {
            self.witness(
                &format!("{:02}", 31 + index).repeat(16),
                DAY0,
                "user",
                &[text],
            )
            .await;
        }
        car
    }
}

fn items(pack: &Value) -> Vec<Value> {
    pack["items"].as_array().cloned().unwrap_or_default()
}

/// The TURN with this witness receipt, among a pack's items.
fn turn_item(pack: &Value, receipt: &Value) -> Option<Value> {
    items(pack)
        .into_iter()
        .find(|item| item["kind"] == "TURN" && item["short_id"] == receipt["turn_short_id"])
}

fn run(test: impl AsyncFnOnce(&Served)) {
    let served = Served::start();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let worker = served.server.spawn_embedding_worker().unwrap();
        test(&served).await;
        worker.abort();
    });
    runtime.shutdown_background();
}

/// Done-means (9B): witness a short conversation, then recall a paraphrase
/// that shares no word with it; the turn comes back, quoting the whole turn.
/// On main a witnessed turn was never embedded and recall left turns out, so
/// the query found nothing it said.
#[test]
fn a_paraphrase_finds_the_conversation_turn_it_shares_no_word_with() {
    run(async |served| {
        let car = served.witness_conversations().await;
        let pack = served
            .recall_until("car repair garage", 3, |pack| {
                turn_item(pack, &car).is_some()
            })
            .await;
        let turn = turn_item(&pack, &car).unwrap_or_else(|| panic!("{car}: {pack}"));
        assert_eq!(pack["retrieval_meta"]["sparse"], json!(false), "{pack}");
        assert_eq!(
            turn["value_text"], "ok\nThe mechanic says the automobile needs new brakes.",
            "a turn reads as its messages, in order"
        );
    });
}

/// 9B: one recall result never holds both a TURN and one of its MESSAGEs. A
/// lexical hit on a message comes back as its turn, which quotes it.
#[test]
fn a_recall_never_returns_a_turn_beside_its_own_message() {
    run(async |served| {
        let car = served.witness_conversations().await;
        // Once the turn has its vector, the words hit the car message and
        // their meaning hits its turn.
        served
            .recall_until("car repair garage", 3, |pack| {
                turn_item(pack, &car).is_some()
            })
            .await;
        let pack = served
            .post(
                "recall",
                json!({"query": "automobile mechanic", "limit": 5}),
            )
            .await;
        let turn = turn_item(&pack, &car).unwrap_or_else(|| panic!("{car}: {pack}"));
        assert_eq!(
            turn["cited_messages"],
            json!([{
                "short_id": car["message_short_ids"][1],
                "value_text": "The mechanic says the automobile needs new brakes.",
            }]),
            "the turn quotes the message the words matched: {pack}"
        );
        let turns = items(&pack)
            .into_iter()
            .filter(|item| item["kind"] == "TURN")
            .map(|item| item["provenance"]["source_revision_ids"][0].clone())
            .collect::<Vec<_>>();
        for item in items(&pack).iter().filter(|item| item["kind"] == "MESSAGE") {
            let parents = item["provenance"]["evidence_turn_ids"].as_array().unwrap();
            assert!(
                parents.iter().all(|turn| !turns.contains(turn)),
                "a message beside its own turn: {pack}"
            );
        }
    });
}

/// 9B: an edit to a message embeds its turn again. The old words no longer
/// find the turn first; the new ones do.
#[test]
fn an_edited_message_embeds_its_turn_again() {
    run(async |served| {
        let car = served.witness_conversations().await;
        let first = |pack: &Value| items(pack).first().cloned().unwrap_or(Value::Null);
        let pack = served
            .recall_until("car repair garage", 1, |pack| {
                turn_item(pack, &car).is_some()
            })
            .await;
        assert!(turn_item(&pack, &car).is_some(), "{car}: {pack}");

        let message = served
            .vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_MESSAGE)
            .unwrap()
            .into_iter()
            .find(|id| {
                let body = served.vault.get(id).unwrap().unwrap();
                let body: Value = rmp_serde::from_slice(&body).unwrap();
                body["content"] == "The mechanic says the automobile needs new brakes."
            })
            .unwrap();
        let writer = oneiron::WriteActor::new(served.owner, oneiron::EdgeActorClass::Human);
        let owner = served
            .vault
            .authenticate_owner(
                served.owner,
                &served.owner.to_hex(),
                true,
                oneiron::store::GateDecisionId::now(),
            )
            .unwrap();
        let authorization = DocAuthorization::Owner(&owner);
        served
            .vault
            .migrate_entity_text(
                &message,
                &TextField::MapField("content".into()),
                writer,
                &authorization,
            )
            .unwrap();
        let end = served.vault.entity_text(&message).unwrap().chars().count();
        let whole = served.vault.entity_text_anchor(&message, 0, end).unwrap();
        served
            .vault
            .edit_entity_text(
                &message,
                &[AnchoredEdit {
                    actor: Some(writer),
                    verb: EditVerb::ReplaceQuotedSpan {
                        span: whole,
                        text: "We met for a meal at noon.".into(),
                    },
                }],
                &authorization,
                DAY0 + 120,
            )
            .unwrap();

        // The vehicle turn now matches the old meaning best.
        let pack = served
            .recall_until("car repair garage", 1, |pack| {
                turn_item(pack, &car).is_none()
            })
            .await;
        assert!(
            turn_item(&pack, &car).is_none(),
            "the old words still find the edited turn: {pack}"
        );
        let pack = served
            .recall_until("lunch meal", 1, |pack| turn_item(pack, &car).is_some())
            .await;
        assert_eq!(
            first(&pack)["value_text"],
            "ok\nWe met for a meal at noon.",
            "the new words find the turn as edited: {pack}"
        );
    });
}
