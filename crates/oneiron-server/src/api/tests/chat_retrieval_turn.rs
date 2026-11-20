//! A live chat turn's board recall names, on its retrieval run, the TURN the
//! user's words are witnessed in and that TURN's conversation (FIX
//! RETRIEVAL-TURN-CONVENTION-HOST-STAMP), the convention the engine's
//! natural outcome producer reads to label the run from the user's later
//! words. Capture is on here; it is off by default. A later correction the
//! user states in that conversation labels the chat turn's own run at the
//! owner's `vault.retrieval.policy.update` (#8444's producer).
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::{GateDecisionId, RetrievalRunRecord, RetrievalTurn};
use oneiron::verbs::{RetrievalPolicyTrainRequest, retrieval_policy_update_as_owner};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, models};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::SyncServer;

/// A rooted vault that captures retrieval runs, served with a chat seat on
/// `base_url`.
pub(super) async fn capturing_server(
    base_url: &str,
) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    let vault = Arc::new(Vault::open(dir.path(), config).unwrap());
    crate::test_credentials::install_fixture_keystore(&vault, TEST_SECRET.as_bytes());
    let issuer = vault.bootstrap_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault.provision_engine_machine_identities(&issuer).unwrap();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (server, host) = AiHost::attach(server, Some(&models(base_url, ""))).await;
    (dir, Arc::new(server), host)
}

/// One owner chat turn in `conversation`, from this device; its NDJSON
/// lines once the reply is saved.
pub(super) async fn chat_turn(
    server: &Arc<SyncServer>,
    conversation: &str,
    text: &str,
) -> Vec<Value> {
    let body = json!({"conversation_ref": conversation, "text": text, "stream": true});
    let mut request: Request<Body> =
        core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body));
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            std::net::Ipv4Addr::LOCALHOST,
            40_000,
        ))));
    let request = slip_credentials::bind_request(server, request);
    let server = Arc::clone(server);
    let body = crate::test_engine_stack::on_engine_stack(async move {
        let response = api_routes(server)
            .oneshot(request)
            .await
            .expect("route response");
        assert_eq!(response.status(), StatusCode::OK);
        to_bytes(response.into_body(), usize::MAX).await.unwrap()
    })
    .await;
    let lines: Vec<Value> = body
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("NDJSON line"))
        .collect();
    assert_eq!(
        lines.last().map(|line| line["type"].clone()),
        Some(json!("saved")),
        "{lines:?}"
    );
    lines
}

/// The turns the vault's captured runs name, oldest run first.
fn stamped_turns(vault: &Vault) -> Vec<RetrievalTurn> {
    let mut runs = vault.retrieval_runs(64).unwrap();
    assert!(
        !runs.is_empty(),
        "capture is on, so the board's recall writes a run"
    );
    runs.sort_by_key(|run| run.started_at);
    runs.into_iter().filter_map(|run| run.turn).collect()
}

/// Whether `turn` is a TURN of `conversation` that holds a MESSAGE with
/// `text`: the TURN the user's words were witnessed in.
fn witnessed_user_turn(
    vault: &Vault,
    conversation: &EntityId,
    turn: &EntityId,
    text: &str,
) -> bool {
    let of_conversation = vault
        .sources(conversation, EdgeKind::ChildOf, None)
        .unwrap()
        .contains(turn);
    let holds_text = vault
        .sources(turn, EdgeKind::ChildOf, None)
        .unwrap()
        .iter()
        .any(|message| {
            vault
                .get(message)
                .unwrap()
                .is_some_and(|raw| String::from_utf8_lossy(&raw).contains(text))
        });
    of_conversation && holds_text
}

#[tokio::test]
async fn a_chat_turns_recall_names_the_witnessed_user_turn_and_its_conversation() {
    let fake = FakeLlm::start(
        Vec::new(),
        Some(Reply::Text {
            text: "noted".into(),
            model: "fake".into(),
        }),
    )
    .await;
    let (_dir, server, host) = capturing_server(&fake.base_url).await;
    let vault = server.vault();
    let conversation = EntityId::now();

    chat_turn(&server, &conversation.to_hex(), "my sister lives in Lisbon").await;
    let first = stamped_turns(vault);
    assert_eq!(
        first.len(),
        1,
        "the turn's board recall names its turn: {first:?}"
    );
    let first = first[0];
    assert_eq!(first.episode_id, *conversation.as_bytes());
    assert_eq!(first.turn_idx, 0, "the conversation's first TURN");
    let first_turn = EntityId::from_bytes(first.turn_id).unwrap();
    assert!(
        witnessed_user_turn(
            vault,
            &conversation,
            &first_turn,
            "my sister lives in Lisbon"
        ),
        "the run names the TURN the user's words were witnessed in"
    );

    // The next turn's run names its own TURN, after the user's and the
    // reply's TURNs of the first turn.
    chat_turn(&server, &conversation.to_hex(), "where does my sister live").await;
    let both = stamped_turns(vault);
    assert_eq!(both.len(), 2, "{both:?}");
    let second = both[1];
    assert_eq!(second.episode_id, *conversation.as_bytes());
    assert_eq!(second.turn_idx, 2);
    let second_turn = EntityId::from_bytes(second.turn_id).unwrap();
    assert_ne!(second_turn, first_turn);
    assert!(witnessed_user_turn(
        vault,
        &conversation,
        &second_turn,
        "where does my sister live"
    ));
    host.shutdown().await;
}

/// The vault's finalized runs that name a turn, oldest first.
fn stamped_runs(vault: &Vault) -> Vec<RetrievalRunRecord> {
    let mut runs: Vec<_> = vault
        .retrieval_runs(64)
        .unwrap()
        .into_iter()
        .filter(|run| run.turn.is_some())
        .collect();
    runs.sort_by_key(|run| run.started_at);
    runs
}

/// An active claim that `subject`'s home is `value`.
fn home_claim(subject: EntityId, value: &str) -> ClaimBody {
    ClaimBody::new(
        "profile.home",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap()
}

#[tokio::test]
async fn a_later_correction_in_the_conversation_labels_the_chat_turns_run() {
    let fake = FakeLlm::start(
        Vec::new(),
        Some(Reply::Text {
            text: "noted".into(),
            model: "fake".into(),
        }),
    )
    .await;
    let (_dir, server, host) = capturing_server(&fake.base_url).await;
    let vault = server.vault();
    let now = vault.now_recorded_at();
    let at = |seconds: u64| TimeRange {
        start: seconds,
        end: seconds,
    };
    // A PERSON and what the vault holds of her home, which the turn reads.
    let sister = EntityId::now();
    vault
        .put_entity(
            &sister,
            ENTITY_TYPE_PERSON,
            at(now - 600),
            now - 600,
            b"sister",
        )
        .unwrap();
    let served = EntityId::now();
    vault
        .put_claim(
            &served,
            &home_claim(sister, "Lisbon"),
            at(now - 300),
            now - 300,
        )
        .unwrap();
    vault
        .batch()
        .text(&served, &[("name", "sister home Lisbon")])
        .commit()
        .unwrap();
    let conversation = EntityId::now();

    chat_turn(&server, &conversation.to_hex(), "where is my sister's home").await;
    let runs = stamped_runs(vault);
    assert_eq!(runs.len(), 1, "{runs:?}");
    let run = runs[0].clone();
    assert!(
        run.result_ids.contains(served.as_bytes()),
        "the turn's recall served the claim: {:?}",
        run.result_ids
    );

    // The user's next turn, a second later than the run, corrects it.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    chat_turn(
        &server,
        &conversation.to_hex(),
        "no, my sister's home is Porto now",
    )
    .await;
    let runs = stamped_runs(vault);
    assert_eq!(runs.len(), 2, "{runs:?}");
    let correction_turn = EntityId::from_bytes(runs[1].turn.unwrap().turn_id).unwrap();
    // What consolidation keeps of those words: a claim the user stated, its
    // evidence that TURN, superseding the served claim.
    let learned = vault.now_recorded_at();
    let mut correction_body = home_claim(sister, "Porto");
    correction_body.source = Some(ClaimSource::UserStated);
    correction_body.evidence = Some(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: vec![correction_turn],
            chain: Vec::new(),
            source_meet: ClaimSource::UserStated,
        },
    ));
    let correction = EntityId::now();
    vault
        .put_claim(&correction, &correction_body, at(learned), learned)
        .unwrap();
    vault
        .batch()
        .edge(&correction, EdgeKind::Supersedes, &served, 1.0)
        .commit()
        .unwrap();

    // The owner's policy update labels the chat turn's own run.
    let owner_id = vault.ensure_embedded_owner_actor().unwrap();
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .unwrap();
    let memory = vault.memory(owner.actor_for_read(vault).unwrap(), EdgeActorClass::Human);
    retrieval_policy_update_as_owner(&memory, &owner, RetrievalPolicyTrainRequest::default())
        .unwrap();
    let outcomes = vault.retrieval_outcomes(run.run_id).unwrap();
    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(
        outcomes[0].key,
        format!("natural.correction:{}", correction.to_hex())
    );
    assert_eq!(outcomes[0].accepted, Some(false));
    assert_eq!(
        outcomes[0].metadata.get("source").map(String::as_str),
        Some("natural")
    );
    // The correcting turn's own run is not labelled by its own words.
    assert!(vault.retrieval_outcomes(runs[1].run_id).unwrap().is_empty());
    host.shutdown().await;
}
