//! The owner's decision-read probe: owner-only, one read admitted and settled
//! once on its meter, a failed check refused typed and charged, and past
//! `limits.decision_reads` a read waits its turn (rule five).
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use oneiron::llm::run_admission::{KeyCustody, LeaseUnit, OfferRoute, PaidConnector, Payer};
use oneiron::llm::{
    BudgetLease, FatalLlmError, LabelReadFailure, LabelReadModel, LabelReadRequest,
    LabelReadResponse, LabelSet, LlmInputUsage, LlmOutputUsage, LlmResult, LlmUsage,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, ModelLocality, Vault, VaultConfig};
use serde_json::{Value as JsonValue, json};
use tower::ServiceExt;

use crate::admission::Crossing;
use crate::config::models::ProbeQuestions;
use crate::models::DecisionReadDoor;
use crate::server::SyncServer;
use crate::wire_telemetry::LimitRow;

/// What one read was asked.
#[derive(Debug, PartialEq)]
struct Seen {
    question: String,
    options: Option<Vec<String>>,
    paired: String,
    person: Option<String>,
    state: JsonValue,
}

/// A house model that answers each read with `answer`, once `held` is false.
struct Reader {
    answer: Mutex<LlmResult<LabelReadResponse>>,
    held: Mutex<bool>,
    released: Condvar,
    seen: Mutex<Vec<Seen>>,
}

impl Reader {
    fn release(&self) {
        *self.held.lock().unwrap() = false;
        self.released.notify_all();
    }
}

impl LabelReadModel for Reader {
    fn model(&self) -> &str {
        "house/qwen@q4km"
    }
    fn revision(&self) -> &str {
        "q4km+recipe.0123456789abcdef"
    }
    fn read(
        &self,
        request: &LabelReadRequest<'_>,
        _: &BudgetLease,
    ) -> LlmResult<LabelReadResponse> {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.released.wait(held).unwrap();
        }
        drop(held);
        self.seen.lock().unwrap().push(Seen {
            question: request.primary.text.to_owned(),
            options: match request.primary.labels {
                LabelSet::Noul => None,
                LabelSet::Choice(options) => Some(options.to_vec()),
            },
            paired: request.paired.to_owned(),
            person: request.person.map(str::to_owned),
            state: request.state.clone(),
        });
        self.answer.lock().unwrap().clone()
    }
}

fn answered() -> LlmResult<LabelReadResponse> {
    Ok(LabelReadResponse {
        primary: vec![0.3, 0.7],
        paired_yes: 0.2,
        person_yes: Some(0.6),
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 40,
                ..LlmInputUsage::default()
            },
            output: LlmOutputUsage {
                total: 1,
                text: 0,
                reasoning: 0,
            },
            raw_provider: JsonValue::Null,
        },
    })
}

/// A vault's server whose probe reads with `reader` on a fresh meter, holding
/// `reads` reads at once.
fn server(reader: &Arc<Reader>, reads: usize) -> (tempfile::TempDir, Arc<SyncServer>, BudgetGuard) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let meter = BudgetGuard::with_reserve_units(
        "decision-read-test",
        1_000_000,
        1,
        BudgetExhaustionPolicy::Suspend,
    );
    let connector = PaidConnector {
        connector: "decision-read:house/qwen@q4km".to_owned(),
        route: OfferRoute::new("llama-cpp-read", "http://127.0.0.1:18134").unwrap(),
        locality: ModelLocality::OwnServer,
        payer: Payer::Local,
        credential_binding: None,
        catalog_revision: Some("q4km".to_owned()),
        custody: KeyCustody::Keyless,
        unit_cost: 1,
        cost_unit: LeaseUnit::tokens(),
        rates: Vec::new(),
    };
    let probe = ProbeQuestions {
        paired: "Think?".to_owned(),
        person: Some("Person?".to_owned()),
    };
    let server = SyncServer::new(
        vault,
        crate::config::SyncServerConfig {
            auth_secret: Some("owner".into()),
            limits: crate::config::LimitsConfig {
                decision_reads: reads,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap()
    .with_decision_read(
        DecisionReadDoor::new(
            Arc::clone(reader) as Arc<dyn LabelReadModel>,
            connector,
            Some(probe),
            0.9,
        ),
        meter.clone(),
    );
    (dir, Arc::new(server), meter)
}

fn reader(answer: LlmResult<LabelReadResponse>, held: bool) -> Arc<Reader> {
    Arc::new(Reader {
        answer: Mutex::new(answer),
        held: Mutex::new(held),
        released: Condvar::new(),
        seen: Mutex::new(Vec::new()),
    })
}

/// One probe under `recipe`'s credential: its status and body.
async fn probe(
    server: &Arc<SyncServer>,
    recipe: &str,
    body: &JsonValue,
) -> (StatusCode, JsonValue) {
    let (slip, key) = crate::test_credentials::credential(server, recipe);
    let response = crate::api::api_routes(Arc::clone(server))
        .oneshot(crate::test_credentials::bind_slip_request(
            server,
            &slip,
            &key,
            Request::post("/v1/llm/decision_read")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        ))
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null),
    )
}

fn split() -> JsonValue {
    json!({"question": "Split?", "options": ["keep", "split"], "state": {"turns": 3}})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_alone_reads_once_on_the_meter_and_a_failed_check_is_refused_typed() {
    let reader = reader(answered(), false);
    let (_dir, server, meter) = server(&reader, 2_048);

    // A scoped credential is not the owner: refused before anything is read.
    let (status, body) = probe(&server, "jti=reader;scope=core:read", &split()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "owner_required");
    assert!(reader.seen.lock().unwrap().is_empty());

    // The owner's read: the caller's question, options and state, the host's
    // paired and person questions; the raw read back, its usage on the meter.
    let (status, body) = probe(&server, "jti=owner", &split()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["model"], "house/qwen@q4km");
    assert_eq!(body["revision"], "q4km+recipe.0123456789abcdef");
    assert_eq!(body["primary"], json!([0.3, 0.7]));
    assert_eq!(body["paired_yes"], 0.2);
    assert_eq!(body["person_yes"], 0.6);
    assert_eq!(
        reader.seen.lock().unwrap().as_slice(),
        [Seen {
            question: "Split?".to_owned(),
            options: Some(vec!["keep".to_owned(), "split".to_owned()]),
            paired: "Think?".to_owned(),
            person: Some("Person?".to_owned()),
            state: json!({"turns": 3}),
        }]
    );
    assert_eq!(meter.read().used_units, 41);
    assert_eq!(meter.read().reserved_units, 0);

    // A read that fails a check is refused with its typed failure, never read
    // as p = 0, and its reservation stays spent.
    *reader.answer.lock().unwrap() =
        Err(FatalLlmError::LabelRead(LabelReadFailure::EmittedText).into());
    let (status, body) = probe(&server, "jti=owner", &split()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"]["code"], "label_read");
    assert_eq!(
        body["error"]["llm"],
        json!({"Fatal": {"LabelRead": "EmittedText"}})
    );
    assert!(body.get("primary").is_none());
    assert!(meter.read().used_units > 41);
    assert_eq!(meter.read().reserved_units, 0);

    // State is an object the caller built, within its bound.
    for bad in [
        json!({"question": "Split?", "state": []}),
        json!({"question": "Split?", "options": ["keep"], "state": {}}),
        json!({"question": "Split?", "state": {"pad": "x".repeat(70_000)}}),
    ] {
        let (status, _) = probe(&server, "jti=owner", &bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert_eq!(reader.seen.lock().unwrap().len(), 2);
}

/// Rule five at `limits.decision_reads`: past a row of one, `callers` owner
/// reads wait their turn behind a held read, all are answered once it lets
/// go, and the row asks.
pub(crate) async fn cross_the_decision_reads(callers: usize) -> Crossing {
    let reader = reader(answered(), true);
    let (_dir, server, _) = server(&reader, 1);
    let body = split();
    let calls =
        futures_util::future::join_all((0..callers).map(|_| probe(&server, "jti=owner", &body)));
    // One read holds the row's one turn; let go once another waits for it.
    let release = async {
        while server.decision_reads.waiting() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        reader.release();
    };
    let (answers, ()) = tokio::time::timeout(
        Duration::from_secs(120),
        futures_util::future::join(calls, release),
    )
    .await
    .expect("the queued reads are answered");
    Crossing {
        refused: answers
            .iter()
            .filter(|(status, _)| *status != StatusCode::OK)
            .count(),
        asked: server
            .wire_telemetry
            .limit_questions()
            .latest(LimitRow::DecisionReads)
            .is_some(),
    }
}
