//! Recall at every declared effort through the MCP recall door (dogfood gate
//! 1): high, xhigh and max rerank on the `[models]` reranker, on a line of
//! the recall's own, and every way that can fail is a typed refusal.
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::extract::State;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent, RunReceipt};

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::models_toml;

const QUERY: &str = "lantern repair";
/// The passage the fake reranker prefers. It is the weakest lexical match
/// for [`QUERY`], so medium recall ranks it below the others.
const KNOWN: &str = "the brass lantern in the attic";
const OTHERS: [&str; 4] = [
    "lantern repair notes for the lantern repair kit",
    "lantern repair: replace the lantern wick",
    "repair the lantern frame before the lantern show",
    "lantern repair shop hours and lantern prices",
];
const SERVED_MODEL: &str = "fake-reranker-v1";

type Score = Arc<dyn Fn(usize, &str) -> f64 + Send + Sync>;
type OnCall = Arc<dyn Fn(usize) + Send + Sync>;

#[derive(Clone)]
struct Fake {
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Value>>>,
    score: Score,
    on_call: OnCall,
    tokens: u64,
    served_model: Arc<str>,
}

/// A loopback `/v1/rerank` server. Call `n` (from 1) scores each document
/// with `score(n, document)`, runs `on_call(n)` first, says
/// [`SERVED_MODEL`] answered (or the name [`FakeReranker::named`] gives) and
/// reports `tokens` used.
struct FakeReranker {
    base_url: String,
    fake: Fake,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeReranker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeReranker {
    async fn start(score: Score, on_call: OnCall, tokens: u64) -> Self {
        Self::named(score, on_call, tokens, SERVED_MODEL).await
    }

    async fn named(score: Score, on_call: OnCall, tokens: u64, served_model: &str) -> Self {
        let fake = Fake {
            calls: Arc::default(),
            seen: Arc::default(),
            score,
            on_call,
            tokens,
            served_model: served_model.into(),
        };
        let app = axum::Router::new()
            .route("/v1/rerank", axum::routing::post(rerank))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            fake,
            task,
        }
    }

    fn calls(&self) -> usize {
        self.fake.calls.load(Ordering::SeqCst)
    }

    fn seen(&self) -> Vec<Value> {
        self.fake.seen.lock().unwrap().clone()
    }
}

async fn rerank(State(fake): State<Fake>, Json(body): Json<Value>) -> Json<Value> {
    let call = fake.calls.fetch_add(1, Ordering::SeqCst) + 1;
    (fake.on_call)(call);
    fake.seen.lock().unwrap().push(body.clone());
    let results: Vec<Value> = body["documents"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, document)| {
            json!({"index": index, "relevance_score": (fake.score)(call, document.as_str().unwrap())})
        })
        .collect();
    Json(json!({
        "model": &*fake.served_model,
        "results": results,
        "usage": {"total_tokens": fake.tokens},
    }))
}

/// The reranker prefers [`KNOWN`] on every call.
fn prefers_known() -> Score {
    Arc::new(|_, document| {
        if document.contains("brass") {
            10.0
        } else {
            0.0
        }
    })
}

fn no_hook() -> OnCall {
    Arc::new(|_| {})
}

fn reranker_models(base_url: &str, units: u64) -> crate::config::models::ModelsConfig {
    models_toml(&format!(
        r#"
[providers.rerank]
kind = "local-openai-compat"
base_url = "{base_url}"
[roles.reranker]
model = "rerank:fake-reranker"
[dreamer]
enabled = false
[recall]
rerank_budget_units = {units}
"#
    ))
}

/// `auth_test_server` with the AI host attached on `models`, its run
/// receipts kept.
async fn served(
    models: Option<&crate::config::models::ModelsConfig>,
) -> (
    tempfile::TempDir,
    Arc<SyncServer>,
    AiHost,
    Arc<MemoryReceipts>,
) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let receipts = Arc::new(MemoryReceipts::default());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_run_receipts(receipts.clone());
    let (server, host) = AiHost::attach(server, models).await;
    (dir, Arc::new(server), host, receipts)
}

fn remember(vault: &oneiron::Vault, actor: oneiron::EntityId, text: &str) -> oneiron::EntityId {
    let id = oneiron::EntityId::now();
    let mut claim = oneiron::ClaimBody::new(
        "profile.note",
        oneiron::ClaimSubject::Entity(actor),
        rmpv::Value::from(text),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.source = Some(oneiron::ClaimSource::UserStated);
    vault
        .put_claim(&id, &claim, oneiron::TimeRange { start: 10, end: 10 }, 10)
        .unwrap();
    vault.batch().text(&id, &[("body", text)]).commit().unwrap();
    id
}

/// A registered MCP actor who remembers [`KNOWN`] and [`OTHERS`].
async fn reader(server: &Arc<SyncServer>, credential: &str) -> oneiron::EntityId {
    let actor = oneiron::EntityId::now();
    register_mcp_actor(server, credential, actor, oneiron::EdgeActorClass::Human).await;
    for text in OTHERS.iter().chain([&KNOWN]) {
        remember(server.vault(), actor, text);
    }
    actor
}

/// One MCP `recall` at `effort`: the pack, or the refusal.
async fn recall(
    server: &Arc<SyncServer>,
    credential: &str,
    actor: oneiron::EntityId,
    effort: &str,
) -> Result<Value, Value> {
    let (status, reply) = route_json(
        server.clone(),
        mcp_endpoint_call_request(
            MCP_TOOL_FIRST_PATH,
            credential,
            &format!("recall-{effort}"),
            "recall",
            mcp_merge_args(
                mcp_endpoint_envelope(actor, "read_memory"),
                json!({"arguments": {"spec": {"query": QUERY, "effort": effort, "limit": 10}}}),
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    match reply.get("error") {
        Some(_) => Err(reply),
        None => Ok(reply["result"]["structuredContent"]["output"].clone()),
    }
}

/// Each item's text, in the pack's order.
fn order(pack: &Value) -> Vec<String> {
    pack["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a pack: {pack}"))
        .iter()
        .map(|item| item["value_text"].as_str().unwrap().to_owned())
        .collect()
}

fn rank_of_known(pack: &Value) -> usize {
    order(pack)
        .iter()
        .position(|text| text.contains("brass"))
        .unwrap_or_else(|| panic!("the known passage is recalled: {pack}"))
}

fn recall_runs(receipts: &MemoryReceipts) -> Vec<RunReceipt> {
    receipts
        .rows()
        .into_iter()
        .filter(|row| row.run.starts_with("recall-rerank:"))
        .collect()
}

/// Done-means (G1 checks 1 and 2): through MCP, high reranks on the
/// `[models]` reranker and puts the passage it prefers first where medium
/// ranks it lower, and xhigh and max reach it too. Each call is admitted,
/// dispatched and settled on the recall's run, and the receipts and the pack
/// name the model that answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_xhigh_and_max_rerank_on_the_models_reranker_through_mcp() {
    let fake = FakeReranker::start(prefers_known(), no_hook(), 120).await;
    let models = reranker_models(&fake.base_url, 32_000);
    let (_dir, server, _host, receipts) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-reader").await;

    let medium = recall(&server, "rerank-reader", actor, "medium")
        .await
        .unwrap();
    assert!(rank_of_known(&medium) > 0, "{medium}");
    assert!(medium["retrieval_meta"].get("rerank").is_none(), "{medium}");
    assert_eq!(fake.calls(), 0, "medium calls no model");

    for (calls, effort) in [(1, "high"), (2, "xhigh"), (3, "max")] {
        let pack = recall(&server, "rerank-reader", actor, effort)
            .await
            .unwrap_or_else(|refusal| panic!("{effort}: {refusal}"));
        assert_eq!(rank_of_known(&pack), 0, "{effort}: {pack}");
        assert_eq!(fake.calls(), calls, "{effort}");
        // The block is the effort's top candidates, rows ranked below the
        // passages too, and the pack counts what the reranker scored.
        let scored = fake.seen()[calls - 1]["documents"]
            .as_array()
            .unwrap()
            .len();
        assert_eq!(
            pack["retrieval_meta"]["rerank"],
            json!({
                "status": "applied",
                "model": "rerank:fake-reranker",
                "served_model": SERVED_MODEL,
                "candidates": scored,
                "calls": 1,
            }),
            "{effort}"
        );
    }
    // The reranker read the query and the reader's own block, and nothing in
    // the request picked its model.
    for seen in fake.seen() {
        assert_eq!(seen["query"], QUERY);
        assert_eq!(seen["model"], "fake-reranker");
        let documents = seen["documents"].as_array().unwrap();
        assert!(
            documents
                .iter()
                .any(|document| document.as_str().unwrap().contains(KNOWN))
        );
    }

    let runs = recall_runs(&receipts);
    let events: Vec<&RunEvent> = runs.iter().map(|row| &row.event).collect();
    assert_eq!(events.len(), 9, "{runs:?}");
    for call in events.chunks(3) {
        let [
            RunEvent::Admitted(facts),
            RunEvent::Dispatched {
                served_model,
                answered,
                ..
            },
            RunEvent::Settled { units, error, .. },
        ] = call
        else {
            panic!("admitted, dispatched, settled: {call:?}");
        };
        assert!(facts.subject.contains("fake-reranker"), "{facts:?}");
        assert!(facts.route.contains("-rerank"), "{facts:?}");
        assert_eq!(served_model.as_deref(), Some(SERVED_MODEL));
        assert!(answered);
        assert_eq!((*units, error), (120, &None));
    }
}

/// Done-means (G1 check 2): a recall whose line is spent is refused with a
/// typed `budget_spent`; it never falls back to an unreranked pack. A call
/// that went out is settled at what it used, past the line too, so a line
/// one call overspends refuses the next: here the block changes during the
/// first call, and the door's second call is the one refused. The line
/// covers the first call's payload (W1-2 prices it before it leaves); the
/// endpoint reports more used than the line held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spent_rerank_line_refuses_xhigh_and_max_by_name() {
    let vault = Arc::new(Mutex::new(None::<(Arc<oneiron::Vault>, oneiron::EntityId)>));
    let hook = {
        let vault = Arc::clone(&vault);
        Arc::new(move |call: usize| {
            if let Some((vault, actor)) = vault.lock().unwrap().clone() {
                remember(&vault, actor, &format!("lantern repair drawer {call}"));
            }
        }) as OnCall
    };
    let fake = FakeReranker::start(prefers_known(), hook, 50_000).await;
    let models = reranker_models(&fake.base_url, 30_000);
    let (_dir, server, _host, receipts) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-spent").await;
    *vault.lock().unwrap() = Some((Arc::clone(server.vault()), actor));

    for (calls, effort) in [(1, "xhigh"), (2, "max")] {
        let refusal = recall(&server, "rerank-spent", actor, effort)
            .await
            .expect_err(effort);
        assert_eq!(refusal["error"]["code"], -32020, "{refusal}");
        assert_eq!(refusal["error"]["data"]["error_code"], "budget_spent");
        assert_eq!(fake.calls(), calls, "{effort} reached the reranker once");
    }
    // Each recall's one call was settled at what it used.
    let settled: Vec<_> = recall_runs(&receipts)
        .into_iter()
        .filter_map(|row| match row.event {
            RunEvent::Settled { units, error, .. } => Some((units, error)),
            _ => None,
        })
        .collect();
    assert_eq!(settled.len(), 2, "{settled:?}");
    assert!(
        settled
            .iter()
            .all(|(units, error)| *units == 50_000 && error.is_none()),
        "{settled:?}"
    );
    // Medium makes no model call, so the spent line does not touch it.
    assert!(
        recall(&server, "rerank-spent", actor, "medium")
            .await
            .is_ok()
    );
}

/// Done-means (G1 check 3): with no reranker route, high runs its expansion
/// unreranked, in the order the engine gives, and says it skipped the
/// rerank. A route none of whose rungs can serve is refused, not skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_reranker_route_high_runs_unreranked_and_says_so() {
    let (_dir, server, _host, receipts) = served(None).await;
    let actor = reader(&server, "rerank-none").await;
    let medium = recall(&server, "rerank-none", actor, "medium")
        .await
        .unwrap();
    let high = recall(&server, "rerank-none", actor, "high").await.unwrap();
    assert_eq!(order(&high), order(&medium));
    assert_eq!(
        high["retrieval_meta"]["rerank"],
        json!({"status": "skipped", "reason": "no_reranker"})
    );
    assert!(recall_runs(&receipts).is_empty());

    let unset = "ONEIRON_RECALL_RERANK_TEST_KEY_NEVER_SET";
    let models = models_toml(&format!(
        r#"
[providers.rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:9"
key_env = "{unset}"
[roles.reranker]
model = "rerank:fake-reranker"
[dreamer]
enabled = false
"#
    ));
    let (_dir, server, _host, _) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-broken").await;
    let refusal = recall(&server, "rerank-broken", actor, "high")
        .await
        .expect_err("an unusable route is refused");
    assert_eq!(refusal["error"]["data"]["error_code"], "model_unavailable");
}

/// Sol round 6 (R6-2): a vault manifest that binds the reranker to a model
/// `[models]` serves only for chat sent the rerank call down that chat route,
/// past the rerank protocol and a provider the reranker refuses. Only a
/// reranker rung answers the role; this call is refused unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_manifest_bound_chat_model_never_answers_as_the_reranker() {
    let reranker = FakeReranker::start(prefers_known(), no_hook(), 10).await;
    let chat = crate::fake_llm::FakeLlm::start(vec![], None).await;
    let models = models_toml(&format!(
        r#"
[providers.rerank]
kind = "local-openai-compat"
base_url = "{}"
[providers.local]
kind = "local-openai-compat"
base_url = "{}"
[roles.reranker]
model = "rerank:fake-reranker"
[roles.generative_reasoner]
model = "local:chat"
[dreamer]
enabled = false
"#,
        reranker.base_url, chat.base_url
    ));
    let (_dir, server, _host, _) = served(Some(&models)).await;
    crate::ai_host::test_support::pin_every_role(
        server.vault(),
        "local/chat@live",
        oneiron::ModelLocality::OwnServer,
    );
    let actor = reader(&server, "rerank-pinned-chat").await;
    let refusal = recall(&server, "rerank-pinned-chat", actor, "high")
        .await
        .expect_err("a chat model is not a reranker");
    assert_eq!(refusal["error"]["data"]["error_code"], "model_unavailable");
    let sent: Vec<String> = chat.seen().into_iter().map(|seen| seen.path).collect();
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(reranker.calls(), 0);
}

/// Done-means (G1 check 4): scores apply only to the block they scored. A
/// write that changes the block during the first call sends the new block to
/// the reranker; the first call's scores, which put the known passage last,
/// are never used. A block that changes during both calls is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_that_changes_while_it_is_scored_takes_none_of_the_stale_scores() {
    let vault = Arc::new(Mutex::new(None::<(Arc<oneiron::Vault>, oneiron::EntityId)>));
    let writes = Arc::new(AtomicUsize::new(1));
    let hook = {
        let vault = Arc::clone(&vault);
        let writes = Arc::clone(&writes);
        Arc::new(move |call: usize| {
            if call <= writes.load(Ordering::SeqCst)
                && let Some((vault, actor)) = vault.lock().unwrap().clone()
            {
                remember(&vault, actor, &format!("lantern repair drawer {call}"));
            }
        }) as OnCall
    };
    // The first call's scores rank the known passage last; later calls rank
    // it first.
    let score: Score = Arc::new(|call, document| match (call, document.contains("brass")) {
        (1, true) => -10.0,
        (1, false) => 1.0,
        (_, true) => 10.0,
        (_, false) => 0.0,
    });
    let fake = FakeReranker::start(score, hook, 50).await;
    let models = reranker_models(&fake.base_url, 32_000);
    let (_dir, server, _host, _) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-stale").await;
    *vault.lock().unwrap() = Some((Arc::clone(server.vault()), actor));

    let pack = recall(&server, "rerank-stale", actor, "high")
        .await
        .unwrap();
    assert_eq!(fake.calls(), 2);
    assert_eq!(rank_of_known(&pack), 0, "{pack}");
    assert_eq!(pack["retrieval_meta"]["rerank"]["calls"], 2, "{pack}");
    let second = &fake.seen()[1];
    assert!(
        second["documents"]
            .as_array()
            .unwrap()
            .iter()
            .any(|document| document.as_str().unwrap().contains("drawer 1")),
        "the second call scores the block as it is now: {second}"
    );

    writes.store(usize::MAX, Ordering::SeqCst);
    let refusal = recall(&server, "rerank-stale", actor, "high")
        .await
        .expect_err("a block that keeps changing is refused");
    assert_eq!(fake.calls(), 4);
    assert_eq!(refusal["error"]["code"], -32020, "{refusal}");
    assert!(
        refusal["error"]["data"]["human_message"]
            .as_str()
            .unwrap()
            .contains("changed while the reranker scored them"),
        "{refusal}"
    );
}

/// #1419 Wonder W1-2: a call's words are known before it leaves, so it is
/// priced on them first. A line that cannot cover the payload refuses the
/// call unsent, as `budget_spent`; before, the call went out and was settled
/// past the line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_payload_past_the_line_is_refused_unsent() {
    let fake = FakeReranker::start(prefers_known(), no_hook(), 1).await;
    let models = reranker_models(&fake.base_url, 32);
    let (_dir, server, _host, receipts) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-priced").await;

    let refusal = recall(&server, "rerank-priced", actor, "high")
        .await
        .expect_err("a payload past the line is refused");

    assert_eq!(
        refusal["error"]["data"]["error_code"], "budget_spent",
        "{refusal}"
    );
    assert_eq!(fake.calls(), 0, "nothing was sent");
    assert!(
        recall_runs(&receipts)
            .iter()
            .all(|row| !matches!(row.event, RunEvent::Dispatched { .. })),
        "{:?}",
        recall_runs(&receipts)
    );
}

/// A loopback `/v1/rerank` that reads each request and fails it, as a
/// provider that went down after it took the words. Counts what it took.
async fn failing_reranker() -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let taken = Arc::new(AtomicUsize::new(0));
    let app = axum::Router::new()
        .route(
            "/v1/rerank",
            axum::routing::post(
                |State(taken): State<Arc<AtomicUsize>>, Json(_): Json<Value>| async move {
                    taken.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR
                },
            ),
        )
        .with_state(Arc::clone(&taken));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}"), taken, task)
}

/// Wonder R1 on this branch (W1-2): a call was priced once, but each rung it
/// reached sent the whole payload, and a rung that failed after it went out
/// was charged the line's flat reservation alone, so the fallback rung went
/// out on a line that no longer covered it. Each rung reserves the payload's
/// price: the first rung fails, the line cannot cover a second send, and the
/// recall is refused as `budget_spent` with the fallback unsent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fallback_rung_goes_out_only_while_the_line_covers_its_payload() {
    let (down_url, taken, down) = failing_reranker().await;
    let fake = FakeReranker::start(prefers_known(), no_hook(), 10).await;
    // A block of 16 to 30 clipped memories (about 530 units each) costs more
    // than the flat reservation (8000) and less than this line, which the
    // flat reservation covers twice and the payload's price once.
    let models = models_toml(&format!(
        r#"
[providers.down]
kind = "local-openai-compat"
base_url = "{down_url}"
[providers.rerank]
kind = "local-openai-compat"
base_url = "{}"
[roles.reranker]
rungs = [{{ model = "down:fake-reranker" }}, {{ model = "rerank:fake-reranker" }}]
[dreamer]
enabled = false
[recall]
rerank_budget_units = 16500
"#,
        fake.base_url
    ));
    let (_dir, server, _host, _) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-fallback").await;
    for entry in 0..25 {
        let words = "the wick was trimmed and the glass was wiped clean ".repeat(12);
        remember(
            server.vault(),
            actor,
            &format!("lantern repair log {entry}: {words}"),
        );
    }

    let refusal = recall(&server, "rerank-fallback", actor, "high")
        .await
        .expect_err("the line cannot cover a second send");

    assert_eq!(
        refusal["error"]["data"]["error_code"], "budget_spent",
        "{refusal}"
    );
    assert_eq!(taken.load(Ordering::SeqCst), 1, "the first rung went out");
    assert_eq!(fake.calls(), 0, "the fallback rung was not sent");
    down.abort();
}

/// #1419 Wonder W1-3: the pack repeats the name the endpoint says answered
/// only when it is a model name: at most 200 printable characters. A name
/// past that is dropped, as though the endpoint named none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_served_model_name_past_its_bound_is_not_repeated() {
    let fake = FakeReranker::named(prefers_known(), no_hook(), 10, &"m".repeat(16 * 1024)).await;
    let models = reranker_models(&fake.base_url, 32_000);
    let (_dir, server, _host, _) = served(Some(&models)).await;
    let actor = reader(&server, "rerank-long-name").await;

    let pack = recall(&server, "rerank-long-name", actor, "high")
        .await
        .unwrap();

    let rerank = &pack["retrieval_meta"]["rerank"];
    assert_eq!(rerank["status"], "applied", "{rerank}");
    assert!(rerank.get("served_model").is_none(), "{rerank}");
}

/// Bugbot on #1419: the sync door runs high, xhigh and max off its caller's
/// thread. On a current-thread runtime that is a plain thread with no
/// runtime, and the rerank door refused a configured reranker there as
/// `model_unavailable`. A host serving from a current-thread runtime reranks
/// a high recall over the sync RPC, with a deadline (Sol R1 on this branch:
/// the deadline's timer was made on the caller's thread, which has no
/// runtime, and panicked) and without.
#[test]
fn high_recall_over_the_sync_rpc_reranks_on_a_current_thread_runtime() {
    let io = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let fake = io.block_on(FakeReranker::start(prefers_known(), no_hook(), 10));
    let models = reranker_models(&fake.base_url, 32_000);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let replies = runtime.block_on(async {
        let (_dir, server, _host, _) = served(Some(&models)).await;
        let owner = server.vault().ensure_embedded_owner_actor().unwrap();
        for text in OTHERS.iter().chain([&KNOWN]) {
            remember(server.vault(), owner, text);
        }
        let recipe = format!(
            "scope=core:read;principal_ref={};actor_class=human",
            owner.to_hex()
        );
        let auth = crate::test_credentials::authenticate(&server, &recipe);
        [
            json!({"query": QUERY, "effort": "high", "limit": 10}),
            json!({"query": QUERY, "effort": "high", "limit": 10, "deadline_ms": 30_000}),
        ]
        .into_iter()
        .map(|params| {
            let frames = crate::livequery::bound_rpc(
                &server,
                &auth,
                crate::livequery::RpcRequest {
                    request_id: 7,
                    method: "recall".to_owned(),
                    params,
                },
            )
            .unwrap();
            crate::livequery::test_wire::reply(&frames)
        })
        .collect::<Vec<_>>()
    });
    runtime.shutdown_background();

    for reply in &replies {
        assert_eq!(
            reply["result"]["retrieval_meta"]["rerank"]["status"], "applied",
            "{reply}"
        );
    }
    assert_eq!(fake.calls(), 2);
    for seen in fake.seen() {
        assert!(
            seen["documents"]
                .as_array()
                .unwrap()
                .iter()
                .any(|document| document.as_str().unwrap().contains(KNOWN)),
            "{seen}"
        );
    }
    drop(fake);
    io.shutdown_background();
}

const PPLX_REPO: &str = "perplexity-ai/pplx-embed-v1-0.6b";
const PPLX_REVISION: &str = "2c4d510dd4a732063c31a0f70193e35067b51fd8";
/// Shares no word with [`PARAPHRASED`]: only the dense signal finds it.
const PARAPHRASE: &str = "where can I buy fresh bread midweek";
const PARAPHRASED: &str = "The bakery on Elm Street sells sourdough loaves every Tuesday morning.";
const INVENTED: [&str; 6] = [
    "The bread machine manual is in the kitchen drawer.",
    "My dentist appointment moved to Friday afternoon.",
    "The car needs new tires before winter.",
    "Remember to water the tomato plants every evening.",
    "The quarterly report is due to the finance team.",
    "Our cat sleeps on the windowsill in the sun.",
];

/// G7, the synthetic acceptance: recall at every effort through MCP on the
/// real local embedder (the pinned pplx model; Metal on a Mac) and a
/// loopback reranker, over invented memories in a throwaway vault. It
/// records the model that loaded, the order at each effort and the run
/// receipts, as JSON to `ONEIRON_ACCEPTANCE_OUT` when that names a file.
/// A first run downloads the checkpoint; `ONEIRON_EMBED_TEST_PPLX_MODEL_DIR`
/// names a directory already holding it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
async fn every_effort_through_mcp_on_the_local_embedder_and_a_loopback_reranker() {
    let score: Score = Arc::new(|_, document| {
        if document.contains("sourdough") {
            10.0
        } else {
            0.0
        }
    });
    let fake = FakeReranker::start(score, no_hook(), 64).await;
    let models = reranker_models(&fake.base_url, 32_000);
    let model_id = format!("{PPLX_REPO}@{PPLX_REVISION}");
    let embedder = crate::config::EmbedderConfig {
        provider: crate::config::EmbedderProvider::Local,
        model_id: model_id.clone(),
        dimensions: 1024,
        local: crate::config::LocalEmbedderConfig {
            repo: PPLX_REPO.to_owned(),
            revision: PPLX_REVISION.to_owned(),
            model_dir: std::env::var_os("ONEIRON_EMBED_TEST_PPLX_MODEL_DIR")
                .map(std::path::PathBuf::from),
            ..crate::config::LocalEmbedderConfig::default()
        },
        ..crate::config::EmbedderConfig::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let backups = tempfile::tempdir().unwrap();
    let mut vault_config = oneiron::VaultConfig::device();
    vault_config.dimensions = 1024;
    vault_config.embedding_model = Some(model_id.clone());
    let vault = Arc::new(oneiron::Vault::open(dir.path(), vault_config.clone()).unwrap());
    let receipts = Arc::new(MemoryReceipts::default());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some("secret".to_owned()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_run_receipts(receipts.clone())
    .with_owner_host(crate::owner::schedule::OwnerHost {
        vault_path: dir.path().to_path_buf(),
        vault_config,
        backups: crate::owner::backup::BackupPlan::new(dir.path(), backups.path().to_path_buf(), 2),
        every: None,
        backup_lock: std::sync::Mutex::new(()),
    })
    .with_embedder(crate::embedder::EmbedderSlot::from_config(&embedder).unwrap());
    let (server, _host) = AiHost::attach(server, Some(&models)).await;
    let server = Arc::new(server);
    let _worker = server.spawn_embedding_worker().unwrap();

    let owner = super::owner_routes::owner_recipe(&server);
    let started = std::time::Instant::now();
    let status = loop {
        let (_, status) =
            super::owner_routes::call(&server, "GET", "/v1/owner/status", owner.clone(), None)
                .await;
        let dense = status["embedder"]["dense"].clone();
        assert_ne!(dense, "refused", "{status}");
        if dense == "ready" {
            break status;
        }
        assert!(started.elapsed().as_secs() < 3_600, "{status}");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };
    let loaded = &status["embedder"]["loaded"];
    assert_eq!(loaded["repo"], PPLX_REPO, "{status}");
    assert_eq!(loaded["revision"], PPLX_REVISION);
    assert_eq!(loaded["dimensions"], 1024);
    #[cfg(target_os = "macos")]
    assert_eq!(loaded["device"], "metal", "{status}");
    let load_secs = started.elapsed().as_secs();

    let actor = oneiron::EntityId::now();
    register_mcp_actor(&server, "acceptance", actor, oneiron::EdgeActorClass::Human).await;
    let ids: Vec<_> = INVENTED
        .iter()
        .chain([&PARAPHRASED])
        .map(|text| remember(server.vault(), actor, text))
        .collect();
    // Every invented memory has its vector before anything is recalled.
    let filled = std::time::Instant::now();
    while !ids
        .iter()
        .all(|id| server.vault().get_vector(id).ok().flatten().is_some())
    {
        assert!(filled.elapsed().as_secs() < 1_200, "vectors still pending");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    let mut efforts = serde_json::Map::new();
    for effort in ["light", "call", "medium", "high", "xhigh", "max"] {
        let (http, reply) = route_json(
            server.clone(),
            mcp_endpoint_call_request(
                MCP_TOOL_FIRST_PATH,
                "acceptance",
                &format!("acceptance-{effort}"),
                "recall",
                mcp_merge_args(
                    mcp_endpoint_envelope(actor, "read_memory"),
                    json!({"arguments": {"spec": {"query": PARAPHRASE, "effort": effort, "limit": 7}}}),
                ),
            ),
        )
        .await;
        assert_eq!(http, StatusCode::OK, "{reply}");
        assert!(reply.get("error").is_none(), "{effort}: {reply}");
        let pack = &reply["result"]["structuredContent"]["output"];
        efforts.insert(
            effort.to_owned(),
            json!({
                "order": order(pack),
                "sparse": pack["retrieval_meta"]["sparse"],
                "partial": pack["retrieval_meta"]["partial"],
                "rerank": pack["retrieval_meta"]["rerank"],
            }),
        );
    }
    let found = |effort: &str| {
        efforts[effort]["order"]
            .as_array()
            .unwrap()
            .iter()
            .position(|text| text.as_str().unwrap().contains("sourdough"))
    };
    assert_eq!(
        found("light"),
        None,
        "lexical recall cannot find a paraphrase"
    );
    assert!(found("medium").is_some(), "{efforts:?}");
    assert_eq!(efforts["medium"]["sparse"], false);
    for effort in ["high", "xhigh", "max"] {
        assert_eq!(found(effort), Some(0), "{effort}: {efforts:?}");
        assert_eq!(efforts[effort]["rerank"]["status"], "applied", "{effort}");
        assert_eq!(efforts[effort]["rerank"]["served_model"], SERVED_MODEL);
    }
    let record = json!({
        "query": PARAPHRASE,
        "memories": INVENTED.iter().chain([&PARAPHRASED]).collect::<Vec<_>>(),
        "load_seconds": load_secs,
        "embedder": status["embedder"],
        "efforts": efforts,
        "receipts": recall_runs(&receipts),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    });
    let record = serde_json::to_string_pretty(&record).unwrap();
    println!("{record}");
    if let Some(out) = std::env::var_os("ONEIRON_ACCEPTANCE_OUT") {
        std::fs::write(out, &record).unwrap();
    }
}
