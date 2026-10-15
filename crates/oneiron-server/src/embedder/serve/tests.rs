use oneiron::embed::PendingEmbeddingInput;

use super::super::endpoint::{HttpEmbedder, ProbeOutcome, probe_endpoint};
use super::super::local::bench::{cpu_config, document, synthetic_documents, synthetic_queries};
use super::*;
use crate::config::EndpointEmbedderConfig;
use crate::embedder::QueryEmbedder;

/// The check the shared endpoint exists for: a vault on the `endpoint`
/// provider pointed at it stores the vectors a vault on the `local`
/// provider makes, to the bit, and embeds queries the same way, with and
/// without a vault-side query instruction. One document is longer than
/// the input cap, which the server's tokenizer must cut where a local
/// vault's does. Both sides run the same loaded model, so any difference
/// is the wire's or the request path's.
#[test]
#[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
fn an_endpoint_vault_stores_the_vectors_a_local_vault_makes() {
    let local_config = cpu_config();
    let local = LocalEmbedder::load(&local_config, &ModelManager::default()).expect("loads");
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bound");
    let addr = listener.local_addr().expect("address");
    let served: Arc<dyn ServedModel> = Arc::<LocalEmbedder>::clone(&local);
    let app = router(served, vec!["pplx".to_owned()], None);
    std::thread::spawn(move || runtime.block_on(async move { axum::serve(listener, app).await }));
    let endpoint_vault = |query_instruction: Option<&str>| {
        HttpEmbedder::from_config(&EmbedderConfig {
            provider: EmbedderProvider::Endpoint,
            query_instruction: query_instruction.map(str::to_owned),
            endpoint: EndpointEmbedderConfig {
                endpoint: Some(format!("http://{addr}/v1")),
                model_key: Some(local_config.model_id.clone()),
                // Bit equality is the claim, not speed, on a shared box.
                timeout_ms: 600_000,
                ..EndpointEmbedderConfig::default()
            },
            ..local_config.clone()
        })
        .expect("client")
    };
    let remote = endpoint_vault(None);
    assert_eq!(probe_endpoint(&remote), Ok(ProbeOutcome::Ready));
    let bits = |vector: &[f32]| vector.iter().map(|v| v.to_bits()).collect::<Vec<_>>();

    let mut texts = synthetic_documents(48, 21);
    texts.push(texts[0].clone());
    let long = texts.join(" ");
    assert!(
        long.len() > 4 * local_config.max_input_tokens,
        "past the input cap"
    );
    texts.push(long);
    let inputs: Vec<PendingEmbeddingInput> = texts.iter().map(|text| document(text)).collect();
    let stored_locally = local.embed(&inputs).expect("local");
    let stored_remotely = remote.embed(&inputs).expect("remote");
    let differing = stored_locally
        .iter()
        .zip(&stored_remotely)
        .filter(|(a, b)| bits(a) != bits(b))
        .count();
    assert_eq!(differing, 0, "documents whose stored vector differs");

    let instructed_config = EmbedderConfig {
        query_instruction: Some("query: ".to_owned()),
        ..local_config.clone()
    };
    let instructed_local =
        LocalEmbedder::load(&instructed_config, &ModelManager::default()).expect("loads");
    let instructed_remote = endpoint_vault(Some("query: "));
    for query in synthetic_queries(12, 22) {
        assert_eq!(
            bits(&local.embed_query(&query).expect("local query")),
            bits(&remote.embed_query(&query).expect("remote query")),
            "a query vector differs"
        );
        assert_eq!(
            bits(&instructed_local.embed_query(&query).expect("local query")),
            bits(&instructed_remote.embed_query(&query).expect("remote query")),
            "an instructed query vector differs"
        );
    }
    println!(
        "{} documents and 24 queries equal to the bit over the wire",
        texts.len()
    );
}

// ─── the routes over a synthetic model ───────────────────────────────────

/// Width of [`Synthetic`]'s vectors.
const SYNTHETIC_DIMS: usize = 8;
/// The bearer key the synthetic servers are started with.
const KEY: &str = "synthetic-endpoint-key";

/// A model that needs no checkpoint: each text along one axis.
struct Synthetic {
    model_id: &'static str,
    transform: &'static str,
    profile: RunProfile,
    provenance: EmbeddingProvenance,
}

impl ServedModel for Synthetic {
    fn model_id(&self) -> &str {
        self.model_id
    }

    fn dimensions(&self) -> usize {
        SYNTHETIC_DIMS
    }

    fn transform(&self) -> &str {
        self.transform
    }

    fn profile(&self) -> &RunProfile {
        &self.profile
    }

    fn provenance(&self) -> EmbeddingProvenance {
        self.provenance.clone()
    }

    fn embed_raw(
        &self,
        texts: &[String],
        _side: Side,
        _instruction: Option<&str>,
        _priority: Priority,
    ) -> oneiron::Result<Embedded> {
        let rows = texts
            .iter()
            .map(|text| {
                let mut row = vec![0.0; SYNTHETIC_DIMS];
                row[text.len() % SYNTHETIC_DIMS] = 1.0;
                row
            })
            .collect();
        Ok(Embedded {
            rows,
            tokens: texts.len(),
        })
    }
}

/// The model [`synthetic`] loads.
const SYNTHETIC_MODEL: &str = "fixture/embedding@1111111111111111111111111111111111111111";
const SYNTHETIC_TRANSFORM: &str = "attn=bidirectional;pool=mean;synthetic";

fn synthetic() -> Arc<dyn ServedModel> {
    Arc::new(Synthetic {
        model_id: SYNTHETIC_MODEL,
        transform: SYNTHETIC_TRANSFORM,
        profile: RunProfile::of(&EmbedderConfig::default()),
        provenance: EmbeddingProvenance::new(
            oneiron::embed::EmbeddingDevice::Cuda,
            "candle 0.11.0 q8_0",
        ),
    })
}

/// Serves `app` on loopback for as long as the returned runtime lives.
fn on_loopback(app: Router) -> (SocketAddr, tokio::runtime::Runtime) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bound");
    let addr = listener.local_addr().expect("address");
    runtime.spawn(async move { axum::serve(listener, app).await });
    (addr, runtime)
}

/// Opens a connection and sends a POST's head with no body after it.
fn post_head(addr: SocketAddr, key: Option<&str>, length: usize) -> std::net::TcpStream {
    use std::io::Write;
    let mut stream = std::net::TcpStream::connect(addr).expect("connected");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    let authorization = key.map_or_else(String::new, |key| {
        format!("Authorization: Bearer {key}\r\n")
    });
    write!(
        stream,
        "POST /v1/embeddings HTTP/1.1\r\nHost: endpoint\r\nContent-Type: application/json\r\n\
         {authorization}Content-Length: {length}\r\n\r\n"
    )
    .expect("head sent");
    stream
}

/// The status a response on `stream` starts with.
fn status(stream: &mut std::net::TcpStream) -> std::io::Result<u16> {
    use std::io::Read;
    let mut line = [0u8; 12];
    stream.read_exact(&mut line)?;
    Ok(String::from_utf8_lossy(&line[9..12])
        .parse()
        .unwrap_or_default())
}

/// Polls until `held` reads `bytes`, for a few seconds at most.
fn holds(served: &Served, bytes: usize) -> bool {
    (0..500).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        served.body_bytes_held() == bytes
    })
}

/// Review P2 (Astra, #1361): the key is checked from a request's headers
/// before any of its body is read. Bug repro: the handler collected the body
/// first, so callers without the key could each make the server hold up to
/// 32 MiB while it waited for the rest.
#[test]
fn a_request_without_the_key_is_refused_before_its_body_is_read() {
    let served = Arc::new(Served::new(
        synthetic(),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &crate::config::LimitsConfig::default(),
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    for key in [None, Some("another key")] {
        let mut stream = post_head(addr, key, MAX_BODY_BYTES);
        assert_eq!(
            status(&mut stream).expect("answered with the body unsent"),
            401
        );
        assert_eq!(served.body_bytes_held(), 0, "no body budget for it");
    }
}

/// Review P2: callers with the key share a byte budget for bodies, taken
/// before a body is read. Past it a large body is not read until an earlier
/// one's request ends, and a query, which draws on its own budget, still
/// answers. Review R7-3 (Sol): a body of no declared length waited on the
/// large budget whatever its size. Review r2 (Sol and Astra, P1): past 32
/// waiters the next request with the key was refused with a 503; under the
/// rate law it waits its turn like the rest.
#[test]
fn bodies_wait_for_their_budget_before_they_are_read() {
    use std::io::Write;
    /// More than the 32 that once could wait.
    const WAITERS: usize = 40;
    let served = Arc::new(Served::new(
        synthetic(),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &crate::config::LimitsConfig::default(),
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let mut uploads: Vec<_> = (0..2 + WAITERS)
        .map(|_| post_head(addr, Some(KEY), MAX_BODY_BYTES))
        .collect();
    let queued = (0..500).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        served.large_bodies.waiting() == WAITERS
    });
    assert!(
        queued,
        "every request past the budget waits; none is turned away"
    );
    assert_eq!(
        served.body_bytes_held(),
        LARGE_BODIES_BYTES,
        "two bodies reserved, the rest wait unread"
    );

    let mut chunked = std::net::TcpStream::connect(addr).expect("connected");
    chunked
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    write!(
        chunked,
        "POST /v1/embeddings HTTP/1.1\r\nHost: endpoint\r\nAuthorization: Bearer {KEY}\r\n\
         Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    )
    .expect("sent");
    assert_eq!(status(&mut chunked).expect("refused at once"), 411);

    let query = serde_json::json!({
        "model": SYNTHETIC_MODEL,
        "input": "a short query",
        "input_type": "query",
    })
    .to_string();
    let mut asking = post_head(addr, Some(KEY), query.len());
    asking.write_all(query.as_bytes()).expect("query sent");
    assert_eq!(status(&mut asking).expect("query answered"), 200);

    // Whichever two were reading, the one left holds its bytes once the
    // others hang up: one that waited was let in.
    uploads.truncate(1);
    assert!(holds(&served, MAX_BODY_BYTES), "one body left");
    drop(uploads);
    assert!(holds(&served, 0), "every request's bytes returned");
}

/// Review P1 (Astra, #1361): a vault may name the model by an alias, and the
/// model behind an alias can change while the alias stays. Every listing row,
/// an alias's too, and every answer names the model loaded, which the vault
/// holds to its own, and the profile it runs with, which decides the vault's
/// evidence floors (review P3). Every answer also names the device and runtime
/// that computed it, which the vault marks its vectors with (ARCH-0036).
/// Review r5 (Sol R5-2, Astra R5-2): freed bytes went to the one waiting
/// body before its task ran again, but the budget still counted it as
/// waiting, so the next request to wait, after the line had run empty,
/// crossed the row and did not ask.
#[tokio::test]
async fn a_wait_after_the_line_ran_empty_crosses_the_body_row_again() {
    use futures_util::FutureExt;
    // One window holds every crossing below.
    let into_minute = oneiron_vault_contract::now_ts() % 60;
    if into_minute > 50 {
        tokio::time::sleep(Duration::from_secs(61 - into_minute)).await;
    }
    let wait = Duration::from_secs(60);
    let questions = Arc::new(LimitQuestions::default());
    let budget = Arc::new(BodyBudget::new(LARGE_BODIES_BYTES));
    let crossings = || {
        questions
            .latest(LimitRow::EmbedderBodyBytes)
            .map_or(0, |question| question.crossings)
    };
    let first = budget.reserve(MAX_BODY_BYTES, wait, &questions).await;
    let second = budget.reserve(MAX_BODY_BYTES, wait, &questions).await;
    assert!(first.is_some() && second.is_some(), "two bodies fit");
    let waiter = tokio::spawn({
        let budget = Arc::clone(&budget);
        let questions = Arc::clone(&questions);
        async move {
            budget
                .reserve(MAX_BODY_BYTES, wait, &questions)
                .await
                .is_some()
        }
    });
    while budget.waiting() == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(crossings(), 1);

    // The freed bytes go to the waiter, whose task runs again only when
    // this one, on the same thread, yields. Nobody waits now.
    drop(first);
    let next = budget
        .reserve(MAX_BODY_BYTES, wait, &questions)
        .now_or_never();
    assert!(next.is_none(), "no bytes are free for it");
    assert_eq!(crossings(), 2, "a wait after the line ran empty crosses");
    assert!(waiter.await.expect("waiter"), "the waiter has its bytes");
}

#[test]
fn every_row_and_answer_names_the_model_loaded() {
    let (addr, _runtime) = on_loopback(router(synthetic(), vec!["shared".to_owned()], None));
    let client = reqwest::blocking::Client::new();
    let listed: serde_json::Value = client
        .get(format!("http://{addr}/v1/models"))
        .send()
        .and_then(reqwest::blocking::Response::json)
        .expect("listing");
    let rows = listed["data"].as_array().expect("rows");
    assert_eq!(rows.len(), 2);
    let profile = serde_json::json!({
        "model_dir": false,
        "quant": "q8_0",
        "attention": "auto",
        "output_quantization": "int8",
        "max_input_tokens": crate::config::embedder::DEFAULT_MAX_INPUT_TOKENS,
    });
    for row in rows {
        assert_eq!(row["model_id"], SYNTHETIC_MODEL, "{row}");
        assert_eq!(row["transform"], SYNTHETIC_TRANSFORM, "{row}");
        assert_eq!(row["profile"], profile, "{row}");
    }
    let answer: serde_json::Value = client
        .post(format!("http://{addr}/v1/embeddings"))
        .json(&serde_json::json!({ "model": "shared", "input": ["one text"] }))
        .send()
        .and_then(reqwest::blocking::Response::json)
        .expect("answer");
    assert_eq!(answer["model"], "shared");
    assert_eq!(answer["model_id"], SYNTHETIC_MODEL);
    assert_eq!(answer["transform"], SYNTHETIC_TRANSFORM);
    assert_eq!(answer["profile"], profile);
    assert_eq!(
        answer["provenance"],
        serde_json::json!({ "device": "cuda", "runtime": "candle 0.11.0 q8_0" })
    );
}

/// A model that takes a while over each request, so several are in flight.
struct Slow(Arc<dyn ServedModel>);

impl ServedModel for Slow {
    fn model_id(&self) -> &str {
        self.0.model_id()
    }

    fn dimensions(&self) -> usize {
        self.0.dimensions()
    }

    fn transform(&self) -> &str {
        self.0.transform()
    }

    fn profile(&self) -> &RunProfile {
        self.0.profile()
    }

    fn provenance(&self) -> EmbeddingProvenance {
        self.0.provenance()
    }

    fn embed_raw(
        &self,
        texts: &[String],
        side: Side,
        instruction: Option<&str>,
        priority: Priority,
    ) -> oneiron::Result<Embedded> {
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.0.embed_raw(texts, side, instruction, priority)
    }
}

/// Sends a whole embeddings request for `input` and reads its status.
fn embed(addr: SocketAddr, input: &serde_json::Value) -> u16 {
    use std::io::Write;
    let body = serde_json::json!({ "model": SYNTHETIC_MODEL, "input": input }).to_string();
    let mut stream = post_head(addr, Some(KEY), body.len());
    stream.write_all(body.as_bytes()).expect("body sent");
    status(&mut stream).unwrap_or_default()
}

/// Joins every caller, counting those not answered 200. All of them were
/// started before any is joined, so they wait at once.
fn unanswered(calls: Vec<std::thread::JoinHandle<u16>>) -> usize {
    calls
        .into_iter()
        .map(|call| call.join().ok())
        .filter(|status| *status != Some(200))
        .count()
}

/// Rule five at the embedder's request row: `callers` requests past a row
/// of one all answer, and the row asks.
pub(crate) fn cross_the_requests(callers: usize) -> crate::admission::Crossing {
    // A row of one: past the first request in flight, the rest wait.
    let limits = crate::config::LimitsConfig {
        embedder_requests: 1,
        ..Default::default()
    };
    let served = Arc::new(Served::new(
        Arc::new(Slow(synthetic())),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &limits,
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let calls: Vec<_> = (0..callers)
        .map(|n| {
            std::thread::spawn(move || {
                embed(
                    addr,
                    &serde_json::json!([format!("document {n}"), "another"]),
                )
            })
        })
        .collect();
    let refused = unanswered(calls);
    crate::admission::Crossing {
        refused,
        asked: served
            .questions
            .latest(LimitRow::EmbedderRequests)
            .is_some(),
    }
}

/// Rule five at the embedder's body row: past a large budget two held
/// bodies fill, `callers` large requests wait, then all answer once the two
/// let go, and the row asks.
pub(crate) fn cross_the_bodies(callers: usize) -> crate::admission::Crossing {
    let served = Arc::new(Served::new(
        synthetic(),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &crate::config::LimitsConfig::default(),
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let holders: Vec<_> = (0..2)
        .map(|_| post_head(addr, Some(KEY), MAX_BODY_BYTES))
        .collect();
    assert!(holds(&served, LARGE_BODIES_BYTES), "the budget is full");
    // Over the small-body size, so each draws on the large budget.
    let large = "x".repeat(SMALL_BODY_BYTES + 1);
    let calls: Vec<_> = (0..callers)
        .map(|_| {
            let large = large.clone();
            std::thread::spawn(move || embed(addr, &serde_json::json!(large)))
        })
        .collect();
    let queued = (0..500).any(|_| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        served.large_bodies.waiting() + calls.iter().filter(|call| call.is_finished()).count()
            == callers
    });
    assert!(queued, "every caller reached the budget");
    drop(holders);
    let refused = unanswered(calls);
    crate::admission::Crossing {
        refused,
        asked: served
            .questions
            .latest(LimitRow::EmbedderBodyBytes)
            .is_some(),
    }
}

/// Rule five at the embedder's answer row: with room for one answer at a
/// time, `callers` requests each wait for the answer before theirs to be
/// delivered, then all answer, and the row asks.
pub(crate) fn cross_the_answers(callers: usize) -> crate::admission::Crossing {
    let limits = crate::config::LimitsConfig {
        embedder_answer_bytes: 1,
        ..Default::default()
    };
    let served = Arc::new(Served::new(
        Arc::new(Slow(synthetic())),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &limits,
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let calls: Vec<_> = (0..callers)
        .map(|n| std::thread::spawn(move || embed(addr, &serde_json::json!([format!("text {n}")]))))
        .collect();
    let refused = unanswered(calls);
    crate::admission::Crossing {
        refused,
        asked: served
            .questions
            .latest(LimitRow::EmbedderAnswerBytes)
            .is_some(),
    }
}

/// Floats in each row the wide model answers.
const WIDE_DIMS: usize = 4_096;

/// A model whose rows are `WIDE_DIMS` wide, so an answer of many inputs is
/// far larger than the sockets between server and client take; it counts
/// the requests it is given.
#[derive(Default)]
struct Wide {
    calls: std::sync::atomic::AtomicUsize,
}

impl Wide {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ServedModel for Wide {
    fn model_id(&self) -> &str {
        SYNTHETIC_MODEL
    }

    fn dimensions(&self) -> usize {
        WIDE_DIMS
    }

    fn transform(&self) -> &str {
        SYNTHETIC_TRANSFORM
    }

    fn profile(&self) -> &RunProfile {
        static PROFILE: std::sync::OnceLock<RunProfile> = std::sync::OnceLock::new();
        PROFILE.get_or_init(|| RunProfile::of(&EmbedderConfig::default()))
    }

    fn provenance(&self) -> EmbeddingProvenance {
        EmbeddingProvenance::new(oneiron::embed::EmbeddingDevice::Cuda, "candle 0.11.0 q8_0")
    }

    fn embed_raw(
        &self,
        texts: &[String],
        _side: Side,
        _instruction: Option<&str>,
        _priority: Priority,
    ) -> oneiron::Result<Embedded> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Embedded {
            rows: texts.iter().map(|_| vec![0.5; WIDE_DIMS]).collect(),
            tokens: texts.len(),
        })
    }
}

/// Review r7 (Astra, P1): an answer kept its whole encoding until its
/// reader took the last piece, and only `embedder_requests` bounded how many
/// did, so callers who read slowly could hold gigabytes of answers. An
/// answer now takes its room in `embedder_answer_bytes` before the model
/// makes it and keeps it until it is delivered; past the row the next
/// request waits its turn, and the row asks.
#[test]
fn an_unread_answer_keeps_its_room_and_the_next_request_waits_for_it() {
    use std::io::Write;
    // Room for one answer at a time: each takes the whole row.
    let limits = crate::config::LimitsConfig {
        embedder_answer_bytes: 1,
        ..Default::default()
    };
    let wide = Arc::new(Wide::default());
    let served = Arc::new(Served::new(
        Arc::clone(&wide) as Arc<dyn ServedModel>,
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
        &limits,
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let inputs: Vec<String> = (0..MAX_INPUTS).map(|n| format!("input {n}")).collect();
    let body = serde_json::json!({ "model": SYNTHETIC_MODEL, "input": inputs }).to_string();
    let send = || {
        let mut stream = post_head(addr, Some(KEY), body.len());
        stream.write_all(body.as_bytes()).expect("body sent");
        stream
    };
    let soon = |done: &dyn Fn() -> bool| {
        (0..1_000).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            done()
        })
    };

    // A 32 MiB answer nobody reads: more than the sockets take.
    let unread = send();
    assert!(soon(&|| wide.calls() == 1), "the first request is embedded");
    let mut next = send();
    assert!(
        soon(&|| served
            .questions
            .latest(LimitRow::EmbedderAnswerBytes)
            .is_some()),
        "the next request waits for the answer row, and the row asks"
    );
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert_eq!(
        wide.calls(),
        1,
        "no answer is made while the one before it holds the row"
    );

    // Once the first answer's reader goes, the next is made and answered.
    drop(unread);
    assert_eq!(status(&mut next).expect("an answer"), 200);
    assert_eq!(wide.calls(), 2);
}
