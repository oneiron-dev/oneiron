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
    let app = router(Arc::clone(&local), vec!["pplx".to_owned()], None);
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

fn synthetic() -> Arc<dyn ServedModel> {
    Arc::new(Synthetic {
        model_id: "fixture/embedding@1111111111111111111111111111111111111111",
        transform: "attn=bidirectional;pool=mean;synthetic",
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
    (0..200).any(|_| {
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
/// one's request ends, and a query, which draws on its own, still answers.
#[test]
fn bodies_wait_for_their_budget_before_they_are_read() {
    use std::io::Write;
    let served = Arc::new(Served::new(
        synthetic(),
        Vec::new(),
        Some(Zeroizing::new(KEY.to_owned())),
    ));
    let (addr, _runtime) = on_loopback(routes(Arc::clone(&served)));
    let mut uploads: Vec<_> = (0..3)
        .map(|_| post_head(addr, Some(KEY), MAX_BODY_BYTES))
        .collect();
    assert!(holds(&served, LARGE_BODIES_BYTES), "two bodies reserved");
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(
        served.body_bytes_held(),
        LARGE_BODIES_BYTES,
        "the third waits, unread"
    );

    let query = serde_json::json!({
        "model": "fixture/embedding@1111111111111111111111111111111111111111",
        "input": "a short query",
        "input_type": "query",
    })
    .to_string();
    let mut asking = post_head(addr, Some(KEY), query.len());
    asking.write_all(query.as_bytes()).expect("query sent");
    assert_eq!(status(&mut asking).expect("query answered"), 200);

    // Whichever two were reading, the one left holds its bytes once the
    // others hang up: the one that waited was let in.
    uploads.truncate(1);
    assert!(holds(&served, MAX_BODY_BYTES), "one body left");
    drop(uploads);
    assert!(holds(&served, 0), "every request's bytes returned");
}
