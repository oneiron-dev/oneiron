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
