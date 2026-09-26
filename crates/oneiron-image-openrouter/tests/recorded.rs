//! Recorded OpenRouter Image API envelopes; no live API key or network.
use oneiron::llm::image::{ImageBackend, ImageBytes, ImageCatalog, ImageIntent};
use oneiron::{BudgetLease, FatalLlmError, LlmError, ModelId, RetryableLlmError};
use oneiron_image_openrouter::{
    OpenRouterImageBackend, OpenRouterImageConfig, OpenRouterImageFuture,
    OpenRouterImageHttpRequest, OpenRouterImageHttpResponse, OpenRouterImageModel,
    OpenRouterImageTransport, PromptShim, build_image_request, parse_image_response,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

fn run<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("fixture transport must be ready"),
    }
}

fn fixtures() -> Vec<Value> {
    serde_json::from_str(include_str!("fixtures/openrouter-images.json"))
        .expect("recorded fixture and transport must be valid")
}

fn config(rows: &[Value]) -> OpenRouterImageConfig {
    OpenRouterImageConfig::new(
        rows.iter()
            .map(|row| OpenRouterImageModel {
                model: ModelId::new(
                    row["model"]
                        .as_str()
                        .expect("recorded fixture and transport must be valid"),
                )
                .expect("recorded fixture and transport must be valid"),
                wire_model: row["wire_model"]
                    .as_str()
                    .expect("recorded fixture and transport must be valid")
                    .to_owned(),
                shim: PromptShim {
                    generate: row["shim"]["generate"]
                        .as_str()
                        .expect("recorded fixture and transport must be valid")
                        .to_owned(),
                    reference_edit: row["shim"]["reference_edit"]
                        .as_str()
                        .expect("recorded fixture and transport must be valid")
                        .to_owned(),
                },
                max_references: row["max_references"]
                    .as_u64()
                    .expect("recorded fixture and transport must be valid")
                    as usize,
                max_pixels: 1024 * 1024,
                allowed_params: row["allowed_params"]
                    .as_array()
                    .expect("recorded fixture and transport must be valid")
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .expect("recorded fixture and transport must be valid")
                            .to_owned()
                    })
                    .collect::<BTreeSet<_>>(),
            })
            .collect(),
    )
    .expect("recorded fixture and transport must be valid")
}

fn intent(row: &Value) -> ImageIntent {
    ImageIntent {
        model: ModelId::new(
            row["model"]
                .as_str()
                .expect("recorded fixture and transport must be valid"),
        )
        .expect("recorded fixture and transport must be valid"),
        instruction: row["instruction"]
            .as_str()
            .expect("recorded fixture and transport must be valid")
            .to_owned(),
        width: 512,
        height: 768,
        params: serde_json::from_value(row["params"].clone())
            .expect("recorded fixture and transport must be valid"),
    }
}

fn references(row: &Value) -> Vec<ImageBytes> {
    serde_json::from_value(row["references"].clone())
        .expect("recorded fixture and transport must be valid")
}

#[test]
fn recorded_per_model_shims_and_request_response_mapping() {
    let rows = fixtures();
    let config = config(&rows.iter().step_by(2).cloned().collect::<Vec<_>>());
    assert_eq!(config.catalog_rows().len(), 3);
    for row in rows {
        let model = ModelId::new(
            row["model"]
                .as_str()
                .expect("recorded fixture and transport must be valid"),
        )
        .expect("recorded fixture and transport must be valid");
        let request = build_image_request(&config, &intent(&row), &references(&row))
            .expect("recorded fixture and transport must be valid");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/v1/images");
        assert_eq!(request.headers["content-type"], "application/json");
        assert_eq!(
            request.body, row["expected_request"],
            "{} {}",
            row["model"], row["mode"]
        );
        let response = parse_image_response(&row["response"], model)
            .expect("recorded fixture and transport must be valid");
        assert_eq!(
            serde_json::to_value(response.image)
                .expect("recorded fixture and transport must be valid"),
            row["expected_image"]
        );
        assert_eq!(
            serde_json::to_value(response.metadata)
                .expect("recorded fixture and transport must be valid"),
            row["expected_metadata"]
        );
    }
}

struct RecordedTransport {
    seen: Mutex<Vec<OpenRouterImageHttpRequest>>,
    response: OpenRouterImageHttpResponse,
}
impl OpenRouterImageTransport for RecordedTransport {
    fn execute<'a>(
        &'a self,
        request: OpenRouterImageHttpRequest,
        _: &'a BudgetLease,
    ) -> OpenRouterImageFuture<'a> {
        self.seen
            .lock()
            .expect("recorded fixture and transport must be valid")
            .push(request);
        Box::pin(async { Ok(self.response.clone()) })
    }
}

#[test]
fn catalog_dispatches_both_verbs_and_adapter_checks_http_status() {
    let rows = fixtures();
    let config = config(&rows.iter().step_by(2).cloned().collect::<Vec<_>>());
    let fixture = &rows[0];
    let transport = RecordedTransport {
        seen: Mutex::new(vec![]),
        response: OpenRouterImageHttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: fixture["response"].clone(),
        },
    };
    let adapter = Arc::new(OpenRouterImageBackend::new(config.clone(), transport));
    let catalog = ImageCatalog::new(
        config.catalog_rows(),
        BTreeMap::from([(
            "openrouter".into(),
            adapter.clone() as Arc<dyn ImageBackend>,
        )]),
    )
    .expect("recorded fixture and transport must be valid");
    let lease = BudgetLease::for_test("image");
    let image = run(catalog.render(intent(fixture), None, &lease))
        .expect("recorded fixture and transport must be valid");
    assert_eq!(image.model, intent(fixture).model);
    let edited = run(catalog.render(intent(&rows[1]), Some(references(&rows[1])), &lease))
        .expect("recorded fixture and transport must be valid");
    assert_eq!(edited.image, image.image);
    let seen = adapter.config().catalog_rows();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        adapter
            .transport()
            .seen
            .lock()
            .expect("recorded fixture and transport must be valid")
            .len(),
        2
    );

    assert!(matches!(
        run(adapter.reference_edit(intent(fixture), vec![], &lease)),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));

    let rejected = OpenRouterImageBackend::new(
        config,
        RecordedTransport {
            seen: Mutex::new(vec![]),
            response: OpenRouterImageHttpResponse {
                status: 429,
                headers: BTreeMap::from([("Retry-After".into(), "3".into())]),
                body: json!({ "error": { "message": "slow down" } }),
            },
        },
    );
    assert!(matches!(
        run(rejected.generate(intent(fixture), &lease)),
        Err(LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after: Some(3)
        }))
    ));
}

#[test]
fn malformed_input_and_output_fail_closed() {
    let rows = fixtures();
    let config = config(&rows.iter().step_by(2).cloned().collect::<Vec<_>>());
    let mut literal = intent(&rows[1]);
    literal.instruction = "Keep the literal {reference_count} token".into();
    assert_eq!(
        build_image_request(&config, &literal, &references(&rows[1]))
            .expect("literal instruction is valid")
            .body["prompt"],
        "Edit the supplied 1 reference images: Keep the literal {reference_count} token"
    );
    let mut request = intent(&rows[0]);
    request
        .params
        .insert("model".into(), json!("attacker/override"));
    assert!(matches!(
        build_image_request(&config, &request, &[]),
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    let model = intent(&rows[0]).model;
    for response in [
        json!({"data":[]}),
        json!({"data":[{"b64_json":"!!!!"}]}),
        json!({"data":[{"b64_json":"eA=="}]}),
        json!({"data":[{"b64_json":"eA==","media_type":"text/plain"}]}),
        json!({"data":[{"b64_json":"eA==","media_type":"image/png"},{"b64_json":"eA=="}]}),
    ] {
        assert!(parse_image_response(&response, model.clone()).is_err());
    }
    let mut edit = intent(&rows[1]);
    edit.params.clear();
    let bad_ref = ImageBytes {
        bytes: vec![1],
        media_type: "image/png;bad,header".into(),
    };
    assert!(build_image_request(&config, &edit, &[bad_ref]).is_err());
}

#[test]
fn status_errors_are_typed() {
    let headers = BTreeMap::from([("Retry-After".into(), "3".into())]);
    assert!(matches!(
        oneiron_image_openrouter::classify_image_status(429, &headers, &json!({})),
        LlmError::Retryable(RetryableLlmError::RateLimited {
            retry_after: Some(3)
        })
    ));
    assert!(matches!(
        oneiron_image_openrouter::classify_image_status(451, &headers, &json!({})),
        LlmError::Fatal(FatalLlmError::ContentFiltered)
    ));
}
