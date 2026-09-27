use super::*;
use oneiron::llm::image::{ImageCatalog, ImageCatalogRow};
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

#[derive(Clone)]
struct FixtureTransport {
    calls: Arc<Mutex<Vec<OpenAiImageHttpRequest>>>,
    response: OpenAiImageHttpResponse,
}
impl OpenAiImageTransport for FixtureTransport {
    fn execute<'a>(
        &'a self,
        request: OpenAiImageHttpRequest,
        _: &'a BudgetLease,
    ) -> OpenAiImageTransportFuture<'a> {
        self.calls.lock().unwrap().push(request);
        let response = self.response.clone();
        Box::pin(async move { Ok(response) })
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("fixture unexpectedly pending"),
    }
}
fn fixture() -> (
    ImageCatalog,
    Arc<Mutex<Vec<OpenAiImageHttpRequest>>>,
    ImageIntent,
    BudgetLease,
) {
    let model = ModelId::new("openai/gpt-image-2@1").unwrap();
    let intent = ImageIntent {
        model: model.clone(),
        instruction: "Keep the reference layout".into(),
        width: 1024,
        height: 1024,
        params: BTreeMap::from([
            ("output_format".into(), serde_json::json!("webp")),
            ("output_compression".into(), serde_json::json!(80)),
            ("stream".into(), serde_json::json!(false)),
        ]),
    };
    let calls = Arc::new(Mutex::new(Vec::new()));
    let adapter = DirectOpenAiImageBackend::new(FixtureTransport {
        calls: calls.clone(),
        response: OpenAiImageHttpResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: serde_json::json!({
                "created": 1234,
                "usage": {"input_tokens": 18},
                "data": [{"b64_json": "AAECAw==", "revised_prompt": "refined"}]
            }),
        },
    });
    let catalog = ImageCatalog::new(
        vec![ImageCatalogRow {
            model,
            adapter: "openai-direct".into(),
            generate: true,
            reference_edit: true,
            max_pixels: 1024 * 1024,
        }],
        BTreeMap::from([(
            "openai-direct".into(),
            Arc::new(adapter) as Arc<dyn ImageBackend>,
        )]),
    )
    .unwrap();
    (
        catalog,
        calls,
        intent,
        BudgetLease::for_test("image-fixture"),
    )
}

#[test]
fn direct_edit_maps_all_eight_ordered_references_and_returns_bytes_with_metadata() {
    let (catalog, calls, intent, lease) = fixture();
    for count in [1, 8] {
        let refs = (0..count)
            .map(|i| ImageBytes {
                bytes: vec![i as u8, 55],
                media_type: if i % 2 == 0 {
                    "image/png"
                } else {
                    "image/jpeg"
                }
                .into(),
            })
            .collect::<Vec<_>>();
        let result = run(catalog.render(intent.clone(), Some(refs.clone()), &lease)).unwrap();
        assert_eq!(result.model, intent.model);
        assert_eq!(
            result.image,
            (ImageBytes {
                bytes: vec![0, 1, 2, 3],
                media_type: "image/webp".into()
            })
        );
        assert_eq!(result.metadata["created"], 1234);
        assert_eq!(result.metadata["usage"]["input_tokens"], 18);
        assert_eq!(
            result.metadata["image_metadata"]["revised_prompt"],
            "refined"
        );
        let request = calls.lock().unwrap().last().unwrap().clone();
        assert_eq!(request.path, "/v1/images/edits");
        let OpenAiImageBody::Multipart { fields, images } = request.body else {
            panic!("expected multipart edit")
        };
        assert_eq!(fields["model"], "gpt-image-2");
        assert_eq!(fields["prompt"], intent.instruction);
        assert_eq!(fields["size"], "1024x1024");
        assert_eq!(fields["n"], "1");
        assert_eq!(fields["output_format"], "webp");
        assert_eq!(fields["output_compression"], "80");
        assert_eq!(fields["stream"], "false");
        assert_eq!(images.len(), count);
        for (i, (image, original)) in images.iter().zip(refs.iter()).enumerate() {
            assert_eq!(image.name, "image[]");
            assert_eq!(image.bytes, original.bytes);
            assert_eq!(image.media_type, original.media_type);
            assert_eq!(
                image.filename,
                format!("reference-{i}.{}", if i % 2 == 0 { "png" } else { "jpg" })
            );
        }
    }
}

#[test]
fn direct_generate_maps_json_request_and_decodes_response() {
    let (catalog, calls, intent, lease) = fixture();
    let result = run(catalog.render(intent.clone(), None, &lease)).unwrap();
    assert_eq!(result.image.bytes, [0, 1, 2, 3]);
    assert_eq!(result.image.media_type, "image/webp");
    assert_eq!(result.metadata["created"], 1234);
    let request = calls.lock().unwrap().last().unwrap().clone();
    assert_eq!(request.path, "/v1/images/generations");
    let OpenAiImageBody::Json(body) = request.body else {
        panic!("expected JSON generation")
    };
    assert_eq!(body["model"], "gpt-image-2");
    assert_eq!(body["n"], 1);
    assert_eq!(body["prompt"], intent.instruction);
    assert_eq!(body["output_format"], "webp");
    assert_eq!(body["output_compression"], 80);
    assert_eq!(body["stream"], false);
}

#[test]
fn direct_edit_refuses_out_of_range_and_malformed_references_before_transport() {
    let (catalog, calls, intent, lease) = fixture();
    for count in [0, 9] {
        let refs = (0..count)
            .map(|_| ImageBytes {
                bytes: vec![1],
                media_type: "image/png".into(),
            })
            .collect();
        assert!(matches!(
            run(catalog.render(intent.clone(), Some(refs), &lease)),
            Err(oneiron::LlmError::Fatal(FatalLlmError::InvalidRequest))
        ));
    }
    for bad in [
        ImageBytes {
            bytes: vec![],
            media_type: "image/png".into(),
        },
        ImageBytes {
            bytes: vec![1],
            media_type: "image/svg+xml".into(),
        },
    ] {
        assert!(matches!(
            run(catalog.render(intent.clone(), Some(vec![bad]), &lease)),
            Err(oneiron::LlmError::Fatal(FatalLlmError::InvalidRequest))
        ));
    }
    let mut bad_intent = intent;
    bad_intent
        .params
        .insert("output_format".into(), serde_json::json!("gif"));
    assert!(matches!(
        run(catalog.render(bad_intent, None, &lease)),
        Err(oneiron::LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    assert!(calls.lock().unwrap().is_empty());
}

#[test]
fn direct_response_rejects_missing_or_invalid_image_and_preserves_status_taxonomy() {
    for (status, body) in [
        (200, serde_json::json!({"data": []})),
        (200, serde_json::json!({"data": [{"b64_json": "%%%"}]})),
        (429, serde_json::json!({"error": {}})),
    ] {
        let (catalog, _, intent, lease) = fixture();
        let fields = fields(&intent).unwrap().1;
        let err = decode_response(
            OpenAiImageHttpResponse {
                status,
                headers: BTreeMap::new(),
                body,
            },
            intent.model.clone(),
            &fields,
        )
        .unwrap_err();
        if status == 429 {
            assert!(matches!(
                err,
                oneiron::LlmError::Retryable(oneiron::RetryableLlmError::RateLimited { .. })
            ));
        } else {
            assert!(matches!(
                err,
                oneiron::LlmError::Fatal(FatalLlmError::EmptyResponse)
            ));
        }
        drop((catalog, lease));
    }
}
