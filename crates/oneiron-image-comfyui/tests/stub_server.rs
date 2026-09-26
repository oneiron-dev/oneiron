//! Stub HTTP peer checks the actual ComfyUI wire rather than a mocked transport.
use oneiron::llm::image::{ImageBackend, ImageBytes, ImageCatalog, ImageCatalogRow, ImageIntent};
use oneiron::{BudgetLease, FatalLlmError, LlmError, ModelId, RetryableLlmError};
use oneiron_image_comfyui::{
    ComfyModelShim, ComfyOptions, ComfyUiBackend, ComfyWorkflow, InputField,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::Arc,
    thread,
    time::Duration,
};

struct Expected {
    method: &'static str,
    path: &'static str,
    status: u16,
    content_type: &'static str,
    body: String,
}
fn reply(method: &'static str, path: &'static str, body: Value) -> Expected {
    Expected {
        method,
        path,
        status: 200,
        content_type: "application/json",
        body: body.to_string(),
    }
}
type CapturedRequests = Vec<(String, Vec<u8>, Option<String>)>;
fn stub(steps: Vec<Expected>) -> (String, thread::JoinHandle<CapturedRequests>) {
    stub_with_gateway(steps, false)
}
fn stub_with_gateway(
    steps: Vec<Expected>,
    protected: bool,
) -> (String, thread::JoinHandle<CapturedRequests>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let url = format!("http://{}", listener.local_addr().expect("stub address"));
    let handle = thread::spawn(move || {
        let mut captures = Vec::new();
        for step in steps {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read deadline");
            let mut reader = BufReader::new(&mut stream);
            let mut line = String::new();
            reader.read_line(&mut line).expect("request line");
            assert_eq!(
                line.trim_end(),
                format!("{} {} HTTP/1.1", step.method, step.path)
            );
            let mut content_length = 0;
            let mut has_lease = false;
            let mut salad_key = None;
            loop {
                line.clear();
                reader.read_line(&mut line).expect("request headers");
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim().split_once(':').expect("header pair");
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().expect("length");
                }
                if name.eq_ignore_ascii_case("x-oneiron-budget-lease") {
                    has_lease = value.trim() == "fixture";
                }
                if name.eq_ignore_ascii_case("Salad-Api-Key") {
                    salad_key = Some(value.trim().to_owned());
                }
            }
            assert!(has_lease, "lease header missing");
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("request body");
            // A protected gateway refuses missing or wrong keys before ComfyUI sees the call.
            let authorized = !protected || salad_key.as_deref() == Some("fixture-salad-key");
            let (status, response_body) = if authorized {
                (step.status, step.body.as_str())
            } else {
                (401, "{}")
            };
            write!(stream, "HTTP/1.1 {} Fixture\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status, step.content_type, response_body.len(), response_body).expect("response");
            captures.push((step.path.to_owned(), body, salad_key));
        }
        captures
    });
    (url, handle)
}
fn field(node: &str, input: &str) -> InputField {
    InputField {
        node: node.into(),
        input: input.into(),
    }
}
fn workflow(edit: bool) -> ComfyWorkflow {
    ComfyWorkflow {
        graph: json!({
            "text": {"class_type": "CLIPTextEncode", "inputs": {"text": "placeholder"}},
            "latent": {"class_type": "EmptyLatentImage", "inputs": {"width": 1, "height": 1}},
            "image": {"class_type": "LoadImage", "inputs": {"image": "placeholder"}},
            "save": {"class_type": "SaveImage", "inputs": {"images": ["latent", 0]}}
        }),
        instruction: field("text", "text"),
        width: field("latent", "width"),
        height: field("latent", "height"),
        params: BTreeMap::from([("style".into(), field("text", "style"))]),
        references: if edit {
            vec![field("image", "image")]
        } else {
            vec![]
        },
        output_node: "save".into(),
    }
}
fn backend(url: &str, polls: u32) -> ComfyUiBackend {
    backend_with_salad_key(url, polls, None)
}
fn backend_with_salad_key(url: &str, polls: u32, salad_key: Option<&str>) -> ComfyUiBackend {
    let mut generate = workflow(false);
    generate.params.clear();
    let mut edit = workflow(true);
    edit.graph["text"]["inputs"]["style"] = json!("unset");
    let model = ModelId::new("comfy/illustration@1").expect("model");
    ComfyUiBackend::new(
        url,
        BTreeMap::from([(
            model,
            ComfyModelShim {
                generate,
                reference_edit: Some(edit),
            },
        )]),
        ComfyOptions {
            max_polls: polls,
            poll_interval: Duration::ZERO,
            max_image_bytes: 1024,
            bearer_token: Some("test-token".into()),
            salad_api_key: salad_key.map(str::to_owned),
        },
    )
    .expect("backend")
}
fn intent(edit: bool) -> ImageIntent {
    ImageIntent {
        model: ModelId::new("comfy/illustration@1").expect("model"),
        instruction: "keep face, change outfit".into(),
        width: 640,
        height: 512,
        params: if edit {
            BTreeMap::from([("style".into(), json!("watercolor"))])
        } else {
            BTreeMap::new()
        },
    }
}
fn finished() -> Value {
    json!({"job-1": {"status": {"completed": true, "status_str": "success"},
        "outputs": {"save": {"images": [{"filename": "portrait one.png", "subfolder": "outputs",
            "type": "output"}]}}}})
}
fn fetch() -> Expected {
    Expected {
        method: "GET",
        path: "/view?filename=portrait+one.png&subfolder=outputs&type=output",
        status: 200,
        content_type: "image/png",
        body: "PNG bytes".into(),
    }
}
#[tokio::test]
async fn generates_via_submit_poll_fetch_with_model_shim_and_catalog() {
    let (url, peer) = stub(vec![
        reply("POST", "/prompt", json!({"prompt_id": "job-1"})),
        reply("GET", "/history/job-1", json!({})),
        reply("GET", "/history/job-1", finished()),
        fetch(),
    ]);
    let backend = backend(&url, 3);
    let model = intent(false).model;
    let catalog = ImageCatalog::new(
        vec![ImageCatalogRow {
            model,
            adapter: "comfy".into(),
            generate: true,
            reference_edit: true,
            max_pixels: 1024 * 1024,
        }],
        BTreeMap::from([("comfy".into(), Arc::new(backend) as Arc<dyn ImageBackend>)]),
    )
    .expect("catalog");
    let response = catalog
        .render(intent(false), None, &BudgetLease::for_test("fixture"))
        .await
        .expect("render");
    assert_eq!(response.image.bytes, b"PNG bytes");
    assert_eq!(response.image.media_type, "image/png");
    assert_eq!(response.metadata["prompt_id"], "job-1");
    let requests = peer.join().expect("stub");
    let submitted: Value = serde_json::from_slice(&requests[0].1).expect("submit json");
    assert_eq!(
        submitted["prompt"]["text"]["inputs"]["text"],
        "keep face, change outfit"
    );
    assert_eq!(submitted["prompt"]["latent"]["inputs"]["width"], 640);
    assert_eq!(submitted["prompt"]["latent"]["inputs"]["height"], 512);
    assert_eq!(submitted["prompt"]["text"]["class_type"], "CLIPTextEncode");
    assert_eq!(requests.len(), 4);
}
#[tokio::test]
async fn reference_edit_uploads_then_submits_assigned_filename_and_params() {
    let (url, peer) = stub(vec![
        reply(
            "POST",
            "/upload/image",
            json!({"name": "server-assigned.jpg", "subfolder": "", "type": "input"}),
        ),
        reply("POST", "/prompt", json!({"prompt_id": "job-1"})),
        reply("GET", "/history/job-1", finished()),
        fetch(),
    ]);
    let backend = backend(&url, 1);
    let reference = ImageBytes {
        bytes: b"JPEG reference".to_vec(),
        media_type: "image/jpeg".into(),
    };
    let response = backend
        .reference_edit(
            intent(true),
            vec![reference],
            &BudgetLease::for_test("fixture"),
        )
        .await
        .expect("reference edit");
    assert_eq!(response.image.bytes, b"PNG bytes");
    let requests = peer.join().expect("stub");
    assert!(String::from_utf8_lossy(&requests[0].1).contains("JPEG reference"));
    assert!(String::from_utf8_lossy(&requests[0].1).contains("reference-0.jpg"));
    let submitted: Value = serde_json::from_slice(&requests[1].1).expect("submit json");
    assert_eq!(
        submitted["prompt"]["image"]["inputs"]["image"],
        "server-assigned.jpg"
    );
    assert_eq!(submitted["prompt"]["text"]["inputs"]["style"], "watercolor");
}
#[tokio::test]
async fn incomplete_job_times_out_and_bad_output_is_rejected_without_fetch() {
    let (url, peer) = stub(vec![
        reply("POST", "/prompt", json!({"prompt_id": "job-1"})),
        reply("GET", "/history/job-1", json!({})),
    ]);
    let error = backend(&url, 1)
        .generate(intent(false), &BudgetLease::for_test("fixture"))
        .await
        .expect_err("bounded poll");
    assert!(matches!(
        error,
        LlmError::Retryable(RetryableLlmError::Timeout)
    ));
    assert_eq!(peer.join().expect("stub").len(), 2);

    let (url, peer) = stub(vec![
        reply("POST", "/prompt", json!({"prompt_id": "job-1"})),
        reply(
            "GET",
            "/history/job-1",
            json!({"job-1": {"status": {"completed": true},
            "outputs": {"save": {"images": [{"filename": "bad", "type": "input"}]}}}}),
        ),
    ]);
    let error = backend(&url, 1)
        .generate(intent(false), &BudgetLease::for_test("fixture"))
        .await
        .expect_err("must not fetch input images");
    assert!(matches!(
        error,
        LlmError::Fatal(FatalLlmError::InvalidRequest)
    ));
    assert_eq!(peer.join().expect("stub").len(), 2);
}
#[tokio::test]
async fn protected_salad_gateway_authenticates_upload_submit_poll_and_fetch() {
    let (url, peer) = stub_with_gateway(
        vec![
            reply(
                "POST",
                "/upload/image",
                json!({"name": "reference.png", "subfolder": "", "type": "input"}),
            ),
            reply("POST", "/prompt", json!({"prompt_id": "job-1"})),
            reply("GET", "/history/job-1", finished()),
            fetch(),
        ],
        true,
    );
    let backend = backend_with_salad_key(&url, 1, Some("fixture-salad-key"));
    let reference = ImageBytes {
        bytes: b"reference".to_vec(),
        media_type: "image/png".into(),
    };
    let response = backend
        .reference_edit(
            intent(true),
            vec![reference],
            &BudgetLease::for_test("fixture"),
        )
        .await
        .expect("protected render");
    assert_eq!(response.image.bytes, b"PNG bytes");
    let requests = peer.join().expect("protected peer");
    assert_eq!(requests.len(), 4);
    for (path, _, key) in requests {
        assert!(
            matches!(
                path.as_str(),
                "/upload/image" | "/prompt" | "/history/job-1"
            ) || path.starts_with("/view?")
        );
        assert_eq!(
            key.as_deref(),
            Some("fixture-salad-key"),
            "missing key on {path}"
        );
    }

    let (url, peer) = stub_with_gateway(
        vec![reply("POST", "/prompt", json!({"prompt_id": "job-1"}))],
        true,
    );
    let error = backend_with_salad_key(&url, 1, Some("wrong-key"))
        .generate(intent(false), &BudgetLease::for_test("fixture"))
        .await
        .expect_err("protected gateway must reject wrong key");
    assert!(matches!(error, LlmError::Fatal(FatalLlmError::Auth)));
    assert_eq!(
        peer.join().expect("rejecting peer")[0].2.as_deref(),
        Some("wrong-key")
    );
}

#[tokio::test]
async fn invalid_model_and_references_fail_before_network() {
    let backend = backend("http://127.0.0.1:1", 1);
    let mut input = intent(false);
    input.model = ModelId::new("comfy/other@1").expect("model");
    assert!(matches!(
        backend
            .generate(input, &BudgetLease::for_test("fixture"))
            .await,
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    assert!(matches!(
        backend
            .reference_edit(intent(true), vec![], &BudgetLease::for_test("fixture"))
            .await,
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
    assert!(matches!(
        backend
            .reference_edit(
                intent(true),
                vec![ImageBytes {
                    bytes: vec![1],
                    media_type: "text/plain".into()
                }],
                &BudgetLease::for_test("fixture")
            )
            .await,
        Err(LlmError::Fatal(FatalLlmError::InvalidRequest))
    ));
}
