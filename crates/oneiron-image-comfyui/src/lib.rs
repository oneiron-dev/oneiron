//! Self-hosted ComfyUI image adapter. Workflow and model dialects are host-supplied data.
//! The engine only sees `ImageIntent`; this crate owns upload, submit, poll and fetch.

use oneiron::llm::image::{ImageBackend, ImageBytes, ImageFuture, ImageIntent, ImageResponse};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId, RetryableLlmError};
use reqwest::{Client, Response, StatusCode, Url, multipart};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};

/// A location in a ComfyUI API-format workflow (`node_id.inputs.input_name`).
#[derive(Debug, Clone)]
pub struct InputField {
    pub node: String,
    pub input: String,
}

/// One workflow dialect, including its output node and reference upload slots.
/// The host supplies API-format graphs; no model prompts are hard-coded in the engine.
#[derive(Debug, Clone)]
pub struct ComfyWorkflow {
    pub graph: Value,
    pub instruction: InputField,
    pub width: InputField,
    pub height: InputField,
    pub params: BTreeMap<String, InputField>,
    pub references: Vec<InputField>,
    pub output_node: String,
}

/// Per-model prompt shim: a generation graph and optional reference-edit graph.
#[derive(Debug, Clone)]
pub struct ComfyModelShim {
    pub generate: ComfyWorkflow,
    pub reference_edit: Option<ComfyWorkflow>,
}

/// Bounded polling and output policy; a zero limit or size is rejected.
#[derive(Clone)]
pub struct ComfyOptions {
    pub max_polls: u32,
    pub poll_interval: Duration,
    pub max_image_bytes: usize,
    pub bearer_token: Option<String>,
    /// Credential for a protected Salad Container Gateway.
    pub salad_api_key: Option<String>,
}
impl Default for ComfyOptions {
    fn default() -> Self {
        Self {
            max_polls: 60,
            poll_interval: Duration::from_secs(1),
            max_image_bytes: 32 * 1024 * 1024,
            bearer_token: None,
            salad_api_key: None,
        }
    }
}

pub struct ComfyUiBackend {
    client: Client,
    base: Url,
    models: BTreeMap<ModelId, ComfyModelShim>,
    options: ComfyOptions,
}

impl ComfyUiBackend {
    /// `base_url` may include a reverse-proxy path prefix. Redirects are disabled so
    /// a peer cannot send the bearer token or reference bytes to another origin.
    pub fn new(
        base_url: &str,
        models: BTreeMap<ModelId, ComfyModelShim>,
        options: ComfyOptions,
    ) -> LlmResult<Self> {
        let mut base = Url::parse(base_url).map_err(|_| FatalLlmError::InvalidRequest)?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || models.is_empty()
            || options.max_polls == 0
            || options.max_image_bytes == 0
            || options.bearer_token.as_ref().is_some_and(String::is_empty)
            || options.salad_api_key.as_ref().is_some_and(|key| {
                key.is_empty() || reqwest::header::HeaderValue::from_str(key).is_err()
            })
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let path = format!("{}/", base.path().trim_end_matches('/'));
        base.set_path(&path);
        for shim in models.values() {
            validate_workflow(&shim.generate)?;
            if let Some(edit) = &shim.reference_edit {
                if edit.references.is_empty() {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                validate_workflow(edit)?;
            }
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        Ok(Self {
            client,
            base,
            models,
            options,
        })
    }

    fn url(&self, path: &str) -> LlmResult<Url> {
        self.base
            .join(path)
            .map_err(|_| FatalLlmError::InvalidRequest.into())
    }

    fn auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match &self.options.bearer_token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        match &self.options.salad_api_key {
            Some(key) => request.header("Salad-Api-Key", key.as_str()),
            None => request,
        }
    }

    async fn upload(
        &self,
        image: ImageBytes,
        index: usize,
        lease: &BudgetLease,
    ) -> LlmResult<String> {
        let extension = match image.media_type.as_str() {
            "image/png" => "png",
            "image/jpeg" => "jpg",
            "image/webp" => "webp",
            _ => return Err(FatalLlmError::InvalidRequest.into()),
        };
        if image.bytes.is_empty() || image.bytes.len() > self.options.max_image_bytes {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let part = multipart::Part::bytes(image.bytes)
            .file_name(format!("reference-{index}.{extension}"))
            .mime_str(&image.media_type)
            .map_err(|_| FatalLlmError::InvalidRequest)?;
        let form = multipart::Form::new()
            .part("image", part)
            .text("type", "input");
        let response = self
            .auth(self.client.post(self.url("upload/image")?))
            .header("x-oneiron-budget-lease", lease.id())
            .multipart(form)
            .send()
            .await
            .map_err(network_error)?;
        let value = json_response(response).await?;
        let name = value["name"]
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or(FatalLlmError::EmptyResponse)?;
        // Comfy returns the assigned name, which may differ if an upload collides.
        let subfolder = value["subfolder"].as_str().unwrap_or("");
        if value["type"].as_str() != Some("input") || !subfolder.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(name.to_owned())
    }

    async fn submit(&self, graph: Value, lease: &BudgetLease) -> LlmResult<String> {
        let response = self
            .auth(self.client.post(self.url("prompt")?))
            .header("x-oneiron-budget-lease", lease.id())
            .json(&json!({"prompt": graph}))
            .send()
            .await
            .map_err(network_error)?;
        let value = json_response(response).await?;
        let id = value["prompt_id"]
            .as_str()
            .filter(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
            .ok_or(FatalLlmError::EmptyResponse)?;
        Ok(id.to_owned())
    }

    async fn poll(&self, id: &str, output_node: &str, lease: &BudgetLease) -> LlmResult<Value> {
        for attempt in 0..self.options.max_polls {
            if attempt > 0 {
                tokio::time::sleep(self.options.poll_interval).await;
            }
            let response = self
                .auth(self.client.get(self.url(&format!("history/{id}"))?))
                .header("x-oneiron-budget-lease", lease.id())
                .send()
                .await
                .map_err(network_error)?;
            let value = json_response(response).await?;
            let job = &value[id];
            if job.is_null() {
                continue;
            }
            if job["status"]["status_str"] == "error"
                || job["status"]["status_str"] == "interrupted"
            {
                return Err(RetryableLlmError::ServerError.into());
            }
            let images = job["outputs"][output_node]["images"].as_array();
            if let Some(image) = images.and_then(|images| images.first()) {
                return Ok(image.clone());
            }
            if job["status"]["completed"] == true {
                return Err(FatalLlmError::EmptyResponse.into());
            }
        }
        Err(RetryableLlmError::Timeout.into())
    }

    async fn fetch(&self, image: &Value, lease: &BudgetLease) -> LlmResult<ImageBytes> {
        let filename = image["filename"]
            .as_str()
            .filter(|v| !v.is_empty())
            .ok_or(FatalLlmError::EmptyResponse)?;
        let subfolder = image["subfolder"].as_str().unwrap_or("");
        if image["type"].as_str() != Some("output") {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let mut url = self.url("view")?;
        url.query_pairs_mut()
            .append_pair("filename", filename)
            .append_pair("subfolder", subfolder)
            .append_pair("type", "output");
        let response = self
            .auth(self.client.get(url))
            .header("x-oneiron-budget-lease", lease.id())
            .send()
            .await
            .map_err(network_error)?;
        check_status(response.status())?;
        let media_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|header| header.to_str().ok())
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_owned();
        if !matches!(
            media_type.as_str(),
            "image/png" | "image/jpeg" | "image/webp"
        ) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let bytes = bounded_body(response, self.options.max_image_bytes).await?;
        if bytes.is_empty() {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(ImageBytes { bytes, media_type })
    }

    async fn render(
        &self,
        intent: ImageIntent,
        references: Option<Vec<ImageBytes>>,
        lease: &BudgetLease,
    ) -> LlmResult<ImageResponse> {
        let shim = self
            .models
            .get(&intent.model)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let workflow = match &references {
            None => &shim.generate,
            Some(_) => shim
                .reference_edit
                .as_ref()
                .ok_or(FatalLlmError::InvalidRequest)?,
        };
        if intent.instruction.trim().is_empty()
            || intent.width == 0
            || intent.height == 0
            || intent
                .params
                .keys()
                .any(|name| !workflow.params.contains_key(name))
            || references
                .as_ref()
                .is_some_and(|refs| refs.is_empty() || refs.len() != workflow.references.len())
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let mut graph = workflow.graph.clone();
        set_input(&mut graph, &workflow.instruction, json!(intent.instruction))?;
        set_input(&mut graph, &workflow.width, json!(intent.width))?;
        set_input(&mut graph, &workflow.height, json!(intent.height))?;
        for (name, value) in intent.params {
            set_input(&mut graph, &workflow.params[&name], value)?;
        }
        if let Some(refs) = references {
            // Validate all references before any upload or submit side effect.
            if refs.iter().any(|r| {
                r.bytes.is_empty()
                    || r.bytes.len() > self.options.max_image_bytes
                    || !matches!(
                        r.media_type.as_str(),
                        "image/png" | "image/jpeg" | "image/webp"
                    )
            }) {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            for (index, (field, image)) in workflow.references.iter().zip(refs).enumerate() {
                let filename = self.upload(image, index, lease).await?;
                set_input(&mut graph, field, json!(filename))?;
            }
        }
        let id = self.submit(graph, lease).await?;
        let image = self.poll(&id, &workflow.output_node, lease).await?;
        let bytes = self.fetch(&image, lease).await?;
        Ok(ImageResponse {
            image: bytes,
            model: intent.model,
            metadata: BTreeMap::from([("prompt_id".into(), json!(id))]),
        })
    }
}

impl ImageBackend for ComfyUiBackend {
    fn generate<'a>(&'a self, intent: ImageIntent, lease: &'a BudgetLease) -> ImageFuture<'a> {
        Box::pin(self.render(intent, None, lease))
    }
    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        references: Vec<ImageBytes>,
        lease: &'a BudgetLease,
    ) -> ImageFuture<'a> {
        Box::pin(self.render(intent, Some(references), lease))
    }
}

fn set_input(graph: &mut Value, field: &InputField, value: Value) -> LlmResult<()> {
    let input = graph
        .get_mut(&field.node)
        .and_then(|node| node.get_mut("inputs"))
        .and_then(|inputs| inputs.get_mut(&field.input))
        .ok_or(FatalLlmError::InvalidRequest)?;
    *input = value;
    Ok(())
}
fn validate_workflow(workflow: &ComfyWorkflow) -> LlmResult<()> {
    if !workflow.graph.is_object()
        || !workflow
            .graph
            .get(&workflow.output_node)
            .is_some_and(Value::is_object)
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let mut graph = workflow.graph.clone();
    for field in [&workflow.instruction, &workflow.width, &workflow.height]
        .into_iter()
        .chain(workflow.params.values())
        .chain(&workflow.references)
    {
        set_input(&mut graph, field, Value::Null)?;
    }
    Ok(())
}
fn check_status(status: StatusCode) -> LlmResult<()> {
    if status.is_success() {
        return Ok(());
    }
    Err(match status.as_u16() {
        401 | 403 => FatalLlmError::Auth.into(),
        429 => RetryableLlmError::RateLimited { retry_after: None }.into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    })
}
fn network_error(error: reqwest::Error) -> oneiron::LlmError {
    if error.is_timeout() {
        RetryableLlmError::Timeout.into()
    } else {
        RetryableLlmError::ServerError.into()
    }
}
async fn bounded_body(mut response: Response, max: usize) -> LlmResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
        if chunk.len() > max.saturating_sub(body.len()) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
async fn json_response(response: Response) -> LlmResult<Value> {
    check_status(response.status())?;
    let body = bounded_body(response, 1024 * 1024).await?;
    serde_json::from_slice(&body).map_err(|_| FatalLlmError::EmptyResponse.into())
}
