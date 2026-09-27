//! Model-local prompt configuration and host-owned HTTP transport.
use crate::{build_image_request, classify_image_status, parse_image_response};
use oneiron::llm::image::{ImageBackend, ImageCatalogRow, ImageFuture, ImageIntent, ImageResponse};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;

const ADAPTER: &str = "openrouter";

/// Templates are host configuration, not engine-authored prompt text. Each must contain
/// exactly one `{instruction}` slot; edits may also use `{reference_count}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptShim {
    pub generate: String,
    pub reference_edit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenRouterImageModel {
    pub model: ModelId,
    /// OpenRouter model slug (for example `openai/gpt-image-2`).
    pub wire_model: String,
    pub shim: PromptShim,
    pub max_references: usize,
    pub max_pixels: u64,
    /// Only these optional, endpoint-supported ImageIntent.params may pass through.
    pub allowed_params: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct OpenRouterImageConfig {
    pub endpoint_path: String,
    models: BTreeMap<ModelId, OpenRouterImageModel>,
}

impl OpenRouterImageConfig {
    /// The host supplies the catalog (including current endpoint capabilities and shims).
    /// This keeps endpoint limits and prompt wording out of the engine binary.
    pub fn new(models: Vec<OpenRouterImageModel>) -> LlmResult<Self> {
        let mut map = BTreeMap::new();
        for row in models {
            if row.wire_model.trim().is_empty()
                || !row.wire_model.contains('/')
                || row.max_pixels == 0
                || !valid_template(&row.shim.generate, false)
                || !valid_template(&row.shim.reference_edit, true)
                || row.allowed_params.iter().any(|key| {
                    !matches!(
                        key.as_str(),
                        "quality"
                            | "output_format"
                            | "background"
                            | "output_compression"
                            | "seed"
                            | "provider"
                            | "user"
                    )
                })
                || map.contains_key(&row.model)
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            map.insert(row.model.clone(), row);
        }
        Ok(Self {
            endpoint_path: "/api/v1/images".into(),
            models: map,
        })
    }

    /// Catalog entries routed to this adapter, including reference-edit capability.
    #[must_use]
    pub fn catalog_rows(&self) -> Vec<ImageCatalogRow> {
        self.models
            .values()
            .map(|row| ImageCatalogRow {
                model: row.model.clone(),
                adapter: ADAPTER.into(),
                generate: true,
                reference_edit: row.max_references > 0,
                max_pixels: row.max_pixels,
            })
            .collect()
    }

    pub(crate) fn model(&self, id: &ModelId) -> LlmResult<&OpenRouterImageModel> {
        self.models
            .get(id)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

fn valid_template(template: &str, edit: bool) -> bool {
    let without_instruction = template.replacen("{instruction}", "", 1);
    if !template.contains("{instruction}") || without_instruction.contains("{instruction}") {
        return false;
    }
    let remainder = if edit {
        without_instruction.replace("{reference_count}", "")
    } else {
        without_instruction
    };
    !remainder.contains('{') && !remainder.contains('}')
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenRouterImageHttpRequest {
    pub method: &'static str,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenRouterImageHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}

pub type OpenRouterImageFuture<'a> =
    Pin<Box<dyn Future<Output = LlmResult<OpenRouterImageHttpResponse>> + Send + 'a>>;

/// The host supplies credentials and transport; a failed network operation returns its typed
/// retryable or fatal LlmError. The lease stays attached to each call.
pub trait OpenRouterImageTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OpenRouterImageHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenRouterImageFuture<'a>;
}

pub struct OpenRouterImageBackend<T> {
    config: OpenRouterImageConfig,
    transport: T,
}

impl<T> OpenRouterImageBackend<T> {
    #[must_use]
    pub fn new(config: OpenRouterImageConfig, transport: T) -> Self {
        Self { config, transport }
    }
    #[must_use]
    pub fn config(&self) -> &OpenRouterImageConfig {
        &self.config
    }
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: OpenRouterImageTransport> OpenRouterImageBackend<T> {
    async fn send(
        &self,
        intent: ImageIntent,
        reference_images: Vec<oneiron::llm::image::ImageBytes>,
        edit: bool,
        lease: &BudgetLease,
    ) -> LlmResult<ImageResponse> {
        if edit && reference_images.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let request = build_image_request(&self.config, &intent, &reference_images)?;
        let response = self.transport.execute(request, lease).await?;
        if !(200..=299).contains(&response.status) {
            return Err(classify_image_status(
                response.status,
                &response.headers,
                &response.body,
            ));
        }
        parse_image_response(&response.body, intent.model)
    }
}

impl<T: OpenRouterImageTransport> ImageBackend for OpenRouterImageBackend<T> {
    fn generate<'a>(&'a self, intent: ImageIntent, lease: &'a BudgetLease) -> ImageFuture<'a> {
        Box::pin(async move { self.send(intent, vec![], false, lease).await })
    }
    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        references: Vec<oneiron::llm::image::ImageBytes>,
        lease: &'a BudgetLease,
    ) -> ImageFuture<'a> {
        Box::pin(async move { self.send(intent, references, true, lease).await })
    }
}
