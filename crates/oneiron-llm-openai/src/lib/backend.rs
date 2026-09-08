//! Backend assembly: config, backend struct, LlmBackend impl, and capability gating.

use super::{
    OpenAiCompatLlmStream, OpenAiCompatTransport, OpenAiProviderOptions, build_openai_chat_request,
    classify_openai_status, parse_openai_chat_response,
};
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, LlmBackend, LlmCapability, LlmCatalogEntry,
    LlmGenerateFuture, LlmMessage, LlmRequest, LlmResult, LlmStream, LlmStreamResult, ModelId,
    ResponseFormat, UnsupportedCapability,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatConfig {
    pub endpoint_path: String,
    pub models: BTreeMap<ModelId, LlmCatalogEntry>,
}

impl OpenAiCompatConfig {
    #[must_use]
    pub fn new(model: LlmCatalogEntry) -> Self {
        let mut models = BTreeMap::new();
        models.insert(model.model.clone(), model);
        Self {
            endpoint_path: "/v1/chat/completions".to_owned(),
            models,
        }
    }

    #[must_use]
    pub fn with_models(models: impl IntoIterator<Item = LlmCatalogEntry>) -> Self {
        Self {
            endpoint_path: "/v1/chat/completions".to_owned(),
            models: models
                .into_iter()
                .map(|entry| (entry.model.clone(), entry))
                .collect(),
        }
    }

    #[must_use]
    pub fn with_endpoint_path(mut self, endpoint_path: impl Into<String>) -> Self {
        self.endpoint_path = endpoint_path.into();
        self
    }

    pub(crate) fn catalog_entry(&self, model: &ModelId) -> LlmResult<&LlmCatalogEntry> {
        self.models
            .get(model)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

#[derive(Debug)]
pub struct OpenAiCompatBackend<T> {
    config: OpenAiCompatConfig,
    transport: T,
}

impl<T> OpenAiCompatBackend<T> {
    #[must_use]
    pub fn new(config: OpenAiCompatConfig, transport: T) -> Self {
        Self { config, transport }
    }

    #[must_use]
    pub fn config(&self) -> &OpenAiCompatConfig {
        &self.config
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> LlmBackend for OpenAiCompatBackend<T>
where
    T: OpenAiCompatTransport,
{
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let wire_request = build_openai_chat_request(&self.config, &request, false)?;
            let response = self.transport.execute(wire_request, lease).await?;
            if !(200..=299).contains(&response.status) {
                return Err(classify_openai_status(
                    response.status,
                    &response.headers,
                    &response.body,
                ));
            }
            parse_openai_chat_response(&response.body)
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let wire_request = build_openai_chat_request(&self.config, &request, true)?;
        let provider_stream = self.transport.stream(wire_request, lease)?;
        Ok(LlmStream::new(OpenAiCompatLlmStream::new(provider_stream)))
    }
}

pub(crate) fn validate_capabilities(
    catalog: &LlmCatalogEntry,
    request: &LlmRequest,
    provider_options: &OpenAiProviderOptions,
    stream: bool,
) -> LlmResult<()> {
    if stream {
        require(catalog, LlmCapability::Streaming, "stream() requested")?;
    }
    if !request.tools.is_empty() {
        require(
            catalog,
            LlmCapability::ToolCalling,
            "request includes tool specs",
        )?;
    }
    if request.messages.iter().any(message_has_tool_result) {
        require(
            catalog,
            LlmCapability::ToolResults,
            "request includes tool result content",
        )?;
    }
    if request.messages.iter().any(message_has_image) {
        require(
            catalog,
            LlmCapability::ImageInput,
            "request includes image content",
        )?;
    }
    if matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ) {
        require(
            catalog,
            LlmCapability::JsonResponse,
            "request asks for a JSON response",
        )?;
    }
    if provider_options.requires_reasoning() || request.params.contains_key("reasoning_effort") {
        require(
            catalog,
            LlmCapability::Reasoning,
            "request includes reasoning controls",
        )?;
    }
    Ok(())
}

fn require(
    catalog: &LlmCatalogEntry,
    capability: LlmCapability,
    reason: &'static str,
) -> LlmResult<()> {
    if catalog.supports(&capability) {
        Ok(())
    } else {
        Err(FatalLlmError::Unsupported(UnsupportedCapability {
            capability,
            model: Some(catalog.model.clone()),
            reason: Some(reason.to_owned()),
        })
        .into())
    }
}

fn message_has_image(message: &LlmMessage) -> bool {
    message
        .content
        .iter()
        .any(|part| matches!(part, ContentPart::Image { .. }))
}

fn message_has_tool_result(message: &LlmMessage) -> bool {
    message
        .content
        .iter()
        .any(|part| matches!(part, ContentPart::ToolResult { .. }))
}
