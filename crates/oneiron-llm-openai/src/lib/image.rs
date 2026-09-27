//! Direct OpenAI image generation and multi-reference edits; HTTP and authentication stay host-owned.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::image::{ImageBackend, ImageBytes, ImageFuture, ImageIntent, ImageResponse};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future, pin::Pin};

/// Multipart parts are distinct so the host sends each ordered reference as `image[]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiImagePart {
    pub name: &'static str,
    pub filename: String,
    pub media_type: String,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq)]
pub enum OpenAiImageBody {
    Json(Value),
    Multipart {
        fields: BTreeMap<String, String>,
        images: Vec<OpenAiImagePart>,
    },
}
#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiImageHttpRequest {
    pub path: &'static str,
    pub body: OpenAiImageBody,
}
#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiImageHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
}
pub type OpenAiImageTransportFuture<'a> =
    Pin<Box<dyn Future<Output = LlmResult<OpenAiImageHttpResponse>> + Send + 'a>>;
pub trait OpenAiImageTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OpenAiImageHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiImageTransportFuture<'a>;
}

pub struct DirectOpenAiImageBackend<T> {
    transport: T,
}
impl<T> DirectOpenAiImageBackend<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}
impl<T: OpenAiImageTransport> ImageBackend for DirectOpenAiImageBackend<T> {
    fn generate<'a>(&'a self, intent: ImageIntent, lease: &'a BudgetLease) -> ImageFuture<'a> {
        Box::pin(async move {
            let (model, fields) = fields(&intent)?;
            let mut body =
                serde_json::to_value(&fields).map_err(|_| FatalLlmError::InvalidRequest)?;
            body["n"] = serde_json::json!(1);
            let request = OpenAiImageHttpRequest {
                path: "/v1/images/generations",
                body: OpenAiImageBody::Json(body),
            };
            let response = self.transport.execute(request, lease).await?;
            decode_response(response, model, &fields)
        })
    }

    fn reference_edit<'a>(
        &'a self,
        intent: ImageIntent,
        references: Vec<ImageBytes>,
        lease: &'a BudgetLease,
    ) -> ImageFuture<'a> {
        Box::pin(async move {
            // Validate here as well as at ImageCatalog: direct users of the trait need the same bound.
            if !(1..=8).contains(&references.len()) {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let images = references
                .into_iter()
                .enumerate()
                .map(|(i, reference)| {
                    let extension = match reference.media_type.as_str() {
                        "image/png" => "png",
                        "image/jpeg" => "jpg",
                        "image/webp" => "webp",
                        _ => return Err(FatalLlmError::InvalidRequest.into()),
                    };
                    if reference.bytes.is_empty() {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
                    Ok(OpenAiImagePart {
                        name: "image[]",
                        filename: format!("reference-{i}.{extension}"),
                        media_type: reference.media_type,
                        bytes: reference.bytes,
                    })
                })
                .collect::<LlmResult<Vec<_>>>()?;
            let (model, fields) = fields(&intent)?;
            let request = OpenAiImageHttpRequest {
                path: "/v1/images/edits",
                body: OpenAiImageBody::Multipart {
                    fields: fields.clone(),
                    images,
                },
            };
            let response = self.transport.execute(request, lease).await?;
            decode_response(response, model, &fields)
        })
    }
}

fn fields(intent: &ImageIntent) -> LlmResult<(ModelId, BTreeMap<String, String>)> {
    if intent.instruction.trim().is_empty() || intent.width == 0 || intent.height == 0 {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let mut fields = BTreeMap::from([
        ("model".into(), intent.model.name().into()),
        ("prompt".into(), intent.instruction.clone()),
        ("size".into(), format!("{}x{}", intent.width, intent.height)),
        ("n".into(), "1".into()),
    ]);
    // Provider-specific knobs are data, never allowed to replace the model, prompt,
    // dimensions, or single-output contract. Complex values do not fit form fields.
    for (key, value) in &intent.params {
        if fields.contains_key(key)
            || key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let value = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return Err(FatalLlmError::InvalidRequest.into()),
        };
        if key == "output_format" && !matches!(value.as_str(), "png" | "jpeg" | "webp") {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        fields.insert(key.clone(), value);
    }
    Ok((intent.model.clone(), fields))
}

fn decode_response(
    response: OpenAiImageHttpResponse,
    model: ModelId,
    fields: &BTreeMap<String, String>,
) -> LlmResult<ImageResponse> {
    if !(200..300).contains(&response.status) {
        return Err(super::classify_openai_status(
            response.status,
            &response.headers,
            &response.body,
        ));
    }
    let mut body = response
        .body
        .as_object()
        .cloned()
        .ok_or(FatalLlmError::EmptyResponse)?;
    let mut data = body
        .remove("data")
        .and_then(|v| v.as_array().cloned())
        .ok_or(FatalLlmError::EmptyResponse)?;
    if data.len() != 1 {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    let mut item = data
        .remove(0)
        .as_object()
        .cloned()
        .ok_or(FatalLlmError::EmptyResponse)?;
    let encoded = item
        .remove("b64_json")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or(FatalLlmError::EmptyResponse)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| FatalLlmError::EmptyResponse)?;
    if bytes.is_empty() {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    // The direct image endpoint defaults to PNG; output_format is an explicit adapter option.
    let media_type = match fields.get("output_format").map_or("png", String::as_str) {
        "png" => "image/png",
        "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    };
    if !item.is_empty() {
        body.insert("image_metadata".into(), Value::Object(item));
    }
    Ok(ImageResponse {
        image: ImageBytes {
            bytes,
            media_type: media_type.into(),
        },
        model,
        metadata: body.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests;
