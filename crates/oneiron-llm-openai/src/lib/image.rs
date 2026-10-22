//! Direct OpenAI image generation and multi-reference edits; HTTP and authentication stay host-owned.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::image::{ImageBackend, ImageBytes, ImageFuture, ImageIntent, ImageResponse};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId, RetryableLlmError};
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
            let body = serde_json::to_value(&fields).map_err(|_| FatalLlmError::InvalidRequest)?;
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
            // An edit edits something. Every reference goes, in order,
            // however many (FIX 8614): no count is refused here.
            if references.is_empty() {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let images = references
                .into_iter()
                .enumerate()
                .map(|(i, reference)| reference_part("image[]", i, reference))
                .collect::<LlmResult<Vec<_>>>()?;
            let (model, fields) = fields(&intent)?;
            let request = OpenAiImageHttpRequest {
                path: "/v1/images/edits",
                body: OpenAiImageBody::Multipart {
                    fields: form_fields(&fields),
                    images,
                },
            };
            let response = self.transport.execute(request, lease).await?;
            decode_response(response, model, &fields)
        })
    }
}

/// One ordered reference image as the multipart file part `name`.
pub(super) fn reference_part(
    name: &'static str,
    index: usize,
    reference: ImageBytes,
) -> LlmResult<OpenAiImagePart> {
    let Some(extension) = reference_extension(&reference.media_type) else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    if reference.bytes.is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    Ok(OpenAiImagePart {
        name,
        filename: format!("reference-{index}.{extension}"),
        media_type: reference.media_type,
        bytes: reference.bytes,
    })
}

/// The file extension a reference image of `media_type` is sent under;
/// `None` for a type the image wire does not take.
pub(super) fn reference_extension(media_type: &str) -> Option<&'static str> {
    match media_type {
        "image/png" => Some("png"),
        "image/jpeg" => Some("jpg"),
        "image/webp" => Some("webp"),
        _ => None,
    }
}

pub(super) fn fields(intent: &ImageIntent) -> LlmResult<(ModelId, BTreeMap<String, Value>)> {
    if intent.instruction.trim().is_empty() || intent.width == 0 || intent.height == 0 {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let mut fields = BTreeMap::from([
        ("model".into(), serde_json::json!(intent.model.name())),
        ("prompt".into(), serde_json::json!(intent.instruction)),
        (
            "size".into(),
            serde_json::json!(format!("{}x{}", intent.width, intent.height)),
        ),
        ("n".into(), serde_json::json!(1)),
    ]);
    // Shared admission preserves scalar JSON types. Multipart encoding stringifies
    // them only at the edit transport boundary.
    for (key, value) in &intent.params {
        if fields.contains_key(key)
            || key.is_empty()
            || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || !(value.is_string() || value.is_number() || value.is_boolean())
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if key == "output_format" && !matches!(value.as_str(), Some("png" | "jpeg" | "webp")) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        fields.insert(key.clone(), value.clone());
    }
    Ok((intent.model.clone(), fields))
}

pub(super) fn form_fields(fields: &BTreeMap<String, Value>) -> BTreeMap<String, String> {
    fields
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned),
            )
        })
        .collect()
}

/// The room standard base64 `encoded` decodes into: the decoder's own
/// estimate, so it writes into this room and never grows it.
fn decoded_room(encoded: &str) -> usize {
    encoded.len().div_ceil(4) * 3
}

pub(super) fn decode_response(
    response: OpenAiImageHttpResponse,
    model: ModelId,
    fields: &BTreeMap<String, Value>,
) -> LlmResult<ImageResponse> {
    if !(200..300).contains(&response.status) {
        return Err(super::classify_openai_status(
            response.status,
            &response.headers,
            &response.body,
        ));
    }
    // The reply is owned: take its parts rather than copying them. An image
    // is kept whole, however large (FIX 8615): its room is allocated
    // fallibly, and only memory this machine cannot give ends the call.
    let Value::Object(mut body) = response.body else {
        return Err(FatalLlmError::EmptyResponse.into());
    };
    let Some(Value::Array(mut data)) = body.remove("data") else {
        return Err(FatalLlmError::EmptyResponse.into());
    };
    if data.len() != 1 {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    let Some(Value::Object(mut item)) = data.pop() else {
        return Err(FatalLlmError::EmptyResponse.into());
    };
    let Some(Value::String(encoded)) = item.remove("b64_json") else {
        return Err(FatalLlmError::EmptyResponse.into());
    };
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(decoded_room(&encoded))
        .map_err(|_| RetryableLlmError::ServerError)?;
    STANDARD
        .decode_vec(encoded.as_bytes(), &mut bytes)
        .map_err(|_| FatalLlmError::EmptyResponse)?;
    drop(encoded);
    if bytes.is_empty() {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    // The direct image endpoint defaults to PNG; output_format is an explicit adapter option.
    let media_type = match fields
        .get("output_format")
        .and_then(Value::as_str)
        .unwrap_or("png")
    {
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
