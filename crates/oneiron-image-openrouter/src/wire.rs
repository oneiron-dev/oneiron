//! Buffered `/api/v1/images` request and response mapping.
use crate::backend::{OpenRouterImageConfig, OpenRouterImageHttpRequest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::image::{ImageBytes, ImageIntent, ImageResponse};
use oneiron::{FatalLlmError, LlmError, LlmResult, ModelId, RetryableLlmError};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub fn build_image_request(
    config: &OpenRouterImageConfig,
    intent: &ImageIntent,
    references: &[ImageBytes],
) -> LlmResult<OpenRouterImageHttpRequest> {
    let row = config.model(&intent.model)?;
    if intent.instruction.trim().is_empty()
        || intent.width == 0
        || intent.height == 0
        || u64::from(intent.width) * u64::from(intent.height) > row.max_pixels
        || references.len() > row.max_references
        || references
            .iter()
            .any(|r| r.bytes.is_empty() || !valid_media_type(&r.media_type))
        || intent
            .params
            .keys()
            .any(|key| !row.allowed_params.contains(key))
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let template = if references.is_empty() {
        &row.shim.generate
    } else {
        &row.shim.reference_edit
    };
    let prompt = template
        .replace("{reference_count}", &references.len().to_string())
        .replace("{instruction}", &intent.instruction);
    let mut body: Map<String, Value> = intent.params.clone().into_iter().collect();
    body.insert("model".into(), json!(row.wire_model));
    body.insert("prompt".into(), json!(prompt));
    body.insert(
        "size".into(),
        json!(format!("{}x{}", intent.width, intent.height)),
    );
    body.insert("n".into(), json!(1));
    if !references.is_empty() {
        body.insert("input_references".into(), Value::Array(references.iter().map(|r| {
            json!({ "type": "image_url", "image_url": {
                "url": format!("data:{};base64,{}", r.media_type, STANDARD.encode(&r.bytes))
            }})
        }).collect()));
    }
    Ok(OpenRouterImageHttpRequest {
        method: "POST",
        path: config.endpoint_path.clone(),
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
        body: Value::Object(body),
    })
}

pub fn parse_image_response(body: &Value, model: ModelId) -> LlmResult<ImageResponse> {
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or(FatalLlmError::EmptyResponse)?;
    // ImageResponse represents exactly one image. Never discard a paid-for second image.
    let [image] = data.as_slice() else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    let encoded = image
        .get("b64_json")
        .and_then(Value::as_str)
        .ok_or(FatalLlmError::EmptyResponse)?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| FatalLlmError::InvalidRequest)?;
    if bytes.is_empty() {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    let media_type = match image.get("media_type") {
        Some(value) => value
            .as_str()
            .filter(|s| valid_media_type(s))
            .ok_or(FatalLlmError::InvalidRequest)?
            .to_owned(),
        None => sniff_media_type(&bytes)
            .ok_or(FatalLlmError::InvalidRequest)?
            .to_owned(),
    };
    let metadata = body
        .as_object()
        .ok_or(FatalLlmError::InvalidRequest)?
        .iter()
        .filter(|(k, _)| k.as_str() != "data")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(ImageResponse {
        image: ImageBytes { bytes, media_type },
        model,
        metadata,
    })
}

fn valid_media_type(value: &str) -> bool {
    // Only known, supported inline-image formats; avoid injecting data-URL syntax.
    matches!(
        value,
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    )
}

fn sniff_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

pub fn classify_image_status(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &Value,
) -> LlmError {
    let code = body
        .get("error")
        .and_then(|e| e.get("code").or_else(|| e.get("type")))
        .and_then(Value::as_str);
    if status == 451 || matches!(code, Some("content_filter" | "content_filtered")) {
        return FatalLlmError::ContentFiltered.into();
    }
    match status {
        408 | 504 => RetryableLlmError::Timeout.into(),
        429 => RetryableLlmError::RateLimited {
            retry_after: headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
                .and_then(|(_, value)| value.parse::<u64>().ok()),
        }
        .into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        401 | 403 => FatalLlmError::Auth.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}
