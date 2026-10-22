//! The Gemini media calls' pure builders (FIX 8612, FIX 8613): every check
//! a call's send makes on its own request, with no I/O, shared by the
//! backend's preflight and its send. A call one of them refuses is refused
//! before its permit starts, so it is never charged, and the send cannot
//! check anything the preflight did not.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron::{FatalLlmError, LlmResult};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// The reference images a Veo job carries: its one start frame. A call
/// with more is not this wire's; a host's ladder passes it to an offer that
/// takes them all, unsent, and this wire never cuts it to its first.
pub(super) const VIDEO_REFERENCE_SLOTS: usize = 1;

/// The aspect ratios a Gemini image model draws, as `(width, height)`.
const IMAGE_RATIOS: [(u32, u32); 10] = [
    (1, 1),
    (2, 3),
    (3, 2),
    (3, 4),
    (4, 3),
    (4, 5),
    (5, 4),
    (9, 16),
    (16, 9),
    (21, 9),
];

/// An image call, checked: its instruction and its `generationConfig`. Its
/// reference images are encoded only as it is sent, never here.
pub(super) struct PreparedImage {
    pub(super) prompt: String,
    pub(super) config: Value,
}

/// A video job, checked: its prompt and its `parameters`.
pub(super) struct PreparedVideo {
    pub(super) prompt: String,
    pub(super) parameters: Value,
}

/// Checks an image call as its send builds it: an instruction, every
/// reference an image with bytes (all of them, however many), and a
/// `generationConfig` its params make.
pub(super) fn prepare_image(request: &MediaRequest) -> LlmResult<PreparedImage> {
    if request.operation != AiOperation::Image || request.voice.is_some() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let prompt = request.text();
    references_are_images(request)?;
    if prompt.trim().is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let config = image_config(request)?;
    Ok(PreparedImage { prompt, config })
}

/// Checks a video job as its submit builds it: a prompt, at most its one
/// start frame (a call with more is refused here, before it is sent, never
/// cut), and the `parameters` its params make.
pub(super) fn prepare_video(request: &MediaRequest) -> LlmResult<PreparedVideo> {
    let prompt = request.text();
    if request.operation != AiOperation::Video || prompt.trim().is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    references_are_images(request)?;
    if request.references.len() > VIDEO_REFERENCE_SLOTS {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let parameters = video_parameters(&request.params)?;
    Ok(PreparedVideo { prompt, parameters })
}

/// One reference image as the API's `inlineData`. `None` for a part that is
/// no image with bytes, which the builders above refuse first.
pub(super) fn inline_image(part: &MediaPart) -> Option<Value> {
    match part {
        MediaPart::Image { media_type, bytes } if !bytes.is_empty() => Some(json!({
            "inlineData": {
                "mimeType": media_type,
                "data": STANDARD.encode(bytes),
            }
        })),
        _ => None,
    }
}

/// Every reference is an image with bytes, read in place: no copy.
fn references_are_images(request: &MediaRequest) -> LlmResult<()> {
    if request
        .references
        .iter()
        .all(|part| matches!(part, MediaPart::Image { bytes, .. } if !bytes.is_empty()))
    {
        Ok(())
    } else {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// An image call's `generationConfig`: image output, its aspect ratio and
/// size from the call's `size` (`"WxH"`) or `width`/`height` when it names
/// one, then each other param as it came. Gemini's own `aspectRatio` and
/// `imageSize` params win over a named size.
fn image_config(request: &MediaRequest) -> LlmResult<Value> {
    let sized = ["size", "width", "height"]
        .iter()
        .any(|key| request.params.contains_key(*key));
    let intent = request.image_intent()?;
    let mut image = Map::new();
    if sized {
        if intent.width == 0 || intent.height == 0 {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        image.insert(
            "aspectRatio".into(),
            json!(nearest_ratio(intent.width, intent.height)),
        );
        let side = intent.width.max(intent.height);
        let size = match side {
            ..=1024 => "1K",
            ..=2048 => "2K",
            _ => "4K",
        };
        image.insert("imageSize".into(), json!(size));
    }
    let mut config = Map::new();
    config.insert("responseModalities".into(), json!(["TEXT", "IMAGE"]));
    for (key, value) in intent.params {
        match key.as_str() {
            "aspect_ratio" | "aspectRatio" => {
                image.insert("aspectRatio".into(), value);
            }
            "image_size" | "imageSize" => {
                image.insert("imageSize".into(), value);
            }
            "" | "responseModalities" | "imageConfig" => {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            _ => {
                config.insert(key, value);
            }
        }
    }
    if !image.is_empty() {
        config.insert("imageConfig".into(), Value::Object(image));
    }
    Ok(Value::Object(config))
}

/// The drawn ratio closest to `width:height`.
fn nearest_ratio(width: u32, height: u32) -> String {
    let wanted = f64::from(width) / f64::from(height);
    let (w, h) = IMAGE_RATIOS
        .into_iter()
        .min_by(|a, b| {
            let off = |(w, h): (u32, u32)| (f64::from(w) / f64::from(h) / wanted).ln().abs();
            off(*a).total_cmp(&off(*b))
        })
        .unwrap_or((1, 1));
    format!("{w}:{h}")
}

/// A Veo job's `parameters`: the call's `seconds` as `durationSeconds`, its
/// `size` (`"WxH"`) as an aspect ratio and resolution, then each other
/// param as it came. A param that names a field set here is refused.
fn video_parameters(params: &BTreeMap<String, Value>) -> LlmResult<Value> {
    fn set(out: &mut Map<String, Value>, key: &str, value: Value) -> LlmResult<()> {
        if key.is_empty() || out.insert(key.to_owned(), value).is_some() {
            Err(FatalLlmError::InvalidRequest.into())
        } else {
            Ok(())
        }
    }
    let mut out = Map::new();
    for (key, value) in params {
        match key.as_str() {
            "seconds" | "durationSeconds" => {
                let seconds = value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
                    .filter(|seconds| *seconds > 0)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                set(&mut out, "durationSeconds", json!(seconds))?;
            }
            "size" => {
                let (width, height) = value
                    .as_str()
                    .and_then(|size| size.split_once('x'))
                    .and_then(|(w, h)| Some((w.parse::<u32>().ok()?, h.parse::<u32>().ok()?)))
                    .filter(|(w, h)| *w > 0 && *h > 0)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let ratio = if width >= height { "16:9" } else { "9:16" };
                let resolution = match width.min(height) {
                    ..=720 => "720p",
                    ..=1080 => "1080p",
                    _ => "4k",
                };
                set(&mut out, "aspectRatio", json!(ratio))?;
                set(&mut out, "resolution", json!(resolution))?;
            }
            _ => set(&mut out, key, value.clone())?,
        }
    }
    Ok(Value::Object(out))
}
