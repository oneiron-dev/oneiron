//! The OpenAI-compatible image and video calls' pure builders (FIX 8614,
//! FIX 8616): every check a call's send makes on its own request, with no
//! I/O, shared by the backend's preflight and its send. A call one of them
//! refuses is refused before its permit starts, so it is never charged, and
//! the send cannot check anything the preflight did not. The field rules
//! every family shares are `oneiron_llm::openai_compat`'s.
//!
//! Nothing here copies or encodes a reference or an image part: the send
//! does that once, as it builds what goes out.
use std::collections::BTreeMap;

use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron::{FatalLlmError, LlmResult, ModelId};
use oneiron_llm::openai_compat::with_params;
use serde_json::{Value, json};

use super::image::{check_edit_mask, fields, reference_extension};

/// The reference images a video job carries: its one `input_reference`. A
/// call with more is not this wire's; a host's ladder passes it to an offer
/// that takes them all, unsent, and this wire never cuts it to its first.
pub(super) const VIDEO_REFERENCE_SLOTS: usize = 1;

/// An image call, checked: the model it answers as and its fields, the
/// provider's model name among them.
pub(super) struct PreparedImage {
    pub(super) model: ModelId,
    pub(super) fields: BTreeMap<String, Value>,
}

/// A video job, checked: its fields. Its start frame, when it has one, is
/// taken from the call as it is sent.
pub(super) struct PreparedVideo {
    pub(super) fields: BTreeMap<String, Value>,
}

/// Checks an image call as its send builds it: every reference (however
/// many, FIX 8614) an image of a type the wire names with bytes, and the
/// fields its intent makes, with the provider's model name `wire`.
pub(super) fn prepare_image(request: &MediaRequest, wire: &str) -> LlmResult<PreparedImage> {
    if request.operation != AiOperation::Image {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    request.validate_image_mask()?;
    references_are_images(request)?;
    check_edit_mask(
        request.mask.as_ref(),
        request.references.len(),
        &request.params,
    )?;
    let (model, mut fields) = fields(&request.image_intent()?)?;
    fields.insert("model".into(), json!(wire));
    Ok(PreparedImage { model, fields })
}

/// Checks a video job as its submit builds it: a prompt, at most its one
/// start frame of a type the wire names (a call with more is refused here,
/// before it is sent, never cut), and the call's params beside its fixed
/// fields.
pub(super) fn prepare_video(request: &MediaRequest, wire: &str) -> LlmResult<PreparedVideo> {
    let prompt = request.text();
    if request.operation != AiOperation::Video || prompt.trim().is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    references_are_images(request)?;
    if request.references.len() > VIDEO_REFERENCE_SLOTS {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let fields = with_params(
        [("model", json!(wire)), ("prompt", json!(prompt))],
        &request.params,
    )?;
    Ok(PreparedVideo { fields })
}

/// Every reference is an image of a type the wire names, with bytes, read
/// in place: no copy.
fn references_are_images(request: &MediaRequest) -> LlmResult<()> {
    let sendable = |part: &MediaPart| {
        matches!(part, MediaPart::Image { media_type, bytes }
            if !bytes.is_empty() && reference_extension(media_type).is_some())
    };
    if request.references.iter().all(sendable) {
        Ok(())
    } else {
        Err(FatalLlmError::InvalidRequest.into())
    }
}
