//! A video job's length as it is charged (FIX 1816): the length its clips
//! state, as the provider's wire reads it, else the length its call asked
//! for. A job whose clips state none and whose call asked none is charged
//! its reservation, as before.
//! Entry: `requested_video_ms`, `HeldJob::charge_requested_length`.
use super::{AiOperation, HeldJob, MediaRequest, MediaResponse};

/// The params a video call names its clip's length in, in seconds.
const LENGTH_PARAMS: [&str; 2] = ["seconds", "durationSeconds"];

/// The length in milliseconds `request` asks its clip to run, from its
/// seconds param, a number or a numeral. `None` for a call that is no
/// video job, or names no positive length.
pub(in crate::models) fn requested_video_ms(request: &MediaRequest) -> Option<u64> {
    if request.operation != AiOperation::Video {
        return None;
    }
    let seconds = LENGTH_PARAMS
        .iter()
        .filter_map(|key| request.params.get(*key))
        .find_map(|value| {
            value
                .as_f64()
                .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
        })?;
    (seconds.is_finite() && seconds > 0.0).then(|| (seconds * 1_000.0).ceil() as u64)
}

impl HeldJob {
    /// A done video job whose clips state no length is charged the length
    /// its call asked for, when it asked one.
    pub(super) fn charge_requested_length(&self, response: &mut MediaResponse) {
        if response.usage.video_ms == 0
            && let Some(requested) = self.requested_video_ms
        {
            response.usage.video_ms = requested;
        }
    }
}
