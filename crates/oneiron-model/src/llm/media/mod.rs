//! The `ai.*` call family past text (runtime "The ai.* call family"): image,
//! video, speech, transcription and embedding calls in one request shape,
//! admitted, sent and settled on the same run admission as a text call. The
//! requested operation picks the call, a row's input and output modalities
//! filter the seats that may serve it, and the answer is a list of parts.
//!
//! A media call is admitted as the [`LlmRequest`] its
//! [`MediaRequest::admission_request`] names: the same model, envelope and
//! params, no messages. So a run's teachers, offer, locality and route rules
//! hold for it unchanged, and one permit buys one physical call. Its usage
//! settles in token units: a provider that counts tokens is charged them,
//! one that counts images, seconds or characters is charged its row's
//! [`NativeRate`] for them.
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::image::{ImageBackend, ImageBytes, ImageIntent, ImageResponse};
use super::{
    BrokerIsolation, BudgetLease, CallEnvelope, FatalLlmError, LlmError, LlmRequest, LlmResult,
    ModelId,
};

mod backend;
mod caps;
mod request;
mod response;
pub mod wav;

pub use backend::{AiMediaDoor, ImageMedia, MediaBackend};
pub use caps::{AiOperation, MediaCaps, Modality, NativeUnit};
pub use request::{MediaPart, MediaRequest, MediaVoice};
pub use response::{MediaJobState, MediaResponse, MediaUsage};

/// What `per` native units cost in token units, rounded up: the rate a run
/// settles a provider's native count at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRate {
    pub unit: NativeUnit,
    pub per: u64,
    pub tokens: u64,
}

impl NativeRate {
    /// The rate an operation settles at when its row names none: a generated
    /// image as a long answer, a second of audio or video as the tokens a
    /// model spends on it, four characters of speech as one token.
    #[must_use]
    pub fn default_for(operation: AiOperation) -> Self {
        let unit = operation.native_unit();
        let (per, tokens) = match unit {
            NativeUnit::Token => (1, 1),
            NativeUnit::Image => (1, 4_000),
            NativeUnit::AudioSecond => (1, 50),
            NativeUnit::VideoSecond => (1, 10_000),
            NativeUnit::Character => (4, 1),
        };
        Self { unit, per, tokens }
    }

    fn charge(&self, count: u64) -> u64 {
        let per = u128::from(self.per.max(1));
        let units = (u128::from(count) * u128::from(self.tokens)).div_ceil(per);
        u64::try_from(units).unwrap_or(u64::MAX)
    }
}

pub type MediaFuture<'a, T> = Pin<Box<dyn Future<Output = LlmResult<T>> + Send + 'a>>;
