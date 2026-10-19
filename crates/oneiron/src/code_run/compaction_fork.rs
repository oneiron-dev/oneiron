//! The live fork (FIX 4465 C): a run's live request, captured at the
//! breakpoint that seals a self-written compaction flight, exactly as the
//! host's admitted rung sends it (its model, the rung's prompt first, its
//! system blocks, messages, tools, params and options). It is never rebuilt
//! from the replay. The flight carries one immutable copy; each of its calls
//! sends that prefix unchanged on the same rung, with the compaction's own
//! words after it, and the flight drops it when it ends.
//!
//! A host-owned descriptor in the request's own provider options names where
//! the prefix ends, so a provider that caches by marked blocks can reuse it.
//! A provider with no rendering for it sends a plain call.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity_id::EntityId;
use crate::llm::SelfCompactionSource;
use crate::llm::run_admission::OfferBinding;
use crate::{FatalLlmError, LlmRequest, LlmResult};

/// The provider-options namespace a host's own descriptors ride in. No
/// adapter reads it as its own, so one with no rendering for a descriptor
/// sends a plain call.
pub const HOST_PROVIDER_OPTIONS: &str = "oneiron";

/// The prompt-cache boundary descriptor's key in [`HOST_PROVIDER_OPTIONS`]:
/// a list of [`CacheBoundary`], in order.
pub const CACHE_BOUNDARIES_KEY: &str = "cache_boundaries";

/// One prompt-cache boundary: the end of one part of the request as its rung
/// sends it, with the rung's prompt already first. A provider that caches by
/// marked blocks marks there and keeps its own cache lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum CacheBoundary {
    /// The end of part `part` of message `message`. A system message's
    /// part is a system block.
    Message { message: usize, part: usize },
    /// The end of tool definition `tool`.
    Tool { tool: usize },
}

impl CacheBoundary {
    /// The end of `request`'s last part: where a live prefix ends.
    #[must_use]
    pub fn prefix_end(request: &LlmRequest) -> Option<Self> {
        let message = request.messages.len().checked_sub(1)?;
        let part = request.messages[message].content.len().checked_sub(1)?;
        Some(Self::Message { message, part })
    }

    fn holds(self, request: &LlmRequest) -> bool {
        match self {
            Self::Message { message, part } => request
                .messages
                .get(message)
                .is_some_and(|message| part < message.content.len()),
            Self::Tool { tool } => tool < request.tools.len(),
        }
    }
}

/// The cache boundaries `request` carries, in order; none when it carries no
/// descriptor. A descriptor that does not decode, or that names a part the
/// request does not hold, makes the request invalid.
pub fn cache_boundaries(request: &LlmRequest) -> LlmResult<Vec<CacheBoundary>> {
    let Some(value) = request
        .provider_options
        .get(HOST_PROVIDER_OPTIONS)
        .and_then(|options| options.get(CACHE_BOUNDARIES_KEY))
    else {
        return Ok(Vec::new());
    };
    let boundaries: Vec<CacheBoundary> =
        serde_json::from_value(value.clone()).map_err(|_| FatalLlmError::InvalidRequest)?;
    if boundaries.iter().all(|boundary| boundary.holds(request)) {
        Ok(boundaries)
    } else {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// Adds `boundary` to `request`'s descriptor and keeps every boundary it
/// already names.
pub fn mark_cache_boundary(request: &mut LlmRequest, boundary: CacheBoundary) -> LlmResult<()> {
    let mut boundaries = cache_boundaries(request)?;
    if !boundaries.contains(&boundary) {
        boundaries.push(boundary);
    }
    let boundaries =
        serde_json::to_value(&boundaries).map_err(|_| FatalLlmError::InvalidRequest)?;
    let options = request
        .provider_options
        .entry(HOST_PROVIDER_OPTIONS.to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(options) = options.as_object_mut() else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    options.insert(CACHE_BOUNDARIES_KEY.to_owned(), boundaries);
    Ok(())
}

/// The rung a live request was admitted on, as its host bound it: its
/// provider, its place in the configured ladder, the model its wire names
/// and the offer a run admits its calls under (route, credential binding,
/// catalog revision, locality and payer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveForkRung {
    pub provider: String,
    pub position: usize,
    pub wire_model: String,
    pub offer: OfferBinding,
}

/// A run's live request at one breakpoint, as its host's admitted rung
/// sends it, for the agent's own compaction (FIX 4465 C). Immutable: the
/// flight sealed at that breakpoint carries it, and every call of the flight
/// sends the same prefix.
#[derive(Debug, Clone)]
pub struct LiveCompactionFork {
    request: LlmRequest,
    rung: LiveForkRung,
    writer: EntityId,
    source: SelfCompactionSource,
    room: u64,
}

impl LiveCompactionFork {
    /// The host's capture: `request` exactly as `rung` sends it, for
    /// `writer` (the run's authenticated actor), under a row whose context
    /// is `source`, with `room` input tokens left beside it on its model for
    /// the compaction's own input.
    #[must_use]
    pub const fn capture(
        request: LlmRequest,
        rung: LiveForkRung,
        writer: EntityId,
        source: SelfCompactionSource,
        room: u64,
    ) -> Self {
        Self {
            request,
            rung,
            writer,
            source,
            room,
        }
    }

    /// The live request as its rung sends it.
    #[must_use]
    pub const fn request(&self) -> &LlmRequest {
        &self.request
    }

    /// The rung it was admitted on.
    #[must_use]
    pub const fn rung(&self) -> &LiveForkRung {
        &self.rung
    }

    /// The run's authenticated actor it was captured for.
    #[must_use]
    pub const fn writer(&self) -> EntityId {
        self.writer
    }

    /// The context the row read when it was captured.
    #[must_use]
    pub const fn source(&self) -> SelfCompactionSource {
        self.source
    }

    /// The compaction input the live model holds beside the prefix, the
    /// instruction and the reply's reserve: what sizes the flight's window.
    #[must_use]
    pub const fn input_room(&self) -> u64 {
        self.room
    }
}

/// A live fork its run's driver admitted (FIX 4465 C): the one Frontier-tier
/// binding a compaction may wear. It is for a profile whose writer is
/// `self`, under a row that selects the live fork, captured for the run's
/// own actor. Only the driver's live admission builds one, and a backend
/// sends a live fork only while it holds one.
#[derive(Debug, Clone)]
pub struct AdmittedLiveFork {
    fork: LiveCompactionFork,
}

impl AdmittedLiveFork {
    pub(crate) const fn admitted(fork: LiveCompactionFork) -> Self {
        Self { fork }
    }

    /// The admitted capture.
    #[must_use]
    pub const fn fork(&self) -> &LiveCompactionFork {
        &self.fork
    }

    /// The admitted capture, by value: what a flight freezes.
    #[must_use]
    pub fn into_fork(self) -> LiveCompactionFork {
        self.fork
    }
}
