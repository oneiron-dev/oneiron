//! The integration tests' door to the `ai.*` media doors as a code-mode run's
//! verb dispatch reaches them for a program the engine's model wrote (FIX
//! CODE-MODE-LENDING-W1): inside the run's bound line (`with_calling_line`),
//! as the run's credential calls them.

use std::sync::Arc;

use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::support::internal;
use super::{ai_image, ai_options, ai_video, ai_video_cancel, ai_video_poll, with_calling_line};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The units the door's line meter holds: far past any call it makes.
const DOOR_LINE_UNITS: u64 = 1_000_000;

/// `verb` (`ai.options`, `ai.image`, `ai.video`, `ai.video.poll` or
/// `ai.video.cancel`) on `input` as `auth` calls it from code-mode run
/// `run`, inside the run's line: a line on a fresh meter under the run's
/// own name, as `code_mode_line` binds one where code mode lends a meter.
/// `Ok` is the door's answer as JSON, `Err` its refusal.
pub(crate) async fn media_door_on_run_line_for_test(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    run: EntityId,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    let meter = BudgetGuard::new(
        "code-mode-line-door",
        DOOR_LINE_UNITS,
        BudgetExhaustionPolicy::Suspend,
    );
    let line =
        server
            .ai
            .model_runtime()
            .funded_run(format!("code-mode:{}", run.to_hex()), meter, None);
    with_calling_line(Some(line), async move {
        match verb {
            "ai.options" => answer(ai_options(server, auth, parsed(input)?).await.0),
            "ai.image" => answer(ai_image(server, auth, parsed(input)?).await.0),
            "ai.video" => answer(ai_video(server, auth, parsed(input)?).await.0),
            "ai.video.poll" => answer(ai_video_poll(server, auth, parsed(input)?).await.0),
            "ai.video.cancel" => answer(ai_video_cancel(server, auth, parsed(input)?).await.0),
            other => Err(MemoryError::bad_request(format!(
                "{other} is not a media door"
            ))),
        }
    })
    .await
}

/// The door's `input` as the request type its door takes.
fn parsed<T: DeserializeOwned>(input: Value) -> MemoryResult<T> {
    serde_json::from_value(input).map_err(|error| {
        MemoryError::bad_request(format!("the door's input does not parse: {error}"))
    })
}

/// A door's answer as JSON.
fn answer<T: Serialize>(answer: MemoryResult<T>) -> MemoryResult<Value> {
    serde_json::to_value(answer?).map_err(|_| internal("media door answer"))
}
