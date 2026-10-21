//! Typed host projections of the run's coordination verbs.
use serde::{Deserialize, Serialize};

/// One typed call for a live agent run. `live_run` is the opaque attachment
/// returned by `/v1/core/live-runs/{run}/attach` to this same credential.
/// It identifies no authority on its own: the host resolves the credential,
/// holds the registered run and rechecks its lease before reading `spec`.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LiveRunRequest<T> {
    pub live_run: String,
    pub spec: T,
}
