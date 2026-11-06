//! Receiving-agent phone sessions use the original line and opaque arrival reference.
use serde::{Deserialize, Serialize};

use super::live_voice::LiveVoiceStartRequest;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PhoneVoiceStartRequest {
    pub identity_ref: String,
    pub arrival_ref: String,
    pub voice: LiveVoiceStartRequest,
}
