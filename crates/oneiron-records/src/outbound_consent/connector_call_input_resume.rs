//! Moved from `crates/oneiron/src/outbound_consent/connector_call_input_resume.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroizing;

/// How a live exchange is taken up again after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorResumeProtocol {
    /// 2026-07-28: the protocol Retry, re-sent from its request state once
    /// the round is answered.
    Retry,
    /// 2025-06-18 and 2025-11-25: the reply stream, reattached after its
    /// last event id.
    Stream,
}
