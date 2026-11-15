//! Memory's catalogue keys (DESIGN 15-setting-primitive): the owner's message-stream policy, as
//! one row at the vault and one per agent for the write mode, and the vault's idle timeout.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::memory::{DEFAULT_MESSAGE_STREAM_IDLE_MS, MessageWriteMode};
use crate::setting::{Kind, ScopeKind, SettingValue};

/// Milliseconds a message stream waits with no append before it closes, independent of the
/// presence TTL. Never zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct StreamIdleTimeoutMs(pub(crate) u64);

impl SettingValue for StreamIdleTimeoutMs {
    fn check(self) -> Result<Self> {
        if self.0 == 0 {
            return Err(Error::InvalidConfig(
                "a message stream's idle timeout must be positive".to_owned(),
            ));
        }
        Ok(self)
    }
}

fn atomic() -> MessageWriteMode {
    MessageWriteMode::Atomic
}

fn default_idle_timeout() -> StreamIdleTimeoutMs {
    StreamIdleTimeoutMs(DEFAULT_MESSAGE_STREAM_IDLE_MS)
}

crate::setting::setting_keys! {
    /// How a message is written when its call names no mode: at once, or streamed with a
    /// visibility and a cadence. An agent's row is that agent's own mode; the vault's row is
    /// every other actor's. The owner sets both.
    pub(crate) MESSAGE_STREAM_MODE: MessageWriteMode = "memory.message_stream.mode" {
        kind: Kind::new(atomic),
        scopes: &[ScopeKind::Vault, ScopeKind::Agent],
    };
    /// Milliseconds a message stream waits with no append before it closes, independent of the
    /// presence TTL.
    pub(crate) MESSAGE_STREAM_IDLE_TIMEOUT: StreamIdleTimeoutMs = "memory.message_stream.idle_timeout_ms" {
        kind: Kind::new(default_idle_timeout),
    };
}
