//! Moved from `crates/oneiron/src/memory/witness/stream/policy.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::witness::stream::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

impl MessageWriteMode {
    pub fn validate(self) -> MessageStreamResult<()> {
        if matches!(
            self,
            Self::Streamed {
                cadence: StreamCadence::PerWindow { chars: 0 },
                ..
            }
        ) {
            return Err(MessageStreamError::InvalidRequest(
                "window must be positive",
            ));
        }
        Ok(())
    }
}
