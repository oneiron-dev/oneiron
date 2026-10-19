//! Which call a named hook pause is (FIX 5526): a retry names its pause by
//! the ask handle, and one request may make more than one call under the
//! same key, a chat turn's model call and its user turn's witness. Only the
//! call that paused on the named ask resumes it; another call of the same
//! request takes its own path, as if it named none. A named pause that no
//! call under the key holds any more is gone, and refuses.

use std::sync::PoisonError;

use crate::EntityId;

use super::{SessionHookKeep, SessionHookKey};

impl SessionHookKeep {
    /// Whether a call under `key` other than `invocation` paused on ask
    /// `ask`, used up or not.
    pub(in crate::runtime_hooks::verb) fn paused_elsewhere(
        &self,
        key: &SessionHookKey,
        invocation: [u8; 16],
        ask: EntityId,
    ) -> bool {
        self.kept
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .is_some_and(|kept| {
                kept.asks
                    .iter()
                    .any(|(held, row)| *held != invocation && row.ask.ask == ask)
            })
    }
}
