//! One engine-owned callback keeps a borrowed room view inside its read.

use super::*;
use crate::claim::{ClaimReadStatus, NativeRawRead};

impl Memory<'_> {
    /// Runs buffer-oriented reads through this actor's verified read lane.
    /// A live session composes its overlay; room loss retries on the SAME
    /// scoped base key, never on a broader bare-Vault reader. A callback may
    /// run again after room loss, as the existing raw query callbacks do.
    pub fn with_credential_raw_read<T>(
        &self,
        read: impl for<'a> Fn(&NativeRawRead<'a>) -> crate::Result<T>,
    ) -> MemoryResult<T> {
        let key = self
            .read_lane(ClaimReadStatus::Recorded)?
            .actor_key()
            .clone();
        let composed = self.raw_session_read(|session| {
            let view = session.read_view()?;
            let lane = self.vault().scoped_read_in_session(key.clone(), &view);
            let value = read(&NativeRawRead::new(lane, Some(session)))?;
            session.admit_participant()?;
            Ok(value)
        })?;
        match composed {
            Some(value) => Ok(value),
            None => Ok(read(&NativeRawRead::new(
                self.vault().scoped_read(key),
                None,
            ))?),
        }
    }
}
