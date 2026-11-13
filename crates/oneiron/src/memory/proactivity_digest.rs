//! The saved proactivity digest under the same live owner proof as its HTTP door.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::digest::ProactivityDigestView;

#[doc(hidden)]
pub use oneiron_verb_wire::memory::proactivity_digest::ProactivityDigestRequest;

impl Memory<'_> {
    /// Reads a saved proactivity digest as the authenticated vault owner.
    /// Any live owner may name any saved locator, as on the owner HTTP door.
    /// Stored verification and viewer screening remain the native getter's.
    pub fn proactivity_digest_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &ProactivityDigestRequest,
    ) -> MemoryResult<Option<ProactivityDigestView>> {
        Ok(match &input.id {
            Some(raw) => {
                let id = crate::task_verb::decode_hex::<32>(raw)
                    .filter(|_| raw.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .ok_or_else(|| {
                        MemoryError::bad_request("id must be a 64-hex proactivity digest locator")
                    })?;
                self.vault.proactivity_digest_view(owner, id)?
            }
            None => self.vault.latest_proactivity_digest_view(owner)?,
        })
    }
}
