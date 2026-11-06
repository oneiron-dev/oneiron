//! The saved proactivity digest under the same live owner proof as its HTTP door.

use serde::{Deserialize, Serialize};

use super::{Memory, MemoryError, MemoryResult};
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::maintenance::digest::ProactivityDigestView;

/// One saved proactivity digest, or the latest when no locator is supplied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProactivityDigestRequest {
    /// The 64-hex locator from an inbox notification's `source.result`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

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
