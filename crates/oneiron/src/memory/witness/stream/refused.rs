//! The stream seeds the vault's open could not replay, kept for the owner
//! (FIX 9974, FIX 11933). Each open retries every surviving seed and keeps
//! the refusals it met in place of the last open's; the owner's read lists
//! those whose seed is still kept, with the refusal each met.

use std::sync::PoisonError;

use serde::{Deserialize, Serialize};

use super::storage::{ACTIVE, Seed};
use super::{MessageStreamError, MessageStreamRuntime};
use crate::consent::AuthenticatedOwner;
use crate::{EntityId, Vault};

/// One surviving stream seed open-time recovery could not replay (FIX
/// 9974): the MESSAGE it names, where and by whom it was streamed, and the
/// refusal its write met, typed as the stream's own doors answer it. Its
/// seed stays for repair, and the next open tries it again.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StreamRecoveryRefusal {
    /// The MESSAGE the seed streams.
    pub message_id: EntityId,
    /// The stream's generation: with `message_id`, its handle.
    pub generation: EntityId,
    pub conversation: EntityId,
    pub actor: EntityId,
    /// One of the `MEMORY_CODE_*` strings.
    pub code: String,
    pub message: String,
    /// The refusal's typed reasons, where it carries any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reason_codes: Vec<String>,
}

impl StreamRecoveryRefusal {
    /// The refusal `error` that `seed`'s replay met.
    pub(super) fn new(seed: &Seed, error: MessageStreamError) -> Self {
        let error = super::api::stream_error(error);
        Self {
            message_id: seed.message_id,
            generation: seed.generation,
            conversation: seed.conversation,
            actor: seed.actor,
            code: error.code,
            message: error.message,
            reason_codes: error.reason_codes,
        }
    }
}

impl MessageStreamRuntime {
    /// Keeps `refused`, this open's refusals, in place of an earlier open's.
    pub(super) fn keep_refused(&self, refused: &[StreamRecoveryRefusal]) {
        *self.refused.lock().unwrap_or_else(PoisonError::into_inner) = refused.to_vec();
    }
}

impl Vault {
    /// The stream seeds this vault's open could not replay and still keeps
    /// (FIX 11933), each with the refusal its replay met, in the order the
    /// open met them, read under the owner's proof. A seed a repair or a
    /// later stream of its MESSAGE retired is no longer listed.
    ///
    /// # Errors
    ///
    /// The owner's proof no longer standing; storage errors.
    pub fn stream_recovery_refusals(
        &self,
        owner: &AuthenticatedOwner,
    ) -> crate::Result<Vec<StreamRecoveryRefusal>> {
        let kept = self
            .message_streams
            .refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let mut retained = Vec::with_capacity(kept.len());
        for refusal in kept {
            if ACTIVE
                .get(&self.store, &txn, &refusal.message_id)?
                .is_some_and(|seed| seed.generation == refusal.generation)
            {
                retained.push(refusal);
            }
        }
        Ok(retained)
    }
}
