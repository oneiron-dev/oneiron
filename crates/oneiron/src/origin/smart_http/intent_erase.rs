//! An erased actor out of the receive-pack intent journal (FIX 3877).

use super::intent::{INTENTS, ReceivePackIntent};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::actor_erase::{ORIGIN_ACTOR_ERASE_PENDING, OriginPendingErase};
use crate::origin::residence::OriginAuthorityStamp;
use crate::receipt::ERASED_CALL_IDENTITY;

impl ReceivePackIntent {
    /// Whether recovery may resume this intent. One whose pusher or admitting
    /// host an erase took keeps its refs and progress as evidence and never
    /// resumes ([`ORIGIN_ACTOR_ERASE_PENDING`]): no ref it named lands under
    /// the erased actor, and it holds no cutover.
    pub(super) fn resumes(&self) -> bool {
        match ORIGIN_ACTOR_ERASE_PENDING {
            OriginPendingErase::RefuseNewEffectsKeepObservedFacts => {
                self.actor_id != ERASED_CALL_IDENTITY
                    && !self
                        .origin_authority
                        .as_ref()
                        .is_some_and(OriginAuthorityStamp::writer_erased)
            }
        }
    }
}

/// Erasing `actor` from the receive-pack intent journal (FIX 3877): an
/// intent it pushed names [`ERASED_CALL_IDENTITY`] as its pusher, in its
/// push stamp too (FIX 8806), and one
/// admitted under it as the host names the erased writer there. Each keeps
/// its repository, epoch, refs, pointers and progress, and neither resumes.
/// One-way, in the erase's own transaction. An id whose entity is no actor
/// scans nothing.
///
/// # Errors
///
/// Storage errors, or a journal row that cannot be read.
pub(crate) fn erase_receive_pack_intent_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let pusher = actor.to_hex();
    let mut rows = Vec::new();
    for row in INTENTS.iter_from(&vault.store, wtxn, &[])? {
        let (key, mut intent) = row?;
        let pushed = intent.actor_id == pusher;
        if pushed {
            ERASED_CALL_IDENTITY.clone_into(&mut intent.actor_id);
        }
        let hosted = intent
            .origin_authority
            .as_mut()
            .is_some_and(|stamp| stamp.erase_writer(actor));
        // The push stamp names the same pusher; it goes with the rest
        // (FIX 8806).
        let stamped = intent
            .push
            .as_mut()
            .is_some_and(|stamp| stamp.erase_principal(actor));
        if pushed || hosted || stamped {
            rows.push((key, intent));
        }
    }
    for (key, intent) in &rows {
        INTENTS.put(&vault.store, wtxn, key, intent)?;
    }
    Ok(())
}
