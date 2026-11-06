//! An erased actor out of the receive-pack intent journal (FIX 3877).

use std::path::Path;

use super::cgi_finish::realized_updates;
use super::intent::{INTENTS, ReceivePackIntent, ReceivePackIntentKey, ReceivePackRefStatus};
use super::paths::ORIGIN_REF_UPDATE_BATCH;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::actor_erase::{ORIGIN_ACTOR_ERASE_PENDING, OriginPendingErase};
use crate::origin::residence::OriginAuthorityStamp;
use crate::store::receipt_identity::ERASED_CALL_IDENTITY;

impl ReceivePackIntent {
    /// Whether recovery may resume this intent. One whose pusher or admitting
    /// host an erase took never resumes ([`ORIGIN_ACTOR_ERASE_PENDING`]): no
    /// ref it named lands under the erased actor, and it holds no cutover. It
    /// is observed instead, and pruned once observed whole
    /// ([`Vault::settle_inert_receive_pack_intent`], FIX 5022).
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

impl Vault {
    /// Settles `intent`, one an erase took, of the repository at `root`, by
    /// observation alone (FIX 5022, Engine 06:58 = A): each pending ref is
    /// read from the repository and
    /// what it showed is kept in the intent's own progress. A ref the backend
    /// did not leave at its proposed value is not applied (superseded once an
    /// earlier pass observed it); one it did is applied and published under
    /// no one. No outcome is recorded and no effect starts, so nothing lands
    /// under the erased actor. A ref whose read fails stays pending for the
    /// next scan. The save that settles the intent prunes it, as any settled
    /// intent is pruned.
    ///
    /// # Errors
    ///
    /// A ref that does not decode, or a store failure saving the progress.
    pub(super) fn settle_inert_receive_pack_intent(
        &self,
        root: &Path,
        key: &ReceivePackIntentKey,
        intent: &mut ReceivePackIntent,
    ) -> Result<()> {
        let refs = intent.refs.len();
        for (batch, start) in (0..refs).step_by(ORIGIN_REF_UPDATE_BATCH).enumerate() {
            let mut observed = false;
            for index in start..(start + ORIGIN_REF_UPDATE_BATCH).min(refs) {
                let entry = &mut intent.refs[index];
                if entry.status != ReceivePackRefStatus::Pending {
                    continue;
                }
                let update = entry.update()?;
                match realized_updates(self, root, std::slice::from_ref(&update)) {
                    Ok(updates) if updates.is_empty() => {
                        entry.status = if entry.observed {
                            ReceivePackRefStatus::Superseded
                        } else {
                            ReceivePackRefStatus::NotApplied
                        };
                    }
                    Ok(_) => {
                        entry.observed = true;
                        entry.status = ReceivePackRefStatus::AppliedUnpublished;
                    }
                    Err(_) => continue,
                }
                observed = true;
            }
            if observed {
                self.save_receive_pack_progress(key, intent, batch)?;
            }
        }
        Ok(())
    }
}
