//! One host pass over the native mail pack's inboxes (OF-519): every active
//! native mail identity's inbox, read page by page through the pack's own poll
//! door from where the host's last pass left it, until the mailbox is read.

use std::collections::BTreeMap;

use super::native_mail_identity_in_txn;
use super::pack::NativeMailPack;
use crate::channel_identity::ChannelIdentityState;
use crate::channel_identity_provider::mail_placement::PlacementPolicy;
use crate::channel_identity_provider::stalwart::{StalwartInboxCursor, StalwartQuarantine};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_CHANNEL_IDENTITY;
use crate::{EntityId, Result, Vault};

/// What one pass over the inboxes came to.
#[derive(Debug, Default)]
pub struct NativeMailInboxPass {
    /// Inbound mail admitted this pass, every identity together.
    pub admitted: usize,
    /// The identities whose read failed this pass, and why. Each is read
    /// again next pass from the cursor its last good page left.
    pub failed: Vec<(EntityId, String)>,
}

impl NativeMailPack {
    /// Reads every active native mail identity's inbox under `policy`. A
    /// page's next cursor goes into `cursors`, the host's progress, only once
    /// the page's mail is admitted; a mailbox read to its end keeps its end
    /// cursor, so the next pass reads only what changed. A message that
    /// stops its page ends that identity's read for this pass, and is in
    /// the pass's failures. An identity no longer active leaves `cursors`.
    ///
    /// # Errors
    ///
    /// The identities could not be read; one inbox's failure is in the pass.
    pub fn poll_inboxes(
        &self,
        vault: &Vault,
        policy: PlacementPolicy,
        cursors: &mut BTreeMap<EntityId, StalwartInboxCursor>,
        quarantine: &StalwartQuarantine,
        now: u64,
    ) -> Result<NativeMailInboxPass> {
        let identities = active_native_mail_identities(vault)?;
        cursors.retain(|identity, _| identities.contains(identity));
        let mut pass = NativeMailInboxPass::default();
        for identity in identities {
            loop {
                let cursor = cursors.get(&identity).cloned();
                match self.poll_inbox(vault, identity, policy, cursor.as_ref(), quarantine, now) {
                    Ok(outcome) => {
                        pass.admitted = pass.admitted.saturating_add(outcome.admissions.len());
                        if let Some(next) = outcome.next_cursor {
                            cursors.insert(identity, next);
                        }
                        // A stopped message is read again next pass, and the
                        // mail after it waits with it.
                        if let Some(stop) = outcome.stopped {
                            pass.failed.push((
                                identity,
                                format!("message {} stopped: {}", stop.message_id, stop.reason),
                            ));
                            break;
                        }
                        if !outcome.more {
                            break;
                        }
                    }
                    Err(error) => {
                        pass.failed.push((identity, error.to_string()));
                        break;
                    }
                }
            }
        }
        Ok(pass)
    }
}

/// Every native mail identity on `vault` that is active now, in id order.
fn active_native_mail_identities(vault: &Vault) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    let mut active = Vec::new();
    for entry in vault
        .store
        .port_entity_ids_by_type(&txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)?
    {
        let identity = entry?;
        if native_mail_identity_in_txn(&vault.store, &txn, identity)?
            .is_some_and(|row| row.custody.state() == ChannelIdentityState::Active)
        {
            active.push(identity);
        }
    }
    Ok(active)
}
