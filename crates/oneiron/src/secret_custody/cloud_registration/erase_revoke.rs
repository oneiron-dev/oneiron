//! Volatile revoke work from an accepted local hard erase. Nothing is queued
//! until that erase's exact transaction commits; an abort drops its copies.

use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use zeroize::Zeroizing;

use super::CloudRegistrationPhase;
use super::store::rows_in_txn;
use crate::Vault;
use crate::entity_id::EntityId;

#[derive(Default)]
pub(crate) struct EraseRevokes {
    sink: Arc<Mutex<Option<Arc<Sink>>>>,
}

struct Sink {
    id: Arc<()>,
    issuer: String,
    audience: String,
    sender: UnboundedSender<CloudRegistrationEraseRevoke>,
}

/// One committed local erase's pre-shred token copy, for RFC 7009 alone.
/// No value is serializable, logged, or returned by the revoke callback.
pub struct CloudRegistrationEraseRevoke {
    /// The exact cloud-registration slot whose generation was erased.
    pub slot: EntityId,
    /// The binding and custody generation captured in the erasing writer.
    pub generation: u32,
    /// The issuer matched to the installed operator pins before capture.
    pub issuer: String,
    /// The audience matched to those same pins.
    pub audience: String,
    value: Zeroizing<Vec<u8>>,
}

impl CloudRegistrationEraseRevoke {
    /// Presents the opaque token set once to the host's pinned-issuer revoke
    /// operation, then wipes the copy. This is not a refresh or access grant.
    pub fn with_token_set_for_revoke(self, send: impl FnOnce(&[u8])) {
        send(&self.value);
    }
}

/// Owns the single volatile consumer installed for this vault. Dropping it
/// detaches this installation and wipes every queued token copy. Replacing
/// it closes the earlier consumer once its already-captured work is dropped.
pub struct CloudRegistrationEraseRevoker {
    state: Arc<Mutex<Option<Arc<Sink>>>>,
    id: Arc<()>,
    receiver: UnboundedReceiver<CloudRegistrationEraseRevoke>,
}

impl CloudRegistrationEraseRevoker {
    /// Waits for work handed over after an accepted local hard erase commits.
    pub async fn recv(&mut self) -> Option<CloudRegistrationEraseRevoke> {
        self.receiver.recv().await
    }
}

impl Drop for CloudRegistrationEraseRevoker {
    fn drop(&mut self) {
        let mut current = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|sink| Arc::ptr_eq(&sink.id, &self.id))
        {
            current.take();
        }
        self.receiver.close();
    }
}

/// Stack-owned until the exact erasing writer commits. Never stored in a
/// receipt, sweep, thread-local, or database; dropping it wipes every value.
#[derive(Default)]
pub(crate) struct PendingEraseRevokes {
    sink: Option<Arc<Sink>>,
    captures: Vec<CloudRegistrationEraseRevoke>,
}

impl PendingEraseRevokes {
    pub(crate) fn publish(self) {
        if let Some(sink) = self.sink {
            for capture in self.captures {
                if sink.sender.send(capture).is_err() {
                    tracing::warn!("a cloud registration erase revoke consumer stopped");
                }
            }
        }
    }
}

impl Vault {
    /// Installs one host-owned revoke consumer for the actual operator pins.
    /// The issuer and audience come from those pins, never from a saved row.
    /// No consumer means no plaintext capture, not a refusal of the erase.
    pub fn attach_cloud_registration_erase_revoker(
        &self,
        issuer: &str,
        audience: &str,
    ) -> CloudRegistrationEraseRevoker {
        let (sender, receiver) = unbounded_channel();
        let id = Arc::new(());
        let state = Arc::clone(&self.cloud_registration_erase_revokes.sink);
        *state.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(Sink {
            id: Arc::clone(&id),
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            sender,
        }));
        CloudRegistrationEraseRevoker {
            state,
            id,
            receiver,
        }
    }

    /// Called only by the accepted local hard-purge continuations, after
    /// their authority and hold checks and before their actor's slots shred.
    /// Restore, replay and marker readers do not enter this capture path.
    pub(crate) fn cloud_registration_revokes_before_local_erase(
        &self,
        txn: &heed::RoTxn<'_>,
        target: &EntityId,
    ) -> PendingEraseRevokes {
        let sink = self
            .cloud_registration_erase_revokes
            .sink
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(sink) = sink else {
            return PendingEraseRevokes::default();
        };
        let rows = match rows_in_txn(&self.store, txn) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "cloud registration erase revoke bindings did not read");
                return PendingEraseRevokes::default();
            }
        };
        let mut pending = PendingEraseRevokes {
            sink: Some(Arc::clone(&sink)),
            captures: Vec::new(),
        };
        for (slot, row) in rows {
            if row.owner != *target
                || !matches!(
                    row.phase,
                    CloudRegistrationPhase::Linked | CloudRegistrationPhase::InFlight
                )
                || row.issuer != sink.issuer
                || row.audience != sink.audience
            {
                continue;
            }
            match self.cloud_registration_revoke_value_in_txn(txn, &slot, row.generation) {
                Ok(Some(value)) => pending.captures.push(CloudRegistrationEraseRevoke {
                    slot,
                    generation: row.generation,
                    issuer: row.issuer,
                    audience: row.audience,
                    value,
                }),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "a cloud registration erase revoke token did not open")
                }
            }
        }
        pending
    }
}
