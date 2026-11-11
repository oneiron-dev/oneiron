//! The roster lifetime of a managed person socket, not an admission gate.

use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::{EntityId, Vault};
use tokio::sync::watch;

pub(super) struct LivePerson {
    holder: EntityId,
    was_member: AtomicBool,
    changes: watch::Receiver<u64>,
}

impl LivePerson {
    pub(super) fn new(vault: &Vault, holder: EntityId) -> Self {
        let changes = vault.subscribe_credential_revocations();
        let was_member = vault.is_live_member_person(&holder).unwrap_or(false);
        Self {
            holder,
            was_member: AtomicBool::new(was_member),
            changes,
        }
    }

    pub(super) fn ended(&self, vault: &Vault) -> bool {
        match vault.is_live_member_person(&self.holder) {
            Ok(true) => {
                self.was_member.store(true, Ordering::Relaxed);
                false
            }
            Ok(false) => self.was_member.load(Ordering::Relaxed),
            // A new liveness read must not turn uncertainty into a refusal.
            Err(_) => false,
        }
    }

    pub(super) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.changes.changed().await
    }
}
