//! The relay delete ctl requests a managed vault answers (FIX 6826):
//! `relay_delete_execute`, `relay_delete_rechecks` and `relay_locker_bind`,
//! over this vault's own executor (`managed::relay_delete`).
//!
//! Each names this vault twice, by its registry name and by its engine
//! vault id, and is answered for another vault without touching anything.
//! A delete also names this boot. It is admitted like a served write: it
//! counts among the owner writes in flight from its freeze check until its
//! job ends, so a reap never reads quiescent over it, and a vault frozen for
//! reap or stopping answers it `unknown` (`not_ready`), never the typed reap
//! pause, and starts nothing.

use std::path::PathBuf;
use std::time::Instant;

use oneiron_vault_contract::relay_delete::{
    RelayDeleteExecuteWire, RelayDeleteRechecksRequest, RelayDeleteRechecksWire,
    RelayDeleteRequest, RelayDeleteState, RelayDeleteUnknown, RelayLockerBindRequest,
    RelayLockerBindWire, RelayLockerRefusal,
};
use oneiron_vault_contract::{CtlResponse, from_hex, hex};

use super::ManagedState;
use super::admission::{Admitted, WriteKind};
use crate::managed::ManagedError;
use crate::managed::RelayDeleteTarget;
use crate::managed::relay_delete::RelayDeleteJob;

impl ManagedState {
    /// Answers `relay_delete_execute`: what became of the delete, with the
    /// request's six fields as sent.
    pub(super) async fn relay_delete_execute(&self, request: RelayDeleteRequest) -> CtlResponse {
        let dispatched = Instant::now();
        let state = self.relay_delete_state(&request, dispatched).await;
        if !state.settled() {
            tracing::info!(
                state = ?state,
                "relay delete not settled; the relay keeps its intent"
            );
        }
        CtlResponse::RelayDeleteExecute {
            relay_delete_execute: RelayDeleteExecuteWire { request, state },
        }
    }

    /// The delete `request` names, run on this vault once it names this
    /// vault and this boot and is admitted like a served write.
    async fn relay_delete_state(
        &self,
        request: &RelayDeleteRequest,
        dispatched: Instant,
    ) -> RelayDeleteState {
        let unknown = |reason| RelayDeleteState::Unknown { reason };
        if !self.names_this_vault(&request.vault, &request.engine_vault_id) {
            return unknown(RelayDeleteUnknown::VaultMismatch);
        }
        if request.engine_instance != self.relay_delete.instance() {
            return unknown(RelayDeleteUnknown::InstanceMismatch);
        }
        let Some(ciphertext_blake3) = from_hex(&request.ciphertext_blake3)
            .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        else {
            return unknown(RelayDeleteUnknown::InvalidTarget);
        };
        let Ok(admission) = self.relay_delete_admission() else {
            return unknown(RelayDeleteUnknown::NotReady);
        };
        let vault = self.server.vault();
        let job = RelayDeleteJob {
            target: RelayDeleteTarget {
                vault_id: vault.vault_key_vault_id(),
                object_id: request.object.clone(),
                ciphertext_blake3,
            },
            request_id: request.request_id.clone(),
        };
        self.relay_delete
            .execute(vault, job, dispatched, admission)
            .await
    }

    /// An owner write's admission, taken for a relay delete's job: counted
    /// in the hold that reads the freeze, so a concurrent freeze either sees
    /// it or refuses it.
    fn relay_delete_admission(&self) -> Result<Admitted, ManagedError> {
        self.admit(WriteKind::OwnerWrite)
    }

    /// Whether `vault` and `engine_vault_id` are this vault's registry name
    /// and engine vault id.
    fn names_this_vault(&self, vault: &str, engine_vault_id: &str) -> bool {
        vault == self.vault_name
            && engine_vault_id == hex(&self.server.vault().vault_key_vault_id())
    }

    /// Answers `relay_delete_rechecks`: this boot's recheck counter, once it
    /// moves or the wait ends. A read: a vault frozen for reap answers it.
    pub(super) async fn relay_delete_rechecks(
        &self,
        request: RelayDeleteRechecksRequest,
    ) -> CtlResponse {
        let RelayDeleteRechecksRequest {
            vault,
            engine_vault_id,
            engine_instance,
            after,
            wait_ms,
        } = request;
        let counter = if self.names_this_vault(&vault, &engine_vault_id) {
            self.relay_delete
                .rechecks(
                    self.server.vault(),
                    engine_instance.as_deref(),
                    after,
                    wait_ms,
                )
                .await
        } else {
            Err(RelayDeleteUnknown::VaultMismatch)
        };
        let relay_delete_rechecks = match counter {
            Ok((counter, changed)) => RelayDeleteRechecksWire::Bound {
                vault,
                engine_vault_id,
                engine_instance: self.relay_delete.instance().to_owned(),
                counter,
                changed,
            },
            Err(reason) => RelayDeleteRechecksWire::Unknown {
                vault,
                engine_vault_id,
                reason,
            },
        };
        CtlResponse::RelayDeleteRechecks {
            relay_delete_rechecks,
        }
    }

    /// Answers `relay_locker_bind`: binds the room's objects directory, in
    /// place of any before it. A vault frozen for reap or stopping binds
    /// nothing.
    pub(super) async fn relay_locker_bind(&self, request: RelayLockerBindRequest) -> CtlResponse {
        let RelayLockerBindRequest {
            vault,
            engine_vault_id,
            objects_dir,
        } = request;
        let bound = if !self.names_this_vault(&vault, &engine_vault_id) {
            Err(RelayLockerRefusal::VaultMismatch)
        } else if self.guard_write().is_err() {
            Err(RelayLockerRefusal::NotReady)
        } else {
            self.relay_delete
                .bind(self.server.vault(), PathBuf::from(objects_dir))
                .await
        };
        let relay_locker_bind = match bound {
            Ok(()) => RelayLockerBindWire::Bound {
                vault,
                engine_vault_id,
                engine_instance: self.relay_delete.instance().to_owned(),
            },
            Err(reason) => RelayLockerBindWire::Refused {
                vault,
                engine_vault_id,
                reason,
            },
        };
        CtlResponse::RelayLockerBind { relay_locker_bind }
    }
}
