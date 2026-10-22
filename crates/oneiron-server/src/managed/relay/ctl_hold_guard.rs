//! The relay's hold guard when its vault's engine runs as another process
//! (FIX 6826, Engine 10-21).
//!
//! [`CtlRelayHoldGuard`] implements [`RelayDeleteHoldGuard`] by asking the
//! engine to execute the delete (`relay_delete_execute`) through the
//! supervisor's restricted broker socket, and never runs the unlink it is
//! handed: the engine claims, unlinks and syncs the object itself, inside
//! its backup-hold writer exclusion. A confirmed `deleted` or `absent` is
//! [`RelayDeleteHoldOutcome::Deleted`]; a standing hold defers it, with the
//! coarse visibility the engine read (FIX 9500); everything else, the engine
//! unknown, unproven or unreachable, or an answer that does not read, defers
//! it `hold_state_unknown`, its intent kept. An engine's storage failure is a
//! storage failure, never one that reads as a missing object.
//!
//! The guard asks only an engine boot it has proven: a rechecks task polls
//! the broker (`relay_delete_rechecks`), first for a snapshot of whichever
//! boot answers, then that boot's counter. Each proven boot, and each move
//! of its counter, moves the guard's own recheck counter, so the room asks
//! its deferred deletes again. A lost engine leaves the room serving and
//! every delete deferred; it never falls back to an unguarded delete.
//!
//! The room is guarded: its objects directory must keep the mode its host
//! provisioned, 02770, setgid to the vault's group, so the vault's engine can
//! read and delete what the room uploads. A room found otherwise defers
//! every delete `hold_state_unknown` until it is put right.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Once, PoisonError, Weak};
use std::time::Duration;

use oneiron_vault_contract::hex;
use oneiron_vault_contract::relay_delete::{
    RelayDeleteIoKind, RelayDeleteRechecksRequest, RelayDeleteRechecksWire, RelayDeleteRequest,
    RelayDeleteState, RelayDeleteUnknown,
};
use rand_core::{OsRng, RngCore};
use tokio::sync::watch;

use super::ctl_client::BrokerClient;
use super::hold_guard::{
    RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard, RelayDeleteHoldOutcome,
    RelayDeleteTarget,
};

/// How long, in milliseconds, one poll waits on a proven boot's counter.
const POLL_MS: u32 = 1000;

/// How long the rechecks task waits after a poll that proved no boot.
const RETRY: Duration = Duration::from_secs(1);

/// The mode bits a guarded room's objects directory keeps: owner and group
/// read, write and search, setgid, nothing for others.
const GUARDED_OBJECTS_MODE: u32 = 0o2770;

const HOLD_STATE_UNKNOWN: RelayDeleteHoldOutcome =
    RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HoldStateUnknown);

/// [`RelayDeleteHoldGuard`] over a vault engine reached through the
/// supervisor's broker.
pub(super) struct CtlRelayHoldGuard {
    room: Arc<Room>,
    /// Whether the rechecks task runs yet.
    following: Once,
}

/// What the guard and its rechecks task share.
struct Room {
    /// The vault's registry id.
    vault: String,
    /// The room's engine vault id, and its lowercase hex.
    engine_vault_id: [u8; 32],
    engine_hex: String,
    /// The room's objects directory.
    objects: PathBuf,
    client: BrokerClient,
    /// The engine boot proven last and its counter, or none.
    proven: Mutex<Option<Proven>>,
    /// The counter the room's deferred deletes follow.
    rechecks: watch::Sender<u64>,
}

#[derive(Clone)]
struct Proven {
    instance: String,
    counter: u64,
}

impl CtlRelayHoldGuard {
    /// The guard for the room of `engine_vault_id`, whose vault's registry
    /// id is `vault`, at the broker `socket`, with its objects directory
    /// `objects`.
    pub(super) fn new(
        vault: String,
        engine_vault_id: [u8; 32],
        socket: PathBuf,
        objects: PathBuf,
    ) -> Self {
        Self {
            room: Arc::new(Room {
                vault,
                engine_vault_id,
                engine_hex: hex(&engine_vault_id),
                objects,
                client: BrokerClient::new(socket),
                proven: Mutex::new(None),
                rechecks: watch::channel(0).0,
            }),
            following: Once::new(),
        }
    }
}

impl Room {
    fn proven(&self) -> MutexGuard<'_, Option<Proven>> {
        self.proven.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `instance` and its `counter` as proven; `true` when that is
    /// another boot than before, or its counter moved.
    fn observe(&self, instance: String, counter: u64) -> bool {
        let mut proven = self.proven();
        let moved = proven
            .as_ref()
            .is_none_or(|proven| proven.instance != instance || proven.counter != counter);
        *proven = Some(Proven { instance, counter });
        moved
    }

    /// Forgets the proven boot, or only `instance` when given; `true` when
    /// one was forgotten.
    fn forget(&self, instance: Option<&str>) -> bool {
        let mut proven = self.proven();
        let matches = proven
            .as_ref()
            .is_some_and(|proven| instance.is_none_or(|instance| proven.instance == instance));
        if matches {
            *proven = None;
        }
        matches
    }

    /// Whether the objects directory keeps a guarded room's mode.
    fn guarded_mode(&self) -> bool {
        std::fs::symlink_metadata(&self.objects).is_ok_and(|metadata| {
            metadata.is_dir() && metadata.permissions().mode() & 0o7777 == GUARDED_OBJECTS_MODE
        })
    }
}

impl RelayDeleteHoldGuard for CtlRelayHoldGuard {
    fn delete_if_released(
        &self,
        target: &RelayDeleteTarget,
        _unlink: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<RelayDeleteHoldOutcome, RelayDeleteHoldError> {
        let room = &self.room;
        if target.vault_id != room.engine_vault_id {
            return Ok(HOLD_STATE_UNKNOWN);
        }
        if !room.guarded_mode() {
            tracing::warn!(
                "relay delete deferred: the room's objects directory is not 02770, the mode its host provisions"
            );
            return Ok(HOLD_STATE_UNKNOWN);
        }
        let Some(instance) = room.proven().as_ref().map(|proven| proven.instance.clone()) else {
            return Ok(HOLD_STATE_UNKNOWN);
        };
        let mut request_id = [0u8; 16];
        OsRng.fill_bytes(&mut request_id);
        let request = RelayDeleteRequest {
            vault: room.vault.clone(),
            engine_vault_id: room.engine_hex.clone(),
            engine_instance: instance,
            request_id: hex(&request_id),
            object: target.object_id.clone(),
            generation: target.generation.clone(),
            ciphertext_blake3: hex(&target.ciphertext_blake3),
        };
        match room.client.execute(&request) {
            Ok(RelayDeleteState::Deleted | RelayDeleteState::Absent) => {
                Ok(RelayDeleteHoldOutcome::Deleted)
            }
            Ok(RelayDeleteState::Held { visibility }) => Ok(RelayDeleteHoldOutcome::Deferred(
                RelayDeleteDeferral::Held { visibility },
            )),
            Ok(RelayDeleteState::StorageIo { stage, kind }) => {
                let kind = match kind {
                    RelayDeleteIoKind::PermissionDenied => io::ErrorKind::PermissionDenied,
                    RelayDeleteIoKind::NotFound | RelayDeleteIoKind::Other => io::ErrorKind::Other,
                };
                Err(RelayDeleteHoldError::StorageIo(io::Error::new(
                    kind,
                    format!("the engine's relay delete failed at {}", stage.as_str()),
                )))
            }
            Ok(RelayDeleteState::Unknown { reason }) | Err(reason) => {
                if reason == RelayDeleteUnknown::InstanceMismatch {
                    room.forget(Some(request.engine_instance.as_str()));
                }
                tracing::info!(
                    reason = reason.as_str(),
                    "relay delete deferred: its engine did not delete it"
                );
                Ok(HOLD_STATE_UNKNOWN)
            }
        }
    }

    fn subscribe_rechecks(&self) -> watch::Receiver<u64> {
        self.following.call_once(|| {
            tokio::spawn(follow(Arc::downgrade(&self.room)));
        });
        self.room.rechecks.subscribe()
    }
}

/// The rechecks task: proves an engine boot through the broker, then
/// follows its counter, moving the room's counter on each proven boot and
/// each move. Until the room drops its guard. A poll that proves nothing
/// forgets the boot, so every delete defers, and asks again after
/// [`RETRY`]; it never wakes a vault.
async fn follow(room: Weak<Room>) {
    let mut lost_logged = false;
    loop {
        let Some(live) = room.upgrade() else {
            return;
        };
        let proven = live.proven().clone();
        let request = RelayDeleteRechecksRequest {
            vault: live.vault.clone(),
            engine_vault_id: live.engine_hex.clone(),
            engine_instance: proven.as_ref().map(|proven| proven.instance.clone()),
            after: proven.as_ref().map_or(0, |proven| proven.counter),
            wait_ms: if proven.is_some() { POLL_MS } else { 0 },
        };
        let client = live.client.clone();
        drop(live);
        let answer = tokio::task::spawn_blocking(move || client.rechecks(&request))
            .await
            .unwrap_or(Err(RelayDeleteUnknown::GuardUnavailable));
        let Some(live) = room.upgrade() else {
            return;
        };
        match answer {
            Ok(RelayDeleteRechecksWire::Bound {
                engine_instance,
                counter,
                ..
            }) => {
                if proven.is_none() {
                    tracing::info!("the relay hold guard proved its vault's engine");
                }
                lost_logged = false;
                if live.observe(engine_instance, counter) {
                    live.rechecks
                        .send_modify(|generation| *generation = generation.wrapping_add(1));
                }
            }
            Ok(RelayDeleteRechecksWire::Unknown { reason, .. }) | Err(reason) => {
                if live.forget(None) || !lost_logged {
                    tracing::warn!(
                        reason = reason.as_str(),
                        "the relay hold guard has no proven engine; relay deletes stay deferred"
                    );
                    lost_logged = true;
                }
                drop(live);
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}
