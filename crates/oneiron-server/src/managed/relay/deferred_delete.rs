//! Locker deletes a host hold guard defers (FIX 1488, Engine 10-20 20:3x).
//!
//! With a guard injected, a delete first records its intent (the vault, the
//! object and the BLAKE3 digest of the ciphertext it names) in
//! `deferred-deletes/` under the room directory, beside `objects/`, so a
//! listing or a read never shows it. Then the guard runs the unlink. A
//! standing hold defers it (202 `held_until_release`), and so does a hold
//! state the guard cannot read (202 `hold_state_unknown`). Nothing is refused.
//! The intents replay at start, before the room serves, and each time the
//! guard's recheck counter moves, through the same guard. An intent clears
//! once its object is gone, or once a later upload has replaced the object,
//! which is never deleted. A delete, a replay and the rename of an upload
//! take one lock per room.

use std::{
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::hold_guard::{
    RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard, RelayDeleteHoldOutcome,
    RelayDeleteTarget,
};
use super::{HttpResult, hex_id, storage_error};

/// The intent directory, under the room directory.
const INTENTS: &str = "deferred-deletes";

/// A delete whose intent did not record: not accepted.
const INTENT_UNRECORDED: (StatusCode, &str) = (
    StatusCode::INTERNAL_SERVER_ERROR,
    "locker storage unavailable",
);

/// One recorded delete, as its file under `deferred-deletes/` holds it. The
/// file is named for the object.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    vault_id: String,
    object_id: String,
    ciphertext_blake3: String,
}

/// The body of a deferred delete's 202. It names no hold, order, date or
/// count.
#[derive(Serialize)]
struct Deferred {
    state: &'static str,
    reason: Reason,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    /// A standing hold keeps the vault's backups.
    HeldUntilRelease,
    /// The guard could not read the holds, or could not run.
    HoldStateUnknown,
}

fn deferred(reason: Reason) -> Response {
    (
        StatusCode::ACCEPTED,
        Json(Deferred {
            state: "deferred",
            reason,
        }),
    )
        .into_response()
}

/// A room's guarded deletes: the host's guard and the intents it has not
/// settled yet.
pub(super) struct HeldDeletes {
    guard: Arc<dyn RelayDeleteHoldGuard>,
    vault: String,
    vault_id: [u8; 32],
    objects: PathBuf,
    intents: PathBuf,
    /// Taken by a delete, a replay and the rename of an upload, so a replay
    /// never unlinks an upload that replaced the object it accepted.
    serial: tokio::sync::Mutex<()>,
    next_intent: AtomicU64,
}

impl HeldDeletes {
    /// Makes the intent directory under `room`, replays the intents it
    /// holds, and replays again each time the guard's recheck counter moves,
    /// for as long as the room keeps the result. Runs before the room
    /// serves.
    pub(super) async fn start(
        guard: Arc<dyn RelayDeleteHoldGuard>,
        vault: &str,
        room: &Path,
        objects: PathBuf,
    ) -> anyhow::Result<Arc<Self>> {
        let vault_id = vault_bytes(vault)
            .ok_or_else(|| anyhow::anyhow!("vault_id must be 32 bytes of lowercase hex"))?;
        let intents = room.join(INTENTS);
        std::fs::create_dir_all(&intents)?;
        std::fs::set_permissions(&intents, std::fs::Permissions::from_mode(0o700))?;
        // Subscribed before the first replay, so a release meanwhile still
        // moves the counter this room follows.
        let rechecks = guard.subscribe_rechecks();
        let held = Arc::new(Self {
            guard,
            vault: vault.to_owned(),
            vault_id,
            objects,
            intents,
            serial: tokio::sync::Mutex::new(()),
            next_intent: AtomicU64::new(0),
        });
        held.replay().await;
        follow(Arc::downgrade(&held), rechecks);
        Ok(held)
    }

    /// The room's lock for a delete, a replay and the rename of an upload.
    pub(super) async fn serialize(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.serial.lock().await
    }

    /// The guarded delete of `object`, a name the room has validated: 204
    /// once unlinked, 202 while deferred, today's 404 when the object is
    /// missing, and 500 when its intent did not record.
    pub(super) async fn delete(self: &Arc<Self>, object: String) -> HttpResult<Response> {
        let _serial = self.serialize().await;
        let held = Arc::clone(self);
        let target = tokio::task::spawn_blocking(move || held.accept(object))
            .await
            .unwrap_or(Err(INTENT_UNRECORDED))?;
        let held = Arc::clone(self);
        let settled = tokio::task::spawn_blocking(move || held.settle(&target))
            .await
            .unwrap_or(Err(RelayDeleteHoldError::GuardUnavailable));
        match settled {
            Ok(RelayDeleteHoldOutcome::Deleted) => Ok(StatusCode::NO_CONTENT.into_response()),
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HeldUntilRelease)) => {
                Ok(deferred(Reason::HeldUntilRelease))
            }
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HoldStateUnknown))
            | Err(RelayDeleteHoldError::GuardUnavailable) => Ok(deferred(Reason::HoldStateUnknown)),
            Err(RelayDeleteHoldError::StorageIo(error)) => Err(storage_error(error)),
        }
    }

    /// Drops the intent for `object` once an upload has replaced it, so no
    /// replay deletes the replacement. Runs under [`Self::serialize`].
    pub(super) async fn superseded(self: &Arc<Self>, object: &str) {
        let held = Arc::clone(self);
        let object = object.to_owned();
        let _ = tokio::task::spawn_blocking(move || held.clear(&object)).await;
    }

    /// Names the ciphertext `object` holds now and records the intent to
    /// delete it. A missing object answers as it does today.
    fn accept(&self, object: String) -> HttpResult<RelayDeleteTarget> {
        let ciphertext_blake3 = digest(&self.objects.join(&object)).map_err(storage_error)?;
        let target = RelayDeleteTarget {
            vault_id: self.vault_id,
            object_id: object,
            ciphertext_blake3,
        };
        self.record(&target).map_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "relay delete not accepted: its intent did not record"
            );
            INTENT_UNRECORDED
        })?;
        Ok(target)
    }

    /// Publishes `target`'s intent: written under a hidden temporary name
    /// and synced, renamed over any older intent for the object, then the
    /// directory synced.
    fn record(&self, target: &RelayDeleteTarget) -> io::Result<()> {
        let intent = serde_json::to_vec(&Intent {
            vault_id: self.vault.clone(),
            object_id: target.object_id.clone(),
            ciphertext_blake3: blake3::Hash::from(target.ciphertext_blake3)
                .to_hex()
                .to_string(),
        })?;
        let sequence = self.next_intent.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .intents
            .join(format!(".{}-{sequence}.tmp", std::process::id()));
        let published = publish(&temporary, &self.intents.join(&target.object_id), &intent)
            .and_then(|()| sync_directory(&self.intents));
        if published.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        published
    }

    /// Hands the guard the unlink of `target`'s object, then its directory
    /// sync, and clears the intent once the object is gone.
    fn settle(
        &self,
        target: &RelayDeleteTarget,
    ) -> Result<RelayDeleteHoldOutcome, RelayDeleteHoldError> {
        let path = self.objects.join(&target.object_id);
        let mut unlink = || -> io::Result<()> {
            std::fs::remove_file(&path)?;
            sync_directory(&self.objects)
        };
        let settled = self.guard.delete_if_released(target, &mut unlink);
        let gone = match &settled {
            Ok(RelayDeleteHoldOutcome::Deleted) => true,
            Err(RelayDeleteHoldError::StorageIo(error)) => error.kind() == io::ErrorKind::NotFound,
            _ => false,
        };
        if gone {
            self.clear(&target.object_id);
        }
        settled
    }

    /// Removes the intent for `object`, then syncs the directory. One that
    /// does not clear stays for the next replay, which finds its object gone
    /// or replaced and clears it then.
    fn clear(&self, object: &str) {
        let cleared = match std::fs::remove_file(self.intents.join(object)) {
            Ok(()) => sync_directory(&self.intents),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        };
        if let Err(error) = cleared {
            tracing::warn!(
                kind = ?error.kind(),
                "relay delete intent did not clear; a replay settles it"
            );
        }
    }

    /// Settles every recorded intent through the guard, under the room's
    /// lock.
    async fn replay(self: &Arc<Self>) {
        let _serial = self.serialize().await;
        let held = Arc::clone(self);
        if tokio::task::spawn_blocking(move || held.replay_all())
            .await
            .is_err()
        {
            tracing::warn!("relay delete replay stopped; the next recheck runs it again");
        }
    }

    fn replay_all(&self) {
        let entries = match std::fs::read_dir(&self.intents) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "relay delete intents did not list");
                return;
            }
        };
        for entry in entries {
            let name = match entry {
                Ok(entry) => entry.file_name(),
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "relay delete intents did not list");
                    return;
                }
            };
            if let Some(object) = name.to_str().filter(|id| hex_id(id) || *id == "manifest") {
                self.replay_one(object);
            }
        }
    }

    /// Settles one intent: cleared when its object is gone or now holds
    /// other bytes than the delete named, else handed to the guard again.
    fn replay_one(&self, object: &str) {
        let Some(target) = self.read_intent(object) else {
            return;
        };
        match digest(&self.objects.join(object)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => self.clear(object),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "relay delete replay did not read the object; the next recheck asks again"
                );
            }
            Ok(current) if current != target.ciphertext_blake3 => self.clear(object),
            Ok(_) => {
                if let Err(RelayDeleteHoldError::StorageIo(error)) = self.settle(&target) {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "relay delete replay did not unlink; the next recheck asks again"
                    );
                }
            }
        }
    }

    /// The intent recorded for `object`, or `None` when the file does not
    /// read as one this room wrote. Such a file stays, and deletes nothing.
    fn read_intent(&self, object: &str) -> Option<RelayDeleteTarget> {
        let target = std::fs::read(self.intents.join(object))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Intent>(&bytes).ok())
            .filter(|intent| intent.vault_id == self.vault && intent.object_id == object)
            .and_then(|intent| {
                let digest = blake3::Hash::from_hex(&intent.ciphertext_blake3).ok()?;
                Some(RelayDeleteTarget {
                    vault_id: self.vault_id,
                    object_id: intent.object_id,
                    ciphertext_blake3: *digest.as_bytes(),
                })
            });
        if target.is_none() {
            tracing::warn!("relay delete intent did not read; it stays and deletes nothing");
        }
        target
    }
}

/// Replays `held`'s intents each time `rechecks` moves, until the room drops
/// its deletes or the guard drops its counter. An event, never a timer.
fn follow(held: Weak<HeldDeletes>, mut rechecks: tokio::sync::watch::Receiver<u64>) {
    tokio::spawn(async move {
        while rechecks.changed().await.is_ok() {
            let Some(held) = held.upgrade() else {
                return;
            };
            held.replay().await;
        }
    });
}

/// The BLAKE3 digest of the bytes stored at `path`.
fn digest(path: &Path) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut std::fs::File::open(path)?, &mut hasher)?;
    Ok(*hasher.finalize().as_bytes())
}

/// Writes `bytes` to the new owner-only file `temporary`, syncs it, then
/// renames it to `path`.
fn publish(temporary: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

/// The 32 bytes a room's lowercase hex vault id names.
fn vault_bytes(vault: &str) -> Option<[u8; 32]> {
    if !hex_id(vault) {
        return None;
    }
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(vault.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}
