//! Locker deletes a host hold guard defers (FIX 1488, Engine 10-20 20:3x).
//!
//! With a guard injected, a delete first records its intent (the vault, the
//! object, its generation and the BLAKE3 digest of the ciphertext it names)
//! in `deferred-deletes/` under the room directory, beside `objects/`, so a
//! listing or a read never shows it. Then the guard runs the unlink. A
//! standing hold the owner may see defers it (202 `held_until_release`); one
//! that stands only as a host order whose silence runs defers it with a
//! neutral 202 `completion_pending` that names no hold (FIX 9500); a hold
//! state the guard cannot read defers it too (202 `hold_state_unknown`).
//! Nothing is refused. The intents replay at start, before the room serves,
//! each time the guard's recheck counter moves, and once an upload kept a
//! generation (`super::overwrite`, FIX 1283), through the same guard. An
//! intent clears once the guard reports its file gone; a current one also
//! once a later upload has replaced the object, which is never deleted. A
//! kept generation's intent clears only on the guard's confirmed absence. A
//! delete, the replay of current intents and an upload's install take one
//! lock per room; a kept generation is retired outside it.

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
use oneiron_vault_contract::relay_delete::{RelayDeleteGeneration, RelayHoldVisibility};
use serde::{Deserialize, Serialize};

use super::hold_guard::{
    PREIMAGE_PREFIX, RelayDeleteDeferral, RelayDeleteHoldError, RelayDeleteHoldGuard,
    RelayDeleteHoldOutcome, RelayDeleteTarget,
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
/// file is named for the file it deletes: the object, or the generation an
/// upload kept (`.preimage-<object>-<generation>`).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    vault_id: String,
    object_id: String,
    generation: RelayDeleteGeneration,
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

/// The body of a delete only silent host orders keep (FIX 9500): its state
/// and nothing else, no hold, reason, order, date or count.
#[derive(Serialize)]
struct CompletionPending {
    state: &'static str,
}

/// The 202 of a delete only silent host orders keep. It claims no deletion.
fn completion_pending_reply() -> Response {
    (
        StatusCode::ACCEPTED,
        Json(CompletionPending {
            state: "completion_pending",
        }),
    )
        .into_response()
}

/// A room's guarded deletes: the host's guard and the intents it has not
/// settled yet.
pub(super) struct HeldDeletes {
    guard: Arc<dyn RelayDeleteHoldGuard>,
    vault: String,
    pub(super) vault_id: [u8; 32],
    pub(super) objects: PathBuf,
    intents: PathBuf,
    /// Taken by a delete, the replay of current intents and an upload's
    /// install, so a replay never unlinks an upload that replaced the object
    /// it accepted.
    serial: tokio::sync::Mutex<()>,
    next_intent: AtomicU64,
    /// Asks the replay to run again once an upload kept a generation: an
    /// event, coalesced, never a timer.
    kick: Arc<tokio::sync::Notify>,
}

impl HeldDeletes {
    /// Makes the intent directory under `room`, replays the intents it
    /// holds, and replays again each time the guard's recheck counter moves
    /// or an upload kept a generation, for as long as the room keeps the
    /// result. Runs before the room serves.
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
        let kick = Arc::new(tokio::sync::Notify::new());
        let held = Arc::new(Self {
            guard,
            vault: vault.to_owned(),
            vault_id,
            objects,
            intents,
            serial: tokio::sync::Mutex::new(()),
            next_intent: AtomicU64::new(0),
            kick: Arc::clone(&kick),
        });
        held.replay().await;
        follow(Arc::downgrade(&held), rechecks, kick);
        Ok(held)
    }

    /// The room's lock for a delete, the replay of current intents and an
    /// upload's install.
    pub(super) async fn serialize(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.serial.lock().await
    }

    /// Asks the replay to run once more, without waiting for it: events that
    /// come while it runs are one more pass, which visits every intent.
    pub(super) fn request_recheck(&self) {
        self.kick.notify_one();
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
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::Held {
                visibility: RelayHoldVisibility::Visible,
            })) => Ok(deferred(Reason::HeldUntilRelease)),
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::Held {
                visibility: RelayHoldVisibility::SilentOnly,
            })) => Ok(completion_pending_reply()),
            Ok(RelayDeleteHoldOutcome::Deferred(RelayDeleteDeferral::HoldStateUnknown))
            | Err(RelayDeleteHoldError::GuardUnavailable) => Ok(deferred(Reason::HoldStateUnknown)),
            Err(RelayDeleteHoldError::StorageIo(error)) => Err(storage_error(error)),
        }
    }

    /// Names the ciphertext `object` holds now and records the intent to
    /// delete it. A missing object answers as it does today.
    fn accept(&self, object: String) -> HttpResult<RelayDeleteTarget> {
        let ciphertext_blake3 = digest(&self.objects.join(&object)).map_err(storage_error)?;
        let target = RelayDeleteTarget {
            vault_id: self.vault_id,
            object_id: object,
            generation: RelayDeleteGeneration::Current,
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
    /// and synced, renamed over any older intent for the same file, then the
    /// directory synced.
    pub(super) fn record(&self, target: &RelayDeleteTarget) -> io::Result<()> {
        let intent = serde_json::to_vec(&Intent {
            vault_id: self.vault.clone(),
            object_id: target.object_id.clone(),
            generation: target.generation.clone(),
            ciphertext_blake3: blake3::Hash::from(target.ciphertext_blake3)
                .to_hex()
                .to_string(),
        })?;
        let sequence = self.next_intent.fetch_add(1, Ordering::Relaxed);
        let temporary = self
            .intents
            .join(format!(".{}-{sequence}.tmp", std::process::id()));
        let published = publish(&temporary, &self.intents.join(target.leaf()), &intent)
            .and_then(|()| sync_directory(&self.intents));
        if published.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        published
    }

    /// Hands the guard the unlink of `target`'s file, then its directory
    /// sync, and clears the intent once the file is gone. A guard that
    /// delegates the delete to the vault's engine reports a confirmed
    /// absence as deleted and never an engine's storage failure as a missing
    /// object, so only a confirmed delete clears its intent (FIX 6826). A
    /// kept generation found missing is gone only once its directory is
    /// synced, inside the guard's exclusion: never on a bare missing file.
    fn settle(
        &self,
        target: &RelayDeleteTarget,
    ) -> Result<RelayDeleteHoldOutcome, RelayDeleteHoldError> {
        let leaf = target.leaf();
        let kept = matches!(target.generation, RelayDeleteGeneration::Preimage { .. });
        let path = self.objects.join(&leaf);
        let mut unlink = || -> io::Result<()> {
            if let Err(error) = std::fs::remove_file(&path)
                && (!kept || error.kind() != io::ErrorKind::NotFound)
            {
                return Err(error);
            }
            sync_directory(&self.objects)
        };
        let settled = self.guard.delete_if_released(target, &mut unlink);
        let gone = match &settled {
            Ok(RelayDeleteHoldOutcome::Deleted) => true,
            Err(RelayDeleteHoldError::StorageIo(error)) => {
                !kept && error.kind() == io::ErrorKind::NotFound
            }
            _ => false,
        };
        if gone {
            self.clear(&leaf);
        }
        settled
    }

    /// Removes the intent file `name`, then syncs the directory. One that
    /// does not clear stays for the next replay, which finds its file gone
    /// or, a current one, replaced and clears it then.
    pub(super) fn clear(&self, name: &str) {
        let cleared = match std::fs::remove_file(self.intents.join(name)) {
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

    /// Settles every recorded intent through the guard: the current ones
    /// under the room's lock, then each kept generation outside it. No upload
    /// writes a kept generation's name, and every one listed under the lock
    /// has its link in place or never will, so an upload never waits on its
    /// guard.
    async fn replay(self: &Arc<Self>) {
        let kept = {
            let _serial = self.serialize().await;
            let held = Arc::clone(self);
            match tokio::task::spawn_blocking(move || held.replay_current()).await {
                Ok(kept) => kept,
                Err(_) => {
                    tracing::warn!("relay delete replay stopped; the next recheck runs it again");
                    return;
                }
            }
        };
        let held = Arc::clone(self);
        let retired = tokio::task::spawn_blocking(move || {
            for name in &kept {
                held.retire(name);
            }
        });
        if retired.await.is_err() {
            tracing::warn!("relay generation retirement stopped; the next recheck runs it again");
        }
    }

    /// Settles every current intent, and names the kept generations' intent
    /// files for [`Self::retire`].
    fn replay_current(&self) -> Vec<String> {
        let mut kept = Vec::new();
        let entries = match std::fs::read_dir(&self.intents) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "relay delete intents did not list");
                return kept;
            }
        };
        for entry in entries {
            let name = match entry {
                Ok(entry) => entry.file_name(),
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), "relay delete intents did not list");
                    return kept;
                }
            };
            match name.to_str() {
                Some(object) if hex_id(object) || object == "manifest" => self.replay_one(object),
                Some(leaf) if leaf.starts_with(PREIMAGE_PREFIX) => kept.push(leaf.to_owned()),
                _ => {}
            }
        }
        kept
    }

    /// Retires one kept generation through the guard: never cleared because
    /// the object now holds other bytes, since the generation is not the
    /// object's current file. Held or unknown, it stays, and its intent too.
    fn retire(&self, leaf: &str) {
        let Some(target) = self.read_intent(leaf) else {
            return;
        };
        if let Err(RelayDeleteHoldError::StorageIo(error)) = self.settle(&target) {
            tracing::warn!(
                kind = ?error.kind(),
                "relay generation retirement did not unlink; the next recheck asks again"
            );
        }
    }

    /// Settles one intent: cleared when its object now holds other bytes
    /// than the delete named, else handed to the guard again, a missing
    /// object too: an engine that executes the delete confirms the absence
    /// itself, and a claimed object a stopped engine job left goes back at
    /// its next bind (FIX 6826).
    fn replay_one(&self, object: &str) {
        let Some(target) = self.read_intent(object) else {
            return;
        };
        match digest(&self.objects.join(object)) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "relay delete replay did not read the object; the next recheck asks again"
                );
            }
            Ok(current) if current != target.ciphertext_blake3 => self.clear(object),
            _ => {
                if let Err(RelayDeleteHoldError::StorageIo(error)) = self.settle(&target)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "relay delete replay did not unlink; the next recheck asks again"
                    );
                }
            }
        }
    }

    /// The intent recorded in the file `name`, or `None` when the file does
    /// not read as one this room wrote for the file it is named for. Such a
    /// file stays, and deletes nothing.
    fn read_intent(&self, name: &str) -> Option<RelayDeleteTarget> {
        let target = std::fs::read(self.intents.join(name))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Intent>(&bytes).ok())
            .filter(|intent| {
                intent.vault_id == self.vault
                    && (hex_id(&intent.object_id) || intent.object_id == "manifest")
                    && intent.generation.validate().is_ok()
            })
            .and_then(|intent| {
                let digest = blake3::Hash::from_hex(&intent.ciphertext_blake3).ok()?;
                Some(RelayDeleteTarget {
                    vault_id: self.vault_id,
                    object_id: intent.object_id,
                    generation: intent.generation,
                    ciphertext_blake3: *digest.as_bytes(),
                })
            })
            .filter(|target| target.leaf() == name);
        if target.is_none() {
            tracing::warn!("relay delete intent did not read; it stays and deletes nothing");
        }
        target
    }
}

/// Replays `held`'s intents each time `rechecks` moves or `kick` is
/// notified, until the room drops its deletes or the guard drops its
/// counter. Events, never a timer.
fn follow(
    held: Weak<HeldDeletes>,
    mut rechecks: tokio::sync::watch::Receiver<u64>,
    kick: Arc<tokio::sync::Notify>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = rechecks.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                () = kick.notified() => {}
            }
            let Some(held) = held.upgrade() else {
                return;
            };
            held.replay().await;
        }
    });
}

/// The BLAKE3 digest of the bytes stored at `path`.
pub(super) fn digest(path: &Path) -> io::Result<[u8; 32]> {
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

/// Syncs directory `path` through the engine's one portable flush (FIX
/// 7060), which opens it as each platform's flush needs; its I/O error is
/// returned as it is, and any other as an I/O error.
pub(super) fn sync_directory(path: &Path) -> io::Result<()> {
    oneiron::store::sync_dir(path).map_err(|error| match error {
        oneiron::Error::Io(error) => error,
        other => io::Error::other(other),
    })
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
