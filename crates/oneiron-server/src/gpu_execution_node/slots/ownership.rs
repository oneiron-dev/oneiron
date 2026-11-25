//! Which Oneiron server of this machine owns each offered GPU: a lock file
//! per GPU in `owner_lock_dir`, held while the table runs, and the kept
//! record beside it, which names the key of the job launched there from its
//! launch confirmation until its slot ends.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::{Shared, State, slot_on};

/// The stem of `device_id`'s files in the owner lock directory.
fn owner_file_stem(device_id: &str) -> String {
    device_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// This server's lock on `device_id` in `dir`, when no other holds it. The
/// lock lasts as long as the open file. The directory is the owner's shared
/// one and is never made here: where it is missing, no lock is taken and the
/// GPU is not offered.
fn owner_lock(dir: &Path, device_id: &str) -> Option<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(format!("{}.lock", owner_file_stem(device_id))))
        .ok()?;
    file.try_lock().ok()?;
    Some(file)
}

/// Where `device_id`'s kept record lives in `dir`: the key of the job
/// launched on it, from its launch confirmation until its slot ends.
fn kept_record_path(dir: &Path, device_id: &str) -> PathBuf {
    dir.join(format!("{}.kept", owner_file_stem(device_id)))
}

/// The key `device_id`'s kept record in `dir` names, if one stands. A record
/// that cannot be read is an error: its GPU is kept by a job no table can
/// name.
fn kept_key(dir: &Path, device_id: &str) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(kept_record_path(dir, device_id)) {
        Ok(text) => Ok(Some(text.lines().next().unwrap_or_default().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether `dir`'s kept record for `device_id` names `key`.
pub(super) fn kept_for(dir: &Path, device_id: &str, key: &str) -> bool {
    kept_key(dir, device_id)
        .ok()
        .flatten()
        .is_some_and(|kept| kept == key)
}

impl Shared {
    /// Takes the owner lock of every offered GPU this table does not own
    /// yet, and answers the ones it owns (`None`: it takes no lock). A lock
    /// another server holds is asked again at the next reading. A GPU whose
    /// kept record names a key this table holds no slot on it under stays
    /// unowned: a job a stopped server launched still runs there.
    pub(super) fn own_offered(&self, state: &mut State) -> Option<BTreeSet<String>> {
        let dir = self.offer.owner_lock_dir.as_ref()?;
        for device_id in &self.offer.offered {
            if state.owner_locks.contains_key(device_id) {
                continue;
            }
            let Some(lock) = owner_lock(dir, device_id) else {
                continue;
            };
            let kept_for_another = match kept_key(dir, device_id) {
                Ok(None) => false,
                Ok(Some(key)) => {
                    !slot_on(&state.slots, device_id).is_some_and(|slot| slot.grant.key == key)
                }
                Err(_) => true,
            };
            // Dropping the lock unasked lets the record's own server take it.
            if !kept_for_another {
                state.owner_locks.insert(device_id.clone(), lock);
            }
        }
        Some(state.owner_locks.keys().cloned().collect())
    }

    /// Writes `key` as `device_id`'s kept record, so the GPU stays its job's
    /// past this server's life. With no owner lock directory there is none.
    pub(super) fn keep_record(&self, device_id: &str, key: &str) -> std::io::Result<()> {
        let Some(dir) = &self.offer.owner_lock_dir else {
            return Ok(());
        };
        let path = kept_record_path(dir, device_id);
        let staged = path.with_extension("kept.new");
        std::fs::write(&staged, format!("{key}\n"))?;
        std::fs::rename(&staged, &path)
    }

    /// Removes `device_id`'s kept record when it names `key`.
    pub(super) fn forget_record(&self, device_id: &str, key: &str) {
        let Some(dir) = &self.offer.owner_lock_dir else {
            return;
        };
        if !kept_for(dir, device_id, key) {
            return;
        }
        if let Err(error) = std::fs::remove_file(kept_record_path(dir, device_id))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                %error,
                device_id,
                key,
                "the GPU's kept record could not be removed; the GPU stays withheld until a person deletes it"
            );
        }
    }

    /// Clears every kept record naming `key`, a key with no slot here, on a
    /// GPU this table owns or can own now, so no live server's record is
    /// touched.
    pub(super) fn forget_records_of(&self, state: &mut State, key: &str) {
        let Some(dir) = &self.offer.owner_lock_dir else {
            return;
        };
        for device_id in &self.offer.offered {
            if !kept_for(dir, device_id, key) {
                continue;
            }
            if !state.owner_locks.contains_key(device_id) {
                let Some(lock) = owner_lock(dir, device_id) else {
                    continue;
                };
                state.owner_locks.insert(device_id.clone(), lock);
            }
            self.forget_record(device_id, key);
        }
    }
}
