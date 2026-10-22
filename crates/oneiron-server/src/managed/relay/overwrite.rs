//! A guarded room's upload over an object it holds (FIX 1283, FIX 9499).
//!
//! An upload never asks the hold guard, the broker or the engine: it lands
//! or fails on storage alone, as it always has, and answers 204 once it is
//! durable. What it replaces is kept, not destroyed. Under the room's lock
//! the install records the intent to retire the object's current generation
//! (the object, a fresh generation id, 16 random bytes as 32 lowercase hex,
//! and the BLAKE3 of the bytes it holds), hard-links the current file to
//! `.preimage-<object>-<generation>` in the same objects directory, syncs the
//! directory, renames the upload over the object and syncs the directory
//! again. Only then does the object's own current delete intent clear: the
//! bytes it named are the kept generation now, whose intent retires them.
//!
//! A crash before the link leaves an intent for a generation never linked,
//! which only the guard's confirmed absence settles; one after it leaves both
//! names on the old bytes until the rename lands. Distinct uploads keep
//! distinct generations, identical bytes included. A kept generation is
//! retired through the guard inside its hold exclusion, as a delete is
//! (`super::deferred_delete`): once the upload's lock is released, and again
//! on each recheck. A hold keeps it and its intent until release. A listing
//! and a read never show it.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use oneiron_vault_contract::hex;
use oneiron_vault_contract::relay_delete::RelayDeleteGeneration;
use rand_core::{OsRng, RngCore};

use super::deferred_delete::{HeldDeletes, digest, sync_directory};
use super::hold_guard::RelayDeleteTarget;

impl HeldDeletes {
    /// Installs `temporary`, an upload already written and synced in the
    /// objects directory, as `object`, a name the room has validated,
    /// keeping the generation it replaces. A storage failure fails the
    /// upload, as it always has; nothing here asks a guard or waits on a
    /// hold. Any generation it queued is asked to retire once the room's lock
    /// is released.
    pub(super) async fn install(
        self: &Arc<Self>,
        temporary: PathBuf,
        object: String,
    ) -> io::Result<()> {
        let installed = {
            let _serial = self.serialize().await;
            let held = Arc::clone(self);
            tokio::task::spawn_blocking(move || held.install_blocking(&temporary, &object))
                .await
                .unwrap_or_else(|_| Err(io::Error::other("the relay upload install stopped")))
        };
        self.request_recheck();
        installed
    }

    /// The install's steps, in their durable order, under the room's lock.
    fn install_blocking(&self, temporary: &Path, object: &str) -> io::Result<()> {
        let current = self.objects.join(object);
        match digest(&current) {
            Ok(ciphertext_blake3) => self.keep_generation(object, ciphertext_blake3)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::rename(temporary, &current)?;
        sync_directory(&self.objects)?;
        self.clear(object);
        Ok(())
    }

    /// Records the retirement intent of `object`'s current bytes, which
    /// hash to `ciphertext_blake3`, under a fresh generation, then links them
    /// to that generation's name and syncs the objects directory.
    fn keep_generation(&self, object: &str, ciphertext_blake3: [u8; 32]) -> io::Result<()> {
        let mut generation_id = [0_u8; 16];
        OsRng.fill_bytes(&mut generation_id);
        let target = RelayDeleteTarget {
            vault_id: self.vault_id,
            object_id: object.to_owned(),
            generation: RelayDeleteGeneration::Preimage {
                generation_id: hex(&generation_id),
            },
            ciphertext_blake3,
        };
        self.record(&target).inspect_err(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "relay upload not installed: its kept generation's intent did not record"
            );
        })?;
        std::fs::hard_link(self.objects.join(object), self.objects.join(target.leaf()))?;
        sync_directory(&self.objects)
    }
}
